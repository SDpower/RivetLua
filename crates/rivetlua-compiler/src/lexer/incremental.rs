use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{ReserveError, StateAllocator, try_reserve_exact_with, try_shared_uninit_with};
use rivetlua_core::Number;

use super::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, Literal, NumericBudget,
    ScanError, SharedBytes, SourcePosition, Span, Symbol, Token, TokenKind,
};
use super::scanner::{NumberError, parse_number};
use crate::official_failure::{OfficialFailure, OfficialFailureNear, OfficialFailureReason};

#[derive(Clone, Copy)]
pub(crate) enum ByteAvailability {
    Byte(u8),
    NeedInput(usize),
    Eof,
}

pub(crate) trait ByteInput: NumericBudget {
    fn next_byte(&mut self) -> Result<ByteAvailability, Self::Error>;
}

pub(crate) enum LexProgress {
    NeedInput(usize),
    Token(Token),
}

#[derive(Clone, Copy)]
struct Marker {
    byte: usize,
    position: SourcePosition,
}

struct LiteralBuffer(AllocVec<u8, StateAllocator>);

impl LiteralBuffer {
    fn new<B: NumericBudget>(budget: &mut B) -> Result<Self, ScanError<B::Error>> {
        budget.check_fault().map_err(ScanError::Budget)?;
        Ok(Self(AllocVec::new_in(budget.allocator())))
    }

    fn push<B: NumericBudget>(
        &mut self,
        byte: u8,
        limits: &CompileLimits,
        start: Marker,
        end: Marker,
        budget: &mut B,
    ) -> Result<(), ScanError<B::Error>> {
        budget.check_fault().map_err(ScanError::Budget)?;
        if self.0.len() >= limits.max_token_bytes {
            return Err(diagnostic(DiagnosticCode::CompileLimit, start, end, "literal 超過編譯限制").into());
        }
        if self.0.len() == self.0.capacity() {
            let target = self.0.capacity().saturating_mul(2).max(8).min(limits.max_token_bytes);
            let additional = target - self.0.len();
            try_reserve_exact_with(&mut self.0, additional, budget)
                .map_err(reserve_error)?;
        }
        self.0.push(byte);
        Ok(())
    }

    fn shared<B: NumericBudget>(self, budget: &mut B) -> Result<SharedBytes, ScanError<B::Error>> {
        budget.check_fault().map_err(ScanError::Budget)?;
        if !self.0.allocator().same_binding(&budget.allocator()) {
            return Err(ScanError::AllocationFailed);
        }
        let owner = try_shared_uninit_with::<AllocVec<u8, StateAllocator>, _>(budget, 0)
            .map_err(reserve_error)?;
        Ok(owner.write(self.0))
    }
}

fn reserve_error<E>(error: ReserveError<E>) -> ScanError<E> {
    match error {
        ReserveError::Recovery(error) => ScanError::Budget(error),
        ReserveError::AllocatorMismatch | ReserveError::CallbackRefused | ReserveError::AllocationFailed =>
            ScanError::AllocationFailed,
    }
}

#[derive(Clone, Copy)]
enum NumberPhase {
    LeadingZero,
    Decimal,
    DecimalExponentSign,
    DecimalExponentDigits(usize),
    DecimalTail,
    Hexadecimal(usize),
    HexExponentSign,
    HexExponentDigits(usize),
    HexTail,
    BadName(usize),
}

#[derive(Clone, Copy)]
enum StringPhase {
    Body,
    Escape(usize),
    HexHigh(usize),
    HexLow(u8, usize),
    Decimal { value: u16, digits: u8, start: usize },
    UnicodeOpen(usize),
    UnicodeDigits { value: u32, digits: usize, start: usize },
    ZSpace,
}

enum Mode {
    Start,
    ReadyToken(Token),
    ReadyString { start: Marker, bytes: LiteralBuffer },
    ReadyDiagnostic(Diagnostic),
    ReadyComment,
    Name { start: Marker, bytes: LiteralBuffer },
    Number { start: Marker, bytes: LiteralBuffer, phase: NumberPhase },
    ShortString { start: Marker, quote: u8, bytes: LiteralBuffer, phase: StringPhase },
    LongOpen { start: Marker, equals: usize, comment: bool },
    LongBody { start: Marker, equals: usize, bytes: Option<LiteralBuffer>, initial: bool },
    LongClose { start: Marker, equals: usize, matched: usize, bytes: Option<LiteralBuffer> },
    ShortComment { start: Marker, maybe_long: bool },
    Symbol { start: Marker, first: u8, second_dot: bool },
}

enum Step {
    Continue(Mode),
    NeedInput(Mode, usize),
    Token(Token),
}

pub(crate) struct LexerState {
    profile: LanguageProfile,
    byte: usize,
    line: usize,
    column: usize,
    previous_newline: Option<u8>,
    pending: Option<u8>,
    mode: Mode,
    failure: Option<OfficialFailure>,
}

impl LexerState {
    pub(crate) fn new(profile: LanguageProfile) -> Self {
        Self { profile, byte: 0, line: 1, column: 1, previous_newline: None, pending: None,
            mode: Mode::Start, failure: None }
    }

    pub(crate) fn take_official_failure(&mut self) -> Option<OfficialFailure> {
        self.failure.take()
    }

    fn fail(&mut self, reason: OfficialFailureReason, near: OfficialFailureNear) {
        self.failure = Some(OfficialFailure { reason, line: self.line, near });
    }

    fn fail_short(&mut self, reason: &'static [u8], quote: u8, bytes: LiteralBuffer,
        escape_start: usize, include_current: bool) {
        let end = self.byte.saturating_add(usize::from(include_current));
        self.fail(OfficialFailureReason::Text(reason), OfficialFailureNear::ShortString {
            quote, cooked: bytes.0, suffix: Some((escape_start, end)),
        });
    }

    pub(crate) fn offset(&self) -> usize { self.byte }

    fn marker(&self) -> Marker {
        Marker { byte: self.byte, position: SourcePosition { line: self.line, column: self.column } }
    }

    fn diagnostic(&self, code: DiagnosticCode, start: Marker, message: &'static str) -> Diagnostic {
        diagnostic(code, start, self.marker(), message)
    }

    fn peek<B: ByteInput>(&mut self, input: &mut B) -> Result<ByteAvailability, ScanError<B::Error>> {
        if let Some(byte) = self.pending { return Ok(ByteAvailability::Byte(byte)); }
        match input.next_byte().map_err(ScanError::Budget)? {
            ByteAvailability::Byte(byte) => {
                self.pending = Some(byte);
                Ok(ByteAvailability::Byte(byte))
            }
            other => Ok(other),
        }
    }

    fn second_newline(&self, byte: u8) -> bool {
        matches!((self.previous_newline, byte), (Some(b'\r'), b'\n') | (Some(b'\n'), b'\r'))
    }

    fn consume(&mut self, limits: &CompileLimits, start: Marker) -> Result<(), Diagnostic> {
        let byte = self.pending.take().ok_or_else(|| self.diagnostic(DiagnosticCode::Lex, start, "lexer 狀態不完整"))?;
        self.byte = self.byte.checked_add(1)
            .ok_or_else(|| self.diagnostic(DiagnosticCode::CompileLimit, start, "byte offset 溢位"))?;
        if matches!(byte, b'\n' | b'\r') {
            if self.second_newline(byte) {
                self.previous_newline = None;
            } else {
                self.line = self.line.checked_add(1)
                    .ok_or_else(|| self.diagnostic(DiagnosticCode::CompileLimit, start, "行數溢位"))?;
                if self.line > limits.max_lines {
                    return Err(self.diagnostic(DiagnosticCode::CompileLimit, start, "行數超過編譯限制"));
                }
                self.column = 1;
                self.previous_newline = Some(byte);
            }
        } else {
            self.column = self.column.checked_add(1)
                .ok_or_else(|| self.diagnostic(DiagnosticCode::CompileLimit, start, "欄位溢位"))?;
            self.previous_newline = None;
        }
        if self.byte.saturating_sub(start.byte) > limits.max_token_bytes {
            return Err(self.diagnostic(DiagnosticCode::CompileLimit, start, "token 超過編譯限制"));
        }
        Ok(())
    }

    fn token(&self, start: Marker, kind: TokenKind, literal: Option<Literal>) -> Token {
        Token { kind, span: Span { start_byte: start.byte, end_byte: self.byte },
            start: start.position, end: self.marker().position, literal }
    }

    pub(crate) fn next_token<B: ByteInput>(
        &mut self,
        limits: &CompileLimits,
        input: &mut B,
    ) -> Result<LexProgress, ScanError<B::Error>> {
        loop {
            let mode = core::mem::replace(&mut self.mode, Mode::Start);
            match self.step(mode, limits, input)? {
                Step::Continue(mode) => self.mode = mode,
                Step::NeedInput(mode, minimum) => {
                    self.mode = mode;
                    return Ok(LexProgress::NeedInput(minimum));
                }
                Step::Token(token) => return Ok(LexProgress::Token(token)),
            }
        }
    }

    fn step<B: ByteInput>(
        &mut self,
        mode: Mode,
        limits: &CompileLimits,
        input: &mut B,
    ) -> Result<Step, ScanError<B::Error>> {
        match mode {
            Mode::ReadyToken(token) => match self.peek(input)? {
                ByteAvailability::NeedInput(minimum) => Ok(Step::NeedInput(Mode::ReadyToken(token), minimum)),
                ByteAvailability::Byte(_) | ByteAvailability::Eof => Ok(Step::Token(token)),
            },
            Mode::ReadyString { start, bytes } => match self.peek(input)? {
                ByteAvailability::NeedInput(minimum) =>
                    Ok(Step::NeedInput(Mode::ReadyString { start, bytes }, minimum)),
                ByteAvailability::Byte(_) | ByteAvailability::Eof => {
                    let literal = Literal::String(bytes.shared(input)?);
                    Ok(Step::Token(self.token(start, TokenKind::String, Some(literal))))
                }
            },
            Mode::ReadyDiagnostic(error) => match self.peek(input)? {
                ByteAvailability::NeedInput(minimum) =>
                    Ok(Step::NeedInput(Mode::ReadyDiagnostic(error), minimum)),
                ByteAvailability::Byte(_) | ByteAvailability::Eof => Err(error.into()),
            },
            Mode::ReadyComment => match self.peek(input)? {
                ByteAvailability::NeedInput(minimum) => Ok(Step::NeedInput(Mode::ReadyComment, minimum)),
                ByteAvailability::Byte(_) | ByteAvailability::Eof => Ok(Step::Continue(Mode::Start)),
            },
            Mode::Start => {
                let start = self.marker();
                let byte = match self.peek(input)? {
                    ByteAvailability::NeedInput(minimum) => return Ok(Step::NeedInput(Mode::Start, minimum)),
                    ByteAvailability::Eof => return Ok(Step::Token(self.token(start, TokenKind::Eof, None))),
                    ByteAvailability::Byte(byte) => byte,
                };
                if is_space(byte) {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::Start));
                }
                if is_name_start(byte) {
                    let mut bytes = LiteralBuffer::new(input)?;
                    bytes.push(byte, limits, start, self.marker(), input)?;
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::Name { start, bytes }));
                }
                if byte.is_ascii_digit() {
                    let mut bytes = LiteralBuffer::new(input)?;
                    bytes.push(byte, limits, start, self.marker(), input)?;
                    self.consume(limits, start)?;
                    let phase = if byte == b'0' { NumberPhase::LeadingZero } else { NumberPhase::Decimal };
                    return Ok(Step::Continue(Mode::Number { start, bytes, phase }));
                }
                if matches!(byte, b'\'' | b'"') {
                    let bytes = LiteralBuffer::new(input)?;
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::ShortString {
                        start, quote: byte, bytes, phase: StringPhase::Body,
                    }));
                }
                if byte == b'[' {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::LongOpen { start, equals: 0, comment: false }));
                }
                self.consume(limits, start)?;
                let fixed = match byte {
                    b'+' => Some(Symbol::Plus), b'*' => Some(Symbol::Star),
                    b'%' => Some(Symbol::Percent), b'^' => Some(Symbol::Caret),
                    b'#' => Some(Symbol::Hash), b'&' => Some(Symbol::Ampersand),
                    b'|' => Some(Symbol::Pipe), b'(' => Some(Symbol::OpenParen),
                    b')' => Some(Symbol::CloseParen), b'{' => Some(Symbol::OpenBrace),
                    b'}' => Some(Symbol::CloseBrace), b']' => Some(Symbol::CloseBracket),
                    b';' => Some(Symbol::Semicolon), b',' => Some(Symbol::Comma),
                    _ => None,
                };
                if let Some(symbol) = fixed {
                    return Ok(Step::Continue(Mode::ReadyToken(
                        self.token(start, TokenKind::Symbol(symbol), None))));
                }
                if !matches!(byte, b'-' | b'/' | b'~' | b'<' | b'>' | b'=' | b':' | b'.') {
                    self.fail(OfficialFailureReason::Text(b"unexpected symbol"),
                        OfficialFailureNear::RawSymbol(byte));
                    return Ok(Step::Continue(Mode::ReadyDiagnostic(
                        self.diagnostic(DiagnosticCode::Lex, start, "未知詞法元素"))));
                }
                Ok(Step::Continue(Mode::Symbol { start, first: byte, second_dot: false }))
            }
            Mode::Name { start, mut bytes } => {
                match self.peek(input)? {
                    ByteAvailability::NeedInput(minimum) => Ok(Step::NeedInput(Mode::Name { start, bytes }, minimum)),
                    ByteAvailability::Byte(byte) if is_name_continue(byte) => {
                        bytes.push(byte, limits, start, self.marker(), input)?;
                        self.consume(limits, start)?;
                        Ok(Step::Continue(Mode::Name { start, bytes }))
                    }
                    _ => {
                        let kind = keyword(self.profile, &bytes.0).map(TokenKind::Keyword).unwrap_or(TokenKind::Name);
                        let literal = if kind == TokenKind::Name { Some(Literal::Name(bytes.shared(input)?)) } else { None };
                        Ok(Step::Token(self.token(start, kind, literal)))
                    }
                }
            }
            Mode::Number { start, mut bytes, phase } => {
                let next = self.peek(input)?;
                let byte = match next {
                    ByteAvailability::NeedInput(minimum) =>
                        return Ok(Step::NeedInput(Mode::Number { start, bytes, phase }, minimum)),
                    ByteAvailability::Eof => None,
                    ByteAvailability::Byte(byte) => Some(byte),
                };
                let next_phase = match phase {
                    NumberPhase::LeadingZero => match byte {
                        Some(b'x' | b'X') => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::Hexadecimal(0)
                        }
                        _ => NumberPhase::Decimal,
                    },
                    NumberPhase::Decimal => match byte {
                        Some(byte) if byte.is_ascii_digit() || byte == b'.' => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::Decimal
                        }
                        Some(b'e' | b'E') => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::DecimalExponentSign
                        }
                        Some(byte) if is_name_start(byte) => NumberPhase::BadName(bytes.0.len()),
                        _ => return self.finish_number(start, bytes, input),
                    },
                    NumberPhase::DecimalExponentSign => match byte {
                        Some(b'+' | b'-') => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::DecimalExponentDigits(0)
                        }
                        _ => NumberPhase::DecimalExponentDigits(0),
                    },
                    NumberPhase::DecimalExponentDigits(digits) => match byte {
                        Some(byte) if byte.is_ascii_digit() => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::DecimalExponentDigits(digits + 1)
                        }
                        _ if digits == 0 => {
                            let near = if byte.is_some_and(is_name_start) {
                                OfficialFailureNear::ScannerSuffix(bytes.0, byte.unwrap_or_default())
                            } else { OfficialFailureNear::Scanner(bytes.0) };
                            self.fail(OfficialFailureReason::Text(b"malformed number"),
                                near);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "decimal exponent 不合法").into());
                        }
                        _ => NumberPhase::DecimalTail,
                    },
                    NumberPhase::DecimalTail => match byte {
                        Some(byte) if byte.is_ascii_hexdigit() || byte == b'.' => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::DecimalTail
                        }
                        Some(byte) if is_name_start(byte) => NumberPhase::BadName(bytes.0.len()),
                        _ => return self.finish_number(start, bytes, input),
                    },
                    NumberPhase::Hexadecimal(digits) => match byte {
                        Some(byte) if byte.is_ascii_hexdigit() || byte == b'.' => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::Hexadecimal(digits + usize::from(byte.is_ascii_hexdigit()))
                        }
                        _ if digits == 0 => {
                            let near = if byte.is_some_and(is_name_start) {
                                OfficialFailureNear::ScannerSuffix(bytes.0, byte.unwrap_or_default())
                            } else { OfficialFailureNear::Scanner(bytes.0) };
                            self.fail(OfficialFailureReason::Text(b"malformed number"),
                                near);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "十六進位 numeral 缺少數字").into());
                        }
                        Some(b'p' | b'P') => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::HexExponentSign
                        }
                        Some(byte) if is_name_start(byte) => NumberPhase::BadName(bytes.0.len()),
                        _ => return self.finish_number(start, bytes, input),
                    },
                    NumberPhase::HexExponentSign => match byte {
                        Some(b'+' | b'-') => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::HexExponentDigits(0)
                        }
                        _ => NumberPhase::HexExponentDigits(0),
                    },
                    NumberPhase::HexExponentDigits(digits) => match byte {
                        Some(byte) if byte.is_ascii_digit() => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::HexExponentDigits(digits + 1)
                        }
                        _ if digits == 0 => {
                            let near = if byte.is_some_and(is_name_start) {
                                OfficialFailureNear::ScannerSuffix(bytes.0, byte.unwrap_or_default())
                            } else { OfficialFailureNear::Scanner(bytes.0) };
                            self.fail(OfficialFailureReason::Text(b"malformed number"),
                                near);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "十六進位 exponent 不合法").into());
                        }
                        _ => NumberPhase::HexTail,
                    },
                    NumberPhase::HexTail => match byte {
                        Some(byte) if byte.is_ascii_hexdigit() || byte == b'.' => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::HexTail
                        }
                        Some(byte) if is_name_start(byte) => NumberPhase::BadName(bytes.0.len()),
                        _ => return self.finish_number(start, bytes, input),
                    },
                    NumberPhase::BadName(first) => match byte {
                        Some(byte) if is_name_continue(byte) => {
                            self.number_byte(&mut bytes, limits, start, input)?;
                            NumberPhase::BadName(first)
                        }
                        _ => {
                            bytes.0.truncate(first.saturating_add(1));
                            self.fail(OfficialFailureReason::Text(b"malformed number"),
                                OfficialFailureNear::Scanner(bytes.0));
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "numeral 不可黏接識別字").into());
                        }
                    },
                };
                Ok(Step::Continue(Mode::Number { start, bytes, phase: next_phase }))
            }
            Mode::ShortString { start, quote, mut bytes, phase } => {
                let next = self.peek(input)?;
                let byte = match next {
                    ByteAvailability::NeedInput(minimum) => return Ok(Step::NeedInput(Mode::ShortString { start, quote, bytes, phase }, minimum)),
                    ByteAvailability::Eof => {
                        match phase {
                            StringPhase::HexHigh(at) | StringPhase::HexLow(_, at) =>
                                self.fail_short(b"hexadecimal digit expected", quote, bytes,
                                    at, false),
                            StringPhase::UnicodeOpen(at) =>
                                self.fail_short(b"missing '{'", quote, bytes, at, false),
                            StringPhase::UnicodeDigits { digits, start: at, .. } =>
                                self.fail_short(if digits == 0 {
                                    b"hexadecimal digit expected".as_slice()
                                } else { b"missing '}'".as_slice() }, quote, bytes, at, false),
                            StringPhase::Decimal { value, digits: 3, start: at } if value > 255 =>
                                self.fail_short(b"decimal escape too large", quote, bytes,
                                    at, false),
                            _ => self.fail(OfficialFailureReason::Text(b"unfinished string"),
                                OfficialFailureNear::Eof),
                        }
                        return Err(self.diagnostic(DiagnosticCode::Lex, start, match phase {
                        StringPhase::Body | StringPhase::ZSpace | StringPhase::Decimal { digits: 1..=3, .. } => "短字串未結束",
                        StringPhase::UnicodeDigits { .. } => "Unicode escape 未結束",
                        StringPhase::UnicodeOpen(_) => "Unicode escape 格式不合法",
                        StringPhase::HexHigh(_) | StringPhase::HexLow(_, _) => "十六進位 escape 不合法",
                        _ => "短字串 escape 未結束",
                        }).into());
                    }
                    ByteAvailability::Byte(byte) => byte,
                };
                let next_phase = match phase {
                    StringPhase::Body if byte == quote => {
                        self.consume(limits, start)?;
                        return Ok(Step::Continue(Mode::ReadyString { start, bytes }));
                    }
                    StringPhase::Body if matches!(byte, b'\n' | b'\r') && self.second_newline(byte) => {
                        self.consume(limits, start)?;
                        StringPhase::Body
                    }
                    StringPhase::Body if matches!(byte, b'\n' | b'\r') => {
                        self.fail(OfficialFailureReason::Text(b"unfinished string"),
                            OfficialFailureNear::ShortString { quote, cooked: bytes.0, suffix: None });
                        return Err(self.diagnostic(DiagnosticCode::Lex, start, "短字串含未轉義換行").into());
                    }
                    StringPhase::Body if byte == b'\\' => {
                        let escape_start = self.byte;
                        self.consume(limits, start)?;
                        StringPhase::Escape(escape_start)
                    }
                    StringPhase::Body => {
                        bytes.push(byte, limits, start, self.marker(), input)?;
                        self.consume(limits, start)?;
                        StringPhase::Body
                    }
                    StringPhase::Escape(escape_start) => {
                        let simple = match byte {
                            b'a' => Some(0x07), b'b' => Some(0x08), b'f' => Some(0x0c),
                            b'n' => Some(b'\n'), b'r' => Some(b'\r'), b't' => Some(b'\t'),
                            b'v' => Some(0x0b), b'\\' | b'\'' | b'"' => Some(byte),
                            _ => None,
                        };
                        if let Some(value) = simple {
                            bytes.push(value, limits, start, self.marker(), input)?;
                            self.consume(limits, start)?;
                            StringPhase::Body
                        } else {
                            match byte {
                                b'x' => { self.consume(limits, start)?; StringPhase::HexHigh(escape_start) }
                                b'z' => { self.consume(limits, start)?; StringPhase::ZSpace }
                                b'u' => { self.consume(limits, start)?; StringPhase::UnicodeOpen(escape_start) }
                                b'0'..=b'9' => StringPhase::Decimal { value: 0, digits: 0,
                                    start: escape_start },
                                b'\n' | b'\r' => {
                                    bytes.push(b'\n', limits, start, self.marker(), input)?;
                                    self.consume(limits, start)?;
                                    StringPhase::Body
                                }
                                _ => {
                                    self.fail_short(b"invalid escape sequence", quote, bytes,
                                        escape_start, true);
                                    return Err(self.diagnostic(DiagnosticCode::Lex, start, "短字串 escape 不合法").into());
                                }
                            }
                        }
                    }
                    StringPhase::HexHigh(escape_start) => {
                        let Some(digit) = hex_value(byte) else {
                            self.fail_short(b"hexadecimal digit expected", quote, bytes,
                                escape_start, true);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "十六進位 escape 不合法").into());
                        };
                        self.consume(limits, start)?;
                        StringPhase::HexLow(digit, escape_start)
                    }
                    StringPhase::HexLow(high, escape_start) => {
                        let Some(digit) = hex_value(byte) else {
                            self.fail_short(b"hexadecimal digit expected", quote, bytes,
                                escape_start, true);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "十六進位 escape 不合法").into());
                        };
                        bytes.push(high * 16 + digit, limits, start, self.marker(), input)?;
                        self.consume(limits, start)?;
                        StringPhase::Body
                    }
                    StringPhase::Decimal { value, digits, start: escape_start } => {
                        if digits < 3 && byte.is_ascii_digit() {
                            let value = value * 10 + u16::from(byte - b'0');
                            self.consume(limits, start)?;
                            StringPhase::Decimal { value, digits: digits + 1, start: escape_start }
                        } else if value > 255 {
                            self.fail_short(b"decimal escape too large", quote, bytes,
                                escape_start, true);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "十進位 escape 超過 255").into());
                        } else {
                            bytes.push(value as u8, limits, start, self.marker(), input)?;
                            StringPhase::Body
                        }
                    }
                    StringPhase::UnicodeOpen(escape_start) => {
                        if byte != b'{' {
                            self.fail_short(b"missing '{'", quote, bytes, escape_start, true);
                            return Err(self.diagnostic(DiagnosticCode::Lex, start, "Unicode escape 格式不合法").into());
                        }
                        self.consume(limits, start)?;
                        StringPhase::UnicodeDigits { value: 0, digits: 0, start: escape_start }
                    }
                    StringPhase::UnicodeDigits { value, digits, start: escape_start } => {
                        if byte == b'}' {
                            if digits == 0 {
                                self.fail_short(b"hexadecimal digit expected", quote, bytes,
                                    escape_start, true);
                                return Err(self.diagnostic(DiagnosticCode::Lex, start, "Unicode escape 缺少十六進位數字").into());
                            }
                            push_unicode(&mut bytes, value, limits, start, self.marker(), input)?;
                            self.consume(limits, start)?;
                            StringPhase::Body
                        } else {
                            let Some(digit) = hex_value(byte) else {
                                self.fail_short(if digits == 0 {
                                    b"hexadecimal digit expected".as_slice()
                                } else { b"missing '}'".as_slice() }, quote, bytes,
                                    escape_start, true);
                                return Err(self.diagnostic(DiagnosticCode::Lex, start, "Unicode escape 格式不合法").into());
                            };
                            let Some(value) = value.checked_mul(16)
                                .and_then(|value| value.checked_add(u32::from(digit)))
                                .filter(|value| *value <= 0x7fff_ffff) else {
                                self.fail_short(b"UTF-8 value too large", quote, bytes,
                                    escape_start, true);
                                return Err(self.diagnostic(DiagnosticCode::Lex, start, "Unicode escape 超出 Lua 範圍").into());
                            };
                            self.consume(limits, start)?;
                            StringPhase::UnicodeDigits { value, digits: digits + 1,
                                start: escape_start }
                        }
                    }
                    StringPhase::ZSpace => {
                        if is_space(byte) { self.consume(limits, start)?; StringPhase::ZSpace }
                        else { StringPhase::Body }
                    }
                };
                Ok(Step::Continue(Mode::ShortString { start, quote, bytes, phase: next_phase }))
            }
            Mode::LongOpen { start, equals, comment } => {
                match self.peek(input)? {
                    ByteAvailability::NeedInput(minimum) => Ok(Step::NeedInput(Mode::LongOpen { start, equals, comment }, minimum)),
                    ByteAvailability::Byte(b'=') => {
                        self.consume(limits, start)?;
                        let equals = equals.checked_add(1)
                            .ok_or_else(|| self.diagnostic(DiagnosticCode::Lex, start, "long delimiter 長度溢位"))?;
                        Ok(Step::Continue(Mode::LongOpen { start, equals, comment }))
                    }
                    ByteAvailability::Byte(b'[') => {
                        let bytes = if comment { None } else { Some(LiteralBuffer::new(input)?) };
                        self.consume(limits, start)?;
                        Ok(Step::Continue(Mode::LongBody { start, equals, bytes, initial: true }))
                    }
                    _ if comment => Ok(Step::Continue(Mode::ShortComment { start, maybe_long: false })),
                    _ if equals != 0 => {
                        self.fail(OfficialFailureReason::Text(b"invalid long string delimiter"),
                            OfficialFailureNear::LongDelimiter(equals));
                        Err(self.diagnostic(DiagnosticCode::Lex, start, "long delimiter 不合法").into())
                    }
                    _ => Ok(Step::Token(self.token(start, TokenKind::Symbol(Symbol::OpenBracket), None))),
                }
            }
            Mode::LongBody { start, equals, mut bytes, initial } => {
                let byte = match self.peek(input)? {
                    ByteAvailability::NeedInput(minimum) => return Ok(Step::NeedInput(Mode::LongBody { start, equals, bytes, initial }, minimum)),
                    ByteAvailability::Eof => {
                        self.fail(OfficialFailureReason::LongUnfinished {
                            comment: bytes.is_none(), opener_line: start.position.line,
                        }, OfficialFailureNear::Eof);
                        return Err(self.diagnostic(DiagnosticCode::Lex, start,
                            if bytes.is_some() { "long 字串未結束" } else { "long 註解未結束" }).into());
                    }
                    ByteAvailability::Byte(byte) => byte,
                };
                if initial {
                    if matches!(byte, b'\n' | b'\r') { self.consume(limits, start)?; }
                    return Ok(Step::Continue(Mode::LongBody { start, equals, bytes, initial: false }));
                }
                if byte == b']' {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::LongClose { start, equals, matched: 0, bytes }));
                }
                if let Some(buffer) = bytes.as_mut() {
                    if matches!(byte, b'\n' | b'\r') {
                        if !self.second_newline(byte) { buffer.push(b'\n', limits, start, self.marker(), input)?; }
                    } else {
                        buffer.push(byte, limits, start, self.marker(), input)?;
                    }
                }
                self.consume(limits, start)?;
                Ok(Step::Continue(Mode::LongBody { start, equals, bytes, initial: false }))
            }
            Mode::LongClose { start, equals, matched, mut bytes } => {
                let next = self.peek(input)?;
                if let ByteAvailability::NeedInput(minimum) = next {
                    return Ok(Step::NeedInput(Mode::LongClose { start, equals, matched, bytes }, minimum));
                }
                if matched < equals && matches!(next, ByteAvailability::Byte(b'=')) {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::LongClose { start, equals, matched: matched + 1, bytes }));
                }
                if matched == equals && matches!(next, ByteAvailability::Byte(b']')) {
                    self.consume(limits, start)?;
                    return if let Some(bytes) = bytes {
                        Ok(Step::Continue(Mode::ReadyString { start, bytes }))
                    } else {
                        Ok(Step::Continue(Mode::ReadyComment))
                    };
                }
                if let Some(buffer) = bytes.as_mut() {
                    buffer.push(b']', limits, start, self.marker(), input)?;
                    for _ in 0..matched { buffer.push(b'=', limits, start, self.marker(), input)?; }
                }
                Ok(Step::Continue(Mode::LongBody { start, equals, bytes, initial: false }))
            }
            Mode::ShortComment { start, maybe_long } => {
                match self.peek(input)? {
                    ByteAvailability::NeedInput(minimum) => Ok(Step::NeedInput(Mode::ShortComment { start, maybe_long }, minimum)),
                    ByteAvailability::Eof | ByteAvailability::Byte(b'\n' | b'\r') => Ok(Step::Continue(Mode::Start)),
                    ByteAvailability::Byte(b'[') if maybe_long => {
                        self.consume(limits, start)?;
                        Ok(Step::Continue(Mode::LongOpen { start, equals: 0, comment: true }))
                    }
                    ByteAvailability::Byte(_) => {
                        self.consume(limits, start)?;
                        Ok(Step::Continue(Mode::ShortComment { start, maybe_long: false }))
                    }
                }
            }
            Mode::Symbol { start, first, second_dot } => {
                let next = self.peek(input)?;
                let byte = match next {
                    ByteAvailability::NeedInput(minimum) => return Ok(Step::NeedInput(Mode::Symbol { start, first, second_dot }, minimum)),
                    ByteAvailability::Eof => None,
                    ByteAvailability::Byte(byte) => Some(byte),
                };
                if second_dot {
                    if byte == Some(b'.') {
                        self.consume(limits, start)?;
                        return Ok(Step::Continue(Mode::ReadyToken(
                            self.token(start, TokenKind::Symbol(Symbol::Vararg), None))));
                    }
                    return Ok(Step::Token(self.token(start, TokenKind::Symbol(Symbol::Concat), None)));
                }
                if first == b'.' && byte.is_some_and(|b| b.is_ascii_digit()) {
                    let mut bytes = LiteralBuffer::new(input)?;
                    bytes.push(b'.', limits, start, self.marker(), input)?;
                    return Ok(Step::Continue(Mode::Number { start, bytes, phase: NumberPhase::Decimal }));
                }
                if first == b'-' && byte == Some(b'-') {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::ShortComment { start, maybe_long: true }));
                }
                let symbol = match (first, byte) {
                    (b'/', Some(b'/')) => Some(Symbol::FloorSlash),
                    (b'~', Some(b'=')) => Some(Symbol::NotEqual),
                    (b'<', Some(b'=')) => Some(Symbol::LessEqual),
                    (b'<', Some(b'<')) => Some(Symbol::ShiftLeft),
                    (b'>', Some(b'=')) => Some(Symbol::GreaterEqual),
                    (b'>', Some(b'>')) => Some(Symbol::ShiftRight),
                    (b'=', Some(b'=')) => Some(Symbol::EqualEqual),
                    (b':', Some(b':')) => Some(Symbol::DoubleColon),
                    (b'.', Some(b'.')) => {
                        self.consume(limits, start)?;
                        return Ok(Step::Continue(Mode::Symbol { start, first, second_dot: true }));
                    }
                    _ => None,
                };
                if let Some(symbol) = symbol {
                    self.consume(limits, start)?;
                    return Ok(Step::Continue(Mode::ReadyToken(
                        self.token(start, TokenKind::Symbol(symbol), None))));
                }
                let symbol = match first {
                    b'+' => Symbol::Plus, b'-' => Symbol::Minus, b'*' => Symbol::Star,
                    b'/' => Symbol::Slash, b'%' => Symbol::Percent, b'^' => Symbol::Caret,
                    b'#' => Symbol::Hash, b'&' => Symbol::Ampersand, b'|' => Symbol::Pipe,
                    b'~' => Symbol::Tilde, b'<' => Symbol::Less, b'>' => Symbol::Greater,
                    b'=' => Symbol::Assign, b'(' => Symbol::OpenParen, b')' => Symbol::CloseParen,
                    b'{' => Symbol::OpenBrace, b'}' => Symbol::CloseBrace, b']' => Symbol::CloseBracket,
                    b';' => Symbol::Semicolon, b':' => Symbol::Colon, b',' => Symbol::Comma,
                    b'.' => Symbol::Dot,
                    _ => return Err(self.diagnostic(DiagnosticCode::Lex, start, "未知詞法元素").into()),
                };
                Ok(Step::Token(self.token(start, TokenKind::Symbol(symbol), None)))
            }
        }
    }

    fn number_byte<B: ByteInput>(&mut self, bytes: &mut LiteralBuffer, limits: &CompileLimits,
        start: Marker, input: &mut B) -> Result<(), ScanError<B::Error>> {
        let byte = self.pending.ok_or_else(|| self.diagnostic(DiagnosticCode::Lex, start, "lexer numeral 狀態不完整"))?;
        bytes.push(byte, limits, start, self.marker(), input)?;
        self.consume(limits, start)?;
        Ok(())
    }

    fn finish_number<B: ByteInput>(&mut self, start: Marker, bytes: LiteralBuffer,
        input: &mut B) -> Result<Step, ScanError<B::Error>> {
        input.check_fault().map_err(ScanError::Budget)?;
        let number = match parse_number(&bytes.0, input) {
            Ok(number) => number,
            Err(NumberError::Syntax(message)) => {
                self.fail(OfficialFailureReason::Text(b"malformed number"),
                    OfficialFailureNear::Scanner(bytes.0));
                return Err(self.diagnostic(DiagnosticCode::Lex, start, message).into());
            }
            Err(NumberError::Budget(error)) => return Err(ScanError::Budget(error)),
        };
        let (kind, literal) = match number {
            Number::Integer(_) => (TokenKind::Integer, Literal::Integer(number)),
            Number::Float(_) => (TokenKind::Float, Literal::Float(number)),
        };
        Ok(Step::Token(self.token(start, kind, Some(literal))))
    }
}

fn push_unicode<B: NumericBudget>(bytes: &mut LiteralBuffer, value: u32,
    limits: &CompileLimits, start: Marker, end: Marker, budget: &mut B) -> Result<(), ScanError<B::Error>> {
    let (length, prefix) = match value {
        0..=0x7f => (1, 0x00), 0x80..=0x7ff => (2, 0xc0),
        0x800..=0xffff => (3, 0xe0), 0x1_0000..=0x1f_ffff => (4, 0xf0),
        0x20_0000..=0x3ff_ffff => (5, 0xf8), 0x400_0000..=0x7fff_ffff => (6, 0xfc),
        _ => return Err(diagnostic(DiagnosticCode::Lex, start, end, "Unicode escape 超出 Lua 範圍").into()),
    };
    let first_shift = (length - 1) * 6;
    bytes.push(prefix | (value >> first_shift) as u8, limits, start, end, budget)?;
    for shift in (0..length - 1).rev() {
        bytes.push(0x80 | ((value >> (shift * 6)) & 0x3f) as u8, limits, start, end, budget)?;
    }
    Ok(())
}

fn diagnostic(code: DiagnosticCode, start: Marker, end: Marker, message: &'static str) -> Diagnostic {
    Diagnostic { code, span: Span { start_byte: start.byte, end_byte: end.byte },
        start: start.position, end: end.position, message }
}

fn keyword(profile: LanguageProfile, name: &[u8]) -> Option<Keyword> {
    Some(match name {
        b"and" => Keyword::And, b"break" => Keyword::Break, b"do" => Keyword::Do,
        b"else" => Keyword::Else, b"elseif" => Keyword::ElseIf, b"end" => Keyword::End,
        b"false" => Keyword::False, b"for" => Keyword::For, b"function" => Keyword::Function,
        b"goto" => Keyword::Goto, b"if" => Keyword::If, b"in" => Keyword::In,
        b"local" => Keyword::Local, b"nil" => Keyword::Nil, b"not" => Keyword::Not,
        b"or" => Keyword::Or, b"repeat" => Keyword::Repeat, b"return" => Keyword::Return,
        b"then" => Keyword::Then, b"true" => Keyword::True, b"until" => Keyword::Until,
        b"while" => Keyword::While,
        b"global" if profile.rules().global_declarations => Keyword::Global,
        _ => return None,
    })
}

fn is_space(byte: u8) -> bool { matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) }
fn is_name_start(byte: u8) -> bool { byte.is_ascii_alphabetic() || byte == b'_' }
fn is_name_continue(byte: u8) -> bool { is_name_start(byte) || byte.is_ascii_digit() }
fn hex_value(byte: u8) -> Option<u8> {
    match byte { b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10), _ => None }
}
