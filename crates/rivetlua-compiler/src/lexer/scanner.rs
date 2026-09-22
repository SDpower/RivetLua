use rivetlua_core::Number;

use super::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LexedChunk, Literal, SourcePosition, Span,
    Symbol, Token, TokenKind, cursor::Cursor, push_token,
};

pub(super) fn scan(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
) -> Result<LexedChunk, Diagnostic> {
    let mut tokens = Vec::new();
    while let Some(byte) = cursor.peek() {
        if is_space(byte) {
            consume_space(cursor, limits)?;
        } else if byte == b'[' {
            match long_opening_separator(cursor) {
                Ok(Some(equals)) => scan_long_string(cursor, limits, &mut tokens, equals)?,
                Ok(None) => scan_symbol(cursor, limits, &mut tokens)?,
                Err(()) => {
                    let start = cursor.position();
                    let start_byte = cursor.offset();
                    advance(cursor, limits, start_byte, start)?;
                    return Err(lex_error(
                        cursor,
                        start_byte,
                        start,
                        "long delimiter 不合法",
                    ));
                }
            }
        } else if is_name_start(byte) {
            scan_name(cursor, limits, &mut tokens)?;
        } else if byte.is_ascii_digit()
            || (byte == b'.' && cursor.peek_n(1).is_some_and(|next| next.is_ascii_digit()))
        {
            scan_number(cursor, limits, &mut tokens)?;
        } else if matches!(byte, b'\'' | b'"') {
            scan_short_string(cursor, limits, &mut tokens)?;
        } else if byte == b'-' && cursor.peek_n(1) == Some(b'-') {
            scan_short_comment(cursor, limits)?;
        } else {
            scan_symbol(cursor, limits, &mut tokens)?;
        }
    }
    let position = cursor.position();
    push_token(
        &mut tokens,
        Token {
            kind: TokenKind::Eof,
            span: Span {
                start_byte: cursor.offset(),
                end_byte: cursor.offset(),
            },
            start: position,
            end: position,
            literal: None,
        },
        limits,
        cursor,
    )?;
    Ok(LexedChunk {
        profile: cursor.profile(),
        source_len: cursor.offset(),
        tokens,
    })
}

fn consume_space(cursor: &mut Cursor<'_>, limits: &CompileLimits) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    advance(cursor, limits, start_byte, start)
}

fn scan_name(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    tokens: &mut Vec<Token>,
) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    let mut bytes = Vec::new();
    while cursor.peek().is_some_and(is_name_continue) {
        append_input_byte(
            &mut bytes,
            cursor.peek().unwrap(),
            limits,
            cursor,
            start_byte,
            start,
        )?;
        advance(cursor, limits, start_byte, start)?;
    }
    let kind = keyword(cursor, &bytes)
        .map(TokenKind::Keyword)
        .unwrap_or(TokenKind::Name);
    let literal = (kind == TokenKind::Name).then_some(Literal::Name(bytes));
    emit(tokens, cursor, limits, start_byte, start, kind, literal)
}

fn scan_number(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    tokens: &mut Vec<Token>,
) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    let mut bytes = Vec::new();
    let hexadecimal = cursor.peek() == Some(b'0') && matches!(cursor.peek_n(1), Some(b'x' | b'X'));
    if hexadecimal {
        consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
        consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
        let mut digits = 0usize;
        while cursor.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
            digits += 1;
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
        }
        if cursor.peek() == Some(b'.') && cursor.peek_n(1) != Some(b'.') {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            while cursor.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                digits += 1;
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
        }
        if digits == 0 {
            return Err(lex_error(
                cursor,
                start_byte,
                start,
                "十六進位 numeral 缺少數字",
            ));
        }
        if matches!(cursor.peek(), Some(b'p' | b'P')) {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            if matches!(cursor.peek(), Some(b'+' | b'-')) {
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
            let exponent_start = bytes.len();
            while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
            if bytes.len() == exponent_start {
                return Err(lex_error(
                    cursor,
                    start_byte,
                    start,
                    "十六進位 exponent 不合法",
                ));
            }
        }
    } else {
        while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
        }
        if cursor.peek() == Some(b'.') && cursor.peek_n(1) != Some(b'.') {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
        }
        if matches!(cursor.peek(), Some(b'e' | b'E')) {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            if matches!(cursor.peek(), Some(b'+' | b'-')) {
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
            let exponent_start = bytes.len();
            while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
            }
            if bytes.len() == exponent_start {
                return Err(lex_error(
                    cursor,
                    start_byte,
                    start,
                    "decimal exponent 不合法",
                ));
            }
        }
    }
    if cursor.peek().is_some_and(is_name_start) {
        while cursor.peek().is_some_and(is_name_continue) {
            consume_number_byte(&mut bytes, cursor, limits, start_byte, start)?;
        }
        return Err(lex_error(
            cursor,
            start_byte,
            start,
            "numeral 不可黏接識別字",
        ));
    }
    let number =
        parse_number(&bytes).map_err(|message| lex_error(cursor, start_byte, start, message))?;
    let (kind, literal) = match number {
        Number::Integer(_) => (TokenKind::Integer, Literal::Integer(number)),
        Number::Float(_) => (TokenKind::Float, Literal::Float(number)),
    };
    emit(
        tokens,
        cursor,
        limits,
        start_byte,
        start,
        kind,
        Some(literal),
    )
}

fn scan_short_string(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    tokens: &mut Vec<Token>,
) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    let quote = cursor.peek().unwrap();
    advance(cursor, limits, start_byte, start)?;
    let mut bytes = Vec::new();
    loop {
        let Some(byte) = cursor.peek() else {
            return Err(lex_error(cursor, start_byte, start, "短字串未結束"));
        };
        if byte == quote {
            advance(cursor, limits, start_byte, start)?;
            break;
        }
        if matches!(byte, b'\n' | b'\r') {
            return Err(lex_error(cursor, start_byte, start, "短字串含未轉義換行"));
        }
        if byte != b'\\' {
            append_input_byte(&mut bytes, byte, limits, cursor, start_byte, start)?;
            advance(cursor, limits, start_byte, start)?;
            continue;
        }
        advance(cursor, limits, start_byte, start)?;
        let Some(escape) = cursor.peek() else {
            return Err(lex_error(cursor, start_byte, start, "短字串 escape 未結束"));
        };
        match escape {
            b'a' => push_literal_byte(&mut bytes, 0x07, limits, cursor, start_byte, start)?,
            b'b' => push_literal_byte(&mut bytes, 0x08, limits, cursor, start_byte, start)?,
            b'f' => push_literal_byte(&mut bytes, 0x0c, limits, cursor, start_byte, start)?,
            b'n' => push_literal_byte(&mut bytes, b'\n', limits, cursor, start_byte, start)?,
            b'r' => push_literal_byte(&mut bytes, b'\r', limits, cursor, start_byte, start)?,
            b't' => push_literal_byte(&mut bytes, b'\t', limits, cursor, start_byte, start)?,
            b'v' => push_literal_byte(&mut bytes, 0x0b, limits, cursor, start_byte, start)?,
            b'\\' | b'\'' | b'"' => {
                push_literal_byte(&mut bytes, escape, limits, cursor, start_byte, start)?
            }
            b'x' => {
                advance(cursor, limits, start_byte, start)?;
                let high = cursor.peek().and_then(hex_value).ok_or_else(|| {
                    lex_error(cursor, start_byte, start, "十六進位 escape 不合法")
                })?;
                advance(cursor, limits, start_byte, start)?;
                let low = cursor.peek().and_then(hex_value).ok_or_else(|| {
                    lex_error(cursor, start_byte, start, "十六進位 escape 不合法")
                })?;
                push_literal_byte(
                    &mut bytes,
                    high * 16 + low,
                    limits,
                    cursor,
                    start_byte,
                    start,
                )?;
            }
            b'z' => {
                advance(cursor, limits, start_byte, start)?;
                while cursor.peek().is_some_and(is_space) {
                    advance(cursor, limits, start_byte, start)?;
                }
                continue;
            }
            b'0'..=b'9' => {
                let mut value = 0u16;
                for _ in 0..3 {
                    let Some(digit @ b'0'..=b'9') = cursor.peek() else {
                        break;
                    };
                    value = value * 10 + u16::from(digit - b'0');
                    if value > 255 {
                        return Err(lex_error(
                            cursor,
                            start_byte,
                            start,
                            "十進位 escape 超過 255",
                        ));
                    }
                    advance(cursor, limits, start_byte, start)?;
                }
                push_literal_byte(&mut bytes, value as u8, limits, cursor, start_byte, start)?;
                continue;
            }
            b'\n' | b'\r' => {
                push_literal_byte(&mut bytes, b'\n', limits, cursor, start_byte, start)?;
                advance(cursor, limits, start_byte, start)?;
                continue;
            }
            _ => return Err(lex_error(cursor, start_byte, start, "短字串 escape 不合法")),
        }
        advance(cursor, limits, start_byte, start)?;
    }
    emit(
        tokens,
        cursor,
        limits,
        start_byte,
        start,
        TokenKind::String,
        Some(Literal::String(bytes)),
    )
}

fn scan_short_comment(cursor: &mut Cursor<'_>, limits: &CompileLimits) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    advance(cursor, limits, start_byte, start)?;
    advance(cursor, limits, start_byte, start)?;
    if cursor.peek() == Some(b'[') {
        match long_opening_separator(cursor) {
            Ok(Some(equals)) => {
                return scan_long_comment(cursor, limits, start_byte, start, equals);
            }
            Ok(None) => {}
            Err(()) => {
                return Err(lex_error(
                    cursor,
                    cursor.offset(),
                    cursor.position(),
                    "long delimiter 不合法",
                ));
            }
        }
    }
    while cursor
        .peek()
        .is_some_and(|byte| !matches!(byte, b'\n' | b'\r'))
    {
        advance(cursor, limits, start_byte, start)?;
    }
    Ok(())
}

fn scan_long_string(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    tokens: &mut Vec<Token>,
    equals: usize,
) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    consume_long_separator(cursor, limits, start_byte, start, equals)?;
    if cursor
        .peek()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        advance(cursor, limits, start_byte, start)?;
    }
    let mut bytes = Vec::new();
    loop {
        let Some(byte) = cursor.peek() else {
            return Err(lex_error(cursor, start_byte, start, "long 字串未結束"));
        };
        if byte == b']' && long_closing_separator(cursor, equals) {
            consume_long_separator(cursor, limits, start_byte, start, equals)?;
            break;
        }
        if matches!(byte, b'\n' | b'\r') {
            push_literal_byte(&mut bytes, b'\n', limits, cursor, start_byte, start)?;
        } else {
            append_input_byte(&mut bytes, byte, limits, cursor, start_byte, start)?;
        }
        advance(cursor, limits, start_byte, start)?;
    }
    emit(
        tokens,
        cursor,
        limits,
        start_byte,
        start,
        TokenKind::String,
        Some(Literal::String(bytes)),
    )
}

fn scan_long_comment(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    comment_start_byte: usize,
    comment_start: SourcePosition,
    equals: usize,
) -> Result<(), Diagnostic> {
    consume_long_separator(cursor, limits, comment_start_byte, comment_start, equals)?;
    loop {
        let Some(byte) = cursor.peek() else {
            return Err(lex_error(
                cursor,
                comment_start_byte,
                comment_start,
                "long 註解未結束",
            ));
        };
        if byte == b']' && long_closing_separator(cursor, equals) {
            return consume_long_separator(
                cursor,
                limits,
                comment_start_byte,
                comment_start,
                equals,
            );
        }
        advance(cursor, limits, comment_start_byte, comment_start)?;
    }
}

fn long_opening_separator(cursor: &Cursor<'_>) -> Result<Option<usize>, ()> {
    if cursor.peek() != Some(b'[') {
        return Ok(None);
    }
    let mut distance = 1usize;
    let mut equals = 0usize;
    while cursor.peek_n(distance) == Some(b'=') {
        equals = equals.checked_add(1).ok_or(())?;
        distance = distance.checked_add(1).ok_or(())?;
    }
    if cursor.peek_n(distance) == Some(b'[') {
        Ok(Some(equals))
    } else if equals > 0 {
        Err(())
    } else {
        Ok(None)
    }
}

fn long_closing_separator(cursor: &Cursor<'_>, equals: usize) -> bool {
    if cursor.peek() != Some(b']') {
        return false;
    }
    let Some(last) = equals.checked_add(1) else {
        return false;
    };
    (1..=equals).all(|distance| cursor.peek_n(distance) == Some(b'='))
        && cursor.peek_n(last) == Some(b']')
}

fn consume_long_separator(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    start_byte: usize,
    start: SourcePosition,
    equals: usize,
) -> Result<(), Diagnostic> {
    let length = equals
        .checked_add(2)
        .ok_or_else(|| lex_error(cursor, start_byte, start, "long delimiter 長度溢位"))?;
    for _ in 0..length {
        advance(cursor, limits, start_byte, start)?;
    }
    Ok(())
}

fn scan_symbol(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    tokens: &mut Vec<Token>,
) -> Result<(), Diagnostic> {
    let start = cursor.position();
    let start_byte = cursor.offset();
    let first = cursor.peek().unwrap();
    let symbol = match first {
        b'+' => Symbol::Plus,
        b'-' => Symbol::Minus,
        b'*' => Symbol::Star,
        b'/' => {
            if cursor.peek_n(1) == Some(b'/') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::FloorSlash
            } else {
                Symbol::Slash
            }
        }
        b'%' => Symbol::Percent,
        b'^' => Symbol::Caret,
        b'#' => Symbol::Hash,
        b'&' => Symbol::Ampersand,
        b'|' => Symbol::Pipe,
        b'~' => {
            if cursor.peek_n(1) == Some(b'=') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::NotEqual
            } else {
                Symbol::Tilde
            }
        }
        b'<' => {
            if cursor.peek_n(1) == Some(b'=') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::LessEqual
            } else if cursor.peek_n(1) == Some(b'<') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::ShiftLeft
            } else {
                Symbol::Less
            }
        }
        b'>' => {
            if cursor.peek_n(1) == Some(b'=') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::GreaterEqual
            } else if cursor.peek_n(1) == Some(b'>') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::ShiftRight
            } else {
                Symbol::Greater
            }
        }
        b'=' => {
            if cursor.peek_n(1) == Some(b'=') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::EqualEqual
            } else {
                Symbol::Assign
            }
        }
        b'(' => Symbol::OpenParen,
        b')' => Symbol::CloseParen,
        b'{' => Symbol::OpenBrace,
        b'}' => Symbol::CloseBrace,
        b'[' => Symbol::OpenBracket,
        b']' => Symbol::CloseBracket,
        b';' => Symbol::Semicolon,
        b':' => {
            if cursor.peek_n(1) == Some(b':') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::DoubleColon
            } else {
                Symbol::Colon
            }
        }
        b',' => Symbol::Comma,
        b'.' => {
            if cursor.peek_n(1) == Some(b'.') && cursor.peek_n(2) == Some(b'.') {
                advance(cursor, limits, start_byte, start)?;
                advance(cursor, limits, start_byte, start)?;
                Symbol::Vararg
            } else if cursor.peek_n(1) == Some(b'.') {
                advance(cursor, limits, start_byte, start)?;
                Symbol::Concat
            } else {
                Symbol::Dot
            }
        }
        _ => {
            advance(cursor, limits, start_byte, start)?;
            return Err(lex_error(cursor, start_byte, start, "未知詞法元素"));
        }
    };
    advance(cursor, limits, start_byte, start)?;
    emit(
        tokens,
        cursor,
        limits,
        start_byte,
        start,
        TokenKind::Symbol(symbol),
        None,
    )
}

fn emit(
    tokens: &mut Vec<Token>,
    cursor: &Cursor<'_>,
    limits: &CompileLimits,
    start_byte: usize,
    start: SourcePosition,
    kind: TokenKind,
    literal: Option<Literal>,
) -> Result<(), Diagnostic> {
    push_token(
        tokens,
        Token {
            kind,
            span: Span {
                start_byte,
                end_byte: cursor.offset(),
            },
            start,
            end: cursor.position(),
            literal,
        },
        limits,
        cursor,
    )
}

fn advance(
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    start_byte: usize,
    start: SourcePosition,
) -> Result<(), Diagnostic> {
    cursor.advance(limits).map_err(|message| {
        Diagnostic::at(
            DiagnosticCode::CompileLimit,
            start_byte,
            start,
            cursor,
            message,
        )
    })?;
    if cursor.offset().saturating_sub(start_byte) > limits.max_token_bytes {
        return Err(Diagnostic::at(
            DiagnosticCode::CompileLimit,
            start_byte,
            start,
            cursor,
            "token 超過編譯限制",
        ));
    }
    Ok(())
}

fn append_input_byte(
    bytes: &mut Vec<u8>,
    byte: u8,
    limits: &CompileLimits,
    cursor: &Cursor<'_>,
    start_byte: usize,
    start: SourcePosition,
) -> Result<(), Diagnostic> {
    push_literal_byte(bytes, byte, limits, cursor, start_byte, start)
}

fn consume_number_byte(
    bytes: &mut Vec<u8>,
    cursor: &mut Cursor<'_>,
    limits: &CompileLimits,
    start_byte: usize,
    start: SourcePosition,
) -> Result<(), Diagnostic> {
    append_input_byte(
        bytes,
        cursor.peek().unwrap(),
        limits,
        cursor,
        start_byte,
        start,
    )?;
    advance(cursor, limits, start_byte, start)
}

fn push_literal_byte(
    bytes: &mut Vec<u8>,
    byte: u8,
    limits: &CompileLimits,
    cursor: &Cursor<'_>,
    start_byte: usize,
    start: SourcePosition,
) -> Result<(), Diagnostic> {
    if bytes.len() >= limits.max_token_bytes {
        return Err(Diagnostic::at(
            DiagnosticCode::CompileLimit,
            start_byte,
            start,
            cursor,
            "literal 超過編譯限制",
        ));
    }
    bytes.push(byte);
    Ok(())
}

fn keyword(cursor: &Cursor<'_>, name: &[u8]) -> Option<Keyword> {
    let keyword = match name {
        b"and" => Keyword::And,
        b"break" => Keyword::Break,
        b"do" => Keyword::Do,
        b"else" => Keyword::Else,
        b"elseif" => Keyword::ElseIf,
        b"end" => Keyword::End,
        b"false" => Keyword::False,
        b"for" => Keyword::For,
        b"function" => Keyword::Function,
        b"goto" => Keyword::Goto,
        b"if" => Keyword::If,
        b"in" => Keyword::In,
        b"local" => Keyword::Local,
        b"nil" => Keyword::Nil,
        b"not" => Keyword::Not,
        b"or" => Keyword::Or,
        b"repeat" => Keyword::Repeat,
        b"return" => Keyword::Return,
        b"then" => Keyword::Then,
        b"true" => Keyword::True,
        b"until" => Keyword::Until,
        b"while" => Keyword::While,
        b"global" if cursor.profile() == super::LanguageProfile::Lua55 => Keyword::Global,
        _ => return None,
    };
    Some(keyword)
}

fn parse_number(bytes: &[u8]) -> Result<Number, &'static str> {
    let text = core::str::from_utf8(bytes).map_err(|_| "numeral 不是 ASCII")?;
    let hexadecimal = text.starts_with("0x") || text.starts_with("0X");
    if hexadecimal {
        let body = &text[2..];
        let float_form = body.contains(['.', 'p', 'P']);
        if !float_form {
            let mut value = 0u64;
            for byte in body.bytes() {
                let digit = u64::from(hex_value(byte).ok_or("十六進位 numeral 不合法")?);
                value = value.wrapping_mul(16).wrapping_add(digit);
            }
            return Ok(Number::Integer(value as i64));
        }
        let (mantissa, exponent) = match body.find(['p', 'P']) {
            Some(index) => (
                &body[..index],
                body[index + 1..]
                    .parse::<i32>()
                    .map_err(|_| "十六進位 exponent 不合法")?,
            ),
            None => (body, 0),
        };
        let mut value = 0.0f64;
        let mut fractional = false;
        let mut scale = 1.0f64;
        for byte in mantissa.bytes() {
            if byte == b'.' {
                if fractional {
                    return Err("十六進位小數點不合法");
                }
                fractional = true;
                continue;
            }
            let digit = hex_value(byte).ok_or("十六進位 numeral 不合法")? as f64;
            if fractional {
                scale /= 16.0;
                value += digit * scale;
            } else {
                value = value * 16.0 + digit;
            }
        }
        let value = value * 2f64.powi(exponent);
        return value
            .is_finite()
            .then_some(Number::Float(value))
            .ok_or("十六進位浮點數超出範圍");
    }
    if text.contains(['.', 'e', 'E']) {
        let value = text.parse::<f64>().map_err(|_| "浮點 numeral 不合法")?;
        return value
            .is_finite()
            .then_some(Number::Float(value))
            .ok_or("浮點數超出範圍");
    }
    match text.parse::<i64>() {
        Ok(value) => Ok(Number::Integer(value)),
        Err(_) => {
            let value = text.parse::<f64>().map_err(|_| "整數 numeral 不合法")?;
            value
                .is_finite()
                .then_some(Number::Float(value))
                .ok_or("整數超出範圍")
        }
    }
}

fn lex_error(
    cursor: &Cursor<'_>,
    start_byte: usize,
    start: SourcePosition,
    message: &'static str,
) -> Diagnostic {
    Diagnostic::at(DiagnosticCode::Lex, start_byte, start, cursor, message)
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | 0x0b | 0x0c | b'\n' | b'\r')
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_name_continue(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
