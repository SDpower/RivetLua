//! P02 byte-slice lexer 入口。

mod cursor;
mod scanner;

use cursor::Cursor;

/// 支援的 Lua 語言 profile。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanguageProfile {
    Lua55,
    Lua54,
}

/// 不受信任編譯輸入的固定上限。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    pub max_source_bytes: usize,
    pub max_token_bytes: usize,
    pub max_tokens: usize,
    pub max_lines: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 1024 * 1024,
            max_token_bytes: 64 * 1024,
            max_tokens: 100_000,
            max_lines: 100_000,
        }
    }
}

/// 可由呼叫端檢查的詞法診斷類別。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCode {
    Lex,
    CompileLimit,
}

/// 不持有完整輸入的詞法診斷。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub span: Span,
    pub start: SourcePosition,
    pub end: SourcePosition,
    pub message: &'static str,
}

impl Diagnostic {
    pub(in crate::lexer) fn at(
        code: DiagnosticCode,
        start_byte: usize,
        start: SourcePosition,
        cursor: &Cursor<'_>,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            span: Span {
                start_byte,
                end_byte: cursor.offset(),
            },
            start,
            end: cursor.position(),
            message,
        }
    }
}

/// 原始 bytes 的半開來源範圍。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// 1 起算的來源位置。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePosition {
    pub line: usize,
    pub column: usize,
}

/// 保留字種類。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Keyword {
    And,
    Break,
    Do,
    Else,
    ElseIf,
    End,
    False,
    For,
    Function,
    Goto,
    If,
    In,
    Local,
    Nil,
    Not,
    Or,
    Repeat,
    Return,
    Then,
    True,
    Until,
    While,
    Global,
}

/// 標點及運算子種類。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    Plus,
    Minus,
    Star,
    Slash,
    FloorSlash,
    Percent,
    Caret,
    Hash,
    Ampersand,
    Pipe,
    Tilde,
    ShiftLeft,
    ShiftRight,
    EqualEqual,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Assign,
    OpenParen,
    CloseParen,
    OpenBrace,
    CloseBrace,
    OpenBracket,
    CloseBracket,
    Semicolon,
    Colon,
    DoubleColon,
    Comma,
    Dot,
    Concat,
    Vararg,
}

/// 只有具 payload 的 token 才能保存 literal。
#[derive(Clone, Debug, PartialEq)]
pub enum Literal {
    Name(Vec<u8>),
    Integer(rivetlua_core::Number),
    Float(rivetlua_core::Number),
    String(Vec<u8>),
}

/// 詞法種類。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Eof,
    Keyword(Keyword),
    Name,
    Integer,
    Float,
    String,
    Symbol(Symbol),
}

/// P03 可直接消費的 token 資料。
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub start: SourcePosition,
    pub end: SourcePosition,
    pub literal: Option<Literal>,
}

/// 一次成功 lex 的完整 token 串流，末尾必有 EOF。
#[derive(Clone, Debug, PartialEq)]
pub struct LexedChunk {
    pub profile: LanguageProfile,
    pub source_len: usize,
    pub tokens: Vec<Token>,
}

/// 將原始 bytes 掃描成詞法資料。此入口不會先將輸入轉為 UTF-8。
pub fn lex(
    input: &[u8],
    profile: LanguageProfile,
    limits: &CompileLimits,
) -> Result<LexedChunk, Diagnostic> {
    if input.len() > limits.max_source_bytes {
        return Err(Diagnostic {
            code: DiagnosticCode::CompileLimit,
            span: Span {
                start_byte: 0,
                end_byte: 0,
            },
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 1 },
            message: "來源超過編譯限制",
        });
    }
    let mut cursor = Cursor::new(input, profile);
    scanner::scan(&mut cursor, limits)
}

pub(in crate::lexer) fn push_token(
    tokens: &mut Vec<Token>,
    token: Token,
    limits: &CompileLimits,
    cursor: &Cursor<'_>,
) -> Result<(), Diagnostic> {
    if tokens.len() >= limits.max_tokens {
        return Err(Diagnostic::at(
            DiagnosticCode::CompileLimit,
            token.span.start_byte,
            token.start,
            cursor,
            "token 數超過編譯限制",
        ));
    }
    tokens.push(token);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CompileLimits, DiagnosticCode, LanguageProfile, Literal, Symbol, TokenKind, lex};
    use rivetlua_core::Number;

    #[test]
    fn empty_input_has_eof_at_first_position() {
        let chunk = lex(b"", LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        assert_eq!(chunk.tokens.len(), 1);
        assert_eq!(chunk.tokens[0].kind, TokenKind::Eof);
        assert_eq!(
            chunk.tokens[0].span,
            super::Span {
                start_byte: 0,
                end_byte: 0
            }
        );
    }

    #[test]
    fn all_logical_newline_forms_increment_once() {
        let chunk = lex(
            b"\n \r \r\n \n\r",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap();
        let eof = &chunk.tokens[0];
        assert_eq!((eof.span.end_byte, eof.end.line, eof.end.column), (9, 5, 1));
    }

    #[test]
    fn source_and_line_limits_fail_before_overflow() {
        let limits = CompileLimits {
            max_source_bytes: 2,
            ..CompileLimits::default()
        };
        assert_eq!(
            lex(b"   ", LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
        let limits = CompileLimits {
            max_lines: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            lex(b"\n", LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
    }

    #[test]
    fn unknown_byte_has_stopping_span() {
        let error = lex(b"@", LanguageProfile::Lua55, &CompileLimits::default()).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Lex);
        assert_eq!(
            error.span,
            super::Span {
                start_byte: 0,
                end_byte: 1
            }
        );
        assert_eq!(error.start, super::SourcePosition { line: 1, column: 1 });
        assert_eq!(error.end, super::SourcePosition { line: 1, column: 2 });
    }

    #[test]
    fn numerals_keep_p01_subtypes_and_reject_bad_forms() {
        let chunk = lex(
            b"0x10 1.5 0x1.8p1",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(
            chunk.tokens[0].literal,
            Some(Literal::Integer(Number::Integer(16)))
        );
        assert_eq!(
            chunk.tokens[1].literal,
            Some(Literal::Float(Number::Float(1.5)))
        );
        assert_eq!(
            chunk.tokens[2].literal,
            Some(Literal::Float(Number::Float(3.0)))
        );
        assert_eq!(
            lex(b"123abc", LanguageProfile::Lua55, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Lex
        );
        assert_eq!(
            lex(b"1e+", LanguageProfile::Lua55, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Lex
        );
    }

    #[test]
    fn strings_and_operators_are_lexed_without_runtime_values() {
        let chunk = lex(
            b"\"\\x41\\000B\" // .. ... == <= >= ~= << >> ::",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(
            chunk.tokens[0].literal,
            Some(Literal::String(vec![0x41, 0x00, 0x42]))
        );
        assert_eq!(chunk.tokens[1].kind, TokenKind::Symbol(Symbol::FloorSlash));
        assert_eq!(chunk.tokens[2].kind, TokenKind::Symbol(Symbol::Concat));
        assert_eq!(chunk.tokens[3].kind, TokenKind::Symbol(Symbol::Vararg));
        assert_eq!(
            chunk.tokens[10].kind,
            TokenKind::Symbol(Symbol::DoubleColon)
        );
    }

    #[test]
    fn long_delimiters_require_the_same_separator_count() {
        let chunk = lex(
            b"[=[abc]=]",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap();
        assert_eq!(
            chunk.tokens[0].literal,
            Some(Literal::String(b"abc".to_vec()))
        );
        assert_eq!(
            lex(
                b"[=[abc]]",
                LanguageProfile::Lua55,
                &CompileLimits::default()
            )
            .unwrap_err()
            .code,
            DiagnosticCode::Lex
        );
    }
}
