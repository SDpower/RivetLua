//! C 載入文字 chunk 的官方診斷所需之短期失敗資料；不改公開 Diagnostic。

use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::StateAllocator;

use crate::{AstName, Keyword, Span, Symbol, Token, TokenKind};

#[doc(hidden)]
#[derive(Debug)]
pub enum OfficialFailureReason {
    Expected {
        token: TokenKind,
        opener: Option<(TokenKind, usize)>,
    },
    Text(&'static [u8]),
    LongUnfinished { comment: bool, opener_line: usize },
    BreakOutside { line: usize, span: Span },
    AssignConst { name: AstName, span: Span },
    GotoMissing { name: AstName, line: usize, span: Span },
    GotoIntoScope { label: AstName, variable: Option<AstName>, line: usize, span: Span },
    EnvironmentGlobal { name: AstName, span: Span },
    VariableUndeclared { name: AstName, span: Span },
    LabelDuplicate { name: AstName, previous: Span, previous_line: usize, span: Span },
    MultipleClose { span: Span },
    UnknownAttribute { name: AstName },
}

#[doc(hidden)]
#[derive(Debug)]
pub enum OfficialFailureNear {
    None,
    Eof,
    RawSymbol(u8),
    LongDelimiter(usize),
    Token(Token),
    Scanner(AllocVec<u8, StateAllocator>),
    ScannerSuffix(AllocVec<u8, StateAllocator>, u8),
    ShortString { quote: u8, cooked: AllocVec<u8, StateAllocator>,
        suffix: Option<(usize, usize)> },
}

#[doc(hidden)]
#[derive(Debug)]
pub struct OfficialFailure {
    pub reason: OfficialFailureReason,
    pub line: usize,
    pub near: OfficialFailureNear,
}

#[doc(hidden)]
pub fn official_token_text(token: TokenKind) -> &'static [u8] {
    match token {
        TokenKind::Eof => b"<eof>",
        TokenKind::Name => b"<name>",
        TokenKind::Integer => b"<integer>",
        TokenKind::Float => b"<number>",
        TokenKind::String => b"<string>",
        TokenKind::Keyword(keyword) => match keyword {
            Keyword::And => b"and", Keyword::Break => b"break", Keyword::Do => b"do",
            Keyword::Else => b"else", Keyword::ElseIf => b"elseif", Keyword::End => b"end",
            Keyword::False => b"false", Keyword::For => b"for", Keyword::Function => b"function",
            Keyword::Goto => b"goto", Keyword::If => b"if", Keyword::In => b"in",
            Keyword::Local => b"local", Keyword::Nil => b"nil", Keyword::Not => b"not",
            Keyword::Or => b"or", Keyword::Repeat => b"repeat", Keyword::Return => b"return",
            Keyword::Then => b"then", Keyword::True => b"true", Keyword::Until => b"until",
            Keyword::While => b"while", Keyword::Global => b"global",
        },
        TokenKind::Symbol(symbol) => match symbol {
            Symbol::Plus => b"+", Symbol::Minus => b"-", Symbol::Star => b"*",
            Symbol::Slash => b"/", Symbol::FloorSlash => b"//", Symbol::Percent => b"%",
            Symbol::Caret => b"^", Symbol::Hash => b"#", Symbol::Ampersand => b"&",
            Symbol::Pipe => b"|", Symbol::Tilde => b"~", Symbol::ShiftLeft => b"<<",
            Symbol::ShiftRight => b">>", Symbol::EqualEqual => b"==", Symbol::NotEqual => b"~=",
            Symbol::Less => b"<", Symbol::LessEqual => b"<=", Symbol::Greater => b">",
            Symbol::GreaterEqual => b">=", Symbol::Assign => b"=", Symbol::OpenParen => b"(",
            Symbol::CloseParen => b")", Symbol::OpenBrace => b"{", Symbol::CloseBrace => b"}",
            Symbol::OpenBracket => b"[", Symbol::CloseBracket => b"]", Symbol::Semicolon => b";",
            Symbol::Colon => b":", Symbol::DoubleColon => b"::", Symbol::Comma => b",",
            Symbol::Dot => b".", Symbol::Concat => b"..", Symbol::Vararg => b"...",
        },
    }
}
