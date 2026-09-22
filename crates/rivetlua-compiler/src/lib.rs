//! RivetLua 編譯器前端。

#![forbid(unsafe_code)]

pub mod lexer;

pub use lexer::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, LexedChunk, Literal,
    SourcePosition, Span, Symbol, Token, TokenKind, lex,
};
