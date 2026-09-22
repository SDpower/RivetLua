//! RivetLua 編譯器前端。

#![forbid(unsafe_code)]

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod resolve;

pub use ast::*;
pub use lexer::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, LexedChunk, Literal,
    SourcePosition, Span, Symbol, Token, TokenKind, lex,
};
pub use parser::parse;
pub use resolve::*;
