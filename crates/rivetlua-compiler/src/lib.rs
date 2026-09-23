//! RivetLua 編譯器前端。

#![forbid(unsafe_code)]

pub mod ast;
pub mod codegen;
pub mod ir;
pub mod lexer;
pub mod parser;
pub mod resolve;

pub use ast::*;
pub use codegen::{IrError, emit, lower};
pub use ir::*;
pub use lexer::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, LexedChunk, Literal,
    SourcePosition, Span, Symbol, Token, TokenKind, lex,
};
pub use parser::parse;
pub use resolve::*;
pub use rivetlua_core::{
    BinaryOperation, BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeError,
    BytecodeErrorCode, BytecodeExitKind, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, BytecodeVersion, ConstId, ControlFlow,
    EncodedModule, EnvironmentSource, FrameLayout, Instruction, InstructionEffects,
    InstructionOffset, IrLimits, LuaProfile, Opcode, ProfileRequirement, ProtoId, RVLU_MAGIC,
    RVLU_NUMERIC_I64_F64, RVLU_V1, RVLU_V2, Register, RegisterEffects, ResultMode, UnaryOperation,
    UpvalueId, VerifiedModule, VerifyLimits, decode_module, encode_module, verify_module,
};
