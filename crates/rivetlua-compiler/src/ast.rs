//! P03 擁有資料的語法樹。
use crate::{LanguageProfile, Literal, Span};

#[derive(Clone, Debug, PartialEq)]
pub struct Module {
    pub profile: LanguageProfile,
    pub span: Span,
    pub root: Block,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub statements: Vec<Stmt>,
    pub terminator: Option<Span>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Empty {
        span: Span,
    },
    Return {
        values: Vec<Expr>,
        span: Span,
    },
    Assignment {
        targets: Vec<Expr>,
        values: Vec<Expr>,
        span: Span,
    },
    Call {
        call: Expr,
        span: Span,
    },
    Local {
        names: Vec<LocalName>,
        values: Vec<Expr>,
        span: Span,
    },
    Global {
        declaration: GlobalDeclaration,
        span: Span,
    },
    Break {
        span: Span,
    },
    Goto {
        name: Vec<u8>,
        name_span: Span,
        span: Span,
    },
    Label {
        name: Vec<u8>,
        name_span: Span,
        span: Span,
    },
    Do {
        body: Block,
        span: Span,
    },
    If {
        clauses: Vec<(Expr, Block)>,
        else_block: Option<Block>,
        span: Span,
    },
    While {
        condition: Expr,
        body: Block,
        span: Span,
    },
    Repeat {
        body: Block,
        condition: Expr,
        span: Span,
    },
    NumericFor {
        name: LocalName,
        initial: Expr,
        limit: Expr,
        step: Option<Expr>,
        body: Block,
        span: Span,
    },
    GenericFor {
        names: Vec<LocalName>,
        values: Vec<Expr>,
        body: Block,
        span: Span,
    },
    Function {
        name: Expr,
        method: Option<MethodName>,
        body: FunctionBody,
        span: Span,
    },
    LocalFunction {
        name: LocalName,
        body: FunctionBody,
        span: Span,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub struct MethodName {
    pub name: Vec<u8>,
    pub colon_span: Span,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LocalName {
    pub name: Vec<u8>,
    pub attribute: Option<Attribute>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub name: Vec<u8>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub enum GlobalDeclaration {
    Names {
        names: Vec<LocalName>,
        values: Vec<Expr>,
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Star {
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Function {
        name: Vec<u8>,
        body: FunctionBody,
        span: Span,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSeparator {
    Comma,
    Semicolon,
}
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionBody {
    pub parameters: Vec<LocalName>,
    pub vararg: Option<Vararg>,
    pub body: Block,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Vararg {
    pub table_name: Option<LocalName>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Literal {
        literal: Literal,
        span: Span,
    },
    Nil {
        span: Span,
    },
    Bool {
        value: bool,
        span: Span,
    },
    Name {
        name: Vec<u8>,
        span: Span,
    },
    Vararg {
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expression: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
    Paren {
        expression: Box<Expr>,
        span: Span,
    },
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    Field {
        base: Box<Expr>,
        name: Vec<u8>,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        arguments: Vec<Expr>,
        span: Span,
    },
    MethodCall {
        receiver: Box<Expr>,
        method: Vec<u8>,
        arguments: Vec<Expr>,
        span: Span,
    },
    Function {
        body: FunctionBody,
        span: Span,
    },
    TableConstructor {
        fields: Vec<TableField>,
        span: Span,
    },
}
#[derive(Clone, Debug, PartialEq)]
pub enum TableField {
    Array {
        value: Expr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
    Named {
        name: Vec<u8>,
        value: Expr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
    Indexed {
        key: Expr,
        value: Expr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
}
impl TableField {
    pub fn set_separator(&mut self, separator: FieldSeparator) {
        match self {
            Self::Array {
                separator: slot, ..
            }
            | Self::Named {
                separator: slot, ..
            }
            | Self::Indexed {
                separator: slot, ..
            } => *slot = Some(separator),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOp {
    Negate,
    Not,
    Length,
    BitNot,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOp {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Pipe,
    BitXor,
    Ampersand,
    ShiftLeft,
    ShiftRight,
    Concat,
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    Modulo,
    Power,
}
impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Self::Literal { span, .. }
            | Self::Nil { span }
            | Self::Bool { span, .. }
            | Self::Name { span, .. }
            | Self::Vararg { span }
            | Self::Unary { span, .. }
            | Self::Binary { span, .. }
            | Self::Paren { span, .. }
            | Self::Index { span, .. }
            | Self::Field { span, .. }
            | Self::Call { span, .. }
            | Self::MethodCall { span, .. }
            | Self::Function { span, .. }
            | Self::TableConstructor { span, .. } => *span,
        }
    }
}
