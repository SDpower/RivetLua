//! P03 擁有資料的語法樹。
use crate::{LanguageProfile, Literal, Span};
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::StateAllocator;
pub type AstVec<T> = AllocVec<T, StateAllocator>;
pub type AstBox<T> = rivetlua_alloc::SharedBlock<T>;

/// SDK 建構公開 AST fixture 時，明確選擇全域配置。
pub fn try_global_ast_vec<T>(values: Vec<T>) -> Option<AstVec<T>> {
    let mut output = AstVec::new_in(StateAllocator::Global);
    output.try_reserve_exact(values.len()).ok()?;
    output.extend(values);
    Some(output)
}
pub type AstName = crate::lexer::SharedBytes;

#[derive(Clone, Debug, PartialEq)]
pub struct Module {
    pub profile: LanguageProfile,
    pub span: Span,
    pub root: Block,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub statements: AstVec<Stmt>,
    pub terminator: Option<Span>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Empty {
        span: Span,
    },
    Return {
        values: AstVec<Expr>,
        span: Span,
    },
    Assignment {
        targets: AstVec<Expr>,
        values: AstVec<Expr>,
        span: Span,
    },
    Call {
        call: Expr,
        span: Span,
    },
    Local {
        names: AstVec<LocalName>,
        values: AstVec<Expr>,
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
        name: AstName,
        name_span: Span,
        span: Span,
    },
    Label {
        name: AstName,
        name_span: Span,
        span: Span,
    },
    Do {
        body: Block,
        span: Span,
    },
    If {
        clauses: AstVec<(Expr, Block)>,
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
        names: AstVec<LocalName>,
        values: AstVec<Expr>,
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
    pub name: AstName,
    pub colon_span: Span,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LocalName {
    pub name: AstName,
    pub attribute: Option<Attribute>,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub name: AstName,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq)]
pub enum GlobalDeclaration {
    Names {
        names: AstVec<LocalName>,
        values: AstVec<Expr>,
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Star {
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Function {
        name: AstName,
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
    pub parameters: AstVec<LocalName>,
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
        name: AstName,
        span: Span,
    },
    Vararg {
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expression: AstBox<Expr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: AstBox<Expr>,
        right: AstBox<Expr>,
        span: Span,
    },
    Paren {
        expression: AstBox<Expr>,
        span: Span,
    },
    Index {
        base: AstBox<Expr>,
        index: AstBox<Expr>,
        span: Span,
    },
    Field {
        base: AstBox<Expr>,
        name: AstName,
        span: Span,
    },
    Call {
        callee: AstBox<Expr>,
        arguments: AstVec<Expr>,
        span: Span,
    },
    MethodCall {
        receiver: AstBox<Expr>,
        method: AstName,
        arguments: AstVec<Expr>,
        span: Span,
    },
    Function {
        body: FunctionBody,
        span: Span,
    },
    TableConstructor {
        fields: AstVec<TableField>,
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
        name: AstName,
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
