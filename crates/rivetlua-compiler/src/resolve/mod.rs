//! P04 名稱與作用域解析；只消費 P03 owned AST 與 P02 位置資料。

use crate::{
    Attribute, BinaryOp, Block, CompileLimits, Diagnostic, DiagnosticCode, Expr, FieldSeparator,
    FunctionBody, GlobalDeclaration, LanguageProfile, LexedChunk, Literal, LocalName, MethodName,
    Module, SourcePosition, Span, Stmt, TableField, Token, TokenKind, UnaryOp,
};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FunctionId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BindingId {
    pub function: FunctionId,
    pub ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpvalueId(pub u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpvalueSource {
    ParentLocal(BindingId),
    ParentUpvalue(UpvalueId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
    Local,
    Parameter,
    NumericFor,
    GenericFor,
    GenericForClose,
    LocalFunction,
    VarargTable,
    Environment,
    Global,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BindingMeta {
    pub id: BindingId,
    pub name: Vec<u8>,
    pub span: Span,
    pub kind: BindingKind,
    pub owner: FunctionId,
    pub scope_depth: usize,
    pub readonly: bool,
    pub attribute: Option<Attribute>,
    pub close_marker: Option<Span>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedName {
    Local(BindingId),
    Upvalue(UpvalueId),
    EnvField { env: BindingId, name: Vec<u8> },
    Global(BindingId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScopeId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitKind {
    Normal,
    Return,
    Break,
    Goto,
    Error,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedModule {
    pub profile: LanguageProfile,
    pub span: Span,
    pub root: ResolvedBlock,
    pub functions: Vec<ResolvedFunction>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedFunction {
    pub id: FunctionId,
    pub parent: Option<FunctionId>,
    pub span: Span,
    pub bindings: Vec<BindingMeta>,
    pub upvalues: Vec<UpvalueSource>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedBlock {
    pub scope: ScopeId,
    pub statements: Vec<ResolvedStmt>,
    pub terminator: Option<Span>,
    pub span: Span,
    pub normal_close_path: ClosePath,
    pub error_close_path: ClosePath,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClosePath {
    pub kind: ExitKind,
    pub span: Span,
    pub from_scope: ScopeId,
    pub target_scope: Option<ScopeId>,
    pub bindings: Vec<BindingId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedLocalName {
    pub binding: BindingId,
    pub name: Vec<u8>,
    pub attribute: Option<Attribute>,
    pub span: Span,
}

/// generic-for 第四個 evaluation value 的隱藏待關閉 binding。
///
/// 此 binding 不會加入 Lua 名稱查找表；P05 必須直接消費此 owned metadata，
/// 不能由 AST 或來源重新推導。
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedGenericForClose {
    pub binding: BindingId,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedFunctionBody {
    pub function: FunctionId,
    pub parameters: Vec<ResolvedLocalName>,
    pub vararg: Option<ResolvedVararg>,
    pub body: Box<ResolvedBlock>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedVararg {
    pub table_binding: Option<BindingId>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedIfClause {
    pub condition: ResolvedExpr,
    pub body: ResolvedBlock,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedGlobalDeclaration {
    Names {
        names: Vec<ResolvedLocalName>,
        values: Vec<ResolvedExpr>,
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Star {
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Function {
        binding: BindingId,
        name: Vec<u8>,
        body: ResolvedFunctionBody,
        span: Span,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedStmt {
    Empty {
        span: Span,
    },
    Return {
        values: Vec<ResolvedExpr>,
        close_path: ClosePath,
        span: Span,
    },
    Assignment {
        targets: Vec<ResolvedExpr>,
        values: Vec<ResolvedExpr>,
        span: Span,
    },
    Call {
        call: ResolvedExpr,
        span: Span,
    },
    Local {
        bindings: Vec<BindingId>,
        names: Vec<ResolvedLocalName>,
        values: Vec<ResolvedExpr>,
        span: Span,
    },
    Global {
        declaration: ResolvedGlobalDeclaration,
        span: Span,
    },
    Break {
        close_path: ClosePath,
        span: Span,
    },
    Goto {
        name: Vec<u8>,
        name_span: Span,
        close_path: ClosePath,
        span: Span,
    },
    Label {
        name: Vec<u8>,
        name_span: Span,
        span: Span,
    },
    Do {
        body: ResolvedBlock,
        span: Span,
    },
    If {
        clauses: Vec<ResolvedIfClause>,
        else_block: Option<ResolvedBlock>,
        span: Span,
    },
    While {
        condition: ResolvedExpr,
        body: ResolvedBlock,
        span: Span,
    },
    Repeat {
        body: ResolvedBlock,
        condition: ResolvedExpr,
        span: Span,
    },
    NumericFor {
        name: ResolvedLocalName,
        initial: ResolvedExpr,
        limit: ResolvedExpr,
        step: Option<ResolvedExpr>,
        body: ResolvedBlock,
        span: Span,
    },
    GenericFor {
        names: Vec<ResolvedLocalName>,
        values: Vec<ResolvedExpr>,
        closing: ResolvedGenericForClose,
        body: ResolvedBlock,
        close_path: ClosePath,
        span: Span,
    },
    Function {
        name: ResolvedExpr,
        method: Option<MethodName>,
        body: ResolvedFunctionBody,
        span: Span,
    },
    LocalFunction {
        name: ResolvedLocalName,
        body: ResolvedFunctionBody,
        span: Span,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedExpr {
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
        resolution: ResolvedName,
        span: Span,
    },
    Vararg {
        binding: Option<BindingId>,
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expression: Box<ResolvedExpr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: Box<ResolvedExpr>,
        right: Box<ResolvedExpr>,
        span: Span,
    },
    Paren {
        expression: Box<ResolvedExpr>,
        span: Span,
    },
    Index {
        base: Box<ResolvedExpr>,
        index: Box<ResolvedExpr>,
        span: Span,
    },
    Field {
        base: Box<ResolvedExpr>,
        name: Vec<u8>,
        span: Span,
    },
    Call {
        callee: Box<ResolvedExpr>,
        arguments: Vec<ResolvedExpr>,
        span: Span,
    },
    MethodCall {
        receiver: Box<ResolvedExpr>,
        method: Vec<u8>,
        arguments: Vec<ResolvedExpr>,
        span: Span,
    },
    Function {
        body: ResolvedFunctionBody,
        span: Span,
    },
    TableConstructor {
        fields: Vec<ResolvedTableField>,
        span: Span,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedTableField {
    Array {
        value: ResolvedExpr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
    Named {
        name: Vec<u8>,
        value: ResolvedExpr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
    Indexed {
        key: ResolvedExpr,
        value: ResolvedExpr,
        separator: Option<FieldSeparator>,
        span: Span,
    },
}

/// 將 P03 AST 連結為 P04 owned resolved AST；不重掃來源 bytes。
pub fn resolve(
    module: &Module,
    lexed: &LexedChunk,
    expected_profile: LanguageProfile,
    limits: &CompileLimits,
) -> Result<ResolvedModule, Diagnostic> {
    validate_input(module, lexed, expected_profile)?;
    let mut resolver = Resolver {
        lexed,
        limits,
        profile: expected_profile,
        owner: FunctionId(0),
        next_binding: 0,
        next_function: 1,
        next_scope: 0,
        bindings: Vec::new(),
        upvalues: Vec::new(),
        upvalue_ids: HashMap::new(),
        upvalue_bindings: Vec::new(),
        pending_ancestor_captures: Vec::new(),
        scopes: Vec::new(),
        loops: Vec::new(),
        parent_metadata: HashMap::new(),
        vararg_available: false,
        vararg_binding: None,
        label_count: 0,
        goto_count: 0,
        parent_visible: None,
        inherited_global_mode: None,
        implicit_globals: HashMap::new(),
        completed_functions: Vec::new(),
    };
    resolver.enter_scope(module.span)?;
    resolver.declare_binding(
        b"_ENV".to_vec(),
        module.span,
        None,
        BindingKind::Environment,
        false,
    )?;
    let root = resolver.resolve_block(&module.root)?;
    resolver.scopes.pop();
    let mut functions = vec![ResolvedFunction {
        id: resolver.owner,
        parent: None,
        span: module.span,
        bindings: resolver.bindings,
        upvalues: resolver.upvalues,
    }];
    functions.extend(resolver.completed_functions);
    Ok(ResolvedModule {
        profile: expected_profile,
        span: module.span,
        root,
        functions,
    })
}

fn validate_input(
    module: &Module,
    lexed: &LexedChunk,
    expected_profile: LanguageProfile,
) -> Result<(), Diagnostic> {
    let Some(eof) = lexed.tokens.last() else {
        return Err(diagnostic(
            None,
            DiagnosticCode::Resolve,
            "token 串流缺少 EOF",
        ));
    };
    if module.profile != expected_profile || lexed.profile != expected_profile {
        return Err(diagnostic(
            Some(eof),
            DiagnosticCode::Resolve,
            "語言 profile 不符",
        ));
    }
    if module.span.end_byte != lexed.source_len {
        return Err(diagnostic(
            Some(eof),
            DiagnosticCode::Resolve,
            "module 與來源長度不符",
        ));
    }
    if eof.kind != TokenKind::Eof
        || eof.span.start_byte != lexed.source_len
        || eof.span.end_byte != lexed.source_len
    {
        return Err(diagnostic(
            Some(eof),
            DiagnosticCode::Resolve,
            "token 串流 EOF 不符",
        ));
    }
    Ok(())
}

struct Resolver<'a> {
    lexed: &'a LexedChunk,
    limits: &'a CompileLimits,
    profile: LanguageProfile,
    owner: FunctionId,
    next_binding: usize,
    next_function: u32,
    next_scope: u32,
    bindings: Vec<BindingMeta>,
    upvalues: Vec<UpvalueSource>,
    upvalue_ids: HashMap<BindingId, UpvalueId>,
    upvalue_bindings: Vec<BindingId>,
    pending_ancestor_captures: Vec<(BindingId, UpvalueId)>,
    scopes: Vec<ScopeFrame>,
    loops: Vec<ScopeId>,
    parent_metadata: HashMap<BindingId, BindingAccess>,
    vararg_available: bool,
    vararg_binding: Option<BindingId>,
    label_count: usize,
    goto_count: usize,
    parent_visible: Option<HashMap<Vec<u8>, ParentBinding>>,
    inherited_global_mode: Option<bool>,
    implicit_globals: HashMap<Vec<u8>, BindingId>,
    completed_functions: Vec<ResolvedFunction>,
}

struct ScopeFrame {
    id: ScopeId,
    bindings: HashMap<Vec<u8>, BindingId>,
    close_bindings: Vec<BindingId>,
    labels: HashMap<Vec<u8>, LabelInfo>,
    declaration_spans: Vec<Span>,
    // Some(true) 是只允許已宣告名稱的 explicit global scope；Some(false) 是 global *。
    global_mode: Option<bool>,
}

#[derive(Clone, Copy)]
struct BindingAccess {
    readonly: bool,
}

#[derive(Clone, Copy)]
struct LabelInfo {
    scope: ScopeId,
    span: Span,
}

#[derive(Clone, Copy)]
enum ParentBinding {
    Direct(BindingId),
    Ancestor(BindingId),
    Global(BindingId),
}

impl<'a> Resolver<'a> {
    fn enter_scope(&mut self, span: Span) -> Result<(), Diagnostic> {
        if self.scopes.len() >= self.limits.max_scope_depth {
            return Err(self.limit(span, "作用域深度超過編譯限制"));
        }
        let ordinal = self
            .next_scope
            .checked_add(1)
            .ok_or_else(|| self.limit(span, "作用域數超過編譯限制"))?;
        let id = ScopeId(self.next_scope);
        self.next_scope = ordinal;
        self.scopes.push(ScopeFrame {
            id,
            bindings: HashMap::new(),
            close_bindings: Vec::new(),
            labels: HashMap::new(),
            declaration_spans: Vec::new(),
            global_mode: None,
        });
        Ok(())
    }

    fn resolve_block(&mut self, block: &Block) -> Result<ResolvedBlock, Diagnostic> {
        if block.statements.len() > self.limits.max_statements
            || block.statements.len() > self.limits.max_ast_nodes
        {
            return Err(self.limit(block.span, "陳述式數超過編譯限制"));
        }
        self.register_labels(block)?;
        self.validate_block_gotos(block)?;
        let mut statements = Vec::new();
        statements
            .try_reserve(block.statements.len())
            .map_err(|_| self.limit(block.span, "陳述式配置超過編譯限制"))?;
        for statement in &block.statements {
            statements.push(self.resolve_statement(statement)?);
        }
        let target_scope = self
            .scopes
            .get(self.scopes.len().saturating_sub(2))
            .map(|scope| scope.id);
        Ok(ResolvedBlock {
            scope: self.scopes.last().expect("scope 已建立").id,
            statements,
            terminator: block.terminator,
            span: block.span,
            normal_close_path: self.close_path(ExitKind::Normal, target_scope, block.span),
            error_close_path: self.close_path(ExitKind::Error, None, block.span),
        })
    }

    fn resolve_statement(&mut self, statement: &Stmt) -> Result<ResolvedStmt, Diagnostic> {
        match statement {
            Stmt::Empty { span } => Ok(ResolvedStmt::Empty { span: *span }),
            Stmt::Do { body, span } => Ok(ResolvedStmt::Do {
                body: self.resolve_nested_block(body)?,
                span: *span,
            }),
            Stmt::Local {
                names,
                values,
                span,
            } => {
                self.ensure_list(values.len(), *span)?;
                self.ensure_list(names.len(), *span)?;
                self.ensure_binding_capacity(names.len(), *span)?;
                let mut resolved_values = Vec::new();
                resolved_values
                    .try_reserve(values.len())
                    .map_err(|_| self.limit(*span, "運算式配置超過編譯限制"))?;
                for value in values {
                    resolved_values.push(self.resolve_expr(value)?);
                }
                let mut bindings = Vec::new();
                bindings
                    .try_reserve(names.len())
                    .map_err(|_| self.limit(*span, "binding 配置超過編譯限制"))?;
                for name in names {
                    bindings.push(self.declare_local(
                        name.name.clone(),
                        name.span,
                        name.attribute.clone(),
                    )?);
                }
                let names = names
                    .iter()
                    .zip(bindings.iter().copied())
                    .map(|(name, binding)| ResolvedLocalName {
                        binding,
                        name: name.name.clone(),
                        attribute: name.attribute.clone(),
                        span: name.span,
                    })
                    .collect();
                Ok(ResolvedStmt::Local {
                    bindings,
                    names,
                    values: resolved_values,
                    span: *span,
                })
            }
            Stmt::LocalFunction { name, body, span } => {
                self.ensure_binding_capacity(1, *span)?;
                let binding = self.declare_binding(
                    name.name.clone(),
                    name.span,
                    name.attribute.clone(),
                    BindingKind::LocalFunction,
                    false,
                )?;
                let resolved_name = ResolvedLocalName {
                    binding,
                    name: name.name.clone(),
                    attribute: name.attribute.clone(),
                    span: name.span,
                };
                let body = self.resolve_function_body(body, None)?;
                Ok(ResolvedStmt::LocalFunction {
                    name: resolved_name,
                    body,
                    span: *span,
                })
            }
            Stmt::Return { values, span } => {
                let resolved_values = self.resolve_expression_list(values, *span)?;
                Ok(ResolvedStmt::Return {
                    values: resolved_values,
                    close_path: self.close_path(ExitKind::Return, None, *span),
                    span: *span,
                })
            }
            Stmt::Assignment {
                targets,
                values,
                span,
            } => {
                self.ensure_list(targets.len(), *span)?;
                let mut resolved_targets = Vec::new();
                resolved_targets
                    .try_reserve(targets.len())
                    .map_err(|_| self.limit(*span, "assignment target 配置超過編譯限制"))?;
                for target in targets {
                    resolved_targets.push(self.resolve_assignment_target(target)?);
                }
                Ok(ResolvedStmt::Assignment {
                    targets: resolved_targets,
                    values: self.resolve_expression_list(values, *span)?,
                    span: *span,
                })
            }
            Stmt::Call { call, span } => {
                let call = self.resolve_expr(call)?;
                if !matches!(
                    call,
                    ResolvedExpr::Call { .. } | ResolvedExpr::MethodCall { .. }
                ) {
                    return Err(self.resolve_error(*span, "獨立陳述式必須是 call"));
                }
                Ok(ResolvedStmt::Call { call, span: *span })
            }
            Stmt::Break { span } => {
                let Some(target) = self.loops.last().copied() else {
                    return Err(self.resolve_error(*span, "break 不在 loop 內"));
                };
                Ok(ResolvedStmt::Break {
                    close_path: self.close_path(ExitKind::Break, Some(target), *span),
                    span: *span,
                })
            }
            Stmt::Goto {
                name,
                name_span,
                span,
            } => {
                if self.goto_count >= self.limits.max_gotos {
                    return Err(self.limit(*span, "goto 數超過編譯限制"));
                }
                self.goto_count += 1;
                let label = self
                    .find_label(name)
                    .ok_or_else(|| self.resolve_error(*span, "找不到 goto label"))?;
                Ok(ResolvedStmt::Goto {
                    name: name.clone(),
                    name_span: *name_span,
                    close_path: self.close_path(ExitKind::Goto, Some(label.scope), *span),
                    span: *span,
                })
            }
            Stmt::Label {
                name,
                name_span,
                span,
            } => {
                if self.label_count >= self.limits.max_labels {
                    return Err(self.limit(*span, "label 數超過編譯限制"));
                }
                self.label_count += 1;
                Ok(ResolvedStmt::Label {
                    name: name.clone(),
                    name_span: *name_span,
                    span: *span,
                })
            }
            Stmt::If {
                clauses,
                else_block,
                span,
            } => {
                self.ensure_list(clauses.len(), *span)?;
                let mut resolved_clauses = Vec::new();
                resolved_clauses
                    .try_reserve(clauses.len())
                    .map_err(|_| self.limit(*span, "if clause 配置超過編譯限制"))?;
                for (condition, body) in clauses {
                    resolved_clauses.push(ResolvedIfClause {
                        condition: self.resolve_expr(condition)?,
                        body: self.resolve_nested_block(body)?,
                    });
                }
                Ok(ResolvedStmt::If {
                    clauses: resolved_clauses,
                    else_block: else_block
                        .as_ref()
                        .map(|body| self.resolve_nested_block(body))
                        .transpose()?,
                    span: *span,
                })
            }
            Stmt::While {
                condition,
                body,
                span,
            } => {
                let condition = self.resolve_expr(condition)?;
                let target = self.current_scope();
                self.loops.push(target);
                let body = self.resolve_nested_block(body);
                self.loops.pop();
                Ok(ResolvedStmt::While {
                    condition,
                    body: body?,
                    span: *span,
                })
            }
            Stmt::Repeat {
                body,
                condition,
                span,
            } => self.resolve_repeat(body, condition, *span),
            Stmt::NumericFor {
                name,
                initial,
                limit,
                step,
                body,
                span,
            } => self.resolve_numeric_for(name, initial, limit, step.as_ref(), body, *span),
            Stmt::GenericFor {
                names,
                values,
                body,
                span,
            } => self.resolve_generic_for(names, values, body, *span),
            Stmt::Function {
                name,
                method,
                body,
                span,
            } => Ok(ResolvedStmt::Function {
                name: self.resolve_assignment_target(name)?,
                method: method.clone(),
                body: self.resolve_function_body(body, method.as_ref())?,
                span: *span,
            }),
            Stmt::Global { declaration, span } => self.resolve_global(declaration, *span),
        }
    }

    fn resolve_global(
        &mut self,
        declaration: &GlobalDeclaration,
        span: Span,
    ) -> Result<ResolvedStmt, Diagnostic> {
        if self.profile != LanguageProfile::Lua55 {
            return Err(self.resolve_error(span, "lua54 不支援 lua55 global declaration"));
        }
        match declaration {
            GlobalDeclaration::Star {
                prefix_attribute,
                span,
            } => {
                self.set_explicit_global_mode(false);
                Ok(ResolvedStmt::Global {
                    declaration: ResolvedGlobalDeclaration::Star {
                        prefix_attribute: prefix_attribute.clone(),
                        span: *span,
                    },
                    span: *span,
                })
            }
            GlobalDeclaration::Names {
                names,
                values,
                prefix_attribute,
                span,
            } => {
                self.ensure_list(names.len(), *span)?;
                self.ensure_list(values.len(), *span)?;
                self.ensure_binding_capacity(names.len(), *span)?;
                self.set_explicit_global_mode(true);
                let mut resolved_names = Vec::new();
                resolved_names
                    .try_reserve(names.len())
                    .map_err(|_| self.limit(*span, "global name 配置超過編譯限制"))?;
                for name in names {
                    let binding = self.declare_binding(
                        name.name.clone(),
                        name.span,
                        name.attribute.clone(),
                        BindingKind::Global,
                        false,
                    )?;
                    resolved_names.push(ResolvedLocalName {
                        binding,
                        name: name.name.clone(),
                        attribute: name.attribute.clone(),
                        span: name.span,
                    });
                }
                let values = self.resolve_expression_list(values, *span)?;
                Ok(ResolvedStmt::Global {
                    declaration: ResolvedGlobalDeclaration::Names {
                        names: resolved_names,
                        values,
                        prefix_attribute: prefix_attribute.clone(),
                        span: *span,
                    },
                    span: *span,
                })
            }
            GlobalDeclaration::Function { name, body, span } => {
                self.ensure_binding_capacity(1, *span)?;
                self.set_explicit_global_mode(true);
                let binding =
                    self.declare_binding(name.clone(), *span, None, BindingKind::Global, false)?;
                let body = self.resolve_function_body(body, None)?;
                Ok(ResolvedStmt::Global {
                    declaration: ResolvedGlobalDeclaration::Function {
                        binding,
                        name: name.clone(),
                        body,
                        span: *span,
                    },
                    span: *span,
                })
            }
        }
    }

    fn resolve_expr(&mut self, expression: &Expr) -> Result<ResolvedExpr, Diagnostic> {
        match expression {
            Expr::Literal { literal, span } => Ok(ResolvedExpr::Literal {
                literal: literal.clone(),
                span: *span,
            }),
            Expr::Nil { span } => Ok(ResolvedExpr::Nil { span: *span }),
            Expr::Bool { value, span } => Ok(ResolvedExpr::Bool {
                value: *value,
                span: *span,
            }),
            Expr::Name { name, span } => {
                let resolution = match self.lookup(name, *span)? {
                    Some(resolution) => Some(resolution),
                    None => self.resolve_free_name(name, *span)?,
                };
                resolution
                    .map(|resolution| ResolvedExpr::Name {
                        name: name.clone(),
                        resolution,
                        span: *span,
                    })
                    .ok_or_else(|| self.resolve_error(*span, "名稱尚未宣告"))
            }
            Expr::Unary {
                op,
                expression,
                span,
            } => Ok(ResolvedExpr::Unary {
                op: *op,
                expression: Box::new(self.resolve_expr(expression)?),
                span: *span,
            }),
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => Ok(ResolvedExpr::Binary {
                op: *op,
                left: Box::new(self.resolve_expr(left)?),
                right: Box::new(self.resolve_expr(right)?),
                span: *span,
            }),
            Expr::Paren { expression, span } => Ok(ResolvedExpr::Paren {
                expression: Box::new(self.resolve_expr(expression)?),
                span: *span,
            }),
            Expr::Index { base, index, span } => Ok(ResolvedExpr::Index {
                base: Box::new(self.resolve_expr(base)?),
                index: Box::new(self.resolve_expr(index)?),
                span: *span,
            }),
            Expr::Field { base, name, span } => Ok(ResolvedExpr::Field {
                base: Box::new(self.resolve_expr(base)?),
                name: name.clone(),
                span: *span,
            }),
            Expr::Call {
                callee,
                arguments,
                span,
            } => Ok(ResolvedExpr::Call {
                callee: Box::new(self.resolve_expr(callee)?),
                arguments: self.resolve_expression_list(arguments, *span)?,
                span: *span,
            }),
            Expr::MethodCall {
                receiver,
                method,
                arguments,
                span,
            } => Ok(ResolvedExpr::MethodCall {
                receiver: Box::new(self.resolve_expr(receiver)?),
                method: method.clone(),
                arguments: self.resolve_expression_list(arguments, *span)?,
                span: *span,
            }),
            Expr::Function { body, span } => Ok(ResolvedExpr::Function {
                body: self.resolve_function_body(body, None)?,
                span: *span,
            }),
            Expr::TableConstructor { fields, span } => {
                self.ensure_list(fields.len(), *span)?;
                let mut resolved_fields = Vec::new();
                resolved_fields
                    .try_reserve(fields.len())
                    .map_err(|_| self.limit(*span, "table field 配置超過編譯限制"))?;
                for field in fields {
                    resolved_fields.push(self.resolve_table_field(field)?);
                }
                Ok(ResolvedExpr::TableConstructor {
                    fields: resolved_fields,
                    span: *span,
                })
            }
            Expr::Vararg { span } => {
                if !self.vararg_available {
                    return Err(self.resolve_error(*span, "vararg 不在 function 內"));
                }
                Ok(ResolvedExpr::Vararg {
                    binding: self.vararg_binding,
                    span: *span,
                })
            }
        }
    }

    fn resolve_expression_list(
        &mut self,
        expressions: &[Expr],
        span: Span,
    ) -> Result<Vec<ResolvedExpr>, Diagnostic> {
        self.ensure_list(expressions.len(), span)?;
        let mut resolved = Vec::new();
        resolved
            .try_reserve(expressions.len())
            .map_err(|_| self.limit(span, "運算式配置超過編譯限制"))?;
        for expression in expressions {
            resolved.push(self.resolve_expr(expression)?);
        }
        Ok(resolved)
    }

    fn resolve_table_field(
        &mut self,
        field: &TableField,
    ) -> Result<ResolvedTableField, Diagnostic> {
        match field {
            TableField::Array {
                value,
                separator,
                span,
            } => Ok(ResolvedTableField::Array {
                value: self.resolve_expr(value)?,
                separator: *separator,
                span: *span,
            }),
            TableField::Named {
                name,
                value,
                separator,
                span,
            } => Ok(ResolvedTableField::Named {
                name: name.clone(),
                value: self.resolve_expr(value)?,
                separator: *separator,
                span: *span,
            }),
            TableField::Indexed {
                key,
                value,
                separator,
                span,
            } => Ok(ResolvedTableField::Indexed {
                key: self.resolve_expr(key)?,
                value: self.resolve_expr(value)?,
                separator: *separator,
                span: *span,
            }),
        }
    }

    fn resolve_assignment_target(&mut self, target: &Expr) -> Result<ResolvedExpr, Diagnostic> {
        let resolved = self.resolve_expr(target)?;
        match &resolved {
            ResolvedExpr::Name {
                resolution, span, ..
            } => {
                self.ensure_writable(resolution, *span)?;
                Ok(resolved)
            }
            ResolvedExpr::Index { .. } | ResolvedExpr::Field { .. } => Ok(resolved),
            _ => Err(self.resolve_error(target.span(), "assignment target 不可指派")),
        }
    }

    fn ensure_writable(&self, resolution: &ResolvedName, span: Span) -> Result<(), Diagnostic> {
        let binding = match resolution {
            ResolvedName::Local(binding) => Some(*binding),
            ResolvedName::Upvalue(upvalue) => Some(self.upvalue_binding(*upvalue, span)?),
            ResolvedName::EnvField { .. } | ResolvedName::Global(_) => None,
        };
        if binding.is_some_and(|binding| self.binding_readonly(binding).unwrap_or(false)) {
            return Err(self.resolve_error(span, "不可指派 readonly binding"));
        }
        Ok(())
    }

    fn resolve_repeat(
        &mut self,
        body: &Block,
        condition: &Expr,
        span: Span,
    ) -> Result<ResolvedStmt, Diagnostic> {
        let target = self.current_scope();
        self.enter_scope(body.span)?;
        self.loops.push(target);
        let result = (|| {
            let body = self.resolve_block(body)?;
            let condition = self.resolve_expr(condition)?;
            Ok(ResolvedStmt::Repeat {
                body,
                condition,
                span,
            })
        })();
        self.loops.pop();
        self.scopes.pop();
        result
    }

    fn resolve_numeric_for(
        &mut self,
        name: &LocalName,
        initial: &Expr,
        limit: &Expr,
        step: Option<&Expr>,
        body: &Block,
        span: Span,
    ) -> Result<ResolvedStmt, Diagnostic> {
        let initial = self.resolve_expr(initial)?;
        let limit = self.resolve_expr(limit)?;
        let step = step.map(|step| self.resolve_expr(step)).transpose()?;
        self.ensure_binding_capacity(1, span)?;
        let target = self.current_scope();
        self.enter_scope(span)?;
        let result = (|| {
            let binding = self.declare_binding(
                name.name.clone(),
                name.span,
                name.attribute.clone(),
                BindingKind::NumericFor,
                self.profile == LanguageProfile::Lua55,
            )?;
            self.loops.push(target);
            let body = self.resolve_nested_block(body);
            self.loops.pop();
            Ok(ResolvedStmt::NumericFor {
                name: ResolvedLocalName {
                    binding,
                    name: name.name.clone(),
                    attribute: name.attribute.clone(),
                    span: name.span,
                },
                initial,
                limit,
                step,
                body: body?,
                span,
            })
        })();
        self.scopes.pop();
        result
    }

    fn resolve_generic_for(
        &mut self,
        names: &[LocalName],
        values: &[Expr],
        body: &Block,
        span: Span,
    ) -> Result<ResolvedStmt, Diagnostic> {
        let closing_span = values.get(3).map(Expr::span).unwrap_or(span);
        let values = self.resolve_expression_list(values, span)?;
        self.ensure_list(names.len(), span)?;
        let binding_count = names
            .len()
            .checked_add(1)
            .ok_or_else(|| self.limit(span, "generic-for binding 數超過編譯限制"))?;
        self.ensure_binding_capacity(binding_count, span)?;
        let target = self.current_scope();
        self.enter_scope(span)?;
        let result = (|| {
            let closing = ResolvedGenericForClose {
                binding: self.declare_generic_for_close(closing_span)?,
                span: closing_span,
            };
            let mut resolved_names = Vec::new();
            resolved_names
                .try_reserve(names.len())
                .map_err(|_| self.limit(span, "generic-for name 配置超過編譯限制"))?;
            for name in names {
                let binding = self.declare_binding(
                    name.name.clone(),
                    name.span,
                    name.attribute.clone(),
                    BindingKind::GenericFor,
                    false,
                )?;
                resolved_names.push(ResolvedLocalName {
                    binding,
                    name: name.name.clone(),
                    attribute: name.attribute.clone(),
                    span: name.span,
                });
            }
            self.loops.push(target);
            let body = self.resolve_nested_block(body);
            self.loops.pop();
            let body = body?;
            Ok(ResolvedStmt::GenericFor {
                names: resolved_names,
                values,
                closing,
                close_path: self.close_path(ExitKind::Normal, Some(target), span),
                body,
                span,
            })
        })();
        self.scopes.pop();
        result
    }

    fn resolve_nested_block(&mut self, block: &Block) -> Result<ResolvedBlock, Diagnostic> {
        self.enter_scope(block.span)?;
        let result = self.resolve_block(block);
        self.scopes.pop();
        result
    }

    fn resolve_function_body(
        &mut self,
        body: &FunctionBody,
        method: Option<&MethodName>,
    ) -> Result<ResolvedFunctionBody, Diagnostic> {
        let function = FunctionId(self.next_function);
        self.next_function = self
            .next_function
            .checked_add(1)
            .ok_or_else(|| self.limit(body.span, "function 數超過編譯限制"))?;
        let mut child = Resolver {
            lexed: self.lexed,
            limits: self.limits,
            profile: self.profile,
            owner: function,
            next_binding: 0,
            next_function: self.next_function,
            next_scope: 0,
            bindings: Vec::new(),
            upvalues: Vec::new(),
            upvalue_ids: HashMap::new(),
            upvalue_bindings: Vec::new(),
            pending_ancestor_captures: Vec::new(),
            scopes: Vec::new(),
            loops: Vec::new(),
            parent_metadata: self.visible_binding_access(),
            vararg_available: false,
            vararg_binding: None,
            label_count: 0,
            goto_count: 0,
            parent_visible: Some(self.visible_bindings()),
            inherited_global_mode: self.effective_global_mode(),
            implicit_globals: HashMap::new(),
            completed_functions: Vec::new(),
        };
        child.enter_scope(body.span)?;
        child.ensure_list(body.parameters.len(), body.span)?;
        let parameter_count = body
            .parameters
            .len()
            .checked_add(usize::from(method.is_some()))
            .ok_or_else(|| child.limit(body.span, "參數超過編譯限制"))?;
        if parameter_count > child.limits.max_parameters {
            return Err(child.limit(body.span, "參數超過編譯限制"));
        }
        child.ensure_binding_capacity(parameter_count, body.span)?;
        let mut parameters = Vec::new();
        parameters
            .try_reserve(parameter_count)
            .map_err(|_| child.limit(body.span, "parameter 配置超過編譯限制"))?;
        if let Some(method) = method {
            let name = b"self".to_vec();
            let binding = child.declare_binding(
                name.clone(),
                method.colon_span,
                None,
                BindingKind::Parameter,
                false,
            )?;
            parameters.push(ResolvedLocalName {
                binding,
                name,
                attribute: None,
                span: method.colon_span,
            });
        }
        for parameter in &body.parameters {
            let binding = child.declare_binding(
                parameter.name.clone(),
                parameter.span,
                parameter.attribute.clone(),
                BindingKind::Parameter,
                false,
            )?;
            parameters.push(ResolvedLocalName {
                binding,
                name: parameter.name.clone(),
                attribute: parameter.attribute.clone(),
                span: parameter.span,
            });
        }
        let vararg = if let Some(vararg) = &body.vararg {
            if self.profile != LanguageProfile::Lua55 && vararg.table_name.is_some() {
                return Err(
                    child.resolve_error(vararg.span, "lua54 不支援 lua55 具名 vararg table")
                );
            }
            let table_binding = match &vararg.table_name {
                Some(name) => {
                    child.ensure_binding_capacity(1, name.span)?;
                    Some(child.declare_binding(
                        name.name.clone(),
                        name.span,
                        name.attribute.clone(),
                        BindingKind::VarargTable,
                        true,
                    )?)
                }
                None => None,
            };
            Some(ResolvedVararg {
                table_binding,
                span: vararg.span,
            })
        } else {
            None
        };
        child.vararg_available = vararg.is_some();
        child.vararg_binding = vararg.as_ref().and_then(|vararg| vararg.table_binding);
        let resolved_body = child.resolve_block(&body.body)?;
        child.scopes.pop();
        for (binding, child_upvalue) in std::mem::take(&mut child.pending_ancestor_captures) {
            let parent_upvalue = self.capture_for_child(binding, body.span)?;
            let index = child_upvalue.0 as usize;
            if index >= child.upvalues.len() {
                return Err(child.resolve_error(body.span, "upvalue 轉接索引不符"));
            }
            child.upvalues[index] = UpvalueSource::ParentUpvalue(parent_upvalue);
        }
        self.next_function = child.next_function;
        let metadata = ResolvedFunction {
            id: function,
            parent: Some(self.owner),
            span: body.span,
            bindings: child.bindings,
            upvalues: child.upvalues,
        };
        self.completed_functions.push(metadata);
        self.completed_functions.extend(child.completed_functions);
        Ok(ResolvedFunctionBody {
            function,
            parameters,
            vararg,
            body: Box::new(resolved_body),
            span: body.span,
        })
    }

    fn ensure_list(&self, len: usize, span: Span) -> Result<(), Diagnostic> {
        if len > self.limits.max_ast_nodes {
            Err(self.limit(span, "list 超過編譯限制"))
        } else {
            Ok(())
        }
    }

    fn ensure_binding_capacity(&self, count: usize, span: Span) -> Result<(), Diagnostic> {
        if count
            > self
                .limits
                .max_bindings_per_function
                .saturating_sub(self.bindings.len())
        {
            Err(self.limit(span, "binding 數超過編譯限制"))
        } else {
            Ok(())
        }
    }

    fn declare_local(
        &mut self,
        name: Vec<u8>,
        span: Span,
        attribute: Option<Attribute>,
    ) -> Result<BindingId, Diagnostic> {
        self.declare_binding(name, span, attribute, BindingKind::Local, false)
    }

    fn declare_binding(
        &mut self,
        name: Vec<u8>,
        span: Span,
        attribute: Option<Attribute>,
        kind: BindingKind,
        readonly: bool,
    ) -> Result<BindingId, Diagnostic> {
        let (readonly, close_marker) = self.binding_flags(attribute.as_ref(), readonly, span)?;
        let scope_depth = self.scopes.len().saturating_sub(1);
        let id = self.allocate_binding(
            name.clone(),
            span,
            attribute,
            kind,
            readonly,
            close_marker,
            scope_depth,
        )?;
        let scope = self.scopes.last_mut().expect("root scope 已建立");
        scope.bindings.insert(name, id);
        if close_marker.is_some() {
            scope.close_bindings.push(id);
        }
        Ok(id)
    }

    fn declare_generic_for_close(&mut self, span: Span) -> Result<BindingId, Diagnostic> {
        let scope_depth = self.scopes.len().saturating_sub(1);
        let binding = self.allocate_binding(
            b"<generic-for-close>".to_vec(),
            span,
            None,
            BindingKind::GenericForClose,
            true,
            Some(span),
            scope_depth,
        )?;
        // 隱藏 binding 僅是 close-path metadata，絕不能被 Lua 名稱查找或指派取得。
        self.scopes
            .last_mut()
            .expect("generic-for scope 已建立")
            .close_bindings
            .push(binding);
        Ok(binding)
    }

    fn declare_implicit_global(
        &mut self,
        name: &[u8],
        span: Span,
    ) -> Result<BindingId, Diagnostic> {
        if let Some(binding) = self.implicit_globals.get(name).copied() {
            return Ok(binding);
        }
        let binding = self.allocate_binding(
            name.to_vec(),
            span,
            None,
            BindingKind::Global,
            false,
            None,
            0,
        )?;
        self.implicit_globals.insert(name.to_vec(), binding);
        Ok(binding)
    }

    fn allocate_binding(
        &mut self,
        name: Vec<u8>,
        span: Span,
        attribute: Option<Attribute>,
        kind: BindingKind,
        readonly: bool,
        close_marker: Option<Span>,
        scope_depth: usize,
    ) -> Result<BindingId, Diagnostic> {
        if self.bindings.len() >= self.limits.max_bindings_per_function {
            return Err(self.limit(span, "binding 數超過編譯限制"));
        }
        let ordinal = u32::try_from(self.next_binding)
            .map_err(|_| self.limit(span, "binding 數超過編譯限制"))?;
        self.next_binding += 1;
        let id = BindingId {
            function: self.owner,
            ordinal,
        };
        self.bindings.push(BindingMeta {
            id,
            name: name.clone(),
            span,
            kind,
            owner: self.owner,
            scope_depth,
            readonly,
            attribute,
            close_marker,
        });
        Ok(id)
    }

    fn lookup(&mut self, name: &[u8], span: Span) -> Result<Option<ResolvedName>, Diagnostic> {
        if let Some(binding) = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bindings.get(name).copied())
        {
            return Ok(Some(
                if self.binding_kind(binding) == Some(BindingKind::Global) {
                    ResolvedName::Global(binding)
                } else {
                    ResolvedName::Local(binding)
                },
            ));
        }
        if let Some(binding) = self
            .parent_visible
            .as_ref()
            .and_then(|visible| visible.get(name).copied())
        {
            return match binding {
                ParentBinding::Direct(binding) => Ok(Some(ResolvedName::Upvalue(
                    self.capture_parent_local(binding, span)?,
                ))),
                ParentBinding::Ancestor(binding) => Ok(Some(ResolvedName::Upvalue(
                    self.capture_ancestor(binding, span)?,
                ))),
                ParentBinding::Global(binding) => Ok(Some(ResolvedName::Global(binding))),
            };
        }
        Ok(None)
    }

    fn resolve_free_name(
        &mut self,
        name: &[u8],
        span: Span,
    ) -> Result<Option<ResolvedName>, Diagnostic> {
        if name == b"_ENV" {
            return Ok(None);
        }
        match self.profile {
            LanguageProfile::Lua55 => {
                if self.effective_global_mode() == Some(true) {
                    Ok(None)
                } else {
                    Ok(Some(ResolvedName::Global(
                        self.declare_implicit_global(name, span)?,
                    )))
                }
            }
            LanguageProfile::Lua54 => match self.lookup(b"_ENV", span)? {
                Some(ResolvedName::Local(env)) => Ok(Some(ResolvedName::EnvField {
                    env,
                    name: name.to_vec(),
                })),
                Some(ResolvedName::Upvalue(upvalue)) => Ok(Some(ResolvedName::EnvField {
                    env: self.upvalue_binding(upvalue, span)?,
                    name: name.to_vec(),
                })),
                Some(ResolvedName::EnvField { .. } | ResolvedName::Global(_)) | None => Ok(None),
            },
        }
    }

    fn capture_parent_local(
        &mut self,
        binding: BindingId,
        span: Span,
    ) -> Result<UpvalueId, Diagnostic> {
        self.reserve_upvalue(binding, UpvalueSource::ParentLocal(binding), span)
    }

    fn capture_ancestor(
        &mut self,
        binding: BindingId,
        span: Span,
    ) -> Result<UpvalueId, Diagnostic> {
        if let Some(id) = self.upvalue_ids.get(&binding).copied() {
            return Ok(id);
        }
        let id = self.reserve_upvalue(binding, UpvalueSource::ParentLocal(binding), span)?;
        self.pending_ancestor_captures.push((binding, id));
        Ok(id)
    }

    fn capture_for_child(
        &mut self,
        binding: BindingId,
        span: Span,
    ) -> Result<UpvalueId, Diagnostic> {
        let source =
            self.parent_visible
                .as_ref()
                .and_then(|visible| {
                    visible
                        .values()
                        .find(|candidate| match candidate {
                            ParentBinding::Direct(candidate)
                            | ParentBinding::Ancestor(candidate) => *candidate == binding,
                            ParentBinding::Global(_) => false,
                        })
                        .copied()
                })
                .ok_or_else(|| self.resolve_error(span, "upvalue 轉接來源不在父 function"))?;
        match source {
            ParentBinding::Direct(binding) => self.capture_parent_local(binding, span),
            ParentBinding::Ancestor(binding) => self.capture_ancestor(binding, span),
            ParentBinding::Global(_) => Err(self.resolve_error(span, "global 不可作 upvalue 轉接")),
        }
    }

    fn reserve_upvalue(
        &mut self,
        binding: BindingId,
        source: UpvalueSource,
        span: Span,
    ) -> Result<UpvalueId, Diagnostic> {
        if let Some(id) = self.upvalue_ids.get(&binding).copied() {
            return Ok(id);
        }
        if self.upvalues.len() >= self.limits.max_upvalues_per_function {
            return Err(self.limit(span, "upvalue 數超過編譯限制"));
        }
        let id = UpvalueId(
            u32::try_from(self.upvalues.len())
                .map_err(|_| self.limit(span, "upvalue 數超過編譯限制"))?,
        );
        self.upvalues.push(source);
        self.upvalue_bindings.push(binding);
        self.upvalue_ids.insert(binding, id);
        Ok(id)
    }

    fn upvalue_binding(&self, upvalue: UpvalueId, span: Span) -> Result<BindingId, Diagnostic> {
        self.upvalue_bindings
            .get(upvalue.0 as usize)
            .copied()
            .ok_or_else(|| self.resolve_error(span, "upvalue binding 索引不符"))
    }

    fn binding_flags(
        &self,
        attribute: Option<&Attribute>,
        requested_readonly: bool,
        span: Span,
    ) -> Result<(bool, Option<Span>), Diagnostic> {
        let Some(attribute) = attribute else {
            return Ok((requested_readonly, None));
        };
        match attribute.name.as_slice() {
            b"const" => Ok((true, None)),
            b"close" => Ok((true, Some(attribute.span))),
            _ => Err(self.resolve_error(span, "未知 local attribute")),
        }
    }

    fn binding_readonly(&self, binding: BindingId) -> Option<bool> {
        self.bindings
            .iter()
            .find(|meta| meta.id == binding)
            .map(|meta| meta.readonly)
            .or_else(|| self.parent_metadata.get(&binding).map(|meta| meta.readonly))
    }

    fn visible_binding_access(&self) -> HashMap<BindingId, BindingAccess> {
        let mut visible = self.parent_metadata.clone();
        for binding in &self.bindings {
            visible.insert(
                binding.id,
                BindingAccess {
                    readonly: binding.readonly,
                },
            );
        }
        visible
    }

    fn visible_bindings(&self) -> HashMap<Vec<u8>, ParentBinding> {
        let mut visible: HashMap<Vec<u8>, ParentBinding> = self
            .parent_visible
            .as_ref()
            .into_iter()
            .flat_map(|bindings| bindings.iter())
            .map(|(name, binding)| {
                let binding = match binding {
                    ParentBinding::Direct(binding) | ParentBinding::Ancestor(binding) => *binding,
                    ParentBinding::Global(binding) => {
                        return (name.clone(), ParentBinding::Global(*binding));
                    }
                };
                (name.clone(), ParentBinding::Ancestor(binding))
            })
            .collect();
        for scope in &self.scopes {
            for (name, binding) in &scope.bindings {
                let parent = if self.binding_kind(*binding) == Some(BindingKind::Global) {
                    ParentBinding::Global(*binding)
                } else {
                    ParentBinding::Direct(*binding)
                };
                visible.insert(name.clone(), parent);
            }
        }
        visible
    }

    fn binding_kind(&self, binding: BindingId) -> Option<BindingKind> {
        self.bindings
            .iter()
            .find(|meta| meta.id == binding)
            .map(|meta| meta.kind)
    }

    fn effective_global_mode(&self) -> Option<bool> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.global_mode)
            .or(self.inherited_global_mode)
    }

    fn set_explicit_global_mode(&mut self, restrictive: bool) {
        self.scopes.last_mut().expect("scope 已建立").global_mode = Some(restrictive);
    }

    fn current_scope(&self) -> ScopeId {
        self.scopes.last().expect("scope 已建立").id
    }

    fn register_labels(&mut self, block: &Block) -> Result<(), Diagnostic> {
        let scope = self.current_scope();
        let label_count = block
            .statements
            .iter()
            .filter(|statement| matches!(statement, Stmt::Label { .. }))
            .count();
        if self.label_count.saturating_add(label_count) > self.limits.max_labels {
            return Err(self.limit(block.span, "label 數超過編譯限制"));
        }
        let declaration_count = block
            .statements
            .iter()
            .map(|statement| match statement {
                Stmt::Local { names, .. } => names.len(),
                Stmt::LocalFunction { .. } => 1,
                _ => 0,
            })
            .sum::<usize>();
        self.ensure_binding_capacity(declaration_count, block.span)?;
        let reserve_error = self.limit(block.span, "label 配置超過編譯限制");
        let declaration_reserve_error = self.limit(block.span, "local snapshot 配置超過編譯限制");
        let frame = self.scopes.last_mut().expect("scope 已建立");
        frame
            .labels
            .try_reserve(label_count)
            .map_err(|_| reserve_error)?;
        frame
            .declaration_spans
            .try_reserve(declaration_count)
            .map_err(|_| declaration_reserve_error)?;
        for statement in &block.statements {
            match statement {
                Stmt::Local { names, .. } => frame
                    .declaration_spans
                    .extend(names.iter().map(|name| name.span)),
                Stmt::LocalFunction { name, .. } => {
                    frame.declaration_spans.push(name.span);
                }
                _ => {}
            }
            let Stmt::Label {
                name, name_span, ..
            } = statement
            else {
                continue;
            };
            if frame
                .labels
                .insert(
                    name.clone(),
                    LabelInfo {
                        scope,
                        span: *name_span,
                    },
                )
                .is_some()
            {
                return Err(self.resolve_error(*name_span, "同一作用域的 label 重複"));
            }
        }
        Ok(())
    }

    fn find_label(&self, name: &[u8]) -> Option<LabelInfo> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.labels.get(name).copied())
    }

    fn validate_block_gotos(&self, block: &Block) -> Result<(), Diagnostic> {
        let gotos = block
            .statements
            .iter()
            .filter(|statement| matches!(statement, Stmt::Goto { .. }))
            .count();
        if self.goto_count.saturating_add(gotos) > self.limits.max_gotos {
            return Err(self.limit(block.span, "goto 數超過編譯限制"));
        }
        for statement in &block.statements {
            let Stmt::Goto { name, span, .. } = statement else {
                continue;
            };
            let label = self
                .find_label(name)
                .ok_or_else(|| self.resolve_error(*span, "找不到 goto label"))?;
            let enters_local = self
                .scopes
                .iter()
                .find(|scope| scope.id == label.scope)
                .is_some_and(|scope| {
                    scope.declaration_spans.iter().any(|declaration| {
                        declaration.start_byte > span.start_byte
                            && declaration.start_byte < label.span.start_byte
                    })
                });
            if enters_local {
                return Err(self.resolve_error(*span, "goto 不可跳入 local scope"));
            }
        }
        Ok(())
    }

    fn close_path(&self, kind: ExitKind, target_scope: Option<ScopeId>, span: Span) -> ClosePath {
        let mut bindings = Vec::new();
        for scope in self.scopes.iter().rev() {
            if Some(scope.id) == target_scope {
                break;
            }
            bindings.extend(scope.close_bindings.iter().rev().copied());
        }
        ClosePath {
            kind,
            span,
            from_scope: self.current_scope(),
            target_scope,
            bindings,
        }
    }

    fn limit(&self, span: Span, message: &'static str) -> Diagnostic {
        diagnostic_at_span(self.lexed, span, DiagnosticCode::CompileLimit, message)
    }

    fn resolve_error(&self, span: Span, message: &'static str) -> Diagnostic {
        diagnostic_at_span(self.lexed, span, DiagnosticCode::Resolve, message)
    }
}

fn diagnostic_at_span(
    lexed: &LexedChunk,
    span: Span,
    code: DiagnosticCode,
    message: &'static str,
) -> Diagnostic {
    let token = lexed
        .tokens
        .iter()
        .find(|token| token.span.start_byte == span.start_byte)
        .or_else(|| lexed.tokens.last());
    diagnostic(token, code, message)
}

fn diagnostic(token: Option<&Token>, code: DiagnosticCode, message: &'static str) -> Diagnostic {
    match token {
        Some(token) => Diagnostic {
            code,
            span: token.span,
            start: token.start,
            end: token.end,
            message,
        },
        None => Diagnostic {
            code,
            span: Span {
                start_byte: 0,
                end_byte: 0,
            },
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 1 },
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::resolve;
    use crate::{CompileLimits, DiagnosticCode, LanguageProfile, lex, parse};

    #[test]
    fn rejects_unimplemented_statement_instead_of_empty_success() {
        let limits = CompileLimits::default();
        let chunk = lex(b"break", LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        assert_eq!(
            resolve(&module, &chunk, LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::Resolve
        );
    }
}
