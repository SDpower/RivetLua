//! P04 名稱與作用域解析；只消費 P03 owned AST 與 P02 位置資料。

pub(crate) mod meaning;

use crate::{
    Attribute, BinaryOp, Block, CompileLimits, Diagnostic, DiagnosticCode, Expr, FieldSeparator,
    FunctionBody, GlobalDeclaration, LanguageProfile, LexedChunk, Literal, LocalName, MethodName,
    Module, SourcePosition, Span, Stmt, TableField, Token, TokenKind, UnaryOp,
};
use crate::ast::AstName;
use crate::parser::ParseError;
use meaning::{MeaningContext, MeaningEvent, MeaningFunction, MeaningState, Unmetered};
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{AllocationRecovery, GlobalAllocation, ReserveError, SharedBlock, StateAllocator, try_reserve_exact_with, try_shared_uninit_with};
use hashbrown::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::Hash;

pub type ResolvedVec<T> = AllocVec<T, StateAllocator>;
pub type ResolvedBox<T> = SharedBlock<T>;

/// SDK 建構公開 resolved fixture 時，明確選擇全域配置。
pub fn try_global_resolved_box<T>(value: T) -> Option<ResolvedBox<T>> {
    Some(StateAllocator::Global.shared_uninit::<T>(0).ok()?.write(value))
}
type StateMap<K, V> = HashMap<K, V, RandomState, StateAllocator>;

fn new_state_map<K, V>(allocator: StateAllocator) -> StateMap<K, V> {
    StateMap::with_hasher_in(RandomState::new(), allocator)
}

fn reserve_map_with<K: Eq + Hash, V, R: AllocationRecovery>(
    values: &mut StateMap<K, V>,
    additional: usize,
    recovery: &mut R,
) -> Result<(), ResolveError<R::Error>> {
    let allocator = values.allocator().clone();
    if !allocator.same_binding(&recovery.allocator()) {
        return Err(ResolveError::AllocationFailed);
    }
    let before = allocator.refusal_count();
    if values.try_reserve(additional).is_ok() {
        return Ok(());
    }
    if !allocator.is_lua() || allocator.refusal_count() == before {
        return Err(ResolveError::AllocationFailed);
    }
    if !recovery.recover_after_refusal(before).map_err(ResolveError::Recovery)? {
        return Err(ResolveError::AllocationFailed);
    }
    values.try_reserve(additional).map_err(|_| ResolveError::AllocationFailed)
}

/// SDK 建構公開 resolved fixture 時，明確選擇全域配置。
pub fn try_global_resolved_vec<T>(values: Vec<T>) -> Option<ResolvedVec<T>> {
    let mut output = ResolvedVec::new_in(StateAllocator::Global);
    output.try_reserve_exact(values.len()).ok()?;
    output.extend(values);
    Some(output)
}

fn reserve_geometric_with<T, R: AllocationRecovery>(
    values: &mut ResolvedVec<T>,
    additional: usize,
    recovery: &mut R,
) -> Result<(), ResolveError<R::Error>> {
    let required = values.len().checked_add(additional)
        .ok_or(ResolveError::AllocationFailed)?;
    if required <= values.capacity() {
        return Ok(());
    }
    let target = values.capacity().saturating_mul(2).max(4).max(required);
    try_reserve_exact_with(values, target - values.len(), recovery).map_err(map_reserve_error)
}

pub(crate) enum ResolveError<E> {
    Diagnostic(Diagnostic),
    Recovery(E),
    AllocationFailed,
}

fn shared_name<R: AllocationRecovery>(
    recovery: &mut R,
    bytes: &[u8],
) -> Result<AstName, ResolveError<R::Error>> {
    let mut name = AllocVec::new_in(recovery.allocator());
    try_reserve_exact_with(&mut name, bytes.len(), recovery).map_err(map_reserve_error)?;
    name.extend_from_slice(bytes);
    let owner = try_shared_uninit_with::<AllocVec<u8, StateAllocator>, _>(recovery, 0)
        .map_err(map_reserve_error)?;
    Ok(owner.write(name))
}

fn map_reserve_error<E>(error: ReserveError<E>) -> ResolveError<E> {
    match error {
        ReserveError::Recovery(error) => ResolveError::Recovery(error),
        ReserveError::AllocatorMismatch
        | ReserveError::CallbackRefused
        | ReserveError::AllocationFailed => ResolveError::AllocationFailed,
    }
}

impl<E> From<Diagnostic> for ResolveError<E> {
    fn from(value: Diagnostic) -> Self {
        Self::Diagnostic(value)
    }
}

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
    pub name: AstName,
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
    EnvField { env: BindingId, name: AstName },
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
    pub functions: ResolvedVec<ResolvedFunction>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedFunction {
    pub id: FunctionId,
    pub parent: Option<FunctionId>,
    pub span: Span,
    pub bindings: ResolvedVec<BindingMeta>,
    pub upvalues: ResolvedVec<UpvalueSource>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedBlock {
    pub scope: ScopeId,
    pub statements: ResolvedVec<ResolvedStmt>,
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
    pub bindings: ResolvedVec<BindingId>,
    pub exited_bindings: ResolvedVec<BindingId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedLocalName {
    pub binding: BindingId,
    pub name: AstName,
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
    pub parameters: ResolvedVec<ResolvedLocalName>,
    pub vararg: Option<ResolvedVararg>,
    pub body: ResolvedBox<ResolvedBlock>,
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
        names: ResolvedVec<ResolvedLocalName>,
        values: ResolvedVec<ResolvedExpr>,
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Star {
        prefix_attribute: Option<Attribute>,
        span: Span,
    },
    Function {
        binding: BindingId,
        name: AstName,
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
        values: ResolvedVec<ResolvedExpr>,
        close_path: ClosePath,
        span: Span,
    },
    Assignment {
        targets: ResolvedVec<ResolvedExpr>,
        values: ResolvedVec<ResolvedExpr>,
        span: Span,
    },
    Call {
        call: ResolvedExpr,
        span: Span,
    },
    Local {
        bindings: ResolvedVec<BindingId>,
        names: ResolvedVec<ResolvedLocalName>,
        values: ResolvedVec<ResolvedExpr>,
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
        name: AstName,
        name_span: Span,
        close_path: ClosePath,
        span: Span,
    },
    Label {
        name: AstName,
        name_span: Span,
        span: Span,
    },
    Do {
        body: ResolvedBlock,
        span: Span,
    },
    If {
        clauses: ResolvedVec<ResolvedIfClause>,
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
        names: ResolvedVec<ResolvedLocalName>,
        values: ResolvedVec<ResolvedExpr>,
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
        name: AstName,
        resolution: ResolvedName,
        span: Span,
    },
    Vararg {
        binding: Option<BindingId>,
        span: Span,
    },
    Unary {
        op: UnaryOp,
        expression: ResolvedBox<ResolvedExpr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: ResolvedBox<ResolvedExpr>,
        right: ResolvedBox<ResolvedExpr>,
        span: Span,
    },
    Paren {
        expression: ResolvedBox<ResolvedExpr>,
        span: Span,
    },
    Index {
        base: ResolvedBox<ResolvedExpr>,
        index: ResolvedBox<ResolvedExpr>,
        span: Span,
    },
    Field {
        base: ResolvedBox<ResolvedExpr>,
        name: AstName,
        span: Span,
    },
    Call {
        callee: ResolvedBox<ResolvedExpr>,
        arguments: ResolvedVec<ResolvedExpr>,
        span: Span,
    },
    MethodCall {
        receiver: ResolvedBox<ResolvedExpr>,
        method: AstName,
        arguments: ResolvedVec<ResolvedExpr>,
        span: Span,
    },
    Function {
        body: ResolvedFunctionBody,
        span: Span,
    },
    TableConstructor {
        fields: ResolvedVec<ResolvedTableField>,
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
        name: AstName,
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
    match resolve_with_recovery(module, lexed, expected_profile, limits, &mut GlobalAllocation) {
        Ok(result) => Ok(result),
        Err(ResolveError::Diagnostic(diagnostic)) => Err(diagnostic),
        Err(ResolveError::Recovery(never)) => match never {},
        Err(ResolveError::AllocationFailed) => Err(diagnostic(
            lexed.tokens.last(), DiagnosticCode::CompileLimit, "resolver 配置失敗",
        )),
    }
}

pub(crate) fn resolve_with_recovery<R: AllocationRecovery>(
    module: &Module,
    lexed: &LexedChunk,
    expected_profile: LanguageProfile,
    limits: &CompileLimits,
    recovery: &mut R,
) -> Result<ResolvedModule, ResolveError<R::Error>> {
    resolve_with_recovery_context(module, lexed, expected_profile, limits, recovery, None)
}

pub(crate) fn resolve_with_recovery_context<R: AllocationRecovery>(
    module: &Module,
    lexed: &LexedChunk,
    expected_profile: LanguageProfile,
    limits: &CompileLimits,
    recovery: &mut R,
    mut failure: Option<&mut Option<crate::official_failure::OfficialFailure>>,
) -> Result<ResolvedModule, ResolveError<R::Error>> {
    validate_input(module, lexed, expected_profile)?;
    let mut meaning = MeaningState::new(expected_profile, *limits, recovery.allocator());
    let root_scope = meaning.begin(module.span, &mut Unmetered(recovery))
        .map_err(|error| map_meaning_parse_error(meaning::parse_error(error, &lexed.tokens)))?;
    let result = (|| {
    let mut resolver = Resolver {
        lexed,
        limits,
        profile: expected_profile,
        owner: FunctionId(0),
        scopes: ResolvedVec::new_in(recovery.allocator()),
        loops: ResolvedVec::new_in(recovery.allocator()),
        completed_functions: ResolvedVec::new_in(recovery.allocator()),
        meaning: Some(&mut meaning),
        recovery: Some(recovery),
    };
    resolver.enter_scope_with_id(root_scope)?;
    let root = resolver.resolve_block(&module.root)?;
    let root_function = resolver.meaning_finish_function(module.span)?;
    resolver.scopes.pop();
    let mut functions = resolver.new_list();
    let function_count = resolver.completed_functions.len().checked_add(1)
        .ok_or(ResolveError::AllocationFailed)?;
    resolver.reserve_list(&mut functions, function_count)?;
    let (bindings, upvalues) = root_function.into_resolved(
        resolver.recovery.as_deref_mut().expect("resolver recovery 有效"))?;
    functions.push(ResolvedFunction {
        id: resolver.owner,
        parent: None,
        span: module.span,
        bindings,
        upvalues,
    });
    functions.extend(resolver.completed_functions);
    Ok(ResolvedModule {
        profile: expected_profile,
        span: module.span,
        root,
        functions,
    })
    })();
    if result.is_err() {
        if let Some(slot) = failure.as_mut() {
            **slot = meaning.take_official_failure();
        }
    }
    result
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

struct Resolver<'a, R: AllocationRecovery> {
    lexed: &'a LexedChunk,
    limits: &'a CompileLimits,
    profile: LanguageProfile,
    owner: FunctionId,
    scopes: ResolvedVec<ScopeFrame>,
    loops: ResolvedVec<ScopeId>,
    completed_functions: ResolvedVec<ResolvedFunction>,
    meaning: Option<&'a mut MeaningState>,
    recovery: Option<&'a mut R>,
}

fn map_meaning_parse_error<E>(error: ParseError<E>) -> ResolveError<E> {
    match error {
        ParseError::Diagnostic(diagnostic) => ResolveError::Diagnostic(diagnostic),
        ParseError::Recovery(error) => ResolveError::Recovery(error),
        ParseError::AllocationFailed => ResolveError::AllocationFailed,
    }
}

fn map_meaning_error<E>(error: meaning::MeaningError<E>, tokens: &[Token]) -> ResolveError<E> {
    map_meaning_parse_error(meaning::parse_error(error, tokens))
}

struct ScopeFrame {
    id: ScopeId,
    local_bindings: ResolvedVec<BindingId>,
    close_bindings: ResolvedVec<BindingId>,
    labels: StateMap<AstName, LabelInfo>,
}

#[derive(Clone, Copy)]
struct LabelInfo {
    scope: ScopeId,
    terminal: bool,
    span: Span,
}


// 預算層需要 private resolver 容器的實際元素大小；不公開其表示或語意。
pub(crate) fn budget_layout_sizes() -> (usize, usize, usize) {
    (
        core::mem::size_of::<ScopeFrame>(),
        core::mem::size_of::<LabelInfo>(),
        core::mem::size_of::<BindingId>(),
    )
}

impl<R: AllocationRecovery> Resolver<'_, R> {
    fn meaning_event(&mut self, event: MeaningEvent<'_>) -> Result<(), ResolveError<R::Error>> {
        self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .event(event, &self.lexed.tokens,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")))
            .map_err(map_meaning_parse_error)
    }
    fn meaning_name(&mut self, name: &AstName, span: Span) -> Result<ResolvedName, ResolveError<R::Error>> {
        self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .name_event(name, span, &self.lexed.tokens,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")))
            .map_err(map_meaning_parse_error)
    }
    fn meaning_enter_scope(&mut self, span: Span) -> Result<ScopeId, ResolveError<R::Error>> {
        let result = self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .enter_scope(span, &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")));
        result.map_err(|error| map_meaning_error(error, &self.lexed.tokens))
    }
    fn meaning_declare(&mut self, name: &LocalName, attribute: Option<&Attribute>,
        kind: BindingKind, readonly: bool) -> Result<BindingId, ResolveError<R::Error>> {
        let result = self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .declare_with_attribute(name, attribute, kind, readonly,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")));
        let id = result.map_err(|error| map_meaning_error(error, &self.lexed.tokens))?;
        self.track_binding(id)?;
        Ok(id)
    }
    fn meaning_generic_close(&mut self, span: Span) -> Result<BindingId, ResolveError<R::Error>> {
        let result = self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .declare_generic_close(span,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")));
        let id = result.map_err(|error| map_meaning_error(error, &self.lexed.tokens))?;
        self.track_binding(id)?;
        Ok(id)
    }
    fn meaning_enter_function(&mut self, body: &FunctionBody, method: Option<&MethodName>)
        -> Result<FunctionId, ResolveError<R::Error>> {
        let result = self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .enter_function(&body.parameters,
                body.vararg.as_ref().and_then(|value| value.table_name.as_ref()),
                body.vararg.is_some(), method.map(|value| value.colon_span), body.span,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")));
        result.map_err(|error| map_meaning_error(error, &self.lexed.tokens))
    }
    fn meaning_finish_function(&mut self, span: Span) -> Result<MeaningFunction, ResolveError<R::Error>> {
        let result = self.meaning.as_deref_mut().expect("resolver meaning 有效")
            .leave_function(span,
                &mut Unmetered(self.recovery.as_deref_mut().expect("resolver recovery 有效")));
        result.map_err(|error| map_meaning_error(error, &self.lexed.tokens))
    }
    fn track_binding(&mut self, id: BindingId) -> Result<(), ResolveError<R::Error>> {
        let info = self.meaning.as_ref().expect("resolver meaning 有效")
            .binding_info(id).ok_or_else(|| self.resolve_error(self.lexed.tokens.last()
                .map_or(Span { start_byte: 0, end_byte: 0 }, |token| token.span),
                "meaning binding 索引不符"))?;
        let scope = self.scopes.last_mut().expect("root scope 已建立");
        let recovery = self.recovery.as_deref_mut().expect("resolver recovery 有效");
        if !matches!(info.kind, BindingKind::Environment | BindingKind::Global) {
            reserve_geometric_with(&mut scope.local_bindings, 1, &mut *recovery)?;
            scope.local_bindings.push(id);
        }
        if info.close_marker.is_some() {
            reserve_geometric_with(&mut scope.close_bindings, 1, &mut *recovery)?;
            scope.close_bindings.push(id);
        }
        Ok(())
    }
    fn new_list<T>(&self) -> ResolvedVec<T> {
        ResolvedVec::new_in(
            self.recovery.as_ref().expect("resolver recovery 有效").allocator(),
        )
    }

    fn reserve_list<T>(
        &mut self,
        values: &mut ResolvedVec<T>,
        additional: usize,
    ) -> Result<(), ResolveError<R::Error>> {
        try_reserve_exact_with(
            values,
            additional,
            self.recovery.as_deref_mut().expect("resolver recovery 有效"),
        )
        .map_err(map_reserve_error)
    }

    fn push_loop(&mut self, scope: ScopeId) -> Result<(), ResolveError<R::Error>> {
        reserve_geometric_with(&mut self.loops, 1,
            self.recovery.as_deref_mut().expect("resolver recovery 有效"))?;
        self.loops.push(scope);
        Ok(())
    }

    fn shared_name(&mut self, bytes: &[u8]) -> Result<AstName, ResolveError<R::Error>> {
        shared_name(self.recovery.as_deref_mut().expect("resolver recovery 有效"), bytes)
    }

    fn box_value<T>(&mut self, value: T) -> Result<ResolvedBox<T>, ResolveError<R::Error>> {
        let owner = try_shared_uninit_with::<T, _>(
            self.recovery.as_deref_mut().expect("resolver recovery 有效"), 0,
        ).map_err(map_reserve_error)?;
        Ok(owner.write(value))
    }

    fn resolve_boxed_expr(&mut self, expression: &Expr) -> Result<ResolvedBox<ResolvedExpr>, ResolveError<R::Error>> {
        let value = self.resolve_expr(expression)?;
        self.box_value(value)
    }

    fn enter_scope(&mut self, span: Span) -> Result<(), ResolveError<R::Error>> {
        let id = self.meaning_enter_scope(span)?;
        self.enter_scope_with_id(id)
    }

    fn enter_scope_with_id(&mut self, id: ScopeId) -> Result<(), ResolveError<R::Error>> {
        reserve_geometric_with(&mut self.scopes, 1,
            self.recovery.as_deref_mut().expect("resolver recovery 有效"))?;
        let local_bindings = self.new_list();
        let close_bindings = self.new_list();
        let labels = new_state_map(self.recovery.as_ref().expect("resolver recovery 有效").allocator());
        self.scopes.push(ScopeFrame {
            id,
            local_bindings,
            close_bindings,
            labels,
        });
        Ok(())
    }

    fn resolve_block(&mut self, block: &Block) -> Result<ResolvedBlock, ResolveError<R::Error>> {
        self.resolve_block_with_terminal_labels(block, true)
    }

    fn resolve_block_with_terminal_labels(
        &mut self,
        block: &Block,
        terminal_labels_end_scope: bool,
    ) -> Result<ResolvedBlock, ResolveError<R::Error>> {
        if block.statements.len() > self.limits.max_statements
            || block.statements.len() > self.limits.max_ast_nodes
        {
            return Err(self.limit(block.span, "陳述式數超過編譯限制"));
        }
        self.register_labels(block, terminal_labels_end_scope)?;
        let mut statements = self.new_list();
        self.reserve_list(&mut statements, block.statements.len())?;
        for statement in &block.statements {
            if !matches!(statement, Stmt::Empty { .. } | Stmt::Label { .. }) {
                self.meaning_event(MeaningEvent::FlushLabels { terminal: false })?;
            }
            statements.push(self.resolve_statement(statement)?);
        }
        self.meaning_event(MeaningEvent::FlushLabels { terminal: terminal_labels_end_scope })?;
        let terminal_suffix_start = block
            .statements
            .iter()
            .rposition(|statement| !matches!(statement, Stmt::Empty { .. } | Stmt::Label { .. }))
            .map_or(0, |index| index + 1);
        let root_terminal_label = self.scopes.len() == 1
            && block.statements[terminal_suffix_start..]
                .iter()
                .any(|statement| matches!(statement, Stmt::Label { .. }));
        let target_scope = if root_terminal_label {
            None
        } else {
            self.scopes
                .get(self.scopes.len().saturating_sub(2))
                .map(|scope| scope.id)
        };
        Ok(ResolvedBlock {
            scope: self.scopes.last().expect("scope 已建立").id,
            statements,
            terminator: block.terminator,
            span: block.span,
            normal_close_path: self.close_path(ExitKind::Normal, target_scope, block.span)?,
            error_close_path: self.close_path(ExitKind::Error, None, block.span)?,
        })
    }

    fn resolve_statement(&mut self, statement: &Stmt) -> Result<ResolvedStmt, ResolveError<R::Error>> {
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
                self.meaning_event(MeaningEvent::BeginDeclarations)?;
                for name in names {
                    self.meaning_event(MeaningEvent::DeclarationAttribute {
                        attribute: name.attribute.as_ref(), global: false, span: name.span })?;
                }
                let mut resolved_values = self.new_list();
                self.reserve_list(&mut resolved_values, values.len())?;
                for value in values {
                    resolved_values.push(self.resolve_expr(value)?);
                }
                let mut bindings = self.new_list();
                self.reserve_list(&mut bindings, names.len())?;
                for name in names {
                    let binding = self.meaning_declare(name, name.attribute.as_ref(),
                        BindingKind::Local, false)?;
                    bindings.push(binding);
                }
                let mut resolved_names = self.new_list();
                self.reserve_list(&mut resolved_names, names.len())?;
                for (name, binding) in names.iter().zip(bindings.iter().copied()) {
                    resolved_names.push(ResolvedLocalName {
                        binding,
                        name: name.name.clone(),
                        attribute: name.attribute.clone(),
                        span: name.span,
                    });
                }
                Ok(ResolvedStmt::Local {
                    bindings,
                    names: resolved_names,
                    values: resolved_values,
                    span: *span,
                })
            }
            Stmt::LocalFunction { name, body, span } => {
                let binding = self.meaning_declare(name, name.attribute.as_ref(),
                    BindingKind::LocalFunction, false)?;
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
                    close_path: self.close_path(ExitKind::Return, None, *span)?,
                    span: *span,
                })
            }
            Stmt::Assignment {
                targets,
                values,
                span,
            } => {
                self.ensure_list(targets.len(), *span)?;
                let mut resolved_targets = self.new_list();
                self.reserve_list(&mut resolved_targets, targets.len())?;
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
                self.meaning_event(MeaningEvent::CheckBreak(*span))?;
                let target = self.loops.last().copied().unwrap_or_else(|| self.current_scope());
                Ok(ResolvedStmt::Break {
                    close_path: self.close_path(ExitKind::Break, Some(target), *span)?,
                    span: *span,
                })
            }
            Stmt::Goto {
                name,
                name_span,
                span,
            } => {
                self.meaning_event(MeaningEvent::Goto { name, span: *name_span })?;
                let close_path = match self.find_label(name) {
                    Some(label) => self.goto_close_path(label, *span)?,
                    None => self.close_path(ExitKind::Goto, None, *span)?,
                };
                Ok(ResolvedStmt::Goto {
                    name: name.clone(),
                    name_span: *name_span,
                    close_path,
                    span: *span,
                })
            }
            Stmt::Label {
                name,
                name_span,
                span,
            } => {
                self.meaning_event(MeaningEvent::QueueLabel { name, span: *name_span })?;
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
                let mut resolved_clauses = self.new_list();
                self.reserve_list(&mut resolved_clauses, clauses.len())?;
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
                self.meaning_event(MeaningEvent::EnterLoop)?;
                self.push_loop(target)?;
                let body = self.resolve_nested_block(body);
                self.loops.pop();
                self.meaning_event(MeaningEvent::LeaveLoop)?;
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
            } => {
                let resolved_name = self.resolve_expr(name)?;
                if !matches!(&resolved_name, ResolvedExpr::Name { .. }
                    | ResolvedExpr::Field { .. } | ResolvedExpr::Index { .. }) {
                    return Err(self.resolve_error(name.span(), "assignment target 不可指派"));
                }
                if self.profile == LanguageProfile::Lua55 {
                    self.meaning_event(MeaningEvent::WriteTarget(name))?;
                }
                let resolved_body = self.resolve_function_body(body, method.as_ref())?;
                if self.profile == LanguageProfile::Lua54 {
                    self.meaning_event(MeaningEvent::WriteTarget(name))?;
                }
                Ok(ResolvedStmt::Function { name: resolved_name,
                    method: method.clone(), body: resolved_body, span: *span })
            }
            Stmt::Global { declaration, span } => self.resolve_global(declaration, *span),
        }
    }

    fn resolve_global(
        &mut self,
        declaration: &GlobalDeclaration,
        span: Span,
    ) -> Result<ResolvedStmt, ResolveError<R::Error>> {
        if !self.profile.rules().global_declarations {
            return Err(self.resolve_error(span, "lua54 不支援 lua55 global declaration"));
        }
        match declaration {
            GlobalDeclaration::Star {
                prefix_attribute,
                span,
            } => {
                self.meaning_event(MeaningEvent::WildcardGlobalMode {
                    attribute: prefix_attribute.as_ref(), span: *span })?;
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
                let mut resolved_names = self.new_list();
                self.reserve_list(&mut resolved_names, names.len())?;
                if let Some(prefix) = prefix_attribute.as_ref() {
                    self.meaning_event(MeaningEvent::Attribute {
                        attribute: Some(prefix), global: true, span: prefix.span })?;
                }
                self.meaning_event(MeaningEvent::BeginDeclarations)?;
                for name in names {
                    let attribute = name.attribute.as_ref().or(prefix_attribute.as_ref());
                    self.meaning_event(MeaningEvent::DeclarationAttribute {
                        attribute, global: true, span: name.span })?;
                }
                if !values.is_empty() {
                    for name in names {
                        self.meaning_event(MeaningEvent::GlobalTarget {
                            name: &name.name, span: name.span })?;
                    }
                }
                let values = self.resolve_expression_list(values, *span)?;
                self.meaning_event(MeaningEvent::NamedGlobalMode)?;
                for name in names {
                    let attribute = name.attribute.as_ref().or(prefix_attribute.as_ref());
                    let binding = self.meaning_declare(name, attribute, BindingKind::Global, false)?;
                    resolved_names.push(ResolvedLocalName {
                        binding,
                        name: name.name.clone(),
                        attribute: name.attribute.clone(),
                        span: name.span,
                    });
                }
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
                self.meaning_event(MeaningEvent::NamedGlobalMode)?;
                let declaration = LocalName { name: name.clone(), attribute: None, span: *span };
                let binding = self.meaning_declare(&declaration, None, BindingKind::Global, false)?;
                self.meaning_event(MeaningEvent::GlobalTarget { name, span: *span })?;
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

    fn resolve_expr(&mut self, expression: &Expr) -> Result<ResolvedExpr, ResolveError<R::Error>> {
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
                let resolution = self.meaning_name(name, *span)?;
                Ok(ResolvedExpr::Name { name: name.clone(), resolution, span: *span })
            }
            Expr::Unary {
                op,
                expression,
                span,
            } => Ok(ResolvedExpr::Unary {
                op: *op,
                expression: self.resolve_boxed_expr(expression)?,
                span: *span,
            }),
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => Ok(ResolvedExpr::Binary {
                op: *op,
                left: self.resolve_boxed_expr(left)?,
                right: self.resolve_boxed_expr(right)?,
                span: *span,
            }),
            Expr::Paren { expression, span } => Ok(ResolvedExpr::Paren {
                expression: self.resolve_boxed_expr(expression)?,
                span: *span,
            }),
            Expr::Index { base, index, span } => Ok(ResolvedExpr::Index {
                base: self.resolve_boxed_expr(base)?,
                index: self.resolve_boxed_expr(index)?,
                span: *span,
            }),
            Expr::Field { base, name, span } => Ok(ResolvedExpr::Field {
                base: self.resolve_boxed_expr(base)?,
                name: name.clone(),
                span: *span,
            }),
            Expr::Call {
                callee,
                arguments,
                span,
            } => Ok(ResolvedExpr::Call {
                callee: self.resolve_boxed_expr(callee)?,
                arguments: self.resolve_expression_list(arguments, *span)?,
                span: *span,
            }),
            Expr::MethodCall {
                receiver,
                method,
                arguments,
                span,
            } => Ok(ResolvedExpr::MethodCall {
                receiver: self.resolve_boxed_expr(receiver)?,
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
                let mut resolved_fields = self.new_list();
                self.reserve_list(&mut resolved_fields, fields.len())?;
                for field in fields {
                    resolved_fields.push(self.resolve_table_field(field)?);
                }
                Ok(ResolvedExpr::TableConstructor {
                    fields: resolved_fields,
                    span: *span,
                })
            }
            Expr::Vararg { span } => {
                self.meaning_event(MeaningEvent::CheckVararg(*span))?;
                Ok(ResolvedExpr::Vararg {
                    binding: self.meaning.as_ref().expect("resolver meaning 有效")
                        .current_vararg_binding(),
                    span: *span,
                })
            }
        }
    }

    fn resolve_expression_list(
        &mut self,
        expressions: &[Expr],
        span: Span,
    ) -> Result<ResolvedVec<ResolvedExpr>, ResolveError<R::Error>> {
        self.ensure_list(expressions.len(), span)?;
        let mut resolved = self.new_list();
        self.reserve_list(&mut resolved, expressions.len())?;
        for expression in expressions {
            resolved.push(self.resolve_expr(expression)?);
        }
        Ok(resolved)
    }

    fn resolve_table_field(
        &mut self,
        field: &TableField,
    ) -> Result<ResolvedTableField, ResolveError<R::Error>> {
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

    fn resolve_assignment_target(&mut self, target: &Expr) -> Result<ResolvedExpr, ResolveError<R::Error>> {
        let resolved = self.resolve_expr(target)?;
        match &resolved {
            ResolvedExpr::Name { .. } => {
                self.meaning_event(MeaningEvent::WriteTarget(target))?;
                Ok(resolved)
            }
            ResolvedExpr::Index { .. } | ResolvedExpr::Field { .. } => Ok(resolved),
            _ => Err(self.resolve_error(target.span(), "assignment target 不可指派")),
        }
    }

    fn resolve_repeat(
        &mut self,
        body: &Block,
        condition: &Expr,
        span: Span,
    ) -> Result<ResolvedStmt, ResolveError<R::Error>> {
        let target = self.current_scope();
        self.enter_scope(body.span)?;
        self.meaning_event(MeaningEvent::EnterLoop)?;
        self.push_loop(target)?;
        let result = (|| {
            let body = self.resolve_block_with_terminal_labels(body, false)?;
            let condition = self.resolve_expr(condition)?;
            self.meaning_event(MeaningEvent::LeaveLoop)?;
            self.meaning_event(MeaningEvent::LeaveScope { span, terminal: false })?;
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
    ) -> Result<ResolvedStmt, ResolveError<R::Error>> {
        let initial = self.resolve_expr(initial)?;
        let limit = self.resolve_expr(limit)?;
        let step = step.map(|step| self.resolve_expr(step)).transpose()?;
        let target = self.current_scope();
        self.enter_scope(span)?;
        let result = (|| {
            let binding = self.meaning_declare(name, None, BindingKind::NumericFor,
                self.profile.rules().readonly_for_control)?;
            self.meaning_event(MeaningEvent::EnterLoop)?;
            self.push_loop(target)?;
            let body = self.resolve_nested_block(body);
            self.loops.pop();
            self.meaning_event(MeaningEvent::LeaveLoop)?;
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
        if result.is_ok() { self.meaning_event(MeaningEvent::LeaveScope { span, terminal: true })?; }
        self.scopes.pop();
        result
    }

    fn resolve_generic_for(
        &mut self,
        names: &[LocalName],
        values: &[Expr],
        body: &Block,
        span: Span,
    ) -> Result<ResolvedStmt, ResolveError<R::Error>> {
        let closing_span = values.get(3).map(Expr::span).unwrap_or(span);
        let values = self.resolve_expression_list(values, span)?;
        self.ensure_list(names.len(), span)?;
        let target = self.current_scope();
        self.enter_scope(span)?;
        let result = (|| {
            let closing = ResolvedGenericForClose {
                binding: self.meaning_generic_close(closing_span)?,
                span: closing_span,
            };
            let mut resolved_names = self.new_list();
            self.reserve_list(&mut resolved_names, names.len())?;
            for (index, name) in names.iter().enumerate() {
                let binding = self.meaning_declare(name, None, BindingKind::GenericFor,
                    index == 0 && self.profile.rules().readonly_for_control)?;
                resolved_names.push(ResolvedLocalName {
                    binding,
                    name: name.name.clone(),
                    attribute: name.attribute.clone(),
                    span: name.span,
                });
            }
            self.meaning_event(MeaningEvent::EnterLoop)?;
            self.push_loop(target)?;
            let body = self.resolve_nested_block(body);
            self.loops.pop();
            self.meaning_event(MeaningEvent::LeaveLoop)?;
            let body = body?;
            Ok(ResolvedStmt::GenericFor {
                names: resolved_names,
                values,
                closing,
                close_path: self.close_path(ExitKind::Normal, Some(target), span)?,
                body,
                span,
            })
        })();
        if result.is_ok() { self.meaning_event(MeaningEvent::LeaveScope { span, terminal: true })?; }
        self.scopes.pop();
        result
    }

    fn resolve_nested_block(&mut self, block: &Block) -> Result<ResolvedBlock, ResolveError<R::Error>> {
        self.enter_scope(block.span)?;
        let result = self.resolve_block(block);
        if result.is_ok() {
            self.meaning_event(MeaningEvent::LeaveScope { span: block.span, terminal: true })?;
        }
        self.scopes.pop();
        result
    }

    fn resolve_function_body(
        &mut self,
        body: &FunctionBody,
        method: Option<&MethodName>,
    ) -> Result<ResolvedFunctionBody, ResolveError<R::Error>> {
        let function = self.meaning_enter_function(body, method)?;
        let mut child = Resolver {
            lexed: self.lexed,
            limits: self.limits,
            profile: self.profile,
            owner: function,
            scopes: self.new_list(),
            loops: self.new_list(),
            completed_functions: self.new_list(),
            meaning: self.meaning.take(),
            recovery: self.recovery.take(),
        };
        let scope = child.meaning.as_ref().expect("resolver meaning 有效").current_scope_id();
        child.enter_scope_with_id(scope)?;
        child.ensure_list(body.parameters.len(), body.span)?;
        let parameter_count = body
            .parameters
            .len()
            .checked_add(usize::from(method.is_some()))
            .ok_or_else(|| child.limit(body.span, "參數超過編譯限制"))?;
        let mut parameters = child.new_list();
        child.reserve_list(&mut parameters, parameter_count)?;
        if let Some(method) = method {
            let name = child.shared_name(b"self")?;
            let binding = child.meaning.as_ref().expect("resolver meaning 有效")
                .current_binding_id(0).ok_or_else(|| child.resolve_error(method.colon_span,
                    "method self binding 索引不符"))?;
            child.track_binding(binding)?;
            parameters.push(ResolvedLocalName {
                binding,
                name,
                attribute: None,
                span: method.colon_span,
            });
        }
        for (index, parameter) in body.parameters.iter().enumerate() {
            let ordinal = index + usize::from(method.is_some());
            let binding = child.meaning.as_ref().expect("resolver meaning 有效")
                .current_binding_id(ordinal).ok_or_else(|| child.resolve_error(parameter.span,
                    "parameter binding 索引不符"))?;
            child.track_binding(binding)?;
            parameters.push(ResolvedLocalName {
                binding,
                name: parameter.name.clone(),
                attribute: parameter.attribute.clone(),
                span: parameter.span,
            });
        }
        let vararg = if let Some(vararg) = &body.vararg {
            if !self.profile.rules().named_vararg && vararg.table_name.is_some() {
                return Err(
                    child.resolve_error(vararg.span, "lua54 不支援 lua55 具名 vararg table")
                );
            }
            let table_binding = match &vararg.table_name {
                Some(name) => {
                    let binding = child.meaning.as_ref().expect("resolver meaning 有效")
                        .current_vararg_binding().ok_or_else(|| child.resolve_error(name.span,
                            "vararg binding 索引不符"))?;
                    child.track_binding(binding)?;
                    Some(binding)
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
        let resolved_body = child.resolve_block(&body.body)?;
        let finished = child.meaning_finish_function(body.span)?;
        child.scopes.pop();
        let (bindings, upvalues) = finished.into_resolved(
            child.recovery.as_deref_mut().expect("resolver recovery 有效"))?;
        self.meaning = child.meaning.take();
        self.recovery = child.recovery.take();
        let boxed_body = self.box_value(resolved_body)?;
        let metadata = ResolvedFunction {
            id: function,
            parent: Some(self.owner),
            span: body.span,
            bindings,
            upvalues,
        };
        let completed_count = child.completed_functions.len().checked_add(1)
            .ok_or(ResolveError::AllocationFailed)?;
        let recovery = self.recovery.as_deref_mut().expect("resolver recovery 有效");
        reserve_geometric_with(&mut self.completed_functions, completed_count, recovery)?;
        self.completed_functions.push(metadata);
        self.completed_functions.extend(child.completed_functions);
        Ok(ResolvedFunctionBody {
            function,
            parameters,
            vararg,
            body: boxed_body,
            span: body.span,
        })
    }

    fn ensure_list(&self, len: usize, span: Span) -> Result<(), ResolveError<R::Error>> {
        if len > self.limits.max_ast_nodes {
            Err(self.limit(span, "list 超過編譯限制"))
        } else {
            Ok(())
        }
    }

    fn current_scope(&self) -> ScopeId {
        self.scopes.last().expect("scope 已建立").id
    }

    fn register_labels(
        &mut self,
        block: &Block,
        terminal_labels_end_scope: bool,
    ) -> Result<(), ResolveError<R::Error>> {
        let scope = self.current_scope();
        let label_count = block
            .statements
            .iter()
            .filter(|statement| matches!(statement, Stmt::Label { .. }))
            .count();
        let frame = self.scopes.last_mut().expect("scope 已建立");
        reserve_map_with(&mut frame.labels, label_count,
            self.recovery.as_deref_mut().expect("resolver recovery 有效"))?;
        let last_non_void = block
            .statements
            .iter()
            .rposition(|statement| !matches!(statement, Stmt::Empty { .. } | Stmt::Label { .. }));
        for (index, statement) in block.statements.iter().enumerate() {
            let Stmt::Label {
                name, name_span, ..
            } = statement
            else {
                continue;
            };
            frame.labels.insert(name.clone(), LabelInfo {
                scope,
                terminal: terminal_labels_end_scope
                    && last_non_void.map_or(true, |last| index > last),
                span: *name_span,
            });
        }
        Ok(())
    }

    fn find_label(&self, name: &[u8]) -> Option<LabelInfo> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.labels.get(name).copied())
    }

    fn goto_close_path(&mut self, label: LabelInfo, span: Span) -> Result<ClosePath, ResolveError<R::Error>> {
        let mut path = self.close_path(ExitKind::Goto, Some(label.scope), span)?;
        if !label.terminal && label.span.start_byte >= span.start_byte {
            return Ok(path);
        }
        let target_count = self
            .scopes
            .iter()
            .find(|scope| scope.id == label.scope)
            .ok_or_else(|| self.resolve_error(span, "goto 目標作用域不符"))?
            .local_bindings.len();
        self.reserve_list(&mut path.exited_bindings, target_count)?;
        self.reserve_list(&mut path.bindings, target_count)?;
        let target = self.scopes.iter().find(|scope| scope.id == label.scope)
            .ok_or_else(|| self.resolve_error(span, "goto 目標作用域不符"))?;
        for binding in target.local_bindings.iter().rev() {
            let meta = self
                .meaning.as_ref().expect("resolver meaning 有效")
                .binding_info(*binding)
                .ok_or_else(|| self.resolve_error(span, "goto binding 索引不符"))?;
            if !label.terminal && meta.span.start_byte <= label.span.start_byte {
                break;
            }
            if meta.span.start_byte < span.start_byte {
                path.exited_bindings.push(*binding);
                if meta.close_marker.is_some() {
                    path.bindings.push(*binding);
                }
            }
        }
        Ok(path)
    }

    fn close_path(&mut self, kind: ExitKind, target_scope: Option<ScopeId>, span: Span) -> Result<ClosePath, ResolveError<R::Error>> {
        let from_scope = self.current_scope();
        let mut close_count = 0usize;
        let mut local_count = 0usize;
        for scope in self.scopes.iter().rev() {
            if Some(scope.id) == target_scope {
                break;
            }
            close_count = close_count.checked_add(scope.close_bindings.len())
                .ok_or(ResolveError::AllocationFailed)?;
            local_count = local_count.checked_add(scope.local_bindings.len())
                .ok_or(ResolveError::AllocationFailed)?;
        }
        let mut bindings = self.new_list();
        let mut exited_bindings = self.new_list();
        self.reserve_list(&mut bindings, close_count)?;
        self.reserve_list(&mut exited_bindings, local_count)?;
        for scope in self.scopes.iter().rev() {
            if Some(scope.id) == target_scope {
                break;
            }
            bindings.extend(scope.close_bindings.iter().rev().copied());
            exited_bindings.extend(scope.local_bindings.iter().rev().copied());
        }
        Ok(ClosePath {
            kind,
            span,
            from_scope,
            target_scope,
            bindings,
            exited_bindings,
        })
    }

    fn limit(&self, span: Span, message: &'static str) -> ResolveError<R::Error> {
        diagnostic_at_span(self.lexed, span, DiagnosticCode::CompileLimit, message).into()
    }

    fn resolve_error(&self, span: Span, message: &'static str) -> ResolveError<R::Error> {
        diagnostic_at_span(self.lexed, span, DiagnosticCode::Resolve, message).into()
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
    use super::{
        BindingAccess, BindingId, FunctionId, LabelInfo, ParentBinding, ResolvedStmt, ScopeFrame,
        ScopeId, UpvalueId, budget_layout_sizes, resolve,
    };
    use crate::{CompileLimits, DiagnosticCode, LanguageProfile, Span, lex, parse};
    use std::collections::HashMap;

    #[test]
    fn budget_layout_uses_private_resolver_element_sizes() {
        assert_eq!(
            budget_layout_sizes(),
            (
                core::mem::size_of::<ScopeFrame>(),
                core::mem::size_of::<LabelInfo>(),
                core::mem::size_of::<ParentBinding>(),
                core::mem::size_of::<BindingAccess>(),
            )
        );
        assert!(budget_layout_sizes().0 > 0);
    }

    fn observed_buckets(capacity: usize) -> usize {
        if capacity == 0 {
            return 0;
        }
        let buckets = if capacity < 8 {
            capacity + 1
        } else {
            assert_eq!(capacity % 7, 0);
            capacity / 7 * 8
        };
        assert!(buckets.is_power_of_two());
        buckets
    }

    fn assert_map_capacity_bound(old: usize, new: usize, entries: usize, entry_size: usize) {
        // 本工具鏈的 hashbrown 0.17.1：小表至少 4 bucket；其餘表
        // capacity 為 7/8 bucket。這裡用實際 capacity 還原 bucket，
        // 同時計入 grow/clone 瞬間的舊表與新表及控制 bytes。
        let buckets = observed_buckets(old) + observed_buckets(new);
        let observed_layout_ceiling = buckets * (entry_size + 1) + 64;
        let admission_ceiling = 5 * entries * (entry_size + 16) + 128;
        assert!(
            observed_layout_ceiling <= admission_ceiling,
            "old={old} new={new} entries={entries} buckets={buckets}"
        );
    }

    fn assert_vec_capacity_bound(old: usize, new: usize, entries: usize) {
        assert!(
            old + new <= 4 * entries,
            "old={old} new={new} entries={entries}"
        );
    }

    #[test]
    fn p17_local_close_list_cardinality_and_effective_attributes() {
        let limits = CompileLimits::default();
        let source = b"local <close> first <const>, second = nil, nil";
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
            panic!("有效 attribute 未保留為 local binding");
        };
        assert_eq!(bindings.len(), 2);
        let first = &resolved.functions[0].bindings[bindings[0].ordinal as usize];
        let second = &resolved.functions[0].bindings[bindings[1].ordinal as usize];
        assert!(first.readonly);
        assert!(first.close_marker.is_none());
        assert!(second.readonly);
        assert!(second.close_marker.is_some());

        for (source, profile) in [
            (b"local <close> a, b".as_slice(), LanguageProfile::Lua55),
            (
                b"local a <close>, b <close>".as_slice(),
                LanguageProfile::Lua54,
            ),
        ] {
            let chunk = lex(source, profile, &limits).unwrap();
            let parsed = parse(&chunk, profile, &limits).unwrap();
            let error = resolve(&parsed, &chunk, profile, &limits).unwrap_err();
            assert_eq!(error.code, DiagnosticCode::Resolve, "{profile:?}");
            assert_eq!(error.message, "local 宣告含多個 close 變數");
        }
    }

    #[test]
    fn p17_terminal_labels_allow_skipped_locals_without_opening_live_scope() {
        let limits = CompileLimits::default();
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            let source = b"do goto done; local x = 1; ::done:: ; end";
            let chunk = lex(source, profile, &limits).unwrap();
            let parsed = parse(&chunk, profile, &limits).unwrap();
            assert!(
                resolve(&parsed, &chunk, profile, &limits).is_ok(),
                "{profile:?}"
            );

            for source in [
                b"do goto live; local x = 1; ::live:: x = 2 end".as_slice(),
                b"do goto live; local x = 1; ::live:: f = function() return x end end",
                b"do goto live; local x <close> = nil; ::live:: f = x end",
                b"repeat goto live; local x = 1; ::live:: until x == nil",
                b"repeat goto live; local x <close> = nil; ::live:: until x == nil",
            ] {
                let chunk = lex(source, profile, &limits).unwrap();
                let parsed = parse(&chunk, profile, &limits).unwrap();
                let error = resolve(&parsed, &chunk, profile, &limits).unwrap_err();
                assert_eq!(error.code, DiagnosticCode::Resolve, "{profile:?}");
                assert_eq!(error.message, "goto 不可跳入 local scope");
            }
        }
    }

    #[test]
    fn p17_backward_goto_exits_captured_and_close_locals_in_reverse_order() {
        let limits = CompileLimits::default();
        let source = b"local base=1; ::again:: local captured=2; local f=function() return captured end; local first <close> = nil; local second <close> = nil; goto again";
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            let chunk = lex(source, profile, &limits).unwrap();
            let parsed = parse(&chunk, profile, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
            let statements: Vec<_> = resolved
                .root
                .statements
                .iter()
                .filter(|statement| !matches!(statement, ResolvedStmt::Empty { .. }))
                .collect();
            let local = |index: usize| match statements[index] {
                ResolvedStmt::Local { bindings, .. } => bindings[0],
                _ => panic!("預期 local binding"),
            };
            let (base, captured, f, first, second) =
                (local(0), local(2), local(3), local(4), local(5));
            let ResolvedStmt::Goto { close_path, .. } = statements[6] else {
                panic!("預期 backward goto");
            };
            assert_eq!(close_path.bindings, vec![second, first], "{profile:?}");
            assert_eq!(
                close_path.exited_bindings,
                vec![second, first, f, captured],
                "{profile:?}"
            );
            assert!(!close_path.exited_bindings.contains(&base));
            assert_eq!(close_path.from_scope, close_path.target_scope.unwrap());
        }
    }

    #[test]
    fn p17_forward_terminal_goto_exits_only_initialized_target_bindings() {
        let limits = CompileLimits::default();
        let source = b"local outer=1; local captured=function() return outer end; local outer_close <close> = nil; do local inner_close <close> = nil; goto done end; local skipped <close> = nil; ::done::";
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            let chunk = lex(source, profile, &limits).unwrap();
            let parsed = parse(&chunk, profile, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
            let statements: Vec<_> = resolved
                .root
                .statements
                .iter()
                .filter(|statement| !matches!(statement, ResolvedStmt::Empty { .. }))
                .collect();
            let local = |statement: &ResolvedStmt| match statement {
                ResolvedStmt::Local { bindings, .. } => bindings[0],
                _ => panic!("預期 local binding"),
            };
            let (outer, captured, outer_close, skipped) = (
                local(statements[0]),
                local(statements[1]),
                local(statements[2]),
                local(statements[4]),
            );
            let ResolvedStmt::Do { body, .. } = statements[3] else {
                panic!("預期 do block");
            };
            let body_statements: Vec<_> = body
                .statements
                .iter()
                .filter(|statement| !matches!(statement, ResolvedStmt::Empty { .. }))
                .collect();
            let inner_close = local(body_statements[0]);
            let ResolvedStmt::Goto { close_path, .. } = body_statements[1] else {
                panic!("預期 forward goto");
            };
            assert_eq!(
                close_path.bindings,
                vec![inner_close, outer_close],
                "{profile:?}"
            );
            assert_eq!(
                close_path.exited_bindings,
                vec![inner_close, outer_close, captured, outer],
                "{profile:?}"
            );
            assert!(!close_path.exited_bindings.contains(&skipped));
            assert_eq!(close_path.target_scope, Some(resolved.root.scope));
            assert_eq!(
                resolved.root.normal_close_path.bindings,
                vec![skipped, outer_close]
            );
            assert_eq!(resolved.root.normal_close_path.target_scope, None);
            assert_eq!(
                resolved.root.normal_close_path.exited_bindings,
                vec![skipped, outer_close, captured, outer]
            );
        }
    }

    #[test]
    fn budget_private_containers_cover_growth_shadow_reserve_and_clone() {
        let (scope_size, label_size, parent_size, access_size) = budget_layout_sizes();
        assert_eq!(scope_size, core::mem::size_of::<ScopeFrame>());
        let actual_entry = [
            core::mem::size_of::<(Vec<u8>, BindingId)>(),
            core::mem::size_of::<(Vec<u8>, LabelInfo)>(),
            core::mem::size_of::<(Vec<u8>, ParentBinding)>(),
            core::mem::size_of::<(Vec<u8>, [Option<BindingId>; 2])>(),
            core::mem::size_of::<(BindingId, BindingAccess)>(),
            core::mem::size_of::<(BindingId, UpvalueId)>(),
        ]
        .into_iter()
        .max()
        .unwrap();
        let admitted_entry = 16
            + [
                core::mem::size_of::<(Vec<u8>, BindingId)>(),
                core::mem::size_of::<Vec<u8>>() + label_size,
                core::mem::size_of::<Vec<u8>>() + parent_size,
                core::mem::size_of::<Vec<u8>>() + 2 * core::mem::size_of::<Option<BindingId>>(),
                core::mem::size_of::<BindingId>() + access_size,
                core::mem::size_of::<(BindingId, UpvalueId)>(),
            ]
            .into_iter()
            .max()
            .unwrap();
        assert!(actual_entry <= admitted_entry);

        let mut scope = ScopeFrame {
            id: ScopeId(0),
            bindings: HashMap::new(),
            local_bindings: Vec::new(),
            close_bindings: Vec::new(),
            labels: HashMap::new(),
            declaration_spans: Vec::new(),
            global_mode: None,
        };
        let label_capacity_before_reserve = scope.labels.capacity();
        scope.labels.try_reserve(64).unwrap();
        assert_map_capacity_bound(
            label_capacity_before_reserve,
            scope.labels.capacity(),
            64,
            core::mem::size_of::<(Vec<u8>, LabelInfo)>(),
        );
        let spans_before_reserve = scope.declaration_spans.capacity();
        scope.declaration_spans.try_reserve(64).unwrap();
        assert_vec_capacity_bound(spans_before_reserve, scope.declaration_spans.capacity(), 64);

        let mut pending = Vec::<(BindingId, UpvalueId)>::new();
        let mut parent_visible = HashMap::<Vec<u8>, ParentBinding>::new();
        let mut parent_metadata = HashMap::<BindingId, BindingAccess>::new();
        let mut implicit = HashMap::<Vec<u8>, [Option<BindingId>; 2]>::new();
        let mut upvalue_ids = HashMap::<BindingId, UpvalueId>::new();
        for index in 0..64 {
            let binding = BindingId {
                function: FunctionId(0),
                ordinal: index,
            };
            let span = Span {
                start_byte: index as usize,
                end_byte: index as usize + 1,
            };
            let key = format!("n{index}").into_bytes();
            let old_scope = scope.bindings.capacity();
            scope.bindings.insert(key.clone(), binding);
            assert_map_capacity_bound(
                old_scope,
                scope.bindings.capacity(),
                index as usize + 1,
                core::mem::size_of::<(Vec<u8>, BindingId)>(),
            );
            let old_labels = scope.labels.capacity();
            scope.labels.insert(
                key.clone(),
                LabelInfo {
                    scope: scope.id,
                    terminal: false,
                    span,
                },
            );
            assert_map_capacity_bound(
                old_labels,
                scope.labels.capacity(),
                64,
                core::mem::size_of::<(Vec<u8>, LabelInfo)>(),
            );
            for values in [&mut scope.local_bindings, &mut scope.close_bindings] {
                let old = values.capacity();
                values.push(binding);
                assert_vec_capacity_bound(old, values.capacity(), index as usize + 1);
            }
            let old = scope.declaration_spans.capacity();
            scope.declaration_spans.push(span);
            assert_vec_capacity_bound(old, scope.declaration_spans.capacity(), 64);
            let old = pending.capacity();
            pending.push((binding, UpvalueId(index)));
            assert_vec_capacity_bound(old, pending.capacity(), index as usize + 1);

            let old = parent_visible.capacity();
            parent_visible.insert(key.clone(), ParentBinding::Direct(binding));
            assert_map_capacity_bound(
                old,
                parent_visible.capacity(),
                index as usize + 1,
                core::mem::size_of::<(Vec<u8>, ParentBinding)>(),
            );
            let old = parent_metadata.capacity();
            parent_metadata.insert(binding, BindingAccess { readonly: false });
            assert_map_capacity_bound(
                old,
                parent_metadata.capacity(),
                index as usize + 1,
                core::mem::size_of::<(BindingId, BindingAccess)>(),
            );
            let old = implicit.capacity();
            implicit.insert(key, [Some(binding), None]);
            assert_map_capacity_bound(
                old,
                implicit.capacity(),
                index as usize + 1,
                core::mem::size_of::<(Vec<u8>, [Option<BindingId>; 2])>(),
            );
            let old = upvalue_ids.capacity();
            upvalue_ids.insert(binding, UpvalueId(index));
            assert_map_capacity_bound(
                old,
                upvalue_ids.capacity(),
                index as usize + 1,
                core::mem::size_of::<(BindingId, UpvalueId)>(),
            );
        }
        let old = scope.bindings.capacity();
        for index in 0..64 {
            scope.bindings.insert(
                b"n0".to_vec(),
                BindingId {
                    function: FunctionId(0),
                    ordinal: index,
                },
            );
        }
        assert_eq!(scope.bindings.len(), 64);
        assert_eq!(scope.bindings.capacity(), old);

        let visible_clone = parent_visible.clone();
        let access_clone = parent_metadata.clone();
        assert_eq!(visible_clone.capacity(), parent_visible.capacity());
        assert_eq!(access_clone.capacity(), parent_metadata.capacity());
        assert_map_capacity_bound(
            parent_visible.capacity(),
            visible_clone.capacity(),
            128,
            core::mem::size_of::<(Vec<u8>, ParentBinding)>(),
        );
        assert_map_capacity_bound(
            parent_metadata.capacity(),
            access_clone.capacity(),
            128,
            core::mem::size_of::<(BindingId, BindingAccess)>(),
        );
    }

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

    #[test]
    fn p09_2_scope_close_keeps_same_scope_shadow_binding_ids() {
        let source = b"local f; do local x=1; local x=2; f=function() return x end end; return f";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let module = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let body = module
            .root
            .statements
            .iter()
            .find_map(|statement| {
                if let ResolvedStmt::Do { body, .. } = statement {
                    Some(body)
                } else {
                    None
                }
            })
            .expect("do scope 須存在");
        let locals = body
            .statements
            .iter()
            .filter_map(|statement| {
                if let ResolvedStmt::Local { bindings, .. } = statement {
                    Some(bindings[0])
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(locals.len(), 2);
        let (first, second) = (locals[0], locals[1]);
        assert_ne!(first, second);
        assert_eq!(body.normal_close_path.exited_bindings, vec![second, first]);
        assert!(body.normal_close_path.bindings.is_empty());
    }
}
