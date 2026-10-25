use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{AllocationRecovery, ReserveError, StateAllocator, try_reserve_exact_with};
use core::borrow::Borrow;
use core::hash::{Hash, Hasher};

use crate::ast::{AstName, Attribute, Expr, LocalName};
use crate::parser::ParseError;
use crate::{CompileLimits, Diagnostic, DiagnosticCode, LanguageProfile, SourcePosition, Span, Token};
use crate::official_failure::{OfficialFailure, OfficialFailureNear, OfficialFailureReason};
use super::{BindingId, BindingKind, BindingMeta, FunctionId, ResolvedName, ResolvedVec,
    ResolveError, ScopeId, StateMap, UpvalueId, UpvalueSource, new_state_map,
    reserve_geometric_with, shared_name};

pub(crate) trait MeaningMeter: AllocationRecovery {
    fn admit_meaning(&mut self, work: usize, temporary: usize) -> Result<(), Self::Error>;
}

pub(crate) struct Unmetered<'a, R>(pub(crate) &'a mut R);

impl<R: AllocationRecovery> AllocationRecovery for Unmetered<'_, R> {
    type Error = R::Error;
    fn allocator(&self) -> StateAllocator { self.0.allocator() }
    fn recover_after_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        self.0.recover_after_refusal(before)
    }
}

impl<R: AllocationRecovery> MeaningMeter for Unmetered<'_, R> {
    fn admit_meaning(&mut self, _: usize, _: usize) -> Result<(), Self::Error> { Ok(()) }
}

#[derive(Debug)]
pub(super) enum MeaningError<E> {
    Diagnostic { span: Span, code: DiagnosticCode, message: &'static str,
        official: Option<OfficialFailure> },
    Recovery(E),
    AllocationFailed,
}

pub(crate) enum MeaningEvent<'a> {
    Root(Span),
    EnterScope(Span),
    LeaveScope { span: Span, terminal: bool },
    EnterFunction { parameters: &'a [LocalName], vararg: Option<&'a LocalName>,
        variadic: bool, method: Option<Span>, span: Span },
    LeaveFunction(Span),
    EnterLoop,
    LeaveLoop,
    CheckVararg(Span),
    CheckBreak(Span),
    Name { name: &'a AstName, span: Span },
    WriteTarget(&'a Expr),
    BeginDeclarations,
    DeclarationAttribute { attribute: Option<&'a Attribute>, global: bool, span: Span },
    Attribute { attribute: Option<&'a Attribute>, global: bool, span: Span },
    Declare { name: &'a LocalName, attribute: Option<&'a Attribute>,
        kind: BindingKind, readonly: bool },
    GenericForClose(Span),
    NamedGlobalMode,
    WildcardGlobalMode { attribute: Option<&'a Attribute>, span: Span },
    GlobalTarget { name: &'a AstName, span: Span },
    QueueLabel { name: &'a AstName, span: Span },
    FlushLabels { terminal: bool },
    Goto { name: &'a AstName, span: Span },
}

pub(crate) trait MeaningContext {
    fn event<R: MeaningMeter>(&mut self, event: MeaningEvent<'_>, tokens: &[Token], meter: &mut R)
        -> Result<(), ParseError<R::Error>>;
}

pub(crate) struct AstOnly;

impl MeaningContext for AstOnly {
    fn event<R: MeaningMeter>(&mut self, _: MeaningEvent<'_>, _: &[Token], _: &mut R)
        -> Result<(), ParseError<R::Error>> { Ok(()) }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AttributeKind { Mutable, Const, Close }

pub(crate) fn classify_attribute(attribute: Option<&Attribute>, global: bool)
    -> Result<AttributeKind, &'static str> {
    match attribute.map(|attribute| attribute.name.as_slice()) {
        None => Ok(AttributeKind::Mutable),
        Some(b"const") => Ok(AttributeKind::Const),
        Some(b"close") if global => Err("global 不可為 close binding"),
        Some(b"close") => Ok(AttributeKind::Close),
        Some(_) if global => Err("未知 global attribute"),
        Some(_) => Err("未知 local attribute"),
    }
}

pub(super) fn parse_error<E>(error: MeaningError<E>, tokens: &[Token]) -> ParseError<E> {
    match error {
        MeaningError::Diagnostic { span, code, message, .. } => {
            let token = tokens.iter().find(|token| token.span.start_byte == span.start_byte)
                .or_else(|| tokens.last());
            let (span, start, end) = token.map(|token| (token.span, token.start, token.end))
                .unwrap_or((span, SourcePosition { line: 1, column: 1 },
                    SourcePosition { line: 1, column: 1 }));
            ParseError::Diagnostic(Diagnostic { code, span, start, end, message })
        }
        MeaningError::Recovery(error) => ParseError::Recovery(error),
        MeaningError::AllocationFailed => ParseError::AllocationFailed,
    }
}

fn semantic<E>(span: Span, message: &'static str) -> MeaningError<E> {
    MeaningError::Diagnostic { span, code: DiagnosticCode::Resolve, message, official: None }
}

fn semantic_official<E>(span: Span, message: &'static str,
    reason: OfficialFailureReason) -> MeaningError<E> {
    MeaningError::Diagnostic { span, code: DiagnosticCode::Resolve, message,
        official: Some(OfficialFailure { reason, line: 0, near: OfficialFailureNear::None }) }
}

fn attribute_error<E>(span: Span, message: &'static str) -> MeaningError<E> {
    MeaningError::Diagnostic { span, code: DiagnosticCode::Parse, message, official: None }
}

fn limit<E>(span: Span, message: &'static str) -> MeaningError<E> {
    MeaningError::Diagnostic { span, code: DiagnosticCode::CompileLimit, message, official: None }
}

fn push<T, R: MeaningMeter>(
    values: &mut AllocVec<T, StateAllocator>, value: T, meter: &mut R,
) -> Result<(), MeaningError<R::Error>> {
    meter.admit_meaning(1, 0).map_err(MeaningError::Recovery)?;
    if values.len() == values.capacity() {
        let target = values.capacity().checked_mul(2).unwrap_or(usize::MAX).max(4);
        let allocation = target.checked_mul(core::mem::size_of::<T>())
            .ok_or(MeaningError::AllocationFailed)?;
        meter.admit_meaning(0, allocation).map_err(MeaningError::Recovery)?;
        try_reserve_exact_with(values, target - values.len(), meter).map_err(|error| match error {
            ReserveError::Recovery(error) => MeaningError::Recovery(error),
            _ => MeaningError::AllocationFailed,
        })?;
        let extra = values.capacity().checked_sub(target)
            .and_then(|count| count.checked_mul(core::mem::size_of::<T>()))
            .ok_or(MeaningError::AllocationFailed)?;
        if extra != 0 {
            meter.admit_meaning(0, extra).map_err(MeaningError::Recovery)?;
        }
    }
    values.push(value);
    Ok(())
}

fn admit_scan<R: MeaningMeter>(meter: &mut R, entries: usize, width: usize)
    -> Result<(), MeaningError<R::Error>> {
    let work = entries.checked_add(1).and_then(|entries| width.checked_add(1)
        .and_then(|width| entries.checked_mul(width)))
        .ok_or(MeaningError::AllocationFailed)?;
    meter.admit_meaning(work, 0).map_err(MeaningError::Recovery)
}

fn reserve_index<K: Eq + Hash + Borrow<[u8]>, V, R: MeaningMeter>(values: &mut StateMap<K, V>,
    max_width: &mut usize, key: &[u8], meter: &mut R) -> Result<(), MeaningError<R::Error>> {
    admit_scan(meter, values.len(), key.len())?;
    if values.contains_key(key) {
        admit_scan(meter, values.len(), key.len())?;
        return Ok(());
    }
    if values.len() < values.capacity() {
        admit_scan(meter, values.len(), key.len())?;
        *max_width = (*max_width).max(key.len());
        return Ok(());
    }
    // StateMap 成長時會重新雜湊所有既有 key；先支付遍歷與最大 key 寬度上界。
    admit_scan(meter, values.len(), *max_width)?;
    admit_scan(meter, values.len(), key.len())?;
    let required = values.len().checked_add(1).ok_or(MeaningError::AllocationFailed)?;
    let bucket_bound = required.max(4).checked_mul(4).ok_or(MeaningError::AllocationFailed)?;
    let entry = core::mem::size_of::<(K, V)>().checked_add(16)
        .ok_or(MeaningError::AllocationFailed)?;
    let bytes = bucket_bound.checked_mul(entry).and_then(|bytes| bytes.checked_add(128))
        .ok_or(MeaningError::AllocationFailed)?;
    meter.admit_meaning(0, bytes).map_err(MeaningError::Recovery)?;
    let allocator = values.allocator().clone();
    if !allocator.same_binding(&meter.allocator()) { return Err(MeaningError::AllocationFailed); }
    let before = allocator.refusal_count();
    if values.try_reserve(1).is_ok() {
        *max_width = (*max_width).max(key.len());
        return Ok(());
    }
    if !allocator.is_lua() || allocator.refusal_count() == before {
        return Err(MeaningError::AllocationFailed);
    }
    if !meter.recover_after_refusal(before).map_err(MeaningError::Recovery)? {
        return Err(MeaningError::AllocationFailed);
    }
    values.try_reserve(1).map_err(|_| MeaningError::AllocationFailed)?;
    *max_width = (*max_width).max(key.len());
    Ok(())
}

#[derive(Clone)]
enum Name {
    RootEnvironment,
    ImplicitSelf,
    HiddenClose,
    User(AstName),
}

impl Name {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::RootEnvironment => b"_ENV",
            Self::ImplicitSelf => b"self",
            Self::HiddenClose => b"<generic-for-close>",
            Self::User(name) => name.as_slice(),
        }
    }
}

impl Borrow<[u8]> for Name {
    fn borrow(&self) -> &[u8] { self.bytes() }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool { self.bytes() == other.bytes() }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) { self.bytes().hash(state); }
}

struct Binding {
    id: BindingId,
    name: Name,
    span: Span,
    declaration_ordinal: Option<u32>,
    scope_id: Option<ScopeId>,
    kind: BindingKind,
    readonly: bool,
    attribute: Option<Attribute>,
    close_marker: Option<Span>,
    scope_depth: usize,
}

#[derive(Clone, Copy)]
pub(super) struct BindingInfo {
    pub span: Span,
    pub kind: BindingKind,
    pub close_marker: Option<Span>,
}

struct Upvalue {
    origin: BindingId,
    source: UpvalueSource,
}

pub(super) struct MeaningFunction {
    id: FunctionId,
    bindings: AllocVec<Binding, StateAllocator>,
    upvalues: AllocVec<Upvalue, StateAllocator>,
}

impl MeaningFunction {
    pub(super) fn into_resolved<R: AllocationRecovery>(self, recovery: &mut R)
        -> Result<(ResolvedVec<BindingMeta>, ResolvedVec<UpvalueSource>), ResolveError<R::Error>> {
        let mut bindings = ResolvedVec::new_in(recovery.allocator());
        reserve_geometric_with(&mut bindings, self.bindings.len(), recovery)?;
        for binding in self.bindings {
            let name = match binding.name {
                Name::User(name) => name,
                other => shared_name(recovery, other.bytes())?,
            };
            bindings.push(BindingMeta {
                id: binding.id, name, span: binding.span, kind: binding.kind,
                owner: self.id, scope_depth: binding.scope_depth,
                readonly: binding.readonly, attribute: binding.attribute,
                close_marker: binding.close_marker,
            });
        }
        let mut upvalues = ResolvedVec::new_in(recovery.allocator());
        reserve_geometric_with(&mut upvalues, self.upvalues.len(), recovery)?;
        for upvalue in self.upvalues { upvalues.push(upvalue.source); }
        Ok((bindings, upvalues))
    }
}

struct Label {
    name: AstName,
    span: Span,
    terminal: bool,
    active_max: Option<u32>,
}

struct PendingGoto {
    name: AstName,
    span: Span,
    line: usize,
    next_declaration: u32,
}

#[derive(Clone, Copy)]
enum GlobalMode {
    NamedOnly,
    Wildcard { readonly: bool },
}

#[derive(Clone, Copy)]
enum Visibility { Lexical, Hidden, Implicit }

struct Scope {
    id: ScopeId,
    visible: StateMap<Name, BindingId>,
    visible_max_width: usize,
    labels: StateMap<AstName, Label>,
    label_max_width: usize,
    queued_labels: AllocVec<(AstName, Span), StateAllocator>,
    pending: AllocVec<PendingGoto, StateAllocator>,
    mode: Option<GlobalMode>,
    active_declaration_max: Option<u32>,
}

struct Function {
    id: FunctionId,
    next_binding: u32,
    next_declaration: u32,
    next_scope: u32,
    bindings: AllocVec<Binding, StateAllocator>,
    scopes: AllocVec<Scope, StateAllocator>,
    upvalues: AllocVec<Upvalue, StateAllocator>,
    implicit_globals: StateMap<Name, [Option<BindingId>; 2]>,
    implicit_global_max_width: usize,
    vararg_binding: Option<BindingId>,
    loops: usize,
    vararg: bool,
    inherited_mode: Option<GlobalMode>,
    pending_break: Option<Span>,
    label_count: usize,
    goto_count: usize,
}

pub(crate) fn budget_layout_sizes() -> [usize; 7] {
    [
        core::mem::size_of::<Function>(),
        core::mem::size_of::<Scope>(),
        core::mem::size_of::<Binding>(),
        core::mem::size_of::<Label>(),
        core::mem::size_of::<PendingGoto>(),
        core::mem::size_of::<(AstName, Span)>(),
        core::mem::size_of::<(Name, [Option<BindingId>; 2])>(),
    ]
}

impl Function {
    fn new(id: FunctionId, allocator: &StateAllocator, vararg: bool, mode: Option<GlobalMode>) -> Self {
        Self { id, next_binding: 0, next_declaration: 0, next_scope: 0,
            bindings: AllocVec::new_in(allocator.clone()), scopes: AllocVec::new_in(allocator.clone()),
            upvalues: AllocVec::new_in(allocator.clone()), implicit_globals: new_state_map(allocator.clone()),
            implicit_global_max_width: 0,
            vararg_binding: None, loops: 0, vararg, inherited_mode: mode, pending_break: None,
            label_count: 0, goto_count: 0 }
    }

    fn binding(&self, id: BindingId) -> Option<&Binding> {
        self.bindings.get(id.ordinal as usize).filter(|binding| binding.id == id)
    }

    fn visible(&self, name: &[u8]) -> Option<BindingId> {
        self.scopes.iter().rev().find_map(|scope| scope.visible.get(name).copied())
    }

    fn mode(&self) -> Option<GlobalMode> {
        let mut named = false;
        for scope in self.scopes.iter().rev() {
            match scope.mode {
                Some(mode @ GlobalMode::Wildcard { .. }) => return Some(mode),
                Some(GlobalMode::NamedOnly) => named = true,
                None => {}
            }
        }
        match self.inherited_mode {
            Some(mode @ GlobalMode::Wildcard { .. }) => Some(mode),
            Some(GlobalMode::NamedOnly) => Some(GlobalMode::NamedOnly),
            None if named => Some(GlobalMode::NamedOnly),
            None => None,
        }
    }
}

pub(crate) struct MeaningState {
    profile: LanguageProfile,
    limits: CompileLimits,
    allocator: StateAllocator,
    next_function: u32,
    functions: AllocVec<Function, StateAllocator>,
    root_environment: Option<BindingId>,
    declaration_closes: usize,
    failure: Option<OfficialFailure>,
}

impl MeaningState {
    pub(crate) fn new(profile: LanguageProfile, limits: CompileLimits, allocator: StateAllocator) -> Self {
        Self { profile, limits, functions: AllocVec::new_in(allocator.clone()),
            allocator, next_function: 0, root_environment: None, declaration_closes: 0,
            failure: None }
    }

    pub(crate) fn take_official_failure(&mut self) -> Option<OfficialFailure> {
        self.failure.take()
    }

    fn current(&self) -> &Function { self.functions.last().expect("meaning function 已建立") }
    fn current_mut(&mut self) -> &mut Function { self.functions.last_mut().expect("meaning function 已建立") }

    pub(super) fn name_event<R: MeaningMeter>(&mut self, name: &AstName, span: Span,
        tokens: &[Token], meter: &mut R) -> Result<ResolvedName, ParseError<R::Error>> {
        self.resolve_name(name, span, meter).map_err(|mut error| {
            if let MeaningError::Diagnostic { official, .. } = &mut error {
                if let Some(mut failure) = official.take() {
                    let source_line = tokens.last().map(|token| token.start.line).unwrap_or(1);
                    let last_line = tokens.iter().find(|token| token.span.start_byte == span.start_byte)
                        .map(|token| token.start.line).unwrap_or(source_line);
                    failure.line = if self.profile == LanguageProfile::Lua55 { last_line }
                        else { source_line };
                    self.failure = Some(failure);
                }
            }
            parse_error(error, tokens)
        })
    }

    pub(super) fn current_scope_id(&self) -> ScopeId {
        self.current().scopes.last().expect("meaning scope 已建立").id
    }

    pub(super) fn current_binding_id(&self, ordinal: usize) -> Option<BindingId> {
        self.current().bindings.get(ordinal).map(|binding| binding.id)
    }

    pub(super) fn current_vararg_binding(&self) -> Option<BindingId> {
        self.current().vararg_binding
    }

    pub(super) fn binding_info(&self, id: BindingId) -> Option<BindingInfo> {
        self.functions.iter().find(|function| function.id == id.function)
            .and_then(|function| function.binding(id))
            .map(|binding| BindingInfo { span: binding.span, kind: binding.kind,
                close_marker: binding.close_marker })
    }

    pub(super) fn begin<R: MeaningMeter>(&mut self, span: Span, meter: &mut R)
        -> Result<ScopeId, MeaningError<R::Error>> {
        if !self.functions.is_empty() { return Err(semantic(span, "meaning root 重複建立")); }
        push(&mut self.functions, Function::new(FunctionId(0), &self.allocator, true, None), meter)?;
        self.next_function = 1;
        let scope = self.enter_scope(span, meter)?;
        let env = self.bind(Name::RootEnvironment, BindingKind::Environment, None,
            false, false, Visibility::Lexical, span, meter)?;
        self.root_environment = Some(env);
        Ok(scope)
    }

    pub(super) fn enter_scope<R: MeaningMeter>(&mut self, span: Span, meter: &mut R)
        -> Result<ScopeId, MeaningError<R::Error>> {
        let max_scope_depth = self.limits.max_scope_depth;
        let allocator = self.allocator.clone();
        let function = self.current_mut();
        if function.scopes.len() >= max_scope_depth { return Err(limit(span, "作用域深度超過編譯限制")); }
        let id = ScopeId(function.next_scope);
        function.next_scope = function.next_scope.checked_add(1)
            .ok_or_else(|| limit(span, "作用域數超過編譯限制"))?;
        push(&mut function.scopes, Scope { id,
            visible: new_state_map(allocator.clone()), visible_max_width: 0,
            labels: new_state_map(allocator.clone()), label_max_width: 0,
            queued_labels: AllocVec::new_in(allocator.clone()), pending: AllocVec::new_in(allocator),
            mode: None, active_declaration_max: None }, meter)?;
        Ok(id)
    }

    fn bind<R: MeaningMeter>(&mut self, name: Name, kind: BindingKind,
        attribute: Option<&Attribute>, requested_readonly: bool, track_declaration: bool,
        visibility: Visibility, span: Span, meter: &mut R,
    ) -> Result<BindingId, MeaningError<R::Error>> {
        let (readonly, close) = self.attribute(attribute, kind == BindingKind::Global, span)?;
        let readonly = readonly || requested_readonly;
        let max_bindings = self.limits.max_bindings_per_function;
        let function = self.current_mut();
        if function.bindings.len() >= max_bindings { return Err(limit(span, "binding 數超過編譯限制")); }
        let id = BindingId { function: function.id, ordinal: function.next_binding };
        let next = function.next_binding.checked_add(1)
            .ok_or_else(|| limit(span, "binding 數超過編譯限制"))?;
        if matches!(visibility, Visibility::Lexical) {
            let scope = function.scopes.last_mut().expect("meaning scope 已建立");
            reserve_index(&mut scope.visible, &mut scope.visible_max_width, name.bytes(), meter)?;
        }
        let scope_depth = if matches!(visibility, Visibility::Implicit) { 0 }
            else { function.scopes.len().saturating_sub(1) };
        let close_marker = if kind == BindingKind::GenericForClose { Some(span) }
            else if close { attribute.map(|attribute| attribute.span) } else { None };
        let declaration_ordinal = track_declaration.then_some(function.next_declaration);
        let scope_id = function.scopes.last().map(|scope| scope.id);
        push(&mut function.bindings, Binding { id, name: name.clone(), span,
            declaration_ordinal, scope_id, kind, readonly,
            attribute: attribute.cloned(), close_marker, scope_depth }, meter)?;
        function.next_binding = next;
        if matches!(visibility, Visibility::Lexical) {
            function.scopes.last_mut().expect("meaning scope 已建立").visible.insert(name, id);
        }
        if track_declaration {
            Self::mark_declaration(function, span)?;
        }
        Ok(id)
    }

    fn mark_declaration<E>(function: &mut Function, span: Span)
        -> Result<(), MeaningError<E>> {
        let ordinal = function.next_declaration;
        function.next_declaration = ordinal.checked_add(1)
            .ok_or_else(|| limit(span, "宣告數超過編譯表示範圍"))?;
        function.scopes.last_mut().expect("meaning scope 已建立").active_declaration_max = Some(ordinal);
        Ok(())
    }

    pub(super) fn attribute<E>(&self, attribute: Option<&Attribute>, global: bool, span: Span)
        -> Result<(bool, bool), MeaningError<E>> {
        match classify_attribute(attribute, global).map_err(|message| attribute_error(span, message))? {
            AttributeKind::Mutable => Ok((false, false)),
            AttributeKind::Const => Ok((true, false)),
            AttributeKind::Close => Ok((true, true)),
        }
    }

    fn declaration_attribute<E>(&mut self, attribute: Option<&Attribute>, global: bool,
        span: Span) -> Result<(), MeaningError<E>> {
        let (_, close) = self.attribute(attribute, global, span)?;
        if close {
            self.declaration_closes = self.declaration_closes.checked_add(1)
                .ok_or_else(|| limit(span, "close 宣告數超過編譯限制"))?;
            if self.declaration_closes > 1 {
                return Err(semantic_official(span, "local 宣告含多個 close 變數",
                    OfficialFailureReason::MultipleClose {
                        span: attribute.map(|attribute| attribute.span).unwrap_or(span) }));
            }
        }
        Ok(())
    }

    pub(super) fn declare<R: MeaningMeter>(&mut self, name: &LocalName, kind: BindingKind,
        readonly: bool, meter: &mut R,
    ) -> Result<BindingId, MeaningError<R::Error>> {
        self.bind(Name::User(name.name.clone()), kind, name.attribute.as_ref(), readonly,
            true, Visibility::Lexical, name.span, meter)
    }

    pub(super) fn declare_with_attribute<R: MeaningMeter>(&mut self, name: &LocalName,
        attribute: Option<&Attribute>, kind: BindingKind, readonly: bool, meter: &mut R,
    ) -> Result<BindingId, MeaningError<R::Error>> {
        self.bind(Name::User(name.name.clone()), kind, attribute, readonly,
            true, Visibility::Lexical, name.span, meter)
    }

    pub(super) fn declare_generic_close<R: MeaningMeter>(&mut self, span: Span, meter: &mut R)
        -> Result<BindingId, MeaningError<R::Error>> {
        self.bind(Name::HiddenClose, BindingKind::GenericForClose, None, true,
            true, Visibility::Hidden, span, meter)
    }

    pub(super) fn set_named_global_mode(&mut self) {
        let scope = self.current_mut().scopes.last_mut().expect("meaning scope 已建立");
        if scope.mode.is_none() { scope.mode = Some(GlobalMode::NamedOnly); }
    }

    pub(super) fn set_wildcard_global_mode<E>(&mut self, attribute: Option<&Attribute>, span: Span)
        -> Result<(), MeaningError<E>> {
        let (readonly, _) = self.attribute(attribute, true, span)?;
        let function = self.current_mut();
        function.scopes.last_mut().expect("meaning scope 已建立").mode = Some(GlobalMode::Wildcard { readonly });
        Self::mark_declaration(function, span)?;
        Ok(())
    }

    pub(super) fn check_vararg<E>(&self, span: Span) -> Result<(), MeaningError<E>> {
        if self.current().vararg { Ok(()) } else { Err(semantic(span, "vararg 不在 function 內")) }
    }

    pub(super) fn enter_function<R: MeaningMeter>(&mut self, parameters: &[LocalName],
        vararg: Option<&LocalName>, variadic: bool, method: Option<Span>, span: Span, meter: &mut R,
    ) -> Result<FunctionId, MeaningError<R::Error>> {
        let count = parameters.len().checked_add(usize::from(method.is_some()))
            .ok_or_else(|| limit(span, "參數超過編譯限制"))?;
        if count > self.limits.max_parameters { return Err(limit(span, "參數超過編譯限制")); }
        let id = FunctionId(self.next_function);
        self.next_function = self.next_function.checked_add(1)
            .ok_or_else(|| limit(span, "function 數超過編譯限制"))?;
        meter.admit_meaning(self.current().scopes.len(), 0).map_err(MeaningError::Recovery)?;
        let inherited = self.current().mode();
        push(&mut self.functions, Function::new(id, &self.allocator, variadic, inherited), meter)?;
        self.enter_scope(span, meter)?;
        if let Some(colon_span) = method {
            self.bind(Name::ImplicitSelf, BindingKind::Parameter, None, false,
                true, Visibility::Lexical, colon_span, meter)?;
        }
        for parameter in parameters { self.declare(parameter, BindingKind::Parameter, false, meter)?; }
        if let Some(name) = vararg {
            let binding = self.declare(name, BindingKind::VarargTable, true, meter)?;
            self.current_mut().vararg_binding = Some(binding);
        }
        Ok(id)
    }

    pub(super) fn enter_loop(&mut self) { self.current_mut().loops += 1; }
    pub(super) fn leave_loop(&mut self) { self.current_mut().loops -= 1; }

    pub(super) fn check_break<E>(&mut self, span: Span) -> Result<(), MeaningError<E>> {
        if self.current().loops != 0 { return Ok(()); }
        if self.profile == LanguageProfile::Lua55 { return Err(semantic(span, "break 不在 loop 內")); }
        self.current_mut().pending_break.get_or_insert(span);
        Ok(())
    }

    fn find_visible(&self, name: &[u8]) -> Option<(usize, BindingId)> {
        self.functions.iter().enumerate().rev().find_map(|(index, function)| {
            function.visible(name).map(|binding| (index, binding))
        })
    }

    fn admit_visible_lookup<R: MeaningMeter>(&self, width: usize, meter: &mut R)
        -> Result<(), MeaningError<R::Error>> {
        meter.admit_meaning(self.functions.len(), 0).map_err(MeaningError::Recovery)?;
        let scopes = self.functions.iter()
            .try_fold(0usize, |count, function| count.checked_add(function.scopes.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        meter.admit_meaning(scopes, 0).map_err(MeaningError::Recovery)?;
        let candidates = self.functions.iter().flat_map(|function| function.scopes.iter())
            .try_fold(0usize, |count, scope| count.checked_add(scope.visible.len())
                .and_then(|count| count.checked_add(1)))
            .ok_or(MeaningError::AllocationFailed)?;
        admit_scan(meter, candidates, width)
    }

    fn capture<R: MeaningMeter>(&mut self, origin: usize, binding: BindingId,
        span: Span, meter: &mut R,
    ) -> Result<UpvalueId, MeaningError<R::Error>> {
        let max_upvalues = self.limits.max_upvalues_per_function;
        meter.admit_meaning(self.functions.len().saturating_sub(origin + 1), 0)
            .map_err(MeaningError::Recovery)?;
        let comparisons = self.functions[origin + 1..].iter()
            .try_fold(0usize, |count, function| count.checked_add(function.upvalues.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        admit_scan(meter, comparisons, core::mem::size_of::<BindingId>())?;
        let mut last = UpvalueId(0);
        for index in origin + 1..self.functions.len() {
            let function = &mut self.functions[index];
            if let Some(found) = function.upvalues.iter().position(|candidate| candidate.origin == binding) {
                last = UpvalueId(u32::try_from(found).map_err(|_| limit(span, "upvalue 數超過編譯限制"))?);
                continue;
            }
            if function.upvalues.len() >= max_upvalues { return Err(limit(span, "upvalue 數超過編譯限制")); }
            let source = if index == origin + 1 { UpvalueSource::ParentLocal(binding) }
                else { UpvalueSource::ParentUpvalue(last) };
            last = UpvalueId(u32::try_from(function.upvalues.len())
                .map_err(|_| limit(span, "upvalue 數超過編譯限制"))?);
            push(&mut function.upvalues, Upvalue { origin: binding, source }, meter)?;
        }
        Ok(last)
    }

    fn implicit_global<R: MeaningMeter>(&mut self, name: &AstName, readonly: bool,
        span: Span, meter: &mut R,
    ) -> Result<BindingId, MeaningError<R::Error>> {
        admit_scan(meter, self.current().implicit_globals.len(), name.as_slice().len())?;
        let index = usize::from(readonly);
        if let Some(binding) = self.current().implicit_globals.get(name.as_slice())
            .and_then(|bindings| bindings[index]) {
            return Ok(binding);
        }
        let function = self.current_mut();
        reserve_index(&mut function.implicit_globals, &mut function.implicit_global_max_width,
            name.as_slice(), meter)?;
        let binding = self.bind(Name::User(name.clone()), BindingKind::Global, None, readonly,
            false, Visibility::Implicit, span, meter)?;
        let function = self.current_mut();
        function.implicit_globals.entry(Name::User(name.clone()))
            .or_insert([None, None])[index] = Some(binding);
        Ok(binding)
    }

    fn global_environment<R: MeaningMeter>(&mut self, name: &AstName, span: Span, meter: &mut R)
        -> Result<Option<BindingId>, MeaningError<R::Error>> {
        self.admit_visible_lookup(b"_ENV".len(), meter)?;
        let (index, environment) = self.find_visible(b"_ENV")
            .ok_or_else(|| semantic_official(span, "_ENV 不可作 global access 環境",
                OfficialFailureReason::EnvironmentGlobal { name: name.clone(), span }))?;
        if self.functions[index].binding(environment)
            .is_some_and(|binding| binding.kind == BindingKind::Global) {
            return Err(semantic_official(span, "_ENV 不可作 global access 環境",
                OfficialFailureReason::EnvironmentGlobal { name: name.clone(), span }));
        }
        if index + 1 != self.functions.len() { self.capture(index, environment, span, meter)?; }
        Ok((Some(environment) != self.root_environment).then_some(environment))
    }

    pub(super) fn resolve_name<R: MeaningMeter>(&mut self, name: &AstName, span: Span,
        meter: &mut R,
    ) -> Result<ResolvedName, MeaningError<R::Error>> {
        self.admit_visible_lookup(name.as_slice().len().max(b"_ENV".len()), meter)?;
        if let Some((index, binding)) = self.find_visible(name.as_slice()) {
            let kind = self.functions[index].binding(binding).expect("meaning binding 有效").kind;
            if kind == BindingKind::Global {
                if self.profile == LanguageProfile::Lua55 {
                    if let Some(env) = self.global_environment(name, span, meter)? {
                        return Ok(ResolvedName::EnvField { env, name: name.clone() });
                    }
                }
                return Ok(ResolvedName::Global(binding));
            }
            if index + 1 == self.functions.len() { return Ok(ResolvedName::Local(binding)); }
            return Ok(ResolvedName::Upvalue(self.capture(index, binding, span, meter)?));
        }
        if name.as_slice() == b"_ENV" {
            return Err(semantic_official(span, "名稱尚未宣告",
                OfficialFailureReason::VariableUndeclared { name: name.clone(), span }));
        }
        if self.profile == LanguageProfile::Lua54 {
            let (index, environment) = self.find_visible(b"_ENV")
                .ok_or_else(|| semantic_official(span, "名稱尚未宣告",
                    OfficialFailureReason::VariableUndeclared { name: name.clone(), span }))?;
            if index + 1 != self.functions.len() { self.capture(index, environment, span, meter)?; }
            return Ok(ResolvedName::EnvField { env: environment, name: name.clone() });
        }
        let mode = self.current().mode();
        if matches!(mode, Some(GlobalMode::NamedOnly)) {
            return Err(semantic_official(span, "名稱尚未宣告",
                OfficialFailureReason::VariableUndeclared { name: name.clone(), span }));
        }
        if let Some(env) = self.global_environment(name, span, meter)? {
            return Ok(ResolvedName::EnvField { env, name: name.clone() });
        }
        Ok(ResolvedName::Global(self.implicit_global(name,
            matches!(mode, Some(GlobalMode::Wildcard { readonly: true })), span, meter)?))
    }

    pub(super) fn check_write<R: MeaningMeter>(&mut self, name: &AstName, span: Span,
        meter: &mut R,
    ) -> Result<(), MeaningError<R::Error>> {
        let resolution = self.resolve_name(name, span, meter)?;
        meter.admit_meaning(self.functions.len(), 0).map_err(MeaningError::Recovery)?;
        let bindings = self.functions.iter()
            .try_fold(0usize, |count, function| count.checked_add(function.bindings.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        admit_scan(meter, bindings, 0)?;
        self.admit_visible_lookup(name.as_slice().len(), meter)?;
        let binding = match &resolution {
            ResolvedName::Local(binding) | ResolvedName::Global(binding) => Some(*binding),
            ResolvedName::Upvalue(_) => self.find_visible(name.as_slice()).map(|(_, binding)| binding),
            ResolvedName::EnvField { .. } => self.find_visible(name.as_slice())
                .map(|(_, binding)| binding),
        };
        let readonly = binding.and_then(|id| self.functions.iter().find_map(|function| function.binding(id)))
            .is_some_and(|binding| binding.readonly);
        let wildcard_readonly = matches!(resolution, ResolvedName::EnvField { .. })
            && binding.is_none()
            && matches!(self.current().mode(), Some(GlobalMode::Wildcard { readonly: true }));
        if readonly || wildcard_readonly {
            self.failure = Some(OfficialFailure {
                reason: OfficialFailureReason::AssignConst { name: name.clone(), span },
                line: 0, near: OfficialFailureNear::None,
            });
            Err(semantic(span, "不可指派 readonly binding"))
        } else { Ok(()) }
    }

    fn active_max(&self, terminal: bool) -> Option<u32> {
        let function = self.current();
        let len = function.scopes.len().saturating_sub(usize::from(terminal));
        function.scopes[..len].iter().filter_map(|scope| scope.active_declaration_max).max()
    }

    pub(super) fn queue_label<R: MeaningMeter>(&mut self, name: &AstName, span: Span,
        meter: &mut R,
    ) -> Result<(), MeaningError<R::Error>> {
        let max = self.limits.max_labels;
        let function = self.current_mut();
        if function.label_count >= max { return Err(limit(span, "label 數超過編譯限制")); }
        function.label_count += 1;
        push(&mut function.scopes.last_mut().expect("meaning scope 已建立").queued_labels,
            (name.clone(), span), meter)
    }

    fn validate_jump<E>(function: &Function, popped_scope: Option<ScopeId>,
        goto: &PendingGoto, label: &Label) -> Result<(), MeaningError<E>> {
        if !label.terminal && label.active_max.is_some_and(|active| active >= goto.next_declaration) {
            let variable = function.bindings.iter().find(|binding| {
                binding.declaration_ordinal.is_some_and(|ordinal|
                    ordinal >= goto.next_declaration && ordinal <= label.active_max.unwrap_or(0))
                    && binding.scope_id.is_some_and(|id| function.scopes.iter()
                        .any(|scope| scope.id == id) || popped_scope == Some(id))
            }).and_then(|binding| match &binding.name {
                Name::User(name) => Some(name.clone()),
                _ => None,
            });
            Err(semantic_official(goto.span, "goto 不可跳入 local scope",
                OfficialFailureReason::GotoIntoScope { label: goto.name.clone(), variable,
                    line: goto.line, span: label.span }))
        } else { Ok(()) }
    }

    pub(super) fn flush_labels<R: MeaningMeter>(&mut self, terminal: bool, meter: &mut R)
        -> Result<(), MeaningError<R::Error>> {
        let profile = self.profile;
        let function = self.current();
        let scope = function.scopes.last().expect("meaning scope 已建立");
        let queued_len = scope.queued_labels.len();
        let initial_scan = function.scopes.len().checked_add(queued_len)
            .ok_or(MeaningError::AllocationFailed)?;
        meter.admit_meaning(initial_scan, 0).map_err(MeaningError::Recovery)?;
        let active_labels = function.scopes.iter().try_fold(0usize,
            |count, scope| count.checked_add(scope.labels.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        let per_label = active_labels.checked_add(function.scopes.len())
            .and_then(|count| count.checked_add(scope.pending.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        let comparisons = queued_len.checked_mul(per_label)
            .and_then(|count| count.checked_add(
                queued_len.checked_mul(queued_len.saturating_sub(1))? / 2))
            .and_then(|count| count.checked_add(function.scopes.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        let max_width = scope.queued_labels.iter().map(|(name, _)| name.as_slice().len()).max().unwrap_or(0);
        admit_scan(meter, comparisons, max_width)?;
        let active_max = self.active_max(terminal);
        let mut queued = {
            let allocator = self.allocator.clone();
            let scope = self.current_mut().scopes.last_mut().expect("meaning scope 已建立");
            core::mem::replace(&mut scope.queued_labels, AllocVec::new_in(allocator))
        };
        while let Some((name, span)) = queued.pop() {
            if let Some(previous) = self.current().scopes.iter()
                .find_map(|scope| scope.labels.get(name.as_slice()).map(|label| label.span)) {
                return Err(semantic_official(span, "同一 function 的 label 重複",
                    OfficialFailureReason::LabelDuplicate { name: name.clone(), previous,
                        previous_line: 0, span }));
            }
            {
                let scope = self.current_mut().scopes.last_mut().expect("meaning scope 已建立");
                reserve_index(&mut scope.labels, &mut scope.label_max_width, name.as_slice(), meter)?;
            }
            let label = Label { name: name.clone(), span, terminal, active_max };
            if profile == LanguageProfile::Lua54 {
                let function = self.current();
                let scope = function.scopes.last().expect("meaning scope 已建立");
                for goto in scope.pending.iter().filter(|goto| goto.name.as_slice() == label.name.as_slice()) {
                    Self::validate_jump(function, None, goto, &label)?;
                }
            }
            let scope = self.current_mut().scopes.last_mut().expect("meaning scope 已建立");
            if profile == LanguageProfile::Lua54 {
                scope.pending.retain(|goto| goto.name.as_slice() != label.name.as_slice());
            }
            scope.labels.insert(name, label);
        }
        Ok(())
    }

    pub(super) fn goto<R: MeaningMeter>(&mut self, name: &AstName, span: Span, line: usize,
        meter: &mut R,
    ) -> Result<(), MeaningError<R::Error>> {
        let max = self.limits.max_gotos;
        let profile = self.profile;
        meter.admit_meaning(self.current().scopes.len(), 0).map_err(MeaningError::Recovery)?;
        let labels = self.current().scopes.iter().try_fold(0usize,
            |count, scope| count.checked_add(scope.labels.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        admit_scan(meter, labels, name.as_slice().len())?;
        let function = self.current_mut();
        if function.goto_count >= max { return Err(limit(span, "goto 數超過編譯限制")); }
        function.goto_count += 1;
        let pending = PendingGoto { name: name.clone(), span, line,
            next_declaration: function.next_declaration };
        if profile == LanguageProfile::Lua54 {
            if let Some(label) = function.scopes.iter().rev()
                .find_map(|scope| scope.labels.get(name.as_slice())) {
                return Self::validate_jump(function, None, &pending, label);
            }
        }
        push(&mut function.scopes.last_mut().expect("meaning scope 已建立").pending, pending, meter)
    }

    pub(super) fn leave_scope<R: MeaningMeter>(&mut self, span: Span, terminal: bool, meter: &mut R)
        -> Result<(), MeaningError<R::Error>> {
        self.flush_labels(terminal, meter)?;
        let profile = self.profile;
        let function = self.current();
        let pending = function.scopes.last().expect("meaning scope 已建立").pending.len();
        meter.admit_meaning(pending.checked_add(function.scopes.len())
            .ok_or(MeaningError::AllocationFailed)?, 0).map_err(MeaningError::Recovery)?;
        let max_width = function.scopes.last().expect("meaning scope 已建立").pending.iter()
            .map(|goto| goto.name.as_slice().len()).max().unwrap_or(0);
        let labels = function.scopes.iter().try_fold(0usize,
            |count, scope| count.checked_add(scope.labels.len()))
            .ok_or(MeaningError::AllocationFailed)?;
        admit_scan(meter, pending.checked_mul(labels).ok_or(MeaningError::AllocationFailed)?,
            max_width)?;
        let function = self.current_mut();
        let mut scope = function.scopes.pop().expect("meaning scope 已建立");
        for goto in scope.pending.drain(..) {
            if profile == LanguageProfile::Lua55 {
                if let Some(label) = scope.labels.get(goto.name.as_slice()) {
                    Self::validate_jump(function, Some(scope.id), &goto, label)?;
                    continue;
                }
            }
            if profile == LanguageProfile::Lua54 {
                if let Some(label) = function.scopes.iter().rev()
                    .find_map(|parent| parent.labels.get(goto.name.as_slice())) {
                    Self::validate_jump(function, Some(scope.id), &goto, label)?;
                    continue;
                }
            }
            let Some(parent) = function.scopes.last_mut() else {
                if let Some(break_span) = function.pending_break {
                    if break_span.start_byte < goto.span.start_byte {
                        return Err(semantic_official(break_span, "break 不在 loop 內",
                            OfficialFailureReason::BreakOutside { line: 0, span: break_span }));
                    }
                }
                return Err(semantic_official(goto.span, "找不到 goto label",
                    OfficialFailureReason::GotoMissing { name: goto.name.clone(), line: 0,
                        span: goto.span }));
            };
            push(&mut parent.pending, goto, meter)?;
        }
        if function.scopes.is_empty() {
            if let Some(break_span) = function.pending_break {
                return Err(semantic_official(break_span, "break 不在 loop 內",
                    OfficialFailureReason::BreakOutside { line: 0, span: break_span }));
            }
        }
        let _ = span;
        Ok(())
    }

    pub(super) fn leave_function<R: MeaningMeter>(&mut self, span: Span, meter: &mut R)
        -> Result<MeaningFunction, MeaningError<R::Error>> {
        self.leave_scope(span, true, meter)?;
        if !self.current().scopes.is_empty() { return Err(semantic(span, "function scope 未關閉")); }
        let function = self.functions.pop().expect("meaning function 已建立");
        Ok(MeaningFunction { id: function.id, bindings: function.bindings,
            upvalues: function.upvalues })
    }
}

impl MeaningContext for MeaningState {
    fn event<R: MeaningMeter>(&mut self, event: MeaningEvent<'_>, tokens: &[Token], meter: &mut R)
        -> Result<(), ParseError<R::Error>> {
        let semantic_context = match &event {
            MeaningEvent::CheckVararg(span) => Some((*span,
                OfficialFailureReason::Text(b"cannot use '...' outside a vararg function"), true)),
            MeaningEvent::CheckBreak(span) if self.profile == LanguageProfile::Lua55 =>
                Some((*span, OfficialFailureReason::BreakOutside { line: 0, span: *span }, true)),
            _ => None,
        };
        let result = match event {
            MeaningEvent::Root(span) => self.begin(span, meter).map(|_| ()),
            MeaningEvent::EnterScope(span) => self.enter_scope(span, meter).map(|_| ()),
            MeaningEvent::LeaveScope { span, terminal } => self.leave_scope(span, terminal, meter),
            MeaningEvent::EnterFunction { parameters, vararg, variadic, method, span } =>
                self.enter_function(parameters, vararg, variadic, method, span, meter).map(|_| ()),
            MeaningEvent::LeaveFunction(span) => self.leave_function(span, meter).map(|_| ()),
            MeaningEvent::EnterLoop => { self.enter_loop(); Ok(()) },
            MeaningEvent::LeaveLoop => { self.leave_loop(); Ok(()) },
            MeaningEvent::CheckVararg(span) => self.check_vararg(span),
            MeaningEvent::CheckBreak(span) => self.check_break(span),
            MeaningEvent::Name { name, span } => self.resolve_name(name, span, meter).map(|_| ()),
            MeaningEvent::WriteTarget(target) => match target {
                Expr::Name { name, span } => self.check_write(name, *span, meter),
                _ => Ok(()),
            },
            MeaningEvent::BeginDeclarations => { self.declaration_closes = 0; Ok(()) },
            MeaningEvent::DeclarationAttribute { attribute, global, span } =>
                self.declaration_attribute(attribute, global, span),
            MeaningEvent::Attribute { attribute, global, span } =>
                self.attribute(attribute, global, span).map(|_| ()),
            MeaningEvent::Declare { name, attribute, kind, readonly } =>
                self.declare_with_attribute(name, attribute, kind, readonly, meter).map(|_| ()),
            MeaningEvent::GenericForClose(span) => self.declare_generic_close(span, meter).map(|_| ()),
            MeaningEvent::NamedGlobalMode => { self.set_named_global_mode(); Ok(()) },
            MeaningEvent::WildcardGlobalMode { attribute, span } =>
                self.set_wildcard_global_mode(attribute, span),
            MeaningEvent::GlobalTarget { name, span } =>
                self.global_environment(name, span, meter).map(|_| ()),
            MeaningEvent::QueueLabel { name, span } => self.queue_label(name, span, meter),
            MeaningEvent::FlushLabels { terminal } => self.flush_labels(terminal, meter),
            MeaningEvent::Goto { name, span } => {
                let line = tokens.iter().rev().find(|token| token.span.start_byte < span.start_byte
                    && token.kind == crate::TokenKind::Keyword(crate::Keyword::Goto))
                    .map(|token| token.start.line).unwrap_or(1);
                self.goto(name, span, line, meter)
            },
        };
        if let (Some((span, reason, syntax_near)), Err(MeaningError::Diagnostic { code: DiagnosticCode::Resolve, .. })) =
            (&semantic_context, &result) {
            let source_line = tokens.last().map(|token| token.start.line).unwrap_or(1);
            let last_line = tokens.iter().find(|token| token.span.start_byte == span.start_byte)
                .map(|token| token.start.line).unwrap_or(source_line);
            self.failure = Some(OfficialFailure {
                reason: match reason {
                    OfficialFailureReason::BreakOutside { .. } =>
                        OfficialFailureReason::BreakOutside { line: last_line, span: *span },
                    OfficialFailureReason::Text(bytes) => OfficialFailureReason::Text(*bytes),
                    _ => unreachable!(),
                },
                line: if self.profile == LanguageProfile::Lua55 { last_line } else { source_line },
                near: if *syntax_near {
                    tokens.iter().find(|token| token.span.start_byte == span.start_byte)
                        .cloned().map_or(OfficialFailureNear::None, OfficialFailureNear::Token)
                } else { OfficialFailureNear::None },
            });
        }
        let result = result.map_err(|mut error| {
            if let MeaningError::Diagnostic { official, .. } = &mut error {
                if let Some(failure) = official.take() { self.failure = Some(failure); }
            }
            error
        });
        if result.is_err() {
            if let Some(failure) = self.failure.as_mut() {
                if failure.line == 0 {
                    let source_line = tokens.last().map(|token| token.start.line).unwrap_or(1);
                    let last_line = match &failure.reason {
                        OfficialFailureReason::AssignConst { span, .. }
                        | OfficialFailureReason::BreakOutside { span, .. }
                        | OfficialFailureReason::GotoMissing { span, .. }
                        | OfficialFailureReason::GotoIntoScope { span, .. }
                        | OfficialFailureReason::EnvironmentGlobal { span, .. }
                        | OfficialFailureReason::VariableUndeclared { span, .. }
                        | OfficialFailureReason::LabelDuplicate { span, .. } => tokens.iter()
                            .find(|token| token.span.start_byte == span.start_byte)
                            .map(|token| token.start.line).unwrap_or(source_line),
                        OfficialFailureReason::MultipleClose { span } => tokens.iter()
                            .find(|token| token.span.end_byte == span.end_byte)
                            .map(|token| token.end.line).unwrap_or(source_line),
                        _ => source_line,
                    };
                    match &mut failure.reason {
                        OfficialFailureReason::BreakOutside { line, .. }
                        | OfficialFailureReason::GotoMissing { line, .. } => *line = last_line,
                        OfficialFailureReason::LabelDuplicate { previous, previous_line, .. } => {
                            *previous_line = tokens.iter()
                                .find(|token| token.span.start_byte == previous.start_byte)
                                .map(|token| token.start.line).unwrap_or(1);
                        }
                        _ => {}
                    }
                    failure.line = if self.profile == LanguageProfile::Lua55 { last_line }
                        else { source_line };
                }
            }
        }
        result.map_err(|error| parse_error(error, tokens))
    }
}




