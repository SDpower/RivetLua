//! 已驗證模組的最小暫存器執行器。

mod numeric_for;
mod ops;

use rivetlua_core::{
    BinaryOperation, BytecodeConstant, BytecodePrototype, BytecodeUpvalueSource, CoreError,
    CoreErrorKind, EnvironmentSource, Instruction, LuaProfile, ObjectRef, Opcode, RVLU_V2,
    Register, ResultMode, UnaryOperation, UpvalueId, Value, VerifiedModule, VmId,
};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, reserve_vec};
use crate::call::{CallFrame, PendingCloseSnapshot};
use crate::closure::Closure;
use crate::coroutine::{CoroutineState, ThreadContext, YieldSite, root_coroutine};
use crate::errors::{Builtin, ProtectedBoundary, ProtectedStage, explicit_error};
use crate::pending_op::{PendingKind, PendingOp, PendingStack, PendingTableKind, ResumeStage};
use crate::unwind::{CloseFinish, CloseUnwind};
use crate::upvalue::{Upvalue, UpvalueState};
use crate::{MetamethodEvent, ObjectKind, RootId, RootKind, Vm, VmError};

/// VM 內部錯誤；不建立 Lua 字串，P08／P11 可用診斷 ID 映射可見錯誤值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorKind {
    UnsupportedFormat,
    MissingEntryPoint,
    UnsupportedInstruction(Opcode),
    UnsupportedUnaryOperation(UnaryOperation),
    UnsupportedBinaryOperation(BinaryOperation),
    UnsupportedConstant,
    UnsupportedResultMode,
    NumericForZeroStep,
    InvalidNamedVarargCount,
    InvalidNumericForState,
    RegisterOutOfBounds,
    ProgramCounterOutOfBounds,
    TerminalExecution,
    NotCallable,
    StackLimit,
    MetatableChainLimit,
    MetamethodAbsent,
    Thrown,
    ErrorHandlerLoop,
    CoroutineYield,
    CoroutineClose,
    Heap(VmError),
    Core(CoreError),
}

impl RuntimeErrorKind {
    fn is_lua_error(self) -> bool {
        matches!(
            self,
            Self::Core(_)
                | Self::NumericForZeroStep
                | Self::InvalidNamedVarargCount
                | Self::NotCallable
                | Self::StackLimit
                | Self::MetatableChainLimit
                | Self::MetamethodAbsent
                | Self::Thrown
                | Self::ErrorHandlerLoop
                | Self::CoroutineYield
                | Self::CoroutineClose
                | Self::Heap(
                    VmError::NilTableKey | VmError::NaNTableKey | VmError::WrongObjectType
                )
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RuntimeError {
    pub kind: RuntimeErrorKind,
    pub diagnostic_id: &'static str,
    pub value: Value,
    pub source_pc: Option<usize>,
    pub source_prototype: Option<usize>,
    pub source_depth: Option<usize>,
}

impl RuntimeError {
    pub const fn new(kind: RuntimeErrorKind) -> Self {
        let diagnostic_id = match kind {
            RuntimeErrorKind::UnsupportedFormat => "E_VM_FORMAT",
            RuntimeErrorKind::MissingEntryPoint => "E_VM_ENTRY",
            RuntimeErrorKind::UnsupportedInstruction(_) => "E_VM_OPCODE_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedUnaryOperation(_) => "E_VM_UNARY_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedBinaryOperation(_) => "E_VM_BINARY_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedConstant => "E_VM_CONSTANT_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedResultMode => "E_VM_RESULT_UNSUPPORTED",
            RuntimeErrorKind::NumericForZeroStep => "E_NUMERIC_FOR_ZERO_STEP",
            RuntimeErrorKind::InvalidNamedVarargCount => "E_VARARG_TABLE_COUNT",
            RuntimeErrorKind::InvalidNumericForState => "E_VM_NUMERIC_FOR_STATE",
            RuntimeErrorKind::RegisterOutOfBounds => "E_VM_REGISTER_BOUNDS",
            RuntimeErrorKind::ProgramCounterOutOfBounds => "E_VM_PC_BOUNDS",
            RuntimeErrorKind::TerminalExecution => "E_VM_TERMINAL",
            RuntimeErrorKind::NotCallable => "E_CALL_NON_FUNCTION",
            RuntimeErrorKind::StackLimit => "E_STACK_LIMIT",
            RuntimeErrorKind::MetatableChainLimit => "E_METATABLE_CHAIN_LIMIT",
            RuntimeErrorKind::MetamethodAbsent => "E_METAMETHOD_ABSENT",
            RuntimeErrorKind::Thrown => "E_LUA_THROWN",
            RuntimeErrorKind::ErrorHandlerLoop => "E_ERROR_HANDLER_LOOP",
            RuntimeErrorKind::CoroutineYield => "E_COROUTINE_YIELD",
            RuntimeErrorKind::CoroutineClose => "E_COROUTINE_CLOSE",
            RuntimeErrorKind::Heap(error) => error.code(),
            RuntimeErrorKind::Core(error) => match error.kind {
                CoreErrorKind::IntegerDivideByZero => "E_INTEGER_DIVIDE_BY_ZERO",
                CoreErrorKind::IntegerModuloByZero => "E_INTEGER_MODULO_BY_ZERO",
                CoreErrorKind::NotInteger => "E_NOT_INTEGER",
                CoreErrorKind::NotNumeric => "E_NOT_NUMERIC",
            },
        };
        Self {
            kind,
            diagnostic_id,
            value: Value::Nil,
            source_pc: None,
            source_prototype: None,
            source_depth: None,
        }
    }
}

impl From<VmError> for RuntimeError {
    fn from(error: VmError) -> Self {
        Self::new(RuntimeErrorKind::Heap(error))
    }
}

impl From<CoreError> for RuntimeError {
    fn from(error: CoreError) -> Self {
        Self::new(RuntimeErrorKind::Core(error))
    }
}

/// 每次取指前消耗一個 fuel；耗盡後不可續跑原 execution。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortReason {
    FuelExhausted,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RunOutcome {
    Returned(Vec<Value>),
    LuaError(crate::LuaError),
    Aborted(AbortReason),
    PendingClose(PendingCloseSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionState {
    Ready,
    Returned,
    LuaError,
    Failed,
    Aborted,
    PendingClose,
}

enum DispatchResult {
    Continue,
    Returned(Vec<Value>, Option<Reservation>),
    Yielded(Vec<Value>, Option<Reservation>),
    PendingClose(PendingCloseSnapshot),
    Aborted,
}

enum ProtectedErrorResult {
    Caught(DispatchResult),
    Uncaught(RuntimeError),
}

#[derive(Clone, Copy)]
enum CoroutineExit {
    Yield,
    Return,
    Error,
}

enum RegularTableAction {
    Read(Value),
    Wrote,
    Invoke {
        current: Value,
        event: ObjectRef,
        chain_steps: usize,
    },
    Aborted,
}

enum RegularCallAction {
    Entered,
    Aborted,
    Completed(DispatchResult),
}

struct ResumeCaller {
    context: ThreadContext,
    owner: Option<ObjectRef>,
    owner_root: Option<RootId>,
    child: ObjectRef,
    child_root: RootId,
    destination: Register,
    result_mode: ResultMode,
    resume_pc: usize,
    tail_return: bool,
    wrapped: bool,
    native_body: Option<NativeBodyContinuation>,
    native: Option<NativeCompletion>,
    outer_resumes: ResumeChain,
    handler_root: Option<RootId>,
}

#[derive(Clone, Copy)]
struct NativeBodyContinuation {
    outer: ObjectRef,
    parent: Option<ObjectRef>,
    parent_root: Option<RootId>,
    wrapped: bool,
    destination: Register,
    result_mode: ResultMode,
    tail_return: bool,
    resume_pc: usize,
}

struct ResumeChain {
    items: Vec<NativeCompletion>,
    charge: usize,
    ledger: AllocationLedger,
}

impl ResumeChain {
    fn new(ledger: &AllocationLedger) -> Self {
        Self {
            items: Vec::new(),
            charge: 0,
            ledger: ledger.clone(),
        }
    }

    fn push(&mut self, continuation: NativeCompletion) -> Result<(), VmError> {
        if self.items.len() == self.items.capacity() {
            let next = self
                .charge
                .checked_add(core::mem::size_of::<NativeCompletion>())
                .ok_or(VmError::ArithmeticOverflow)?;
            let ticket = reserve_vec(&self.ledger, &mut self.items, 1, FailPoint::WorkReserve)?;
            ticket.commit()?;
            self.charge = next;
        }
        self.items.push(continuation);
        Ok(())
    }

    fn last(&self) -> Option<NativeCompletion> {
        self.items.last().copied()
    }
}

impl Drop for ResumeChain {
    fn drop(&mut self) {
        self.ledger.refund_on_drop(self.charge);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum NativeCompletion {
    PCall {
        depth: u8,
    },
    XPCallBody {
        handler: Value,
        errors: u8,
    },
    XPCallHandler {
        handler: Value,
        errors: u8,
    },
    Resume {
        outer: ObjectRef,
        parent: Option<ObjectRef>,
        parent_root: Option<RootId>,
        protected: Option<NativeProtected>,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum NativeProtected {
    PCall { depth: u8 },
    XPCall { handler: Value },
}

fn arithmetic_event(op: BinaryOperation) -> Option<MetamethodEvent> {
    use BinaryOperation as B;
    use MetamethodEvent as M;
    Some(match op {
        B::Add => M::Add,
        B::Subtract => M::Sub,
        B::Multiply => M::Mul,
        B::Modulo => M::Mod,
        B::Power => M::Pow,
        B::Divide => M::Div,
        B::FloorDivide => M::IDiv,
        B::Ampersand => M::Band,
        B::Pipe => M::Bor,
        B::BitXor => M::Bxor,
        B::ShiftLeft => M::Shl,
        B::ShiftRight => M::Shr,
        B::Concat => M::Concat,
        _ => return None,
    })
}

/// 擁有 frame 並借用原 VM；丟棄未執行的 execution 也會清理 stack roots。
pub struct Execution<'vm> {
    vm: &'vm mut Vm,
    vm_id: VmId,
    module: Option<VerifiedModule>,
    module_root: Option<RootId>,
    frame: CallFrame,
    callers: Vec<CallFrame>,
    callers_charge: usize,
    peak_frame_count: usize,
    pending_ops: PendingStack,
    protected: Vec<ProtectedBoundary>,
    protected_charge: usize,
    error_root: Option<RootId>,
    close_unwind: Option<CloseUnwind>,
    yield_site: Option<YieldSite>,
    active_coroutine: Option<ObjectRef>,
    active_coroutine_root: Option<RootId>,
    resume_stack: Vec<ResumeCaller>,
    resume_charge: usize,
    fuel: u64,
    state: ExecutionState,
}

impl Vm {
    /// 載入 P05 已驗證模組；未提供宿主環境時保持原有 nil 初值。
    ///
    /// ```compile_fail
    /// use rivetlua_runtime::Vm;
    /// use rivetlua_core::BytecodeModule;
    /// let mut vm = Vm::new().unwrap();
    /// let candidate: BytecodeModule = todo!();
    /// let _execution = vm.load(candidate);
    /// ```
    pub fn load(&mut self, module: VerifiedModule) -> Result<Execution<'_>, RuntimeError> {
        self.load_impl(module, None)
    }

    /// 將宿主提供的 raw table 放入已驗證 root frame 的 `_ENV` register。
    pub fn load_with_environment(
        &mut self,
        module: VerifiedModule,
        environment: Value,
    ) -> Result<Execution<'_>, RuntimeError> {
        let Value::Object(table) = environment else {
            return Err(VmError::WrongObjectType.into());
        };
        if self.object_kind(table)? != crate::ObjectKind::Table {
            return Err(VmError::WrongObjectType.into());
        }
        self.load_impl(module, Some(table))
    }

    fn load_impl(
        &mut self,
        module: VerifiedModule,
        environment: Option<ObjectRef>,
    ) -> Result<Execution<'_>, RuntimeError> {
        if module.format_version() != RVLU_V2 {
            return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedFormat));
        }
        let data = module.module();
        if !matches!(module.profile(), LuaProfile::Lua54 | LuaProfile::Lua55) {
            return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedFormat));
        }
        let Some((_, entry_id)) = data
            .function_prototypes
            .iter()
            .find(|(function, _)| *function == 0)
        else {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        };
        let entry_index = data
            .prototypes
            .iter()
            .position(|candidate| candidate.id == *entry_id)
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        if data.prototypes[entry_index].parent.is_some() {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        }
        let environment_register = data.prototypes[entry_index].frame.environment;
        if environment.is_some()
            && !matches!(
                data.prototypes[entry_index].frame.environment_source,
                EnvironmentSource::RootExternal
            )
        {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        }
        for prototype in &data.prototypes {
            for constant in &prototype.constants {
                if !matches!(
                    constant,
                    BytecodeConstant::Integer(_)
                        | BytecodeConstant::FloatBits(_)
                        | BytecodeConstant::Boolean(_)
                        | BytecodeConstant::Name(_)
                        | BytecodeConstant::String(_)
                ) {
                    return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedConstant));
                }
            }
            for instruction in &prototype.instructions {
                match instruction.instruction {
                    Instruction::LoadConst { .. }
                    | Instruction::LoadNil { .. }
                    | Instruction::Move { .. }
                    | Instruction::NewTable { .. }
                    | Instruction::GetTable { .. }
                    | Instruction::SetTable { .. }
                    | Instruction::Jump { .. }
                    | Instruction::JumpIfFalse { .. }
                    | Instruction::NumericForPrepare { .. }
                    | Instruction::NumericForNext { .. }
                    | Instruction::Closure { .. }
                    | Instruction::GetUpvalue { .. }
                    | Instruction::SetUpvalue { .. }
                    | Instruction::Call { .. }
                    | Instruction::TailCall { .. }
                    | Instruction::Vararg { .. }
                    | Instruction::Close { .. }
                    | Instruction::UnaryOp {
                        op:
                            UnaryOperation::Negate
                            | UnaryOperation::Not
                            | UnaryOperation::BitNot
                            | UnaryOperation::Length,
                        ..
                    }
                    | Instruction::BinaryOp {
                        op:
                            BinaryOperation::Equal
                            | BinaryOperation::NotEqual
                            | BinaryOperation::Less
                            | BinaryOperation::LessEqual
                            | BinaryOperation::Greater
                            | BinaryOperation::GreaterEqual
                            | BinaryOperation::Pipe
                            | BinaryOperation::BitXor
                            | BinaryOperation::Ampersand
                            | BinaryOperation::ShiftLeft
                            | BinaryOperation::ShiftRight
                            | BinaryOperation::Concat
                            | BinaryOperation::Add
                            | BinaryOperation::Subtract
                            | BinaryOperation::Multiply
                            | BinaryOperation::Divide
                            | BinaryOperation::FloorDivide
                            | BinaryOperation::Modulo
                            | BinaryOperation::Power,
                        ..
                    }
                    | Instruction::Return { .. } => {}
                    Instruction::BinaryOp { op, .. } => {
                        return Err(RuntimeError::new(
                            RuntimeErrorKind::UnsupportedBinaryOperation(op),
                        ));
                    }
                }
            }
        }
        let needs_module_payload = data.prototypes.iter().any(|prototype| {
            prototype
                .instructions
                .iter()
                .any(|entry| matches!(entry.instruction, Instruction::Closure { .. }))
        });
        let environment_guard = match environment {
            Some(table) => Some(self.add_root(RootKind::Temporary, table)?),
            None => None,
        };
        let frame_result = (|| {
            let (mut frame, owned_module, module_root) = if needs_module_payload {
                let module_ref = self.allocate_module(module)?;
                let root = match self.add_root(RootKind::Temporary, module_ref) {
                    Ok(root) => root,
                    Err(error) => {
                        self.reclaim(module_ref)?;
                        return Err(error.into());
                    }
                };
                let frame = match CallFrame::new(
                    &self.module(module_ref)?.module().prototypes[entry_index],
                    entry_index,
                    Some(module_ref),
                    self.allocation_ledger(),
                ) {
                    Ok(frame) => frame,
                    Err(error) => {
                        self.remove_root(root)?;
                        self.reclaim(module_ref)?;
                        return Err(error);
                    }
                };
                (frame, None, Some(root))
            } else {
                let frame = CallFrame::new(
                    &module.module().prototypes[entry_index],
                    entry_index,
                    None,
                    self.allocation_ledger(),
                )?;
                (frame, Some(module), None)
            };
            if let Some(table) = environment {
                if let Err(error) = frame.write(self, environment_register, Value::Object(table)) {
                    frame.clear_roots(self)?;
                    if let Some(root) = module_root {
                        self.remove_root(root)?;
                        if let Some(reference) = frame.module {
                            self.reclaim(reference)?;
                        }
                    }
                    return Err(error);
                }
            }
            Ok((frame, owned_module, module_root))
        })();
        if let Some(root) = environment_guard {
            self.remove_root(root)?;
        }
        let (frame, owned_module, module_root) = frame_result?;
        let pending_ops = PendingStack::new(self.allocation_ledger().clone());
        Ok(Execution {
            vm_id: self.id(),
            vm: self,
            module: owned_module,
            module_root,
            frame,
            callers: Vec::new(),
            callers_charge: 0,
            peak_frame_count: 1,
            pending_ops,
            protected: Vec::new(),
            protected_charge: 0,
            error_root: None,
            close_unwind: None,
            yield_site: None,
            active_coroutine: None,
            active_coroutine_root: None,
            resume_stack: Vec::new(),
            resume_charge: 0,
            fuel: 1_000_000,
            state: ExecutionState::Ready,
        })
    }
}

impl Execution<'_> {
    fn rollback_new_open(&mut self, original: usize) -> Result<(), RuntimeError> {
        while self.frame.open_upvalues.len() > original {
            let entry = self
                .frame
                .open_upvalues
                .pop()
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
            if let Some(root) = entry.root {
                self.vm.remove_root(root)?;
            }
            self.vm.reclaim(entry.object)?;
            let bytes = core::mem::size_of::<crate::call::OpenUpvalue>();
            self.vm.allocation_ledger().refund(bytes)?;
            self.frame.open_charge -= bytes;
        }
        Ok(())
    }

    fn capture_upvalues(
        &mut self,
        child_index: usize,
    ) -> Result<(Vec<ObjectRef>, Option<Reservation>, usize), RuntimeError> {
        let count = self.current_module()?.module().prototypes[child_index]
            .upvalues
            .len();
        let mut captures = Vec::new();
        let ticket = if count == 0 {
            None
        } else {
            Some(reserve_vec(
                self.vm.allocation_ledger(),
                &mut captures,
                count,
                FailPoint::ClosureCapturesReserve,
            )?)
        };
        let original = self.frame.open_upvalues.len();
        let result = (|| {
            for index in 0..count {
                let source = self.current_module()?.module().prototypes[child_index].upvalues
                    [index]
                    .source
                    .clone();
                let captured = match source {
                    BytecodeUpvalueSource::ParentLocal(binding) => {
                        let register = self
                            .prototype()
                            .binding_registers
                            .iter()
                            .find_map(|(candidate, register)| {
                                (*candidate == binding).then_some(*register)
                            })
                            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                        let slot = self
                            .frame
                            .stack_base
                            .checked_add(self.frame.index(register)?)
                            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                        if let Some(existing) = self.frame.find_open(slot) {
                            existing
                        } else {
                            let object = self.vm.allocate_upvalue(Upvalue::open(
                                self.vm_id,
                                self.active_coroutine,
                                slot,
                            ))?;
                            if let Err(error) = self.frame.add_open(self.vm, slot, object) {
                                self.vm.reclaim(object)?;
                                return Err(error);
                            }
                            object
                        }
                    }
                    BytecodeUpvalueSource::ParentUpvalue(parent) => {
                        let owner = self
                            .frame
                            .closure
                            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                        self.vm
                            .with_closure(owner, |closure| closure.upvalue(usize::from(parent.0)))?
                            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?
                    }
                };
                captures.push(captured);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.rollback_new_open(original)?;
            return Err(error);
        }
        Ok((captures, ticket, original))
    }

    fn current_upvalue(&self, id: UpvalueId) -> Result<ObjectRef, RuntimeError> {
        let closure = self
            .frame
            .closure
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        self.vm
            .with_closure(closure, |payload| payload.upvalue(usize::from(id.0)))?
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
    }

    fn read_upvalue(&self, object: ObjectRef) -> Result<Value, RuntimeError> {
        match self.vm.upvalue_state(object)? {
            UpvalueState::Closed(value) => Ok(value),
            UpvalueState::Open {
                thread,
                coroutine,
                slot,
            } if thread == self.vm_id => {
                if coroutine == self.active_coroutine {
                    let frame = core::iter::once(&self.frame)
                        .chain(self.callers.iter())
                        .find(|frame| {
                            slot.checked_sub(frame.stack_base)
                                .is_some_and(|index| index < frame.register_limit)
                        })
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                    return Ok(frame.registers[slot - frame.stack_base]);
                }
                if let Some(caller) = self.resume_stack.iter().rev().find(|caller| {
                    match caller.outer_resumes.last().or(caller.native) {
                        Some(NativeCompletion::Resume { parent, .. }) => parent == coroutine,
                        _ => caller.owner == coroutine,
                    }
                }) {
                    return caller
                        .context
                        .read_slot(slot)
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
                }
                if let Some(owner) = coroutine {
                    return self
                        .vm
                        .coroutine_stack_read(owner, slot)?
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
                }
                Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
            }
            UpvalueState::Open { .. } => Err(VmError::WrongVm.into()),
        }
    }

    fn write_upvalue(&mut self, object: ObjectRef, value: Value) -> Result<(), RuntimeError> {
        match self.vm.upvalue_state(object)? {
            UpvalueState::Closed(_) => {
                if let Value::Object(reference) = value {
                    self.vm.object_kind(reference)?;
                }
                self.vm
                    .with_upvalue_mut(object, |upvalue| upvalue.set_closed(value))?;
                Ok(())
            }
            UpvalueState::Open {
                thread,
                coroutine,
                slot,
            } if thread == self.vm_id => {
                if coroutine == self.active_coroutine {
                    let frame = core::iter::once(&mut self.frame)
                        .chain(self.callers.iter_mut())
                        .find(|frame| {
                            slot.checked_sub(frame.stack_base)
                                .is_some_and(|index| index < frame.register_limit)
                        })
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                    return frame.write(
                        self.vm,
                        Register(u16::try_from(slot - frame.stack_base).map_err(|_| {
                            RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds)
                        })?),
                        value,
                    );
                }
                if let Some(caller) =
                    self.resume_stack.iter_mut().rev().find(|caller| {
                        match caller.outer_resumes.last().or(caller.native) {
                            Some(NativeCompletion::Resume { parent, .. }) => parent == coroutine,
                            _ => caller.owner == coroutine,
                        }
                    })
                {
                    let frame = core::iter::once(&mut caller.context.frame)
                        .chain(caller.context.callers.iter_mut())
                        .find(|frame| {
                            slot.checked_sub(frame.stack_base)
                                .is_some_and(|index| index < frame.register_limit)
                        })
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                    return frame.write(
                        self.vm,
                        Register(u16::try_from(slot - frame.stack_base).map_err(|_| {
                            RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds)
                        })?),
                        value,
                    );
                }
                if let Some(owner) = coroutine {
                    if self.vm.coroutine_stack_write(owner, slot, value)? {
                        return Ok(());
                    }
                }
                Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
            }
            UpvalueState::Open { .. } => Err(VmError::WrongVm.into()),
        }
    }

    fn regular_table_access(
        &mut self,
        target: Value,
        key: Value,
        value: Option<Value>,
    ) -> Result<RegularTableAction, RuntimeError> {
        const MAX_TAG_LOOP: usize = 2000;
        let event_kind = if value.is_some() {
            MetamethodEvent::NewIndex
        } else {
            MetamethodEvent::Index
        };
        let mut current = target;
        for step in 0..MAX_TAG_LOOP {
            let Value::Object(object) = current else {
                return Err(VmError::WrongObjectType.into());
            };
            if self.vm.object_kind(object)? != ObjectKind::Table {
                return Err(VmError::WrongObjectType.into());
            }
            let raw = self.vm.raw_get(object, key)?;
            if raw != Value::Nil {
                if let Some(value) = value {
                    self.vm.raw_set(object, key, value)?;
                    return Ok(RegularTableAction::Wrote);
                }
                return Ok(RegularTableAction::Read(raw));
            }
            let event = self.vm.lookup_metamethod(object, event_kind)?;
            if event == Value::Nil {
                if let Some(value) = value {
                    self.vm.raw_set(object, key, value)?;
                    return Ok(RegularTableAction::Wrote);
                }
                return Ok(RegularTableAction::Read(Value::Nil));
            }
            if self.fuel == 0 {
                return Ok(RegularTableAction::Aborted);
            }
            self.fuel -= 1;
            if let Value::Object(event_object) = event {
                if matches!(
                    self.vm.object_kind(event_object)?,
                    ObjectKind::Closure | ObjectKind::Builtin
                ) {
                    return Ok(RegularTableAction::Invoke {
                        current,
                        event: event_object,
                        chain_steps: step + 1,
                    });
                }
            }
            current = event;
        }
        Err(RuntimeError::new(RuntimeErrorKind::MetatableChainLimit))
    }

    fn invoke_table_event(
        &mut self,
        kind: PendingTableKind,
        original: Value,
        current: Value,
        key: Value,
        value: Value,
        event: ObjectRef,
        destination: Register,
        next: usize,
        chain_steps: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let args = [current, key, value];
        let (arg_count, result_mode) = match kind {
            PendingTableKind::Get => (2, ResultMode::Fixed(1)),
            PendingTableKind::Set => (3, ResultMode::Fixed(0)),
        };
        self.invoke_event(
            PendingKind::Table(kind),
            [original, current, key, value, Value::Object(event)],
            event,
            &args[..arg_count],
            destination,
            result_mode,
            next,
            chain_steps,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_event(
        &mut self,
        kind: PendingKind,
        values: [Value; 5],
        event: ObjectRef,
        args: &[Value],
        destination: Register,
        result_mode: ResultMode,
        next: usize,
        chain_steps: usize,
        tail_return: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        let mut pending = PendingOp::new(
            self.vm,
            kind,
            values,
            self.callers.len(),
            self.frame.pc,
            self.frame.stack_base,
            self.frame.prototype,
            self.frame.module,
            next,
            destination,
            result_mode,
            self.frame.dynamic_top,
            chain_steps,
        )?;
        let prepared = match self.pending_ops.prepare_push() {
            Ok(prepared) => prepared,
            Err(error) => {
                pending.clear(self.vm)?;
                return Err(error.into());
            }
        };
        let event_kind = match self.vm.object_kind(event) {
            Ok(kind) => kind,
            Err(error) => {
                pending.clear(self.vm)?;
                return Err(error.into());
            }
        };
        if event_kind == ObjectKind::Closure {
            if let Err(error) = self.enter_metamethod_call(
                event,
                args,
                destination,
                result_mode,
                next,
                tail_return,
                false,
            ) {
                pending.clear(self.vm)?;
                return Err(error);
            }
            self.pending_ops.push_prepared(prepared, pending);
            return Ok(RegularCallAction::Entered);
        }
        if event_kind != ObjectKind::Builtin {
            pending.clear(self.vm)?;
            return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
        }
        self.pending_ops.push_prepared(prepared, pending);
        let action =
            self.invoke_builtin_event(event, args, destination, result_mode, next, tail_return);
        match action {
            Ok(RegularCallAction::Entered) => Ok(RegularCallAction::Entered),
            Ok(RegularCallAction::Completed(DispatchResult::Yielded(values, ticket))) => Ok(
                RegularCallAction::Completed(DispatchResult::Yielded(values, ticket)),
            ),
            Ok(action) => {
                self.complete_immediate_event()?;
                Ok(action)
            }
            Err(error) => {
                let mut pending = self
                    .pending_ops
                    .pop()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                pending.clear(self.vm)?;
                self.pending_ops.release_empty()?;
                Err(error)
            }
        }
    }

    fn invoke_builtin_event(
        &mut self,
        event: ObjectRef,
        args: &[Value],
        destination: Register,
        result_mode: ResultMode,
        next: usize,
        tail_return: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        match self.vm.builtin(event)? {
            Builtin::Error => Err(explicit_error(
                args.first().copied().unwrap_or(Value::Nil),
                self.frame.pc,
            )),
            builtin @ (Builtin::PCall | Builtin::XPCall) => {
                let handler = (builtin == Builtin::XPCall)
                    .then(|| args.get(1).copied().unwrap_or(Value::Nil));
                let skip = if handler.is_some() { 2 } else { 1 };
                let target = args.first().copied().unwrap_or(Value::Nil);
                self.push_protected_boundary(destination, result_mode, tail_return, handler, next)?;
                let action = self.enter_callable_values(
                    target,
                    args.get(skip..).unwrap_or(&[]),
                    destination,
                    result_mode,
                    next,
                )?;
                if matches!(action, RegularCallAction::Aborted) {
                    self.fuel = 0;
                }
                if let RegularCallAction::Completed(DispatchResult::Continue) = action {
                    let first = self.frame.index(destination)?;
                    let end = self.frame.dynamic_top;
                    let mut values = Vec::new();
                    let ticket = reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut values,
                        end.saturating_sub(first),
                        FailPoint::ReturnReserve,
                    )?;
                    values.extend_from_slice(&self.frame.registers[first..end]);
                    return Ok(RegularCallAction::Completed(
                        self.propagate_tail_result(values, Some(ticket))?,
                    ));
                }
                Ok(action)
            }
            builtin => {
                self.coroutine_builtin(builtin, destination, args, result_mode, tail_return, next)
            }
        }
    }

    fn complete_immediate_event(&mut self) -> Result<(), RuntimeError> {
        let pending = self
            .pending_ops
            .last()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let kind = pending.kind;
        let destination = pending.destination;
        let dynamic_top = pending.dynamic_top;
        if let PendingKind::Boolean { invert } = kind {
            let value = self.frame.read(destination)?;
            self.frame.write(
                self.vm,
                destination,
                Value::Boolean(value.is_truthy() ^ invert),
            )?;
        }
        if !matches!(kind, PendingKind::Call) {
            self.frame.dynamic_top = dynamic_top;
        }
        let mut pending = self
            .pending_ops
            .pop()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        pending.clear(self.vm)?;
        self.pending_ops.release_empty()?;
        Ok(())
    }

    fn settle_ready_builtin_event(&mut self) -> Result<(), RuntimeError> {
        let ready = self.pending_ops.last().is_some_and(|pending| {
            pending.stage == ResumeStage::AwaitingReturn
                && pending.caller_depth == self.callers.len()
                && pending.caller_stack_base == self.frame.stack_base
                && pending.caller_prototype == self.frame.prototype
                && pending.caller_module == self.frame.module
                && pending.resume_pc == self.frame.pc
        });
        if ready {
            self.complete_immediate_event()?;
        }
        Ok(())
    }

    fn enter_metamethod_call(
        &mut self,
        event: ObjectRef,
        args: &[Value],
        destination: Register,
        result_mode: ResultMode,
        next: usize,
        tail_return: bool,
        reuse_tail_frame: bool,
    ) -> Result<(), RuntimeError> {
        const FRAME_LIMIT: usize = 1024;
        let base = self.frame.index(destination)?;
        let (module_ref, prototype_id, captured_environment) =
            self.vm.with_closure(event, |closure| {
                (closure.module(), closure.prototype(), closure.environment())
            })?;
        let child_index = self
            .vm
            .module(module_ref)?
            .module()
            .prototypes
            .iter()
            .position(|prototype| prototype.id == prototype_id)
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let prototype = &self.vm.module(module_ref)?.module().prototypes[child_index];
        let parameter_count = usize::from(prototype.parameter_count);
        let is_variadic = prototype.is_variadic;
        let environment_register = prototype.frame.environment;
        let depth = if reuse_tail_frame {
            self.frame.depth
        } else {
            self.frame
                .depth
                .checked_add(1)
                .filter(|depth| *depth <= FRAME_LIMIT)
                .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?
        };
        let next_charge = if reuse_tail_frame {
            self.callers_charge
        } else {
            self.callers_charge
                .checked_add(core::mem::size_of::<CallFrame>())
                .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                    VmError::ArithmeticOverflow,
                )))?
        };
        let mut callee = CallFrame::new(
            prototype,
            child_index,
            Some(module_ref),
            self.vm.allocation_ledger(),
        )?;
        callee.closure = Some(event);
        callee.stack_base = if reuse_tail_frame {
            self.frame.stack_base
        } else {
            self.frame
                .stack_base
                .checked_add(self.frame.max_register_limit)
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?
        };
        callee.base = if reuse_tail_frame {
            self.frame.base
        } else {
            base
        };
        callee.return_destination = if reuse_tail_frame {
            self.frame.return_destination
        } else {
            Some(destination)
        };
        callee.return_mode = if reuse_tail_frame {
            self.frame.return_mode
        } else {
            result_mode
        };
        callee.caller = if reuse_tail_frame {
            self.frame.caller
        } else {
            Some(self.callers.len())
        };
        callee.depth = depth;
        callee.closure_root = Some(self.vm.add_root(RootKind::Stack, event)?);
        if let Some(environment) = captured_environment {
            if let Err(error) = callee.write(self.vm, environment_register, environment) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        for (offset, argument) in args.iter().copied().take(parameter_count).enumerate() {
            let register = Register(
                u16::try_from(offset + 1)
                    .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
            );
            if let Err(error) = callee.write(self.vm, register, argument) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        let mut named_payload = None;
        if is_variadic {
            let extra = args.get(parameter_count..).unwrap_or(&[]);
            if callee.named_vararg.is_some() {
                match callee.set_named_varargs(self.vm, extra) {
                    Ok(payload) => named_payload = Some(payload),
                    Err(error) => {
                        callee.clear_roots(self.vm)?;
                        return Err(error);
                    }
                }
            } else if let Err(error) = callee.set_varargs(self.vm, extra) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        if !reuse_tail_frame && self.callers.len() == self.callers.capacity() {
            let ticket = match reserve_vec(
                self.vm.allocation_ledger(),
                &mut self.callers,
                1,
                FailPoint::CallFrameReserve,
            ) {
                Ok(ticket) => ticket,
                Err(error) => {
                    callee.clear_roots(self.vm)?;
                    if let Some((table, key)) = named_payload {
                        self.vm.reclaim(table)?;
                        self.vm.reclaim(key)?;
                    }
                    return Err(error.into());
                }
            };
            if let Err(error) = ticket.commit() {
                callee.clear_roots(self.vm)?;
                if let Some((table, key)) = named_payload {
                    self.vm.reclaim(table)?;
                    self.vm.reclaim(key)?;
                }
                return Err(error.into());
            }
            self.callers_charge = next_charge;
        }
        if reuse_tail_frame {
            let close = self
                .frame
                .close_open(self.vm)
                .and_then(|()| self.frame.clear_roots(self.vm));
            if let Err(error) = close {
                callee.clear_roots(self.vm)?;
                if let Some((table, key)) = named_payload {
                    self.vm.reclaim(table)?;
                    self.vm.reclaim(key)?;
                }
                return Err(error);
            }
            self.frame.release_storage();
            self.frame = callee;
            return Ok(());
        }
        self.frame.pc = next;
        self.frame.tail_return = tail_return;
        let caller = core::mem::replace(&mut self.frame, callee);
        self.callers.push(caller);
        self.peak_frame_count = self.peak_frame_count.max(self.callers.len() + 1);
        Ok(())
    }

    fn resolve_callable_event(
        &mut self,
        target: Value,
        args: &[Value],
    ) -> Result<Option<(ObjectRef, Vec<Value>, Reservation, usize)>, RuntimeError> {
        const MAX_TAG_LOOP: usize = 2000;
        let mut chain = [Value::Nil; MAX_TAG_LOOP];
        let mut count: usize = 0;
        let mut current = target;
        loop {
            let Value::Object(object) = current else {
                return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
            };
            match self.vm.object_kind(object)? {
                ObjectKind::Closure | ObjectKind::Builtin => {
                    let total = count
                        .checked_add(args.len())
                        .ok_or(VmError::ArithmeticOverflow)?;
                    let mut final_args = Vec::new();
                    let ticket = reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut final_args,
                        total,
                        FailPoint::WorkReserve,
                    )?;
                    final_args.extend(chain[..count].iter().rev().copied());
                    final_args.extend_from_slice(args);
                    return Ok(Some((object, final_args, ticket, count)));
                }
                ObjectKind::Table => {
                    if count == MAX_TAG_LOOP {
                        return Err(RuntimeError::new(RuntimeErrorKind::MetatableChainLimit));
                    }
                    let event = self.vm.lookup_metamethod(object, MetamethodEvent::Call)?;
                    if event == Value::Nil {
                        return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
                    }
                    if self.fuel == 0 {
                        return Ok(None);
                    }
                    self.fuel -= 1;
                    chain[count] = current;
                    count += 1;
                    current = event;
                }
                _ => return Err(RuntimeError::new(RuntimeErrorKind::NotCallable)),
            }
        }
    }

    fn lookup_value_event(
        &mut self,
        value: Value,
        event: MetamethodEvent,
    ) -> Result<Value, RuntimeError> {
        let Value::Object(object) = value else {
            return Ok(Value::Nil);
        };
        if self.vm.object_kind(object)? != ObjectKind::Table {
            return Ok(Value::Nil);
        }
        Ok(self.vm.lookup_metamethod(object, event)?)
    }

    fn lookup_binary_event(
        &mut self,
        left: Value,
        right: Value,
        event: MetamethodEvent,
    ) -> Result<Value, RuntimeError> {
        let first = self.lookup_value_event(left, event)?;
        if first != Value::Nil {
            return Ok(first);
        }
        self.lookup_value_event(right, event)
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_value_event(
        &mut self,
        event_value: Value,
        args: &[Value],
        original: [Value; 2],
        destination: Register,
        next: usize,
        boolean: Option<bool>,
    ) -> Result<RegularCallAction, RuntimeError> {
        if event_value == Value::Nil {
            return Err(RuntimeError::new(RuntimeErrorKind::MetamethodAbsent));
        }
        let Some((event, args, ticket, chain_steps)) =
            self.resolve_callable_event(event_value, args)?
        else {
            return Ok(RegularCallAction::Aborted);
        };
        let kind = match boolean {
            Some(invert) => PendingKind::Boolean { invert },
            None => PendingKind::Value,
        };
        let result = self.invoke_event(
            kind,
            [
                original[0],
                original[1],
                event_value,
                Value::Nil,
                Value::Object(event),
            ],
            event,
            &args,
            destination,
            ResultMode::Fixed(1),
            next,
            chain_steps + 1,
            false,
        );
        drop(ticket);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn start_protected_call(
        &mut self,
        base: Register,
        start: usize,
        end: usize,
        result_mode: ResultMode,
        tail_return: bool,
        builtin: Builtin,
    ) -> Result<RegularCallAction, RuntimeError> {
        let next = if tail_return {
            self.frame.pc.checked_add(1).ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))?
        } else {
            self.next_pc()?
        };
        let target = self
            .frame
            .registers
            .get(start)
            .copied()
            .unwrap_or(Value::Nil);
        let handler = if builtin == Builtin::XPCall {
            Some(
                self.frame
                    .registers
                    .get(start + 1)
                    .copied()
                    .unwrap_or(Value::Nil),
            )
        } else {
            None
        };
        let arg_start = start + if handler.is_some() { 2 } else { 1 };
        let arg_count = end.saturating_sub(arg_start);
        let mut args = Vec::new();
        let args_ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut args,
            arg_count,
            FailPoint::WorkReserve,
        )?;
        args.extend_from_slice(&self.frame.registers[arg_start.min(end)..end]);
        self.push_protected_boundary(base, result_mode, tail_return, handler, next)?;
        let action = self.enter_callable_values(target, &args, base, result_mode, next)?;
        drop(args_ticket);
        if matches!(action, RegularCallAction::Aborted) {
            self.fuel = 0;
        }
        if let RegularCallAction::Completed(DispatchResult::Continue) = action {
            let first = self.frame.index(base)?;
            let end = self.frame.dynamic_top;
            let mut values = Vec::new();
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                end.saturating_sub(first),
                FailPoint::ReturnReserve,
            )?;
            values.extend_from_slice(&self.frame.registers[first..end]);
            return Ok(RegularCallAction::Completed(
                self.propagate_tail_result(values, Some(ticket))?,
            ));
        }
        Ok(action)
    }

    fn push_protected_boundary(
        &mut self,
        destination: Register,
        result_mode: ResultMode,
        tail_return: bool,
        handler: Option<Value>,
        next: usize,
    ) -> Result<(), RuntimeError> {
        let next_charge = if self.protected.len() == self.protected.capacity() {
            Some(
                self.protected_charge
                    .checked_add(core::mem::size_of::<ProtectedBoundary>())
                    .ok_or(VmError::ArithmeticOverflow)?,
            )
        } else {
            None
        };
        let handler_root = if let Some(Value::Object(object)) = handler {
            Some(self.vm.add_root(RootKind::Temporary, object)?)
        } else {
            None
        };
        if let Some(next_charge) = next_charge {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut self.protected,
                1,
                FailPoint::WorkReserve,
            );
            let ticket = match ticket {
                Ok(ticket) => ticket,
                Err(error) => {
                    if let Some(root) = handler_root {
                        self.vm.remove_root(root)?;
                    }
                    return Err(error.into());
                }
            };
            if let Err(error) = ticket.commit() {
                if let Some(root) = handler_root {
                    self.vm.remove_root(root)?;
                }
                return Err(error.into());
            }
            self.protected_charge = next_charge;
        }
        self.protected.push(ProtectedBoundary {
            caller_depth: self.callers.len(),
            caller_pc: self.frame.pc,
            resume_pc: next,
            destination,
            result_mode,
            tail_return,
            inline_target: false,
            handler,
            handler_root,
            stage: ProtectedStage::Body,
            handler_depth: None,
            handler_errors: 0,
            close_scope: self.frame.pending_close,
        });
        Ok(())
    }

    fn enter_callable_values(
        &mut self,
        target: Value,
        args: &[Value],
        destination: Register,
        result_mode: ResultMode,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let mut target = target;
        let mut current_mode = result_mode;
        let mut carried: Option<(Vec<Value>, Reservation, usize)> = None;
        loop {
            let inputs = carried
                .as_ref()
                .map_or(args, |(values, _, skip)| &values[*skip..]);
            let Some((callee, arguments, ticket, _)) =
                self.resolve_callable_event(target, inputs)?
            else {
                return Ok(RegularCallAction::Aborted);
            };
            match self.vm.object_kind(callee)? {
                ObjectKind::Builtin => match self.vm.builtin(callee)? {
                    Builtin::Error => {
                        return Err(explicit_error(
                            arguments.first().copied().unwrap_or(Value::Nil),
                            self.frame.pc,
                        ));
                    }
                    builtin @ (Builtin::PCall | Builtin::XPCall) => {
                        let handler = if builtin == Builtin::XPCall {
                            Some(arguments.get(1).copied().unwrap_or(Value::Nil))
                        } else {
                            None
                        };
                        let skip = (if handler.is_some() { 2 } else { 1 }).min(arguments.len());
                        let next_target = arguments.first().copied().unwrap_or(Value::Nil);
                        self.protected
                            .last_mut()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                            .inline_target = true;
                        self.push_protected_boundary(
                            destination,
                            ResultMode::All,
                            false,
                            handler,
                            next,
                        )?;
                        target = next_target;
                        current_mode = ResultMode::All;
                        carried = Some((arguments, ticket, skip));
                    }
                    builtin @ (Builtin::CoroutineCreate
                    | Builtin::CoroutineResume
                    | Builtin::CoroutineYield
                    | Builtin::CoroutineStatus
                    | Builtin::CoroutineClose
                    | Builtin::CoroutineWrap
                    | Builtin::CoroutineWrapped(_)) => {
                        if let Some(boundary) = self.protected.last_mut() {
                            boundary.inline_target = true;
                        }
                        let action = self.coroutine_builtin(
                            builtin,
                            destination,
                            &arguments,
                            current_mode,
                            false,
                            next,
                        )?;
                        drop(ticket);
                        return Ok(action);
                    }
                },
                ObjectKind::Closure => {
                    let entered = self.enter_metamethod_call(
                        callee,
                        &arguments,
                        destination,
                        current_mode,
                        next,
                        false,
                        false,
                    );
                    drop(ticket);
                    entered?;
                    return Ok(RegularCallAction::Entered);
                }
                _ => return Err(RuntimeError::new(RuntimeErrorKind::NotCallable)),
            }
        }
    }

    fn enter_regular_call(
        &mut self,
        base: Register,
        arg_count: u16,
        result_mode: ResultMode,
        tail_return: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        let first = self.frame.index(base)?;
        let start = first
            .checked_add(1)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let end = if arg_count == u16::MAX {
            self.frame.dynamic_top
        } else {
            start
                .checked_add(usize::from(arg_count))
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?
        };
        if end < start || end > self.frame.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let target = self.frame.read(base)?;
        if tail_return {
            // 末引數先求值，再於任何 callee 或 builtin 執行前關閉 caller upvalue。
            self.frame.close_open(self.vm)?;
        }
        if let Value::Object(object) = target {
            match self.vm.object_kind(object)? {
                ObjectKind::Closure => {
                    self.enter_call(base, arg_count, result_mode, tail_return)?;
                    return Ok(RegularCallAction::Entered);
                }
                ObjectKind::Builtin => match self.vm.builtin(object)? {
                    Builtin::Error => {
                        return Err(explicit_error(
                            self.frame
                                .registers
                                .get(start)
                                .copied()
                                .unwrap_or(Value::Nil),
                            self.frame.pc,
                        ));
                    }
                    builtin @ (Builtin::PCall | Builtin::XPCall) => {
                        return self.start_protected_call(
                            base,
                            start,
                            end,
                            result_mode,
                            tail_return,
                            builtin,
                        );
                    }
                    builtin => {
                        let next = if tail_return {
                            self.frame.pc.checked_add(1).ok_or(RuntimeError::new(
                                RuntimeErrorKind::ProgramCounterOutOfBounds,
                            ))?
                        } else {
                            self.next_pc()?
                        };
                        let mut args = Vec::new();
                        let ticket = reserve_vec(
                            self.vm.allocation_ledger(),
                            &mut args,
                            end - start,
                            FailPoint::WorkReserve,
                        )?;
                        args.extend_from_slice(&self.frame.registers[start..end]);
                        let action = self.coroutine_builtin(
                            builtin,
                            base,
                            &args,
                            result_mode,
                            tail_return,
                            next,
                        );
                        drop(ticket);
                        return action;
                    }
                },
                _ => {}
            }
        }
        let mut original_args = Vec::new();
        let original_ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut original_args,
            end - start,
            FailPoint::WorkReserve,
        )?;
        original_args.extend_from_slice(&self.frame.registers[start..end]);
        let Some((event, args, event_ticket, chain_steps)) =
            self.resolve_callable_event(target, &original_args)?
        else {
            return Ok(RegularCallAction::Aborted);
        };
        let next = if tail_return {
            self.frame.pc.checked_add(1).ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))?
        } else {
            self.next_pc()?
        };
        if tail_return
            && self.frame.pending_close.is_none()
            && self.vm.object_kind(event)? == ObjectKind::Closure
        {
            // 尾呼叫沒有本 frame 的回填目的；參數在替換 frame 前取得新 roots。
            self.enter_metamethod_call(event, &args, base, result_mode, next, true, true)?;
            drop(event_ticket);
            drop(original_ticket);
            return Ok(RegularCallAction::Entered);
        }
        let action = self.invoke_event(
            PendingKind::Call,
            [
                target,
                Value::Nil,
                Value::Nil,
                Value::Nil,
                Value::Object(event),
            ],
            event,
            &args,
            base,
            result_mode,
            next,
            chain_steps,
            tail_return,
        );
        drop(event_ticket);
        drop(original_ticket);
        action
    }

    fn enter_call(
        &mut self,
        base: Register,
        arg_count: u16,
        result_mode: ResultMode,
        tail_return: bool,
    ) -> Result<(), RuntimeError> {
        const FRAME_LIMIT: usize = 1024;
        let reuse_tail_frame = tail_return && self.frame.pending_close.is_none();
        let first = self.frame.index(base)?;
        let arguments_start = first
            .checked_add(1)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let arguments_end = if arg_count == u16::MAX {
            self.frame.dynamic_top
        } else {
            arguments_start
                .checked_add(usize::from(arg_count))
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?
        };
        if arguments_end < arguments_start || arguments_end > self.frame.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let actual_arg_count = arguments_end - arguments_start;
        if let ResultMode::Fixed(count) = result_mode {
            first
                .checked_add(usize::from(count))
                .filter(|end| *end <= self.frame.register_limit)
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        }
        let next = if tail_return {
            self.frame.pc.checked_add(1).ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))?
        } else {
            self.next_pc()?
        };
        let Value::Object(target) = self.frame.read(base)? else {
            return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
        };
        let (module_ref, prototype_id, captured_environment) = self
            .vm
            .with_closure(target, |closure| {
                (closure.module(), closure.prototype(), closure.environment())
            })
            .map_err(|error| {
                if error == VmError::WrongObjectType {
                    RuntimeError::new(RuntimeErrorKind::NotCallable)
                } else {
                    error.into()
                }
            })?;
        let child_index = self
            .vm
            .module(module_ref)?
            .module()
            .prototypes
            .iter()
            .position(|prototype| prototype.id == prototype_id)
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let prototype = &self.vm.module(module_ref)?.module().prototypes[child_index];
        let parameter_count = prototype.parameter_count;
        let is_variadic = prototype.is_variadic;
        let environment_register = prototype.frame.environment;
        let depth = if reuse_tail_frame {
            self.frame.depth
        } else {
            self.frame
                .depth
                .checked_add(1)
                .filter(|depth| *depth <= FRAME_LIMIT)
                .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?
        };
        let next_charge = if reuse_tail_frame {
            self.callers_charge
        } else {
            self.callers_charge
                .checked_add(core::mem::size_of::<CallFrame>())
                .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                    VmError::ArithmeticOverflow,
                )))?
        };
        let mut callee = CallFrame::new(
            prototype,
            child_index,
            Some(module_ref),
            self.vm.allocation_ledger(),
        )?;
        callee.closure = Some(target);
        callee.stack_base = if reuse_tail_frame {
            self.frame.stack_base
        } else {
            self.frame
                .stack_base
                .checked_add(self.frame.max_register_limit)
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?
        };
        callee.base = if reuse_tail_frame {
            self.frame.base
        } else {
            first
        };
        callee.return_destination = if reuse_tail_frame {
            self.frame.return_destination
        } else {
            Some(base)
        };
        callee.return_mode = if reuse_tail_frame {
            self.frame.return_mode
        } else {
            result_mode
        };
        callee.caller = if reuse_tail_frame {
            self.frame.caller
        } else {
            Some(self.callers.len())
        };
        callee.depth = depth;
        callee.closure_root = Some(self.vm.add_root(RootKind::Stack, target)?);
        if let Some(environment) = captured_environment {
            if let Err(error) = callee.write(self.vm, environment_register, environment) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        let copied = actual_arg_count.min(usize::from(parameter_count));
        for offset in 0..copied {
            let source = self.frame.registers[first + 1 + offset];
            let register = Register(
                u16::try_from(offset + 1)
                    .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
            );
            if let Err(error) = callee.write(self.vm, register, source) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        let mut named_payload = None;
        if is_variadic {
            let extra_start = first + 1 + usize::from(parameter_count);
            let extra = if extra_start < arguments_end {
                &self.frame.registers[extra_start..arguments_end]
            } else {
                &[]
            };
            if callee.named_vararg.is_some() {
                match callee.set_named_varargs(self.vm, extra) {
                    Ok(payload) => named_payload = Some(payload),
                    Err(error) => {
                        callee.clear_roots(self.vm)?;
                        return Err(error);
                    }
                }
            } else if let Err(error) = callee.set_varargs(self.vm, extra) {
                callee.clear_roots(self.vm)?;
                return Err(error);
            }
        }
        debug_assert_eq!(arguments_end, arguments_start + actual_arg_count);
        if !reuse_tail_frame && self.callers.len() == self.callers.capacity() {
            let ticket = match reserve_vec(
                self.vm.allocation_ledger(),
                &mut self.callers,
                1,
                FailPoint::CallFrameReserve,
            ) {
                Ok(ticket) => ticket,
                Err(error) => {
                    callee.clear_roots(self.vm)?;
                    if let Some((table, key)) = named_payload {
                        self.vm.reclaim(table)?;
                        self.vm.reclaim(key)?;
                    }
                    return Err(error.into());
                }
            };
            if let Err(error) = ticket.commit() {
                callee.clear_roots(self.vm)?;
                if let Some((table, key)) = named_payload {
                    self.vm.reclaim(table)?;
                    self.vm.reclaim(key)?;
                }
                return Err(error.into());
            }
            self.callers_charge = next_charge;
        }
        if reuse_tail_frame {
            let close = self
                .frame
                .close_open(self.vm)
                .and_then(|()| self.frame.clear_roots(self.vm));
            if let Err(error) = close {
                callee.clear_roots(self.vm)?;
                if let Some((table, key)) = named_payload {
                    self.vm.reclaim(table)?;
                    self.vm.reclaim(key)?;
                }
                return Err(error);
            }
            self.frame.release_storage();
            self.frame = callee;
            return Ok(());
        }
        self.frame.pc = next;
        self.frame.tail_return = tail_return;
        let caller = core::mem::replace(&mut self.frame, callee);
        self.callers.push(caller);
        self.peak_frame_count = self.peak_frame_count.max(self.callers.len() + 1);
        Ok(())
    }

    fn return_to_caller(&mut self, values: &[Value]) -> Result<(), RuntimeError> {
        if self.frame.caller != self.callers.len().checked_sub(1) {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        }
        let destination = self
            .frame
            .return_destination
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let mode = self.frame.return_mode;
        let caller = self
            .callers
            .last_mut()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let first = caller.index(destination)?;
        let count = match mode {
            ResultMode::Fixed(count) => usize::from(count),
            ResultMode::All => values.len(),
        };
        let end = first
            .checked_add(count)
            .filter(|end| *end <= caller.max_register_limit)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        if matches!(mode, ResultMode::All) {
            caller.grow_for_open_results(end)?;
        }
        for offset in 0..count {
            let value = values.get(offset).copied().unwrap_or(Value::Nil);
            caller.write(
                self.vm,
                Register(
                    u16::try_from(first + offset)
                        .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
                ),
                value,
            )?;
        }
        caller.dynamic_top = end;
        let resumed = self
            .callers
            .pop()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let mut finished = core::mem::replace(&mut self.frame, resumed);
        finished.close_open(self.vm)?;
        finished.clear_roots(self.vm)?;
        finished.release_storage();
        Ok(())
    }

    pub fn vm_id(&self) -> VmId {
        self.vm_id
    }

    pub fn pc(&self) -> usize {
        self.frame.pc
    }

    pub fn dynamic_top(&self) -> usize {
        self.frame.dynamic_top
    }

    pub fn peak_frame_count(&self) -> usize {
        self.peak_frame_count
    }

    pub fn pending_close(&self) -> Option<PendingCloseSnapshot> {
        (self.state == ExecutionState::PendingClose)
            .then_some(self.frame.pending_close)
            .flatten()
    }

    /// 只在 Execution 持有 frame roots 時讀取暫存的 return 值。
    pub fn pending_close_result(&self, index: usize) -> Option<Value> {
        let snapshot = self.pending_close()?;
        let base = usize::from(snapshot.return_base?.0);
        (index < snapshot.result_count)
            .then(|| {
                base.checked_add(index)
                    .and_then(|slot| self.frame.registers.get(slot).copied())
            })
            .flatten()
    }

    fn close_snapshot(&self) -> Result<PendingCloseSnapshot, RuntimeError> {
        let prototype = self.prototype();
        let pc = self.frame.pc;
        let entry = &prototype.instructions[pc];
        let path = entry.close_path.as_ref().ok_or(RuntimeError::new(
            RuntimeErrorKind::UnsupportedInstruction(Opcode::Close),
        ))?;
        let Some((path_offset, path_start_pc)) = (0..path.registers.len()).find_map(|offset| {
            let start = pc.checked_sub(offset)?;
            let valid = path.registers.iter().enumerate().all(|(index, register)| {
                matches!(prototype.instructions.get(start + index), Some(candidate)
                    if candidate.instruction == Instruction::Close { base: *register, count: 1 }
                        && candidate.close_path.as_ref() == Some(path))
            });
            valid.then_some((offset, start))
        }) else {
            return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedInstruction(
                Opcode::Close,
            )));
        };
        let after = path_start_pc
            .checked_add(path.registers.len())
            .ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))?;
        let (return_base, return_mode, result_count) = match prototype
            .instructions
            .get(after)
            .map(|entry| &entry.instruction)
        {
            Some(Instruction::Return { base, result_mode }) => {
                let count = match result_mode {
                    ResultMode::Fixed(count) => usize::from(*count),
                    ResultMode::All => self
                        .frame
                        .dynamic_top
                        .checked_sub(usize::from(base.0))
                        .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
                };
                (Some(*base), Some(*result_mode), count)
            }
            _ => (None, None, 0),
        };
        Ok(PendingCloseSnapshot {
            prototype: prototype.id,
            close_pc: pc,
            path_start_pc,
            path_offset,
            path_kind: path.kind,
            next_binding: path.bindings[path_offset],
            next_register: path.registers[path_offset],
            return_base,
            return_mode,
            result_count,
            retained_root_count: self.vm.roots().total_count(),
        })
    }

    pub fn fuel_remaining(&self) -> u64 {
        self.fuel
    }

    fn swap_thread(&mut self, mut context: ThreadContext) -> ThreadContext {
        core::mem::swap(&mut self.frame, &mut context.frame);
        core::mem::swap(&mut self.callers, &mut context.callers);
        core::mem::swap(&mut self.callers_charge, &mut context.callers_charge);
        core::mem::swap(&mut self.pending_ops, &mut context.pending_ops);
        core::mem::swap(&mut self.protected, &mut context.protected);
        core::mem::swap(&mut self.protected_charge, &mut context.protected_charge);
        core::mem::swap(&mut self.error_root, &mut context.error_root);
        core::mem::swap(&mut self.close_unwind, &mut context.close_unwind);
        core::mem::swap(&mut self.yield_site, &mut context.yield_site);
        context
    }

    fn new_coroutine_frame(
        &mut self,
        entry: Value,
        args: &[Value],
    ) -> Result<CallFrame, RuntimeError> {
        let Value::Object(closure) = entry else {
            return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
        };
        let (module, prototype_id, environment) = self
            .vm
            .with_closure(closure, |c| (c.module(), c.prototype(), c.environment()))
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::NotCallable))?;
        let index = self
            .vm
            .module(module)?
            .module()
            .prototypes
            .iter()
            .position(|p| p.id == prototype_id)
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let prototype = &self.vm.module(module)?.module().prototypes[index];
        let parameter_count = usize::from(prototype.parameter_count);
        let is_variadic = prototype.is_variadic;
        let env_register = prototype.frame.environment;
        let mut frame =
            CallFrame::new(prototype, index, Some(module), self.vm.allocation_ledger())?;
        frame.closure = Some(closure);
        frame.closure_root = Some(self.vm.add_root(RootKind::Stack, closure)?);
        let initialized = (|| {
            if let Some(value) = environment {
                frame.write(self.vm, env_register, value)?;
            }
            for (offset, value) in args.iter().copied().take(parameter_count).enumerate() {
                let register = Register(
                    u16::try_from(offset + 1)
                        .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
                );
                frame.write(self.vm, register, value)?;
            }
            if is_variadic {
                let extra = args.get(parameter_count..).unwrap_or(&[]);
                if frame.named_vararg.is_some() {
                    frame.set_named_varargs(self.vm, extra)?;
                } else {
                    frame.set_varargs(self.vm, extra)?;
                }
            }
            Ok::<(), RuntimeError>(())
        })();
        if let Err(error) = initialized {
            frame.clear_roots(self.vm)?;
            return Err(error);
        }
        Ok(frame)
    }

    fn complete_builtin_values(
        &mut self,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        values: Vec<Value>,
        ticket: Option<Reservation>,
    ) -> Result<RegularCallAction, RuntimeError> {
        if tail_return {
            return Ok(RegularCallAction::Completed(
                self.propagate_tail_result(values, ticket)?,
            ));
        }
        self.write_call_values(destination, mode, next, &values)?;
        drop(ticket);
        Ok(RegularCallAction::Completed(DispatchResult::Continue))
    }

    fn coroutine_message(&mut self, bytes: &[u8]) -> Result<Value, RuntimeError> {
        Ok(Value::Object(self.vm.allocate_byte_string(bytes)?))
    }

    fn ensure_resume_capacity(&mut self) -> Result<(), RuntimeError> {
        if self.resume_stack.len() == self.resume_stack.capacity() {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut self.resume_stack,
                1,
                FailPoint::WorkReserve,
            )?;
            ticket.commit()?;
            self.resume_charge = self
                .resume_charge
                .checked_add(core::mem::size_of::<ResumeCaller>())
                .ok_or(VmError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn enter_native_protected_frame(
        &mut self,
        object: ObjectRef,
        frame: CallFrame,
        native: NativeCompletion,
        handler: Option<Value>,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let mut context = ThreadContext::new(frame, self.vm.allocation_ledger());
        if let Err(error) = self.ensure_resume_capacity() {
            context.finish(self.vm)?;
            return Err(error);
        }
        let child_root = match root_coroutine(self.vm, object) {
            Ok(root) => root,
            Err(error) => {
                context.finish(self.vm)?;
                return Err(error.into());
            }
        };
        let handler_root = if let Some(Value::Object(handler)) = handler {
            match self.vm.add_root(RootKind::Temporary, handler) {
                Ok(root) => Some(root),
                Err(error) => {
                    self.vm.remove_root(child_root)?;
                    context.finish(self.vm)?;
                    return Err(error.into());
                }
            }
        } else {
            None
        };
        let parent = self.swap_thread(context);
        self.resume_stack.push(ResumeCaller {
            context: parent,
            owner: self.active_coroutine,
            owner_root: self.active_coroutine_root.take(),
            child: object,
            child_root,
            destination,
            result_mode: mode,
            resume_pc: next,
            tail_return,
            wrapped: false,
            native_body: None,
            native: Some(native),
            outer_resumes: ResumeChain::new(self.vm.allocation_ledger()),
            handler_root,
        });
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.active_coroutine = Some(object);
        self.vm.with_coroutine_mut(object, |co| {
            co.state = CoroutineState::Running;
            co.entry = Value::Nil;
        })?;
        Ok(RegularCallAction::Entered)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_native_body_direct(
        &mut self,
        object: ObjectRef,
        success: bool,
        body_values: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let root = root_coroutine(self.vm, object)?;
        let mut values = Vec::new();
        let prepared = (|| {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                body_values.len().saturating_add(1),
                FailPoint::ReturnReserve,
            )?;
            values.push(Value::Boolean(success));
            values.extend_from_slice(body_values);
            Ok::<_, RuntimeError>(ticket)
        })();
        self.vm.with_coroutine_mut(object, |co| {
            co.state = CoroutineState::Dead;
            co.entry = Value::Nil;
            co.error = (!success).then(|| body_values.first().copied().unwrap_or(Value::Nil));
            co.native = None;
        })?;
        self.vm.remove_root(root)?;
        let ticket = prepared?;
        self.complete_builtin_values(destination, mode, tail_return, next, values, Some(ticket))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_native_protected_direct(
        &mut self,
        object: ObjectRef,
        protected: NativeProtected,
        body: Result<&[Value], Value>,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let mut result = Vec::new();
        let body_len = body.as_ref().map_or(1, |values| values.len());
        let ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut result,
            body_len.saturating_add(3),
            FailPoint::ReturnReserve,
        )?;
        match (protected, body) {
            (NativeProtected::PCall { depth }, Ok(values)) => {
                for _ in 0..depth {
                    result.push(Value::Boolean(true));
                }
                result.extend_from_slice(values);
            }
            (NativeProtected::PCall { depth }, Err(error)) => {
                for _ in 1..depth {
                    result.push(Value::Boolean(true));
                }
                result.push(Value::Boolean(false));
                result.push(error);
            }
            (NativeProtected::XPCall { .. }, Ok(values)) => {
                result.push(Value::Boolean(true));
                result.extend_from_slice(values);
            }
            (NativeProtected::XPCall { .. }, Err(_)) => {
                return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
            }
        }
        let completed = self.finish_native_body_direct(
            object,
            true,
            &result,
            destination,
            mode,
            tail_return,
            next,
        );
        drop(ticket);
        completed
    }

    #[allow(clippy::too_many_arguments)]
    fn start_native_protected_error(
        &mut self,
        object: ObjectRef,
        protected: NativeProtected,
        error: Value,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let NativeProtected::XPCall { handler } = protected else {
            return self.finish_native_protected_direct(
                object,
                protected,
                Err(error),
                destination,
                mode,
                tail_return,
                next,
            );
        };
        if let Value::Object(handler_object) = handler {
            if self.vm.object_kind(handler_object)? == ObjectKind::Closure {
                let error_root = if let Value::Object(value) = error {
                    Some(self.vm.add_root(RootKind::Temporary, value)?)
                } else {
                    None
                };
                let frame = self.new_coroutine_frame(handler, &[error]);
                if let Some(root) = error_root {
                    self.vm.remove_root(root)?;
                }
                return self.enter_native_protected_frame(
                    object,
                    frame?,
                    NativeCompletion::XPCallHandler { handler, errors: 0 },
                    Some(handler),
                    destination,
                    mode,
                    tail_return,
                    next,
                );
            }
        }
        let message = self.coroutine_message(b"error in error handling")?;
        self.finish_native_body_direct(
            object,
            false,
            &[message],
            destination,
            mode,
            tail_return,
            next,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_native_protected_yield(
        &mut self,
        object: ObjectRef,
        protected: NativeProtected,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let root = root_coroutine(self.vm, object)?;
        let mut values = Vec::new();
        let prepared = (|| {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                args.len().saturating_add(1),
                FailPoint::ReturnReserve,
            )?;
            values.push(Value::Boolean(true));
            values.extend_from_slice(args);
            Ok::<_, RuntimeError>(ticket)
        })();
        if prepared.is_ok() {
            self.vm.with_coroutine_mut(object, |co| {
                co.state = CoroutineState::Suspended;
                co.native_yielded = true;
                co.native = Some(match protected {
                    NativeProtected::PCall { depth } => NativeCompletion::PCall { depth },
                    NativeProtected::XPCall { handler } => {
                        NativeCompletion::XPCallBody { handler, errors: 0 }
                    }
                });
            })?;
        }
        self.vm.remove_root(root)?;
        self.complete_builtin_values(
            destination,
            mode,
            tail_return,
            next,
            values,
            Some(prepared?),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_native_protected_resume(
        &mut self,
        object: ObjectRef,
        protected: NativeProtected,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let mut resume_args = Vec::new();
        let ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut resume_args,
            args.len().saturating_add(1),
            FailPoint::WorkReserve,
        )?;
        resume_args.push(Value::Object(object));
        resume_args.extend_from_slice(args);
        let result = self.start_native_resume_coroutine(
            object,
            &resume_args,
            destination,
            mode,
            tail_return,
            next,
            Some(protected),
        );
        drop(ticket);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn start_native_protected_coroutine(
        &mut self,
        object: ObjectRef,
        builtin: Builtin,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let input = args.get(1..).unwrap_or(&[]);
        let mut target = input.first().copied().unwrap_or(Value::Nil);
        let handler =
            (builtin == Builtin::XPCall).then(|| input.get(1).copied().unwrap_or(Value::Nil));
        let mut start = if handler.is_some() { 2 } else { 1 };
        let mut depth = 1u8;
        if builtin == Builtin::PCall {
            while let Value::Object(candidate) = target {
                if self.vm.object_kind(candidate)? != ObjectKind::Builtin
                    || self.vm.builtin(candidate)? != Builtin::PCall
                {
                    break;
                }
                depth = depth
                    .checked_add(1)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?;
                target = input.get(start).copied().unwrap_or(Value::Nil);
                start += 1;
            }
        }
        let protected = match handler {
            Some(handler) => NativeProtected::XPCall { handler },
            None => NativeProtected::PCall { depth },
        };
        let body_args = input.get(start..).unwrap_or(&[]);
        if let Value::Object(target_object) = target {
            if self.vm.object_kind(target_object)? == ObjectKind::Builtin {
                match self.vm.builtin(target_object)? {
                    Builtin::Error => {
                        return self.start_native_protected_error(
                            object,
                            protected,
                            body_args.first().copied().unwrap_or(Value::Nil),
                            destination,
                            mode,
                            tail_return,
                            next,
                        );
                    }
                    Builtin::CoroutineStatus => {
                        let state = match body_args.first().copied().unwrap_or(Value::Nil) {
                            Value::Object(target) if target == object => {
                                Ok(CoroutineState::Running)
                            }
                            Value::Object(target) if Some(target) == self.active_coroutine => {
                                Ok(CoroutineState::Normal)
                            }
                            Value::Object(target) => self.vm.coroutine_state(target),
                            _ => Err(VmError::WrongObjectType),
                        };
                        let state = match state {
                            Ok(state) => state,
                            Err(VmError::WrongObjectType) => {
                                let error = self.coroutine_message(b"E_WRONG_OBJECT_TYPE")?;
                                return self.start_native_protected_error(
                                    object,
                                    protected,
                                    error,
                                    destination,
                                    mode,
                                    tail_return,
                                    next,
                                );
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let name = match state {
                            CoroutineState::Suspended => b"suspended".as_slice(),
                            CoroutineState::Running => b"running".as_slice(),
                            CoroutineState::Normal => b"normal".as_slice(),
                            CoroutineState::Dead => b"dead".as_slice(),
                        };
                        let value = self.coroutine_message(name)?;
                        return self.finish_native_protected_direct(
                            object,
                            protected,
                            Ok(&[value]),
                            destination,
                            mode,
                            tail_return,
                            next,
                        );
                    }
                    Builtin::CoroutineCreate => {
                        let entry = body_args.first().copied().unwrap_or(Value::Nil);
                        let valid = match entry {
                            Value::Object(target) => matches!(
                                self.vm.object_kind(target)?,
                                ObjectKind::Closure | ObjectKind::Builtin
                            ),
                            _ => false,
                        };
                        if !valid {
                            let error = self.coroutine_message(b"E_CALL_NON_FUNCTION")?;
                            return self.start_native_protected_error(
                                object,
                                protected,
                                error,
                                destination,
                                mode,
                                tail_return,
                                next,
                            );
                        }
                        let created = Value::Object(self.vm.allocate_coroutine(entry)?);
                        return self.finish_native_protected_direct(
                            object,
                            protected,
                            Ok(&[created]),
                            destination,
                            mode,
                            tail_return,
                            next,
                        );
                    }
                    Builtin::CoroutineYield => {
                        return self.start_native_protected_yield(
                            object,
                            protected,
                            body_args,
                            destination,
                            mode,
                            tail_return,
                            next,
                        );
                    }
                    Builtin::CoroutineResume => {
                        return self.start_native_protected_resume(
                            object,
                            protected,
                            body_args,
                            destination,
                            mode,
                            tail_return,
                            next,
                        );
                    }
                    Builtin::PCall
                    | Builtin::XPCall
                    | Builtin::CoroutineClose
                    | Builtin::CoroutineWrap
                    | Builtin::CoroutineWrapped(_) => {
                        let inner = self.vm.allocate_coroutine(target)?;
                        let inner_root = root_coroutine(self.vm, inner)?;
                        let mut bridge_args = Vec::new();
                        let prepared = reserve_vec(
                            self.vm.allocation_ledger(),
                            &mut bridge_args,
                            body_args.len().saturating_add(2),
                            FailPoint::WorkReserve,
                        );
                        let prepared = match prepared {
                            Ok(ticket) => ticket,
                            Err(error) => {
                                self.vm.remove_root(inner_root)?;
                                return Err(error.into());
                            }
                        };
                        bridge_args.push(Value::Object(object));
                        bridge_args.push(Value::Object(inner));
                        bridge_args.extend_from_slice(body_args);
                        let action = self.start_native_resume_coroutine(
                            object,
                            &bridge_args,
                            destination,
                            mode,
                            tail_return,
                            next,
                            None,
                        );
                        drop(prepared);
                        self.vm.remove_root(inner_root)?;
                        return action;
                    }
                }
            }
        }
        let frame = match self.new_coroutine_frame(target, body_args) {
            Ok(frame) => frame,
            Err(error) if matches!(error.kind, RuntimeErrorKind::NotCallable) => {
                let value = self.coroutine_message(error.diagnostic_id.as_bytes())?;
                return self.start_native_protected_error(
                    object,
                    protected,
                    value,
                    destination,
                    mode,
                    tail_return,
                    next,
                );
            }
            Err(error) => return Err(error),
        };
        let native = match protected {
            NativeProtected::PCall { depth } => NativeCompletion::PCall { depth },
            NativeProtected::XPCall { handler } => {
                NativeCompletion::XPCallBody { handler, errors: 0 }
            }
        };
        self.enter_native_protected_frame(
            object,
            frame,
            native,
            handler,
            destination,
            mode,
            tail_return,
            next,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_native_resume_coroutine(
        &mut self,
        object: ObjectRef,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        protected: Option<NativeProtected>,
    ) -> Result<RegularCallAction, RuntimeError> {
        let outer_root = root_coroutine(self.vm, object)?;
        let parent = self.active_coroutine;
        let parent_root = self.active_coroutine_root.take();
        if let Some(parent) = parent {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.active_coroutine = Some(object);
        self.active_coroutine_root = Some(outer_root);
        self.vm
            .with_coroutine_mut(object, |co| co.state = CoroutineState::Running)?;
        let action = self.start_coroutine_resume(
            destination,
            args.get(1..).unwrap_or(&[]),
            ResultMode::All,
            false,
            next,
            false,
        );
        match action {
            Ok(RegularCallAction::Entered) => {
                let caller = self
                    .resume_stack
                    .last_mut()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                let continuation = NativeCompletion::Resume {
                    outer: object,
                    parent,
                    parent_root,
                    protected,
                };
                if caller.native.is_some() {
                    if let Err(error) = caller.outer_resumes.push(continuation) {
                        self.vm.with_coroutine_mut(object, |co| {
                            co.state = CoroutineState::Dead;
                            co.native_bridge = None;
                        })?;
                        if let Some(root) = parent_root {
                            self.vm.remove_root(root)?;
                        }
                        return Err(error.into());
                    }
                } else {
                    caller.native = Some(continuation);
                }
                caller.result_mode = mode;
                caller.tail_return = tail_return;
                Ok(RegularCallAction::Entered)
            }
            Ok(RegularCallAction::Completed(DispatchResult::Continue)) => {
                let first = self.frame.index(destination)?;
                let mut values = Vec::new();
                let protected_count = match protected {
                    Some(NativeProtected::PCall { depth }) => usize::from(depth),
                    Some(NativeProtected::XPCall { .. }) => 1,
                    None => 0,
                };
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    self.frame.dynamic_top.saturating_sub(first) + 1 + protected_count,
                    FailPoint::ReturnReserve,
                )?;
                values.push(Value::Boolean(true));
                values.extend(core::iter::repeat_n(Value::Boolean(true), protected_count));
                values.extend_from_slice(&self.frame.registers[first..self.frame.dynamic_top]);
                self.vm.with_coroutine_mut(object, |co| {
                    co.state = CoroutineState::Dead;
                    co.entry = Value::Nil;
                })?;
                self.vm.remove_root(outer_root)?;
                self.active_coroutine = parent;
                self.active_coroutine_root = parent_root;
                if let Some(parent) = parent {
                    self.vm
                        .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
                }
                self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    Some(ticket),
                )
            }
            Ok(RegularCallAction::Completed(result)) => Ok(RegularCallAction::Completed(result)),
            Ok(RegularCallAction::Aborted) => Ok(RegularCallAction::Aborted),
            Err(error) => {
                let lua_failure = matches!(
                    error.kind,
                    RuntimeErrorKind::NotCallable
                        | RuntimeErrorKind::Heap(VmError::WrongObjectType)
                );
                let mut values = Vec::new();
                let result = if lua_failure {
                    let prepared = (|| {
                        let ticket = reserve_vec(
                            self.vm.allocation_ledger(),
                            &mut values,
                            2,
                            FailPoint::ReturnReserve,
                        )?;
                        values.push(Value::Boolean(false));
                        values.push(self.coroutine_message(error.diagnostic_id.as_bytes())?);
                        Ok::<_, RuntimeError>(ticket)
                    })();
                    Some(prepared)
                } else {
                    None
                };
                self.vm.with_coroutine_mut(object, |co| {
                    co.state = CoroutineState::Dead;
                    co.entry = Value::Nil;
                })?;
                self.vm.remove_root(outer_root)?;
                self.active_coroutine = parent;
                self.active_coroutine_root = parent_root;
                if let Some(parent) = parent {
                    self.vm
                        .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
                }
                match (result, protected) {
                    (Some(Ok(ticket)), Some(protected)) => {
                        let error_value = values.get(1).copied().unwrap_or(Value::Nil);
                        drop(ticket);
                        self.start_native_protected_error(
                            object,
                            protected,
                            error_value,
                            destination,
                            mode,
                            tail_return,
                            next,
                        )
                    }
                    (Some(Ok(ticket)), None) => self.complete_builtin_values(
                        destination,
                        mode,
                        tail_return,
                        next,
                        values,
                        Some(ticket),
                    ),
                    (Some(Err(fatal)), _) => Err(fatal),
                    (None, _) => Err(error),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_wrapped_native_action(
        &mut self,
        object: ObjectRef,
        action: RegularCallAction,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        match action {
            RegularCallAction::Entered => {
                let caller = self
                    .resume_stack
                    .last_mut()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                caller.wrapped = true;
                caller.result_mode = mode;
                caller.tail_return = tail_return;
                Ok(RegularCallAction::Entered)
            }
            RegularCallAction::Aborted => Ok(RegularCallAction::Aborted),
            RegularCallAction::Completed(DispatchResult::Continue) => {
                let first = self.frame.index(destination)?;
                let count = self.frame.dynamic_top.saturating_sub(first);
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    count,
                    FailPoint::ReturnReserve,
                )?;
                values.extend_from_slice(&self.frame.registers[first..self.frame.dynamic_top]);
                let success = values.first() == Some(&Value::Boolean(true));
                if !success {
                    drop(ticket);
                    return self.start_coroutine_close(
                        object,
                        destination,
                        mode,
                        tail_return,
                        next,
                        true,
                    );
                }
                values.remove(0);
                self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    Some(ticket),
                )
            }
            RegularCallAction::Completed(_) => {
                Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_native_builtin_body(
        &mut self,
        continuation: NativeBodyContinuation,
        success: bool,
        mut values: Vec<Value>,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<DispatchResult, RuntimeError> {
        let outer_root = self.active_coroutine_root.take();
        self.vm.with_coroutine_mut(continuation.outer, |co| {
            co.state = CoroutineState::Dead;
            co.entry = Value::Nil;
            co.native = None;
            co.native_bridge = None;
            co.error = (!success).then(|| values.first().copied().unwrap_or(Value::Nil));
        })?;
        self.active_coroutine = continuation.parent;
        self.active_coroutine_root = continuation.parent_root;
        if let Some(parent) = continuation.parent {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
        }
        let result = (|| -> Result<DispatchResult, RuntimeError> {
            if continuation.wrapped && !success {
                Err(explicit_error(
                    values.first().copied().unwrap_or(Value::Nil),
                    self.frame.pc,
                ))
            } else {
                if !continuation.wrapped {
                    let ticket = reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut values,
                        1,
                        FailPoint::ReturnReserve,
                    )?;
                    values.insert(0, Value::Boolean(success));
                    drop(ticket);
                }
                match self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    None,
                )? {
                    RegularCallAction::Completed(action) => Ok(action),
                    RegularCallAction::Aborted => Ok(DispatchResult::Aborted),
                    RegularCallAction::Entered => {
                        Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))
                    }
                }
            }
        })();
        if let Some(root) = outer_root {
            self.vm.remove_root(root)?;
        }
        result
    }

    fn cleanup_native_builtin_failure(
        &mut self,
        continuation: NativeBodyContinuation,
    ) -> Result<(), RuntimeError> {
        let outer_root = self.active_coroutine_root.take();
        let dead = self.vm.with_coroutine_mut(continuation.outer, |co| {
            co.state = CoroutineState::Dead;
            co.entry = Value::Nil;
            co.native = None;
            co.native_bridge = None;
        });
        self.active_coroutine = continuation.parent;
        self.active_coroutine_root = continuation.parent_root;
        if let Some(root) = outer_root {
            self.vm.remove_root(root)?;
        }
        dead?;
        if let Some(parent) = continuation.parent {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn run_new_native_builtin_body(
        &mut self,
        object: ObjectRef,
        builtin: Builtin,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        wrapped: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        let outer_root = root_coroutine(self.vm, object)?;
        let parent = self.active_coroutine;
        let parent_root = self.active_coroutine_root.take();
        if let Some(parent) = parent {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.active_coroutine = Some(object);
        self.active_coroutine_root = Some(outer_root);
        self.vm
            .with_coroutine_mut(object, |co| co.state = CoroutineState::Running)?;
        let continuation = NativeBodyContinuation {
            outer: object,
            parent,
            parent_root,
            wrapped,
            destination,
            result_mode: mode,
            tail_return,
            resume_pc: next,
        };
        let input = args.get(1..).unwrap_or(&[]);
        let action = match builtin {
            Builtin::CoroutineWrapped(inner) => self.start_wrapped_coroutine(
                inner,
                input,
                destination,
                ResultMode::All,
                false,
                next,
            ),
            Builtin::CoroutineClose | Builtin::CoroutineWrap => {
                self.coroutine_builtin(builtin, destination, input, ResultMode::All, false, next)
            }
            _ => Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint)),
        };
        match action {
            Ok(RegularCallAction::Entered) => {
                self.resume_stack
                    .last_mut()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                    .native_body = Some(continuation);
                Ok(RegularCallAction::Entered)
            }
            Ok(RegularCallAction::Completed(DispatchResult::Continue)) => {
                let first = match self.frame.index(destination) {
                    Ok(first) => first,
                    Err(error) => {
                        self.cleanup_native_builtin_failure(continuation)?;
                        return Err(error);
                    }
                };
                let mut values = Vec::new();
                let ticket = match reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    self.frame.dynamic_top.saturating_sub(first),
                    FailPoint::ReturnReserve,
                ) {
                    Ok(ticket) => ticket,
                    Err(error) => {
                        self.cleanup_native_builtin_failure(continuation)?;
                        return Err(error.into());
                    }
                };
                values.extend_from_slice(&self.frame.registers[first..self.frame.dynamic_top]);
                let result = self.finish_native_builtin_body(
                    continuation,
                    true,
                    values,
                    destination,
                    mode,
                    tail_return,
                    next,
                );
                drop(ticket);
                result.map(RegularCallAction::Completed)
            }
            Ok(RegularCallAction::Aborted) => {
                self.cleanup_native_builtin_failure(continuation)?;
                Ok(RegularCallAction::Aborted)
            }
            Ok(RegularCallAction::Completed(_)) => {
                self.cleanup_native_builtin_failure(continuation)?;
                Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))
            }
            Err(mut error) => {
                if !error.kind.is_lua_error() {
                    self.cleanup_native_builtin_failure(continuation)?;
                    return Err(error);
                }
                if error.value == Value::Nil && error.kind != RuntimeErrorKind::Thrown {
                    error.value = match self.coroutine_message(error.diagnostic_id.as_bytes()) {
                        Ok(value) => value,
                        Err(fatal) => {
                            self.cleanup_native_builtin_failure(continuation)?;
                            return Err(fatal);
                        }
                    };
                }
                let mut values = Vec::new();
                let ticket = match reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    1,
                    FailPoint::ReturnReserve,
                ) {
                    Ok(ticket) => ticket,
                    Err(fatal) => {
                        self.cleanup_native_builtin_failure(continuation)?;
                        return Err(fatal.into());
                    }
                };
                values.push(error.value);
                let completed = self.finish_native_builtin_body(
                    continuation,
                    false,
                    values,
                    destination,
                    mode,
                    tail_return,
                    next,
                );
                drop(ticket);
                completed.map(RegularCallAction::Completed)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_native_coroutine(
        &mut self,
        object: ObjectRef,
        builtin: Builtin,
        already_yielded: bool,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        wrapped: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        if let Some(inner) = self.vm.with_coroutine(object, |co| co.native_bridge)? {
            let mut bridge_args = Vec::new();
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut bridge_args,
                args.len().saturating_add(1),
                FailPoint::WorkReserve,
            )?;
            bridge_args.push(Value::Object(object));
            bridge_args.push(Value::Object(inner));
            bridge_args.extend_from_slice(args.get(1..).unwrap_or(&[]));
            let result = self.start_native_resume_coroutine(
                object,
                &bridge_args,
                destination,
                if wrapped { ResultMode::All } else { mode },
                tail_return && !wrapped,
                next,
                None,
            );
            drop(ticket);
            return if wrapped {
                self.finish_wrapped_native_action(
                    object,
                    result?,
                    destination,
                    mode,
                    tail_return,
                    next,
                )
            } else {
                result
            };
        }
        if !already_yielded {
            match builtin {
                Builtin::CoroutineClose | Builtin::CoroutineWrap | Builtin::CoroutineWrapped(_) => {
                    return self.run_new_native_builtin_body(
                        object,
                        builtin,
                        args,
                        destination,
                        mode,
                        tail_return,
                        next,
                        wrapped,
                    );
                }
                Builtin::PCall | Builtin::XPCall => {
                    let result = self.start_native_protected_coroutine(
                        object,
                        builtin,
                        args,
                        destination,
                        if wrapped { ResultMode::All } else { mode },
                        tail_return && !wrapped,
                        next,
                    );
                    return if wrapped {
                        self.finish_wrapped_native_action(
                            object,
                            result?,
                            destination,
                            mode,
                            tail_return,
                            next,
                        )
                    } else {
                        result
                    };
                }
                Builtin::CoroutineResume => {
                    let result = self.start_native_resume_coroutine(
                        object,
                        args,
                        destination,
                        if wrapped { ResultMode::All } else { mode },
                        tail_return && !wrapped,
                        next,
                        None,
                    );
                    return if wrapped {
                        self.finish_wrapped_native_action(
                            object,
                            result?,
                            destination,
                            mode,
                            tail_return,
                            next,
                        )
                    } else {
                        result
                    };
                }
                _ => {}
            }
        }
        let root = root_coroutine(self.vm, object)?;
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.vm
            .with_coroutine_mut(object, |co| co.state = CoroutineState::Running)?;
        let mut values = Vec::new();
        let native = self.vm.with_coroutine(object, |co| co.native)?;
        let native_count = if already_yielded {
            match native {
                Some(NativeCompletion::PCall { depth }) => usize::from(depth),
                Some(NativeCompletion::XPCallBody { .. }) => 1,
                _ => 0,
            }
        } else {
            0
        };
        let evaluation = (|| {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                args.len().saturating_add(2 + native_count),
                FailPoint::ReturnReserve,
            )?;
            let input = args.get(1..).unwrap_or(&[]);
            let (success, state, error) = if already_yielded {
                values.extend(core::iter::repeat_n(Value::Boolean(true), native_count));
                values.extend_from_slice(input);
                (true, CoroutineState::Dead, None)
            } else {
                match builtin {
                    Builtin::CoroutineYield => {
                        values.extend_from_slice(input);
                        (true, CoroutineState::Suspended, None)
                    }
                    Builtin::Error => {
                        let error = input.first().copied().unwrap_or(Value::Nil);
                        values.push(error);
                        (false, CoroutineState::Dead, Some(error))
                    }
                    Builtin::CoroutineStatus => {
                        match input.first().copied().unwrap_or(Value::Nil) {
                            Value::Object(target) => match self.vm.coroutine_state(target) {
                                Ok(state) => {
                                    let name = match state {
                                        CoroutineState::Suspended => b"suspended".as_slice(),
                                        CoroutineState::Running => b"running".as_slice(),
                                        CoroutineState::Normal => b"normal".as_slice(),
                                        CoroutineState::Dead => b"dead".as_slice(),
                                    };
                                    values.push(self.coroutine_message(name)?);
                                    (true, CoroutineState::Dead, None)
                                }
                                Err(VmError::WrongObjectType) => {
                                    let error = self.coroutine_message(b"E_WRONG_OBJECT_TYPE")?;
                                    values.push(error);
                                    (false, CoroutineState::Dead, Some(error))
                                }
                                Err(error) => return Err(error.into()),
                            },
                            _ => {
                                let error = self.coroutine_message(b"E_WRONG_OBJECT_TYPE")?;
                                values.push(error);
                                (false, CoroutineState::Dead, Some(error))
                            }
                        }
                    }
                    Builtin::CoroutineCreate => {
                        let entry = input.first().copied().unwrap_or(Value::Nil);
                        let valid = match entry {
                            Value::Object(target) => matches!(
                                self.vm.object_kind(target)?,
                                ObjectKind::Closure | ObjectKind::Builtin
                            ),
                            _ => false,
                        };
                        if valid {
                            let child = self.vm.allocate_coroutine(entry)?;
                            values.push(Value::Object(child));
                            (true, CoroutineState::Dead, None)
                        } else {
                            let error = self.coroutine_message(b"E_CALL_NON_FUNCTION")?;
                            values.push(error);
                            (false, CoroutineState::Dead, Some(error))
                        }
                    }
                    Builtin::PCall
                    | Builtin::XPCall
                    | Builtin::CoroutineResume
                    | Builtin::CoroutineClose
                    | Builtin::CoroutineWrap
                    | Builtin::CoroutineWrapped(_) => unreachable!(),
                }
            };
            Ok::<(bool, CoroutineState, Option<Value>, Reservation), RuntimeError>((
                success, state, error, ticket,
            ))
        })();
        let (success, state, error, ticket) = match evaluation {
            Ok(result) => result,
            Err(fatal) => {
                self.vm.with_coroutine_mut(object, |co| {
                    co.state = CoroutineState::Dead;
                    co.entry = Value::Nil;
                })?;
                if let Some(parent) = self.active_coroutine {
                    self.vm
                        .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
                }
                self.vm.remove_root(root)?;
                return Err(fatal);
            }
        };
        self.vm.with_coroutine_mut(object, |co| {
            co.state = state;
            co.error = error;
            co.native_yielded = state == CoroutineState::Suspended;
            if state == CoroutineState::Dead {
                co.entry = Value::Nil;
                co.native = None;
            }
        })?;
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
        }
        self.vm.remove_root(root)?;
        if wrapped && !success {
            let error = explicit_error(error.unwrap_or(Value::Nil), self.frame.pc);
            return Err(error);
        }
        if !wrapped {
            values.insert(0, Value::Boolean(success));
        }
        self.complete_builtin_values(destination, mode, tail_return, next, values, Some(ticket))
    }

    fn coroutine_builtin(
        &mut self,
        builtin: Builtin,
        destination: Register,
        args: &[Value],
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        match builtin {
            Builtin::CoroutineCreate => {
                let entry = args.first().copied().unwrap_or(Value::Nil);
                let Value::Object(function) = entry else {
                    return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
                };
                if !matches!(
                    self.vm.object_kind(function)?,
                    ObjectKind::Closure | ObjectKind::Builtin
                ) {
                    return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
                }
                let coroutine = self.vm.allocate_coroutine(entry)?;
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    1,
                    FailPoint::ReturnReserve,
                )?;
                values.push(Value::Object(coroutine));
                self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    Some(ticket),
                )
            }
            Builtin::CoroutineStatus => {
                let Value::Object(object) = args.first().copied().unwrap_or(Value::Nil) else {
                    return Err(VmError::WrongObjectType.into());
                };
                let state = self.vm.coroutine_state(object)?;
                let bytes = match state {
                    CoroutineState::Suspended => b"suspended".as_slice(),
                    CoroutineState::Running => b"running".as_slice(),
                    CoroutineState::Normal => b"normal".as_slice(),
                    CoroutineState::Dead => b"dead".as_slice(),
                };
                let value = self.coroutine_message(bytes)?;
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    1,
                    FailPoint::ReturnReserve,
                )?;
                values.push(value);
                self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    Some(ticket),
                )
            }
            Builtin::CoroutineResume => {
                self.start_coroutine_resume(destination, args, mode, tail_return, next, false)
            }
            Builtin::CoroutineClose => {
                let Value::Object(object) = args.first().copied().unwrap_or(Value::Nil) else {
                    return Err(VmError::WrongObjectType.into());
                };
                self.start_coroutine_close(object, destination, mode, tail_return, next, false)
            }
            Builtin::CoroutineWrap => {
                let entry = args.first().copied().unwrap_or(Value::Nil);
                let Value::Object(function) = entry else {
                    return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
                };
                if !matches!(
                    self.vm.object_kind(function)?,
                    ObjectKind::Closure | ObjectKind::Builtin
                ) {
                    return Err(RuntimeError::new(RuntimeErrorKind::NotCallable));
                }
                let coroutine = self.vm.allocate_coroutine(entry)?;
                let coroutine_root = root_coroutine(self.vm, coroutine)?;
                let wrapped = self.vm.allocate_coroutine_wrapper(coroutine);
                self.vm.remove_root(coroutine_root)?;
                let wrapped = wrapped?;
                let wrapped_root = self.vm.add_root(RootKind::Temporary, wrapped)?;
                let mut values = Vec::new();
                let result = (|| {
                    let ticket = reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut values,
                        1,
                        FailPoint::ReturnReserve,
                    )?;
                    values.push(Value::Object(wrapped));
                    self.complete_builtin_values(
                        destination,
                        mode,
                        tail_return,
                        next,
                        values,
                        Some(ticket),
                    )
                })();
                self.vm.remove_root(wrapped_root)?;
                result
            }
            Builtin::CoroutineWrapped(object) => {
                self.start_wrapped_coroutine(object, args, destination, mode, tail_return, next)
            }
            Builtin::CoroutineYield => {
                if self.active_coroutine.is_none() {
                    return Err(RuntimeError::new(RuntimeErrorKind::CoroutineYield));
                }
                self.yield_site = Some(YieldSite {
                    destination,
                    result_mode: mode,
                    resume_pc: next,
                    tail_return,
                });
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    args.len(),
                    FailPoint::ReturnReserve,
                )?;
                values.extend_from_slice(args);
                Ok(RegularCallAction::Completed(DispatchResult::Yielded(
                    values,
                    Some(ticket),
                )))
            }
            _ => Err(RuntimeError::new(RuntimeErrorKind::NotCallable)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start_wrapped_coroutine(
        &mut self,
        object: ObjectRef,
        args: &[Value],
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
    ) -> Result<RegularCallAction, RuntimeError> {
        let root = root_coroutine(self.vm, object)?;
        let mut resumed = Vec::new();
        let result = (|| {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut resumed,
                args.len().saturating_add(1),
                FailPoint::WorkReserve,
            )?;
            resumed.push(Value::Object(object));
            resumed.extend_from_slice(args);
            let action =
                self.start_coroutine_resume(destination, &resumed, mode, tail_return, next, true);
            drop(ticket);
            action
        })();
        self.vm.remove_root(root)?;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn start_coroutine_close(
        &mut self,
        object: ObjectRef,
        destination: Register,
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        wrap: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        let state = self.vm.coroutine_state(object)?;
        if matches!(state, CoroutineState::Running | CoroutineState::Normal)
            || self.active_coroutine == Some(object)
        {
            return Err(RuntimeError::new(RuntimeErrorKind::CoroutineClose));
        }
        let root = root_coroutine(self.vm, object)?;
        let original = self.vm.with_coroutine(object, |co| co.error)?;
        let prior = self.vm.with_coroutine_mut(object, |co| {
            co.context.take().or_else(|| co.unwind_context.take())
        })?;
        let Some(mut context) = prior else {
            self.vm.with_coroutine_mut(object, |co| {
                co.state = CoroutineState::Dead;
                co.entry = Value::Nil;
                co.native = None;
                co.native_bridge = None;
            })?;
            let mut values = Vec::new();
            let result = if wrap {
                Err(explicit_error(
                    original.unwrap_or(Value::Nil),
                    self.frame.pc,
                ))
            } else {
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    if original.is_some() { 2 } else { 1 },
                    FailPoint::ReturnReserve,
                )?;
                values.push(Value::Boolean(original.is_none()));
                if let Some(error) = original {
                    values.push(error);
                }
                self.complete_builtin_values(
                    destination,
                    mode,
                    tail_return,
                    next,
                    values,
                    Some(ticket),
                )
            };
            self.vm.remove_root(root)?;
            return result;
        };
        if let Err(error) = self.ensure_resume_capacity() {
            self.vm
                .with_coroutine_mut(object, |co| co.context = Some(context))?;
            self.vm.remove_root(root)?;
            return Err(error);
        }
        if let Err(error) = context.restore_roots(self.vm) {
            self.vm
                .with_coroutine_mut(object, |co| co.context = Some(context))?;
            self.vm.remove_root(root)?;
            return Err(error);
        }
        let parent = self.swap_thread(context);
        self.resume_stack.push(ResumeCaller {
            context: parent,
            owner: self.active_coroutine,
            owner_root: self.active_coroutine_root.take(),
            child: object,
            child_root: root,
            destination,
            result_mode: mode,
            resume_pc: next,
            tail_return,
            wrapped: false,
            native_body: None,
            native: None,
            outer_resumes: ResumeChain::new(self.vm.allocation_ledger()),
            handler_root: None,
        });
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.active_coroutine = Some(object);
        self.active_coroutine_root = None;
        self.vm.with_coroutine_mut(object, |co| {
            co.state = CoroutineState::Running;
            co.native = None;
            co.native_bridge = None;
        })?;
        let mut error = explicit_error(original.unwrap_or(Value::Nil), self.frame.pc);
        self.prepare_close_error_value(&mut error)?;
        self.close_unwind = Some(CloseUnwind {
            error,
            caller_depth: 0,
            include_root: true,
            finish: CloseFinish::Coroutine { wrap },
            failed: original.is_some(),
            waiting_depth: None,
        });
        Ok(RegularCallAction::Entered)
    }

    fn complete_close_coroutine(
        &mut self,
        unwind: CloseUnwind,
        wrap: bool,
    ) -> Result<DispatchResult, RuntimeError> {
        let caller = self
            .resume_stack
            .pop()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let mut child = self.swap_thread(caller.context);
        child.finish(self.vm)?;
        let extra = self
            .vm
            .with_coroutine_mut(caller.child, |co| co.unwind_context.take())?;
        let has_extra = extra.is_some();
        self.vm.with_coroutine_mut(caller.child, |co| {
            co.state = CoroutineState::Dead;
            co.context = extra;
            co.entry = Value::Nil;
            co.native = None;
            co.native_bridge = None;
            co.error = unwind.failed.then_some(unwind.error.value);
        })?;
        self.active_coroutine = caller.owner;
        self.active_coroutine_root = caller.owner_root;
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
        }
        if has_extra {
            let next = self.start_coroutine_close(
                caller.child,
                caller.destination,
                caller.result_mode,
                caller.tail_return,
                caller.resume_pc,
                wrap,
            );
            self.vm.remove_root(caller.child_root)?;
            return match next? {
                RegularCallAction::Entered => {
                    if let Some(continuation) = caller.native_body {
                        self.resume_stack
                            .last_mut()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                            .native_body = Some(continuation);
                    }
                    Ok(DispatchResult::Continue)
                }
                RegularCallAction::Aborted => Ok(DispatchResult::Aborted),
                RegularCallAction::Completed(result) => Ok(result),
            };
        }
        let result = (|| -> Result<DispatchResult, RuntimeError> {
            if let Some(continuation) = caller.native_body {
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    if !wrap && unwind.failed { 2 } else { 1 },
                    FailPoint::ReturnReserve,
                )?;
                if !wrap {
                    values.push(Value::Boolean(!unwind.failed));
                }
                if unwind.failed {
                    values.push(unwind.error.value);
                }
                let result = self.finish_native_builtin_body(
                    continuation,
                    !wrap,
                    values,
                    continuation.destination,
                    continuation.result_mode,
                    continuation.tail_return,
                    continuation.resume_pc,
                );
                drop(ticket);
                return result;
            }
            if wrap {
                let mut error = unwind.error;
                self.prepare_close_error_value(&mut error)?;
                return Err(error);
            }
            let mut values = Vec::new();
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                if unwind.failed { 2 } else { 1 },
                FailPoint::ReturnReserve,
            )?;
            values.push(Value::Boolean(!unwind.failed));
            if unwind.failed {
                values.push(unwind.error.value);
            }
            if caller.tail_return {
                self.propagate_tail_result(values, Some(ticket))
            } else {
                self.write_call_values(
                    caller.destination,
                    caller.result_mode,
                    caller.resume_pc,
                    &values,
                )?;
                drop(ticket);
                Ok(DispatchResult::Continue)
            }
        })();
        self.vm.remove_root(caller.child_root)?;
        result
    }

    fn start_coroutine_resume(
        &mut self,
        destination: Register,
        args: &[Value],
        mode: ResultMode,
        tail_return: bool,
        next: usize,
        wrapped: bool,
    ) -> Result<RegularCallAction, RuntimeError> {
        let Value::Object(object) = args.first().copied().unwrap_or(Value::Nil) else {
            return Err(VmError::WrongObjectType.into());
        };
        let state = self.vm.coroutine_state(object)?;
        if state != CoroutineState::Suspended {
            let message = if state == CoroutineState::Dead {
                b"cannot resume dead coroutine".as_slice()
            } else {
                b"cannot resume non-suspended coroutine".as_slice()
            };
            if wrapped {
                let value = self.coroutine_message(message)?;
                return Err(explicit_error(value, self.frame.pc));
            }
            let mut values = Vec::new();
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut values,
                2,
                FailPoint::ReturnReserve,
            )?;
            values.push(Value::Boolean(false));
            values.push(self.coroutine_message(message)?);
            return self.complete_builtin_values(
                destination,
                mode,
                tail_return,
                next,
                values,
                Some(ticket),
            );
        }
        let mut resume_values = Vec::new();
        let resume_ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut resume_values,
            args.len().saturating_sub(1),
            FailPoint::WorkReserve,
        )?;
        resume_values.extend_from_slice(args.get(1..).unwrap_or(&[]));
        let bytes = core::mem::size_of::<ResumeCaller>();
        if self.resume_stack.len() == self.resume_stack.capacity() {
            let ticket = reserve_vec(
                self.vm.allocation_ledger(),
                &mut self.resume_stack,
                1,
                FailPoint::WorkReserve,
            )?;
            ticket.commit()?;
            self.resume_charge = self
                .resume_charge
                .checked_add(bytes)
                .ok_or(VmError::ArithmeticOverflow)?;
        }
        let child_root = root_coroutine(self.vm, object)?;
        let prior = self.vm.take_coroutine_context(object)?;
        if prior.is_none() {
            let (entry, already_yielded) = self
                .vm
                .with_coroutine(object, |co| (co.entry, co.native_yielded))?;
            if let Value::Object(callable) = entry {
                if self.vm.object_kind(callable)? == ObjectKind::Builtin {
                    self.vm.remove_root(child_root)?;
                    return self.run_native_coroutine(
                        object,
                        self.vm.builtin(callable)?,
                        already_yielded,
                        args,
                        destination,
                        mode,
                        tail_return,
                        next,
                        wrapped,
                    );
                }
            }
        }
        let mut tail_resume = false;
        let mut inline_resume = false;
        let mut context = if let Some(mut context) = prior {
            if let Err(error) = context.restore_roots(self.vm) {
                self.vm
                    .with_coroutine_mut(object, |co| co.context = Some(context))?;
                self.vm.remove_root(child_root)?;
                return Err(error);
            }
            let site = context
                .yield_site
                .take()
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
            let input = resume_values.as_slice();
            tail_resume = site.tail_return;
            inline_resume = context.protected.last().is_some_and(|boundary| {
                boundary.inline_target
                    && match boundary.stage {
                        ProtectedStage::Body => boundary.caller_depth == context.callers.len(),
                        ProtectedStage::Handler => {
                            boundary.handler_depth == Some(context.callers.len())
                        }
                    }
            });
            let write = (|| {
                if site.tail_return || inline_resume {
                    return Ok::<(), RuntimeError>(());
                }
                let first = context.frame.index(site.destination)?;
                let count = match site.result_mode {
                    ResultMode::Fixed(count) => usize::from(count),
                    ResultMode::All => input.len(),
                };
                let end = first
                    .checked_add(count)
                    .filter(|end| *end <= context.frame.max_register_limit)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                if matches!(site.result_mode, ResultMode::All) {
                    context.frame.grow_for_open_results(end)?;
                }
                for offset in 0..count {
                    context.frame.write(
                        self.vm,
                        Register(u16::try_from(first + offset).map_err(|_| {
                            RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds)
                        })?),
                        input.get(offset).copied().unwrap_or(Value::Nil),
                    )?;
                }
                context.frame.dynamic_top = end;
                context.frame.pc = site.resume_pc;
                Ok::<(), RuntimeError>(())
            })();
            if let Err(error) = write {
                context.park_roots(self.vm)?;
                self.vm.with_coroutine_mut(object, |co| {
                    co.state = CoroutineState::Dead;
                    co.context = Some(context);
                })?;
                self.vm.remove_root(child_root)?;
                return Err(error);
            }
            context
        } else {
            let entry = self.vm.with_coroutine(object, |co| co.entry)?;
            let frame = match self.new_coroutine_frame(entry, &resume_values) {
                Ok(frame) => frame,
                Err(error) => {
                    self.vm.remove_root(child_root)?;
                    return Err(error);
                }
            };
            ThreadContext::new(frame, self.vm.allocation_ledger())
        };
        let resumed_native = self.vm.with_coroutine(object, |co| co.native)?;
        let handler_root_result = match resumed_native {
            Some(
                NativeCompletion::XPCallBody {
                    handler: Value::Object(handler),
                    ..
                }
                | NativeCompletion::XPCallHandler {
                    handler: Value::Object(handler),
                    ..
                },
            ) => self.vm.add_root(RootKind::Temporary, handler).map(Some),
            _ => Ok(None),
        };
        let handler_root = match handler_root_result {
            Ok(root) => root,
            Err(error) => {
                context.park_roots(self.vm)?;
                self.vm
                    .with_coroutine_mut(object, |co| co.context = Some(context))?;
                self.vm.remove_root(child_root)?;
                return Err(error.into());
            }
        };
        let parent = self.swap_thread(context);
        self.resume_stack.push(ResumeCaller {
            context: parent,
            owner: self.active_coroutine,
            owner_root: self.active_coroutine_root.take(),
            child: object,
            child_root,
            destination,
            result_mode: mode,
            resume_pc: next,
            tail_return,
            wrapped,
            native_body: None,
            native: resumed_native,
            outer_resumes: ResumeChain::new(self.vm.allocation_ledger()),
            handler_root,
        });
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Normal)?;
        }
        self.active_coroutine = Some(object);
        self.active_coroutine_root = None;
        self.vm.with_coroutine_mut(object, |co| {
            co.state = CoroutineState::Running;
            co.entry = Value::Nil;
        })?;
        if tail_resume || inline_resume {
            return Ok(RegularCallAction::Completed(
                self.propagate_tail_result(resume_values, Some(resume_ticket))?,
            ));
        }
        drop(resume_ticket);
        Ok(RegularCallAction::Entered)
    }

    fn write_call_values(
        &mut self,
        destination: Register,
        mode: ResultMode,
        next: usize,
        values: &[Value],
    ) -> Result<(), RuntimeError> {
        let first = self.frame.index(destination)?;
        let count = match mode {
            ResultMode::Fixed(count) => usize::from(count),
            ResultMode::All => values.len(),
        };
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.frame.max_register_limit)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        if matches!(mode, ResultMode::All) {
            self.frame.grow_for_open_results(end)?;
        }
        for offset in 0..count {
            self.frame.write(
                self.vm,
                Register(
                    u16::try_from(first + offset)
                        .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
                ),
                values.get(offset).copied().unwrap_or(Value::Nil),
            )?;
        }
        self.frame.dynamic_top = end;
        self.frame.pc = next;
        Ok(())
    }

    fn complete_coroutine(
        &mut self,
        mut values: Vec<Value>,
        ticket: Option<Reservation>,
        exit: CoroutineExit,
    ) -> Result<DispatchResult, RuntimeError> {
        let caller = self
            .resume_stack
            .pop()
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        let resumed_native = match caller.native {
            Some(resume @ NativeCompletion::Resume { .. }) => Some(resume),
            _ => None,
        };
        let bridge_yield = matches!(exit, CoroutineExit::Yield)
            && resumed_native.is_none()
            && !caller.outer_resumes.items.is_empty();
        let mut child_context = self.swap_thread(caller.context);
        match exit {
            CoroutineExit::Yield => {
                child_context.park_roots(self.vm)?;
                self.vm.with_coroutine_mut(caller.child, |co| {
                    co.state = CoroutineState::Suspended;
                    co.context = Some(child_context);
                    co.native = match caller.native {
                        Some(
                            native @ (NativeCompletion::PCall { .. }
                            | NativeCompletion::XPCallBody { .. }
                            | NativeCompletion::XPCallHandler { .. }),
                        ) => Some(native),
                        _ => None,
                    };
                })?;
            }
            CoroutineExit::Return => {
                child_context.finish(self.vm)?;
                self.vm.with_coroutine_mut(caller.child, |co| {
                    co.state = CoroutineState::Dead;
                    co.context = None;
                    co.entry = Value::Nil;
                    co.native = None;
                })?;
            }
            CoroutineExit::Error => {
                child_context.park_roots(self.vm)?;
                let error = values.first().copied().unwrap_or(Value::Nil);
                self.vm.with_coroutine_mut(caller.child, |co| {
                    co.state = CoroutineState::Dead;
                    co.error = Some(error);
                    co.context = Some(child_context);
                    co.native = None;
                })?;
            }
        }
        if let Some(root) = caller.handler_root {
            self.vm.remove_root(root)?;
        }
        self.active_coroutine = caller.owner;
        self.active_coroutine_root = caller.owner_root;
        let mut bridge_child = caller.child;
        for continuation in resumed_native
            .into_iter()
            .chain(caller.outer_resumes.items.iter().copied())
        {
            let NativeCompletion::Resume {
                outer,
                parent,
                parent_root,
                ..
            } = continuation
            else {
                return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
            };
            self.vm.with_coroutine_mut(outer, |co| {
                co.state = if bridge_yield {
                    CoroutineState::Suspended
                } else {
                    CoroutineState::Dead
                };
                co.native_bridge = bridge_yield.then_some(bridge_child);
                if !bridge_yield {
                    co.entry = Value::Nil;
                }
            })?;
            if let Some(root) = self.active_coroutine_root.take() {
                self.vm.remove_root(root)?;
            }
            self.active_coroutine = parent;
            self.active_coroutine_root = parent_root;
            bridge_child = outer;
        }
        if let Some(parent) = self.active_coroutine {
            self.vm
                .with_coroutine_mut(parent, |co| co.state = CoroutineState::Running)?;
        }
        if caller.wrapped && matches!(exit, CoroutineExit::Error) {
            let action = self.start_coroutine_close(
                caller.child,
                caller.destination,
                caller.result_mode,
                caller.tail_return,
                caller.resume_pc,
                true,
            );
            self.vm.remove_root(caller.child_root)?;
            if let Some(continuation) = caller.native_body {
                return match action {
                    Ok(RegularCallAction::Entered) => {
                        self.resume_stack
                            .last_mut()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                            .native_body = Some(continuation);
                        Ok(DispatchResult::Continue)
                    }
                    Err(error) if error.kind == RuntimeErrorKind::Thrown => {
                        let mut values = Vec::new();
                        let ticket = match reserve_vec(
                            self.vm.allocation_ledger(),
                            &mut values,
                            1,
                            FailPoint::ReturnReserve,
                        ) {
                            Ok(ticket) => ticket,
                            Err(fatal) => {
                                self.cleanup_native_builtin_failure(continuation)?;
                                return Err(fatal.into());
                            }
                        };
                        values.push(error.value);
                        let completed = self.finish_native_builtin_body(
                            continuation,
                            false,
                            values,
                            continuation.destination,
                            continuation.result_mode,
                            continuation.tail_return,
                            continuation.resume_pc,
                        );
                        drop(ticket);
                        completed
                    }
                    Err(error) => Err(error),
                    Ok(RegularCallAction::Aborted) => Ok(DispatchResult::Aborted),
                    Ok(RegularCallAction::Completed(action)) => Ok(action),
                };
            }
            return match action? {
                RegularCallAction::Entered => Ok(DispatchResult::Continue),
                RegularCallAction::Aborted => Ok(DispatchResult::Aborted),
                RegularCallAction::Completed(action) => Ok(action),
            };
        }
        self.vm.remove_root(caller.child_root)?;
        let native_status = match (exit, caller.native) {
            (CoroutineExit::Yield, Some(NativeCompletion::Resume { protected, .. })) => {
                let extra = match protected {
                    Some(NativeProtected::PCall { depth }) => usize::from(depth),
                    Some(NativeProtected::XPCall { .. }) => 1,
                    None => 0,
                };
                let growth = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    extra + 1,
                    FailPoint::ReturnReserve,
                )?;
                values.insert(0, Value::Boolean(true));
                for _ in 0..extra {
                    values.insert(0, Value::Boolean(true));
                }
                drop(growth);
                true
            }
            (CoroutineExit::Yield, _) => false,
            (_, Some(NativeCompletion::PCall { depth })) => {
                values.insert(0, Value::Boolean(!matches!(exit, CoroutineExit::Error)));
                for _ in 1..depth {
                    values.insert(0, Value::Boolean(true));
                }
                true
            }
            (_, Some(NativeCompletion::XPCallBody { .. })) => {
                values.insert(0, Value::Boolean(!matches!(exit, CoroutineExit::Error)));
                true
            }
            (_, Some(NativeCompletion::XPCallHandler { .. })) => {
                let value = values.first().copied().unwrap_or(Value::Nil);
                values.clear();
                values.push(Value::Boolean(false));
                values.push(value);
                true
            }
            (_, Some(NativeCompletion::Resume { protected, .. })) => {
                let extra = match protected {
                    Some(NativeProtected::PCall { depth }) => usize::from(depth),
                    Some(NativeProtected::XPCall { .. }) => 1,
                    None => 0,
                };
                let growth = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    extra + 1,
                    FailPoint::ReturnReserve,
                )?;
                values.insert(0, Value::Boolean(!matches!(exit, CoroutineExit::Error)));
                for _ in 0..extra {
                    values.insert(0, Value::Boolean(true));
                }
                drop(growth);
                true
            }
            (_, None) => false,
        };
        let mut result = Vec::new();
        let bridge_prefixes = if bridge_yield {
            0
        } else {
            caller.outer_resumes.items.len()
        };
        let result_ticket = reserve_vec(
            self.vm.allocation_ledger(),
            &mut result,
            values.len() + 1 + bridge_prefixes,
            FailPoint::ReturnReserve,
        )?;
        result.push(Value::Boolean(
            native_status || !matches!(exit, CoroutineExit::Error),
        ));
        result.extend_from_slice(&values);
        for _ in 0..bridge_prefixes {
            result.insert(0, Value::Boolean(true));
        }
        if caller.wrapped {
            result.remove(0);
        }
        drop(ticket);
        if let Some(continuation) = caller.native_body {
            let completed = self.finish_native_builtin_body(
                continuation,
                true,
                result,
                continuation.destination,
                continuation.result_mode,
                continuation.tail_return,
                continuation.resume_pc,
            );
            drop(result_ticket);
            return completed;
        }
        if self.inline_boundary_ready() {
            let outcome = self.propagate_tail_result(result, Some(result_ticket))?;
            return Ok(outcome);
        }
        if caller.tail_return {
            let returned = self.propagate_tail_result(result, Some(result_ticket))?;
            return Ok(returned);
        }
        self.write_call_values(
            caller.destination,
            caller.result_mode,
            caller.resume_pc,
            &result,
        )?;
        drop(result_ticket);
        Ok(DispatchResult::Continue)
    }

    fn settle_coroutine_dispatch(
        &mut self,
        mut action: DispatchResult,
    ) -> Result<DispatchResult, RuntimeError> {
        loop {
            action = match action {
                DispatchResult::Returned(values, ticket) if !self.resume_stack.is_empty() => {
                    self.complete_coroutine(values, ticket, CoroutineExit::Return)?
                }
                DispatchResult::Yielded(values, ticket) => {
                    self.complete_coroutine(values, ticket, CoroutineExit::Yield)?
                }
                other => return Ok(other),
            };
        }
    }

    fn handle_native_xpcall_error(
        &mut self,
        error: &RuntimeError,
    ) -> Result<Option<DispatchResult>, RuntimeError> {
        let stage = self.resume_stack.last().and_then(|caller| caller.native);
        let (handler, errors, from_body) = match stage {
            Some(NativeCompletion::XPCallBody { handler, errors }) => (handler, errors, true),
            Some(NativeCompletion::XPCallHandler { handler, errors }) => {
                (handler, errors.saturating_add(1), false)
            }
            _ => return Ok(None),
        };
        let callable = match handler {
            Value::Object(object) => self.vm.object_kind(object)?,
            _ => ObjectKind::Table,
        };
        if callable == ObjectKind::Builtin {
            let Value::Object(handler_object) = handler else {
                return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
            };
            if self.vm.builtin(handler_object)? == Builtin::Error {
                let mut current = error.value;
                for _ in errors..32 {
                    current = explicit_error(current, self.frame.pc).value;
                }
            }
        }
        if errors >= 32 || callable != ObjectKind::Closure {
            let message = self.vm.allocate_byte_string(b"error in error handling")?;
            let root = self.vm.add_root(RootKind::Temporary, message)?;
            if let Some(caller) = self.resume_stack.last_mut() {
                caller.native = None;
            }
            let completed =
                self.complete_coroutine(vec![Value::Object(message)], None, CoroutineExit::Error);
            self.vm.remove_root(root)?;
            return completed.map(Some);
        }
        let frame = self.new_coroutine_frame(handler, &[error.value])?;
        let context = ThreadContext::new(frame, self.vm.allocation_ledger());
        let mut failed = self.swap_thread(context);
        if from_body {
            failed.park_roots(self.vm)?;
            let child = self
                .active_coroutine
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
            self.vm
                .with_coroutine_mut(child, |co| co.unwind_context = Some(failed))?;
        } else {
            failed.finish(self.vm)?;
        }
        if let Some(caller) = self.resume_stack.last_mut() {
            caller.native = Some(NativeCompletion::XPCallHandler { handler, errors });
        }
        Ok(Some(DispatchResult::Continue))
    }

    pub fn set_fuel(&mut self, fuel: u64) -> Result<(), RuntimeError> {
        if self.state != ExecutionState::Ready {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        self.fuel = fuel;
        Ok(())
    }

    fn current_module(&self) -> Result<&VerifiedModule, RuntimeError> {
        match self.frame.module {
            Some(reference) => Ok(self.vm.module(reference)?),
            None => self
                .module
                .as_ref()
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint)),
        }
    }

    fn prototype(&self) -> &BytecodePrototype {
        &self
            .current_module()
            .expect("活躍 frame 的 module 必須存活")
            .module()
            .prototypes[self.frame.prototype]
    }

    fn next_pc(&self) -> Result<usize, RuntimeError> {
        self.frame
            .pc
            .checked_add(1)
            .filter(|index| *index < self.prototype().instructions.len())
            .ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))
    }

    fn jump_target(&self, target: rivetlua_core::InstructionOffset) -> Result<usize, RuntimeError> {
        let index = usize::try_from(target.0)
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::ProgramCounterOutOfBounds))?;
        if index >= self.prototype().instructions.len() {
            return Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ));
        }
        Ok(index)
    }

    /// 執行直到 Return、pending ClosePath、受控錯誤或 fuel 中止。
    /// PendingClose 保留 frame 與 roots；P11 接上 continuation 前不能再一般 run。
    pub fn run(&mut self) -> Result<RunOutcome, RuntimeError> {
        if self.state != ExecutionState::Ready {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        loop {
            if self.frame.pc >= self.prototype().instructions.len() {
                self.state = ExecutionState::Failed;
                self.finish()?;
                return Err(RuntimeError::new(
                    RuntimeErrorKind::ProgramCounterOutOfBounds,
                ));
            }
            if self.fuel == 0 {
                self.state = ExecutionState::Aborted;
                self.finish()?;
                return Ok(RunOutcome::Aborted(AbortReason::FuelExhausted));
            }
            self.fuel -= 1;
            let resume_close = self.close_unwind.is_some_and(|unwind| {
                unwind
                    .waiting_depth
                    .is_none_or(|depth| self.callers.len() < depth)
            });
            let dispatch = self
                .settle_ready_builtin_event()
                .and_then(|()| {
                    if resume_close {
                        self.advance_close_unwind()
                    } else {
                        self.dispatch_one()
                    }
                })
                .and_then(|action| self.settle_coroutine_dispatch(action));
            match dispatch {
                Ok(DispatchResult::Returned(values, ticket)) => {
                    self.state = ExecutionState::Returned;
                    self.finish()?;
                    // 結果 Vec 在此移交宿主持有；VM 僅檢查並暫留配置額度。
                    drop(ticket);
                    return Ok(RunOutcome::Returned(values));
                }
                Ok(DispatchResult::Continue) => {}
                Ok(DispatchResult::Yielded(_, _)) => {
                    self.state = ExecutionState::Failed;
                    self.finish()?;
                    return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                }
                Ok(DispatchResult::PendingClose(snapshot)) => {
                    self.state = ExecutionState::PendingClose;
                    return Ok(RunOutcome::PendingClose(snapshot));
                }
                Ok(DispatchResult::Aborted) => {
                    self.state = ExecutionState::Aborted;
                    self.finish()?;
                    return Ok(RunOutcome::Aborted(AbortReason::FuelExhausted));
                }
                Err(mut error) => {
                    let lua_error = error.kind.is_lua_error();
                    if lua_error {
                        error.source_pc.get_or_insert(self.frame.pc);
                        error.source_prototype.get_or_insert(self.frame.prototype);
                        error.source_depth.get_or_insert(self.frame.depth);
                        if let Some(mut unwind) = self.close_unwind.take() {
                            match self.prepare_close_error_value(&mut error) {
                                Ok(()) => {
                                    unwind.error = error;
                                    unwind.failed = true;
                                    unwind.waiting_depth = None;
                                    self.close_unwind = Some(unwind);
                                    continue;
                                }
                                Err(fatal) => {
                                    self.state = ExecutionState::Failed;
                                    self.finish()?;
                                    return Err(fatal);
                                }
                            }
                        }
                        match self.begin_close_unwind(error) {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(fatal) => {
                                self.state = ExecutionState::Failed;
                                self.finish()?;
                                return Err(fatal);
                            }
                        }
                        error = match self.handle_protected_error(error) {
                            Ok(ProtectedErrorResult::Uncaught(error)) => error,
                            Ok(ProtectedErrorResult::Caught(DispatchResult::Continue)) => continue,
                            Ok(ProtectedErrorResult::Caught(DispatchResult::Returned(
                                values,
                                ticket,
                            ))) => {
                                self.state = ExecutionState::Returned;
                                self.finish()?;
                                drop(ticket);
                                return Ok(RunOutcome::Returned(values));
                            }
                            Ok(ProtectedErrorResult::Caught(_)) => {
                                self.state = ExecutionState::Failed;
                                self.finish()?;
                                return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                            }
                            Err(fatal) => {
                                self.state = ExecutionState::Failed;
                                self.finish()?;
                                return Err(fatal);
                            }
                        };
                        if let Some(action) = match self.handle_native_xpcall_error(&error) {
                            Ok(action) => action,
                            Err(fatal) => {
                                self.state = ExecutionState::Failed;
                                self.finish()?;
                                return Err(fatal);
                            }
                        } {
                            match self.settle_coroutine_dispatch(action) {
                                Ok(DispatchResult::Continue) => continue,
                                Ok(DispatchResult::Returned(values, ticket)) => {
                                    self.state = ExecutionState::Returned;
                                    self.finish()?;
                                    drop(ticket);
                                    return Ok(RunOutcome::Returned(values));
                                }
                                Ok(_) => {
                                    self.state = ExecutionState::Failed;
                                    self.finish()?;
                                    return Err(RuntimeError::new(
                                        RuntimeErrorKind::MissingEntryPoint,
                                    ));
                                }
                                Err(fatal) => {
                                    self.state = ExecutionState::Failed;
                                    self.finish()?;
                                    return Err(fatal);
                                }
                            }
                        }
                        if !self.resume_stack.is_empty() {
                            let result = self
                                .complete_coroutine(vec![error.value], None, CoroutineExit::Error)
                                .and_then(|action| self.settle_coroutine_dispatch(action));
                            match result {
                                Ok(DispatchResult::Continue) => continue,
                                Ok(DispatchResult::Returned(values, ticket)) => {
                                    self.state = ExecutionState::Returned;
                                    self.finish()?;
                                    drop(ticket);
                                    return Ok(RunOutcome::Returned(values));
                                }
                                Ok(_) => {
                                    self.state = ExecutionState::Failed;
                                    self.finish()?;
                                    return Err(RuntimeError::new(
                                        RuntimeErrorKind::MissingEntryPoint,
                                    ));
                                }
                                Err(fatal) => {
                                    self.state = ExecutionState::Failed;
                                    self.finish()?;
                                    return Err(fatal);
                                }
                            }
                        }
                        let host_error = match crate::LuaError::from_runtime(
                            self.vm,
                            error,
                            self.frame.prototype,
                            self.frame.depth,
                            self.frame.pc,
                        ) {
                            Ok(error) => error,
                            Err(fatal) => {
                                self.state = ExecutionState::Failed;
                                self.finish()?;
                                return Err(fatal.into());
                            }
                        };
                        self.state = ExecutionState::LuaError;
                        self.finish()?;
                        return Ok(RunOutcome::LuaError(host_error));
                    }
                    self.state = ExecutionState::Failed;
                    self.finish()?;
                    return Err(error);
                }
            }
        }
    }

    fn prepare_close_error_value(&mut self, error: &mut RuntimeError) -> Result<(), RuntimeError> {
        if error.value == Value::Nil
            && !matches!(
                error.kind,
                RuntimeErrorKind::Thrown | RuntimeErrorKind::ErrorHandlerLoop
            )
        {
            error.value = Value::Object(
                self.vm
                    .allocate_byte_string(error.diagnostic_id.as_bytes())?,
            );
        }
        let replacement = if let Value::Object(object) = error.value {
            Some(self.vm.add_root(RootKind::Temporary, object)?)
        } else {
            None
        };
        if let Some(root) = core::mem::replace(&mut self.error_root, replacement) {
            self.vm.remove_root(root)?;
        }
        Ok(())
    }

    fn begin_close_unwind(&mut self, mut error: RuntimeError) -> Result<bool, RuntimeError> {
        let (caller_depth, include_root, finish) = if let Some(boundary) = self.protected.last() {
            (boundary.caller_depth, false, CloseFinish::Protected)
        } else if self.active_coroutine.is_some() {
            // coroutine body 的 LuaError 先停在 Dead，由顯式 close 收束。
            return Ok(false);
        } else {
            (0, true, CloseFinish::Host)
        };
        let has_entries = (self.callers.len() > caller_depth || include_root)
            && (!self.frame.close_entries.is_empty()
                || self
                    .callers
                    .iter()
                    .skip(caller_depth + usize::from(!include_root))
                    .any(|frame| !frame.close_entries.is_empty()));
        if !has_entries {
            return Ok(false);
        }
        self.prepare_close_error_value(&mut error)?;
        self.close_unwind = Some(CloseUnwind {
            error,
            caller_depth,
            include_root,
            finish,
            failed: true,
            waiting_depth: None,
        });
        Ok(true)
    }

    fn advance_close_unwind(&mut self) -> Result<DispatchResult, RuntimeError> {
        let mut unwind = self
            .close_unwind
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        unwind.waiting_depth = None;
        loop {
            if self.callers.len() < unwind.caller_depth
                || (self.callers.len() == unwind.caller_depth && !unwind.include_root)
            {
                break;
            }
            if let Some(entry) = self.frame.close_entries.last().copied() {
                let value = entry.value;
                if value == Value::Nil || value == Value::Boolean(false) {
                    self.frame.pop_close(self.vm)?;
                    continue;
                }
                let caller_depth = self.callers.len();
                let resume_depth = self.resume_stack.len();
                let invoked = (|| {
                    let event_value = self.lookup_value_event(value, MetamethodEvent::Close)?;
                    if event_value == Value::Nil {
                        return Err(RuntimeError::new(RuntimeErrorKind::MetamethodAbsent));
                    }
                    let Some((event, args, ticket, chain_steps)) =
                        self.resolve_callable_event(event_value, &[value, unwind.error.value])?
                    else {
                        return Ok(None);
                    };
                    let next = self.frame.pc.checked_add(1).ok_or(RuntimeError::new(
                        RuntimeErrorKind::ProgramCounterOutOfBounds,
                    ))?;
                    let result = self.invoke_event(
                        PendingKind::Close,
                        [
                            value,
                            unwind.error.value,
                            event_value,
                            Value::Nil,
                            Value::Object(event),
                        ],
                        event,
                        &args,
                        entry.register,
                        ResultMode::Fixed(0),
                        next,
                        chain_steps + 1,
                        false,
                    );
                    drop(ticket);
                    result.map(Some)
                })();
                match invoked {
                    Ok(Some(RegularCallAction::Entered)) if self.callers.len() > caller_depth => {
                        self.callers
                            .last_mut()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                            .pop_close(self.vm)?;
                        unwind.waiting_depth = Some(self.callers.len());
                        self.close_unwind = Some(unwind);
                        return Ok(DispatchResult::Continue);
                    }
                    Ok(Some(RegularCallAction::Entered))
                        if self.resume_stack.len() > resume_depth =>
                    {
                        self.resume_stack
                            .last_mut()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                            .context
                            .frame
                            .pop_close(self.vm)?;
                        return Ok(DispatchResult::Continue);
                    }
                    Ok(Some(RegularCallAction::Entered)) => {
                        self.frame.pop_close(self.vm)?;
                        unwind.waiting_depth = Some(self.callers.len());
                        self.close_unwind = Some(unwind);
                        return Ok(DispatchResult::Continue);
                    }
                    Ok(Some(RegularCallAction::Completed(result))) => {
                        self.frame.pop_close(self.vm)?;
                        if !matches!(result, DispatchResult::Continue) {
                            return Ok(result);
                        }
                        continue;
                    }
                    Ok(Some(RegularCallAction::Aborted)) | Ok(None) => {
                        return Ok(DispatchResult::Aborted);
                    }
                    Err(error) => {
                        self.frame.pop_close(self.vm)?;
                        return Err(error);
                    }
                }
            }
            if self.callers.len() == unwind.caller_depth {
                break;
            }
            self.unwind_to_protected(self.callers.len() - 1)?;
        }
        self.close_unwind = None;
        match unwind.finish {
            CloseFinish::Protected => match self.handle_protected_error(unwind.error)? {
                ProtectedErrorResult::Caught(action) => Ok(action),
                ProtectedErrorResult::Uncaught(error) => Err(error),
            },
            CloseFinish::Host => Err(unwind.error),
            CloseFinish::Coroutine { wrap } => self.complete_close_coroutine(unwind, wrap),
        }
    }

    fn unwind_to_protected(&mut self, caller_depth: usize) -> Result<(), RuntimeError> {
        if self.callers.len() < caller_depth {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        }
        while self
            .pending_ops
            .last()
            .is_some_and(|pending| pending.caller_depth >= caller_depth.saturating_add(1))
        {
            let mut pending = self
                .pending_ops
                .pop()
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
            pending.clear(self.vm)?;
        }
        self.pending_ops.release_empty()?;
        while self.callers.len() > caller_depth {
            let caller = self
                .callers
                .pop()
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
            let mut finished = core::mem::replace(&mut self.frame, caller);
            finished.close_open(self.vm)?;
            finished.clear_roots(self.vm)?;
            finished.release_storage();
        }
        Ok(())
    }

    fn write_protected_values(
        &mut self,
        boundary: &ProtectedBoundary,
        values: &[Value],
    ) -> Result<(), RuntimeError> {
        let first = self.frame.index(boundary.destination)?;
        let count = match boundary.result_mode {
            ResultMode::Fixed(count) => usize::from(count),
            ResultMode::All => values.len(),
        };
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.frame.max_register_limit)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        if matches!(boundary.result_mode, ResultMode::All) {
            self.frame.grow_for_open_results(end)?;
        }
        for offset in 0..count {
            let value = values.get(offset).copied().unwrap_or(Value::Nil);
            self.frame.write(
                self.vm,
                Register(
                    u16::try_from(first + offset)
                        .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
                ),
                value,
            )?;
        }
        self.frame.dynamic_top = end;
        self.frame.pc = boundary.resume_pc;
        Ok(())
    }

    fn mark_protected_result(
        &mut self,
        boundary: &ProtectedBoundary,
        result: &mut Vec<Value>,
    ) -> Result<(), RuntimeError> {
        let needed = match boundary.stage {
            ProtectedStage::Body => 1,
            ProtectedStage::Handler => 2usize.saturating_sub(result.len()),
        };
        let ticket = if needed > 0 {
            Some(reserve_vec(
                self.vm.allocation_ledger(),
                result,
                needed,
                FailPoint::ReturnReserve,
            )?)
        } else {
            None
        };
        match boundary.stage {
            ProtectedStage::Body => result.insert(0, Value::Boolean(true)),
            ProtectedStage::Handler => {
                let value = result.first().copied().unwrap_or(Value::Nil);
                result.clear();
                result.push(Value::Boolean(false));
                result.push(value);
            }
        }
        drop(ticket);
        Ok(())
    }

    fn inline_boundary_ready(&self) -> bool {
        self.protected.last().is_some_and(|boundary| {
            boundary.inline_target
                && match boundary.stage {
                    ProtectedStage::Body => boundary.caller_depth == self.callers.len(),
                    ProtectedStage::Handler => boundary.handler_depth == Some(self.callers.len()),
                }
        })
    }

    fn propagate_tail_result(
        &mut self,
        mut result: Vec<Value>,
        ticket: Option<Reservation>,
    ) -> Result<DispatchResult, RuntimeError> {
        loop {
            let nested_protected = self.inline_boundary_ready()
                || self.protected.last().is_some_and(|boundary| {
                    let depth = match boundary.stage {
                        ProtectedStage::Body => Some(boundary.caller_depth),
                        ProtectedStage::Handler => boundary.handler_depth,
                    };
                    !boundary.inline_target
                        && depth.and_then(|depth| depth.checked_add(1)) == Some(self.callers.len())
                });
            if nested_protected {
                let mut boundary = self
                    .protected
                    .pop()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                let marked = self.mark_protected_result(&boundary, &mut result);
                marked?;
                let tail = boundary.tail_return;
                let completed = if boundary.stage == ProtectedStage::Handler {
                    let root = if let Some(Value::Object(object)) = result.get(1).copied() {
                        Some(self.vm.add_root(RootKind::Temporary, object)?)
                    } else {
                        None
                    };
                    let written = self
                        .unwind_to_protected(boundary.caller_depth)
                        .and_then(|()| self.write_protected_values(&boundary, &result));
                    if let Some(root) = root {
                        self.vm.remove_root(root)?;
                    }
                    written
                } else {
                    if boundary.inline_target {
                        self.write_protected_values(&boundary, &result)
                    } else {
                        self.return_to_caller(&result)
                    }
                };
                boundary.clear(self.vm)?;
                completed?;
                if !tail && !self.inline_boundary_ready() {
                    drop(ticket);
                    return Ok(DispatchResult::Continue);
                }
                continue;
            }
            if self.callers.is_empty() {
                return Ok(DispatchResult::Returned(result, ticket));
            }
            self.return_to_caller(&result)?;
            if !self.frame.tail_return {
                drop(ticket);
                return Ok(DispatchResult::Continue);
            }
        }
    }

    /// 只接收 Lua 層錯誤；暫存 root 在 unwind、handler 呼叫或宿主接收前存活。
    fn handle_protected_error(
        &mut self,
        mut error: RuntimeError,
    ) -> Result<ProtectedErrorResult, RuntimeError> {
        loop {
            if error.value == Value::Nil
                && !matches!(
                    error.kind,
                    RuntimeErrorKind::Thrown | RuntimeErrorKind::ErrorHandlerLoop
                )
            {
                error.value = Value::Object(
                    self.vm
                        .allocate_byte_string(error.diagnostic_id.as_bytes())?,
                );
            }
            if let Value::Object(object) = error.value {
                if self.error_root.is_none() {
                    self.error_root = Some(self.vm.add_root(RootKind::Temporary, object)?);
                }
            }
            if self.protected.is_empty() {
                return Ok(ProtectedErrorResult::Uncaught(error));
            }
            let index = self.protected.len() - 1;
            let caller_depth = self.protected[index].caller_depth;
            let boundary = &self.protected[index];
            let caller = if self.callers.len() == caller_depth {
                &self.frame
            } else {
                self.callers
                    .get(caller_depth)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
            };
            if (caller.pc != boundary.caller_pc && caller.pc != boundary.resume_pc)
                || caller.pending_close != boundary.close_scope
            {
                return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
            }
            let stage = self.protected[index].stage;
            let handler = self.protected[index].handler;
            if let Some(handler) = handler {
                if stage == ProtectedStage::Handler {
                    self.protected[index].handler_errors =
                        self.protected[index].handler_errors.saturating_add(1);
                    if self.protected[index].handler_errors >= 32 {
                        let message = self.vm.allocate_byte_string(b"error in error handling")?;
                        let message_root = self.vm.add_root(RootKind::Temporary, message)?;
                        if let Some(root) = self.error_root.replace(message_root) {
                            self.vm.remove_root(root)?;
                        }
                        self.unwind_to_protected(caller_depth)?;
                        let mut boundary = self
                            .protected
                            .pop()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                        boundary.clear(self.vm)?;
                        let mut loop_error = RuntimeError::new(RuntimeErrorKind::ErrorHandlerLoop);
                        loop_error.value = Value::Object(message);
                        loop_error.source_pc = error.source_pc;
                        loop_error.source_prototype = error.source_prototype;
                        loop_error.source_depth = error.source_depth;
                        error = loop_error;
                        continue;
                    }
                }
                self.protected[index].stage = ProtectedStage::Handler;
                self.protected[index].handler_depth = Some(self.callers.len());
                let destination = if self.callers.len() == caller_depth {
                    self.protected[index].destination
                } else {
                    Register(0)
                };
                let next = self.frame.pc;
                let invoked = self.enter_callable_values(
                    handler,
                    &[error.value],
                    destination,
                    ResultMode::Fixed(1),
                    next,
                );
                if let Some(root) = self.error_root.take() {
                    self.vm.remove_root(root)?;
                }
                match invoked {
                    Ok(RegularCallAction::Entered) => {
                        return Ok(ProtectedErrorResult::Caught(DispatchResult::Continue));
                    }
                    Ok(RegularCallAction::Aborted) => {
                        self.fuel = 0;
                        return Ok(ProtectedErrorResult::Caught(DispatchResult::Continue));
                    }
                    Ok(RegularCallAction::Completed(DispatchResult::Continue)) => {
                        let value = self.frame.read(destination)?;
                        let result = self.propagate_tail_result(vec![value], None)?;
                        return Ok(ProtectedErrorResult::Caught(result));
                    }
                    Ok(RegularCallAction::Completed(result)) => {
                        return Ok(ProtectedErrorResult::Caught(result));
                    }
                    Err(next_error) => {
                        if matches!(
                            next_error.kind,
                            RuntimeErrorKind::Heap(
                                VmError::AllocationFailed | VmError::InjectedFailure(_)
                            )
                        ) {
                            return Err(next_error);
                        }
                        error = next_error;
                        error.source_pc.get_or_insert(self.frame.pc);
                        error.source_prototype.get_or_insert(self.frame.prototype);
                        error.source_depth.get_or_insert(self.frame.depth);
                        continue;
                    }
                }
            }
            self.unwind_to_protected(caller_depth)?;
            let mut boundary = self
                .protected
                .pop()
                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
            let written =
                self.write_protected_values(&boundary, &[Value::Boolean(false), error.value]);
            boundary.clear(self.vm)?;
            if let Some(root) = self.error_root.take() {
                self.vm.remove_root(root)?;
            }
            written?;
            if boundary.tail_return || self.inline_boundary_ready() {
                let mut values = Vec::new();
                let ticket = reserve_vec(
                    self.vm.allocation_ledger(),
                    &mut values,
                    2,
                    FailPoint::ReturnReserve,
                )?;
                values.extend_from_slice(&[Value::Boolean(false), error.value]);
                let result = self.propagate_tail_result(values, Some(ticket))?;
                return Ok(ProtectedErrorResult::Caught(result));
            }
            return Ok(ProtectedErrorResult::Caught(DispatchResult::Continue));
        }
    }

    fn finish(&mut self) -> Result<(), RuntimeError> {
        self.close_unwind = None;
        self.yield_site = None;
        if let Some(root) = self.error_root.take() {
            self.vm.remove_root(root)?;
        }
        while let Some(mut boundary) = self.protected.pop() {
            boundary.clear(self.vm)?;
        }
        if self.protected_charge != 0 {
            self.protected = Vec::new();
            self.vm.allocation_ledger().refund(self.protected_charge)?;
            self.protected_charge = 0;
        }
        self.pending_ops.clear(self.vm)?;
        self.frame.close_open(self.vm)?;
        self.frame.clear_roots(self.vm)?;
        self.frame.release_storage();
        for caller in &mut self.callers {
            caller.close_open(self.vm)?;
            caller.clear_roots(self.vm)?;
            caller.release_storage();
        }
        self.callers = Vec::new();
        if self.callers_charge != 0 {
            self.vm.allocation_ledger().refund(self.callers_charge)?;
            self.callers_charge = 0;
        }
        if let Some(active) = self.active_coroutine.take() {
            self.vm
                .with_coroutine_mut(active, |co| co.state = CoroutineState::Dead)?;
        }
        if let Some(root) = self.active_coroutine_root.take() {
            self.vm.remove_root(root)?;
        }
        while let Some(mut caller) = self.resume_stack.pop() {
            caller.context.finish(self.vm)?;
            self.vm
                .with_coroutine_mut(caller.child, |co| co.state = CoroutineState::Dead)?;
            for continuation in caller
                .outer_resumes
                .items
                .iter()
                .copied()
                .chain(caller.native)
            {
                let NativeCompletion::Resume {
                    outer, parent_root, ..
                } = continuation
                else {
                    continue;
                };
                self.vm.with_coroutine_mut(outer, |co| {
                    co.state = CoroutineState::Dead;
                    co.native_bridge = None;
                })?;
                if let Some(root) = parent_root {
                    self.vm.remove_root(root)?;
                }
            }
            if let Some(root) = caller.handler_root {
                self.vm.remove_root(root)?;
            }
            if let Some(native_body) = caller.native_body {
                if let Some(root) = native_body.parent_root {
                    self.vm.remove_root(root)?;
                }
            }
            self.vm.remove_root(caller.child_root)?;
            if let Some(root) = caller.owner_root {
                self.vm.remove_root(root)?;
            }
        }
        if self.resume_charge != 0 {
            self.vm.allocation_ledger().refund(self.resume_charge)?;
            self.resume_charge = 0;
        }
        if let Some(root) = self.module_root.take() {
            self.vm.remove_root(root)?;
        }
        Ok(())
    }

    fn dispatch_one(&mut self) -> Result<DispatchResult, RuntimeError> {
        let instruction = self.prototype().instructions[self.frame.pc]
            .instruction
            .clone();
        match instruction {
            Instruction::LoadConst { dest, constant } => {
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let mut string_bytes = Vec::new();
                let mut string_ticket = None;
                let value = match self.current_module()?.module().prototypes[self.frame.prototype]
                    .constants
                    .get(constant.0 as usize)
                {
                    Some(BytecodeConstant::Integer(value)) => Value::Integer(*value),
                    Some(BytecodeConstant::FloatBits(bits)) => Value::Float(f64::from_bits(*bits)),
                    Some(BytecodeConstant::Boolean(value)) => Value::Boolean(*value),
                    Some(BytecodeConstant::Name(bytes) | BytecodeConstant::String(bytes)) => {
                        let ticket = reserve_vec(
                            self.vm.allocation_ledger(),
                            &mut string_bytes,
                            bytes.len(),
                            FailPoint::StringBytesReserve,
                        )?;
                        string_bytes.extend_from_slice(bytes);
                        string_ticket = Some(ticket);
                        Value::Nil
                    }
                    _ => return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedConstant)),
                };
                let value = if string_ticket.is_some() {
                    Value::Object(self.vm.allocate_byte_string(&string_bytes)?)
                } else {
                    value
                };
                drop(string_ticket);
                if let Err(error) = self.frame.write(self.vm, dest, value) {
                    if let Value::Object(object) = value {
                        self.vm.reclaim(object)?;
                    }
                    return Err(error);
                }
                self.frame.pc = next;
            }
            Instruction::NewTable { dest } => {
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let table = self.vm.allocate_table()?;
                if let Err(error) = self.frame.write(self.vm, dest, Value::Object(table)) {
                    self.vm.reclaim(table)?;
                    return Err(error);
                }
                self.frame.pc = next;
            }
            Instruction::GetTable { dest, table, key } => {
                let table = self.frame.read(table)?;
                let key = self.frame.read(key)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                match self.regular_table_access(table, key, None)? {
                    RegularTableAction::Read(value) => {
                        self.frame.write(self.vm, dest, value)?;
                        self.frame.pc = next;
                    }
                    RegularTableAction::Invoke {
                        current,
                        event,
                        chain_steps,
                    } => match self.invoke_table_event(
                        PendingTableKind::Get,
                        table,
                        current,
                        key,
                        Value::Nil,
                        event,
                        dest,
                        next,
                        chain_steps,
                    )? {
                        RegularCallAction::Entered => {}
                        RegularCallAction::Aborted => return Ok(DispatchResult::Aborted),
                        RegularCallAction::Completed(result) => return Ok(result),
                    },
                    RegularTableAction::Aborted => return Ok(DispatchResult::Aborted),
                    RegularTableAction::Wrote => {
                        return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                    }
                }
            }
            Instruction::SetTable { table, key, value } => {
                let target = self.frame.read(table)?;
                let key = self.frame.read(key)?;
                let value = self.frame.read(value)?;
                let next = self.next_pc()?;
                match self.regular_table_access(target, key, Some(value))? {
                    RegularTableAction::Wrote => self.frame.pc = next,
                    RegularTableAction::Invoke {
                        current,
                        event,
                        chain_steps,
                    } => match self.invoke_table_event(
                        PendingTableKind::Set,
                        target,
                        current,
                        key,
                        value,
                        event,
                        table,
                        next,
                        chain_steps,
                    )? {
                        RegularCallAction::Entered => {}
                        RegularCallAction::Aborted => return Ok(DispatchResult::Aborted),
                        RegularCallAction::Completed(result) => return Ok(result),
                    },
                    RegularTableAction::Aborted => return Ok(DispatchResult::Aborted),
                    RegularTableAction::Read(_) => {
                        return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                    }
                }
            }
            Instruction::LoadNil { start, count } => {
                let first = self.frame.index(start)?;
                let end = first
                    .checked_add(usize::from(count))
                    .filter(|end| *end <= self.frame.register_limit)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                let next = self.next_pc()?;
                for index in first..end {
                    self.frame
                        .write(self.vm, Register(index as u16), Value::Nil)?;
                }
                self.frame.pc = next;
            }
            Instruction::Move { dest, src } => {
                let value = self.frame.read(src)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let close_binding = self.prototype().instructions[self.frame.pc]
                    .close_path
                    .as_ref()
                    .map(|marker| marker.bindings[0]);
                if let Some(binding) = close_binding {
                    if value != Value::Nil && value != Value::Boolean(false) {
                        let event = self.lookup_value_event(value, MetamethodEvent::Close)?;
                        if event == Value::Nil {
                            return Err(RuntimeError::new(RuntimeErrorKind::MetamethodAbsent));
                        }
                    }
                    self.frame.write(self.vm, dest, value)?;
                    self.frame.add_close(self.vm, binding, dest, value)?;
                } else {
                    self.frame.write(self.vm, dest, value)?;
                }
                self.frame.pc = next;
            }
            Instruction::Closure { dest, proto } => {
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let child_index = self
                    .current_module()?
                    .module()
                    .prototypes
                    .iter()
                    .position(|candidate| {
                        candidate.id == proto && candidate.parent == Some(self.prototype().id)
                    })
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                let environment_source = self.current_module()?.module().prototypes[child_index]
                    .frame
                    .environment_source;
                let environment = match environment_source {
                    EnvironmentSource::ParentFrame { parent, register }
                        if parent == self.prototype().id =>
                    {
                        Some(self.frame.read(register)?)
                    }
                    EnvironmentSource::ParentFrame { .. } => {
                        return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                    }
                    _ => None,
                };
                let (captures, ticket, original) = self.capture_upvalues(child_index)?;
                let result = (|| {
                    let closure = Closure::new(
                        self.frame
                            .module
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?,
                        proto,
                        &captures,
                        environment,
                        self.vm.allocation_ledger(),
                    )?;
                    let object = self.vm.allocate_closure(closure)?;
                    if let Err(error) = self.frame.write(self.vm, dest, Value::Object(object)) {
                        self.vm.reclaim(object)?;
                        return Err(error);
                    }
                    Ok(())
                })();
                drop(ticket);
                if let Err(error) = result {
                    self.rollback_new_open(original)?;
                    return Err(error);
                }
                self.frame.pc = next;
            }
            Instruction::GetUpvalue { dest, upvalue } => {
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let object = self.current_upvalue(upvalue)?;
                let value = self.read_upvalue(object)?;
                self.frame.write(self.vm, dest, value)?;
                self.frame.pc = next;
            }
            Instruction::SetUpvalue { upvalue, src } => {
                let value = self.frame.read(src)?;
                let next = self.next_pc()?;
                let object = self.current_upvalue(upvalue)?;
                self.write_upvalue(object, value)?;
                self.frame.pc = next;
            }
            Instruction::Call {
                base,
                arg_count,
                result_mode,
            } => match self.enter_regular_call(base, arg_count, result_mode, false)? {
                RegularCallAction::Aborted => return Ok(DispatchResult::Aborted),
                RegularCallAction::Completed(result) => return Ok(result),
                RegularCallAction::Entered => {}
            },
            Instruction::TailCall {
                base,
                arg_count,
                result_mode: ResultMode::All,
            } => match self.enter_regular_call(base, arg_count, ResultMode::All, true)? {
                RegularCallAction::Aborted => return Ok(DispatchResult::Aborted),
                RegularCallAction::Completed(result) => return Ok(result),
                RegularCallAction::Entered => {}
            },
            Instruction::TailCall { .. } => {
                return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedResultMode));
            }
            Instruction::Close { base, count: 0 } => {
                let next = self.next_pc()?;
                self.frame.close_slot(self.vm, base)?;
                self.frame.pc = next;
            }
            Instruction::Close { .. } => {
                let snapshot = self.close_snapshot()?;
                let entry = self
                    .frame
                    .close_entries
                    .last()
                    .copied()
                    .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                if entry.binding != snapshot.next_binding
                    || entry.register != snapshot.next_register
                {
                    return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                }
                let next = self.next_pc()?;
                let value = entry.value;
                if value == Value::Nil || value == Value::Boolean(false) {
                    self.frame.pop_close(self.vm)?;
                    self.frame.pc = next;
                } else {
                    let caller_depth = self.callers.len();
                    let resume_depth = self.resume_stack.len();
                    let invoked = (|| {
                        let event_value = self.lookup_value_event(value, MetamethodEvent::Close)?;
                        if event_value == Value::Nil {
                            return Err(RuntimeError::new(RuntimeErrorKind::MetamethodAbsent));
                        }
                        let Some((event, args, ticket, chain_steps)) =
                            self.resolve_callable_event(event_value, &[value])?
                        else {
                            return Ok(None);
                        };
                        let result = self.invoke_event(
                            PendingKind::Close,
                            [
                                value,
                                event_value,
                                Value::Nil,
                                Value::Nil,
                                Value::Object(event),
                            ],
                            event,
                            &args,
                            snapshot.next_register,
                            ResultMode::Fixed(0),
                            next,
                            chain_steps + 1,
                            false,
                        );
                        drop(ticket);
                        result.map(Some)
                    })();
                    match invoked {
                        Ok(Some(RegularCallAction::Entered))
                            if self.callers.len() > caller_depth =>
                        {
                            self.callers
                                .last_mut()
                                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                                .pop_close(self.vm)?;
                        }
                        Ok(Some(RegularCallAction::Entered))
                            if self.resume_stack.len() > resume_depth =>
                        {
                            self.resume_stack
                                .last_mut()
                                .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?
                                .context
                                .frame
                                .pop_close(self.vm)?;
                        }
                        Ok(Some(RegularCallAction::Entered)) => {
                            self.frame.pop_close(self.vm)?;
                        }
                        Ok(Some(RegularCallAction::Completed(result))) => {
                            self.frame.pop_close(self.vm)?;
                            if !matches!(result, DispatchResult::Continue) {
                                return Ok(result);
                            }
                        }
                        Ok(Some(RegularCallAction::Aborted)) | Ok(None) => {
                            return Ok(DispatchResult::Aborted);
                        }
                        Err(error) => {
                            self.frame.pop_close(self.vm)?;
                            return Err(error);
                        }
                    }
                }
            }
            Instruction::UnaryOp { dest, op, src } => {
                let value = self.frame.read(src)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let event = match op {
                    UnaryOperation::Not => None,
                    UnaryOperation::Length => {
                        if let Value::Object(object) = value {
                            if self.vm.object_kind(object)? == ObjectKind::Table {
                                let event = self.lookup_value_event(value, MetamethodEvent::Len)?;
                                if event != Value::Nil {
                                    Some(event)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    UnaryOperation::Negate
                        if !matches!(value, Value::Integer(_) | Value::Float(_)) =>
                    {
                        Some(self.lookup_value_event(value, MetamethodEvent::Unm)?)
                    }
                    UnaryOperation::BitNot
                        if !matches!(value, Value::Integer(_) | Value::Float(_)) =>
                    {
                        Some(self.lookup_value_event(value, MetamethodEvent::Bnot)?)
                    }
                    _ => None,
                };
                if let Some(event) = event {
                    let args = [value, value];
                    if matches!(
                        self.invoke_value_event(
                            event,
                            &args,
                            [value, Value::Nil],
                            dest,
                            next,
                            None
                        )?,
                        RegularCallAction::Aborted
                    ) {
                        return Ok(DispatchResult::Aborted);
                    }
                } else {
                    let result = if op == UnaryOperation::Length {
                        ops::length(self.vm, value)?
                    } else {
                        ops::unary(op, value)?
                    };
                    self.frame.write(self.vm, dest, result)?;
                    self.frame.pc = next;
                }
            }
            Instruction::BinaryOp {
                dest,
                op,
                left,
                right,
            } => {
                let left = self.frame.read(left)?;
                let right = self.frame.read(right)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                use BinaryOperation as B;
                let mut event_request = None;
                let raw = match op {
                    B::Equal | B::NotEqual => {
                        let equal = ops::raw_equal(self.vm, left, right)?;
                        if !equal
                            && matches!((left, right), (Value::Object(a), Value::Object(b)) if a != b && self.vm.object_kind(a)? == ObjectKind::Table && self.vm.object_kind(b)? == ObjectKind::Table)
                        {
                            event_request =
                                Some((MetamethodEvent::Eq, left, right, op == B::NotEqual));
                            None
                        } else {
                            Some(Value::Boolean(if op == B::NotEqual {
                                !equal
                            } else {
                                equal
                            }))
                        }
                    }
                    B::Less | B::LessEqual | B::Greater | B::GreaterEqual => {
                        let raw = ops::raw_order(self.vm, op, left, right)?;
                        if raw.is_none() {
                            let (event, a, b) = match op {
                                B::Less => (MetamethodEvent::Lt, left, right),
                                B::LessEqual => (MetamethodEvent::Le, left, right),
                                B::Greater => (MetamethodEvent::Lt, right, left),
                                B::GreaterEqual => (MetamethodEvent::Le, right, left),
                                _ => unreachable!(),
                            };
                            event_request = Some((event, a, b, false));
                        }
                        raw
                    }
                    B::Or | B::And => Some(ops::binary(op, left, right)?),
                    B::Concat => {
                        let profile = self.current_module()?.profile();
                        let raw = ops::raw_concat(self.vm, profile, left, right)?;
                        if raw.is_none() {
                            event_request = Some((MetamethodEvent::Concat, left, right, false));
                        }
                        raw
                    }
                    _ => {
                        let raw = ops::raw_arithmetic(op, left, right)?;
                        if raw.is_none() {
                            event_request =
                                arithmetic_event(op).map(|event| (event, left, right, false));
                        }
                        raw
                    }
                };
                if let Some(result) = raw {
                    if let Err(error) = self.frame.write(self.vm, dest, result) {
                        if op == B::Concat {
                            if let Value::Object(object) = result {
                                self.vm.reclaim(object)?;
                            }
                        }
                        return Err(error);
                    }
                    self.frame.pc = next;
                } else {
                    let (event, a, b, mut invert) = event_request
                        .ok_or(RuntimeError::new(RuntimeErrorKind::MetamethodAbsent))?;
                    let mut found = self.lookup_binary_event(a, b, event)?;
                    let mut call_args = [a, b];
                    if found == Value::Nil
                        && event == MetamethodEvent::Le
                        && self.current_module()?.profile() == LuaProfile::Lua54
                    {
                        found = self.lookup_binary_event(b, a, MetamethodEvent::Lt)?;
                        if found != Value::Nil {
                            invert = true;
                            call_args = [b, a];
                        }
                    }
                    if found == Value::Nil && event == MetamethodEvent::Eq {
                        self.frame
                            .write(self.vm, dest, Value::Boolean(op == B::NotEqual))?;
                        self.frame.pc = next;
                    } else {
                        if found == Value::Nil && arithmetic_event(op).is_some() && op != B::Concat
                        {
                            let _ = ops::binary(op, left, right)?;
                        }
                        if matches!(
                            op,
                            B::Equal
                                | B::NotEqual
                                | B::Less
                                | B::LessEqual
                                | B::Greater
                                | B::GreaterEqual
                        ) {
                            let action = self.invoke_value_event(
                                found,
                                &call_args,
                                [left, right],
                                dest,
                                next,
                                Some(invert),
                            )?;
                            if matches!(action, RegularCallAction::Aborted) {
                                return Ok(DispatchResult::Aborted);
                            }
                        } else {
                            let action = self.invoke_value_event(
                                found,
                                &call_args,
                                [left, right],
                                dest,
                                next,
                                None,
                            )?;
                            if matches!(action, RegularCallAction::Aborted) {
                                return Ok(DispatchResult::Aborted);
                            }
                        }
                    }
                }
            }
            Instruction::Jump { target } => {
                self.frame.pc = self.jump_target(target)?;
            }
            Instruction::JumpIfFalse { condition, target } => {
                let value = self.frame.read(condition)?;
                self.frame.pc = if value.is_truthy() {
                    self.next_pc()?
                } else {
                    self.jump_target(target)?
                };
            }
            Instruction::NumericForPrepare {
                control,
                limit,
                step,
                visible,
                exit,
            } => {
                let initial = self.frame.read(control)?;
                let limit_value = self.frame.read(limit)?;
                let step_value = self.frame.read(step)?;
                self.frame.index(visible)?;
                let body = self.next_pc()?;
                let exit = self.jump_target(exit)?;
                match numeric_for::prepare(initial, limit_value, step_value)? {
                    numeric_for::Prepared::Skip => self.frame.pc = exit,
                    numeric_for::Prepared::Enter {
                        control: prepared_control,
                        limit: prepared_limit,
                        step: prepared_step,
                        visible: prepared_visible,
                    } => {
                        self.frame.write(self.vm, control, prepared_control)?;
                        self.frame.write(self.vm, limit, prepared_limit)?;
                        self.frame.write(self.vm, step, prepared_step)?;
                        self.frame.write(self.vm, visible, prepared_visible)?;
                        self.frame.pc = body;
                    }
                }
            }
            Instruction::NumericForNext {
                control,
                limit,
                step,
                visible,
                target,
                exit,
            } => {
                let control_value = self.frame.read(control)?;
                let limit_value = self.frame.read(limit)?;
                let step_value = self.frame.read(step)?;
                self.frame.index(visible)?;
                let body = self.jump_target(target)?;
                let exit = self.jump_target(exit)?;
                match numeric_for::next(control_value, limit_value, step_value)? {
                    numeric_for::Advanced::Exit => self.frame.pc = exit,
                    numeric_for::Advanced::Enter {
                        control: next_control,
                        visible: next_visible,
                    } => {
                        self.frame.write(self.vm, control, next_control)?;
                        self.frame.write(self.vm, visible, next_visible)?;
                        self.frame.pc = body;
                    }
                }
            }
            Instruction::Vararg { base, result_mode } => {
                let first = self.frame.index(base)?;
                let named_table = match self.frame.named_vararg {
                    Some(register) => match self.frame.read(register)? {
                        Value::Object(table) => Some(table),
                        _ => return Err(VmError::WrongObjectType.into()),
                    },
                    None => None,
                };
                let available = if let Some(table) = named_table {
                    let key = self.vm.allocate_byte_string(b"n")?;
                    let field = self.vm.raw_get(table, Value::Object(key));
                    self.vm.reclaim(key)?;
                    let count = match field? {
                        Value::Integer(count) if (0..=i64::from(i32::MAX / 2)).contains(&count) => {
                            count
                        }
                        _ => {
                            return Err(RuntimeError::new(
                                RuntimeErrorKind::InvalidNamedVarargCount,
                            ));
                        }
                    };
                    usize::try_from(count)
                        .map_err(|_| RuntimeError::new(RuntimeErrorKind::InvalidNamedVarargCount))?
                } else {
                    self.frame.varargs.len()
                };
                let count = match result_mode {
                    ResultMode::Fixed(count) => usize::from(count),
                    ResultMode::All => available,
                };
                let end = first
                    .checked_add(count)
                    .filter(|end| *end <= self.frame.max_register_limit)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                let next = self.next_pc()?;
                if matches!(result_mode, ResultMode::All) {
                    self.frame.grow_for_open_results(end)?;
                } else if end > self.frame.register_limit {
                    return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
                }
                for offset in 0..count {
                    let value = if let Some(table) = named_table {
                        if offset < available {
                            let key = i64::try_from(offset + 1)
                                .map_err(|_| VmError::ArithmeticOverflow)?;
                            self.vm.raw_get(table, Value::Integer(key))?
                        } else {
                            Value::Nil
                        }
                    } else {
                        self.frame
                            .varargs
                            .get(offset)
                            .copied()
                            .unwrap_or(Value::Nil)
                    };
                    self.frame.write(
                        self.vm,
                        Register(u16::try_from(first + offset).map_err(|_| {
                            RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds)
                        })?),
                        value,
                    )?;
                }
                if matches!(result_mode, ResultMode::All) {
                    self.frame.dynamic_top = end;
                }
                self.frame.pc = next;
            }
            Instruction::Return { base, result_mode } => {
                let first = self.frame.index(base)?;
                let end = match result_mode {
                    ResultMode::Fixed(count) => first
                        .checked_add(usize::from(count))
                        .filter(|end| *end <= self.frame.register_limit),
                    ResultMode::All => Some(self.frame.dynamic_top)
                        .filter(|end| *end >= first && *end <= self.frame.register_limit),
                }
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                let count = end - first;
                let mut result = Vec::new();
                let mut ticket = if count == 0 {
                    None
                } else {
                    Some(reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut result,
                        count,
                        FailPoint::ReturnReserve,
                    )?)
                };
                result.extend_from_slice(&self.frame.registers[first..end]);
                let protected_return = self.protected.last().is_some_and(|boundary| {
                    let depth = match boundary.stage {
                        ProtectedStage::Body => Some(boundary.caller_depth),
                        ProtectedStage::Handler => boundary.handler_depth,
                    };
                    depth.and_then(|depth| depth.checked_add(1)) == Some(self.callers.len())
                });
                if protected_return {
                    let mut boundary = self
                        .protected
                        .pop()
                        .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                    let marked = self.mark_protected_result(&boundary, &mut result);
                    let tail_return = boundary.tail_return;
                    marked?;
                    let completed = if boundary.stage == ProtectedStage::Handler {
                        let root = if let Some(Value::Object(object)) = result.get(1).copied() {
                            Some(self.vm.add_root(RootKind::Temporary, object)?)
                        } else {
                            None
                        };
                        let written = self
                            .unwind_to_protected(boundary.caller_depth)
                            .and_then(|()| self.write_protected_values(&boundary, &result));
                        if let Some(root) = root {
                            self.vm.remove_root(root)?;
                        }
                        written
                    } else if boundary.inline_target {
                        self.write_protected_values(&boundary, &result)
                    } else {
                        self.return_to_caller(&result)
                    };
                    boundary.clear(self.vm)?;
                    completed?;
                    if tail_return || self.inline_boundary_ready() {
                        return self.propagate_tail_result(result, ticket);
                    }
                    drop(ticket);
                    return Ok(DispatchResult::Continue);
                }
                if !self.callers.is_empty() {
                    let completed_pending = self.pending_ops.last().is_some_and(|pending| {
                        pending.caller_depth.checked_add(1) == Some(self.callers.len())
                    });
                    if completed_pending {
                        if let Some(PendingKind::Boolean { invert }) =
                            self.pending_ops.last().map(|pending| pending.kind)
                        {
                            let truth = result.first().copied().unwrap_or(Value::Nil).is_truthy();
                            if result.is_empty() {
                                ticket = Some(reserve_vec(
                                    self.vm.allocation_ledger(),
                                    &mut result,
                                    1,
                                    FailPoint::ReturnReserve,
                                )?);
                                result.push(Value::Boolean(truth ^ invert));
                            } else {
                                result[0] = Value::Boolean(truth ^ invert);
                                result.truncate(1);
                            }
                        }
                    }
                    let returned_mode = self.frame.return_mode;
                    let returned_destination = self.frame.return_destination;
                    self.return_to_caller(&result)?;
                    if completed_pending {
                        let mut pending = self
                            .pending_ops
                            .pop()
                            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
                        let awaiting = pending.stage == ResumeStage::AwaitingReturn;
                        pending.stage = ResumeStage::Resuming;
                        let expected_mode = match pending.kind {
                            PendingKind::Table(PendingTableKind::Get)
                            | PendingKind::Value
                            | PendingKind::Boolean { .. } => ResultMode::Fixed(1),
                            PendingKind::Table(PendingTableKind::Set) => ResultMode::Fixed(0),
                            PendingKind::Close => ResultMode::Fixed(0),
                            PendingKind::Call => pending.result_mode,
                        };
                        let valid = awaiting
                            && pending.chain_steps > 0
                            && matches!(pending.values[4], Value::Object(_))
                            && pending.result_mode == expected_mode
                            && self.callers.len() == pending.caller_depth
                            && self.frame.pc == pending.resume_pc
                            && pending.caller_pc.checked_add(1) == Some(pending.resume_pc)
                            && self.frame.stack_base == pending.caller_stack_base
                            && self.frame.prototype == pending.caller_prototype
                            && self.frame.module == pending.caller_module
                            && returned_destination == Some(pending.destination)
                            && returned_mode == pending.result_mode;
                        if !matches!(pending.kind, PendingKind::Call) {
                            self.frame.dynamic_top = pending.dynamic_top;
                        }
                        pending.clear(self.vm)?;
                        self.pending_ops.release_empty()?;
                        if !valid {
                            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                        }
                    }
                    while self.frame.tail_return {
                        if self.callers.is_empty() {
                            return Ok(DispatchResult::Returned(result, ticket));
                        }
                        self.return_to_caller(&result)?;
                    }
                    drop(ticket);
                    return Ok(DispatchResult::Continue);
                }
                return Ok(DispatchResult::Returned(result, ticket));
            }
        }
        Ok(DispatchResult::Continue)
    }
}

impl Drop for Execution<'_> {
    fn drop(&mut self) {
        // RootId 由各 frame 唯一持有；P06 remove_root 不配置也不觸發 GC。
        let cleanup = self.finish();
        debug_assert!(cleanup.is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RootKind, Vm};
    use rivetlua_core::{
        BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule,
        BytecodePrototype, BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction,
        InstructionOffset, LuaProfile, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register,
        ResultMode, Value, VerifyLimits, verify_module,
    };

    #[test]
    fn review_builtin_event_clears_pending_roots_on_error_and_reserve_failure() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let key = vm.allocate_byte_string(b"error").unwrap();
        let Value::Object(event) = vm.raw_get(env, Value::Object(key)).unwrap() else {
            panic!("error builtin 必須已安裝")
        };
        let target = vm.allocate_table().unwrap();
        let target_root = crate::HostHandle::<Value>::new(&mut vm, target).unwrap();
        let mut execution = vm
            .load(module(
                vec![Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                }],
                vec![],
            ))
            .unwrap();
        let baseline = execution.vm.roots().total_count();
        let values = [
            Value::Object(target),
            Value::Nil,
            Value::Nil,
            Value::Nil,
            Value::Object(event),
        ];
        let args = [Value::Object(target)];
        let Err(error) = execution.invoke_event(
            PendingKind::Value,
            values,
            event,
            &args,
            Register(0),
            ResultMode::Fixed(1),
            1,
            1,
            false,
        ) else {
            panic!("Builtin error 應拋出原始值")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Thrown);
        assert_eq!(error.value, Value::Object(target));
        assert!(execution.pending_ops.is_empty());
        assert_eq!(execution.vm.roots().total_count(), baseline);
        execution.vm.inject_failure_once(FailPoint::WorkReserve);
        let Err(error) = execution.invoke_event(
            PendingKind::Value,
            values,
            event,
            &args,
            Register(0),
            ResultMode::Fixed(1),
            1,
            1,
            false,
        ) else {
            panic!("pending 容量失敗須回傳受控錯誤")
        };
        assert_eq!(
            error.kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert!(execution.pending_ops.is_empty());
        assert_eq!(execution.vm.roots().total_count(), baseline);
        drop(execution);
        drop(target_root);
        drop(env_root);
        assert_eq!(vm.roots().total_count(), 0);
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_4_installer_exposes_close_and_wrap() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let host = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let coroutine_key = vm.allocate_byte_string(b"coroutine").unwrap();
        let Value::Object(table) = vm.raw_get(env, Value::Object(coroutine_key)).unwrap() else {
            panic!("coroutine table 必須已安裝")
        };
        for name in [b"close".as_slice(), b"wrap".as_slice()] {
            let key = vm.allocate_byte_string(name).unwrap();
            let Value::Object(entry) = vm.raw_get(table, Value::Object(key)).unwrap() else {
                panic!("P11-4 coroutine 入口缺失：{name:?}")
            };
            assert_eq!(vm.object_kind(entry), Ok(ObjectKind::Builtin));
        }
        drop(host);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_4_native_body_allocation_failure_restores_roots() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let host = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let coroutine_key = vm.allocate_byte_string(b"coroutine").unwrap();
        let Value::Object(table) = vm.raw_get(env, Value::Object(coroutine_key)).unwrap() else {
            panic!("coroutine table 缺失")
        };
        let wrap_key = vm.allocate_byte_string(b"wrap").unwrap();
        let Value::Object(wrap) = vm.raw_get(table, Value::Object(wrap_key)).unwrap() else {
            panic!("coroutine.wrap 缺失")
        };
        let status_key = vm.allocate_byte_string(b"status").unwrap();
        let Value::Object(status) = vm.raw_get(table, Value::Object(status_key)).unwrap() else {
            panic!("coroutine.status 缺失")
        };
        let outer = vm.allocate_coroutine(Value::Object(wrap)).unwrap();
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut execution = vm.load(verified).unwrap();
        let before = execution.vm.roots().total_count();
        execution.vm.inject_failure_once(FailPoint::ObjectReserve);
        assert_eq!(
            execution
                .run_new_native_builtin_body(
                    outer,
                    Builtin::CoroutineWrap,
                    &[Value::Object(outer), Value::Object(status)],
                    Register(0),
                    ResultMode::Fixed(2),
                    false,
                    1,
                    false,
                )
                .err()
                .map(|error| error.kind),
            Some(RuntimeErrorKind::Heap(VmError::InjectedFailure(
                FailPoint::ObjectReserve
            )))
        );
        assert_eq!(execution.active_coroutine, None);
        assert_eq!(
            execution.vm.coroutine_state(outer),
            Ok(CoroutineState::Dead)
        );
        assert_eq!(execution.vm.roots().total_count(), before);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.finish().unwrap();
        drop(host);
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_4_nested_native_completion_failure_releases_roots() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local parent=coroutine.create(function() local f=coroutine.wrap(function() return {} end); local outer=coroutine.create(f); return coroutine.resume(outer) end); return coroutine.resume(parent)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let host = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let mut execution = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap();
        for _ in 0..100 {
            match execution.dispatch_one().unwrap() {
                DispatchResult::Returned(values, ticket)
                    if execution
                        .resume_stack
                        .last()
                        .is_some_and(|caller| caller.native_body.is_some()) =>
                {
                    execution.vm.inject_failure_once(FailPoint::ReturnReserve);
                    let error = execution
                        .complete_coroutine(values, ticket, CoroutineExit::Return)
                        .err()
                        .unwrap();
                    assert_eq!(
                        error.kind,
                        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::ReturnReserve))
                    );
                    drop(execution);
                    assert_eq!(vm.roots().total_count(), 1);
                    assert_eq!(vm.ledger_snapshot().reserved, 0);
                    drop(host);
                    vm.collect().unwrap();
                    assert_eq!(vm.roots().total_count(), 0);
                    return;
                }
                action => {
                    let _ = execution.settle_coroutine_dispatch(action).unwrap();
                }
            }
        }
        panic!("應到達 wrapped native body 的巢狀返回")
    }

    #[test]
    fn p11_5_hard_abort_clears_close_continuation_and_roots() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let one = vm.allocate_table().unwrap();
        let one_key = vm.allocate_byte_string(b"one").unwrap();
        vm.raw_set(env, Value::Object(one_key), Value::Object(one))
            .unwrap();
        let handler = vm
            .load_with_environment(
                compile(b"return function(v,e) while true do end end"),
                Value::Object(env),
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = handler else {
            panic!("close handler 應是 closure")
        };
        let mt = vm.allocate_table().unwrap();
        let close_key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(mt, Value::Object(close_key), values[0]).unwrap();
        vm.set_metatable(one, Some(mt)).unwrap();
        let mut execution = vm
            .load_with_environment(
                compile(b"local x <close> = one; error(9)"),
                Value::Object(env),
            )
            .unwrap();
        execution.set_fuel(100).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert!(execution.close_unwind.is_none());
        assert!(execution.pending_ops.is_empty());
        assert!(execution.resume_stack.is_empty());
        assert_eq!(execution.vm.roots().total_count(), 1);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        drop(execution);
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p11_5_error_root_replacement_failure_preserves_prior_value() {
        let mut vm = Vm::new().unwrap();
        let old = vm.allocate_table().unwrap();
        let replacement = vm.allocate_table().unwrap();
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut execution = vm.load(verified).unwrap();
        let mut first = explicit_error(Value::Object(old), 0);
        execution.prepare_close_error_value(&mut first).unwrap();
        let prior_root = execution.error_root;
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        let mut second = explicit_error(Value::Object(replacement), 0);
        assert_eq!(
            execution
                .prepare_close_error_value(&mut second)
                .err()
                .map(|error| error.kind),
            Some(RuntimeErrorKind::Heap(VmError::InjectedFailure(
                FailPoint::RootReserve
            )))
        );
        assert_eq!(execution.error_root, prior_root);
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.object_kind(old), Ok(ObjectKind::Table));
        assert_eq!(
            execution.vm.object_kind(replacement),
            Err(VmError::StaleObject)
        );
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.finish().unwrap();
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.object_kind(old), Err(VmError::StaleObject));
        assert_eq!(execution.vm.roots().total_count(), 0);
    }

    #[test]
    fn p11_3_invalid_close_value_fails_at_declaration() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local x <close> = 1; return 7";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let outcome = vm.load(module).unwrap().run().unwrap();
        assert!(matches!(outcome, RunOutcome::LuaError(_)));
    }

    #[test]
    fn p11_3_close_entry_root_and_reservation_cleanup() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate_table().unwrap();
        let host = crate::HostHandle::<Value>::new(&mut vm, object).unwrap();
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut execution = vm.load(verified).unwrap();
        let binding = BytecodeBindingId {
            function: 0,
            ordinal: 1,
        };
        let before = execution.vm.roots().count(RootKind::Stack);
        execution.vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            execution
                .frame
                .add_close(execution.vm, binding, Register(0), Value::Object(object))
                .err()
                .map(|error| error.kind),
            Some(RuntimeErrorKind::Heap(VmError::InjectedFailure(
                FailPoint::WorkReserve
            )))
        );
        assert!(execution.frame.close_entries.is_empty());
        assert_eq!(execution.vm.roots().count(RootKind::Stack), before);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);

        execution
            .frame
            .add_close(execution.vm, binding, Register(0), Value::Object(object))
            .unwrap();
        assert_eq!(execution.vm.roots().count(RootKind::Stack), before + 1);
        drop(host);
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.object_kind(object), Ok(ObjectKind::Table));
        assert_eq!(
            execution
                .frame
                .pop_close(execution.vm)
                .unwrap()
                .unwrap()
                .value,
            Value::Object(object)
        );
        assert_eq!(execution.vm.roots().count(RootKind::Stack), before);
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.object_kind(object), Err(VmError::StaleObject));
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_2_native_resume_chain_reservation_rolls_back() {
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut chain = ResumeChain::new(vm.allocation_ledger());
        let continuation = NativeCompletion::Resume {
            outer: vm.allocate_coroutine(Value::Nil).unwrap(),
            parent: None,
            parent_root: None,
            protected: None,
        };
        let with_coroutine = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            chain.push(continuation).err(),
            Some(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert!(chain.items.is_empty());
        assert_eq!(vm.ledger_snapshot(), with_coroutine);
        vm.set_allocation_limit(with_coroutine.committed);
        assert_eq!(
            chain.push(continuation).err(),
            Some(VmError::AllocationFailed)
        );
        assert!(chain.items.is_empty());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.set_allocation_limit(before.limit);
        chain.push(continuation).unwrap();
        assert_eq!(chain.items.len(), 1);
        assert!(vm.ledger_snapshot().committed > with_coroutine.committed);
        drop(chain);
        assert_eq!(vm.ledger_snapshot(), with_coroutine);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_2_native_resume_chain_completion_failure_releases_roots() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local c=coroutine.create(function() return 4 end); local z=coroutine.create(pcall); return coroutine.resume(z,xpcall,pcall,function(v) return v end,coroutine.resume,c)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let mut execution = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap();
        for _ in 0..100 {
            match execution.dispatch_one().unwrap() {
                DispatchResult::Returned(values, ticket) if !execution.resume_stack.is_empty() => {
                    assert_eq!(
                        execution
                            .resume_stack
                            .last()
                            .unwrap()
                            .outer_resumes
                            .items
                            .len(),
                        2
                    );
                    execution.vm.inject_failure_once(FailPoint::ReturnReserve);
                    let failure = execution
                        .complete_coroutine(values, ticket, CoroutineExit::Return)
                        .err()
                        .unwrap();
                    assert_eq!(
                        failure.kind,
                        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::ReturnReserve))
                    );
                    drop(execution);
                    assert_eq!(vm.roots().total_count(), 1);
                    assert_eq!(vm.ledger_snapshot().reserved, 0);
                    drop(env_root);
                    vm.collect().unwrap();
                    assert_eq!(vm.roots().total_count(), 0);
                    return;
                }
                action => {
                    let _ = execution.settle_coroutine_dispatch(action).unwrap();
                }
            }
        }
        panic!("應到達第三層 return");
    }

    #[test]
    fn p11_2_resume_precommit_failures_keep_suspended_context_and_roots() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = crate::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let result = vm.load_with_environment(
            compile(b"local co=coroutine.create(function() local x=coroutine.yield(1); return x end); coroutine.resume(co); return co"),
            Value::Object(env),
        ).unwrap().run().unwrap();
        let RunOutcome::Returned(values) = result else {
            panic!("須回傳 suspended coroutine")
        };
        let Value::Object(co) = values[0] else {
            panic!("須為 coroutine")
        };
        let co_root = crate::HostHandle::<Value>::new(&mut vm, co).unwrap();
        let mut execution = vm.load(compile(b"return 0")).unwrap();
        let roots_before = execution.vm.roots().total_count();
        for point in [FailPoint::WorkReserve, FailPoint::RootReserve] {
            execution.vm.inject_failure_once(point);
            let error = execution
                .start_coroutine_resume(
                    Register(0),
                    &[Value::Object(co), Value::Integer(20)],
                    ResultMode::All,
                    false,
                    1,
                    false,
                )
                .err()
                .unwrap();
            assert_eq!(
                error.kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(execution.vm.roots().total_count(), roots_before);
            let (state, pending) = execution
                .vm
                .with_coroutine(co, |co| (co.state, co.context.is_some()))
                .unwrap();
            assert_eq!(state, CoroutineState::Suspended);
            assert!(pending);
        }
        drop(execution);
        drop(co_root);
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    fn assert_reclaimed_diagnostic(vm: &mut Vm, message: ObjectRef, count: usize) {
        assert_eq!(vm.collect().unwrap(), count);
        assert_eq!(vm.object_kind(message), Err(VmError::StaleObject));
        let stable = vm.ledger_snapshot();
        assert_eq!(stable.reserved, 0);
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.ledger_snapshot(), stable);
    }

    #[test]
    fn p09_1_call_frame_nocapture_entry_return_and_nil_callee() {
        let mut candidate = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        )
        .module()
        .clone();
        candidate.prototypes[0].instructions = vec![
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Call {
                base: Register(0),
                arg_count: 0,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span: candidate.span,
            close_path: None,
        })
        .collect();
        let mut child = candidate.prototypes[0].clone();
        child.id = ProtoId(1);
        child.function = 1;
        child.parent = Some(ProtoId(0));
        child.frame.environment_source = EnvironmentSource::ParentFrame {
            parent: ProtoId(0),
            register: Register(2),
        };
        child.global_environment_binding = BytecodeBindingId {
            function: 1,
            ordinal: 0,
        };
        child.binding_registers = vec![(child.global_environment_binding, Register(2))];
        child.constants = vec![BytecodeConstant::Integer(42)];
        child.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                span: candidate.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span: candidate.span,
                close_path: None,
            },
        ];
        candidate.function_prototypes.push((1, ProtoId(1)));
        candidate.prototypes.push(child);
        let mut all_candidate = candidate.clone();
        all_candidate.prototypes[0].instructions[1].instruction = Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        all_candidate.prototypes[0].instructions[2].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::All,
        };
        all_candidate.prototypes[1].instructions[1].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(2),
        };
        let mut fixed_candidate = candidate.clone();
        fixed_candidate.prototypes[0].instructions[1].instruction = Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::Fixed(2),
        };
        fixed_candidate.prototypes[0].instructions[2].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(2),
        };
        let mut argument_candidate = candidate.clone();
        argument_candidate.prototypes[0].constants = vec![BytecodeConstant::String(vec![0, 0x80])];
        argument_candidate.prototypes[0].instructions.insert(
            1,
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(0),
                },
                span: candidate.span,
                close_path: None,
            },
        );
        argument_candidate.prototypes[0].instructions[2].instruction = Instruction::Call {
            base: Register(0),
            arg_count: 1,
            result_mode: ResultMode::Fixed(1),
        };
        argument_candidate.prototypes[1].parameter_count = 1;
        argument_candidate.prototypes[1].instructions = vec![BytecodeInstruction {
            instruction: Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
            span: candidate.span,
            close_path: None,
        }];
        let verified = verify_module(
            candidate.clone(),
            LuaProfile::Lua55,
            &VerifyLimits::default(),
        )
        .unwrap();
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified.clone()).unwrap();
        assert_eq!(execution.frame.prototype, 0);
        assert_eq!(execution.frame.pc, 0);
        assert_eq!(execution.frame.base, 0);
        assert_eq!(execution.frame.register_limit, 3);
        assert_eq!(execution.frame.dynamic_top, 3);
        assert_eq!(execution.frame.return_destination, None);
        assert_eq!(execution.frame.return_mode, ResultMode::Fixed(0));
        assert_eq!(execution.frame.pending_close, None);
        assert_eq!(execution.frame.caller, None);
        assert_eq!(execution.frame.depth, 0);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(42)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 2);

        let verified_fixed =
            verify_module(fixed_candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut execution = vm.load(verified_fixed).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(42), Value::Nil]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 2);

        let verified_argument = verify_module(
            argument_candidate,
            LuaProfile::Lua55,
            &VerifyLimits::default(),
        )
        .unwrap();
        let mut execution = vm.load(verified_argument).unwrap();
        execution
            .vm
            .inject_failure_once(FailPoint::CallFrameReserve);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::CallFrameReserve))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.collect().unwrap(), 3);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let stable_charge = vm.ledger_snapshot().committed;

        let verified_depth = verified.clone();
        let mut execution = vm.load(verified).unwrap();
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.callers.len(), 1);
        assert_eq!(execution.callers[0].pc, 2);
        assert_eq!(execution.frame.prototype, 1);
        assert_eq!(execution.frame.pc, 0);
        assert_eq!(execution.frame.base, 0);
        assert_eq!(execution.frame.return_destination, Some(Register(0)));
        assert_eq!(execution.frame.return_mode, ResultMode::Fixed(1));
        assert_eq!(execution.frame.caller, Some(0));
        assert_eq!(execution.frame.depth, 1);
        execution.frame.pc = usize::MAX;
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::ProgramCounterOutOfBounds
        );
        assert!(execution.callers.is_empty());
        assert_eq!(execution.callers_charge, 0);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 2);

        let mut execution = vm.load(verified_depth).unwrap();
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        execution.frame.depth = 1024;
        let RunOutcome::LuaError(error) = execution.run().unwrap() else {
            panic!("超出 frame 深度須是受控 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::StackLimit);
        assert_eq!(error.diagnostic_id, "E_STACK_LIMIT");
        drop(execution);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        drop(error);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 3);

        let verified_all =
            verify_module(all_candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut execution = vm.load(verified_all).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(42), Value::Nil]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 2);

        let verified_failure =
            verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut execution = vm.load(verified_failure).unwrap();
        execution
            .vm
            .inject_failure_once(FailPoint::CallFrameReserve);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::CallFrameReserve))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(vm.ledger_snapshot().committed, stable_charge);

        let mut execution = vm
            .load(module(
                vec![
                    Instruction::Call {
                        base: Register(0),
                        arg_count: 0,
                        result_mode: ResultMode::Fixed(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![],
            ))
            .unwrap();
        assert!(matches!(execution.run(), Ok(RunOutcome::LuaError(_))));
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p09_1_call_frame_pending_close_preserves_verified_path() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn step_with_close_metatable(
            execution: &mut Execution<'_>,
        ) -> Result<DispatchResult, RuntimeError> {
            let marker_source = match &execution.prototype().instructions[execution.pc()] {
                rivetlua_core::BytecodeInstruction {
                    instruction: Instruction::Move { src, .. },
                    close_path: Some(_),
                    ..
                } => Some(*src),
                _ => None,
            };
            if let Some(src) = marker_source {
                let Value::Object(table) = execution.frame.read(src)? else {
                    return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
                };
                let handler = execution.frame.read(Register(2))?;
                let metatable = execution.vm.allocate_table()?;
                let metatable_root = crate::HostHandle::<Value>::new(execution.vm, metatable)?;
                let key = execution.vm.allocate_byte_string(b"__close")?;
                let key_root = crate::HostHandle::<Value>::new(execution.vm, key)?;
                execution
                    .vm
                    .raw_set(metatable, Value::Object(key), handler)?;
                execution.vm.set_metatable(table, Some(metatable))?;
                drop(key_root);
                drop(metatable_root);
            }
            execution.dispatch_one()
        }
        fn advance_to_close(execution: &mut Execution<'_>, close_pc: usize) {
            for _ in 0..100 {
                if execution.frame.prototype == 0 && execution.pc() == close_pc {
                    return;
                }
                assert!(matches!(
                    step_with_close_metatable(execution),
                    Ok(DispatchResult::Continue)
                ));
            }
            panic!("應到達 ClosePath")
        }
        let source = b"local f=function() return nil,1,nil end; do local a <close> = {}; do local b <close> = {}; return f() end end";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let root = &verified.module().prototypes[0];
        let call = root
            .instructions
            .iter()
            .position(|entry| {
                matches!(
                    entry.instruction,
                    Instruction::Call {
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            })
            .unwrap();
        let first_path = root.instructions[call + 1].close_path.as_ref().unwrap();
        assert_eq!(first_path.registers.len(), 2);
        for (offset, register) in first_path.registers.iter().enumerate() {
            let entry = &root.instructions[call + 1 + offset];
            assert_eq!(
                entry.instruction,
                Instruction::Close {
                    base: *register,
                    count: 1
                }
            );
            assert_eq!(entry.close_path.as_ref(), Some(first_path));
        }
        assert!(matches!(
            root.instructions[call + 3].instruction,
            Instruction::Return {
                result_mode: ResultMode::All,
                ..
            }
        ));
        let first_path = first_path.clone();
        assert_eq!(first_path.kind, rivetlua_core::BytecodeExitKind::Return);
        let initial_register_count = usize::from(root.register_count);
        let Instruction::Return {
            base: return_base, ..
        } = root.instructions[call + 3].instruction
        else {
            panic!("ClosePath 後必須有 Return(All)")
        };
        assert_eq!(usize::from(return_base.0) + 3, initial_register_count + 2);
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified.clone()).unwrap();
        advance_to_close(&mut execution, call + 1);
        assert_eq!(execution.pc(), call + 1);
        let snapshot = execution.close_snapshot().unwrap();
        assert_eq!(snapshot.prototype, root.id);
        assert_eq!(snapshot.close_pc, call + 1);
        assert_eq!(snapshot.path_start_pc, call + 1);
        assert_eq!(snapshot.path_offset, 0);
        assert_eq!(snapshot.path_kind, first_path.kind);
        assert_eq!(snapshot.next_binding, first_path.bindings[0]);
        assert_eq!(snapshot.next_register, first_path.registers[0]);
        assert_eq!(snapshot.return_base, Some(return_base));
        assert_eq!(snapshot.return_mode, Some(ResultMode::All));
        assert_eq!(snapshot.result_count, 3);
        assert!(snapshot.retained_root_count >= 3);
        assert_eq!(execution.pending_close(), None);
        assert_eq!(execution.frame.read(return_base), Ok(Value::Nil));
        assert_eq!(
            execution.frame.read(Register(return_base.0 + 1)),
            Ok(Value::Integer(1))
        );
        assert_eq!(
            execution.frame.read(Register(return_base.0 + 2)),
            Ok(Value::Nil)
        );
        assert_eq!(execution.pc(), call + 1);
        assert_eq!(
            execution.frame.register_limit,
            usize::from(return_base.0) + 3
        );
        assert_eq!(
            execution.vm.roots().total_count(),
            snapshot.retained_root_count
        );
        assert_eq!(execution.vm.collect().unwrap(), 0);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Nil,
                Value::Integer(1),
                Value::Nil
            ]))
        );
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert!(vm.collect().unwrap() >= 1);
        let stable_charge = vm.ledger_snapshot().committed;
        let mut execution = vm.load(verified.clone()).unwrap();
        advance_to_close(&mut execution, call + 1);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Nil,
                Value::Integer(1),
                Value::Nil
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert!(vm.collect().unwrap() >= 1);
        assert_eq!(vm.ledger_snapshot().committed, stable_charge);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let source =
            b"local f=function() return {},1,nil end; do local a <close> = {}; return f() end";
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified_object = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified_object).unwrap();
        let object_path_pc = execution
            .prototype()
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::Close { count: 1, .. }))
            .unwrap();
        advance_to_close(&mut execution, object_path_pc);
        let object_snapshot = execution.close_snapshot().unwrap();
        assert_eq!(object_snapshot.result_count, 3);
        let Some(Value::Object(returned_table)) = object_snapshot
            .return_base
            .and_then(|base| execution.frame.read(base).ok())
        else {
            panic!("首個 open result 須是 table object")
        };
        let object_return_base = object_snapshot.return_base.unwrap();
        assert_eq!(
            execution.frame.read(Register(object_return_base.0 + 1)),
            Ok(Value::Integer(1))
        );
        assert_eq!(
            execution.frame.read(Register(object_return_base.0 + 2)),
            Ok(Value::Nil)
        );
        assert_eq!(execution.vm.collect().unwrap(), 0);
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("含 object return 的 ClosePath 須完成實際關閉")
        };
        assert_eq!(
            values,
            vec![Value::Object(returned_table), Value::Integer(1), Value::Nil]
        );
        let returned_root = crate::HostHandle::<Value>::new(execution.vm, returned_table).unwrap();
        execution.vm.collect().unwrap();
        execution
            .vm
            .with_table(returned_table, |table| assert!(table.is_empty()))
            .unwrap();
        drop(returned_root);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert!(vm.collect().unwrap() >= 1);

        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        while execution.frame.depth == 0 {
            assert!(matches!(
                step_with_close_metatable(&mut execution),
                Ok(DispatchResult::Continue)
            ));
        }
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Return { .. }
        ) {
            assert!(matches!(
                step_with_close_metatable(&mut execution),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.frame.return_destination, Some(return_base));
        let caller_registers = execution.callers.last().unwrap().register_limit;
        let roots_before = execution.vm.roots().total_count();
        let ledger_before = execution.vm.ledger_snapshot();
        execution
            .vm
            .inject_failure_once(FailPoint::FrameRootsReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::FrameRootsReserve))
        );
        assert_eq!(
            execution.callers.last().unwrap().register_limit,
            caller_registers
        );
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot(), ledger_before);
        let result_bytes = 3 * core::mem::size_of::<Value>();
        execution
            .vm
            .set_allocation_limit(ledger_before.committed + result_bytes);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        assert_eq!(
            execution.callers.last().unwrap().register_limit,
            caller_registers
        );
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(
            execution.vm.ledger_snapshot().committed,
            ledger_before.committed
        );
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.vm.set_allocation_limit(usize::MAX);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.frame.dynamic_top, usize::from(return_base.0) + 3);
        assert_eq!(
            execution.frame.registers[usize::from(return_base.0)..execution.frame.dynamic_top],
            [Value::Nil, Value::Integer(1), Value::Nil]
        );
        let roots_at_close = execution.vm.roots().total_count();
        let snapshot = execution.close_snapshot().unwrap();
        assert_eq!(snapshot.result_count, 3);
        assert_eq!(snapshot.retained_root_count, roots_at_close);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Nil,
                Value::Integer(1),
                Value::Nil
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert!(vm.collect().unwrap() >= 1);
    }

    #[test]
    fn p09_2_upvalue_frame_exit_preserves_shared_closed_value() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function make() local x={v=7}; local t={}; t.get=function() return x.v end; t.set=function() x={v=9} end; return t end; local p=make(); local a=p.get(); p.set(); local b=p.get(); return a,b";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let captured = verified
            .module()
            .prototypes
            .iter()
            .filter(|prototype| !prototype.upvalues.is_empty())
            .count();
        assert!(captured >= 2);
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        while execution.frame.depth == 0 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let mut child_closures = Vec::new();
        while child_closures.len() < 2 {
            let instruction = execution.prototype().instructions[execution.frame.pc]
                .instruction
                .clone();
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            if let Instruction::Closure { dest, .. } = instruction {
                let Value::Object(object) = execution.frame.read(dest).unwrap() else {
                    panic!("captured closure 必須有物件身分")
                };
                child_closures.push(object);
            }
        }
        assert_eq!(execution.frame.open_upvalues.len(), 1);
        let first = execution
            .vm
            .with_closure(child_closures[0], |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        let second = execution
            .vm
            .with_closure(child_closures[1], |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            execution.vm.upvalue_state(first),
            Ok(UpvalueState::Open { .. })
        ));
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(9)
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_upvalue_module_identity_survives_execution_drop() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let compile = |source: &[u8]| {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        };
        let first = compile(b"local f=function() return 11 end; return f");
        let second = compile(b"local f=function() return 22 end; local x=f(); return x");
        assert_eq!(
            first.module().prototypes[1].id,
            second.module().prototypes[1].id
        );
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(first).unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("第一模組須回傳 closure")
        };
        let Value::Object(closure) = values[0] else {
            panic!("第一模組須回傳 closure 物件")
        };
        drop(execution);
        let root = vm.add_root(RootKind::Host, closure).unwrap();
        let first_module = vm
            .with_closure(closure, |payload| payload.module())
            .unwrap();
        assert_eq!(vm.object_kind(first_module), Ok(crate::ObjectKind::Module));
        assert_eq!(vm.collect().unwrap(), 0);

        let mut execution = vm.load(second).unwrap();
        loop {
            let instruction = execution.prototype().instructions[execution.frame.pc]
                .instruction
                .clone();
            if let Instruction::Call { base, .. } = instruction {
                execution
                    .frame
                    .write(execution.vm, base, Value::Object(closure))
                    .unwrap();
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(11)]))
        );
        drop(execution);
        assert_eq!(vm.object_kind(closure), Ok(crate::ObjectKind::Closure));
        let other_vm = Vm::new().unwrap();
        assert_eq!(other_vm.object_kind(closure), Err(VmError::WrongVm));
        vm.remove_root(root).unwrap();
        assert!(vm.collect().unwrap() >= 2);
        assert_eq!(vm.object_kind(closure), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_upvalue_closed_object_is_traced_until_host_root_removed() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function make() local x={v=7}; return function() return x.v end end; local f=make(); return f";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("外層應回傳 captured closure")
        };
        let Value::Object(closure) = values[0] else {
            panic!("回傳值應為 closure")
        };
        drop(execution);
        let root = vm.add_root(RootKind::Host, closure).unwrap();
        let upvalue = vm
            .with_closure(closure, |payload| payload.upvalue(0))
            .unwrap()
            .unwrap();
        let UpvalueState::Closed(Value::Object(table)) = vm.upvalue_state(upvalue).unwrap() else {
            panic!("frame 退出前必須由 Open 複製為 Closed(Object)")
        };
        assert_eq!(vm.object_kind(table), Ok(crate::ObjectKind::Table));
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(upvalue), Ok(crate::ObjectKind::Upvalue));
        assert_eq!(vm.object_kind(table), Ok(crate::ObjectKind::Table));
        vm.remove_root(root).unwrap();
        assert!(vm.collect().unwrap() >= 4);
        assert_eq!(vm.object_kind(upvalue), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_upvalue_error_exit_closes_before_slot_release() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function make() local x={v=7}; local f=function() return x.v end; local z=nil; z(); return f end; local f=make(); return f";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let closure = loop {
            let instruction = execution.prototype().instructions[execution.frame.pc]
                .instruction
                .clone();
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            if let Instruction::Closure {
                dest,
                proto: ProtoId(2),
            } = instruction
            {
                let Value::Object(object) = execution.frame.read(dest).unwrap() else {
                    panic!("captured closure 須為 heap 物件")
                };
                break object;
            }
        };
        let root = execution.vm.add_root(RootKind::Host, closure).unwrap();
        let upvalue = execution
            .vm
            .with_closure(closure, |payload| payload.upvalue(0))
            .unwrap()
            .unwrap();
        assert!(matches!(
            execution.vm.upvalue_state(upvalue),
            Ok(UpvalueState::Open { .. })
        ));
        let RunOutcome::LuaError(error) = execution.run().unwrap() else {
            panic!("nil call 須為 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::NotCallable);
        assert_eq!(execution.vm.roots().total_count(), 2);
        drop(execution);
        drop(error);
        assert_eq!(vm.roots().total_count(), 1);
        let UpvalueState::Closed(Value::Object(table)) = vm.upvalue_state(upvalue).unwrap() else {
            panic!("LuaError 退出 frame 須先關閉 upvalue")
        };
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Ok(crate::ObjectKind::Table));
        vm.remove_root(root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(upvalue), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_upvalue_active_callee_survives_caller_binding_clear_and_gc() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f; local t={v=7}; f=function() f=nil; local x={}; return t.v end; local z=f(); return z";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let produced = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut candidate = produced.module().clone();
        let child = candidate.prototypes[1].id;
        let child_code = &candidate.prototypes[1].instructions;
        let set = child_code
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::SetUpvalue { .. }))
            .unwrap();
        let allocation = child_code
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::NewTable { .. }))
            .unwrap();
        let get = child_code
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::GetUpvalue { .. }))
            .unwrap();
        assert!(set < allocation && allocation < get);
        let root = &mut candidate.prototypes[0];
        let f = root.binding_registers[1].1;
        let table = root.binding_registers[2].1;
        let key = Register(root.register_count - 2);
        let value = Register(root.register_count - 1);
        root.constants = vec![
            BytecodeConstant::Name(b"v".to_vec()),
            BytecodeConstant::Integer(7),
        ];
        root.instructions = vec![
            Instruction::NewTable { dest: table },
            Instruction::LoadConst {
                dest: key,
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: value,
                constant: ConstId(1),
            },
            Instruction::SetTable { table, key, value },
            Instruction::Closure {
                dest: f,
                proto: child,
            },
            Instruction::Call {
                base: f,
                arg_count: 0,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::Return {
                base: f,
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span: candidate.span,
            close_path: None,
        })
        .collect();
        let verified =
            verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified.clone()).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Call { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let call_pc = execution.frame.pc;
        let roots_before = execution.vm.roots().total_count();
        let ledger_before = execution.vm.ledger_snapshot();
        for point in [FailPoint::RootReserve, FailPoint::CallFrameReserve] {
            execution.vm.inject_failure_once(point);
            assert_eq!(
                execution.dispatch_one().err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(execution.frame.pc, call_pc);
            assert_eq!(execution.callers.len(), 0);
            assert_eq!(execution.vm.roots().total_count(), roots_before);
            assert_eq!(execution.vm.ledger_snapshot(), ledger_before);
        }
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.callers.len(), 1);
        assert!(execution.frame.closure_root.is_some());
        let active = execution.frame.closure.unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::NewTable { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.callers[0].read(f), Ok(Value::Nil));
        execution.vm.collect().unwrap();
        assert_eq!(
            execution.vm.object_kind(active),
            Ok(crate::ObjectKind::Closure)
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_scope_close_closes_captured_local_before_frame_exit() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f; do local x={v=7}; f=function() return x.v end end; local y={}; local z=f(); return z";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let close_pc = verified.module().prototypes[0]
            .instructions
            .iter()
            .position(|entry| {
                matches!(entry.instruction, Instruction::Close { count: 0, .. })
                    && entry.close_path.is_none()
            })
            .expect("captured local 須在詞法作用域退出時產生 count0 Close");
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let mut captured = None;
        while execution.pc() < close_pc {
            let instruction = execution.prototype().instructions[execution.pc()]
                .instruction
                .clone();
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            if let Instruction::Closure { dest, .. } = instruction {
                let Value::Object(closure) = execution.frame.read(dest).unwrap() else {
                    panic!("captured closure 須是 heap 物件")
                };
                captured = Some(closure);
            }
        }
        assert_eq!(execution.frame.depth, 0);
        let upvalue = execution
            .vm
            .with_closure(captured.unwrap(), |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        assert!(matches!(
            execution.vm.upvalue_state(upvalue),
            Ok(UpvalueState::Open { .. })
        ));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        let UpvalueState::Closed(Value::Object(table)) =
            execution.vm.upvalue_state(upvalue).unwrap()
        else {
            panic!("作用域退出後且 frame 尚存活時 captured upvalue 必須 Closed")
        };
        execution.vm.collect().unwrap();
        assert_eq!(
            execution.vm.object_kind(table),
            Ok(crate::ObjectKind::Table)
        );
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        drop(execution);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_scope_close_precedes_tbc_pending_close() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f; do local x={v=7}; local c <close> = nil; f=function() return x.v end end; return f";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let root = &verified.module().prototypes[0];
        let close_pc = root
            .instructions
            .iter()
            .position(|entry| {
                matches!(entry.instruction, Instruction::Close { count: 0, .. })
                    && entry.close_path.is_none()
            })
            .unwrap();
        assert!(matches!(
            root.instructions[close_pc + 1].instruction,
            Instruction::Close { count: 1, .. }
        ));
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let mut captured = None;
        while execution.pc() < close_pc {
            let instruction = execution.prototype().instructions[execution.pc()]
                .instruction
                .clone();
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            if let Instruction::Closure { dest, .. } = instruction {
                let Value::Object(closure) = execution.frame.read(dest).unwrap() else {
                    panic!("captured closure 須有物件身分")
                };
                captured = Some(closure);
            }
        }
        let upvalue = execution
            .vm
            .with_closure(captured.unwrap(), |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        assert!(matches!(
            execution.vm.upvalue_state(upvalue),
            Ok(UpvalueState::Open { .. })
        ));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        let UpvalueState::Closed(Value::Object(table)) =
            execution.vm.upvalue_state(upvalue).unwrap()
        else {
            panic!("實際 close handler 前 captured upvalue 須先 Closed")
        };
        assert!(execution.frame.open_upvalues.is_empty());
        assert_eq!(execution.frame.close_entries.len(), 1);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert!(execution.frame.close_entries.is_empty());
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("scope close 後須回傳 closure")
        };
        let Value::Object(returned_closure) = values[0] else {
            panic!("scope close 後須回傳 closure")
        };
        let closure_root = crate::HostHandle::<Value>::new(execution.vm, returned_closure).unwrap();
        execution.vm.collect().unwrap();
        assert_eq!(
            execution.vm.object_kind(table),
            Ok(crate::ObjectKind::Table)
        );
        drop(closure_root);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_scope_close_preserves_shared_getter_setter_state() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local t={}; do local x=3; t.get=function() return x end; t.set=function() x=9 end end; local a=t.get(); t.set(); local b=t.get(); return a,b";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let close_pc = verified.module().prototypes[0]
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::Close { count: 0, .. }))
            .unwrap();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let mut closures = Vec::new();
        while execution.pc() < close_pc {
            let instruction = execution.prototype().instructions[execution.pc()]
                .instruction
                .clone();
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            if let Instruction::Closure { dest, .. } = instruction {
                let Value::Object(closure) = execution.frame.read(dest).unwrap() else {
                    panic!("getter/setter 須是 closure")
                };
                closures.push(closure);
            }
        }
        assert_eq!(closures.len(), 2);
        let first = execution
            .vm
            .with_closure(closures[0], |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        let second = execution
            .vm
            .with_closure(closures[1], |closure| closure.upvalue(0))
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(
            execution.vm.upvalue_state(first),
            Ok(UpvalueState::Closed(Value::Integer(3)))
        );
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(3),
                Value::Integer(9)
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_3_return_adjustment_fixed_parameter_registers() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(a,b) return a,b end; local x,y=f(7); return x,y";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert_eq!(verified.module().prototypes[1].parameter_count, 2);
        assert_eq!(
            verified.module().prototypes[1].binding_registers[0].1,
            Register(1)
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7), Value::Nil]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p09_3_return_adjustment_fixed_parameter_count_and_setter() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        for (source, expected) in [
            (
                b"local f=function(a,b) return a,b end; local x,y=f(); return x,y".as_slice(),
                vec![Value::Nil, Value::Nil],
            ),
            (
                b"local f=function(a,b) return a,b end; local x,y=f(7,8); return x,y".as_slice(),
                vec![Value::Integer(7), Value::Integer(8)],
            ),
            (
                b"local f=function(a,b) return a,b end; local x,y=f(7,8,9); return x,y".as_slice(),
                vec![Value::Integer(7), Value::Integer(8)],
            ),
            (
                b"local x=1; local set=function(v) x=v end; set(9); return x".as_slice(),
                vec![Value::Integer(9)],
            ),
        ] {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let verified = emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)));
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn p09_3_return_adjustment_vararg_preserves_tail_nil() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(a,...) return a,... end; local w,x,y,z=f(7,nil,9,nil); return w,x,y,z";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert!(verified.module().prototypes[1].is_variadic);
        assert_eq!(verified.module().prototypes[1].parameter_count, 1);
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Nil,
                Value::Integer(9),
                Value::Nil,
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p09_3_return_adjustment_vararg_fixed_expansion() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(a,...) local x,y,z=...; return a,x,y,z end; local w,x,y,z=f(7,nil,9,nil); return w,x,y,z";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Nil,
                Value::Integer(9),
                Value::Nil,
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_3_return_adjustment_vararg_all_zero_and_tail_nil() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        for (source, expected) in [
            (
                b"local f=function(...) return ... end; local x,y,z=f(); return x,y,z".as_slice(),
                vec![Value::Nil, Value::Nil, Value::Nil],
            ),
            (
                b"local f=function(...) return ... end; local x,y,z=f(1,nil,3); return x,y,z"
                    .as_slice(),
                vec![Value::Integer(1), Value::Nil, Value::Integer(3)],
            ),
        ] {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let verified = emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)));
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn p09_3_return_adjustment_vararg_root_survives_gc() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f; local o={v=7}; f=function(...) o=nil; local x={}; local y=...; return y.v end; local z=f(o); return z";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_3_return_adjustment_vararg_storage_failure_rolls_back() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        let before = execution.vm.ledger_snapshot();
        let roots_before = execution.vm.roots().total_count();
        execution
            .vm
            .inject_failure_once(FailPoint::FrameRootsReserve);
        assert_eq!(
            execution
                .frame
                .set_varargs(execution.vm, &[Value::Integer(1), Value::Nil])
                .unwrap_err()
                .kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::FrameRootsReserve))
        );
        assert!(execution.frame.varargs.is_empty());
        assert!(execution.frame.vararg_roots.is_empty());
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        execution.vm.allocation_ledger().set_limit(before.committed);
        assert_eq!(
            execution
                .frame
                .set_varargs(execution.vm, &[Value::Integer(1), Value::Nil])
                .unwrap_err()
                .kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        assert!(execution.frame.varargs.is_empty());
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.vm.allocation_ledger().set_limit(before.limit);
        execution
            .frame
            .set_varargs(execution.vm, &[Value::Integer(1), Value::Nil])
            .unwrap();
        assert_eq!(execution.frame.varargs, [Value::Integer(1), Value::Nil]);
        assert!(execution.vm.ledger_snapshot().committed > before.committed);
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
        assert_eq!(execution.vm.ledger_snapshot().committed, 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p09_3_return_adjustment_vararg_fixed_zero_one_and_padding() {
        for (count, expected) in [
            (0, vec![]),
            (1, vec![Value::Integer(7)]),
            (3, vec![Value::Integer(7), Value::Nil, Value::Nil]),
        ] {
            let mut candidate = module(
                vec![Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                }],
                vec![],
            )
            .module()
            .clone();
            candidate.prototypes[0].is_variadic = true;
            candidate.prototypes[0].instructions = vec![
                BytecodeInstruction {
                    instruction: Instruction::Vararg {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(count),
                    },
                    span: candidate.span,
                    close_path: None,
                },
                BytecodeInstruction {
                    instruction: Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(count),
                    },
                    span: candidate.span,
                    close_path: None,
                },
            ];
            let verified =
                verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            execution
                .frame
                .set_varargs(execution.vm, &[Value::Integer(7), Value::Nil])
                .unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)));
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn p09_3_return_adjustment_vararg_all_exact_result_count() {
        for (values, expected) in [
            (vec![], vec![]),
            (vec![Value::Nil], vec![Value::Nil]),
            (
                vec![Value::Nil, Value::Integer(1), Value::Nil],
                vec![Value::Nil, Value::Integer(1), Value::Nil],
            ),
        ] {
            let mut candidate = module(
                vec![Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                }],
                vec![],
            )
            .module()
            .clone();
            candidate.prototypes[0].is_variadic = true;
            candidate.prototypes[0].instructions = vec![
                BytecodeInstruction {
                    instruction: Instruction::Vararg {
                        base: Register(0),
                        result_mode: ResultMode::All,
                    },
                    span: candidate.span,
                    close_path: None,
                },
                BytecodeInstruction {
                    instruction: Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::All,
                    },
                    span: candidate.span,
                    close_path: None,
                },
            ];
            let verified =
                verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            execution.frame.set_varargs(execution.vm, &values).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)));
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn p09_3_dynamic_call_arguments_vm_expands_last_result() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(...) return ... end; local g=function() return 1,2 end; local a,b,c=f(9,g()); return a,b,c";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(9),
                Value::Integer(1),
                Value::Integer(2),
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_named_vararg_table_mutation_reloads_current_n() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(...va) local a,b=...; va[1]=9; va.n=1; local c=...; return a,b,c end; local a,b,c=f(1,2); return a,b,c";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert!(
            verified
                .module()
                .prototypes
                .iter()
                .any(|prototype| prototype.named_vararg.is_some())
        );
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(9),
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_named_vararg_frame_entry_failures_rollback() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(...va) return ... end; local a=f(1,2); return a";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let prototype = verified
            .module()
            .prototypes
            .iter()
            .find(|prototype| prototype.named_vararg.is_some())
            .unwrap();
        let mut vm = Vm::new().unwrap();
        for _ in 0..8 {
            vm.allocate(Value::Nil).unwrap();
        }
        vm.collect().unwrap();
        let mut frame = CallFrame::new(prototype, 0, None, vm.allocation_ledger()).unwrap();
        let binding = frame.named_vararg.unwrap();
        let before = vm.ledger_snapshot();
        for point in [
            FailPoint::TableArrayReserve,
            FailPoint::TableHashReserve,
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
            FailPoint::TableInsert,
            FailPoint::StringBytesReserve,
        ] {
            vm.inject_failure_once(point);
            assert_eq!(
                frame
                    .set_named_varargs(&mut vm, &[Value::Integer(1), Value::Integer(2)])
                    .unwrap_err()
                    .kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point)),
            );
            assert_eq!(frame.read(binding), Ok(Value::Nil));
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot(), before);
        }
        vm.inject_failure_once(FailPoint::TableInsert);
        assert_eq!(
            frame.set_named_varargs(&mut vm, &[]).unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::TableInsert)),
        );
        assert_eq!(frame.read(binding), Ok(Value::Nil));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        vm.set_allocation_limit(before.committed);
        assert_eq!(
            frame
                .set_named_varargs(&mut vm, &[Value::Integer(1), Value::Integer(2)])
                .unwrap_err()
                .kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed),
        );
        vm.set_allocation_limit(before.limit);
        assert_eq!(frame.read(binding), Ok(Value::Nil));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);

        frame
            .set_named_varargs(&mut vm, &[Value::Integer(1), Value::Integer(2)])
            .unwrap();
        let Value::Object(table) = frame.read(binding).unwrap() else {
            panic!("具名 vararg binding 須保存 table")
        };
        assert_eq!(vm.raw_get(table, Value::Integer(2)), Ok(Value::Integer(2)));
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Ok(crate::ObjectKind::Table));
        frame.clear_roots(&mut vm).unwrap();
        drop(frame);
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_named_vararg_enter_call_failure_keeps_caller() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(...va) return ... end; local a=f(1,2); return a";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        for _ in 0..8 {
            vm.allocate(Value::Nil).unwrap();
        }
        vm.collect().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Call { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let before_pc = execution.pc();
        let before_roots = execution.vm.roots().total_count();
        let before_ledger = execution.vm.ledger_snapshot();
        for point in [FailPoint::TableInsert, FailPoint::StringBytesReserve] {
            execution.vm.inject_failure_once(point);
            assert_eq!(
                execution.dispatch_one().err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point)),
            );
            assert_eq!(execution.pc(), before_pc);
            assert_eq!(execution.callers.len(), 0);
            assert_eq!(execution.vm.roots().total_count(), before_roots);
            assert_eq!(execution.vm.ledger_snapshot(), before_ledger);
        }
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(1)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_named_vararg_tail_call_local() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function f(...va) va[1]=9; va.n=1; return ... end; return f(1,2)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert!(
            verified.module().prototypes[0]
                .instructions
                .iter()
                .any(|entry| {
                    matches!(
                        entry.instruction,
                        Instruction::TailCall {
                            result_mode: ResultMode::All,
                            ..
                        }
                    )
                })
        );
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(9)]))
        );
        assert_eq!(execution.peak_frame_count(), 1);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_named_vararg_original_global_requires_host_environment() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"function f(...va) va[1]=9; va.n=1; return ... end; return f(1,2)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert_eq!(
            verified.module().prototypes[0].frame.environment_source,
            EnvironmentSource::RootExternal
        );
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(verified, Value::Object(environment))
            .unwrap();
        execution.vm.remove_root(environment_root).unwrap();
        execution.vm.collect().unwrap();
        assert_eq!(
            execution.vm.object_kind(environment),
            Ok(crate::ObjectKind::Table)
        );
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(9)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_4_host_environment_rejects_invalid_handles_and_recovers_failed_load() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"function f(...va) return ... end; return f(1,2)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut legacy = Vm::new().unwrap();
        let mut legacy_execution = legacy.load(verified.clone()).unwrap();
        let Ok(RunOutcome::LuaError(error)) = legacy_execution.run() else {
            panic!("既有 load 不提供環境，原有 nil 行為須保留")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Heap(VmError::WrongObjectType));
        drop(legacy_execution);
        assert_eq!(legacy.roots().count(RootKind::Host), 1);
        drop(error);
        assert_eq!(legacy.roots().total_count(), 0);
        let mut vm = Vm::new().unwrap();
        let mut other = Vm::new().unwrap();
        let foreign = other.allocate_table().unwrap();
        assert_eq!(
            vm.load_with_environment(verified.clone(), Value::Object(foreign))
                .err()
                .unwrap()
                .kind,
            RuntimeErrorKind::Heap(VmError::WrongVm)
        );
        let stale = vm.allocate_table().unwrap();
        vm.collect().unwrap();
        assert_eq!(
            vm.load_with_environment(verified.clone(), Value::Object(stale))
                .err()
                .unwrap()
                .kind,
            RuntimeErrorKind::Heap(VmError::StaleObject)
        );
        let wrong_type = vm.allocate_byte_string(b"env").unwrap();
        assert_eq!(
            vm.load_with_environment(verified.clone(), Value::Object(wrong_type))
                .err()
                .unwrap()
                .kind,
            RuntimeErrorKind::Heap(VmError::WrongObjectType)
        );
        assert_eq!(
            vm.load_with_environment(verified.clone(), Value::Nil)
                .err()
                .unwrap()
                .kind,
            RuntimeErrorKind::Heap(VmError::WrongObjectType)
        );
        for _ in 0..8 {
            vm.allocate(Value::Nil).unwrap();
        }
        vm.collect().unwrap();
        let environment = vm.allocate_table().unwrap();
        let host_root = vm.add_root(RootKind::Host, environment).unwrap();
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        for point in [
            FailPoint::RootReserve,
            FailPoint::ObjectInitialize,
            FailPoint::FrameRootsReserve,
        ] {
            vm.inject_failure_once(point);
            assert_eq!(
                vm.load_with_environment(verified.clone(), Value::Object(environment))
                    .err()
                    .unwrap()
                    .kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.object_kind(environment), Ok(crate::ObjectKind::Table));
        }
        vm.set_allocation_limit(before.committed);
        assert_eq!(
            vm.load_with_environment(verified.clone(), Value::Object(environment))
                .err()
                .unwrap()
                .kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        vm.set_allocation_limit(before.limit);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot(), before);

        let mut execution = vm
            .load_with_environment(verified.clone(), Value::Object(environment))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2)
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), roots);
        vm.remove_root(host_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut unrooted = Vm::new().unwrap();
        let table = unrooted.allocate_table().unwrap();
        unrooted.set_collect_every_allocation(true);
        let mut execution = unrooted
            .load_with_environment(verified, Value::Object(table))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2)
            ]))
        );
        drop(execution);
        assert_eq!(unrooted.roots().total_count(), 0);
    }

    #[test]
    fn p09_4_named_vararg_non_tail_call_late_failure_reclaims_table() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function f(...va) return ... end; local a,b=f(1,2); return a,b";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        for _ in 0..8 {
            vm.allocate(Value::Nil).unwrap();
        }
        vm.collect().unwrap();
        let mut execution = vm.load(verified).unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Call { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let before_pc = execution.pc();
        let before_roots = execution.vm.roots().total_count();
        let before_ledger = execution.vm.ledger_snapshot();
        execution
            .vm
            .inject_failure_once(FailPoint::CallFrameReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::CallFrameReserve)),
        );
        assert_eq!(execution.pc(), before_pc);
        assert_eq!(execution.callers.len(), 0);
        assert_eq!(execution.vm.roots().total_count(), before_roots);
        assert_eq!(execution.vm.ledger_snapshot(), before_ledger);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2)
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_5_tail_call_reuses_frame_for_large_recursion() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source =
            b"local function f(n) if n==0 then return 7 end return f(n-1) end; return f(1500)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert!(verified.module().prototypes.iter().any(|prototype| {
            prototype
                .instructions
                .iter()
                .any(|entry| matches!(entry.instruction, Instruction::TailCall { .. }))
        }));
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(100_000).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        assert_eq!(execution.peak_frame_count(), 1);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_5_tail_call_non_tail_limit_and_pending_path() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let non_tail = b"local function f(n) if n==0 then return 0 end local x=f(n-1); return x+1 end; return f(1100)";
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(compile(non_tail)).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("非尾遞迴須受控超限")
        };
        assert_eq!(error.diagnostic_id, "E_STACK_LIMIT");
        assert_eq!(execution.peak_frame_count(), 1025);
        drop(execution);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        drop(error);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let pending = b"local f=function() return nil,1,nil end; do local a <close> = nil; do local b <close> = nil; return f() end end";
        let verified = compile(pending);
        let root = &verified.module().prototypes[0];
        let call = root
            .instructions
            .iter()
            .position(|entry| {
                matches!(
                    entry.instruction,
                    Instruction::Call {
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            })
            .unwrap();
        let path = root.instructions[call + 1].close_path.clone().unwrap();
        assert_eq!(path.bindings.len(), 2);
        assert_eq!(root.instructions[call + 2].close_path.as_ref(), Some(&path));
        assert!(matches!(
            root.instructions[call + 3].instruction,
            Instruction::Return {
                result_mode: ResultMode::All,
                ..
            }
        ));
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..100 {
            if execution.frame.prototype == 0 && execution.pc() == call + 1 {
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pc(), call + 1);
        let snapshot = execution.close_snapshot().unwrap();
        assert_eq!(execution.peak_frame_count(), 2);
        assert_eq!(snapshot.path_start_pc, call + 1);
        assert_eq!(snapshot.next_binding, path.bindings[0]);
        assert_eq!(snapshot.next_register, path.registers[0]);
        assert_eq!(snapshot.return_mode, Some(ResultMode::All));
        assert_eq!(snapshot.result_count, 3);
        assert!(snapshot.retained_root_count >= 3);
        let base = snapshot.return_base.unwrap();
        assert_eq!(execution.frame.read(base), Ok(Value::Nil));
        assert_eq!(
            execution.frame.read(Register(base.0 + 1)),
            Ok(Value::Integer(1))
        );
        assert_eq!(execution.frame.read(Register(base.0 + 2)), Ok(Value::Nil));
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Nil,
                Value::Integer(1),
                Value::Nil
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_5_tail_call_precommit_failures_keep_frame_and_roots() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source =
            b"local function f(n) if n==0 then return 7 end return f(n-1) end; return f(4)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::TailCall { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let before_pc = execution.pc();
        let before_roots = execution.vm.roots().total_count();
        let before_ledger = execution.vm.ledger_snapshot();
        for point in [
            FailPoint::FrameRegistersReserve,
            FailPoint::FrameRootsReserve,
            FailPoint::RootReserve,
        ] {
            execution.vm.inject_failure_once(point);
            assert_eq!(
                execution.dispatch_one().err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(execution.pc(), before_pc);
            assert_eq!(execution.callers.len(), 0);
            assert_eq!(execution.vm.roots().total_count(), before_roots);
            assert_eq!(execution.vm.ledger_snapshot(), before_ledger);
        }
        execution.vm.set_allocation_limit(before_ledger.committed);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        execution.vm.set_allocation_limit(before_ledger.limit);
        assert_eq!(execution.pc(), before_pc);
        assert_eq!(execution.vm.roots().total_count(), before_roots);
        assert_eq!(execution.vm.ledger_snapshot(), before_ledger);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.callers.len(), 0);
        assert_eq!(execution.peak_frame_count(), 1);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_3_dynamic_call_arguments_growth_failure_preserves_top_roots_and_ledger() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local f=function(...) return ... end; local g=function() return 1,2,3,4,5,6,7,8,9,10 end; local a,b=f(g()); return a,b";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        while execution.frame.depth == 0 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Return { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let caller_limit = execution.callers.last().unwrap().register_limit;
        let caller_top = execution.callers.last().unwrap().dynamic_top;
        assert!(
            caller_limit < execution.frame.base + 10,
            "十個 open results 須觸發 caller storage 增長"
        );
        let roots_before = execution.vm.roots().total_count();
        let ledger_before = execution.vm.ledger_snapshot();
        let pc_before = execution.frame.pc;
        let result_bytes = 10 * core::mem::size_of::<Value>();
        execution
            .vm
            .allocation_ledger()
            .set_limit(ledger_before.committed + result_bytes);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        execution
            .vm
            .allocation_ledger()
            .set_limit(ledger_before.limit);
        assert_eq!(execution.frame.pc, pc_before);
        assert_eq!(
            execution.callers.last().unwrap().register_limit,
            caller_limit
        );
        assert_eq!(execution.callers.last().unwrap().dynamic_top, caller_top);
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot(), ledger_before);
        execution
            .vm
            .inject_failure_once(FailPoint::FrameRootsReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::FrameRootsReserve))
        );
        assert_eq!(execution.frame.pc, pc_before);
        assert_eq!(
            execution.callers.last().unwrap().register_limit,
            caller_limit
        );
        assert_eq!(execution.callers.last().unwrap().dynamic_top, caller_top);
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot(), ledger_before);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2)
            ]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p09_2_upvalue_capture_failures_preserve_frame_roots_and_ledger() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        let source = b"local function make() local x=7; return function() return x end end; local f=make(); return f";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut probe = Vm::new().unwrap();
        for _ in 0..8 {
            probe.allocate(Value::Nil).unwrap();
        }
        assert_eq!(probe.collect().unwrap(), 8);
        let baseline = probe.ledger_snapshot();
        for point in [
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
            FailPoint::FrameRegistersReserve,
        ] {
            probe.inject_failure_once(point);
            assert_eq!(
                probe.load(verified.clone()).err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(probe.roots().total_count(), 0);
            assert_eq!(probe.collect().unwrap(), 0);
            assert_eq!(probe.ledger_snapshot(), baseline);
        }
        probe.set_allocation_limit(baseline.committed);
        assert_eq!(
            probe.load(verified.clone()).err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        assert_eq!(probe.roots().total_count(), 0);
        assert_eq!(probe.ledger_snapshot().reserved, 0);
        let mut vm = Vm::new().unwrap();
        for _ in 0..8 {
            vm.allocate(Value::Nil).unwrap();
        }
        assert_eq!(vm.collect().unwrap(), 8);
        let mut execution = vm.load(verified).unwrap();
        while !matches!(
            execution.prototype().instructions[execution.frame.pc].instruction,
            Instruction::Closure {
                proto: ProtoId(2),
                ..
            }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let before_pc = execution.frame.pc;
        let before_roots = execution.vm.roots().total_count();
        let before_ledger = execution.vm.ledger_snapshot();
        for point in [
            FailPoint::ClosureCapturesReserve,
            FailPoint::OpenUpvaluesReserve,
            FailPoint::RootReserve,
        ] {
            execution.vm.inject_failure_once(point);
            assert_eq!(
                execution.dispatch_one().err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            assert_eq!(execution.frame.pc, before_pc);
            assert!(execution.frame.open_upvalues.is_empty());
            assert_eq!(execution.vm.roots().total_count(), before_roots);
            assert_eq!(execution.vm.ledger_snapshot(), before_ledger);
        }
        execution.vm.set_allocation_limit(before_ledger.committed);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        assert_eq!(execution.frame.pc, before_pc);
        assert_eq!(execution.vm.roots().total_count(), before_roots);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.vm.set_allocation_limit(usize::MAX);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert!(matches!(execution.run(), Ok(RunOutcome::Returned(_))));
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    fn module(
        instructions: Vec<Instruction>,
        constants: Vec<BytecodeConstant>,
    ) -> rivetlua_core::VerifiedModule {
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 10,
        };
        let candidate = BytecodeModule {
            format_version: RVLU_V2,
            profile: LuaProfile::Lua55,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 3,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 4096,
                    initial_top: Register(3),
                    dynamic_top: Register(3),
                    return_base: Register(0),
                    environment: Register(2),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(2),
                global_environment_binding: BytecodeBindingId {
                    function: 0,
                    ordinal: 0,
                },
                binding_registers: vec![(
                    BytecodeBindingId {
                        function: 0,
                        ordinal: 0,
                    },
                    Register(2),
                )],
                constants,
                upvalues: vec![],
                instructions: instructions
                    .into_iter()
                    .map(|instruction| BytecodeInstruction {
                        instruction,
                        span,
                        close_path: None,
                    })
                    .collect(),
                close_paths: vec![],
            }],
        };
        verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap()
    }

    fn numeric_for_candidate(
        instructions: Vec<Instruction>,
        constants: Vec<BytecodeConstant>,
    ) -> BytecodeModule {
        let mut candidate = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        )
        .module()
        .clone();
        let span = candidate.span;
        let root = &mut candidate.prototypes[0];
        root.register_count = 6;
        root.frame.initial_top = Register(6);
        root.frame.dynamic_top = Register(6);
        root.frame.environment = Register(5);
        root.global_environment = Register(5);
        root.binding_registers[0].1 = Register(5);
        root.constants = constants;
        root.instructions = instructions
            .into_iter()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect();
        candidate
    }

    fn numeric_for_module(
        initial: BytecodeConstant,
        limit: BytecodeConstant,
        step: BytecodeConstant,
    ) -> rivetlua_core::VerifiedModule {
        let instructions = vec![
            Instruction::LoadConst {
                dest: Register(0),
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: Register(1),
                constant: ConstId(1),
            },
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(2),
            },
            Instruction::NumericForPrepare {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                exit: InstructionOffset(6),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(3),
            },
            Instruction::NumericForNext {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                target: InstructionOffset(4),
                exit: InstructionOffset(6),
            },
            Instruction::Return {
                base: Register(4),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        verify_module(
            numeric_for_candidate(instructions, vec![initial, limit, step]),
            LuaProfile::Lua55,
            &VerifyLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn raw_table_string_constant_loads_full_bytes_through_value_object() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::String(vec![0, 0x80, 0xff])],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("測試需要正常回傳")
        };
        drop(execution);
        let [Value::Object(object)] = values.as_slice() else {
            panic!("字串常數須以 heap object 回傳")
        };
        vm.with_byte_string(*object, |string| {
            assert_eq!(string.as_bytes(), [0, 0x80, 0xff])
        })
        .unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn raw_table_vm_previous_write_survives_later_nil_key_lua_error() {
        let verified = module(
            vec![
                Instruction::NewTable { dest: Register(0) },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(1),
                },
                Instruction::SetTable {
                    table: Register(0),
                    key: Register(1),
                    value: Register(2),
                },
                Instruction::LoadNil {
                    start: Register(1),
                    count: 1,
                },
                Instruction::SetTable {
                    table: Register(0),
                    key: Register(1),
                    value: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![
                BytecodeConstant::Name(b"x".to_vec()),
                BytecodeConstant::Integer(1),
            ],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..4 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let Value::Object(table) = execution.frame.read(Register(0)).unwrap() else {
            panic!("NewTable 須產生 heap object")
        };
        let root = execution.vm.add_root(RootKind::Host, table).unwrap();
        let RunOutcome::LuaError(error) = execution.run().unwrap() else {
            panic!("nil 寫鍵須為 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Heap(VmError::NilTableKey));
        assert_eq!(error.diagnostic_id, "E_TABLE_KEY_NIL");
        drop(execution);
        let key = vm.allocate_byte_string(b"x").unwrap();
        assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Integer(1)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        drop(error);
        assert_eq!(vm.collect().unwrap(), 4);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn raw_table_vm_nan_key_is_lua_error() {
        let verified = module(
            vec![
                Instruction::NewTable { dest: Register(0) },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(1),
                },
                Instruction::SetTable {
                    table: Register(0),
                    key: Register(1),
                    value: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![
                BytecodeConstant::FloatBits(f64::NAN.to_bits()),
                BytecodeConstant::Integer(1),
            ],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        let RunOutcome::LuaError(error) = execution.run().unwrap() else {
            panic!("NaN 寫鍵須為 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Heap(VmError::NaNTableKey));
        assert_eq!(error.diagnostic_id, "E_TABLE_KEY_NAN");
        drop(execution);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        drop(error);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let after_collect = vm.ledger_snapshot();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.ledger_snapshot(), after_collect);
    }

    #[test]
    fn raw_table_vm_new_payload_root_failure_reclaims_object() {
        for (instruction, constants) in [
            (Instruction::NewTable { dest: Register(0) }, vec![]),
            (
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                vec![BytecodeConstant::String(vec![0, 0x80])],
            ),
        ] {
            let verified = module(
                vec![
                    instruction,
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(0),
                    },
                ],
                constants,
            );
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            execution.vm.inject_failure_once(FailPoint::RootReserve);
            assert_eq!(
                execution.dispatch_one().err().unwrap().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve))
            );
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(
                execution.vm.slot_state(rivetlua_core::SlotId::new(0)),
                Some(crate::SlotState::Free)
            );
            assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
            drop(execution);
            assert_eq!(vm.collect().unwrap(), 0);
        }
    }

    #[test]
    fn table_gc_vm_growth_failure_clears_stack_and_keeps_prior_write() {
        let verified = module(
            vec![
                Instruction::NewTable { dest: Register(0) },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(1),
                },
                Instruction::SetTable {
                    table: Register(0),
                    key: Register(1),
                    value: Register(2),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(2),
                },
                Instruction::SetTable {
                    table: Register(0),
                    key: Register(1),
                    value: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![
                BytecodeConstant::Integer(1),
                BytecodeConstant::Integer(7),
                BytecodeConstant::Integer(5),
            ],
        );
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..5 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let Value::Object(table) = execution.frame.read(Register(0)).unwrap() else {
            panic!("NewTable 須產生 table")
        };
        let root = execution.vm.add_root(RootKind::Host, table).unwrap();
        execution.vm.inject_failure_once(FailPoint::TableArrayGrow);
        let error = execution.run().err().unwrap();
        assert_eq!(
            error.kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::TableArrayGrow))
        );
        assert_eq!(execution.vm.roots().total_count(), 1);
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        assert_eq!(execution.vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        drop(execution);
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(7)));
        assert_eq!(vm.raw_get(table, Value::Integer(5)), Ok(Value::Nil));
        assert_eq!(vm.collect().unwrap(), 0);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn vm_frame_starts_nil_and_checks_register_bounds() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(execution.frame.registers, vec![Value::Nil; 3]);
        assert_eq!(execution.dynamic_top(), 3);
        assert_eq!(
            execution.frame.read(Register(3)),
            Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
        );
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![Value::Nil])));
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_dispatch_checks_pc_and_jump_target() {
        let verified = module(
            vec![
                Instruction::Jump {
                    target: InstructionOffset(2),
                },
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(99)],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![Value::Nil])));
        assert_eq!(execution.pc(), 2);
        drop(execution);

        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.jump_target(InstructionOffset(u32::MAX)),
            Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds
            ))
        );
        execution.frame.pc = usize::MAX;
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds
            ))
        );
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_stack_roots_protect_objects_and_are_released_on_drop() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        {
            let mut execution = vm.load(verified).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
            assert_eq!(execution.vm.collect().unwrap(), 0);
        }
        assert_eq!(vm.roots().count(RootKind::Stack), 0);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn vm_stack_roots_are_released_after_return_and_internal_error() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(9)).unwrap();
        {
            let mut execution = vm.load(verified.clone()).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
            assert_eq!(
                execution.run(),
                Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
            );
        }
        {
            let mut execution = vm.load(verified).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            execution.frame.pc = usize::MAX;
            assert_eq!(
                execution.run(),
                Err(RuntimeError::new(
                    RuntimeErrorKind::ProgramCounterOutOfBounds
                ))
            );
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        }
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn vm_rejected_object_write_preserves_existing_register_and_root() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(1)).unwrap();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        let foreign = rivetlua_core::ObjectRef::new_opaque().unwrap();
        assert!(
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(foreign))
                .is_err()
        );
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Object(object)));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
    }

    #[test]
    fn vm_move_keeps_both_object_registers_rooted_until_return() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(12)).unwrap();
        let object_only = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.frame.read(Register(1)), Ok(Value::Object(object)));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 2);
        assert_eq!(execution.vm.collect().unwrap(), 0);
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        assert_eq!(execution.vm.ledger_snapshot(), object_only);
    }

    #[test]
    fn vm_frame_charge_is_live_until_drop_and_refunded_after_return() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        {
            let mut execution = vm.load(verified.clone()).unwrap();
            assert!(execution.vm.ledger_snapshot().committed > before.committed);
            assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }
        {
            let execution = vm.load(verified).unwrap();
            assert!(execution.vm.ledger_snapshot().committed > before.committed);
            drop(execution);
        }
        assert_eq!(vm.ledger_snapshot(), before);
    }

    #[test]
    fn vm_return_result_respects_remaining_quota_and_releases_frame() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let frame_bytes = execution.vm.ledger_snapshot().committed;
        execution.vm.set_allocation_limit(frame_bytes);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::Heap(
                crate::VmError::AllocationFailed
            )))
        );
        assert_eq!(execution.vm.ledger_snapshot().committed, baseline.committed);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        assert_eq!(execution.vm.roots().total_count(), 0);
    }

    #[test]
    fn vm_return_reserve_failure_is_terminal_and_refunds_frame() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.vm.inject_failure_once(FailPoint::ReturnReserve);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::InjectedFailure(FailPoint::ReturnReserve)
            )))
        );
        assert_eq!(execution.vm.ledger_snapshot(), baseline);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_returned_values_transfer_to_host_without_vm_charge() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let outcome = execution.run().unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Nil]));
        assert_eq!(execution.vm.ledger_snapshot(), baseline);
        drop(execution);
        assert_eq!(vm.ledger_snapshot(), baseline);
        drop(outcome);
        assert_eq!(vm.ledger_snapshot(), baseline);
    }

    #[test]
    fn vm_empty_return_does_not_allocate_a_result_buffer() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let frame_bytes = execution.vm.ledger_snapshot().committed;
        execution.vm.set_allocation_limit(frame_bytes);
        execution.vm.inject_failure_once(FailPoint::ReturnReserve);
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
        assert_eq!(execution.vm.ledger_snapshot().committed, baseline.committed);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn vm_p01_integer_wrap_and_power_float_path() {
        for (constants, op, expected) in [
            (
                vec![
                    BytecodeConstant::Integer(i64::MAX),
                    BytecodeConstant::Integer(1),
                ],
                rivetlua_core::BinaryOperation::Add,
                Value::Integer(i64::MIN),
            ),
            (
                vec![BytecodeConstant::Integer(2), BytecodeConstant::Integer(3)],
                rivetlua_core::BinaryOperation::Power,
                Value::Float(8.0),
            ),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                constants,
            );
            let mut vm = Vm::new().unwrap();
            let baseline = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), baseline);
        }
    }

    #[test]
    fn vm_p01_exact_integer_float_comparison_and_truthy_zero() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Greater,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![
                BytecodeConstant::Integer(9_007_199_254_740_993),
                BytecodeConstant::FloatBits(9_007_199_254_740_992.0_f64.to_bits()),
            ],
        );
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.load(verified).unwrap().run(),
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
        );

        for constant in [
            BytecodeConstant::Integer(0),
            BytecodeConstant::FloatBits(0.0_f64.to_bits()),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::UnaryOp {
                        dest: Register(0),
                        op: rivetlua_core::UnaryOperation::Not,
                        src: Register(0),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![constant],
            );
            assert_eq!(
                vm.load(verified).unwrap().run(),
                Ok(RunOutcome::Returned(vec![Value::Boolean(false)]))
            );
        }
    }

    #[test]
    fn vm_p01_lua_error_is_structured_and_terminal() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("整數除以零須為 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert!(
            matches!(error.kind, RuntimeErrorKind::Core(core) if core.operation == rivetlua_core::Operation::FloorDivide && core.operand == rivetlua_core::ValueKind::Integer && core.kind == rivetlua_core::CoreErrorKind::IntegerDivideByZero)
        );
        assert_eq!(execution.fuel_remaining(), 999_997);
        assert_eq!(execution.pc(), 2);
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        let Value::Object(message) = error.value else {
            panic!("隱含錯誤須持有診斷字串")
        };
        drop(error);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, baseline.reserved);
        assert_reclaimed_diagnostic(execution.vm, message, 1);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_numeric_opcodes_route_to_p01_helpers() {
        use rivetlua_core::BinaryOperation as B;
        for (left, right, op, expected) in [
            (6, 3, B::Subtract, Value::Integer(3)),
            (6, 3, B::Multiply, Value::Integer(18)),
            (6, 3, B::Divide, Value::Float(2.0)),
            (6, 3, B::FloorDivide, Value::Integer(2)),
            (6, 4, B::Modulo, Value::Integer(2)),
            (6, 3, B::Pipe, Value::Integer(7)),
            (6, 3, B::BitXor, Value::Integer(5)),
            (6, 3, B::Ampersand, Value::Integer(2)),
            (1, 2, B::ShiftLeft, Value::Integer(4)),
            (8, 2, B::ShiftRight, Value::Integer(2)),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![
                    BytecodeConstant::Integer(left),
                    BytecodeConstant::Integer(right),
                ],
            );
            let mut vm = Vm::new().unwrap();
            assert_eq!(
                vm.load(verified).unwrap().run(),
                Ok(RunOutcome::Returned(vec![expected]))
            );
        }
    }

    #[test]
    fn vm_p01_type_and_integer_errors_become_lua_errors() {
        for (left, right, op, diagnostic) in [
            (
                BytecodeConstant::Boolean(true),
                BytecodeConstant::Integer(1),
                rivetlua_core::BinaryOperation::Add,
                "E_NOT_NUMERIC",
            ),
            (
                BytecodeConstant::Integer(1),
                BytecodeConstant::Integer(0),
                rivetlua_core::BinaryOperation::Modulo,
                "E_INTEGER_MODULO_BY_ZERO",
            ),
            (
                BytecodeConstant::FloatBits(1.5_f64.to_bits()),
                BytecodeConstant::Integer(1),
                rivetlua_core::BinaryOperation::Ampersand,
                "E_NOT_INTEGER",
            ),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![left, right],
            );
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            let Ok(RunOutcome::LuaError(error)) = execution.run() else {
                panic!("P01 錯誤須變成 LuaError")
            };
            assert_eq!(error.diagnostic_id, diagnostic);
            assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
            drop(error);
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn table_length_vm_invalid_operand_and_concat_missing_event() {
        let unary = module(
            vec![
                Instruction::UnaryOp {
                    dest: Register(0),
                    op: rivetlua_core::UnaryOperation::Length,
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![],
        );
        let binary = module(
            vec![
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Concat,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(unary).unwrap();
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::UnsupportedUnaryOperation(rivetlua_core::UnaryOperation::Length)
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        let mut execution = vm.load(binary).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("缺少 __concat 須是 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::MetamethodAbsent);
    }

    #[test]
    fn vm_condition_branches_and_return_consume_fuel() {
        for (condition, expected, fuel_used) in
            [(false, Value::Nil, 3), (true, Value::Integer(9), 4)]
        {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::JumpIfFalse {
                        condition: Register(0),
                        target: InstructionOffset(3),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::Return {
                        base: Register(1),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![
                    BytecodeConstant::Boolean(condition),
                    BytecodeConstant::Integer(9),
                ],
            );
            let mut vm = Vm::new().unwrap();
            let baseline = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(fuel_used).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 3);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), baseline);
        }
    }

    #[test]
    fn assignment_overlap_and_repeated_source_follow_move_order() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                Instruction::Move {
                    dest: Register(0),
                    src: Register(1),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(2),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(2)],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(2),
                Value::Integer(1)
            ]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(1),
                    result_mode: ResultMode::Fixed(2),
                },
            ],
            vec![BytecodeConstant::Integer(7)],
        );
        assert_eq!(
            vm.load(verified).unwrap().run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(7)
            ]))
        );
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
    }

    #[test]
    fn assignment_prior_write_survives_later_lua_error_without_partial_destination_write() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::Move {
                    dest: Register(0),
                    src: Register(1),
                },
                Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(2),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![
                BytecodeConstant::Integer(10),
                BytecodeConstant::Integer(20),
                BytecodeConstant::Integer(0),
            ],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..4 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pc(), 4);
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(20)));
        let error = execution.dispatch_one().err().unwrap();
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(20)));
        assert_eq!(execution.pc(), 4);
        let Ok(RunOutcome::LuaError(actual)) = execution.run() else {
            panic!("應交付 LuaError")
        };
        assert_eq!(actual.kind, error.kind);
        assert_eq!(actual.diagnostic_id, error.diagnostic_id);
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        let Value::Object(message) = actual.value else {
            panic!("隱含錯誤須持有診斷字串")
        };
        drop(actual);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, before.reserved);
        assert_reclaimed_diagnostic(execution.vm, message, 1);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn assignment_move_root_failure_keeps_destination_and_cleans_existing_root() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(5)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        execution
            .frame
            .write(execution.vm, Register(1), Value::Integer(9))
            .unwrap();
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve))
        );
        assert_eq!(execution.frame.read(Register(1)), Ok(Value::Integer(9)));
        assert_eq!(execution.pc(), 0);
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn numeric_for_prepare_and_next_update_control_visible_and_targets() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(1),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Nil));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.pc(), 4);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Integer(1)));
        for expected in [2, 3] {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            assert_eq!(execution.pc(), 5);
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            assert_eq!(execution.pc(), 4);
            assert_eq!(
                execution.frame.read(Register(0)),
                Ok(Value::Integer(expected))
            );
            assert_eq!(
                execution.frame.read(Register(3)),
                Ok(Value::Integer(expected))
            );
            assert_eq!(execution.frame.read(Register(1)), Ok(Value::Integer(3)));
            assert_eq!(execution.frame.read(Register(2)), Ok(Value::Integer(1)));
        }
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.pc(), 6);
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(3)));
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Integer(3)));
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(3)]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn numeric_for_zero_step_fails_before_visible_write_and_cleans_frame() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(0),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let error = execution.dispatch_one().err().unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::NumericForZeroStep);
        assert_eq!(error.diagnostic_id, "E_NUMERIC_FOR_ZERO_STEP");
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Nil));
        let Ok(RunOutcome::LuaError(actual)) = execution.run() else {
            panic!("應交付 LuaError")
        };
        assert_eq!(actual.kind, error.kind);
        assert_eq!(actual.diagnostic_id, error.diagnostic_id);
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        let Value::Object(message) = actual.value else {
            panic!("隱含錯誤須持有診斷字串")
        };
        drop(actual);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, before.reserved);
        assert_reclaimed_diagnostic(execution.vm, message, 1);
    }

    #[test]
    fn numeric_for_integer_edge_and_fuel_stop_before_next_side_effect() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(i64::MAX - 1),
            BytecodeConstant::Integer(i64::MAX),
            BytecodeConstant::Integer(1),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified.clone()).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(i64::MAX)]))
        );
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(5).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn numeric_for_verifier_rejects_alias_and_unpaired_next() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(1),
        );
        let mut alias = verified.module().clone();
        alias.prototypes[0].instructions[3].instruction = Instruction::NumericForPrepare {
            control: Register(0),
            limit: Register(0),
            step: Register(2),
            visible: Register(3),
            exit: InstructionOffset(6),
        };
        assert!(verify_module(alias, LuaProfile::Lua55, &VerifyLimits::default()).is_err());

        let mut unmatched = verified.module().clone();
        unmatched.prototypes[0].instructions[5].instruction = Instruction::NumericForNext {
            control: Register(0),
            limit: Register(1),
            step: Register(4),
            visible: Register(3),
            target: InstructionOffset(4),
            exit: InstructionOffset(6),
        };
        assert!(verify_module(unmatched, LuaProfile::Lua55, &VerifyLimits::default()).is_err());
    }

    #[test]
    fn numeric_for_next_rejects_unprepared_mixed_mode() {
        let error = numeric_for::next(Value::Integer(1), Value::Float(2.0), Value::Integer(1))
            .err()
            .unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNumericForState);
        assert_eq!(error.diagnostic_id, "E_VM_NUMERIC_FOR_STATE");
        let error = numeric_for::next(Value::Integer(1), Value::Integer(2), Value::Integer(0))
            .err()
            .unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNumericForState);
    }

    #[test]
    fn fuel_linear_dispatch_and_return_each_cost_one() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::LoadNil {
                    start: Register(2),
                    count: 1,
                },
                Instruction::UnaryOp {
                    dest: Register(2),
                    op: rivetlua_core::UnaryOperation::Not,
                    src: Register(2),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Equal,
                    left: Register(1),
                    right: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1)],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified.clone()).unwrap();
        execution.set_fuel(6).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Boolean(false)]))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(5).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn fuel_jump_and_both_conditional_edges_each_cost_one() {
        for (condition, expected) in [(false, Value::Nil), (true, Value::Boolean(true))] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::JumpIfFalse {
                        condition: Register(0),
                        target: InstructionOffset(3),
                    },
                    Instruction::Jump {
                        target: InstructionOffset(4),
                    },
                    Instruction::LoadNil {
                        start: Register(0),
                        count: 1,
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![BytecodeConstant::Boolean(condition)],
            );
            let mut vm = Vm::new().unwrap();
            let before = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(4).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 4);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }
    }

    #[test]
    fn fuel_numeric_for_enter_next_skip_and_return_each_cost_one() {
        for (initial, limit, budget, expected) in
            [(1, 2, 9, Value::Integer(2)), (3, 1, 5, Value::Nil)]
        {
            let verified = numeric_for_module(
                BytecodeConstant::Integer(initial),
                BytecodeConstant::Integer(limit),
                BytecodeConstant::Integer(1),
            );
            let mut vm = Vm::new().unwrap();
            let before = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(budget).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 6);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }

        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(2),
            BytecodeConstant::Integer(0),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(4).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("零 step 預備指令須形成 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::NumericForZeroStep);
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        let Value::Object(message) = error.value else {
            panic!("隱含錯誤須持有診斷字串")
        };
        drop(error);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, before.reserved);
        assert_reclaimed_diagnostic(execution.vm, message, 1);
    }

    #[test]
    fn fuel_zero_prevents_move_root_side_effect_and_releases_frame() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(4)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
        execution.set_fuel(0).unwrap();
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 0);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);
        assert_eq!(
            vm.add_root(RootKind::Temporary, object).err().unwrap(),
            VmError::InjectedFailure(FailPoint::RootReserve)
        );
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn fuel_lua_error_and_early_internal_error_clear_roots_and_terminalize() {
        let lua_error_module = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(lua_error_module).unwrap();
        execution
            .frame
            .write(execution.vm, Register(2), Value::Object(object))
            .unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("整數除零必須形成 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert_eq!(execution.pc(), 2);
        assert_eq!(execution.fuel_remaining(), 999_997);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        let Value::Object(message) = error.value else {
            panic!("隱含錯誤須持有診斷字串")
        };
        drop(error);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot().reserved, before.reserved);
        drop(execution);
        assert_reclaimed_diagnostic(&mut vm, message, 2);

        let internal_module = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let object = vm.allocate(Value::Integer(9)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(internal_module).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        execution.frame.pc = usize::MAX;
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::ProgramCounterOutOfBounds
        );
        assert_eq!(execution.fuel_remaining(), 1_000_000);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn p10_2_regular_access() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &rivetlua_core::VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let proxy = vm.allocate_table().unwrap();
        let key_t = vm.allocate_byte_string(b"t").unwrap();
        let key_x = vm.allocate_byte_string(b"x").unwrap();
        let key_index = vm.allocate_byte_string(b"__index").unwrap();
        vm.raw_set(env, Value::Object(key_t), Value::Object(table))
            .unwrap();
        vm.raw_set(proxy, Value::Object(key_x), Value::Integer(7))
            .unwrap();
        vm.raw_set(metatable, Value::Object(key_index), Value::Object(proxy))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        drop(execution);
        assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));
        vm.raw_set(table, Value::Object(key_x), Value::Boolean(false))
            .unwrap();
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Boolean(false)]))
        );
        drop(execution);
        vm.raw_set(table, Value::Object(key_x), Value::Nil).unwrap();
        let event = {
            let mut execution = vm
                .load(compile(b"return function(self,key) return 5 end"))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得 Lua closure")
            };
            let Value::Object(event) = values[0] else {
                panic!("事件須為 closure")
            };
            event
        };
        vm.raw_set(metatable, Value::Object(key_index), Value::Object(event))
            .unwrap();
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        let target_pc = execution
            .prototype()
            .instructions
            .iter()
            .rposition(|entry| matches!(entry.instruction, Instruction::GetTable { .. }))
            .unwrap();
        while execution.pc() != target_pc {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let before = execution.vm.ledger_snapshot();
        let roots_before = execution.vm.roots().total_count();
        execution
            .vm
            .inject_failure_once(FailPoint::FrameRegistersReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::FrameRegistersReserve))
        );
        assert_eq!(execution.pc(), target_pc);
        assert!(execution.pending_ops.is_empty());
        assert_eq!(execution.callers.len(), 0);
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        let pending = execution.pending_ops.last().unwrap();
        assert_eq!(pending.values[0], Value::Object(table));
        assert_eq!(pending.values[4], Value::Object(event));
        assert_eq!(pending.caller_pc, target_pc);
        assert_eq!(execution.callers.len(), 1);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(5)]))
        );
        drop(execution);
        vm.remove_root(table_root).unwrap();
        vm.remove_root(env_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut vm = Vm::new().unwrap();
        let object = vm.allocate_table().unwrap();
        let baseline = vm.ledger_snapshot();
        let sample = vm.add_root(RootKind::Temporary, object).unwrap();
        let root_charge = vm.ledger_snapshot().committed - baseline.committed;
        vm.remove_root(sample).unwrap();
        vm.set_allocation_limit(baseline.committed + root_charge);
        let limited = vm.ledger_snapshot();
        assert_eq!(
            PendingOp::new(
                &mut vm,
                PendingKind::Table(PendingTableKind::Get),
                [Value::Object(object); 5],
                0,
                0,
                0,
                0,
                None,
                1,
                Register(0),
                ResultMode::Fixed(1),
                0,
                1,
            )
            .err(),
            Some(VmError::AllocationFailed)
        );
        assert_eq!(vm.ledger_snapshot(), limited);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p10_3_pending_op_resume() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &rivetlua_core::VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let bridge = vm.allocate_table().unwrap();
        let outer_mt = vm.allocate_table().unwrap();
        let inner_mt = vm.allocate_table().unwrap();
        let key_t = vm.allocate_byte_string(b"t").unwrap();
        let key_bridge = vm.allocate_byte_string(b"bridge").unwrap();
        let key_index = vm.allocate_byte_string(b"__index").unwrap();
        vm.raw_set(env, Value::Object(key_t), Value::Object(table))
            .unwrap();
        vm.raw_set(table, Value::Object(key_bridge), Value::Object(bridge))
            .unwrap();
        vm.set_metatable(table, Some(outer_mt)).unwrap();
        vm.set_metatable(bridge, Some(inner_mt)).unwrap();
        let outer = {
            let mut execution = vm
                .load(compile(
                    b"return function(self,key) return self.bridge[key]+1 end",
                ))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得外層事件")
            };
            let Value::Object(value) = values[0] else {
                panic!("須為 closure")
            };
            value
        };
        let inner = {
            let mut execution = vm
                .load(compile(b"return function(self,key) return 4,99 end"))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得內層事件")
            };
            let Value::Object(value) = values[0] else {
                panic!("須為 closure")
            };
            value
        };
        vm.raw_set(outer_mt, Value::Object(key_index), Value::Object(outer))
            .unwrap();
        vm.raw_set(inner_mt, Value::Object(key_index), Value::Object(inner))
            .unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        let first_get = execution
            .prototype()
            .instructions
            .iter()
            .rposition(|entry| matches!(entry.instruction, Instruction::GetTable { .. }))
            .unwrap();
        while execution.pc() != first_get {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let ledger_before = execution.vm.ledger_snapshot();
        let roots_before = execution.vm.roots().total_count();
        execution.vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert_eq!(execution.pc(), first_get);
        assert!(execution.pending_ops.is_empty());
        assert_eq!(execution.vm.ledger_snapshot(), ledger_before);
        assert_eq!(execution.vm.roots().total_count(), roots_before);
        for _ in 0..40 {
            let nested_get = matches!(
                execution.prototype().instructions[execution.pc()].instruction,
                Instruction::GetTable { table, .. }
                    if execution.frame.read(table) == Ok(Value::Object(bridge))
            );
            if nested_get {
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pending_ops.len(), 1);
        let nested_pc = execution.pc();
        let nested_ledger = execution.vm.ledger_snapshot();
        let nested_roots = execution.vm.roots().total_count();
        execution.vm.set_allocation_limit(nested_ledger.committed);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        assert_eq!(execution.pc(), nested_pc);
        assert_eq!(execution.pending_ops.len(), 1);
        assert_eq!(execution.vm.roots().total_count(), nested_roots);
        assert_eq!(
            execution.vm.ledger_snapshot().committed,
            nested_ledger.committed
        );
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        execution.vm.set_allocation_limit(nested_ledger.limit);
        for _ in 0..40 {
            if execution
                .pending_ops
                .last()
                .is_some_and(|pending| pending.caller_depth == 1)
            {
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let pending = execution.pending_ops.last().expect("須保留內層 pending");
        assert_eq!(pending.caller_depth, 1);
        assert_eq!(pending.kind, PendingKind::Table(PendingTableKind::Get));
        assert_eq!(pending.stage, ResumeStage::AwaitingReturn);
        assert_eq!(pending.chain_steps, 1);
        assert_eq!(execution.pending_ops.len(), 2);
        assert_eq!(execution.callers.len(), 2);
        let outer_pending = execution.pending_ops.get(0).unwrap();
        assert_eq!(outer_pending.caller_depth, 0);
        assert_eq!(outer_pending.result_mode, ResultMode::Fixed(1));
        assert_eq!(outer_pending.resume_pc, execution.callers[0].pc);
        assert_eq!(pending.result_mode, ResultMode::Fixed(1));
        assert_eq!(pending.resume_pc, execution.callers[1].pc);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(5)]))
        );
        drop(execution);
        let roots_before_drop = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        for _ in 0..40 {
            if execution.pending_ops.len() == 2 {
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pending_ops.len(), 2);
        drop(execution);
        assert_eq!(vm.roots().total_count(), roots_before_drop);
        vm.remove_root(table_root).unwrap();
        vm.remove_root(env_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut vm = Vm::new().unwrap();
        let object = vm.allocate_table().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut stack = PendingStack::new(vm.allocation_ledger().clone());
        let make_pending = |vm: &mut Vm| {
            PendingOp::new(
                vm,
                PendingKind::Table(PendingTableKind::Get),
                [Value::Object(object); 5],
                0,
                0,
                0,
                0,
                None,
                1,
                Register(0),
                ResultMode::Fixed(1),
                0,
                1,
            )
            .unwrap()
        };
        let mut pending = make_pending(&mut vm);
        let rooted = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            stack.prepare_push().err(),
            Some(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert_eq!(vm.ledger_snapshot(), rooted);
        pending.clear(&mut vm).unwrap();
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);

        let mut pending = make_pending(&mut vm);
        let rooted = vm.ledger_snapshot();
        vm.set_allocation_limit(rooted.committed);
        assert_eq!(stack.prepare_push().err(), Some(VmError::AllocationFailed));
        pending.clear(&mut vm).unwrap();
        vm.set_allocation_limit(baseline.limit);
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);

        let pending = make_pending(&mut vm);
        let rooted = vm.ledger_snapshot();
        let prepared = stack.prepare_push().unwrap();
        stack.push_prepared(prepared, pending);
        assert_eq!(stack.len(), 1);
        assert_eq!(
            vm.ledger_snapshot().committed - rooted.committed,
            stack.capacity() * core::mem::size_of::<PendingOp>()
        );
        while stack.len() < stack.capacity() {
            let pending = make_pending(&mut vm);
            let prepared = stack.prepare_push().unwrap();
            stack.push_prepared(prepared, pending);
        }
        let filled = vm.ledger_snapshot();
        let filled_count = stack.len();
        let mut pending = make_pending(&mut vm);
        let prepared = stack.prepare_push().unwrap();
        assert!(vm.ledger_snapshot().committed > filled.committed);
        drop(prepared);
        pending.clear(&mut vm).unwrap();
        assert_eq!(stack.len(), filled_count);
        assert_eq!(vm.ledger_snapshot(), filled);
        let mut pending = make_pending(&mut vm);
        let rooted = vm.ledger_snapshot();
        vm.set_allocation_limit(rooted.committed);
        assert_eq!(stack.prepare_push().err(), Some(VmError::AllocationFailed));
        pending.clear(&mut vm).unwrap();
        vm.set_allocation_limit(baseline.limit);
        assert_eq!(stack.len(), filled_count);
        assert_eq!(vm.ledger_snapshot(), filled);
        let mut pending = make_pending(&mut vm);
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            stack.prepare_push().err(),
            Some(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        pending.clear(&mut vm).unwrap();
        assert_eq!(stack.len(), filled_count);
        assert_eq!(vm.ledger_snapshot(), filled);
        stack.clear(&mut vm).unwrap();
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p10_4_metamethod_events() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &rivetlua_core::VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        let target = vm.allocate_table().unwrap();
        let target_root = vm.add_root(RootKind::Host, target).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key_t = vm.allocate_byte_string(b"t").unwrap();
        let key_x = vm.allocate_byte_string(b"x").unwrap();
        let key_call = vm.allocate_byte_string(b"__call").unwrap();
        vm.raw_set(env, Value::Object(key_t), Value::Object(target))
            .unwrap();
        vm.raw_set(target, Value::Object(key_x), Value::Integer(7))
            .unwrap();
        vm.set_metatable(target, Some(metatable)).unwrap();
        let closure = {
            let mut execution = vm
                .load(compile(b"return function(self,a,b) return a+b,self.x end"))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得 __call closure")
            };
            let Value::Object(closure) = values[0] else {
                panic!("須回傳 closure")
            };
            closure
        };
        vm.raw_set(metatable, Value::Object(key_call), Value::Object(closure))
            .unwrap();
        let mut execution = vm
            .load_with_environment(compile(b"local a,b=t(3,4); return a,b"), Value::Object(env))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(7)
            ]))
        );
        drop(execution);
        let roots_before_failure = vm.roots().total_count();
        for (point, source) in [
            (FailPoint::WorkReserve, b"return t(3,4)".as_slice()),
            (FailPoint::CallFrameReserve, b"local a,b=t(3,4); return a,b"),
        ] {
            let mut execution = vm
                .load_with_environment(compile(source), Value::Object(env))
                .unwrap();
            execution.vm.inject_failure_once(point);
            assert_eq!(
                execution.run().unwrap_err().kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            drop(execution);
            assert_eq!(vm.roots().total_count(), roots_before_failure);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        let mut execution = vm
            .load_with_environment(compile(b"return t(3,4)"), Value::Object(env))
            .unwrap();
        let committed = execution.vm.ledger_snapshot().committed;
        execution.vm.set_allocation_limit(committed);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        drop(execution);
        vm.set_allocation_limit(usize::MAX);
        assert_eq!(vm.roots().total_count(), roots_before_failure);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(target_root).unwrap();
        vm.remove_root(env_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p10_4_event_matrix() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &rivetlua_core::VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        let t = vm.allocate_table().unwrap();
        let u = vm.allocate_table().unwrap();
        let mt = vm.allocate_table().unwrap();
        vm.set_metatable(t, Some(mt)).unwrap();
        vm.set_metatable(u, Some(mt)).unwrap();
        for (name, object) in [(b"t".as_slice(), t), (b"u".as_slice(), u)] {
            let key = vm.allocate_byte_string(name).unwrap();
            vm.raw_set(env, Value::Object(key), Value::Object(object))
                .unwrap();
        }
        let event = {
            let mut execution = vm
                .load(compile(b"return function(a,b) return 41 end"))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("事件 closure")
            };
            let Value::Object(event) = values[0] else {
                panic!("事件 closure")
            };
            event
        };
        let cases: &[(&[u8], &[u8], Value)] = &[
            (b"__add", b"return t+u", Value::Integer(41)),
            (b"__sub", b"return t-u", Value::Integer(41)),
            (b"__mul", b"return t*u", Value::Integer(41)),
            (b"__mod", b"return t%u", Value::Integer(41)),
            (b"__pow", b"return t^u", Value::Integer(41)),
            (b"__div", b"return t/u", Value::Integer(41)),
            (b"__idiv", b"return t//u", Value::Integer(41)),
            (b"__band", b"return t&u", Value::Integer(41)),
            (b"__bor", b"return t|u", Value::Integer(41)),
            (b"__bxor", b"return t~u", Value::Integer(41)),
            (b"__shl", b"return t<<u", Value::Integer(41)),
            (b"__shr", b"return t>>u", Value::Integer(41)),
            (b"__unm", b"return -t", Value::Integer(41)),
            (b"__bnot", b"return ~t", Value::Integer(41)),
            (b"__len", b"return #t", Value::Integer(41)),
            (b"__concat", b"return t..u", Value::Integer(41)),
            (b"__lt", b"return t<u", Value::Boolean(true)),
            (b"__le", b"return t<=u", Value::Boolean(true)),
            (b"__eq", b"return t==u", Value::Boolean(true)),
        ];
        for (name, source, expected) in cases {
            let key = vm.allocate_byte_string(name).unwrap();
            vm.raw_set(mt, Value::Object(key), Value::Object(event))
                .unwrap();
            let mut execution = vm
                .load_with_environment(compile(source), Value::Object(env))
                .unwrap();
            assert_eq!(
                execution.run(),
                Ok(RunOutcome::Returned(vec![*expected])),
                "{source:?}"
            );
        }
        let len_key = vm.allocate_byte_string(b"__len").unwrap();
        let len_second_arg = {
            let mut execution = vm
                .load(compile(b"return function(a,b) return b end"))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("__len 事件 closure")
            };
            let Value::Object(closure) = values[0] else {
                panic!("__len 事件 closure")
            };
            closure
        };
        vm.raw_set(mt, Value::Object(len_key), Value::Object(len_second_arg))
            .unwrap();
        let mut execution = vm
            .load_with_environment(compile(b"return #t"), Value::Object(env))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Object(t)]))
        );
        drop(execution);
        vm.remove_root(env_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p10_4_raw_concat_float_profiles() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        for (profile, expected) in [
            (
                LanguageProfile::Lua55,
                [
                    b"1.2345678901234567x".as_slice(),
                    b"1e+20x",
                    b"1e-05x",
                    b"0.0001x",
                    b"100000000000000.0x",
                    b"1e+15x",
                ],
            ),
            (
                LanguageProfile::Lua54,
                [
                    b"1.2345678901235x".as_slice(),
                    b"1e+20x",
                    b"1e-05x",
                    b"0.0001x",
                    b"1e+14x",
                    b"1e+15x",
                ],
            ),
        ] {
            let mut vm = Vm::new().unwrap();
            for (source, bytes) in [
                b"return 1.2345678901234567 .. 'x'".as_slice(),
                b"return 1e20 .. 'x'",
                b"return 1e-5 .. 'x'",
                b"return 1e-4 .. 'x'",
                b"return 1e14 .. 'x'",
                b"return 1e15 .. 'x'",
            ]
            .into_iter()
            .zip(expected)
            {
                let limits = CompileLimits::default();
                let chunk = lex(source, profile, &limits).unwrap();
                let parsed = parse(&chunk, profile, &limits).unwrap();
                let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
                let ir = lower(&resolved, &IrLimits::default()).unwrap();
                let module = emit(&ir, &rivetlua_core::VerifyLimits::default())
                    .unwrap()
                    .verified()
                    .clone();
                let mut execution = vm.load(module).unwrap();
                let Ok(RunOutcome::Returned(values)) = execution.run() else {
                    panic!("raw concat 須回傳 byte string")
                };
                let Value::Object(object) = values[0] else {
                    panic!("raw concat 須回傳 byte string")
                };
                assert_eq!(
                    execution
                        .vm
                        .with_byte_string(object, |s| s.as_bytes().to_vec())
                        .unwrap(),
                    bytes
                );
            }
        }
    }

    #[test]
    fn p10_5_reentry_gc_cleanup() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        fn compile(source: &[u8]) -> VerifiedModule {
            let limits = CompileLimits::default();
            let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            emit(&ir, &rivetlua_core::VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key_t = vm.allocate_byte_string(b"t").unwrap();
        let key_call = vm.allocate_byte_string(b"__call").unwrap();
        vm.raw_set(env, Value::Object(key_t), Value::Object(table))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        let event = {
            let mut execution = vm
                .load(compile(
                    b"return function(self,n) if n==0 then return 7 end return self(n-1) end",
                ))
                .unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得 __call closure")
            };
            let Value::Object(event) = values[0] else {
                panic!("須取得 __call closure")
            };
            event
        };
        vm.raw_set(metatable, Value::Object(key_call), Value::Object(event))
            .unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(b"return t(1500)"), Value::Object(env))
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
        );
        assert!(execution.peak_frame_count() <= 3);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        let make_event = |vm: &mut Vm, source: &[u8]| {
            let mut execution = vm.load(compile(source)).unwrap();
            let Ok(RunOutcome::Returned(values)) = execution.run() else {
                panic!("須取得事件 closure")
            };
            let Value::Object(event) = values[0] else {
                panic!("須取得事件 closure")
            };
            event
        };
        vm.set_collect_every_allocation(false);
        let key_index = vm.allocate_byte_string(b"__index").unwrap();
        let key_newindex = vm.allocate_byte_string(b"__newindex").unwrap();
        let key_side = vm.allocate_byte_string(b"side").unwrap();
        vm.raw_set(table, Value::Object(key_side), Value::Integer(0))
            .unwrap();
        let index = make_event(&mut vm, b"return function(self,key) return self(2) end");
        vm.raw_set(metatable, Value::Object(key_index), Value::Object(index))
            .unwrap();
        let newindex = make_event(
            &mut vm,
            b"return function(self,key,value) local f=function() self.side=value; return self.x end; return f() end",
        );
        vm.raw_set(
            metatable,
            Value::Object(key_newindex),
            Value::Object(newindex),
        )
        .unwrap();
        vm.set_collect_every_allocation(true);
        let baseline_roots = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(
                compile(b"t.missing=9; return t.side,t.x"),
                Value::Object(env),
            )
            .unwrap();
        for _ in 0..100 {
            if execution.pending_ops.len() == 2 {
                break;
            }
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pending_ops.len(), 2);
        for index in 0..2 {
            let pending = execution.pending_ops.get(index).unwrap();
            assert_eq!(pending.stage, ResumeStage::AwaitingReturn);
            for value in pending.values {
                if let Value::Object(object) = value {
                    assert!(execution.vm.object_kind(object).is_ok());
                }
            }
        }
        let pending_roots = execution.vm.roots().total_count();
        execution.vm.collect().unwrap();
        assert_eq!(execution.vm.roots().total_count(), pending_roots);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(9),
                Value::Integer(7)
            ]))
        );
        assert!(execution.peak_frame_count() <= 4);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut execution = vm
            .load_with_environment(compile(b"return t(3)"), Value::Object(env))
            .unwrap();
        execution
            .vm
            .inject_failure_once(FailPoint::FrameRegistersReserve);
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::FrameRegistersReserve))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        vm.set_collect_every_allocation(false);
        let throwing = make_event(
            &mut vm,
            b"return function(self,n) local z=nil; return z.bad end",
        );
        vm.raw_set(metatable, Value::Object(key_call), Value::Object(throwing))
            .unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("巢狀事件錯誤須傳至現有 LuaError 邊界")
        };
        assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots + 1);
        drop(error);
        assert_eq!(vm.roots().total_count(), baseline_roots);

        vm.set_collect_every_allocation(false);
        let looping = make_event(&mut vm, b"return function(self,n) while true do end end");
        vm.raw_set(metatable, Value::Object(key_call), Value::Object(looping))
            .unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        execution.set_fuel(80).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);

        vm.raw_set(metatable, Value::Object(key_call), Value::Object(table))
            .unwrap();
        let mut execution = vm
            .load_with_environment(compile(b"return t.x"), Value::Object(env))
            .unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("__call 事件鏈須受控終止")
        };
        assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
        assert_eq!(
            execution.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots + 1);
        drop(error);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(table_root).unwrap();
        vm.remove_root(env_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p11_1_explicit_error_value_survives_execution_cleanup() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };

        let source = b"local t={}; error(t)";
        let profile = LanguageProfile::Lua55;
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(verified.clone(), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::LuaError(error) = outcome else {
            panic!("顯式 error(t) 必須保留原值")
        };
        let Value::Object(table) = error.value else {
            panic!("錯誤值須為 table")
        };
        assert_eq!(error.source_pc.is_some(), true);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        let retained = error.clone();
        drop(error);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        drop(retained);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        vm.remove_root(env_root).unwrap();

        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let mut execution = vm
            .load_with_environment(verified, Value::Object(env))
            .unwrap();
        while !matches!(
            execution.prototype().instructions[execution.pc()].instruction,
            Instruction::Call { .. } | Instruction::TailCall { .. }
        ) {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::InjectedFailure(FailPoint::RootReserve)
            )))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(env_root).unwrap();
    }

    #[test]
    fn p11_1_xpcall_handler_runs_before_body_unwind() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };

        let source = b"n=0; local function body() local t={}; error(t) end; local function handler(e) n=n+1; return e end; return xpcall(body,handler)";
        let profile = LanguageProfile::Lua55;
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let mut execution = vm
            .load_with_environment(verified.clone(), Value::Object(env))
            .unwrap();
        let error = loop {
            match execution.dispatch_one() {
                Ok(DispatchResult::Continue) => {}
                Err(error) => break error,
                _ => panic!("body 應先產生 LuaError"),
            }
        };
        assert_eq!(error.kind, RuntimeErrorKind::Thrown);
        let body_prototype = execution.frame.prototype;
        assert!(matches!(
            execution.handle_protected_error(error),
            Ok(ProtectedErrorResult::Caught(DispatchResult::Continue))
        ));
        assert!(
            execution
                .callers
                .iter()
                .any(|frame| frame.prototype == body_prototype),
            "handler 執行期間 body frame 須仍在 call stack"
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 1);
        vm.remove_root(env_root).unwrap();

        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let mut execution = vm
            .load_with_environment(verified, Value::Object(env))
            .unwrap();
        let error = loop {
            match execution.dispatch_one() {
                Ok(DispatchResult::Continue) => {}
                Err(error) => break error,
                _ => panic!("body 應先產生 LuaError"),
            }
        };
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.handle_protected_error(error).err(),
            Some(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::InjectedFailure(FailPoint::RootReserve)
            )))
        );
        drop(execution);
        let key = vm.allocate_byte_string(b"n").unwrap();
        assert_eq!(vm.raw_get(env, Value::Object(key)), Ok(Value::Integer(0)));
        assert_eq!(vm.roots().total_count(), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(env_root).unwrap();
    }

    #[test]
    fn p11_1_builtin_target_keeps_nested_protected_results() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };

        let source = b"return pcall(pcall, function() return 7,8 end)";
        let profile = LanguageProfile::Lua55;
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let verified = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(verified, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Integer(7),
                Value::Integer(8),
            ])
        );
        vm.remove_root(env_root).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p11_1_unprotected_runtime_error_has_host_owned_message() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified.clone()).unwrap();
        let RunOutcome::LuaError(error) = execution.run().unwrap() else {
            panic!("無保護邊界的整數除零應交付 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        let Value::Object(message) = error.value else {
            panic!("隱含 LuaError 值須為 byte string")
        };
        assert_eq!(execution.vm.roots().count(RootKind::Host), 1);
        drop(execution);
        vm.collect().unwrap();
        assert_eq!(
            vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
            Ok(b"E_INTEGER_DIVIDE_BY_ZERO".to_vec())
        );
        let retained = error.clone();
        drop(error);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(message), Ok(ObjectKind::ByteString));
        drop(retained);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(message), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        let stable = vm.ledger_snapshot();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.ledger_snapshot(), stable);
        let message_slot = message.identity().unwrap().slot;
        let mut reused = false;
        for _ in 0..=message_slot.index() {
            let probe = vm.allocate_byte_string(b"x").unwrap();
            reused |= probe.identity().unwrap().slot == message_slot;
        }
        assert!(reused, "收回的診斷字串 slot 須可重用");
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot(), stable);

        for point in [
            FailPoint::StringBytesReserve,
            FailPoint::ObjectReserve,
            FailPoint::RootReserve,
            FailPoint::HostLease,
        ] {
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified.clone()).unwrap();
            execution.vm.inject_failure_once(point);
            let failure = execution.run().err().unwrap();
            assert_eq!(
                failure.kind,
                RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
            );
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}
