//! P06-1 最小非移動 heap 與 slot 生命週期。

use core::mem::size_of;

use rivetlua_core::{
    Generation, LuaProfile, ObjectId, ObjectRef, SlotId, Value, VerifiedModule, VmId,
};

use crate::alloc::{
    AllocationAttempt, AllocationLedger, AllocationTrace, FailPoint, LedgerProbe, LedgerSnapshot,
    Reservation, checked_bytes, reserve_vec,
};
use crate::callback::CallbackFn;
use crate::closure::Closure;
use crate::coroutine::{Coroutine, CoroutineState, ThreadContext};
use crate::errors::Builtin;
use crate::gc::trace::RefField;
use crate::gc::{
    AtomicFinalizerStage, FinalizerState, GcAge, GcColor, GcCycleKind, GcMode, GcPhase, GcState,
    GcTrace, WeakMode,
};
use crate::host::{
    DebugCapability, DumpCapability, HostEntropyServiceError, HostFileLease, HostOsOperation,
    HostOsValue, HostResourceError, HostResourceErrorKind, HostServiceError, HostServices,
    LoadBudget, LoadLimits, LoadServiceError, LoadTemporaryCharge, PathEncoding, ResourceBudget,
    ResourceLimits,
};
use crate::roots::{RootId, RootKind, RootLease, RootSet};
use crate::stdlib::basic::BasicBuiltin;
use crate::stdlib::debug::DebugBuiltin;
use crate::stdlib::debug::DebugHook;
use crate::stdlib::io::IoBuiltin;
use crate::stdlib::math::MathBuiltin;
use crate::stdlib::os::OsBuiltin;
use crate::stdlib::package::LoadBuiltin;
use crate::stdlib::string::StringBuiltin;
use crate::stdlib::table::TableBuiltin;
use crate::stdlib::utf8::{self as utf8_lib, Utf8Builtin};
use crate::string::ByteString;
use crate::table::Table;
use crate::upvalue::{Upvalue, UpvalueState};

/// 公開的 slot 狀態，不暴露 heap 配置或可變借用。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotState {
    Occupied,
    Free,
    Retired,
}

#[cfg(test)]
mod p13_b_tests {
    use rivetlua_core::Value;

    use super::{ObjectKind, Vm};

    #[test]
    fn p13_b_installer_exposes_vm_local_table_functions() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        vm.install_table_builtins(env).unwrap();
        let table_key = vm.allocate_byte_string(b"table").unwrap();
        let Value::Object(table) = vm.raw_get(env, Value::Object(table_key)).unwrap() else {
            panic!("明示安裝後須有 table 欄位");
        };
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        let pack_key = vm.allocate_byte_string(b"pack").unwrap();
        assert!(matches!(
            vm.raw_get(table, Value::Object(pack_key)).unwrap(),
            Value::Object(_)
        ));
    }
}

/// Heap 物件 payload 的分類；不改變 `Value::Object` 身分。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Value,
    ByteString,
    Table,
    Closure,
    Builtin,
    Coroutine,
    Upvalue,
    Module,
    File,
}

/// VM 邊界的可檢查結果。P06 後續步驟補上配置計帳。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmError {
    VmIdExhausted,
    AllocationFailed,
    IdentityExhausted,
    RootIdExhausted,
    WrongVm,
    StaleObject,
    StaleRoot,
    WrongObjectType,
    NilTableKey,
    NaNTableKey,
    ArithmeticOverflow,
    LedgerInvariant,
    InvalidGcStepBudget,
    WrongGcPhase,
    InvalidGcConfig,
    FinalizerGcReentry,
    InjectedFailure(FailPoint),
    InjectedAllocation(AllocationAttempt),
    HostResource(HostResourceErrorKind),
}

impl VmError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::VmIdExhausted => "E_VM_ID_EXHAUSTED",
            Self::AllocationFailed => "E_ALLOCATION_FAILED",
            Self::IdentityExhausted => "E_IDENTITY_EXHAUSTED",
            Self::RootIdExhausted => "E_ROOT_ID_EXHAUSTED",
            Self::WrongVm => "E_WRONG_VM",
            Self::StaleObject => "E_STALE_HANDLE",
            Self::StaleRoot => "E_STALE_ROOT",
            Self::WrongObjectType => "E_WRONG_OBJECT_TYPE",
            Self::NilTableKey => "E_TABLE_KEY_NIL",
            Self::NaNTableKey => "E_TABLE_KEY_NAN",
            Self::ArithmeticOverflow => "E_ALLOCATION_FAILED",
            Self::LedgerInvariant => "E_ALLOCATION_FAILED",
            Self::InvalidGcStepBudget => "E_GC_STEP_BUDGET",
            Self::WrongGcPhase => "E_GC_PHASE",
            Self::InvalidGcConfig => "E_GC_CONFIG",
            Self::FinalizerGcReentry => "E_GC_FINALIZER_REENTRY",
            Self::InjectedFailure(_) => "E_ALLOCATION_FAILED",
            Self::InjectedAllocation(_) => "E_ALLOCATION_FAILED",
            Self::HostResource(kind) => match kind {
                HostResourceErrorKind::PolicyDenied => "E_HOST_POLICY_IO",
                HostResourceErrorKind::Unsupported => "E_HOST_UNSUPPORTED",
                HostResourceErrorKind::PathDenied => "E_HOST_PATH_DENIED",
                HostResourceErrorKind::IoFailure => "E_HOST_IO_FAILED",
                HostResourceErrorKind::PlatformDifference => "E_HOST_PLATFORM_DIFFERENCE",
                HostResourceErrorKind::Cancelled => "E_HOST_CANCELLED",
                HostResourceErrorKind::Deadline => "E_HOST_DEADLINE",
                HostResourceErrorKind::Budget => "E_HOST_RESOURCE_BUDGET",
            },
        }
    }
}

struct HeapObject {
    payload: HeapPayload,
    children: Vec<ObjectRef>,
}

enum HeapPayload {
    Value(Value),
    ByteString(ByteString),
    Table(Table),
    Closure(Closure),
    Builtin(Builtin),
    Coroutine(Coroutine),
    Upvalue(Upvalue),
    Module(ModulePayload),
    File(FilePayload),
}

pub(crate) struct FilePayload {
    pub(crate) lease: Option<Box<dyn HostFileLease>>,
    pub(crate) metatable: Option<ObjectRef>,
    pub(crate) standard: bool,
    pub(crate) charge: Option<LoadTemporaryCharge>,
}

impl Drop for FilePayload {
    fn drop(&mut self) {
        self.lease.take();
        self.charge.take();
    }
}

struct ModulePayload {
    module: VerifiedModule,
    ledger: AllocationLedger,
    host_charge: usize,
}

impl Drop for ModulePayload {
    fn drop(&mut self) {
        if self.host_charge != 0 {
            self.ledger.refund_on_drop(self.host_charge);
        }
    }
}

pub(crate) fn module_allocation_bytes(module: &VerifiedModule) -> Result<usize, VmError> {
    // HeapObject 已計入 inline VerifiedModule；Core 持有唯一巢狀容量算法。
    let retained = rivetlua_core::verified_module_allocation_bytes(module)
        .map_err(|_| VmError::ArithmeticOverflow)?;
    retained
        .checked_sub(size_of::<VerifiedModule>())
        .ok_or(VmError::ArithmeticOverflow)
}

impl HeapObject {
    fn debt_bytes(&self) -> Result<usize, VmError> {
        let payload = match &self.payload {
            HeapPayload::ByteString(string) => string.len(),
            HeapPayload::Table(table) => table.charge_bytes()?,
            HeapPayload::Value(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_) => 0,
            HeapPayload::File(_) => 0,
        };
        size_of::<Self>()
            .checked_add(payload)
            .ok_or(VmError::ArithmeticOverflow)
    }

    fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        match &self.payload {
            HeapPayload::Value(Value::Object(child)) => visit(*child)?,
            HeapPayload::Value(
                Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::Float(_),
            ) => {}
            HeapPayload::ByteString(_) => {}
            HeapPayload::Table(table) => table.trace_children(&mut visit)?,
            HeapPayload::Closure(closure) => closure.trace_children(&mut visit)?,
            HeapPayload::Builtin(Builtin::CoroutineWrapped(coroutine)) => visit(*coroutine)?,
            HeapPayload::Builtin(Builtin::Utf8(Utf8Builtin::Codes { strict, lax })) => {
                visit(*strict)?;
                visit(*lax)?;
            }
            HeapPayload::Builtin(Builtin::Load(kind)) => {
                if let Some(owner) = kind.owner() {
                    visit(owner)?;
                }
                if let Some(environment) = kind.environment() {
                    visit(environment)?;
                }
            }
            HeapPayload::Builtin(Builtin::Io(IoBuiltin::LinesIterator {
                file, formats, ..
            })) => {
                visit(*file)?;
                visit(*formats)?;
            }
            HeapPayload::Builtin(Builtin::StringIterator {
                source, pattern, ..
            }) => {
                if let Value::Object(object) = source {
                    visit(*object)?;
                }
                if let Value::Object(object) = pattern {
                    visit(*object)?;
                }
            }
            HeapPayload::Builtin(
                Builtin::HostCallback(_)
                | Builtin::Official(_)
                | Builtin::Error
                | Builtin::PCall
                | Builtin::XPCall
                | Builtin::CoroutineCreate
                | Builtin::CoroutineResume
                | Builtin::CoroutineYield
                | Builtin::CoroutineStatus
                | Builtin::CoroutineClose
                | Builtin::CoroutineWrap,
            ) => {}
            HeapPayload::Builtin(
                Builtin::Basic(_)
                | Builtin::Table(_)
                | Builtin::Math(_)
                | Builtin::String(_)
                | Builtin::Utf8(_)
                | Builtin::Io(_)
                | Builtin::Os(_)
                | Builtin::Debug(_),
            ) => {}
            HeapPayload::Coroutine(coroutine) => coroutine.trace_children(&mut visit)?,
            HeapPayload::Upvalue(upvalue) => match upvalue.state() {
                UpvalueState::Closed(Value::Object(child)) => visit(child)?,
                UpvalueState::Closed(_) => {}
                UpvalueState::Open {
                    coroutine: Some(child),
                    ..
                } => visit(child)?,
                UpvalueState::Open {
                    coroutine: None, ..
                } => {}
            },
            HeapPayload::Module(_) => {}
            HeapPayload::File(file) => {
                if let Some(metatable) = file.metatable {
                    visit(metatable)?;
                }
            }
        }
        for &child in &self.children {
            visit(child)?;
        }
        Ok(())
    }

    fn trace_gc_children(
        &self,
        is_string: impl FnMut(ObjectRef) -> Result<bool, VmError>,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        match &self.payload {
            HeapPayload::Table(table) => table.trace_gc_children(is_string, &mut visit)?,
            _ => self.trace_children(&mut visit)?,
        }
        if matches!(self.payload, HeapPayload::Table(_)) {
            for &child in &self.children {
                visit(child)?;
            }
        }
        Ok(())
    }
}

enum Slot {
    Occupied {
        generation: Generation,
        reference: ObjectRef,
        age: GcAge,
        survivals: u8,
        finalizer: FinalizerState,
        finalizer_order: u64,
        finalizer_remarked: bool,
        // 唯一元素不再增減；Vec 只搬移指標，中間的物件配置維持原址。
        object: Vec<HeapObject>,
    },
    Free {
        generation: Generation,
    },
    Retired,
}

#[derive(Clone, Copy)]
struct FinalizerEntry {
    object: ObjectRef,
    order: u64,
}

impl Slot {
    fn state(&self) -> SlotState {
        match self {
            Self::Occupied { .. } => SlotState::Occupied,
            Self::Free { .. } => SlotState::Free,
            Self::Retired => SlotState::Retired,
        }
    }
}

fn gc_mark_slot(
    slots: &[Slot],
    vm: VmId,
    gc: &mut GcState,
    object: ObjectRef,
) -> Result<(), VmError> {
    let id = object.identity().ok_or(VmError::StaleObject)?;
    if id.vm != vm {
        return Err(VmError::WrongVm);
    }
    match slots.get(id.slot.index()) {
        Some(Slot::Occupied {
            generation,
            reference,
            ..
        }) if *generation == id.generation && *reference == object => {}
        _ => return Err(VmError::StaleObject),
    }
    if gc.phase != GcPhase::Pause
        && gc
            .colors
            .get(id.slot.index())
            .copied()
            .ok_or(VmError::LedgerInvariant)?
            == GcColor::White
    {
        if gc.work.len() == gc.work.capacity() {
            return Err(VmError::AllocationFailed);
        }
        *gc.colors
            .get_mut(id.slot.index())
            .ok_or(VmError::LedgerInvariant)? = GcColor::Gray;
        gc.work.push(object);
        if gc.phase == GcPhase::Sweep {
            gc.transition(GcPhase::Propagate);
        }
    }
    Ok(())
}

fn gc_is_string(slots: &[Slot], vm: VmId, object: ObjectRef) -> Result<bool, VmError> {
    let id = object.identity().ok_or(VmError::StaleObject)?;
    if id.vm != vm {
        return Err(VmError::WrongVm);
    }
    match slots.get(id.slot.index()) {
        Some(Slot::Occupied {
            generation,
            reference,
            object: stored,
            ..
        }) if *generation == id.generation && *reference == object => {
            Ok(matches!(stored[0].payload, HeapPayload::ByteString(_)))
        }
        _ => Err(VmError::StaleObject),
    }
}

/// P06 最小 VM。所有公開存取均用完整 ObjectId 重新驗證。
pub struct Vm {
    id: VmId,
    profile: LuaProfile,
    slots: Vec<Slot>,
    roots: RootSet,
    ledger: AllocationLedger,
    gc: GcState,
    collect_every_allocation: bool,
    finalizer_queue: Vec<FinalizerEntry>,
    finalizer_queue_charge: usize,
    finalizer_next_order: u64,
    finalizer_warnings: usize,
    finalizer_deferred_terminals: usize,
    finalizer_running: bool,
    execution_running: bool,
    host_services: HostServices,
    math_rng: Option<[u64; 4]>,
    table_sort_trace: crate::stdlib::table::TableSortTrace,
    string_metatable: Option<(ObjectRef, RootId)>,
    package_registry: Option<PackageRegistry>,
    io_registry: Option<(ObjectRef, RootId)>,
    debug_main_hook: Option<(DebugHook, RootId)>,
    debug_hook_running: bool,
    callbacks: Vec<Option<CallbackEntry>>,
    callbacks_charge: usize,
}

struct CallbackEntry {
    callback: std::rc::Rc<CallbackFn>,
    captures: Vec<Value>,
    charge: usize,
}

#[derive(Clone, Copy)]
struct PackageRegistry {
    loaded: ObjectRef,
    loaded_root: RootId,
    preload: ObjectRef,
    preload_root: RootId,
}

impl Vm {
    pub fn new() -> Result<Self, VmError> {
        Self::new_with_profile(LuaProfile::Lua55)
    }

    pub fn new_with_profile(profile: LuaProfile) -> Result<Self, VmError> {
        Self::new_with_services(profile, HostServices::deny_all())
    }

    pub fn new_with_services(
        profile: LuaProfile,
        host_services: HostServices,
    ) -> Result<Self, VmError> {
        let id = VmId::new_unique().ok_or(VmError::VmIdExhausted)?;
        let ledger = AllocationLedger::new(usize::MAX);
        Ok(Self {
            id,
            profile,
            slots: Vec::new(),
            roots: RootSet::new(id),
            gc: GcState::new(ledger.clone()),
            ledger,
            collect_every_allocation: false,
            finalizer_queue: Vec::new(),
            finalizer_queue_charge: 0,
            finalizer_next_order: 1,
            finalizer_warnings: 0,
            finalizer_deferred_terminals: 0,
            finalizer_running: false,
            execution_running: false,
            host_services,
            math_rng: None,
            table_sort_trace: crate::stdlib::table::TableSortTrace::default(),
            string_metatable: None,
            package_registry: None,
            io_registry: None,
            debug_main_hook: None,
            debug_hook_running: false,
            callbacks: Vec::new(),
            callbacks_charge: 0,
        })
    }

    pub(crate) fn write_host_output(&mut self, bytes: &[u8]) -> Result<(), HostServiceError> {
        self.host_services.output(bytes)
    }

    pub(crate) fn host_output_allowed(&self) -> bool {
        self.host_services.output_allowed()
    }

    pub(crate) fn host_entropy_seed(&mut self) -> Result<u64, HostEntropyServiceError> {
        self.host_services.entropy_seed()
    }

    pub(crate) fn load_limits(&self) -> LoadLimits {
        self.host_services.load.limits
    }

    pub(crate) fn resource_limits(&self) -> ResourceLimits {
        self.host_services.resource.limits
    }

    pub(crate) fn debug_capability(&self) -> DebugCapability {
        self.host_services.debug
    }

    pub(crate) fn dump_capability(&self) -> DumpCapability {
        self.host_services.dump
    }

    pub(crate) fn debug_hook_running(&self) -> bool {
        self.debug_hook_running
    }

    pub(crate) fn set_debug_hook_running(&mut self, running: bool) {
        self.debug_hook_running = running;
    }

    pub(crate) fn debug_hook_for(
        &self,
        thread: Option<ObjectRef>,
    ) -> Result<Option<DebugHook>, VmError> {
        match thread {
            Some(thread) => self.with_coroutine(thread, |coroutine| coroutine.debug_hook),
            None => Ok(self.debug_main_hook.map(|(hook, _)| hook)),
        }
    }

    /// Hook 執行期間抑制整個 VM 的巢狀 hook；其他 coroutine 仍可正常 yield。
    pub(crate) fn debug_hook_tick(
        &mut self,
        thread: Option<ObjectRef>,
    ) -> Result<Option<ObjectRef>, VmError> {
        if self.debug_hook_running {
            return Ok(None);
        }
        match thread {
            Some(thread) => self.with_coroutine_mut(thread, &[], |coroutine| {
                coroutine
                    .debug_hook
                    .as_mut()
                    .and_then(|hook| hook.tick().then_some(hook.function))
            }),
            None => Ok(self
                .debug_main_hook
                .as_mut()
                .and_then(|(hook, _)| hook.tick().then_some(hook.function))),
        }
    }

    pub(crate) fn set_debug_hook(
        &mut self,
        thread: Option<ObjectRef>,
        hook: Option<DebugHook>,
    ) -> Result<(), VmError> {
        match thread {
            Some(thread) => {
                let new_refs = hook.map(|hook| hook.function);
                self.with_coroutine_mut(thread, new_refs.as_slice(), |coroutine| {
                    coroutine.debug_hook = hook
                })?;
            }
            None => {
                let root = match hook {
                    Some(hook) => Some((hook, self.add_root(RootKind::Registry, hook.function)?)),
                    None => None,
                };
                let old = core::mem::replace(&mut self.debug_main_hook, root);
                if let Some((_, old_root)) = old {
                    self.remove_root(old_root)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn resource_path_encoding(&self) -> PathEncoding {
        self.host_services.resource.path_encoding
    }

    pub(crate) fn host_io_available(&self) -> bool {
        self.host_services.resource.io.is_some()
    }

    pub(crate) fn host_os_available(&self) -> bool {
        self.host_services.resource.os.is_some()
    }

    pub(crate) fn resource_deadline_check(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()
    }

    pub(crate) fn host_io_open(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        let Some(io) = self.host_services.resource.io.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        io.authorize_path(path, mode, budget)?;
        budget.ensure_active()?;
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()?;
        io.open(path, mode, budget)
    }

    pub(crate) fn host_io_standard(
        &mut self,
        which: u8,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        let Some(io) = self.host_services.resource.io.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()?;
        match which {
            0 => io.stdin(budget),
            1 => io.stdout(budget),
            2 => io.stderr(budget),
            _ => Err(HostResourceError::new(
                HostResourceErrorKind::Unsupported,
                Vec::new(),
            )),
        }
    }

    pub(crate) fn host_io_tmpfile(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        let Some(io) = self.host_services.resource.io.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()?;
        io.tmpfile(budget)
    }

    pub(crate) fn host_io_popen(
        &mut self,
        command: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        let Some(io) = self.host_services.resource.io.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        io.authorize_process(command, mode, budget)?;
        budget.ensure_active()?;
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()?;
        io.popen(command, mode, budget)
    }

    pub(crate) fn host_os_perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        let Some(os) = self.host_services.resource.os.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        os.authorize(operation, budget)?;
        budget.ensure_active()?;
        match operation {
            HostOsOperation::Remove(path) | HostOsOperation::Rename(path, _) => {
                os.authorize_path(path, budget)?;
                budget.ensure_active()?;
                if let HostOsOperation::Rename(_, other) = operation {
                    os.authorize_path(other, budget)?;
                    budget.ensure_active()?;
                }
            }
            _ => {}
        }
        let Some(checker) = self.host_services.resource.deadline.as_mut() else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        checker.check(budget)?;
        budget.ensure_active()?;
        os.perform(operation, budget)
    }

    pub(crate) fn load_verify_limits(&self) -> rivetlua_core::VerifyLimits {
        self.host_services.load.verify_limits
    }

    pub(crate) fn load_allows_bytecode(&self) -> bool {
        self.host_services.load.allow_bytecode
    }

    pub(crate) fn load_allows_official_bytecode(&self) -> bool {
        self.host_services.load.allow_official_bytecode
    }

    pub(crate) fn host_compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<VerifiedModule, LoadServiceError> {
        let Some(compiler) = self.host_services.load.compiler.as_mut() else {
            return Err(LoadServiceError::PolicyDenied);
        };
        compiler
            .compile(source, chunkname, self.profile, budget)
            .map_err(LoadServiceError::Host)
    }

    pub(crate) fn host_read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, LoadServiceError> {
        let Some(reader) = self.host_services.load.reader.as_mut() else {
            return Err(LoadServiceError::PolicyDenied);
        };
        reader
            .read_path(path, budget)
            .map_err(LoadServiceError::Host)
    }

    pub(crate) fn host_read_stdin(
        &mut self,
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, LoadServiceError> {
        let Some(reader) = self.host_services.load.reader.as_mut() else {
            return Err(LoadServiceError::PolicyDenied);
        };
        reader.read_stdin(budget).map_err(LoadServiceError::Host)
    }

    pub(crate) fn host_compiler_available(&self) -> bool {
        self.host_services.load.compiler.is_some()
    }

    pub(crate) fn host_reader_available(&self) -> bool {
        self.host_services.load.reader.is_some()
    }

    pub(crate) fn host_repository_available(&self) -> bool {
        self.host_services.load.repository.is_some()
    }

    pub(crate) fn host_native_available(&self) -> bool {
        self.host_services.load.native.is_some()
    }

    pub(crate) fn host_search_repository(
        &mut self,
        modname: &[u8],
        path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Option<crate::host::HostModuleBytes>, LoadServiceError> {
        let Some(repository) = self.host_services.load.repository.as_mut() else {
            return Err(LoadServiceError::PolicyDenied);
        };
        repository
            .search(modname, path, budget)
            .map_err(LoadServiceError::Host)
    }

    pub(crate) fn host_search_native(
        &mut self,
        modname: &[u8],
        root: bool,
        budget: &mut LoadBudget,
    ) -> Result<Option<crate::host::HostNativeModule>, LoadServiceError> {
        let Some(native) = self.host_services.load.native.as_mut() else {
            return Err(LoadServiceError::PolicyDenied);
        };
        native
            .search(modname, root, budget)
            .map_err(LoadServiceError::Host)
    }

    pub(crate) fn math_rng(&self) -> Option<[u64; 4]> {
        self.math_rng
    }

    pub(crate) fn set_math_rng(&mut self, state: [u64; 4]) {
        self.math_rng = Some(state);
    }

    pub(crate) const fn language_profile(&self) -> LuaProfile {
        self.profile
    }

    pub const fn table_sort_trace(&self) -> crate::stdlib::table::TableSortTrace {
        self.table_sort_trace
    }

    pub(crate) fn begin_table_sort(&mut self) {
        self.table_sort_trace = crate::stdlib::table::TableSortTrace {
            comparisons: 0,
            swaps: 0,
            stop: crate::stdlib::table::TableSortStop::Running,
        };
    }

    pub(crate) fn restore_table_sort_trace(&mut self, trace: crate::stdlib::table::TableSortTrace) {
        self.table_sort_trace = trace;
    }

    pub(crate) fn table_sort_comparison(&mut self) -> Result<(), VmError> {
        self.table_sort_trace.comparisons = self
            .table_sort_trace
            .comparisons
            .checked_add(1)
            .ok_or(VmError::ArithmeticOverflow)?;
        Ok(())
    }

    pub(crate) fn table_sort_swap(&mut self) -> Result<(), VmError> {
        self.table_sort_trace.swaps = self
            .table_sort_trace
            .swaps
            .checked_add(1)
            .ok_or(VmError::ArithmeticOverflow)?;
        Ok(())
    }

    pub(crate) fn end_table_sort(&mut self, stop: crate::stdlib::table::TableSortStop) {
        if self.table_sort_trace.stop == crate::stdlib::table::TableSortStop::Running {
            self.table_sort_trace.stop = stop;
        }
    }

    pub const fn id(&self) -> VmId {
        self.id
    }

    pub fn slot_state(&self, slot: SlotId) -> Option<SlotState> {
        self.slots.get(slot.index()).map(Slot::state)
    }

    pub const fn roots(&self) -> &RootSet {
        &self.roots
    }

    /// 逐一呈現目前強 root 的來源與身分；訪客不得改動 VM。
    pub fn visit_roots(&self, mut visit: impl FnMut(RootKind, RootId, ObjectRef)) {
        self.roots.visit_labeled(&mut visit);
    }

    pub fn ledger_snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    pub fn ledger_probe(&self) -> LedgerProbe {
        self.ledger.probe()
    }

    pub fn allocation_trace(&self) -> AllocationTrace {
        self.ledger.trace()
    }

    pub fn inject_allocation_failure_at(&mut self, ordinal: u64) {
        self.ledger.fail_once_at_ordinal(ordinal);
    }

    pub fn observe_shared_rss(&mut self, bytes: usize) {
        self.ledger.observe_shared_rss(bytes);
    }

    pub fn gc_trace(&self) -> GcTrace {
        let mut white = 0;
        let mut gray = 0;
        let mut black = 0;
        let mut young = 0;
        let mut survivor = 0;
        let mut old = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            let Slot::Occupied { age, .. } = slot else {
                continue;
            };
            match age {
                GcAge::Young => young += 1,
                GcAge::Survivor => survivor += 1,
                GcAge::Old => old += 1,
            }
            match self.gc.colors.get(index).copied().unwrap_or(GcColor::White) {
                GcColor::White => white += 1,
                GcColor::Gray => gray += 1,
                GcColor::Black => black += 1,
            }
        }
        GcTrace {
            phase: self.gc.phase,
            mode: self.gc.mode,
            cycle: self.gc.cycle,
            white,
            gray,
            black,
            worklist_len: self.gc.work.len(),
            debt_bytes: self.gc.debt_bytes,
            barrier_count: self.gc.barrier_count,
            reclaimed_bytes: self.gc.reclaimed_bytes,
            transition_count: self.gc.transition_count,
            young,
            survivor,
            old,
            remembered_len: self.gc.remembered.len(),
            major_debt_bytes: self.gc.major_debt_bytes,
            major_threshold_bytes: self.gc.major_threshold_bytes,
            promotion_survivals: self.gc.promotion_survivals,
            ephemeron_iterations: self.gc.ephemeron_iterations,
            ephemeron_last_key: self.gc.ephemeron_last_key,
            ephemeron_converged: self.gc.ephemeron_converged,
            weak_cleared_pairs: self.gc.weak_cleared_pairs,
            finalizer_pending: self.finalizer_queue.len(),
            finalizer_warnings: self.finalizer_warnings,
            finalizer_deferred_terminals: self.finalizer_deferred_terminals,
        }
    }

    pub fn gc_mode(&self) -> GcMode {
        self.gc.mode
    }

    pub fn gc_age(&self, object: ObjectRef) -> Result<GcAge, VmError> {
        let Slot::Occupied { age, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        Ok(*age)
    }

    pub fn finalizer_state(&self, object: ObjectRef) -> Result<FinalizerState, VmError> {
        let Slot::Occupied { finalizer, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        Ok(*finalizer)
    }

    pub(crate) fn register_finalizer(&mut self, object: ObjectRef) -> Result<(), VmError> {
        let Slot::Occupied {
            finalizer: current,
            finalizer_remarked: remarked,
            ..
        } = self.checked_slot(object)?
        else {
            return Err(VmError::StaleObject);
        };
        let new_registration = match current {
            FinalizerState::Registered | FinalizerState::Pending => false,
            FinalizerState::Running => !*remarked,
            FinalizerState::Unregistered | FinalizerState::Finalized => true,
        };
        let next_order = if new_registration {
            self.finalizer_next_order
                .checked_add(1)
                .ok_or(VmError::ArithmeticOverflow)?
        } else {
            self.finalizer_next_order
        };
        let index = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        let Slot::Occupied {
            finalizer,
            finalizer_order,
            finalizer_remarked,
            ..
        } = &mut self.slots[index]
        else {
            return Err(VmError::StaleObject);
        };
        match finalizer {
            FinalizerState::Registered | FinalizerState::Pending => {}
            FinalizerState::Running if *finalizer_remarked => {}
            FinalizerState::Running => {
                *finalizer_remarked = true;
            }
            FinalizerState::Unregistered | FinalizerState::Finalized => {
                *finalizer = FinalizerState::Registered;
            }
        }
        if new_registration {
            *finalizer_order = self.finalizer_next_order;
            self.finalizer_next_order = next_order;
        }
        Ok(())
    }

    pub(crate) fn preflight_finalizer_registration(
        &self,
        object: ObjectRef,
    ) -> Result<(), VmError> {
        let Slot::Occupied {
            finalizer,
            finalizer_remarked,
            ..
        } = self.checked_slot(object)?
        else {
            return Err(VmError::StaleObject);
        };
        if matches!(
            finalizer,
            FinalizerState::Registered | FinalizerState::Pending
        ) || (*finalizer == FinalizerState::Running && *finalizer_remarked)
        {
            return Ok(());
        }
        self.finalizer_next_order
            .checked_add(1)
            .map(|_| ())
            .ok_or(VmError::ArithmeticOverflow)
    }

    pub(crate) fn pending_finalizer(&self) -> Result<Option<(ObjectRef, Value)>, VmError> {
        let Some(entry) = self.finalizer_queue.last() else {
            return Ok(None);
        };
        let metatable = self.get_metatable(entry.object)?;
        let callback = match metatable {
            Some(metatable) => self.with_table(metatable, Table::finalizer_value)?,
            None => Value::Nil,
        };
        Ok(Some((entry.object, callback)))
    }

    pub(crate) fn start_finalizer(&mut self, object: ObjectRef) -> Result<(), VmError> {
        if self.finalizer_running || self.finalizer_queue.last().map(|e| e.object) != Some(object) {
            return Err(VmError::FinalizerGcReentry);
        }
        let index = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        let Slot::Occupied { finalizer, .. } = &mut self.slots[index] else {
            return Err(VmError::StaleObject);
        };
        if *finalizer != FinalizerState::Pending {
            return Err(VmError::LedgerInvariant);
        }
        *finalizer = FinalizerState::Running;
        self.finalizer_running = true;
        Ok(())
    }

    pub(crate) fn pause_finalizer_start(&mut self, object: ObjectRef) -> Result<(), VmError> {
        let index = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        let Slot::Occupied { finalizer, .. } = &mut self.slots[index] else {
            return Err(VmError::StaleObject);
        };
        if *finalizer != FinalizerState::Running {
            return Err(VmError::LedgerInvariant);
        }
        *finalizer = FinalizerState::Pending;
        self.finalizer_running = false;
        Ok(())
    }

    pub(crate) fn finish_finalizer(&mut self, object: ObjectRef) -> Result<(), VmError> {
        if !self.finalizer_running || self.finalizer_queue.last().map(|e| e.object) != Some(object)
        {
            return Err(VmError::LedgerInvariant);
        }
        let index = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        let Slot::Occupied {
            finalizer,
            finalizer_remarked,
            ..
        } = &mut self.slots[index]
        else {
            return Err(VmError::StaleObject);
        };
        if *finalizer != FinalizerState::Running {
            return Err(VmError::LedgerInvariant);
        }
        *finalizer = if *finalizer_remarked {
            FinalizerState::Registered
        } else {
            FinalizerState::Finalized
        };
        *finalizer_remarked = false;
        self.finalizer_queue.pop();
        self.finalizer_running = false;
        if self.finalizer_queue.is_empty() {
            self.finalizer_queue = Vec::new();
            self.ledger.refund(self.finalizer_queue_charge)?;
            self.finalizer_queue_charge = 0;
        }
        Ok(())
    }

    pub(crate) fn record_finalizer_warning(&mut self) {
        self.finalizer_warnings += 1;
    }

    pub(crate) fn record_finalizer_deferred_terminal(&mut self) {
        self.finalizer_deferred_terminals += 1;
    }

    pub(crate) fn execution_running(&self) -> bool {
        self.execution_running
    }

    pub(crate) fn finalizer_running(&self) -> bool {
        self.finalizer_running
    }

    pub(crate) fn set_execution_running(&mut self, running: bool) {
        self.execution_running = running;
    }

    pub fn set_gc_mode(&mut self, mode: GcMode) -> Result<(), VmError> {
        if self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        if self.gc.mode != mode {
            self.gc.clear_remembered()?;
            for slot in &mut self.slots {
                if let Slot::Occupied { age, survivals, .. } = slot {
                    *age = GcAge::Young;
                    *survivals = 0;
                }
            }
            self.gc.mode = mode;
            self.gc.cycle = GcCycleKind::Full;
            self.gc.major_debt_bytes = 0;
        }
        Ok(())
    }

    pub fn set_gc_promotion_survivals(&mut self, survivals: u8) -> Result<(), VmError> {
        if survivals == 0 {
            return Err(VmError::InvalidGcConfig);
        }
        if self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        self.gc.promotion_survivals = survivals;
        Ok(())
    }

    pub fn set_gc_major_threshold(&mut self, bytes: usize) -> Result<(), VmError> {
        if bytes == 0 {
            return Err(VmError::InvalidGcConfig);
        }
        if self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        self.gc.major_threshold_bytes = bytes;
        Ok(())
    }

    pub fn collect_minor(&mut self) -> Result<usize, VmError> {
        if self.finalizer_running {
            return Err(VmError::FinalizerGcReentry);
        }
        if self.gc.mode != GcMode::Generational || self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        let before = self.gc.reclaimed_objects;
        self.begin_gc_cycle_kind(GcCycleKind::Minor)?;
        while self.gc.phase != GcPhase::Pause {
            self.incremental_step(1024)?;
        }
        Ok(self.gc.reclaimed_objects - before)
    }

    pub fn collect_major(&mut self) -> Result<usize, VmError> {
        if self.finalizer_running {
            return Err(VmError::FinalizerGcReentry);
        }
        if self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        let before = self.gc.reclaimed_objects;
        let kind = if self.gc.mode == GcMode::Generational {
            GcCycleKind::Major
        } else {
            GcCycleKind::Full
        };
        self.begin_gc_cycle_kind(kind)?;
        while self.gc.phase != GcPhase::Pause {
            self.incremental_step(1024)?;
        }
        Ok(self.gc.reclaimed_objects - before)
    }

    pub fn gc_color(&self, object: ObjectRef) -> Result<GcColor, VmError> {
        self.checked_slot(object)?;
        let slot = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        Ok(self.gc.colors.get(slot).copied().unwrap_or(GcColor::White))
    }

    pub fn incremental_step(&mut self, budget: usize) -> Result<GcTrace, VmError> {
        if self.finalizer_running {
            return Err(VmError::FinalizerGcReentry);
        }
        if budget == 0 {
            return Err(VmError::InvalidGcStepBudget);
        }
        let mut began = self.gc.phase != GcPhase::Pause;
        for _ in 0..budget {
            match self.gc.phase {
                GcPhase::Pause => {
                    if began {
                        break;
                    }
                    self.begin_gc_cycle()?;
                    began = true;
                }
                GcPhase::RootMark => {
                    if let Some(&root) = self.gc.roots.get(self.gc.root_cursor) {
                        self.mark_gc_object(root)?;
                        self.gc.root_cursor += 1;
                    } else if self.gc.cycle == GcCycleKind::Minor {
                        if let Some(&owner) = self.gc.remembered.get(self.gc.remembered_cursor) {
                            self.trace_gc_object(owner)?;
                            self.gc.remembered_cursor += 1;
                        } else {
                            self.gc.transition(GcPhase::Propagate);
                        }
                    } else {
                        self.gc.transition(GcPhase::Propagate);
                    }
                }
                GcPhase::Propagate => {
                    if let Some(object) = self.gc.work.pop() {
                        let traced = self.trace_gc_object(object);
                        if let Err(error) = traced {
                            self.gc.work.push(object);
                            return Err(error);
                        }
                        let slot = object.identity().ok_or(VmError::StaleObject)?.slot.index();
                        *self
                            .gc
                            .colors
                            .get_mut(slot)
                            .ok_or(VmError::LedgerInvariant)? = GcColor::Black;
                    } else {
                        self.gc.transition(GcPhase::Atomic);
                    }
                }
                GcPhase::Atomic => {
                    self.step_gc_atomic()?;
                }
                GcPhase::Sweep => {
                    if !self.gc.work.is_empty() {
                        self.gc.transition(GcPhase::Propagate);
                    } else if self.gc.sweep_cursor < self.slots.len() {
                        let index = self.gc.sweep_cursor;
                        if let Slot::Occupied { reference, .. } = &self.slots[index] {
                            if *self.gc.colors.get(index).ok_or(VmError::LedgerInvariant)?
                                == GcColor::White
                                && (self.gc.cycle != GcCycleKind::Minor
                                    || self.gc_age(*reference)? != GcAge::Old)
                            {
                                let reference = *reference;
                                let before = self.ledger.snapshot().committed;
                                self.reclaim(reference)?;
                                let after = self.ledger.snapshot().committed;
                                self.gc.reclaimed_bytes += before.saturating_sub(after);
                                self.gc.reclaimed_objects += 1;
                            }
                        }
                        self.gc.sweep_cursor += 1;
                    } else {
                        self.roots.compact();
                        self.promote_gc_survivors();
                        self.gc.clear_cycle()?;
                    }
                }
            }
        }
        if self.gc.phase == GcPhase::Pause && !self.execution_running {
            self.run_pending_finalizers()?;
        }
        Ok(self.gc_trace())
    }

    pub fn set_gc_debt_threshold(&mut self, bytes: usize) {
        self.gc.debt_threshold = bytes.max(1);
    }

    pub(crate) fn begin_gc_cycle(&mut self) -> Result<(), VmError> {
        let kind = match self.gc.mode {
            GcMode::Incremental => GcCycleKind::Full,
            GcMode::Generational if self.gc.major_debt_bytes >= self.gc.major_threshold_bytes => {
                GcCycleKind::Major
            }
            GcMode::Generational => GcCycleKind::Minor,
        };
        self.begin_gc_cycle_kind(kind)
    }

    fn begin_gc_cycle_kind(&mut self, kind: GcCycleKind) -> Result<(), VmError> {
        if self.gc.phase != GcPhase::Pause {
            return Err(VmError::WrongGcPhase);
        }
        let mut colors = Vec::new();
        let mark_ticket = reserve_vec(
            &self.ledger,
            &mut colors,
            self.slots.len(),
            FailPoint::MarkReserve,
        )?;
        for slot in &self.slots {
            let color = if kind == GcCycleKind::Minor
                && matches!(
                    slot,
                    Slot::Occupied {
                        age: GcAge::Old,
                        ..
                    }
                ) {
                GcColor::Black
            } else {
                GcColor::White
            };
            colors.push(color);
        }
        let mut work = Vec::new();
        let work_ticket = reserve_vec(
            &self.ledger,
            &mut work,
            self.slots.len(),
            FailPoint::WorkReserve,
        )?;
        let mut roots = Vec::new();
        let root_count = self
            .roots
            .total_count()
            .checked_add(self.finalizer_queue.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        let root_ticket =
            reserve_vec(&self.ledger, &mut roots, root_count, FailPoint::WorkReserve)?;
        self.roots.try_visit_all(|root| {
            self.checked_slot(root)?;
            roots.push(root);
            Ok(())
        })?;
        for entry in &self.finalizer_queue {
            self.checked_slot(entry.object)?;
            roots.push(entry.object);
        }
        self.snapshot_weak_modes()?;
        let mark_bytes = checked_bytes(self.slots.len(), size_of::<GcColor>())?;
        let work_bytes = checked_bytes(self.slots.len(), size_of::<ObjectRef>())?;
        let root_bytes = checked_bytes(root_count, size_of::<ObjectRef>())?;
        let charge = mark_bytes
            .checked_add(work_bytes)
            .and_then(|bytes| bytes.checked_add(root_bytes))
            .ok_or(VmError::ArithmeticOverflow)?;
        mark_ticket.commit()?;
        if let Err(error) = work_ticket.commit() {
            self.ledger.refund(mark_bytes)?;
            return Err(error);
        }
        if let Err(error) = root_ticket.commit() {
            self.ledger.refund(mark_bytes + work_bytes)?;
            return Err(error);
        }
        self.gc.colors = colors;
        self.gc.work = work;
        self.gc.roots = roots;
        self.gc.root_cursor = 0;
        self.gc.remembered_cursor = 0;
        self.gc.sweep_cursor = 0;
        self.gc.ephemeron_cursor = 0;
        self.gc.ephemeron_iterations = 0;
        self.gc.ephemeron_last_key = None;
        self.gc.ephemeron_converged = false;
        self.gc.weak_cleared_pairs = 0;
        self.gc.atomic_finalizer_stage = AtomicFinalizerStage::BeforeWeakValues;
        self.gc.charge = charge;
        self.gc.cycle = kind;
        self.gc.transition(GcPhase::RootMark);
        Ok(())
    }

    fn snapshot_weak_modes(&mut self) -> Result<(), VmError> {
        for index in 0..self.slots.len() {
            let Slot::Occupied {
                reference, object, ..
            } = &self.slots[index]
            else {
                continue;
            };
            let HeapPayload::Table(table) = &object[0].payload else {
                continue;
            };
            let reference = *reference;
            let mode_value = match table.metatable() {
                Some(metatable) => self.with_table(metatable, Table::mode_value)?,
                None => Value::Nil,
            };
            let mode = if let Value::Object(value) = mode_value {
                if self.object_kind(value)? == ObjectKind::ByteString {
                    self.with_byte_string(value, |string| {
                        if self.profile == LuaProfile::Lua54 && string.len() > 40 {
                            return WeakMode::Strong;
                        }
                        let bytes = string
                            .as_bytes()
                            .split(|byte| *byte == 0)
                            .next()
                            .unwrap_or(&[]);
                        match (bytes.contains(&b'k'), bytes.contains(&b'v')) {
                            (false, false) => WeakMode::Strong,
                            (true, false) => WeakMode::Keys,
                            (false, true) => WeakMode::Values,
                            (true, true) => WeakMode::All,
                        }
                    })?
                } else {
                    WeakMode::Strong
                }
            } else {
                WeakMode::Strong
            };
            self.with_table_mut(reference, |table, _| {
                table.set_weak_mode(mode);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn step_gc_atomic(&mut self) -> Result<(), VmError> {
        if !self.gc.work.is_empty() {
            self.gc.ephemeron_cursor = 0;
            self.gc.transition(GcPhase::Propagate);
            return Ok(());
        }
        if self.gc.ephemeron_cursor == 0 {
            self.gc.ephemeron_iterations += 1;
        }
        if self.gc.ephemeron_cursor < self.slots.len() {
            let index = self.gc.ephemeron_cursor;
            self.gc.ephemeron_cursor += 1;
            let slots = &self.slots;
            let gc = &mut self.gc;
            if let Slot::Occupied { object, .. } = &slots[index] {
                if gc.colors.get(index) != Some(&GcColor::White) {
                    if let HeapPayload::Table(table) = &object[0].payload {
                        table.visit_ephemeron_pairs(|key, value| {
                            let live_key = if let Some(key) = key {
                                let id = key.identity().ok_or(VmError::StaleObject)?;
                                gc_is_string(slots, self.id, key)?;
                                gc.colors.get(id.slot.index()) != Some(&GcColor::White)
                            } else {
                                true
                            };
                            if live_key {
                                let id = value.identity().ok_or(VmError::StaleObject)?;
                                if gc.colors.get(id.slot.index()) == Some(&GcColor::White) {
                                    gc_mark_slot(slots, self.id, gc, value)?;
                                    gc.ephemeron_last_key = key;
                                }
                            }
                            Ok(())
                        })?;
                    }
                }
            }
            if !self.gc.work.is_empty() {
                self.gc.ephemeron_cursor = 0;
                self.gc.transition(GcPhase::Propagate);
            }
            return Ok(());
        }
        if self.gc.mode == GcMode::Generational {
            for index in 0..self.slots.len() {
                let Slot::Occupied {
                    age: GcAge::Old,
                    reference,
                    ..
                } = &self.slots[index]
                else {
                    continue;
                };
                if self.gc.colors.get(index) == Some(&GcColor::White) {
                    continue;
                }
                self.trace_gc_object(*reference)?;
            }
            if !self.gc.work.is_empty() {
                self.gc.ephemeron_cursor = 0;
                self.gc.transition(GcPhase::Propagate);
                return Ok(());
            }
        }
        self.gc.ephemeron_converged = true;
        if self.gc.atomic_finalizer_stage == AtomicFinalizerStage::BeforeWeakValues {
            self.reserve_finalizer_candidates()?;
            self.clear_dead_weak_pairs(true, false)?;
            self.gc.atomic_finalizer_stage = AtomicFinalizerStage::BeforeSeparation;
        }
        if self.gc.atomic_finalizer_stage == AtomicFinalizerStage::BeforeSeparation {
            self.separate_dead_finalizers()?;
            self.gc.atomic_finalizer_stage = AtomicFinalizerStage::AfterSeparation;
            if !self.gc.work.is_empty() {
                self.gc.ephemeron_converged = false;
                self.gc.ephemeron_cursor = 0;
                self.gc.transition(GcPhase::Propagate);
                return Ok(());
            }
        }
        self.clear_dead_weak_pairs(false, true)?;
        if self.gc.mode == GcMode::Generational && !self.rebuild_remembered_set()? {
            self.gc.ephemeron_converged = false;
            self.gc.ephemeron_cursor = 0;
            self.gc.transition(GcPhase::Propagate);
            return Ok(());
        }
        self.gc.transition(GcPhase::Sweep);
        Ok(())
    }

    fn clear_dead_weak_pairs(
        &mut self,
        clear_values: bool,
        clear_keys: bool,
    ) -> Result<(), VmError> {
        for index in 0..self.slots.len() {
            let (before, rest) = self.slots.split_at_mut(index);
            let Some((current, after)) = rest.split_first_mut() else {
                return Err(VmError::LedgerInvariant);
            };
            let Slot::Occupied {
                reference: owner,
                object,
                ..
            } = current
            else {
                continue;
            };
            let HeapPayload::Table(table) = &mut object[0].payload else {
                continue;
            };
            let owner = *owner;
            let vm = self.id;
            let colors = &self.gc.colors;
            let cleared = table.clear_dead_weak_pairs(
                |child| {
                    let id = child.identity().ok_or(VmError::StaleObject)?;
                    if id.vm != vm {
                        return Err(VmError::WrongVm);
                    }
                    if child == owner {
                        return Ok(colors.get(index) == Some(&GcColor::White));
                    }
                    let slot = if id.slot.index() < index {
                        before.get(id.slot.index())
                    } else {
                        after.get(id.slot.index().saturating_sub(index + 1))
                    };
                    let Some(Slot::Occupied {
                        generation,
                        reference,
                        object,
                        ..
                    }) = slot
                    else {
                        return Err(VmError::StaleObject);
                    };
                    if *generation != id.generation || *reference != child {
                        return Err(VmError::StaleObject);
                    }
                    if matches!(object[0].payload, HeapPayload::ByteString(_)) {
                        return Ok(false);
                    }
                    Ok(colors.get(id.slot.index()) == Some(&GcColor::White))
                },
                clear_values,
                clear_keys,
            )?;
            self.gc.weak_cleared_pairs += cleared;
        }
        Ok(())
    }

    fn reserve_finalizer_candidates(&mut self) -> Result<(), VmError> {
        let candidates = self
            .slots
            .iter()
            .enumerate()
            .filter(|(index, slot)| {
                matches!(
                    slot,
                    Slot::Occupied {
                        finalizer: FinalizerState::Registered,
                        ..
                    }
                ) && self.gc.colors.get(*index) == Some(&GcColor::White)
            })
            .count();
        if candidates == 0 {
            return Ok(());
        }
        let charge = checked_bytes(candidates, size_of::<FinalizerEntry>())?;
        let next_charge = self
            .finalizer_queue_charge
            .checked_add(charge)
            .ok_or(VmError::ArithmeticOverflow)?;
        let ticket = reserve_vec(
            &self.ledger,
            &mut self.finalizer_queue,
            candidates,
            FailPoint::WorkReserve,
        )?;
        ticket.commit()?;
        self.finalizer_queue_charge = next_charge;
        Ok(())
    }

    fn separate_dead_finalizers(&mut self) -> Result<(), VmError> {
        for index in 0..self.slots.len() {
            let Slot::Occupied {
                reference,
                finalizer: FinalizerState::Registered,
                finalizer_order,
                ..
            } = &self.slots[index]
            else {
                continue;
            };
            if self.gc.colors.get(index) != Some(&GcColor::White) {
                continue;
            }
            let (object, order) = (*reference, *finalizer_order);
            self.mark_gc_object(object)?;
            let Slot::Occupied { finalizer, .. } = &mut self.slots[index] else {
                return Err(VmError::LedgerInvariant);
            };
            *finalizer = FinalizerState::Pending;
            self.finalizer_queue.push(FinalizerEntry { object, order });
        }
        self.finalizer_queue
            .sort_unstable_by_key(|entry| entry.order);
        Ok(())
    }

    fn mark_gc_object(&mut self, object: ObjectRef) -> Result<(), VmError> {
        gc_mark_slot(&self.slots, self.id, &mut self.gc, object)
    }

    fn trace_gc_object(&mut self, object: ObjectRef) -> Result<(), VmError> {
        let slots = &self.slots;
        let gc = &mut self.gc;
        gc_mark_slot(slots, self.id, gc, object)?;
        let slot = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        let Slot::Occupied { object: stored, .. } = &slots[slot] else {
            return Err(VmError::StaleObject);
        };
        stored[0].trace_gc_children(
            |child| gc_is_string(slots, self.id, child),
            |child| gc_mark_slot(slots, self.id, gc, child),
        )
    }

    fn future_gc_age_at(&self, index: usize) -> Result<Option<GcAge>, VmError> {
        let Some(Slot::Occupied { age, survivals, .. }) = self.slots.get(index) else {
            return Ok(None);
        };
        if self.gc.cycle == GcCycleKind::Minor && *age == GcAge::Old {
            return Ok(Some(GcAge::Old));
        }
        if self
            .gc
            .colors
            .get(index)
            .copied()
            .ok_or(VmError::LedgerInvariant)?
            == GcColor::White
        {
            return Ok(None);
        }
        if *age == GcAge::Old || self.gc.mode == GcMode::Incremental {
            return Ok(Some(*age));
        }
        let survived = survivals.saturating_add(1);
        Ok(Some(if survived >= self.gc.promotion_survivals {
            GcAge::Old
        } else {
            GcAge::Survivor
        }))
    }

    fn old_owner_has_young_child(
        &self,
        index: usize,
    ) -> Result<(bool, Option<ObjectRef>), VmError> {
        let Slot::Occupied { object, .. } = &self.slots[index] else {
            return Ok((false, None));
        };
        let mut young = false;
        let mut white_child = None;
        object[0].trace_children(|child| {
            self.checked_slot(child)?;
            let child_index = child.identity().ok_or(VmError::StaleObject)?.slot.index();
            match self.future_gc_age_at(child_index)? {
                Some(GcAge::Old) => {}
                Some(GcAge::Young | GcAge::Survivor) => young = true,
                None => white_child = Some(child),
            }
            Ok(())
        })?;
        Ok((young, white_child))
    }

    fn rebuild_remembered_set(&mut self) -> Result<bool, VmError> {
        let mut count = 0usize;
        for index in 0..self.slots.len() {
            if self.future_gc_age_at(index)? != Some(GcAge::Old) {
                continue;
            }
            let (young, white_child) = self.old_owner_has_young_child(index)?;
            if let Some(child) = white_child {
                self.mark_gc_object(child)?;
                return Ok(false);
            }
            count += usize::from(young);
        }
        if count == 0 {
            self.gc.clear_remembered()?;
            return Ok(true);
        }
        let mut next = Vec::new();
        let ticket = reserve_vec(&self.ledger, &mut next, count, FailPoint::RememberedReserve)?;
        for index in 0..self.slots.len() {
            if self.future_gc_age_at(index)? != Some(GcAge::Old) {
                continue;
            }
            if self.old_owner_has_young_child(index)?.0 {
                let Slot::Occupied { reference, .. } = &self.slots[index] else {
                    return Err(VmError::LedgerInvariant);
                };
                next.push(*reference);
            }
        }
        let charge = checked_bytes(count, size_of::<ObjectRef>())?;
        self.gc.clear_remembered()?;
        ticket.commit()?;
        self.gc.remembered = next;
        self.gc.remembered_charge = charge;
        Ok(true)
    }

    fn promote_gc_survivors(&mut self) {
        if self.gc.mode != GcMode::Generational {
            return;
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            let Slot::Occupied { age, survivals, .. } = slot else {
                continue;
            };
            if *age == GcAge::Old || self.gc.colors.get(index) != Some(&GcColor::Black) {
                continue;
            }
            *survivals = survivals.saturating_add(1);
            *age = if *survivals >= self.gc.promotion_survivals {
                GcAge::Old
            } else {
                GcAge::Survivor
            };
        }
    }

    fn remember_gc_owner(&mut self, owner: ObjectRef) -> Result<(), VmError> {
        if self.gc.remembered.contains(&owner) {
            return Ok(());
        }
        let next_charge = self
            .gc
            .remembered_charge
            .checked_add(size_of::<ObjectRef>())
            .ok_or(VmError::ArithmeticOverflow)?;
        let ticket = reserve_vec(
            &self.ledger,
            &mut self.gc.remembered,
            1,
            FailPoint::RememberedReserve,
        )?;
        ticket.commit()?;
        self.gc.remembered.push(owner);
        self.gc.remembered_charge = next_charge;
        Ok(())
    }

    pub(crate) const fn allocation_ledger(&self) -> &AllocationLedger {
        &self.ledger
    }

    pub fn set_allocation_limit(&mut self, limit: usize) {
        self.ledger.set_limit(limit);
    }

    pub fn inject_failure_once(&mut self, point: FailPoint) {
        self.ledger.fail_once_at(point);
    }

    /// 測試模式：每次成功配置後執行一次完整收集。
    pub fn set_collect_every_allocation(&mut self, enabled: bool) {
        self.collect_every_allocation = enabled;
    }

    pub fn add_root(&mut self, kind: RootKind, object: ObjectRef) -> Result<RootId, VmError> {
        self.checked_slot(object)?;
        self.mark_gc_object(object)?;
        self.roots.add(&self.ledger, kind, object)
    }

    pub fn remove_root(&mut self, root: RootId) -> Result<ObjectRef, VmError> {
        self.roots.remove(&self.ledger, root)
    }

    pub(crate) fn add_host_root(
        &mut self,
        object: ObjectRef,
    ) -> Result<(RootId, RootLease), VmError> {
        self.checked_slot(object)?;
        self.mark_gc_object(object)?;
        self.roots.add_host(&self.ledger, object)
    }

    pub fn allocate(&mut self, value: Value) -> Result<ObjectRef, VmError> {
        if let Value::Object(child) = value {
            self.checked_slot(child)?;
        }
        self.allocate_payload(HeapPayload::Value(value))
    }

    /// 建立完整內容的 byte string；失敗時 payload 與帳本票據均丟棄。
    pub fn allocate_byte_string(&mut self, bytes: &[u8]) -> Result<ObjectRef, VmError> {
        let (string, ticket) = ByteString::try_from_bytes(&self.ledger, bytes)?;
        let reference = self.allocate_payload(HeapPayload::ByteString(string))?;
        ticket.commit()?;
        Ok(reference)
    }

    /// 複製期間保護來源；建立新 payload 時也沿用配置器的短期 root。
    pub fn clone_byte_string(&mut self, source: ObjectRef) -> Result<ObjectRef, VmError> {
        let root = self.add_root(RootKind::Temporary, source)?;
        let result = (|| {
            let (string, ticket) = self.with_byte_string(source, |string| {
                ByteString::try_from_bytes(&self.ledger, string.as_bytes())
            })??;
            let reference = self.allocate_payload(HeapPayload::ByteString(string))?;
            ticket.commit()?;
            Ok(reference)
        })();
        let removed = self.remove_root(root);
        removed?;
        result
    }

    pub fn allocate_table(&mut self) -> Result<ObjectRef, VmError> {
        self.allocate_table_with_capacity(0, 0)
    }

    /// 將本階段唯一三個內建入口安裝至宿主提供的環境。
    pub fn install_error_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let result = (|| {
            for (name, builtin) in [
                (b"error".as_slice(), Builtin::Error),
                (b"pcall".as_slice(), Builtin::PCall),
                (b"xpcall".as_slice(), Builtin::XPCall),
            ] {
                self.install_one_builtin(environment, name, builtin)?;
            }
            Ok(())
        })();
        self.remove_root(env_root)?;
        result
    }

    /// 先建好完整函式庫，再以單一環境欄位發布。
    pub fn install_debug_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            let library = self.allocate_table()?;
            let library_root = self.add_root(RootKind::Temporary, library)?;
            let staged = (|| {
                for (name, builtin) in [
                    (b"getinfo".as_slice(), DebugBuiltin::GetInfo),
                    (b"getlocal", DebugBuiltin::GetLocal),
                    (b"setlocal", DebugBuiltin::SetLocal),
                    (b"getupvalue", DebugBuiltin::GetUpvalue),
                    (b"setupvalue", DebugBuiltin::SetUpvalue),
                    (b"upvalueid", DebugBuiltin::UpvalueId),
                    (b"upvaluejoin", DebugBuiltin::UpvalueJoin),
                    (b"traceback", DebugBuiltin::Traceback),
                    (b"sethook", DebugBuiltin::SetHook),
                    (b"gethook", DebugBuiltin::GetHook),
                    (b"getmetatable", DebugBuiltin::GetMetatable),
                    (b"setmetatable", DebugBuiltin::SetMetatable),
                    (b"getregistry", DebugBuiltin::GetRegistry),
                    (b"getuservalue", DebugBuiltin::GetUserValue),
                    (b"setuservalue", DebugBuiltin::SetUserValue),
                    (b"debug", DebugBuiltin::Debug),
                ] {
                    self.install_one_builtin(library, name, Builtin::Debug(builtin))?;
                }
                if self.profile == LuaProfile::Lua54 {
                    self.install_one_builtin(
                        library,
                        b"setcstacklimit",
                        Builtin::Debug(DebugBuiltin::SetCStackLimit),
                    )?;
                }
                let key = self.allocate_byte_string(b"debug")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let published = (|| {
                    let old = self.raw_get(environment, Value::Object(key))?;
                    let old_root = match old {
                        Value::Object(object) => Some(self.add_root(RootKind::Temporary, object)?),
                        _ => None,
                    };
                    let result = (|| {
                        if let Value::Object(object) = old {
                            self.write_ref(environment, RefField::TableValue, object)?;
                        }
                        self.raw_set(environment, Value::Object(key), Value::Object(library))
                    })();
                    if let Some(root) = old_root {
                        self.remove_root(root)?;
                    }
                    result
                })();
                self.remove_root(key_root)?;
                published
            })();
            self.remove_root(library_root)?;
            staged
        })();
        self.remove_root(env_root)?;
        installed
    }

    pub fn install_io_os_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let mut first_holder = None;
        let mut staged_streams = [None; 3];
        let installed = (|| {
            let holder = if let Some((holder, _)) = self.io_registry {
                holder
            } else {
                let holder = self.allocate_table()?;
                let root = self.add_root(RootKind::Registry, holder)?;
                first_holder = Some((holder, root));
                holder
            };
            let io = self.allocate_table()?;
            let io_root = self.add_root(RootKind::Temporary, io)?;
            let staged = (|| {
                let os = self.allocate_table()?;
                let os_root = self.add_root(RootKind::Temporary, os)?;
                let staged = (|| {
                    for (name, kind) in [
                        (b"open".as_slice(), IoBuiltin::Open),
                        (b"close", IoBuiltin::Close),
                        (b"flush", IoBuiltin::Flush),
                        (b"input", IoBuiltin::Input),
                        (b"output", IoBuiltin::Output),
                        (b"lines", IoBuiltin::Lines),
                        (b"read", IoBuiltin::Read),
                        (b"write", IoBuiltin::Write),
                        (b"type", IoBuiltin::Type),
                        (b"tmpfile", IoBuiltin::TmpFile),
                        (b"popen", IoBuiltin::POpen),
                    ] {
                        self.install_one_builtin(io, name, Builtin::Io(kind))?;
                    }
                    for (name, kind) in [
                        (b"clock".as_slice(), OsBuiltin::Clock),
                        (b"date", OsBuiltin::Date),
                        (b"difftime", OsBuiltin::Difftime),
                        (b"execute", OsBuiltin::Execute),
                        (b"exit", OsBuiltin::Exit),
                        (b"getenv", OsBuiltin::GetEnv),
                        (b"remove", OsBuiltin::Remove),
                        (b"rename", OsBuiltin::Rename),
                        (b"setlocale", OsBuiltin::SetLocale),
                        (b"time", OsBuiltin::Time),
                        (b"tmpname", OsBuiltin::TmpName),
                    ] {
                        self.install_one_builtin(os, name, Builtin::Os(kind))?;
                    }
                    if first_holder.is_some() {
                        self.install_file_metatable(holder)?;
                        self.install_standard_streams(holder, io, &mut staged_streams)?;
                    } else {
                        for name in [b"stdin".as_slice(), b"stdout", b"stderr"] {
                            let value = self.io_holder_field(holder, name)?;
                            if value != Value::Nil {
                                self.set_string_field(io, name, value)?;
                            }
                        }
                    }
                    self.publish_io_os(environment, io, os)
                })();
                self.remove_root(os_root)?;
                staged
            })();
            self.remove_root(io_root)?;
            staged?;
            if let Some(registry) = first_holder.take() {
                self.io_registry = Some(registry);
            }
            Ok(())
        })();
        if installed.is_err() {
            if let Some((_, root)) = first_holder.take() {
                for file in staged_streams.into_iter().flatten() {
                    self.with_file_mut(file, |payload| {
                        payload.lease.take();
                        payload.charge.take();
                    })?;
                }
                self.remove_root(root)?;
            }
        }
        self.remove_root(env_root)?;
        installed
    }

    fn install_file_metatable(&mut self, holder: ObjectRef) -> Result<(), VmError> {
        let methods = self.allocate_table()?;
        let methods_root = self.add_root(RootKind::Temporary, methods)?;
        let installed = (|| {
            for (name, kind) in [
                (b"close".as_slice(), IoBuiltin::FileClose),
                (b"flush", IoBuiltin::FileFlush),
                (b"lines", IoBuiltin::FileLines),
                (b"read", IoBuiltin::FileRead),
                (b"write", IoBuiltin::FileWrite),
                (b"seek", IoBuiltin::FileSeek),
                (b"setvbuf", IoBuiltin::FileSetVBuf),
            ] {
                self.install_one_builtin(methods, name, Builtin::Io(kind))?;
            }
            let metatable = self.allocate_table()?;
            let meta_root = self.add_root(RootKind::Temporary, metatable)?;
            let installed = (|| {
                self.set_string_field(metatable, b"__index", Value::Object(methods))?;
                for (name, kind) in [
                    (b"__gc".as_slice(), IoBuiltin::FileGc),
                    (b"__close", IoBuiltin::FileGc),
                    (b"__tostring", IoBuiltin::FileToString),
                ] {
                    self.install_one_builtin(metatable, name, Builtin::Io(kind))?;
                }
                self.set_string_field(holder, b"metatable", Value::Object(metatable))
            })();
            self.remove_root(meta_root)?;
            installed
        })();
        self.remove_root(methods_root)?;
        installed
    }

    pub(crate) fn io_holder_field(
        &mut self,
        holder: ObjectRef,
        name: &[u8],
    ) -> Result<Value, VmError> {
        let key = self.allocate_byte_string(name)?;
        self.raw_get(holder, Value::Object(key))
    }

    fn io_file_metatable(&mut self, holder: ObjectRef) -> Result<ObjectRef, VmError> {
        let Value::Object(metatable) = self.io_holder_field(holder, b"metatable")? else {
            return Err(VmError::WrongObjectType);
        };
        Ok(metatable)
    }

    pub(crate) fn io_holder(&self) -> Option<ObjectRef> {
        self.io_registry.map(|(holder, _)| holder)
    }

    pub(crate) fn file_metatable(&mut self) -> Result<ObjectRef, VmError> {
        let holder = self.io_holder().ok_or(VmError::WrongObjectType)?;
        self.io_file_metatable(holder)
    }

    pub(crate) fn set_io_default(&mut self, input: bool, file: ObjectRef) -> Result<(), VmError> {
        self.with_file(file, |_| ())?;
        let holder = self.io_holder().ok_or(VmError::WrongObjectType)?;
        self.set_string_field(
            holder,
            if input { b"input" } else { b"output" },
            Value::Object(file),
        )
    }

    fn install_standard_streams(
        &mut self,
        holder: ObjectRef,
        io: ObjectRef,
        staged_streams: &mut [Option<ObjectRef>; 3],
    ) -> Result<(), VmError> {
        if !self.host_io_available() {
            return Ok(());
        }
        let metatable = self.io_file_metatable(holder)?;
        for (which, name) in [(0_u8, b"stdin".as_slice()), (1, b"stdout"), (2, b"stderr")] {
            let limits = self.resource_limits();
            let mut fuel = u64::MAX;
            let mut finalizer_steps = 0;
            let mut budget = ResourceBudget::metered(
                limits,
                &mut fuel,
                &mut finalizer_steps,
                false,
                self.ledger.clone(),
            );
            budget
                .spend_work(1)
                .map_err(|error| VmError::HostResource(error.kind))?;
            let lease = self
                .host_io_standard(which, &mut budget)
                .map_err(|error| VmError::HostResource(error.kind))?;
            if budget.stop().is_some() {
                return Err(VmError::HostResource(HostResourceErrorKind::Budget));
            }
            let retained = budget.claimed_retained();
            if retained == 0 {
                return Err(VmError::HostResource(HostResourceErrorKind::Budget));
            }
            let charge = budget
                .take_retained_charge()
                .ok_or(VmError::LedgerInvariant)?;
            let file = self.allocate_file(lease, true, charge, Some(metatable))?;
            staged_streams[usize::from(which)] = Some(file);
            let root = self.add_root(RootKind::Temporary, file)?;
            let inserted = (|| {
                self.set_string_field(holder, name, Value::Object(file))?;
                self.set_string_field(io, name, Value::Object(file))?;
                if which == 0 {
                    self.set_string_field(holder, b"input", Value::Object(file))?;
                }
                if which == 1 {
                    self.set_string_field(holder, b"output", Value::Object(file))?;
                }
                Ok(())
            })();
            self.remove_root(root)?;
            inserted?;
        }
        Ok(())
    }

    fn publish_io_os(
        &mut self,
        environment: ObjectRef,
        io: ObjectRef,
        os: ObjectRef,
    ) -> Result<(), VmError> {
        let io_key = self.allocate_byte_string(b"io")?;
        let io_key_root = self.add_root(RootKind::Temporary, io_key)?;
        let result = (|| {
            let os_key = self.allocate_byte_string(b"os")?;
            let os_key_root = self.add_root(RootKind::Temporary, os_key)?;
            let result = (|| {
                let old_io = self.raw_get(environment, Value::Object(io_key))?;
                let old_os = self.raw_get(environment, Value::Object(os_key))?;
                let old_io_root = if let Value::Object(object) = old_io {
                    Some(self.add_root(RootKind::Temporary, object)?)
                } else {
                    None
                };
                let result = (|| {
                    let old_os_root = if let Value::Object(object) = old_os {
                        Some(self.add_root(RootKind::Temporary, object)?)
                    } else {
                        None
                    };
                    let result = (|| {
                        if let Value::Object(object) = old_io {
                            self.write_ref(environment, RefField::TableValue, object)?;
                        }
                        self.raw_set(environment, Value::Object(io_key), Value::Object(io))?;
                        if let Err(error) =
                            self.raw_set(environment, Value::Object(os_key), Value::Object(os))
                        {
                            self.restore_existing_byte_key(environment, b"io", old_io)?;
                            return Err(error);
                        }
                        Ok(())
                    })();
                    if let Some(root) = old_os_root {
                        self.remove_root(root)?;
                    }
                    result
                })();
                if let Some(root) = old_io_root {
                    self.remove_root(root)?;
                }
                result
            })();
            self.remove_root(os_key_root)?;
            result
        })();
        self.remove_root(io_key_root)?;
        result
    }

    pub fn install_basic_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            self.install_error_builtins(environment)?;
            for (name, builtin) in [
                (b"assert".as_slice(), BasicBuiltin::Assert),
                (b"select", BasicBuiltin::Select),
                (b"type", BasicBuiltin::Type),
                (b"tostring", BasicBuiltin::ToString),
                (b"tonumber", BasicBuiltin::ToNumber),
                (b"next", BasicBuiltin::Next),
                (b"pairs", BasicBuiltin::Pairs),
                (b"ipairs", BasicBuiltin::IPairs),
                (b"getmetatable", BasicBuiltin::GetMetatable),
                (b"setmetatable", BasicBuiltin::SetMetatable),
                (b"rawget", BasicBuiltin::RawGet),
                (b"rawset", BasicBuiltin::RawSet),
                (b"rawequal", BasicBuiltin::RawEqual),
                (b"rawlen", BasicBuiltin::RawLen),
                (b"print", BasicBuiltin::Print),
            ] {
                self.install_one_builtin(environment, name, Builtin::Basic(builtin))?;
            }
            for (name, kind) in [
                (b"load".as_slice(), LoadBuiltin::Load { environment }),
                (b"loadfile", LoadBuiltin::LoadFile { environment }),
                (b"dofile", LoadBuiltin::DoFile { environment }),
            ] {
                self.install_one_builtin(environment, name, Builtin::Load(kind))?;
            }
            Ok(())
        })();
        self.remove_root(env_root)?;
        installed
    }

    pub(crate) fn package_loaded(&self) -> Option<ObjectRef> {
        self.package_registry.map(|registry| registry.loaded)
    }

    pub(crate) fn package_preload(&self) -> Option<ObjectRef> {
        self.package_registry.map(|registry| registry.preload)
    }

    pub(crate) fn set_string_field(
        &mut self,
        table: ObjectRef,
        name: &[u8],
        value: Value,
    ) -> Result<(), VmError> {
        let value_root = if let Value::Object(object) = value {
            Some(self.add_root(RootKind::Temporary, object)?)
        } else {
            None
        };
        let result = (|| {
            let key = self.allocate_byte_string(name)?;
            let key_root = self.add_root(RootKind::Temporary, key)?;
            let inserted = self.raw_set(table, Value::Object(key), value);
            self.remove_root(key_root)?;
            inserted
        })();
        if let Some(root) = value_root {
            self.remove_root(root)?;
        }
        result
    }

    fn install_searcher(
        &mut self,
        searchers: ObjectRef,
        index: i64,
        kind: LoadBuiltin,
    ) -> Result<(), VmError> {
        let function = self.allocate_payload(HeapPayload::Builtin(Builtin::Load(kind)))?;
        let root = self.add_root(RootKind::Temporary, function)?;
        let inserted = self.raw_set(searchers, Value::Integer(index), Value::Object(function));
        self.remove_root(root)?;
        inserted
    }

    /// 先完整建立 package，再發布 env.package／env.require；失敗恢復舊值。
    pub fn install_package_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let mut first_registry_roots = None;
        let installed = (|| {
            let (loaded, preload) = if let Some(registry) = self.package_registry {
                (registry.loaded, registry.preload)
            } else {
                let loaded = self.allocate_table()?;
                let loaded_root = self.add_root(RootKind::Registry, loaded)?;
                let preload = match self.allocate_table() {
                    Ok(preload) => preload,
                    Err(error) => {
                        self.remove_root(loaded_root)?;
                        return Err(error);
                    }
                };
                let preload_root = match self.add_root(RootKind::Registry, preload) {
                    Ok(root) => root,
                    Err(error) => {
                        self.remove_root(loaded_root)?;
                        return Err(error);
                    }
                };
                first_registry_roots = Some(PackageRegistry {
                    loaded,
                    loaded_root,
                    preload,
                    preload_root,
                });
                (loaded, preload)
            };
            let package = self.allocate_table()?;
            let package_root = self.add_root(RootKind::Temporary, package)?;
            let staged = (|| {
                let searchers = self.allocate_table_with_capacity(4, 0)?;
                let searchers_root = self.add_root(RootKind::Temporary, searchers)?;
                let staged_searchers = (|| {
                    let mut index = 1;
                    self.install_searcher(searchers, index, LoadBuiltin::PreloadSearcher)?;
                    if self.host_services.load.repository.is_some() {
                        index += 1;
                        self.install_searcher(
                            searchers,
                            index,
                            LoadBuiltin::LuaSearcher {
                                package,
                                environment,
                            },
                        )?;
                    }
                    if self.host_services.load.native.is_some() {
                        index += 1;
                        self.install_searcher(
                            searchers,
                            index,
                            LoadBuiltin::NativeSearcher {
                                package,
                                environment,
                                root: false,
                            },
                        )?;
                        index += 1;
                        self.install_searcher(
                            searchers,
                            index,
                            LoadBuiltin::NativeSearcher {
                                package,
                                environment,
                                root: true,
                            },
                        )?;
                    }
                    self.set_string_field(package, b"loaded", Value::Object(loaded))?;
                    self.set_string_field(package, b"preload", Value::Object(preload))?;
                    self.set_string_field(package, b"searchers", Value::Object(searchers))?;
                    let path = self.allocate_byte_string(b"")?;
                    self.set_string_field(package, b"path", Value::Object(path))?;
                    let cpath = self.allocate_byte_string(b"")?;
                    self.set_string_field(package, b"cpath", Value::Object(cpath))?;
                    Ok(())
                })();
                self.remove_root(searchers_root)?;
                staged_searchers?;
                let require = self.allocate_payload(HeapPayload::Builtin(Builtin::Load(
                    LoadBuiltin::Require { package },
                )))?;
                let require_root = self.add_root(RootKind::Temporary, require)?;
                let published = (|| {
                    let package_key = self.allocate_byte_string(b"package")?;
                    let package_key_root = self.add_root(RootKind::Temporary, package_key)?;
                    let result = (|| {
                        let require_key = self.allocate_byte_string(b"require")?;
                        let require_key_root = self.add_root(RootKind::Temporary, require_key)?;
                        let result = (|| {
                            let old_package =
                                self.raw_get(environment, Value::Object(package_key))?;
                            let old_require =
                                self.raw_get(environment, Value::Object(require_key))?;
                            let old_package_root = if let Value::Object(object) = old_package {
                                Some(self.add_root(RootKind::Temporary, object)?)
                            } else {
                                None
                            };
                            let result = (|| {
                                let old_require_root = if let Value::Object(object) = old_require {
                                    Some(self.add_root(RootKind::Temporary, object)?)
                                } else {
                                    None
                                };
                                let result = (|| {
                                    if let Value::Object(object) = old_package {
                                        self.write_ref(environment, RefField::TableValue, object)?;
                                    }
                                    if let Value::Object(object) = old_require {
                                        self.write_ref(environment, RefField::TableValue, object)?;
                                    }
                                    self.raw_set(
                                        environment,
                                        Value::Object(package_key),
                                        Value::Object(package),
                                    )?;
                                    if let Err(error) = self.raw_set(
                                        environment,
                                        Value::Object(require_key),
                                        Value::Object(require),
                                    ) {
                                        self.restore_existing_byte_key(
                                            environment,
                                            b"package",
                                            old_package,
                                        )?;
                                        return Err(error);
                                    }
                                    Ok(())
                                })();
                                if let Some(root) = old_require_root {
                                    self.remove_root(root)?;
                                }
                                result
                            })();
                            if let Some(root) = old_package_root {
                                self.remove_root(root)?;
                            }
                            result
                        })();
                        self.remove_root(require_key_root)?;
                        result
                    })();
                    self.remove_root(package_key_root)?;
                    result
                })();
                self.remove_root(require_root)?;
                published
            })();
            self.remove_root(package_root)?;
            staged?;
            if let Some(registry) = first_registry_roots.take() {
                self.package_registry = Some(registry);
            }
            Ok(())
        })();
        if installed.is_err() {
            if let Some(registry) = first_registry_roots.take() {
                self.remove_root(registry.preload_root)?;
                self.remove_root(registry.loaded_root)?;
            }
        }
        self.remove_root(env_root)?;
        installed
    }

    pub fn install_table_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            let table = self.allocate_table()?;
            let table_root = self.add_root(RootKind::Temporary, table)?;
            let result = (|| {
                for (name, builtin) in [
                    (b"concat".as_slice(), TableBuiltin::Concat),
                    (b"insert", TableBuiltin::Insert),
                    (b"remove", TableBuiltin::Remove),
                    (b"move", TableBuiltin::Move),
                    (b"pack", TableBuiltin::Pack),
                    (b"unpack", TableBuiltin::Unpack),
                    (b"sort", TableBuiltin::Sort),
                ] {
                    self.install_one_builtin(table, name, Builtin::Table(builtin))?;
                }
                let key = self.allocate_byte_string(b"table")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let inserted = self.raw_set(environment, Value::Object(key), Value::Object(table));
                self.remove_root(key_root)?;
                inserted
            })();
            self.remove_root(table_root)?;
            result
        })();
        self.remove_root(env_root)?;
        installed
    }

    pub fn install_math_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            let library = self.allocate_table()?;
            let library_root = self.add_root(RootKind::Temporary, library)?;
            let result = (|| {
                for (name, builtin) in [
                    (b"abs".as_slice(), MathBuiltin::Abs),
                    (b"acos", MathBuiltin::Acos),
                    (b"asin", MathBuiltin::Asin),
                    (b"atan", MathBuiltin::Atan),
                    (b"ceil", MathBuiltin::Ceil),
                    (b"cos", MathBuiltin::Cos),
                    (b"deg", MathBuiltin::Deg),
                    (b"exp", MathBuiltin::Exp),
                    (b"floor", MathBuiltin::Floor),
                    (b"fmod", MathBuiltin::Fmod),
                    (b"log", MathBuiltin::Log),
                    (b"max", MathBuiltin::Max),
                    (b"min", MathBuiltin::Min),
                    (b"modf", MathBuiltin::Modf),
                    (b"rad", MathBuiltin::Rad),
                    (b"sin", MathBuiltin::Sin),
                    (b"sqrt", MathBuiltin::Sqrt),
                    (b"tan", MathBuiltin::Tan),
                    (b"tointeger", MathBuiltin::ToInteger),
                    (b"type", MathBuiltin::Type),
                    (b"ult", MathBuiltin::Ult),
                    (b"random", MathBuiltin::Random),
                    (b"randomseed", MathBuiltin::RandomSeed),
                ] {
                    self.install_one_builtin(library, name, Builtin::Math(builtin))?;
                }
                if self.profile == LuaProfile::Lua55 {
                    self.install_one_builtin(library, b"frexp", Builtin::Math(MathBuiltin::Frexp))?;
                    self.install_one_builtin(library, b"ldexp", Builtin::Math(MathBuiltin::Ldexp))?;
                }
                for (name, value) in [
                    (b"pi".as_slice(), Value::Float(core::f64::consts::PI)),
                    (b"huge", Value::Float(f64::INFINITY)),
                    (b"maxinteger", Value::Integer(i64::MAX)),
                    (b"mininteger", Value::Integer(i64::MIN)),
                ] {
                    let key = self.allocate_byte_string(name)?;
                    let key_root = self.add_root(RootKind::Temporary, key)?;
                    let inserted = self.raw_set(library, Value::Object(key), value);
                    self.remove_root(key_root)?;
                    if inserted.is_err() {
                        self.reclaim(key)?;
                    }
                    inserted?;
                }
                let key = self.allocate_byte_string(b"math")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let inserted =
                    self.raw_set(environment, Value::Object(key), Value::Object(library));
                self.remove_root(key_root)?;
                if inserted.is_err() {
                    self.reclaim(key)?;
                }
                inserted
            })();
            self.remove_root(library_root)?;
            result
        })();
        self.remove_root(env_root)?;
        installed
    }

    pub fn install_utf8_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            let library = self.allocate_table()?;
            let library_root = self.add_root(RootKind::Temporary, library)?;
            let result = (|| {
                for (name, kind) in [
                    (b"len".as_slice(), Utf8Builtin::Len),
                    (b"codepoint", Utf8Builtin::Codepoint),
                    (b"char", Utf8Builtin::Char),
                    (b"offset", Utf8Builtin::Offset),
                ] {
                    self.install_one_builtin(library, name, Builtin::Utf8(kind))?;
                }

                let strict = self.allocate_payload(HeapPayload::Builtin(Builtin::Utf8(
                    Utf8Builtin::Iterator { strict: true },
                )))?;
                let strict_root = self.add_root(RootKind::Temporary, strict)?;
                let iterators = (|| {
                    let lax = self.allocate_payload(HeapPayload::Builtin(Builtin::Utf8(
                        Utf8Builtin::Iterator { strict: false },
                    )))?;
                    let lax_root = self.add_root(RootKind::Temporary, lax)?;
                    let inserted = self.install_one_builtin(
                        library,
                        b"codes",
                        Builtin::Utf8(Utf8Builtin::Codes { strict, lax }),
                    );
                    self.remove_root(lax_root)?;
                    inserted
                })();
                self.remove_root(strict_root)?;
                iterators?;

                let pattern = self.allocate_byte_string(utf8_lib::CHAR_PATTERN)?;
                let pattern_root = self.add_root(RootKind::Temporary, pattern)?;
                let pattern_result = (|| {
                    let key = self.allocate_byte_string(b"charpattern")?;
                    let key_root = self.add_root(RootKind::Temporary, key)?;
                    let inserted =
                        self.raw_set(library, Value::Object(key), Value::Object(pattern));
                    self.remove_root(key_root)?;
                    if inserted.is_err() {
                        self.reclaim(key)?;
                    }
                    inserted
                })();
                self.remove_root(pattern_root)?;
                if pattern_result.is_err() {
                    self.reclaim(pattern)?;
                }
                pattern_result?;

                let key = self.allocate_byte_string(b"utf8")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let inserted =
                    self.raw_set(environment, Value::Object(key), Value::Object(library));
                self.remove_root(key_root)?;
                if inserted.is_err() {
                    self.reclaim(key)?;
                }
                inserted
            })();
            self.remove_root(library_root)?;
            result
        })();
        self.remove_root(env_root)?;
        installed
    }

    /// 每個 VM 自己持有 string 型別 metatable；重裝時只替換成功建成的版本。
    pub fn install_string_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let installed = (|| {
            let library = self.allocate_table()?;
            let library_root = self.add_root(RootKind::Temporary, library)?;
            let result = (|| {
                let metatable = self.allocate_table()?;
                let meta_root = self.add_root(RootKind::Temporary, metatable)?;
                let result = (|| {
                    for (name, builtin) in [
                        (b"byte".as_slice(), StringBuiltin::Byte),
                        (b"char", StringBuiltin::Char),
                        (b"find", StringBuiltin::Find),
                        (b"match", StringBuiltin::Match),
                        (b"gmatch", StringBuiltin::GMatch),
                        (b"gsub", StringBuiltin::GSub),
                        (b"len", StringBuiltin::Len),
                        (b"lower", StringBuiltin::Lower),
                        (b"upper", StringBuiltin::Upper),
                        (b"rep", StringBuiltin::Rep),
                        (b"reverse", StringBuiltin::Reverse),
                        (b"sub", StringBuiltin::Sub),
                        (b"format", StringBuiltin::Format),
                        (b"dump", StringBuiltin::Dump),
                        (b"pack", StringBuiltin::Pack),
                        (b"unpack", StringBuiltin::Unpack),
                        (b"packsize", StringBuiltin::PackSize),
                    ] {
                        self.install_one_builtin(library, name, Builtin::String(builtin))?;
                    }
                    let index_key = self.allocate_byte_string(b"__index")?;
                    let index_root = self.add_root(RootKind::Temporary, index_key)?;
                    let indexed =
                        self.raw_set(metatable, Value::Object(index_key), Value::Object(library));
                    self.remove_root(index_root)?;
                    if indexed.is_err() {
                        self.reclaim(index_key)?;
                    }
                    indexed?;
                    let name = self.allocate_byte_string(b"string")?;
                    let name_root = self.add_root(RootKind::Temporary, name)?;
                    let registry_root = self.add_root(RootKind::Registry, metatable);
                    let installed = match registry_root {
                        Ok(registry_root) => {
                            let result = self.raw_set(
                                environment,
                                Value::Object(name),
                                Value::Object(library),
                            );
                            if result.is_err() {
                                self.remove_root(registry_root)?;
                            } else if let Some((_, prior_root)) =
                                self.string_metatable.replace((metatable, registry_root))
                            {
                                self.remove_root(prior_root)?;
                            }
                            result
                        }
                        Err(error) => Err(error),
                    };
                    self.remove_root(name_root)?;
                    if installed.is_err() {
                        self.reclaim(name)?;
                    }
                    installed
                })();
                self.remove_root(meta_root)?;
                result
            })();
            self.remove_root(library_root)?;
            result
        })();
        self.remove_root(env_root)?;
        installed
    }

    pub(crate) fn string_metatable(&self) -> Option<ObjectRef> {
        self.string_metatable.map(|(object, _)| object)
    }

    pub(crate) fn string_index_event(&mut self) -> Result<Option<Value>, VmError> {
        let Some(metatable) = self.string_metatable() else {
            return Ok(None);
        };
        let key = self.allocate_byte_string(b"__index")?;
        let event = self.raw_get(metatable, Value::Object(key));
        self.reclaim(key)?;
        event.map(Some)
    }

    /// 安裝本階段必要的 coroutine 入口。
    pub fn install_coroutine_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let result = (|| {
            let table = self.allocate_table()?;
            let table_root = self.add_root(RootKind::Temporary, table)?;
            let installed = (|| {
                for (name, builtin) in [
                    (b"create".as_slice(), Builtin::CoroutineCreate),
                    (b"resume".as_slice(), Builtin::CoroutineResume),
                    (b"yield".as_slice(), Builtin::CoroutineYield),
                    (b"status".as_slice(), Builtin::CoroutineStatus),
                    (b"close".as_slice(), Builtin::CoroutineClose),
                    (b"wrap".as_slice(), Builtin::CoroutineWrap),
                ] {
                    self.install_one_builtin(table, name, builtin)?;
                }
                let key = self.allocate_byte_string(b"coroutine")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let result = self.raw_set(environment, Value::Object(key), Value::Object(table));
                self.remove_root(key_root)?;
                result
            })();
            self.remove_root(table_root)?;
            installed
        })();
        self.remove_root(env_root)?;
        result
    }

    fn install_one_builtin(
        &mut self,
        environment: ObjectRef,
        name: &[u8],
        builtin: Builtin,
    ) -> Result<(), VmError> {
        let key = self.allocate_byte_string(name)?;
        let key_root = match self.add_root(RootKind::Temporary, key) {
            Ok(root) => root,
            Err(error) => return Err(error),
        };
        let result = (|| {
            let value = self.allocate_payload(HeapPayload::Builtin(builtin))?;
            let value_root = match self.add_root(RootKind::Temporary, value) {
                Ok(root) => root,
                Err(error) => return Err(error),
            };
            let inserted = self.raw_set(environment, Value::Object(key), Value::Object(value));
            self.remove_root(value_root)?;
            inserted
        })();
        self.remove_root(key_root)?;
        result
    }

    pub(crate) fn builtin(&self, object: ObjectRef) -> Result<Builtin, VmError> {
        let Slot::Occupied { object: entry, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        match &entry[0].payload {
            HeapPayload::Builtin(builtin) => Ok(*builtin),
            _ => Err(VmError::WrongObjectType),
        }
    }

    /// 將宿主函式綁定為 VM 內的 callable；捕獲物件由 builtin 的強邊追蹤。
    pub fn register_callback(
        &mut self,
        captures: &[Value],
        callback: std::rc::Rc<CallbackFn>,
    ) -> Result<crate::HostHandle<Value>, VmError> {
        for &value in captures {
            if let Value::Object(object) = value {
                self.checked_slot(object)?;
            }
        }
        let mut temporary_roots = Vec::new();
        let root_ticket = reserve_vec(
            &self.ledger,
            &mut temporary_roots,
            captures.len(),
            FailPoint::WorkReserve,
        )?;
        let registered = (|| {
            for &value in captures {
                if let Value::Object(object) = value {
                    temporary_roots.push(self.add_root(RootKind::Temporary, object)?);
                }
            }
            let mut owned = Vec::new();
            let capture_ticket = reserve_vec(
                &self.ledger,
                &mut owned,
                captures.len(),
                FailPoint::WorkReserve,
            )?;
            owned.extend_from_slice(captures);
            let capture_base = checked_bytes(captures.len(), size_of::<Value>())?;
            let charge = checked_bytes(owned.capacity(), size_of::<Value>())?;
            let capture_extra_ticket = self.ledger.reserve(
                charge
                    .checked_sub(capture_base)
                    .ok_or(VmError::LedgerInvariant)?,
            )?;
            let id = match self.callbacks.iter().position(Option::is_none) {
                Some(id) => id,
                None => {
                    let old_charge = self.callbacks_charge;
                    let needed = self
                        .callbacks
                        .len()
                        .checked_add(1)
                        .ok_or(VmError::ArithmeticOverflow)?;
                    let minimum_charge = checked_bytes(needed, size_of::<Option<CallbackEntry>>())?;
                    let mut replacement = Vec::new();
                    let ticket = reserve_vec(
                        &self.ledger,
                        &mut replacement,
                        needed,
                        FailPoint::WorkReserve,
                    )?;
                    let new_charge =
                        checked_bytes(replacement.capacity(), size_of::<Option<CallbackEntry>>())?;
                    let extra = new_charge
                        .checked_sub(minimum_charge)
                        .ok_or(VmError::LedgerInvariant)?;
                    let extra_ticket = self.ledger.reserve(extra)?;
                    ticket.commit()?;
                    if let Err(error) = extra_ticket.commit() {
                        self.ledger.refund_on_drop(minimum_charge);
                        return Err(error);
                    }
                    replacement.append(&mut self.callbacks);
                    replacement.push(None);
                    self.callbacks = replacement;
                    self.ledger.refund_on_drop(old_charge);
                    self.callbacks_charge = new_charge;
                    self.callbacks.len() - 1
                }
            };
            let function =
                self.allocate_payload(HeapPayload::Builtin(Builtin::HostCallback(id)))?;
            let attached = (|| {
                let handle = crate::HostHandle::new(self, function)?;
                for &value in captures {
                    if let Value::Object(object) = value {
                        self.add_child(function, object)?;
                    }
                }
                capture_ticket.commit()?;
                if let Err(error) = capture_extra_ticket.commit() {
                    self.ledger.refund(capture_base)?;
                    return Err(error);
                }
                Ok(handle)
            })();
            let handle = match attached {
                Ok(handle) => handle,
                Err(error) => {
                    self.reclaim(function)?;
                    return Err(error);
                }
            };
            self.callbacks[id] = Some(CallbackEntry {
                callback,
                captures: owned,
                charge,
            });
            Ok(handle)
        })();
        for root in temporary_roots {
            self.remove_root(root)?;
        }
        drop(root_ticket);
        registered
    }

    pub(crate) fn callback_snapshot(
        &self,
        id: usize,
    ) -> Result<(std::rc::Rc<CallbackFn>, Vec<Value>, Reservation), VmError> {
        let entry = self
            .callbacks
            .get(id)
            .and_then(Option::as_ref)
            .ok_or(VmError::StaleObject)?;
        let mut captures = Vec::new();
        let ticket = reserve_vec(
            &self.ledger,
            &mut captures,
            entry.captures.len(),
            FailPoint::WorkReserve,
        )?;
        captures.extend_from_slice(&entry.captures);
        Ok((std::rc::Rc::clone(&entry.callback), captures, ticket))
    }

    pub(crate) fn callback_capture_len(&self, id: usize) -> Result<usize, VmError> {
        self.callbacks
            .get(id)
            .and_then(Option::as_ref)
            .map(|entry| entry.captures.len())
            .ok_or(VmError::StaleObject)
    }

    pub(crate) fn allocate_basic_builtin(
        &mut self,
        builtin: BasicBuiltin,
    ) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Builtin(Builtin::Basic(builtin)))
    }

    pub(crate) fn allocate_official_builtin(
        &mut self,
        builtin: rivetlua_core::OfficialPlanBuiltin,
    ) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Builtin(Builtin::Official(builtin)))
    }

    pub(crate) fn allocate_callback_action_builtin(
        &mut self,
        builtin: Builtin,
    ) -> Result<ObjectRef, VmError> {
        debug_assert!(matches!(
            builtin,
            Builtin::CoroutineResume | Builtin::CoroutineYield
        ));
        self.allocate_payload(HeapPayload::Builtin(builtin))
    }

    pub(crate) fn allocate_string_iterator(
        &mut self,
        source: Value,
        pattern: Value,
        next: usize,
    ) -> Result<ObjectRef, VmError> {
        let mut roots = [None; 2];
        let allocated = (|| {
            for (index, value) in [source, pattern].into_iter().enumerate() {
                if let Value::Object(object) = value {
                    roots[index] = Some(self.add_root(RootKind::Temporary, object)?);
                }
            }
            self.allocate_payload(HeapPayload::Builtin(Builtin::StringIterator {
                source,
                pattern,
                next,
                last: None,
            }))
        })();
        for root in roots.into_iter().flatten() {
            self.remove_root(root)?;
        }
        allocated
    }

    pub(crate) fn advance_string_iterator(
        &mut self,
        iterator: ObjectRef,
        next: usize,
        last: Option<usize>,
    ) -> Result<(), VmError> {
        let slot = iterator
            .identity()
            .ok_or(VmError::StaleObject)?
            .slot
            .index();
        self.checked_slot(iterator)?;
        let Slot::Occupied { object, .. } = self.slots.get_mut(slot).ok_or(VmError::StaleObject)?
        else {
            return Err(VmError::StaleObject);
        };
        let HeapPayload::Builtin(Builtin::StringIterator {
            next: old_next,
            last: old_last,
            ..
        }) = &mut object[0].payload
        else {
            return Err(VmError::WrongObjectType);
        };
        *old_next = next;
        *old_last = last;
        Ok(())
    }

    pub(crate) fn allocate_coroutine(&mut self, entry: Value) -> Result<ObjectRef, VmError> {
        if let Value::Object(object) = entry {
            self.checked_slot(object)?;
        }
        self.allocate_payload(HeapPayload::Coroutine(Coroutine::new(entry)))
    }

    /// 以 VM 自身的 coroutine payload 建立可由宿主持有的協程。
    pub fn new_coroutine(&mut self, function: Value) -> Result<crate::HostHandle<Value>, VmError> {
        let Value::Object(entry) = function else {
            return Err(VmError::WrongObjectType);
        };
        if !matches!(
            self.object_kind(entry)?,
            ObjectKind::Closure | ObjectKind::Builtin
        ) {
            return Err(VmError::WrongObjectType);
        }
        let entry_root = self.add_root(RootKind::Temporary, entry)?;
        let result = (|| {
            let coroutine = self.allocate_coroutine(function)?;
            match crate::HostHandle::new(self, coroutine) {
                Ok(handle) => Ok(handle),
                Err(error) => {
                    self.reclaim(coroutine)?;
                    Err(error)
                }
            }
        })();
        self.remove_root(entry_root)?;
        result
    }

    pub(crate) fn allocate_coroutine_wrapper(
        &mut self,
        coroutine: ObjectRef,
    ) -> Result<ObjectRef, VmError> {
        self.with_coroutine(coroutine, |_| ())?;
        self.allocate_payload(HeapPayload::Builtin(Builtin::CoroutineWrapped(coroutine)))
    }

    pub(crate) fn allocate_io_iterator(
        &mut self,
        file: ObjectRef,
        auto_close: bool,
        formats: ObjectRef,
        count: usize,
    ) -> Result<ObjectRef, VmError> {
        self.with_file(file, |_| ())?;
        self.with_table(formats, |_| ())?;
        self.allocate_payload(HeapPayload::Builtin(Builtin::Io(
            IoBuiltin::LinesIterator {
                file,
                formats,
                count,
                auto_close,
            },
        )))
    }

    pub(crate) fn with_coroutine<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Coroutine) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object: entry, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        match &entry[0].payload {
            HeapPayload::Coroutine(co) => Ok(f(co)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    /// 所有新強邊須列入 new_refs；context/native 的可變長邊先由 prepare 函式逐一檢查。
    /// 預檢完成後回呼只提交欄位，不可配置或觸發 GC。
    pub(crate) fn with_coroutine_mut<R>(
        &mut self,
        object: ObjectRef,
        new_refs: &[ObjectRef],
        f: impl FnOnce(&mut Coroutine) -> R,
    ) -> Result<R, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        self.with_coroutine(object, |_| ())?;
        for &child in new_refs {
            self.write_ref(object, RefField::Coroutine, child)?;
        }
        let Slot::Occupied { object: entry, .. } = &mut self.slots[id.slot.index()] else {
            return Err(VmError::StaleObject);
        };
        let HeapPayload::Coroutine(co) = &mut entry[0].payload else {
            unreachable!("預檢後 coroutine kind 不得改變")
        };
        Ok(f(co))
    }

    pub(crate) fn prepare_coroutine_context_write(
        &mut self,
        owner: ObjectRef,
        context: &ThreadContext,
    ) -> Result<(), VmError> {
        self.with_coroutine(owner, |_| ())?;
        context.trace_children(|child| self.write_ref(owner, RefField::Coroutine, child))
    }

    pub(crate) fn prepare_coroutine_native_write(
        &mut self,
        owner: ObjectRef,
        native: crate::vm::NativeCompletion,
    ) -> Result<(), VmError> {
        self.with_coroutine(owner, |_| ())?;
        crate::gc::trace::trace_native(native, |child| {
            self.write_ref(owner, RefField::Coroutine, child)
        })
    }

    pub(crate) fn coroutine_state(&self, object: ObjectRef) -> Result<CoroutineState, VmError> {
        self.with_coroutine(object, |co| co.state)
    }

    pub(crate) fn take_coroutine_context(
        &mut self,
        object: ObjectRef,
    ) -> Result<Option<ThreadContext>, VmError> {
        self.with_coroutine_mut(object, &[], |co| co.context.take())
    }

    pub(crate) fn coroutine_stack_read(
        &self,
        object: ObjectRef,
        slot: usize,
    ) -> Result<Option<Value>, VmError> {
        self.with_coroutine(object, |co| {
            co.context
                .as_ref()
                .and_then(|context| context.read_slot(slot))
        })
    }

    pub(crate) fn coroutine_stack_write(
        &mut self,
        object: ObjectRef,
        slot: usize,
        value: Value,
    ) -> Result<bool, VmError> {
        if let Value::Object(child) = value {
            self.write_ref(object, RefField::Coroutine, child)?;
        }
        self.with_coroutine_mut(object, &[], |co| {
            co.context
                .as_mut()
                .is_some_and(|context| context.write_parked_slot(slot, value))
        })
    }

    pub(crate) fn allocate_closure(&mut self, closure: Closure) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Closure(closure))
    }

    pub(crate) fn allocate_upvalue(&mut self, upvalue: Upvalue) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Upvalue(upvalue))
    }

    pub(crate) fn allocate_module(&mut self, module: VerifiedModule) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Module(ModulePayload {
            module,
            ledger: self.ledger.clone(),
            host_charge: 0,
        }))
    }

    pub(crate) fn allocate_charged_module(
        &mut self,
        module: VerifiedModule,
        host_charge: usize,
    ) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Module(ModulePayload {
            module,
            ledger: self.ledger.clone(),
            host_charge,
        }))
    }

    pub(crate) fn allocate_file(
        &mut self,
        lease: Box<dyn HostFileLease>,
        standard: bool,
        charge: LoadTemporaryCharge,
        metatable: Option<ObjectRef>,
    ) -> Result<ObjectRef, VmError> {
        let file = FilePayload {
            lease: Some(lease),
            metatable,
            standard,
            charge: Some(charge),
        };
        let object = self.allocate_payload(HeapPayload::File(file))?;
        if let Some(metatable) = metatable {
            if let Err(error) = self
                .write_ref(object, RefField::Metatable, metatable)
                .and_then(|()| self.register_finalizer(object))
            {
                let (lease, charge) =
                    self.with_file_mut(object, |file| (file.lease.take(), file.charge.take()))?;
                drop(lease);
                drop(charge);
                return Err(error);
            }
        }
        Ok(object)
    }

    pub(crate) fn with_file<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&FilePayload) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!()
        };
        match &object[0].payload {
            HeapPayload::File(file) => Ok(f(file)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn with_file_mut<R>(
        &mut self,
        object: ObjectRef,
        f: impl FnOnce(&mut FilePayload) -> R,
    ) -> Result<R, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(object)?;
        let Slot::Occupied { object: stored, .. } = &mut self.slots[id.slot.index()] else {
            unreachable!()
        };
        match &mut stored[0].payload {
            HeapPayload::File(file) => Ok(f(file)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn take_file_lease(
        &mut self,
        object: ObjectRef,
    ) -> Result<Option<Box<dyn HostFileLease>>, VmError> {
        self.with_file_mut(object, |file| file.lease.take())
    }

    pub(crate) fn restore_file_lease(
        &mut self,
        object: ObjectRef,
        lease: Box<dyn HostFileLease>,
    ) -> Result<(), VmError> {
        self.with_file_mut(object, |file| {
            debug_assert!(file.lease.is_none());
            file.lease = Some(lease);
        })
    }

    /// 預留空 array 與 hash bucket；兩者成功且 heap 物件建成後才提交帳額。
    pub fn allocate_table_with_capacity(
        &mut self,
        array_capacity: usize,
        hash_capacity: usize,
    ) -> Result<ObjectRef, VmError> {
        let (table, array_ticket, hash_ticket) =
            Table::try_new(&self.ledger, array_capacity, hash_capacity)?;
        let reference = self.allocate_payload(HeapPayload::Table(table))?;
        array_ticket.commit()?;
        hash_ticket.commit()?;
        Ok(reference)
    }

    fn allocate_payload(&mut self, payload: HeapPayload) -> Result<ObjectRef, VmError> {
        let candidate = HeapObject {
            payload,
            children: Vec::new(),
        };
        candidate.trace_children(|child| {
            self.checked_slot(child)?;
            Ok(())
        })?;
        let debt_charge = candidate.debt_bytes()?;
        if !self.finalizer_running
            && self.collect_every_allocation
            && self.gc.phase != GcPhase::Pause
        {
            candidate.trace_children(|child| self.mark_gc_object(child))?;
            while self.gc.phase != GcPhase::Pause {
                self.incremental_step(1024)?;
            }
        }
        if !self.finalizer_running
            && !self.collect_every_allocation
            && self.gc.debt_bytes >= self.gc.debt_threshold
        {
            if self.gc.phase != GcPhase::Pause {
                candidate.trace_children(|child| self.mark_gc_object(child))?;
            }
            self.incremental_step(1)?;
        }
        let free = self
            .slots
            .iter()
            .position(|slot| matches!(slot, Slot::Free { .. }));
        let slot_ticket = if free.is_none() {
            Some(reserve_vec(
                &self.ledger,
                &mut self.slots,
                1,
                FailPoint::SlotReserve,
            )?)
        } else {
            None
        };

        let mut object = Vec::new();
        let object_ticket = reserve_vec(&self.ledger, &mut object, 1, FailPoint::ObjectReserve)?;
        self.ledger.checkpoint(FailPoint::ObjectInitialize)?;
        object.push(candidate);

        let gc_growth = if self.gc.phase != GcPhase::Pause && free.is_none() {
            self.gc
                .charge
                .checked_add(size_of::<GcColor>() + size_of::<ObjectRef>())
                .ok_or(VmError::ArithmeticOverflow)?;
            let color_ticket =
                reserve_vec(&self.ledger, &mut self.gc.colors, 1, FailPoint::MarkReserve)?;
            let work_ticket = self.ledger.reserve(size_of::<ObjectRef>())?;
            self.ledger.checkpoint(FailPoint::WorkReserve)?;
            let needed = self
                .slots
                .len()
                .checked_add(1)
                .and_then(|len| len.checked_sub(self.gc.work.len()))
                .ok_or(VmError::ArithmeticOverflow)?;
            self.gc
                .work
                .try_reserve_exact(needed)
                .map_err(|_| work_ticket.rust_reserve_failure())?;
            Some((color_ticket, work_ticket))
        } else {
            None
        };

        let (slot, generation) = match free {
            Some(index) => {
                let Slot::Free { generation } = self.slots[index] else {
                    unreachable!("找到的空 slot 必須仍為空")
                };
                (SlotId::new(index), generation)
            }
            None => {
                let index = self.slots.len();
                let generation = Generation::new(0);
                (SlotId::new(index), generation)
            }
        };
        let reference = ObjectRef::new_runtime(ObjectId::new(self.id, slot, generation))
            .ok_or(VmError::IdentityExhausted)?;
        let occupied = Slot::Occupied {
            generation,
            reference,
            age: GcAge::Young,
            survivals: 0,
            finalizer: FinalizerState::Unregistered,
            finalizer_order: 0,
            finalizer_remarked: false,
            object,
        };
        match free {
            Some(index) => self.slots[index] = occupied,
            None => self.slots.push(occupied),
        }
        if self.gc.phase != GcPhase::Pause {
            match free {
                Some(index) => self.gc.colors[index] = GcColor::White,
                None => self.gc.colors.push(GcColor::White),
            }
        }
        if let Some((color_ticket, work_ticket)) = gc_growth {
            color_ticket.commit()?;
            work_ticket.commit()?;
            self.gc.charge += size_of::<GcColor>() + size_of::<ObjectRef>();
        }
        if self.collect_every_allocation && !self.finalizer_running {
            if let Err(error) = self.mark_gc_object(reference) {
                self.rollback_new_object(slot.index(), free, generation);
                return Err(error);
            }
            let temporary = match self.roots.add(&self.ledger, RootKind::Temporary, reference) {
                Ok(root) => root,
                Err(error) => {
                    self.rollback_new_object(slot.index(), free, generation);
                    return Err(error);
                }
            };
            let collection = self.collect();
            let removal = self.roots.remove(&self.ledger, temporary);
            if let Err(error) = removal {
                self.rollback_new_object(slot.index(), free, generation);
                return Err(error);
            }
            if let Err(error) = collection {
                self.rollback_new_object(slot.index(), free, generation);
                return Err(error);
            }
        }
        object_ticket.commit()?;
        if let Some(ticket) = slot_ticket {
            ticket.commit()?;
        }
        self.gc.debt_bytes = self.gc.debt_bytes.saturating_add(debt_charge);
        if self.gc.mode == GcMode::Generational {
            self.gc.major_debt_bytes = self.gc.major_debt_bytes.saturating_add(debt_charge);
        }
        Ok(reference)
    }

    fn rollback_new_object(&mut self, index: usize, free: Option<usize>, generation: Generation) {
        if self.gc.phase != GcPhase::Pause {
            self.gc
                .work
                .retain(|object| object.identity().is_none_or(|id| id.slot.index() != index));
            if free.is_some() {
                self.gc.colors[index] = GcColor::White;
            } else if self.gc.colors.len() > self.slots.len().saturating_sub(1) {
                self.gc.colors.pop();
            }
        }
        if free.is_some() {
            self.slots[index] = Slot::Free { generation };
        } else {
            self.slots.pop();
        }
    }

    /// 增加受驗證的物件欄位邊；失敗不修改原有邊。
    pub fn add_child(&mut self, parent: ObjectRef, child: ObjectRef) -> Result<(), VmError> {
        self.write_ref(parent, RefField::Child, child)?;
        let id = parent.identity().ok_or(VmError::StaleObject)?;
        let index = id.slot.index();
        let mut children = {
            let Slot::Occupied { object, .. } = &mut self.slots[index] else {
                return Err(VmError::StaleObject);
            };
            std::mem::take(&mut object[0].children)
        };

        // 唯有受控帳本與 Vec 預留位於欄位暫離期間；不呼叫 GC 或宿主回呼。
        let reservation = self.reserve_child_growth(&mut children);
        {
            let Slot::Occupied { object, .. } = &mut self.slots[index] else {
                unreachable!("預留期間 VM 未重入，parent slot 必須仍為 occupied")
            };
            object[0].children = children;
        }
        let ticket = reservation?;
        ticket.commit()?;
        // 已有容量且無可失敗邊界；以短借用完成唯一圖變更。
        let Slot::Occupied { object, .. } = &mut self.slots[index] else {
            unreachable!("提交後 parent slot 必須仍為 occupied")
        };
        object[0].children.push(child);
        Ok(())
    }

    /// `&self` 使呼叫端無法在借用 heap 內部 children 時跨越配置邊界。
    fn reserve_child_growth(&self, children: &mut Vec<ObjectRef>) -> Result<Reservation, VmError> {
        reserve_vec(&self.ledger, children, 1, FailPoint::ChildReserve)
    }

    /// 強邊提交前的共同檢查與三色寫入屏障；預留失敗不得提交欄位。
    pub(crate) fn write_ref(
        &mut self,
        owner: ObjectRef,
        field: RefField,
        child: ObjectRef,
    ) -> Result<(), VmError> {
        self.checked_slot(owner)?;
        self.checked_slot(child)?;
        if self.gc.mode == GcMode::Generational
            && self.gc_age(owner)? == GcAge::Old
            && self.gc_age(child)? != GcAge::Old
        {
            self.remember_gc_owner(owner)?;
        }
        let weak_table_edge = match field {
            RefField::TableKey | RefField::TableValue => {
                let mode = self.with_table(owner, Table::weak_mode)?;
                let string = self.object_kind(child)? == ObjectKind::ByteString;
                match field {
                    RefField::TableKey => matches!(mode, WeakMode::Keys | WeakMode::All) && !string,
                    RefField::TableValue => mode != WeakMode::Strong,
                    _ => false,
                }
            }
            _ => false,
        };
        if weak_table_edge {
            return Ok(());
        }
        if self.gc.phase != GcPhase::Pause {
            let owner_slot = owner.identity().ok_or(VmError::StaleObject)?.slot.index();
            let child_slot = child.identity().ok_or(VmError::StaleObject)?.slot.index();
            if self
                .gc
                .colors
                .get(owner_slot)
                .copied()
                .ok_or(VmError::LedgerInvariant)?
                == GcColor::Black
                && self
                    .gc
                    .colors
                    .get(child_slot)
                    .copied()
                    .ok_or(VmError::LedgerInvariant)?
                    == GcColor::White
            {
                self.mark_gc_object(child)?;
                self.gc.barrier_count += 1;
            }
        }
        Ok(())
    }

    /// 完成當前增量 cycle，再從現有 roots 執行一輪完整 cycle。
    pub fn collect(&mut self) -> Result<usize, VmError> {
        if self.finalizer_running {
            return Err(VmError::FinalizerGcReentry);
        }
        let before = self.gc.reclaimed_objects;
        if self.gc.phase != GcPhase::Pause {
            while self.gc.phase != GcPhase::Pause {
                self.incremental_step(1024)?;
            }
        }
        let kind = if self.gc.mode == GcMode::Generational {
            GcCycleKind::Major
        } else {
            GcCycleKind::Full
        };
        self.begin_gc_cycle_kind(kind)?;
        while self.gc.phase != GcPhase::Pause {
            self.incremental_step(1024)?;
        }
        Ok(self.gc.reclaimed_objects - before)
    }

    fn checked_slot(&self, object: ObjectRef) -> Result<&Slot, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        if id.vm != self.id {
            return Err(VmError::WrongVm);
        }
        let slot = self
            .slots
            .get(id.slot.index())
            .ok_or(VmError::StaleObject)?;
        match slot {
            Slot::Occupied {
                generation,
                reference,
                ..
            } if *generation == id.generation && *reference == object => Ok(slot),
            _ => Err(VmError::StaleObject),
        }
    }

    pub fn read(&self, object: ObjectRef) -> Result<Value, VmError> {
        self.with_value(object, |value| *value)
    }

    pub fn object_kind(&self, object: ObjectRef) -> Result<ObjectKind, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        Ok(match object[0].payload {
            HeapPayload::Value(_) => ObjectKind::Value,
            HeapPayload::ByteString(_) => ObjectKind::ByteString,
            HeapPayload::Table(_) => ObjectKind::Table,
            HeapPayload::Closure(_) => ObjectKind::Closure,
            HeapPayload::Builtin(_) => ObjectKind::Builtin,
            HeapPayload::Coroutine(_) => ObjectKind::Coroutine,
            HeapPayload::Upvalue(_) => ObjectKind::Upvalue,
            HeapPayload::Module(_) => ObjectKind::Module,
            HeapPayload::File(_) => ObjectKind::File,
        })
    }

    /// 借用僅限此回呼；呼叫者不能持有 heap 的可變借用。
    ///
    /// ```
    /// use rivetlua_core::Value;
    /// use rivetlua_runtime::Vm;
    /// let mut vm = Vm::new().unwrap();
    /// let object = vm.allocate(Value::Integer(1)).unwrap();
    /// assert_eq!(vm.with_value(object, |value| *value), Ok(Value::Integer(1)));
    /// vm.allocate(Value::Integer(2)).unwrap();
    /// ```
    ///
    /// ```compile_fail
    /// use rivetlua_core::Value;
    /// use rivetlua_runtime::Vm;
    /// let mut vm = Vm::new().unwrap();
    /// let object = vm.allocate(Value::Integer(1)).unwrap();
    /// vm.with_value(object, |_| {
    ///     vm.allocate(Value::Integer(2)).unwrap();
    /// }).unwrap();
    /// ```
    pub fn with_value<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Value) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Value(value) => Ok(f(value)),
            HeapPayload::ByteString(_)
            | HeapPayload::Table(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_)
            | HeapPayload::File(_) => Err(VmError::WrongObjectType),
        }
    }

    /// 借用 byte string 僅限回呼期間；回呼不能跨越 VM 可變配置。
    pub fn with_byte_string<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&ByteString) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::ByteString(string) => Ok(f(string)),
            HeapPayload::Value(_)
            | HeapPayload::Table(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_)
            | HeapPayload::File(_) => Err(VmError::WrongObjectType),
        }
    }

    pub fn with_table<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Table) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Table(table) => Ok(f(table)),
            HeapPayload::Value(_)
            | HeapPayload::ByteString(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_)
            | HeapPayload::File(_) => Err(VmError::WrongObjectType),
        }
    }

    pub fn with_closure<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Closure) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Closure(closure) => Ok(f(closure)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn module(&self, reference: ObjectRef) -> Result<&VerifiedModule, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(reference)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Module(module) => Ok(&module.module),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn upvalue_state(&self, reference: ObjectRef) -> Result<UpvalueState, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(reference)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Upvalue(upvalue) => Ok(upvalue.state()),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn with_upvalue_mut<R>(
        &mut self,
        reference: ObjectRef,
        f: impl FnOnce(&mut Upvalue) -> R,
    ) -> Result<R, VmError> {
        let id = reference.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(reference)?;
        let Slot::Occupied { object, .. } = &mut self.slots[id.slot.index()] else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &mut object[0].payload {
            HeapPayload::Upvalue(upvalue) => Ok(f(upvalue)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn close_upvalue(&mut self, owner: ObjectRef, value: Value) -> Result<(), VmError> {
        if let Value::Object(child) = value {
            self.write_ref(owner, RefField::Upvalue, child)?;
        }
        self.with_upvalue_mut(owner, |upvalue| upvalue.close(value))
    }

    pub(crate) fn set_closed_upvalue(
        &mut self,
        owner: ObjectRef,
        value: Value,
    ) -> Result<(), VmError> {
        if let Value::Object(child) = value {
            self.write_ref(owner, RefField::Upvalue, child)?;
        }
        self.with_upvalue_mut(owner, |upvalue| upvalue.set_closed(value))
    }

    /// table 內部短借用；回呼只使用帳本，不能重入 VM 或觸發 GC。
    pub(crate) fn with_table_mut<R>(
        &mut self,
        reference: ObjectRef,
        f: impl FnOnce(&mut Table, &AllocationLedger) -> Result<R, VmError>,
    ) -> Result<R, VmError> {
        let id = reference.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(reference)?;
        let ledger = self.ledger.clone();
        let Slot::Occupied { object, .. } = &mut self.slots[id.slot.index()] else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &mut object[0].payload {
            HeapPayload::Table(table) => f(table, &ledger),
            _ => Err(VmError::WrongObjectType),
        }
    }

    /// P06-2 收集器將接管回收時機；本步只在 crate 內提供 slot 轉移。
    pub(crate) fn reclaim(&mut self, object: ObjectRef) -> Result<(), VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        let Slot::Occupied { object: stored, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        let object_bytes = size_of::<HeapObject>();
        let child_bytes = checked_bytes(stored[0].children.len(), size_of::<ObjectRef>())?;
        let payload_bytes = match &stored[0].payload {
            HeapPayload::ByteString(string) => string.len(),
            HeapPayload::Value(_) => 0,
            HeapPayload::Table(table) => table.charge_bytes()?,
            HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_)
            | HeapPayload::File(_) => 0,
        };
        let callback_id = match &stored[0].payload {
            HeapPayload::Builtin(Builtin::HostCallback(id)) => Some(*id),
            _ => None,
        };
        let refund = object_bytes
            .checked_add(child_bytes)
            .and_then(|total| total.checked_add(payload_bytes))
            .ok_or(VmError::ArithmeticOverflow)?;
        self.ledger.refund_lua(refund)?;
        let slot = &mut self.slots[id.slot.index()];
        *slot = match id.generation.next() {
            Some(next) => Slot::Free { generation: next },
            None => Slot::Retired,
        };
        if let Some(callback_id) = callback_id {
            if let Some(entry) = self.callbacks.get_mut(callback_id).and_then(Option::take) {
                self.ledger.refund(entry.charge)?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_generation_for_test(
        &mut self,
        object: ObjectRef,
        generation: Generation,
    ) -> ObjectRef {
        let id = object.identity().unwrap();
        assert_eq!(id.vm, self.id);
        let Slot::Occupied {
            generation: current,
            reference,
            ..
        } = &mut self.slots[id.slot.index()]
        else {
            panic!("測試需要 occupied slot")
        };
        assert_eq!(*current, id.generation);
        *current = generation;
        *reference = ObjectRef::new_runtime(ObjectId::new(self.id, id.slot, generation)).unwrap();
        *reference
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.roots.release_all_on_vm_drop(&self.ledger);
        self.ledger.refund_on_drop(self.callbacks_charge);
        for entry in self.callbacks.iter().flatten() {
            self.ledger.refund_on_drop(entry.charge);
        }
        self.ledger.refund_on_drop(self.finalizer_queue_charge);
        for slot in &self.slots {
            let Slot::Occupied { object, .. } = slot else {
                continue;
            };
            let heap = &object[0];
            self.ledger.refund_lua_on_drop(size_of::<HeapObject>());
            match checked_bytes(heap.children.len(), size_of::<ObjectRef>()) {
                Ok(bytes) => self.ledger.refund_lua_on_drop(bytes),
                Err(_) => self.ledger.poison(),
            }
            match &heap.payload {
                HeapPayload::ByteString(string) => self.ledger.refund_lua_on_drop(string.len()),
                HeapPayload::Table(table) => match table.charge_bytes() {
                    Ok(bytes) => self.ledger.refund_lua_on_drop(bytes),
                    Err(_) => self.ledger.poison(),
                },
                _ => {}
            }
        }
        match checked_bytes(self.slots.len(), size_of::<Slot>()) {
            Ok(bytes) => self.ledger.refund_lua_on_drop(bytes),
            Err(_) => self.ledger.poison(),
        }
    }
}

#[cfg(test)]
mod p12_5_tests {
    use rivetlua_core::Value;

    use super::{
        AtomicFinalizerStage, FailPoint, FinalizerState, GcPhase, ObjectKind, Vm, VmError,
    };

    #[test]
    fn p12_5_atomic_queue_reserve_failure_preserves_registration() {
        let mut vm = Vm::new().unwrap();
        let target = vm.allocate_table().unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::Integer(1))
            .unwrap();
        vm.set_metatable(target, Some(metatable)).unwrap();
        vm.set_execution_running(true);
        while vm.gc.phase != GcPhase::Atomic {
            vm.incremental_step(1).unwrap();
        }
        vm.inject_failure_once(FailPoint::WorkReserve);
        let mut failed = false;
        for _ in 0..64 {
            match vm.incremental_step(1) {
                Err(VmError::InjectedFailure(FailPoint::WorkReserve)) => {
                    failed = true;
                    break;
                }
                Ok(_) => {}
                other => panic!("非預期 GC 結果: {other:?}"),
            }
        }
        assert!(failed);
        assert_eq!(
            vm.gc.atomic_finalizer_stage,
            AtomicFinalizerStage::BeforeWeakValues
        );
        assert_eq!(vm.finalizer_state(target), Ok(FinalizerState::Registered));
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.object_kind(target), Ok(ObjectKind::Table));
        while vm.gc.phase != GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        vm.set_execution_running(false);
        assert_eq!(vm.finalizer_state(target), Ok(FinalizerState::Pending));
        vm.run_pending_finalizers().unwrap();
        assert_eq!(vm.finalizer_state(target), Ok(FinalizerState::Finalized));
    }
}

#[cfg(test)]
mod p12_6_tests {
    use rivetlua_core::{ProtoId, Value};

    use super::{Closure, FailPoint, RootKind, Vm, VmError};
    use crate::alloc::AllocationDomain;

    #[test]
    fn p12_6_vm_drop_refunds_live_lua_and_host_charges() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table_with_capacity(2, 4).unwrap();
        let string = vm.allocate_byte_string(b"live object").unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(string))
            .unwrap();
        let _root = vm.add_root(RootKind::Registry, table).unwrap();
        let ledger = vm.ledger.clone();
        assert!(ledger.snapshot().committed > 0);
        drop(vm);
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(ledger.snapshot().reserved, 0);
    }

    #[test]
    fn p12_6_closure_capture_site_injection_refunds_and_retries() {
        let mut vm = Vm::new().unwrap();
        let module = vm.allocate(Value::Nil).unwrap();
        let capture = vm.allocate(Value::Integer(1)).unwrap();
        let ordinal = vm.allocation_trace().next_ordinal;
        vm.inject_allocation_failure_at(ordinal);
        let error = Closure::new(module, ProtoId(0), &[capture], None, &vm.ledger)
            .err()
            .unwrap();
        let VmError::InjectedAllocation(attempt) = error else {
            panic!("capture 配置應回報 ordinal: {error:?}");
        };
        assert_eq!(attempt.ordinal, ordinal);
        assert_eq!(attempt.point, Some(FailPoint::ClosureCapturesReserve));
        assert_eq!(attempt.domain, AllocationDomain::LuaHeap);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let before = vm.ledger_snapshot().lua_heap_bytes;
        let closure = Closure::new(module, ProtoId(0), &[capture], None, &vm.ledger).unwrap();
        assert!(vm.ledger_snapshot().lua_heap_bytes > before);
        drop(closure);
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, before);
    }

    #[test]
    fn p12_6_direct_host_root_reserve_injection_leaves_no_root() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Nil).unwrap();
        let before = vm.ledger_snapshot();
        let ordinal = vm.allocation_trace().next_ordinal;
        vm.inject_allocation_failure_at(ordinal);
        let error = vm.add_root(RootKind::Temporary, object).err().unwrap();
        let VmError::InjectedAllocation(attempt) = error else {
            panic!("直接 host reserve 應回報 site: {error:?}");
        };
        assert_eq!(attempt.ordinal, ordinal);
        assert_eq!(attempt.domain, AllocationDomain::Host);
        assert_eq!(
            attempt.site.file.rsplit(['/', '\\']).next(),
            Some("roots.rs")
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
        let root = vm.add_root(RootKind::Temporary, object).unwrap();
        vm.remove_root(root).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }
}
