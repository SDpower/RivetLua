//! B3：固定 Lua C 載入與輸出的已計費 Rust session；C callback 只由純 C driver 執行。

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{
    InputError, InputErrorKind, InputFormat, IrLimits, LuaProfile, TransportLimits, VerifiedModule,
    classify_input, decode_input_module, input_scan_admission, preflight_input_module,
};
use rivetlua_runtime::{
    AllocationCharges, CapiDumpBytes, HostAllocationCharge, LoadLimits, RuntimeErrorKind, Vm,
    VmError,
};

use crate::error::ErrorClass;
use crate::stack::{
    StackError, dump_top_bytes, load_configure_limits, load_prepare_error, load_publish_charged,
    load_restore_reader_stack, load_with_vm, lua_State,
};
use crate::trampoline::Checkpoint;

#[derive(Clone, Copy, Debug)]
#[repr(i32)]
enum Fault {
    Syntax = 1,
    Memory = 2,
    Budget = 3,
    File = 4,
}

impl Fault {
    fn from_code(code: c_int) -> Option<Self> {
        Some(match code {
            1 => Self::Syntax,
            2 => Self::Memory,
            3 => Self::Budget,
            4 => Self::File,
            _ => return None,
        })
    }

    fn message(self) -> &'static [u8] {
        match self {
            Self::Syntax => b"invalid or incompatible Lua chunk",
            Self::Memory => b"not enough memory",
            Self::Budget => b"load resource limit exceeded",
            Self::File => b"cannot open or read Lua file",
        }
    }
}

fn vm_fault(error: VmError) -> Fault {
    match error {
        VmError::AllocationFailed
        | VmError::InjectedAllocation(_)
        | VmError::InjectedFailure(_)
        | VmError::ArithmeticOverflow
        | VmError::RootIdExhausted
        | VmError::IdentityExhausted => Fault::Memory,
        _ => Fault::Budget,
    }
}

/// Rivet 宿主私有入口：僅在閒置 state 調整既有 load 資源上限。
///
/// # Safety
/// `state` 必須是同執行緒存活的 Lua state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_configure_load_limits_b3(
    state: *mut lua_State,
    source: usize,
    encoded: usize,
    module: usize,
    temporary: usize,
    work: usize,
    chunks: usize,
    paths: usize,
) -> c_int {
    let limits = LoadLimits {
        max_source_bytes: source,
        max_encoded_bytes: encoded,
        max_module_allocation_bytes: module,
        max_temporary_bytes: temporary,
        max_work_units: work,
        max_reader_chunks: chunks,
        max_path_candidates: paths,
    };
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C 宿主保活 state；helper 檢查 thread、live 與閒置狀態。
        unsafe { load_configure_limits(state, limits) }
    })) {
        Ok(Ok(())) => 1,
        _ => 0,
    }
}

/// 5.5 reader 返回後還原 stack，保留 checkpoint 的錯誤 slot 容量。
///
/// # Safety
/// `state` 是同執行緒存活 state，`original_top` 由本次 C load 保存。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_restore_reader_stack_b3(
    state: *mut lua_State,
    original_top: c_int,
) -> c_int {
    let Ok(original_top) = usize::try_from(original_top) else {
        return Fault::Budget as c_int;
    };
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C caller 保活 state 並保存正確的 original_top。
        unsafe { load_restore_reader_stack(state, original_top) }
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => stack_fault(error) as c_int,
        Err(_) => Fault::Budget as c_int,
    }
}

fn stack_fault(error: StackError) -> Fault {
    match error {
        StackError::Runtime(error) => vm_fault(error),
        StackError::Number(error) => match error.kind {
            RuntimeErrorKind::Heap(error) => vm_fault(error),
            RuntimeErrorKind::UnsupportedFormat
            | RuntimeErrorKind::MissingEntryPoint
            | RuntimeErrorKind::LoadBytecode
            | RuntimeErrorKind::LoadCompile => Fault::Syntax,
            _ => Fault::Budget,
        },
        StackError::StackLimit => Fault::Memory,
        _ => Fault::Budget,
    }
}

impl From<StackError> for Fault {
    fn from(error: StackError) -> Self {
        stack_fault(error)
    }
}

fn input_fault(error: InputError) -> Fault {
    match error.kind {
        InputErrorKind::InvalidFormat => Fault::Syntax,
        InputErrorKind::LimitExceeded => Fault::Budget,
        InputErrorKind::AllocationFailed => Fault::Memory,
    }
}

struct ChargedBytes {
    bytes: Vec<u8>,
    _base: Option<HostAllocationCharge>,
    _extra: Option<HostAllocationCharge>,
}

impl ChargedBytes {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            _base: None,
            _extra: None,
        }
    }

    fn append(&mut self, vm: &Vm, part: &[u8], limit: usize) -> Result<(), Fault> {
        let required = self
            .bytes
            .len()
            .checked_add(part.len())
            .ok_or(Fault::Budget)?;
        if required > limit {
            return Err(Fault::Budget);
        }
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(limit);
            let base = vm.reserve_host_allocation(capacity).map_err(vm_fault)?;
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(capacity)
                .map_err(|_| vm_fault(base.rust_reserve_failure()))?;
            let extra_bytes = replacement
                .capacity()
                .checked_sub(capacity)
                .ok_or(Fault::Budget)?;
            let extra = if extra_bytes == 0 {
                None
            } else {
                Some(vm.reserve_host_allocation(extra_bytes).map_err(vm_fault)?)
            };
            replacement.extend_from_slice(&self.bytes);
            let extra = extra
                .map(|ticket| ticket.commit().map_err(vm_fault))
                .transpose()?;
            let base = base.commit().map_err(vm_fault)?;
            *self = Self {
                bytes: replacement,
                _base: Some(base),
                _extra: extra,
            };
        }
        self.bytes.extend_from_slice(part);
        Ok(())
    }
}

struct CompileMeter<'a> {
    vm: &'a Vm,
    work_left: &'a mut usize,
    temporary_left: usize,
    module_left: usize,
    _temporary: AllocationCharges,
    module: AllocationCharges,
}

impl CompileMeter<'_> {
    fn claim(vm: &Vm, bytes: usize, charges: &mut AllocationCharges) -> Result<(), Fault> {
        if bytes == 0 {
            return Ok(());
        }
        charges.try_reserve(1).map_err(vm_fault)?;
        let charge = vm
            .reserve_host_allocation(bytes)
            .map_err(vm_fault)?
            .commit_module_charge()
            .map_err(vm_fault)?;
        charges.try_push(charge).map_err(|(error, charge)| {
            drop(charge);
            vm_fault(error)
        })?;
        Ok(())
    }
}

impl CompileBudgetSink for CompileMeter<'_> {
    type Error = Fault;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        *self.work_left = self.work_left.checked_sub(units).ok_or(Fault::Budget)?;
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary_left = self
            .temporary_left
            .checked_sub(bytes)
            .ok_or(Fault::Budget)?;
        Self::claim(self.vm, bytes, &mut self._temporary)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module_left = self.module_left.checked_sub(bytes).ok_or(Fault::Budget)?;
        Self::claim(self.vm, bytes, &mut self.module)
    }
}

struct LoadSession {
    state: *mut lua_State,
    profile: LuaProfile,
    limits: LoadLimits,
    source: ChargedBytes,
    chunkname: ChargedBytes,
    work_left: usize,
    chunks: usize,
    file_style: bool,
    _owner: HostAllocationCharge,
}

impl LoadSession {
    fn new(state: *mut lua_State, vm: &Vm, name: &[u8], file_style: c_int) -> Result<Self, Fault> {
        let limits = vm.capi_load_limits();
        let owner = vm
            .reserve_host_allocation(size_of::<Self>())
            .map_err(vm_fault)?;
        let mut chunkname = ChargedBytes::empty();
        if file_style == 1 {
            chunkname.append(vm, b"@", limits.max_temporary_bytes)?;
        }
        chunkname.append(vm, name, limits.max_temporary_bytes)?;
        Ok(Self {
            state,
            profile: if cfg!(feature = "lua55") {
                LuaProfile::Lua55
            } else {
                LuaProfile::Lua54
            },
            limits,
            source: ChargedBytes::empty(),
            chunkname,
            work_left: limits.max_work_units,
            chunks: 0,
            file_style: file_style != 0,
            _owner: owner.commit().map_err(vm_fault)?,
        })
    }

    fn append(&mut self, vm: &Vm, bytes: &[u8]) -> Result<(), Fault> {
        self.chunks = self.chunks.checked_add(1).ok_or(Fault::Budget)?;
        if self.chunks > self.limits.max_reader_chunks {
            return Err(Fault::Budget);
        }
        self.work_left = self
            .work_left
            .checked_sub(bytes.len().saturating_add(1))
            .ok_or(Fault::Budget)?;
        // reader 的分片與 file BOM/shebang 可能延後揭露 binary signature；
        // spool 先採既有兩種輸入上限的較大值，finish 再依實際格式收緊。
        let limit = self
            .limits
            .max_source_bytes
            .max(self.limits.max_encoded_bytes);
        self.source.append(vm, bytes, limit)
    }

    fn preprocess_file(&mut self) {
        if !self.file_style {
            return;
        }
        let bytes = &mut self.source.bytes;
        if bytes.starts_with(b"\xef\xbb\xbf") {
            bytes.copy_within(3.., 0);
            bytes.truncate(bytes.len() - 3);
        }
        if bytes.starts_with(b"#") {
            let skip = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |at| at + 1);
            let tail = bytes.len() - skip;
            bytes.copy_within(skip.., 1);
            bytes[0] = b'\n';
            bytes.truncate(tail + 1);
        }
    }

    fn finish(
        &mut self,
        vm: &mut Vm,
        mode: Option<&[u8]>,
    ) -> Result<(VerifiedModule, AllocationCharges), Fault> {
        self.preprocess_file();
        let format = classify_input(&self.source.bytes);
        let binary = !matches!(format, InputFormat::Source);
        let allow_text = mode.is_none_or(|mode| mode.contains(&b't'));
        let allow_binary = mode.is_none_or(|mode| {
            mode.contains(&b'b') || (self.profile == LuaProfile::Lua55 && mode.contains(&b'B'))
        });
        if (binary && !allow_binary) || (!binary && !allow_text) {
            return Err(Fault::Syntax);
        }
        if matches!(format, InputFormat::UnsupportedBinary) {
            return Err(Fault::Syntax);
        }
        let source_limit = if binary {
            self.limits.max_encoded_bytes
        } else {
            self.limits.max_source_bytes
        };
        if self.source.bytes.len() > source_limit {
            return Err(Fault::Budget);
        }

        let (module, charges) = if binary {
            let scan =
                input_scan_admission(self.source.bytes.len(), format).map_err(input_fault)?;
            let scan_work = usize::try_from(scan.work).map_err(|_| Fault::Budget)?;
            if scan_work > self.work_left {
                return Err(Fault::Budget);
            }
            let mut limits = TransportLimits::default();
            limits.verify = vm.capi_load_verify_limits();
            limits.max_temporary_bytes = self.limits.max_temporary_bytes;
            limits.max_retained_bytes = self.limits.max_module_allocation_bytes;
            limits.max_work = u64::try_from(self.work_left).map_err(|_| Fault::Budget)?;
            limits.official.max_bytes =
                limits.official.max_bytes.min(self.limits.max_encoded_bytes);
            let preflight = preflight_input_module(&self.source.bytes, self.profile, &limits)
                .map_err(input_fault)?;
            let admitted = preflight.admission();
            let all_work = admitted
                .scan_work
                .checked_add(admitted.subsequent_work)
                .ok_or(Fault::Budget)?;
            self.work_left = self
                .work_left
                .checked_sub(usize::try_from(all_work).map_err(|_| Fault::Budget)?)
                .ok_or(Fault::Budget)?;
            let temporary = vm
                .reserve_host_allocation(admitted.temporary_bytes)
                .map_err(vm_fault)?
                .commit()
                .map_err(vm_fault)?;
            let mut charges = AllocationCharges::new();
            charges.try_reserve(1).map_err(vm_fault)?;
            let retained = vm
                .reserve_host_allocation(admitted.retained_bytes)
                .map_err(vm_fault)?
                .commit_module_charge()
                .map_err(vm_fault)?;
            charges.try_push(retained).map_err(|(error, charge)| {
                drop(charge);
                vm_fault(error)
            })?;
            let module = decode_input_module(preflight).map_err(input_fault)?;
            drop(temporary);
            (module, charges)
        } else {
            let language = match self.profile {
                LuaProfile::Lua54 => LanguageProfile::Lua54,
                LuaProfile::Lua55 => LanguageProfile::Lua55,
            };
            let mut sink = CompileMeter {
                vm,
                work_left: &mut self.work_left,
                temporary_left: self.limits.max_temporary_bytes,
                module_left: self.limits.max_module_allocation_bytes,
                _temporary: AllocationCharges::new(),
                module: AllocationCharges::new(),
            };
            let module = compile_with_budget(
                &self.source.bytes,
                &self.chunkname.bytes,
                language,
                &CompileLimits::default(),
                &IrLimits::default(),
                &vm.capi_load_verify_limits(),
                &mut sink,
            )
            .map_err(|error| match error {
                BudgetedCompileError::Budget(fault) => fault,
                BudgetedCompileError::AdmissionOverflow
                | BudgetedCompileError::AdmissionUnderestimated => Fault::Budget,
                BudgetedCompileError::Frontend(_)
                | BudgetedCompileError::Ir(_)
                | BudgetedCompileError::Bytecode(_) => Fault::Syntax,
            })?;
            (module, std::mem::take(&mut sink.module))
        };
        Ok((module, charges))
    }
}

#[repr(C)]
pub(crate) struct LoadStart {
    pointer: *mut c_void,
    fault: c_int,
}

/// C driver 只在返回後才執行 reader callback；此函式不保存外部 name/mode 指標。
///
/// # Safety
/// state 是存活且同執行緒的 Lua state；name 為有效 NUL 結尾字串或 NULL。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_begin_b3(
    state: *mut lua_State,
    name: *const c_char,
    file_style: c_int,
) -> LoadStart {
    match catch_unwind(AssertUnwindSafe(|| {
        let name = if name.is_null() {
            b"?".as_slice()
        } else {
            // SAFETY：C caller 保證 NUL 結尾指標，立即複製至已計費 session。
            unsafe { CStr::from_ptr(name) }.to_bytes()
        };
        // SAFETY：C caller 保活 state；VM 借用在 reader 前結束。
        unsafe { load_with_vm(state, |vm| LoadSession::new(state, vm, name, file_style)) }
    })) {
        Ok(Ok(session)) => LoadStart {
            pointer: Box::into_raw(Box::new(session)).cast(),
            fault: 0,
        },
        Ok(Err(fault)) => LoadStart {
            pointer: ptr::null_mut(),
            fault: fault as c_int,
        },
        Err(_) => LoadStart {
            pointer: ptr::null_mut(),
            fault: Fault::Budget as c_int,
        },
    }
}

/// reader 已返回，Rust 僅在此同步複製其有效片段。
///
/// # Safety
/// pointer 是本模組 begin 尚未 drop 的 session，data 在 len 期間有效。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_append_b3(
    state: *mut lua_State,
    pointer: *mut c_void,
    data: *const c_char,
    len: usize,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        if pointer.is_null() || (data.is_null() && len != 0) {
            return Err(Fault::Syntax);
        }
        // SAFETY：pointer 由本模組 begin 產生，C driver 單一 owner。
        let session = unsafe { &mut *pointer.cast::<LoadSession>() };
        if session.state != state {
            return Err(Fault::Budget);
        }
        let bytes = if len == 0 {
            &[][..]
        } else {
            // SAFETY：reader 回傳的 data 在下一次 reader 呼叫前有效，同步複製。
            unsafe { std::slice::from_raw_parts(data.cast(), len) }
        };
        // SAFETY：C caller 保活 state；本次 VM 借用在下一個 callback 前結束。
        unsafe { load_with_vm(state, |vm| session.append(vm, bytes)) }
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(fault)) => fault as c_int,
        Err(_) => Fault::Budget as c_int,
    }
}

/// C driver 已結束 reader 並恢復原 stack top 後，才編譯／decode／發布 closure。
///
/// # Safety
/// pointer 是本模組 begin 尚未 drop 的 session；mode 為有效 NUL 結尾字串或 NULL。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_finish_b3(
    state: *mut lua_State,
    pointer: *mut c_void,
    mode: *const c_char,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        if pointer.is_null() {
            return Err(Fault::Budget);
        }
        // SAFETY：pointer 由本模組 begin 產生，C driver 單一 owner。
        let session = unsafe { &mut *pointer.cast::<LoadSession>() };
        if session.state != state {
            return Err(Fault::Budget);
        }
        let mode = if mode.is_null() {
            None
        } else {
            // SAFETY：C caller 保證 NUL 結尾 mode，同步讀取不保存指標。
            Some(unsafe { CStr::from_ptr(mode) }.to_bytes())
        };
        // SAFETY：C caller 保活 state；此處沒有 user callback。
        let (module, charges) = unsafe { load_with_vm(state, |vm| session.finish(vm, mode)) }?;
        // SAFETY：上一階段 VM 借用已退出；此函式同步發布 module 和 stack root。
        unsafe { load_publish_charged(state, module, charges) }.map_err(stack_fault)
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(fault)) => fault as c_int,
        Err(_) => Fault::Budget as c_int,
    }
}

/// C driver 在正常或 C longjmp 捕捉後唯一地釋放 session。
///
/// # Safety
/// pointer 為 begin 回傳且尚未釋放的 session 或 NULL。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_drop_b3(pointer: *mut c_void) {
    if !pointer.is_null() {
        // SAFETY：C driver 唯一持有且只呼叫一次。
        drop(unsafe { Box::from_raw(pointer.cast::<LoadSession>()) });
    }
}

/// 目前 C checkpoint 把靜態診斷轉為 pending slot；配置失敗由既有 emergency 接手。
///
/// # Safety
/// generation/token 是目前純 C checkpoint，state 有效且同執行緒。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_error_b3(
    state: *mut lua_State,
    generation: u64,
    token: u64,
    fault: c_int,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        let fault = Fault::from_code(fault).ok_or(())?;
        let class = if matches!(fault, Fault::Memory) {
            ErrorClass::Allocation
        } else {
            ErrorClass::Lua
        };
        // SAFETY：C driver 的活躍 checkpoint token 與 state 由 C frame 保證。
        unsafe {
            load_prepare_error(
                Checkpoint {
                    state,
                    generation,
                    token,
                },
                fault.message(),
                class,
            )
        }
        .map(|class| class as c_int)
        .map_err(|_| ())
    })) {
        Ok(Ok(class)) => class,
        _ => -1,
    }
}

struct DumpSession {
    bytes: CapiDumpBytes,
    _owner: HostAllocationCharge,
}

#[repr(C)]
pub(crate) struct DumpStart {
    pointer: *mut c_void,
    data: *const c_void,
    len: usize,
    fault: c_int,
}

/// dump bytes 在 writer callback 期間由獨立 session 保活，不借 VM／stack。
///
/// # Safety
/// state 是存活且同執行緒的 Lua state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump_begin_b3(
    state: *mut lua_State,
    strip: c_int,
) -> DumpStart {
    match catch_unwind(AssertUnwindSafe(|| -> Result<DumpSession, Fault> {
        // SAFETY：C driver 保活 state；dump_top_bytes 返回前釋放 VM 借用。
        let bytes = unsafe { dump_top_bytes(state, strip != 0) }.map_err(stack_fault)?;
        // SAFETY：C caller 保活 state；metadata 由原 VM ledger 支付。
        let owner = unsafe {
            load_with_vm(state, |vm| {
                vm.reserve_host_allocation(size_of::<DumpSession>())
                    .map_err(StackError::from)?
                    .commit()
                    .map_err(StackError::from)
            })
        }
        .map_err(stack_fault)?;
        Ok(DumpSession {
            bytes,
            _owner: owner,
        })
    })) {
        Ok(Ok(session)) => {
            let boxed = Box::new(session);
            let data = boxed.bytes.as_bytes().as_ptr().cast();
            let len = boxed.bytes.as_bytes().len();
            DumpStart {
                pointer: Box::into_raw(boxed).cast(),
                data,
                len,
                fault: 0,
            }
        }
        Ok(Err(fault)) => DumpStart {
            pointer: ptr::null_mut(),
            data: ptr::null(),
            len: 0,
            fault: fault as c_int,
        },
        Err(_) => DumpStart {
            pointer: ptr::null_mut(),
            data: ptr::null(),
            len: 0,
            fault: Fault::Budget as c_int,
        },
    }
}

/// C driver 在正常或 writer C longjmp 捕捉後唯一地釋放 dump bytes。
///
/// # Safety
/// pointer 是 dump_begin 回傳且尚未釋放的 session 或 NULL。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump_drop_b3(pointer: *mut c_void) {
    if !pointer.is_null() {
        // SAFETY：C driver 唯一持有且只呼叫一次。
        drop(unsafe { Box::from_raw(pointer.cast::<DumpSession>()) });
    }
}
