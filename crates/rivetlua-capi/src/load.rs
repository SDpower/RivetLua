//! B3：固定 Lua C 載入與輸出的已計費 Rust session；C callback 只由純 C driver 執行。

use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
#[cfg(feature = "lua54")]
use std::mem::{align_of, size_of};

use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{
    AllocationRecovery, ReserveError, StateAllocator, ThinBlock, try_reserve_exact_with,
};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, CompileJob, CompileProgress,
    CompileSource, DiagnosticCode, LanguageProfile, Literal, TokenKind,
};
use rivetlua_compiler::official_failure::{
    OfficialFailure, OfficialFailureNear, OfficialFailureReason, official_token_text,
};
use rivetlua_core::{
    InputDecodeRecoveryError, InputError, InputErrorKind, InputFormat, IrLimits, LuaProfile,
    OfficialChunkCursor, OfficialChunkCursorBudget, OfficialChunkProgress,
    OfficialChunkRecoveryError, TransportLimits,
    VerifiedModule, classify_input, decode_input_module_with_recovery, input_scan_admission,
};
use rivetlua_core::bytecode::preflight_input_module_with_recovery;
use rivetlua_runtime::{
    AllocationCharges, HostAllocationCharge, HostAllocationReservation, LoadLimits,
    RuntimeErrorKind, Vm, VmError, VmPolicy, capi_official_short_source,
};
#[cfg(feature = "lua54")]
use rivetlua_runtime::CapiDump54Lease;
#[cfg(feature = "lua55")]
use rivetlua_runtime::CapiDumpBytes;

use crate::error::ErrorClass;
use crate::stack::{
    StackError, load_configure_limits, load_prepare_error, load_publish_charged,
    load_restore_reader_stack, load_with_vm, lua_State, rivetlua_capi_c_depth_get_b13,
};
#[cfg(feature = "lua54")]
use crate::stack::dump_top54_lease;
#[cfg(feature = "lua55")]
use crate::stack::dump_top_bytes;
use crate::trampoline::Checkpoint;

#[derive(Clone, Copy, Debug)]
#[repr(i32)]
enum Fault {
    Syntax = 1,
    Memory = 2,
    Budget = 3,
    File = 4,
    Policy = 5,
    OutputLimit = 6,
    Depth = 7,
}

impl Fault {
    fn from_code(code: c_int) -> Option<Self> {
        Some(match code {
            1 => Self::Syntax,
            2 => Self::Memory,
            3 => Self::Budget,
            4 => Self::File,
            5 => Self::Policy,
            6 => Self::OutputLimit,
            7 => Self::Depth,
            _ => return None,
        })
    }

    fn message(self) -> &'static [u8] {
        match self {
            Self::Syntax => b"invalid or incompatible Lua chunk",
            Self::Memory => b"not enough memory",
            Self::Budget => b"load resource limit exceeded",
            Self::File => b"cannot open or read Lua file",
            Self::Policy => b"E_POLICY_DENIED",
            Self::OutputLimit => b"E_OUTPUT_LIMIT",
            Self::Depth => b"C stack overflow",
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

/// 已由實體 backing 或 Rust stack/session 負責的帳款不再向 C allocator 申請影子 token。
fn reserve_host_accounting(vm: &Vm, bytes: usize) -> Result<HostAllocationReservation, VmError> {
    if vm.allocator().is_lua() {
        vm.reserve_physical_host_allocation(bytes)
    } else {
        vm.reserve_host_allocation(bytes)
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
        StackError::PolicyDenied => Fault::Policy,
        StackError::OutputLimit => Fault::OutputLimit,
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
    bytes: AllocVec<u8, StateAllocator>,
    _base: Option<HostAllocationCharge>,
    _extra: Option<HostAllocationCharge>,
}

impl ChargedBytes {
    fn empty(allocator: StateAllocator) -> Self {
        Self {
            bytes: AllocVec::new_in(allocator),
            _base: None,
            _extra: None,
        }
    }

    fn append(&mut self, vm: &mut Vm, part: &[u8], limit: usize) -> Result<(), Fault> {
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
            let base = vm
                .reserve_physical_host_allocation(capacity)
                .map_err(vm_fault)?;
            let mut replacement = AllocVec::new_in(vm.allocator());
            try_reserve_exact_with(&mut replacement, capacity, vm).map_err(|error| {
                vm_fault(match error {
                    ReserveError::AllocatorMismatch => VmError::LedgerInvariant,
                    ReserveError::CallbackRefused => base.physical_reserve_failure(),
                    ReserveError::AllocationFailed => base.rust_reserve_failure(),
                    ReserveError::Recovery(error) => error,
                })
            })?;
            let extra_bytes = replacement
                .capacity()
                .checked_sub(capacity)
                .ok_or(Fault::Budget)?;
            let extra = if extra_bytes == 0 {
                None
            } else {
                Some(
                    vm.reserve_physical_host_allocation(extra_bytes)
                        .map_err(vm_fault)?,
                )
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

impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn diagnostic_part(vm: &mut Vm, out: &mut ChargedBytes, bytes: &[u8]) -> Result<(), Fault> {
    out.append(vm, bytes, usize::MAX)
}

fn diagnostic_decimal(vm: &mut Vm, out: &mut ChargedBytes, mut value: usize) -> Result<(), Fault> {
    let mut digits = [0_u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 { break; }
    }
    diagnostic_part(vm, out, &digits[at..])
}

fn diagnostic_token(vm: &mut Vm, out: &mut ChargedBytes, kind: TokenKind) -> Result<(), Fault> {
    let text = official_token_text(kind);
    let quoted = matches!(kind, TokenKind::Keyword(_) | TokenKind::Symbol(_));
    if quoted { diagnostic_part(vm, out, b"'")?; }
    diagnostic_part(vm, out, text)?;
    if quoted { diagnostic_part(vm, out, b"'")?; }
    Ok(())
}

fn diagnostic_near(vm: &mut Vm, out: &mut ChargedBytes, near: &OfficialFailureNear,
    source: &[u8]) -> Result<(), Fault> {
    match near {
        OfficialFailureNear::None => Ok(()),
        OfficialFailureNear::Eof => diagnostic_part(vm, out, b" near <eof>"),
        OfficialFailureNear::RawSymbol(byte) => {
            diagnostic_part(vm, out, b" near '")?;
            if byte.is_ascii_graphic() || *byte == b' ' {
                diagnostic_part(vm, out, &[*byte])?;
            } else {
                diagnostic_part(vm, out, b"<\\")?;
                diagnostic_decimal(vm, out, usize::from(*byte))?;
                diagnostic_part(vm, out, b">")?;
            }
            diagnostic_part(vm, out, b"'")
        }
        OfficialFailureNear::LongDelimiter(equals) => {
            diagnostic_part(vm, out, b" near '[")?;
            let block = [b'='; 64];
            let mut remaining = *equals;
            while remaining != 0 {
                let amount = remaining.min(block.len());
                diagnostic_part(vm, out, &block[..amount])?;
                remaining -= amount;
            }
            diagnostic_part(vm, out, b"'")
        }
        OfficialFailureNear::Token(token) => {
            diagnostic_part(vm, out, b" near ")?;
            match (token.kind, token.literal.as_ref()) {
                (TokenKind::Name, Some(Literal::Name(bytes))) => {
                    diagnostic_part(vm, out, b"'")?;
                    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
                    diagnostic_part(vm, out, &bytes[..end])?;
                    diagnostic_part(vm, out, b"'")
                }
                (TokenKind::String, Some(Literal::String(bytes))) => {
                    let start = token.span.start_byte;
                    let opening = source.get(start).copied().unwrap_or(b'\'');
                    diagnostic_part(vm, out, b"'")?;
                    let delimiter = if opening == b'[' {
                        source.get(start..token.span.end_byte)
                            .and_then(|raw| raw.iter().skip(1).position(|byte| *byte == b'[')
                                .map(|offset| offset + 2))
                            .unwrap_or(1)
                    } else { 1 };
                    if opening == b'[' {
                        if let Some(raw) = source.get(start..start.saturating_add(delimiter)) {
                            diagnostic_part(vm, out, raw)?;
                        }
                    } else { diagnostic_part(vm, out, &[opening])?; }
                    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
                    diagnostic_part(vm, out, &bytes[..end])?;
                    if end == bytes.len() {
                        if opening == b'[' {
                            if let Some(raw) = source.get(token.span.end_byte.saturating_sub(delimiter)..token.span.end_byte) {
                                diagnostic_part(vm, out, raw)?;
                            }
                        } else { diagnostic_part(vm, out, &[opening])?; }
                    }
                    diagnostic_part(vm, out, b"'")
                }
                (TokenKind::Integer | TokenKind::Float, _) => {
                    diagnostic_part(vm, out, b"'")?;
                    if let Some(bytes) = source.get(token.span.start_byte..token.span.end_byte) {
                        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
                        diagnostic_part(vm, out, &bytes[..end])?;
                    }
                    diagnostic_part(vm, out, b"'")
                }
                _ => diagnostic_token(vm, out, token.kind),
            }
        }
        OfficialFailureNear::Scanner(bytes) => {
            diagnostic_part(vm, out, b" near '")?;
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, out, &bytes[..end])?;
            diagnostic_part(vm, out, b"'")
        }
        OfficialFailureNear::ScannerSuffix(bytes, suffix) => {
            diagnostic_part(vm, out, b" near '")?;
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, out, &bytes[..end])?;
            if end == bytes.len() && *suffix != 0 { diagnostic_part(vm, out, &[*suffix])?; }
            diagnostic_part(vm, out, b"'")
        }
        OfficialFailureNear::ShortString { quote, cooked, suffix } => {
            diagnostic_part(vm, out, b" near '")?;
            diagnostic_part(vm, out, &[*quote])?;
            let end = cooked.iter().position(|byte| *byte == 0).unwrap_or(cooked.len());
            diagnostic_part(vm, out, &cooked[..end])?;
            if end == cooked.len() {
                if let Some((start, end)) = suffix {
                    if let Some(raw) = source.get(*start..*end) {
                        let visible = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                        diagnostic_part(vm, out, &raw[..visible])?;
                    }
                }
            }
            diagnostic_part(vm, out, b"'")
        }
    }
}

fn official_diagnostic(vm: &mut Vm, chunkname: &[u8], source: &[u8],
    failure: &OfficialFailure, profile: LuaProfile) -> Result<ChargedBytes, Fault> {
    let mut out = ChargedBytes::empty(vm.allocator());
    let (short, len) = capi_official_short_source(chunkname);
    diagnostic_part(vm, &mut out, &short[..len])?;
    diagnostic_part(vm, &mut out, b":")?;
    diagnostic_decimal(vm, &mut out, failure.line)?;
    diagnostic_part(vm, &mut out, b": ")?;
    match &failure.reason {
        OfficialFailureReason::Expected { token, opener } => {
            diagnostic_token(vm, &mut out, *token)?;
            diagnostic_part(vm, &mut out, b" expected")?;
            if let Some((opener, line)) = *opener {
                if line != failure.line {
                    diagnostic_part(vm, &mut out, b" (to close ")?;
                    diagnostic_token(vm, &mut out, opener)?;
                    diagnostic_part(vm, &mut out, b" at line ")?;
                    diagnostic_decimal(vm, &mut out, line)?;
                    diagnostic_part(vm, &mut out, b")")?;
                }
            }
        }
        OfficialFailureReason::Text(reason) => diagnostic_part(vm, &mut out, reason)?,
        OfficialFailureReason::LongUnfinished { comment, opener_line } => {
            diagnostic_part(vm, &mut out, if *comment {
                b"unfinished long comment (starting at line ".as_slice()
            } else { b"unfinished long string (starting at line ".as_slice() })?;
            diagnostic_decimal(vm, &mut out, *opener_line)?;
            diagnostic_part(vm, &mut out, b")")?;
        }
        OfficialFailureReason::BreakOutside { line, .. } => {
            diagnostic_part(vm, &mut out, b"break outside loop")?;
            if profile == LuaProfile::Lua54 {
                diagnostic_part(vm, &mut out, b" at line ")?;
                diagnostic_decimal(vm, &mut out, *line)?;
            }
        }
        OfficialFailureReason::AssignConst { name, .. } => {
            diagnostic_part(vm, &mut out, b"attempt to assign to const variable '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"'")?;
        }
        OfficialFailureReason::GotoMissing { name, line, .. } => {
            diagnostic_part(vm, &mut out, b"no visible label '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"' for <goto> at line ")?;
            diagnostic_decimal(vm, &mut out, *line)?;
        }
        OfficialFailureReason::GotoIntoScope { label, variable, line, .. } => {
            diagnostic_part(vm, &mut out, b"<goto ")?;
            let bytes = label.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"> at line ")?;
            diagnostic_decimal(vm, &mut out, *line)?;
            diagnostic_part(vm, &mut out, if profile == LuaProfile::Lua54 {
                b" jumps into the scope of local '".as_slice()
            } else { b" jumps into the scope of '".as_slice() })?;
            if let Some(variable) = variable {
                let bytes = variable.as_slice();
                let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
                diagnostic_part(vm, &mut out, &bytes[..end])?;
            } else { diagnostic_part(vm, &mut out, b"*")?; }
            diagnostic_part(vm, &mut out, b"'")?;
        }
        OfficialFailureReason::EnvironmentGlobal { name, .. } => {
            diagnostic_part(vm, &mut out, b"_ENV is global when accessing variable '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"'")?;
        }
        OfficialFailureReason::VariableUndeclared { name, .. } => {
            diagnostic_part(vm, &mut out, b"variable '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"' not declared")?;
        }
        OfficialFailureReason::LabelDuplicate { name, previous_line, .. } => {
            diagnostic_part(vm, &mut out, b"label '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"' already defined on line ")?;
            diagnostic_decimal(vm, &mut out, *previous_line)?;
        }
        OfficialFailureReason::MultipleClose { .. } =>
            diagnostic_part(vm, &mut out, b"multiple to-be-closed variables in local list")?,
        OfficialFailureReason::UnknownAttribute { name } => {
            diagnostic_part(vm, &mut out, b"unknown attribute '")?;
            let bytes = name.as_slice();
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
            diagnostic_part(vm, &mut out, &bytes[..end])?;
            diagnostic_part(vm, &mut out, b"'")?;
        }
    }
    diagnostic_near(vm, &mut out, &failure.near, source)?;
    Ok(out)
}

fn official_mode_diagnostic(vm: &mut Vm, binary: bool, mode: &[u8])
    -> Result<ChargedBytes, Fault> {
    let mut out = ChargedBytes::empty(vm.allocator());
    diagnostic_part(vm, &mut out, b"attempt to load a ")?;
    diagnostic_part(vm, &mut out, if binary { b"binary".as_slice() } else { b"text".as_slice() })?;
    diagnostic_part(vm, &mut out, b" chunk (mode is '")?;
    diagnostic_part(vm, &mut out, mode)?;
    diagnostic_part(vm, &mut out, b"')")?;
    Ok(out)
}

struct CompileMeter {
    state: *mut lua_State,
    allocator: StateAllocator,
    work_left: usize,
    temporary_left: usize,
    module_left: usize,
    _temporary: AllocationCharges,
    module: AllocationCharges,
}

impl AllocationRecovery for CompileMeter {
    type Error = Fault;

    fn allocator(&self) -> StateAllocator {
        self.allocator.clone()
    }

    fn recover_after_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        // SAFETY：B3 driver 保活 state；此處只在回傳前短借 VM。
        unsafe { load_with_vm(self.state, |vm| vm.recover_after_refusal(before).map_err(vm_fault)) }
    }
}

impl CompileMeter {
    fn claim(&mut self, bytes: usize, module: bool) -> Result<(), Fault> {
        if bytes == 0 {
            return Ok(());
        }
        let state = self.state;
        let charges = if module { &mut self.module } else { &mut self._temporary };
        // SAFETY：B3 driver 保活 state；allocator 與 GC 重試只在此閉包內借用 VM。
        unsafe { load_with_vm(state, |vm| {
            let allocator = vm.allocator();
            let before = allocator.refusal_count();
            if let Err(error) = charges.try_reserve(1) {
                if allocator.refusal_count() == before
                    || !vm.recover_after_refusal(before).map_err(vm_fault)?
                {
                    return Err(vm_fault(error));
                }
                charges.try_reserve(1).map_err(vm_fault)?;
            }
            let charge = reserve_host_accounting(vm, bytes)
                .map_err(vm_fault)?
                .commit_module_charge()
                .map_err(vm_fault)?;
            charges.try_push(charge).map_err(|(error, charge)| {
                drop(charge);
                vm_fault(error)
            })?;
            Ok(())
        }) }
    }
}

impl CompileBudgetSink for CompileMeter {
    type Error = Fault;

    fn state_allocator(&self) -> StateAllocator {
        self.allocator.clone()
    }

    fn recover_allocator_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        AllocationRecovery::recover_after_refusal(self, before)
    }

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work_left = self.work_left.checked_sub(units).ok_or(Fault::Budget)?;
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary_left = self
            .temporary_left
            .checked_sub(bytes)
            .ok_or(Fault::Budget)?;
        self.claim(bytes, false)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module_left = self.module_left.checked_sub(bytes).ok_or(Fault::Budget)?;
        self.claim(bytes, true)
    }
}

impl OfficialChunkCursorBudget for CompileMeter {
    fn claim_cursor_temporary(&mut self, additional: usize) -> Result<(), Self::Error> {
        self.claim_temporary(additional)
    }
}

#[repr(C)]
struct ReaderPiece {
    data: *const c_char,
    len: usize,
    status: c_int,
    new_piece: c_int,
    class_code: c_int,
}

unsafe extern "C" {
    fn rivetlua_b3_reader_peek_c(state: *mut lua_State, context: *mut c_void) -> ReaderPiece;
    fn rivetlua_b3_reader_consume_c(context: *mut c_void, bytes: usize) -> c_int;
}

#[derive(Clone, Copy)]
enum PullFault {
    Fault(Fault),
    ReaderStopped(c_int),
    ReaderYield,
    Terminal,
}

struct CapiReader<'a> {
    session: &'a mut LoadSession,
    context: *mut c_void,
    meter: CompileMeter,
    eof: bool,
}

impl CapiReader<'_> {
    fn peek(&mut self) -> Result<Option<ReaderPiece>, PullFault> {
        if self.eof { return Ok(None); }
        // SAFETY：純 C child checkpoint 已在 Rust 返回前退鏈；片段活到下一次 reader。
        let piece = unsafe { rivetlua_b3_reader_peek_c(self.session.state, self.context) };
        match piece.status {
            -1 => { self.eof = true; return Ok(None); }
            -2 => return Err(PullFault::ReaderStopped(piece.class_code)),
            -3 => return Err(PullFault::Terminal),
            -4 => return Err(PullFault::ReaderYield),
            0 => {}
            code => return Err(PullFault::Fault(Fault::from_code(code).unwrap_or(Fault::Budget))),
        }
        if piece.data.is_null() || piece.len == 0 { return Err(PullFault::Fault(Fault::Budget)); }
        if piece.new_piece != 0 {
            self.session.chunks = self.session.chunks.checked_add(1)
                .ok_or(PullFault::Fault(Fault::Budget))?;
            if self.session.chunks > self.session.limits.max_reader_chunks {
                return Err(PullFault::Fault(Fault::Budget));
            }
            self.meter.spend_work(1).map_err(PullFault::Fault)?;
        }
        Ok(Some(piece))
    }

    fn consume(&self, count: usize) -> Result<(), PullFault> {
        if count == 0 { return Ok(()); }
        // SAFETY：count 只取本次 peek 片段已由 source/job 接受的前綴。
        if unsafe { rivetlua_b3_reader_consume_c(self.context, count) } != 1 {
            return Err(PullFault::Fault(Fault::Budget));
        }
        Ok(())
    }

    fn copy_prefix(&mut self, piece: ReaderPiece, count: usize) -> Result<(), PullFault> {
        if count == 0 || count > piece.len { return Err(PullFault::Fault(Fault::Budget)); }
        let limit = self.session.limits.max_source_bytes.max(self.session.limits.max_encoded_bytes);
        self.meter.spend_work(count).map_err(PullFault::Fault)?;
        // SAFETY：C piece 在下一次 reader 前有效，且 VM 借用在呼叫 reader 前結束。
        let part = unsafe { std::slice::from_raw_parts(piece.data.cast::<u8>(), count) };
        let state = self.session.state;
        unsafe { load_with_vm(state, |vm| self.session.source.append(vm, part, limit)) }
            .map_err(PullFault::Fault)?;
        self.consume(count)
    }
}

struct CapiCompileSource<'a> {
    state: *mut lua_State,
    archive: &'a mut ChargedBytes,
    allocator: StateAllocator,
    limit: usize,
    admitted: usize,
    fault: Option<Fault>,
}

impl CompileSource for CapiCompileSource<'_> {
    type Source = ChargedBytes;

    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, _: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        if let Some(existing) = self.archive.bytes.get(self.admitted) {
            if *existing != byte { return Err(BudgetedCompileError::AdmissionUnderestimated); }
        } else {
            if self.admitted != self.archive.bytes.len() {
                return Err(BudgetedCompileError::AdmissionUnderestimated);
            }
            let required = self.admitted.checked_add(1)
                .ok_or(BudgetedCompileError::AdmissionOverflow)?;
            if required > self.limit {
                self.fault = Some(Fault::Budget);
                return Err(BudgetedCompileError::AllocationFailed);
            }
            if required <= self.archive.bytes.capacity() {
                self.archive.bytes.push(byte);
            } else {
                let part = [byte];
                // SAFETY：配置及一次 GC refusal recovery 僅短借 VM，不呼叫 C reader。
                if let Err(fault) = unsafe {
                    load_with_vm(self.state, |vm| self.archive.append(vm, &part, self.limit))
                } {
                    self.fault = Some(fault);
                    return Err(BudgetedCompileError::AllocationFailed);
                }
            }
        }
        self.admitted += 1;
        Ok(())
    }

    fn take_source(&mut self) -> Self::Source {
        std::mem::replace(self.archive, ChargedBytes::empty(self.allocator.clone()))
    }
}

struct LoadSession {
    state: *mut lua_State,
    profile: LuaProfile,
    limits: LoadLimits,
    unbounded: bool,
    source: ChargedBytes,
    chunkname: ChargedBytes,
    work_left: usize,
    chunks: usize,
    official_cursor: Option<OfficialChunkCursor>,
    official_need: usize,
    official_consumed: Option<usize>,
    ready: Option<(VerifiedModule, AllocationCharges)>,
    diagnostic: Option<ChargedBytes>,
    _owner: HostAllocationCharge,
}

fn official_header_prefix_valid(bytes: &[u8], profile: LuaProfile) -> bool {
    let version = if profile == LuaProfile::Lua55 { 0x55 } else { 0x54 };
    let prefix = [b"\x1bLua".as_slice(), &[version, 0], b"\x19\x93\r\n\x1a\n"];
    let common = prefix.into_iter().flatten();
    let valid_common = bytes.iter().zip(common).all(|(actual, expected)| actual == expected);
    if !valid_common { return false; }
    let fixed = &bytes[bytes.len().min(12)..];
    let valid_fixed = match profile {
        LuaProfile::Lua54 => {
            let integer = 0x5678_i64.to_le_bytes();
            let number = 370.5_f64.to_le_bytes();
            let fields = [b"\x04\x08\x08".as_slice(), integer.as_slice(), number.as_slice()];
            fixed.iter().zip(fields.into_iter().flatten()).all(|(actual, expected)| actual == expected)
        }
        LuaProfile::Lua55 => {
            let cint = (-0x5678_i32).to_le_bytes();
            let instruction = 0x1234_5678_u32.to_le_bytes();
            let integer = (-0x5678_i64).to_le_bytes();
            let number = (-370.5_f64).to_le_bytes();
            let fields = [b"\x04".as_slice(), cint.as_slice(), b"\x04", instruction.as_slice(), b"\x08", integer.as_slice(), b"\x08", number.as_slice()];
            fixed.iter().zip(fields.into_iter().flatten()).all(|(actual, expected)| actual == expected)
        }
    };
    valid_fixed
}

impl LoadSession {
    fn text_limits(&self, vm: &Vm, c_depth: usize) -> (CompileLimits, IrLimits, rivetlua_core::VerifyLimits) {
        let mut verify_limits = vm.capi_load_verify_limits();
        let mut compile_limits = CompileLimits::default();
        let mut ir_limits = IrLimits::default();
        if self.unbounded {
            compile_limits.max_source_bytes = usize::MAX;
            compile_limits.max_token_bytes = usize::MAX;
            compile_limits.max_tokens = usize::MAX;
            compile_limits.max_lines = usize::MAX;
            compile_limits.max_ast_nodes = usize::MAX;
            compile_limits.max_parse_depth = 199usize.saturating_sub(c_depth);
            compile_limits.max_statements = usize::MAX;
            compile_limits.max_list_entries = usize::MAX;
            compile_limits.max_bindings_per_function = usize::MAX;
            compile_limits.max_scope_depth = 200;
            compile_limits.max_labels = usize::MAX;
            compile_limits.max_gotos = usize::MAX;
            ir_limits.max_prototypes = usize::MAX;
            ir_limits.max_instructions = usize::MAX;
            if !vm.capi_load_verify_limits_explicit() {
                verify_limits.max_module_bytes = usize::MAX;
                verify_limits.max_artifact_bytes = usize::MAX;
                verify_limits.max_prototypes = usize::MAX;
                verify_limits.max_instructions = usize::MAX;
                verify_limits.max_constants = usize::MAX;
            }
        }
        (compile_limits, ir_limits, verify_limits)
    }

    fn new(
        state: *mut lua_State,
        vm: &mut Vm,
        name: &[u8],
        file_style: c_int,
    ) -> Result<ThinBlock<Self>, Fault> {
        let mut limits = vm.capi_load_limits();
        let unbounded = vm.policy() == VmPolicy::Compatibility
            && !vm.capi_load_limits_explicit();
        if unbounded {
            limits = LoadLimits {
                max_source_bytes: usize::MAX,
                max_encoded_bytes: usize::MAX,
                max_module_allocation_bytes: usize::MAX,
                max_temporary_bytes: usize::MAX,
                max_work_units: usize::MAX,
                max_reader_chunks: usize::MAX,
                max_path_candidates: usize::MAX,
            };
        }
        let (storage, owner) = vm.capi_reserve_host_thin::<Self>().map_err(vm_fault)?;
        let mut chunkname = ChargedBytes::empty(vm.allocator());
        if file_style == 1 {
            chunkname.append(vm, b"@", limits.max_temporary_bytes)?;
        }
        chunkname.append(vm, name, limits.max_temporary_bytes)?;
        let owner = owner.commit().map_err(vm_fault)?;
        Ok(storage.write(Self {
            state,
            profile: if cfg!(feature = "lua55") {
                LuaProfile::Lua55
            } else {
                LuaProfile::Lua54
            },
            limits,
            unbounded,
            source: ChargedBytes::empty(vm.allocator()),
            chunkname,
            work_left: limits.max_work_units,
            chunks: 0,
            official_cursor: None,
            official_need: 1,
            official_consumed: None,
            ready: None,
            diagnostic: None,
            _owner: owner,
        }))
    }

    fn binary_limits(&self, vm: &Vm) -> Result<TransportLimits, Fault> {
        let mut limits = TransportLimits::default();
        limits.verify = vm.capi_load_verify_limits();
        if self.unbounded {
            if !vm.capi_load_verify_limits_explicit() {
                limits.verify.max_module_bytes = usize::MAX;
                limits.verify.max_artifact_bytes = usize::MAX;
                limits.verify.max_prototypes = usize::MAX;
                limits.verify.max_instructions = usize::MAX;
                limits.verify.max_constants = usize::MAX;
            }
            limits.official.max_bytes = usize::MAX;
            limits.official.max_depth = usize::MAX;
            limits.official.max_prototypes = usize::MAX;
            limits.official.max_instructions = usize::MAX;
            limits.official.max_constants = usize::MAX;
            limits.official.max_upvalues = usize::MAX;
            limits.official.max_debug_entries = usize::MAX;
            limits.official.max_strings = usize::MAX;
            limits.official.max_string_bytes = usize::MAX;
            limits.official.max_total_string_bytes = usize::MAX;
            limits.official.max_allocated_bytes = usize::MAX;
            limits.max_sidecar_bytes = usize::MAX;
        }
        limits.max_temporary_bytes = self.limits.max_temporary_bytes;
        limits.max_retained_bytes = self.limits.max_module_allocation_bytes;
        limits.max_work = u64::try_from(self.work_left).map_err(|_| Fault::Budget)?;
        limits.official.max_bytes = limits.official.max_bytes.min(self.limits.max_encoded_bytes);
        Ok(limits)
    }

    fn finish(
        &mut self,
        vm: &mut Vm,
        mode: Option<&[u8]>,
        _c_depth: usize,
    ) -> Result<(VerifiedModule, AllocationCharges), Fault> {
        self.official_cursor = None;
        if let Some(consumed) = self.official_consumed {
            if consumed > self.source.bytes.len() { return Err(Fault::Budget); }
            self.source.bytes.truncate(consumed);
        }
        let format = classify_input(&self.source.bytes);
        let binary = !matches!(format, InputFormat::Source);
        if binary && vm.policy() != VmPolicy::Compatibility {
            return Err(Fault::Policy);
        }
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

        if !binary {
            return Err(Fault::Syntax);
        }
        let (module, charges) = {
            let scan =
                input_scan_admission(self.source.bytes.len(), format).map_err(input_fault)?;
            let scan_work = usize::try_from(scan.work).map_err(|_| Fault::Budget)?;
            if scan_work > self.work_left {
                return Err(Fault::Budget);
            }
            let limits = self.binary_limits(vm)?;
            let preflight = preflight_input_module_with_recovery(&self.source.bytes, self.profile, &limits, vm)
                .map_err(|error| match error {
                    InputDecodeRecoveryError::Input(error) => input_fault(error),
                    InputDecodeRecoveryError::Reserve(ReserveError::Recovery(error)) => vm_fault(error),
                    InputDecodeRecoveryError::Reserve(ReserveError::AllocatorMismatch) => Fault::Budget,
                    InputDecodeRecoveryError::Reserve(_) => Fault::Memory,
                })?;
            let admitted = preflight.admission();
            let all_work = admitted
                .scan_work
                .checked_add(admitted.subsequent_work)
                .ok_or(Fault::Budget)?;
            self.work_left = self
                .work_left
                .checked_sub(usize::try_from(all_work).map_err(|_| Fault::Budget)?)
                .ok_or(Fault::Budget)?;
            let temporary = reserve_host_accounting(vm, admitted.temporary_bytes)
                .map_err(vm_fault)?
                .commit()
                .map_err(vm_fault)?;
            let mut charges = AllocationCharges::new_in(vm.capi_backing_allocator());
            charges.try_reserve(1).map_err(vm_fault)?;
            let retained = reserve_host_accounting(vm, admitted.retained_bytes)
                .map_err(vm_fault)?
                .commit_module_charge()
                .map_err(vm_fault)?;
            charges.try_push(retained).map_err(|(error, charge)| {
                drop(charge);
                vm_fault(error)
            })?;
            let module = decode_input_module_with_recovery(preflight, vm).map_err(|error| {
                match error {
                    InputDecodeRecoveryError::Input(error) => input_fault(error),
                    InputDecodeRecoveryError::Reserve(ReserveError::Recovery(error)) => {
                        vm_fault(error)
                    }
                    InputDecodeRecoveryError::Reserve(ReserveError::AllocatorMismatch) => {
                        Fault::Budget
                    }
                    InputDecodeRecoveryError::Reserve(_) => Fault::Memory,
                }
            })?;
            drop(temporary);
            (module, charges)
        };
        Ok((module, charges))
    }
}

fn compile_fault(error: BudgetedCompileError<Fault>, unbounded: bool) -> Fault {
    match error {
        BudgetedCompileError::Budget(fault) => fault,
        BudgetedCompileError::AllocationFailed => Fault::Memory,
        BudgetedCompileError::AdmissionOverflow | BudgetedCompileError::AdmissionUnderestimated =>
            Fault::Budget,
        BudgetedCompileError::Frontend(diagnostic)
            if unbounded && diagnostic.code == DiagnosticCode::CompileLimit
                && diagnostic.message == "解析深度超過編譯限制" => Fault::Depth,
        BudgetedCompileError::Frontend(_) | BudgetedCompileError::Ir(_)
        | BudgetedCompileError::Bytecode(_) => Fault::Syntax,
    }
}

fn raw_rvlu_may_follow(prefix: &[u8]) -> bool {
    if prefix.len() <= 4 { return b"RVLU".starts_with(prefix); }
    prefix.starts_with(b"RVLU") && prefix.len() < 6
}

fn advance_official(reader: &mut CapiReader<'_>) -> Result<bool, PullFault> {
    let session = &mut *reader.session;
    if !official_header_prefix_valid(&session.source.bytes, session.profile) {
        return Err(PullFault::Fault(Fault::Syntax));
    }
    if session.official_cursor.is_none() {
        session.work_left = reader.meter.work_left;
        let state = session.state;
        // SAFETY：只在同步短借內讀 policy、allocator 與限額；cursor 不借 VM。
        let (mut limits, allocator) = unsafe { load_with_vm(state, |vm| {
            if vm.policy() != VmPolicy::Compatibility { return Err(Fault::Policy); }
            Ok((session.binary_limits(vm)?, vm.allocator()))
        }) }.map_err(PullFault::Fault)?;
        limits.official.max_allocated_bytes =
            limits.official.max_allocated_bytes.min(limits.max_temporary_bytes);
        session.official_cursor = Some(OfficialChunkCursor::new(
            session.profile, limits.official, limits.verify, allocator,
        ));
    }
    let result = session.official_cursor.as_mut().expect("官方 cursor 已建立")
        .advance_budgeted(&session.source.bytes, &mut reader.meter);
    match result {
        Ok(OfficialChunkProgress::NeedMore { minimum_total }) => {
            session.official_need = minimum_total;
            Ok(false)
        }
        Ok(OfficialChunkProgress::Complete { consumed }) => {
            session.official_consumed = Some(consumed);
            Ok(true)
        }
        Err(OfficialChunkRecoveryError::Chunk(error)) =>
            Err(PullFault::Fault(input_fault(error.into()))),
        Err(OfficialChunkRecoveryError::Reserve(ReserveError::Recovery(error))) =>
            Err(PullFault::Fault(error)),
        Err(OfficialChunkRecoveryError::Reserve(ReserveError::AllocatorMismatch)) =>
            Err(PullFault::Fault(Fault::Budget)),
        Err(OfficialChunkRecoveryError::Reserve(_)) =>
            Err(PullFault::Fault(Fault::Memory)),
    }
}

fn finish_binary(reader: &mut CapiReader<'_>, mode: Option<&[u8]>)
    -> Result<(), PullFault> {
    reader.session.work_left = reader.meter.work_left;
    reader.session.official_cursor = None;
    drop(std::mem::take(&mut reader.meter._temporary));
    let state = reader.session.state;
    // SAFETY：reader 已停，短借 VM 只用於安全 decode，返回後才由 C 發布 closure。
    let (module, charges) = unsafe {
        load_with_vm(state, |vm| reader.session.finish(vm, mode, 0))
    }.map_err(PullFault::Fault)?;
    reader.session.ready = Some((module, charges));
    Ok(())
}

fn drive_reader_load(
    session: &mut LoadSession, context: *mut c_void, mode: *const c_char,
) -> Result<(), PullFault> {
    let state = session.state;
    // SAFETY：深度查詢須先於 StateGroup 的任何可變借用。
    let c_depth = unsafe { rivetlua_capi_c_depth_get_b13(state) };
    if c_depth < 0 { return Err(PullFault::Fault(Fault::Budget)); }
    // SAFETY：只讀設定及 allocator 身分；C reader 不在 VM 借用期間執行。
    let (allocator, backing, compile_limits, ir_limits, verify_limits) = unsafe {
        load_with_vm(state, |vm| {
            let (compile, ir, verify) = session.text_limits(vm, c_depth as usize);
            Ok((vm.allocator(), vm.capi_backing_allocator(), compile, ir, verify))
        })
    }.map_err(PullFault::Fault)?;
    let mode_bytes = if mode.is_null() { None } else {
        // SAFETY：C action 在整次同步 load 保活 mode。
        Some(unsafe { CStr::from_ptr(mode) }.to_bytes())
    };
    let meter = CompileMeter {
        state, allocator: allocator.clone(), work_left: session.work_left,
        temporary_left: session.limits.max_temporary_bytes,
        module_left: session.limits.max_module_allocation_bytes,
        _temporary: AllocationCharges::new_in(backing.clone()),
        module: AllocationCharges::new_in(backing),
    };
    let mut reader = CapiReader { session, context, meter, eof: false };
    let mut head = [0u8; 6];
    let mut head_len = 0usize;
    let format = 'classify: loop {
        let Some(piece) = reader.peek()? else { break InputFormat::Source; };
        // SAFETY：本片段在下一次 C reader 前有效；分類不消耗文字片段的尾端。
        let available = unsafe { std::slice::from_raw_parts(piece.data.cast::<u8>(), piece.len) };
        let mut examined = 0usize;
        while examined < available.len() && head_len + examined < head.len() {
            head[head_len + examined] = available[examined];
            let candidate = &head[..head_len + examined + 1];
            if candidate[0] == 0x1b {
                reader.copy_prefix(piece, examined + 1)?;
                head_len += examined + 1;
                break 'classify InputFormat::Official;
            }
            if matches!(classify_input(candidate), InputFormat::RawRvlu) {
                reader.copy_prefix(piece, examined + 1)?;
                head_len += examined + 1;
                break 'classify InputFormat::RawRvlu;
            }
            if !raw_rvlu_may_follow(candidate) {
                reader.meter.spend_work(examined + 1).map_err(PullFault::Fault)?;
                break 'classify InputFormat::Source;
            }
            examined += 1;
        }
        if examined == 0 { return Err(PullFault::Fault(Fault::Budget)); }
        reader.copy_prefix(piece, examined)?;
        head_len += examined;
    };
    if !matches!(format, InputFormat::Source) {
        // SAFETY：分類完成後先讀取相容策略，避免不允許的 binary 拉取 reader 尾端。
        let compatible = unsafe { load_with_vm(state, |vm| Ok::<_, Fault>(vm.policy() == VmPolicy::Compatibility)) }
            .map_err(PullFault::Fault)?;
        if !compatible { return Err(PullFault::Fault(Fault::Policy)); }
        if !mode_bytes.is_none_or(|mode| mode.contains(&b'b')
            || (reader.session.profile == LuaProfile::Lua55 && mode.contains(&b'B'))) {
            let mode = mode_bytes.unwrap_or_default();
            // SAFETY：同步 load action 保活 state；reader 返回後沒有 VM 借用。
            let message = unsafe { load_with_vm(state, |vm| {
                official_mode_diagnostic(vm, true, mode)
            }) }.map_err(|_| PullFault::Fault(Fault::Memory))?;
            reader.session.diagnostic = Some(message);
            return Err(PullFault::Fault(Fault::Syntax));
        }
        if matches!(format, InputFormat::Official) {
            loop {
                if advance_official(&mut reader)? { break; }
                let need = reader.session.official_need
                    .checked_sub(reader.session.source.bytes.len())
                    .filter(|need| *need != 0).ok_or(PullFault::Fault(Fault::Budget))?;
                let Some(piece) = reader.peek()? else { return Err(PullFault::Fault(Fault::Syntax)); };
                let take = need.min(piece.len);
                reader.copy_prefix(piece, take)?;
            }
        } else {
            while let Some(piece) = reader.peek()? {
                let length = piece.len;
                reader.copy_prefix(piece, length)?;
            }
        }
        return finish_binary(&mut reader, mode_bytes);
    }
    if !mode_bytes.is_none_or(|mode| mode.contains(&b't')) {
        let mode = mode_bytes.unwrap_or_default();
        // SAFETY：同步 load action 保活 state；reader 返回後沒有 VM 借用。
        let message = unsafe { load_with_vm(state, |vm| {
            official_mode_diagnostic(vm, false, mode)
        }) }.map_err(|_| PullFault::Fault(Fault::Memory))?;
        reader.session.diagnostic = Some(message);
        return Err(PullFault::Fault(Fault::Syntax));
    }
    if reader.session.source.bytes.len() > reader.session.limits.max_source_bytes {
        return Err(PullFault::Fault(Fault::Budget));
    }
    let language = match reader.session.profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let mut job = CompileJob::new(language, compile_limits, ir_limits, verify_limits);
    let mut initial = head_len != 0;
    loop {
        let piece = if initial { None } else { reader.peek()? };
        let eof = if initial { reader.eof } else { piece.is_none() };
        let available = if initial {
            &head[..head_len]
        } else if let Some(piece) = piece.as_ref() {
            // SAFETY：C piece 直到下次 reader callback 都有效；job 不持此 slice。
            unsafe { std::slice::from_raw_parts(piece.data.cast::<u8>(), piece.len) }
        } else {
            &[]
        };
        let before = job.consumed_total();
        let (result, source_fault) = {
            let session = &mut *reader.session;
            let mut source = CapiCompileSource {
                state, archive: &mut session.source, allocator: allocator.clone(),
                limit: session.limits.max_source_bytes, admitted: before, fault: None,
            };
            let result = job.advance(available, eof, &mut source,
                &session.chunkname.bytes, &mut reader.meter);
            (result, source.fault)
        };
        let consumed = job.consumed_total().checked_sub(before)
            .ok_or(PullFault::Fault(Fault::Budget))?;
        if !initial { reader.consume(consumed)?; }
        initial = false;
        match result {
            Ok(progress) => match progress.progress {
                CompileProgress::NeedInput { .. } if consumed == available.len() => {}
                CompileProgress::NeedInput { .. } => return Err(PullFault::Fault(Fault::Budget)),
                CompileProgress::Complete(module) => {
                    reader.session.work_left = reader.meter.work_left;
                    let charges = std::mem::take(&mut reader.meter.module);
                    reader.session.ready = Some((module, charges));
                    return Ok(());
                }
            },
            Err(error) => {
                let compiler_failed = source_fault.is_none();
                let fault = source_fault
                    .unwrap_or_else(|| compile_fault(error, reader.session.unbounded));
                if compiler_failed && matches!(fault, Fault::Syntax) {
                    if let Some(failure) = job.official_failure() {
                        let session = &mut *reader.session;
                        // SAFETY：C reader 已返回，且 Rust 仍持有唯一 session；短借 VM 後才交回 C。
                        let message = unsafe { load_with_vm(state, |vm| {
                            official_diagnostic(vm, &session.chunkname.bytes,
                                &session.source.bytes, failure, session.profile)
                        }) };
                        session.diagnostic = Some(message.map_err(|_| PullFault::Fault(Fault::Memory))?);
                    }
                }
                return Err(PullFault::Fault(fault));
            }
        }
    }
}

#[repr(C)]
pub(crate) struct LoadDrive {
    fault: c_int,
    stopped_class: c_int,
    terminal: c_int,
    yield_attempt: c_int,
}

/// B3 在外層純 C checkpoint 內執行；任何 reader longjmp 都先由 C child 接住。
///
/// # Safety
/// session 與 context 皆屬同一個仍存活的 B3 load action。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_drive_b3(
    state: *mut lua_State, pointer: *mut c_void, context: *mut c_void, mode: *const c_char,
) -> LoadDrive {
    let fault = catch_unwind(AssertUnwindSafe(|| {
        if pointer.is_null() || context.is_null() { return Err(PullFault::Fault(Fault::Budget)); }
        // SAFETY：B3 C action 唯一持有 session，直到 cleanup 才釋放。
        let session = unsafe { &mut *pointer.cast::<LoadSession>() };
        if session.state != state { return Err(PullFault::Fault(Fault::Budget)); }
        drive_reader_load(session, context, mode)
    }));
    match fault {
        Ok(Ok(())) => LoadDrive { fault: 0, stopped_class: 0, terminal: 0, yield_attempt: 0 },
        Ok(Err(PullFault::Fault(fault))) => LoadDrive { fault: fault as c_int, stopped_class: 0, terminal: 0, yield_attempt: 0 },
        Ok(Err(PullFault::ReaderStopped(class))) => LoadDrive { fault: 0, stopped_class: class, terminal: 0, yield_attempt: 0 },
        Ok(Err(PullFault::Terminal)) => LoadDrive { fault: 0, stopped_class: 0, terminal: 1, yield_attempt: 0 },
        Ok(Err(PullFault::ReaderYield)) => LoadDrive { fault: 0, stopped_class: 0, terminal: 0, yield_attempt: 1 },
        Err(_) => LoadDrive { fault: Fault::Budget as c_int, stopped_class: 0, terminal: 0, yield_attempt: 0 },
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
        // SAFETY：state 在同步 C coordinator 期間存活；不保留 group 借用。
        unsafe { load_with_vm(state, |vm| LoadSession::new(state, vm, name, file_style)) }
    })) {
        Ok(Ok(session)) => LoadStart {
            pointer: session.into_raw().cast(),
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

/// C driver 已結束 reader 並恢復原 stack top 後，才發布已準備的 closure。
///
/// # Safety
/// pointer 是本模組 begin 尚未 drop 的 session；mode 為有效 NUL 結尾字串或 NULL。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_finish_b3(
    state: *mut lua_State,
    pointer: *mut c_void,
    _mode: *const c_char,
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
        let (module, charges) = session.ready.take().ok_or(Fault::Budget)?;
        // SAFETY：上一階段 VM 借用已退出；此函式同步發布 module 和 stack root。
        unsafe {
            load_publish_charged(
                state,
                module,
                charges,
                session.limits.max_module_allocation_bytes,
            )
        }
        .map_err(stack_fault)
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
        drop(unsafe { ThinBlock::from_raw(pointer.cast::<LoadSession>()) });
    }
}

/// C checkpoint 把固定或檔案診斷轉為 pending slot；配置失敗由既有 emergency 接手。
///
/// # Safety
/// generation/token 是目前純 C checkpoint；非空 pointer 是該 C action 保活的 session。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_load_error_b3(
    state: *mut lua_State,
    generation: u64,
    token: u64,
    fault: c_int,
    filename: *const c_char,
    reason: *const c_char,
    operation: c_int,
    pointer: *mut c_void,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        let fault = Fault::from_code(fault).ok_or(())?;
        let mut class = if matches!(fault, Fault::Memory) {
            ErrorClass::Allocation
        } else {
            ErrorClass::Lua
        };
        let message = if matches!(fault, Fault::File) {
            let name = if filename.is_null() { b"stdin".as_slice() }
                else { unsafe { CStr::from_ptr(filename) }.to_bytes() };
            let verb = match operation {
                0 => b"cannot open ".as_slice(),
                1 => b"cannot reopen ".as_slice(),
                2 => b"cannot read ".as_slice(),
                _ => return Err(()),
            };
            let constructed = unsafe { load_with_vm(state, |vm| {
                let mut message = ChargedBytes::empty(vm.allocator());
                message.append(vm, verb, usize::MAX)?;
                message.append(vm, name, usize::MAX)?;
                if !reason.is_null() {
                    // SAFETY：C 傳入仍有效的 strerror 靜態字串，立即複製入 message。
                    let reason = unsafe { CStr::from_ptr(reason) }.to_bytes();
                    message.append(vm, b": ", usize::MAX)?;
                    message.append(vm, reason, usize::MAX)?;
                }
                Ok::<_, Fault>(message)
            }) };
            match constructed {
                Ok(message) => Some(message),
                Err(_) => {
                    class = ErrorClass::Allocation;
                    None
                }
            }
        } else {
            None
        };
        let session_message = if matches!(fault, Fault::Syntax) && !pointer.is_null() {
            // SAFETY：C action 持有 session 到 error 發布完成，Rust 在此只短借診斷 bytes。
            let session = unsafe { &*pointer.cast::<LoadSession>() };
            if session.state != state { return Err(()); }
            session.diagnostic.as_ref().map(|message| message.bytes.as_slice())
        } else { None };
        let bytes = message.as_ref().map(|message| message.bytes.as_slice())
            .or(session_message)
            .unwrap_or_else(|| if class == ErrorClass::Allocation {
                Fault::Memory.message()
            } else { fault.message() });
        // SAFETY：C driver 的活躍 checkpoint token 與 state 由 C frame 保證。
        unsafe {
            load_prepare_error(
                Checkpoint {
                    state,
                    generation,
                    token,
                },
                bytes,
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

#[cfg(feature = "lua55")]
struct DumpSession {
    bytes: CapiDumpBytes,
    _owner: HostAllocationCharge,
}

#[repr(C)]
#[cfg(feature = "lua55")]
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
#[cfg(feature = "lua55")]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump_begin_b3(
    state: *mut lua_State,
    strip: c_int,
) -> DumpStart {
    match catch_unwind(AssertUnwindSafe(|| -> Result<ThinBlock<DumpSession>, Fault> {
        // SAFETY：C driver 保活 state；dump_top_bytes 返回前釋放 VM 借用。
        let bytes = unsafe { dump_top_bytes(state, strip != 0) }.map_err(stack_fault)?;
        // SAFETY：C caller 保活 state；session 實體 backing 與帳款同時建立。
        unsafe {
            load_with_vm(state, |vm| {
                let (storage, owner) = vm
                    .capi_reserve_host_thin::<DumpSession>()
                    .map_err(StackError::from)?;
                let owner = owner.commit().map_err(StackError::from)?;
                Ok(storage.write(DumpSession {
                    bytes,
                    _owner: owner,
                }))
            })
        }
        .map_err(stack_fault)
    })) {
        Ok(Ok(session)) => {
            let data = session.bytes.as_bytes().as_ptr().cast();
            let len = session.bytes.as_bytes().len();
            DumpStart {
                pointer: session.into_raw().cast(),
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
#[cfg(feature = "lua55")]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump_drop_b3(pointer: *mut c_void) {
    if !pointer.is_null() {
        // SAFETY：C driver 唯一持有且只呼叫一次。
        drop(unsafe { ThinBlock::from_raw(pointer.cast::<DumpSession>()) });
    }
}

#[cfg(feature = "lua54")]
const DUMP54_STORAGE_BYTES: usize = 256;

#[cfg(feature = "lua54")]
const _: () = {
    assert!(size_of::<CapiDump54Lease>() <= DUMP54_STORAGE_BYTES);
    assert!(align_of::<CapiDump54Lease>() <= align_of::<u64>());
};

#[repr(C)]
#[cfg(feature = "lua54")]
pub(crate) struct Dump54Next {
    data: *const c_void,
    len: usize,
    inline: [u8; 16],
    fault: c_int,
    done: c_int,
}

/// C stack 對齊的固定大小 storage 只在成功時初始化一次，無 VM 配置。
///
/// # Safety
/// `storage` 至少 256 bytes 且對齊 u64，成功後由同一 C frame 唯一釋放。
#[unsafe(no_mangle)]
#[cfg(feature = "lua54")]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump54_prepare_b3(
    state: *mut lua_State,
    strip: c_int,
    storage: *mut c_void,
) -> c_int {
    if storage.is_null() {
        return Fault::Budget as c_int;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C frame 保活 state；storage 由固定對齊 union 提供。
        let lease = unsafe { dump_top54_lease(state, strip != 0) }.map_err(stack_fault)?;
        unsafe { storage.cast::<CapiDump54Lease>().write(lease) };
        Ok::<_, Fault>(())
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(fault)) => fault as c_int,
        Err(_) => Fault::Budget as c_int,
    }
}

/// 每次只借用 lease 至返回 POD；C writer 執行時沒有 Rust 借用。
///
/// # Safety
/// `storage` 是 prepare 成功且尚未 drop 的同一 C frame storage。
#[unsafe(no_mangle)]
#[cfg(feature = "lua54")]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump54_next_b3(
    storage: *mut c_void,
) -> Dump54Next {
    let failure = |fault: Fault| Dump54Next {
        data: ptr::null(), len: 0, inline: [0; 16], fault: fault as c_int, done: 0,
    };
    if storage.is_null() {
        return failure(Fault::Budget);
    }
    match catch_unwind(AssertUnwindSafe(|| -> Result<Dump54Next, Fault> {
        let lease = unsafe { &mut *storage.cast::<CapiDump54Lease>() };
        let piece = lease.next_piece().map_err(|error| stack_fault(error.into()))?;
        Ok(match piece {
            Some(rivetlua_core::Dump54Piece::Borrowed(bytes)) => Dump54Next {
                data: bytes.as_ptr().cast(), len: bytes.len(), inline: [0; 16],
                fault: 0, done: 0,
            },
            Some(rivetlua_core::Dump54Piece::Inline { bytes, len }) => Dump54Next {
                data: ptr::null(), len: usize::from(len), inline: bytes,
                fault: 0, done: 0,
            },
            None => Dump54Next {
                data: ptr::null(), len: 0, inline: [0; 16], fault: 0, done: 1,
            },
        })
    })) {
        Ok(Ok(piece)) => piece,
        Ok(Err(fault)) => failure(fault),
        Err(_) => failure(Fault::Budget),
    }
}

/// C frame 包括 writer 提早終止或錯誤退出，皆恰好呼叫一次。
///
/// # Safety
/// `storage` 是 prepare 成功且尚未 drop 的同一 C frame storage。
#[unsafe(no_mangle)]
#[cfg(feature = "lua54")]
pub(crate) unsafe extern "C" fn rivetlua_capi_dump54_drop_b3(storage: *mut c_void) {
    if !storage.is_null() {
        unsafe { ptr::drop_in_place(storage.cast::<CapiDump54Lease>()) };
    }
}
