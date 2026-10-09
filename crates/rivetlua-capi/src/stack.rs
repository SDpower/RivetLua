//! P16-2：C state 控制區、前置 extraspace、有根 stack overlay 與 byte string view。

use std::alloc::Layout;
use std::any::Any;
use std::cell::{Cell, RefCell};
use std::ffi::c_uint;
use std::ffi::{CStr, c_char, c_int, c_short, c_void};
use std::mem::{align_of, offset_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, ThreadId};

use rivetlua_core::{
    BinaryOperation, HostFunctionId, LuaProfile, ObjectRef, RVLU_V2, ResultMode, UnaryOperation,
    Value, VerifiedModule, VmId,
};
#[cfg(feature = "lua55")]
use rivetlua_runtime::ExternalStringStorage;
use rivetlua_runtime::{
    AllocationCharges, AllocationFailureKind, CapiDumpBytes, CoroutineState, DebugFrameHandle,
    DebugFrameInfo, DebugFrameKind, DebugHookConfig, ExternalCommand, ExternalToken, FailPoint,
    GcControl, GcControlResult, HostAllocationCharge, HostAllocationReservation, HostHandle,
    ObjectKind, RootId, RootKind, RunOutcome, RuntimeError, RuntimeErrorKind, ValueOperation, Vm,
    VmError,
};

use crate::allocator::{CAllocatorState, LuaAlloc};
use crate::error::{ErrorClass, Reject, codes};
use crate::trampoline::Checkpoint;

unsafe extern "C" {
    fn strerror(errnum: c_int) -> *mut c_char;
    fn rivetlua_capi_default_warning_install_b6(pointer: *mut lua_State);
    fn rivetlua_capi_default_panic_install_a2(pointer: *mut lua_State);
    #[link_name = "lua_compare"]
    fn c_lua_compare(pointer: *mut lua_State, left: c_int, right: c_int, operation: c_int)
    -> c_int;
    #[link_name = "luaL_len"]
    fn c_lual_len(pointer: *mut lua_State, index: c_int) -> i64;
    fn rivetlua_capi_requiref_protected_b2(
        pointer: *mut lua_State,
        name: *const c_char,
        opener: LuaCFunction,
        global: c_int,
    ) -> c_int;
    fn rivetlua_capi_close_status_b2(pointer: *mut lua_State) -> c_int;
}

/// 此型別只供 ABI 指標使用；C 端固定 header 也不揭露其內容。
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct lua_State {
    _opaque: [u8; 0],
}

/// 固定 Lua 5.4.9 header 的公開 ABI；`i_ci` 僅是 state-owned token，絕不解參照。
#[cfg(feature = "lua54")]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct lua_Debug {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    istailcall: c_char,
    ftransfer: u16,
    ntransfer: u16,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

/// 固定 Lua 5.5.1 header 的公開 ABI；`extraargs` 與 transfer 寬度須保持此佈局。
#[cfg(feature = "lua55")]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct lua_Debug {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    extraargs: u8,
    istailcall: c_char,
    ftransfer: c_int,
    ntransfer: c_int,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

/// 此型別僅供固定 lauxlib ABI 指標使用，不暴露 C union 內容。
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct luaL_Buffer {
    _opaque: [u8; 0],
}

#[repr(C)]
struct LuaLBufferPrefix {
    b: *mut c_char,
    size: usize,
    n: usize,
    state: *mut lua_State,
}

#[cfg(all(feature = "lua55", target_os = "linux"))]
const LUAL_BUFFER_ALIGN: usize = 16;
#[cfg(not(all(feature = "lua55", target_os = "linux")))]
const LUAL_BUFFER_ALIGN: usize = 8;

#[derive(Clone, Copy)]
struct BufferSnapshot {
    b: *mut u8,
    size: usize,
    n: usize,
    state: *mut lua_State,
    init: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TolstringFallbackB5 {
    kind: c_int,
    pointer: *const c_char,
    length: usize,
}

impl TolstringFallbackB5 {
    fn error() -> Self {
        Self {
            kind: -1,
            pointer: std::ptr::null(),
            length: 0,
        }
    }

    fn success(pointer: *const c_char, length: usize) -> Self {
        Self {
            kind: 1,
            pointer,
            length,
        }
    }

    fn failed(error: StackError) -> Self {
        Self {
            kind: -operation_error_class_b5(error),
            pointer: std::ptr::null(),
            length: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BufferFailure {
    TooLarge,
    Stack(StackError),
}

impl From<StackError> for BufferFailure {
    fn from(error: StackError) -> Self {
        Self::Stack(error)
    }
}

/// # Safety
/// buffer 必須指向有效期內的完整固定 header luaL_Buffer；已初始化欄位可讀。
unsafe fn buffer_snapshot(buffer: *mut luaL_Buffer) -> Result<BufferSnapshot, StackError> {
    if buffer.is_null() || (buffer as usize) % LUAL_BUFFER_ALIGN != 0 {
        return Err(StackError::Layout);
    }
    // SAFETY：呼叫者保證完整、對齊且已初始化；只複製固定 32-byte 前綴。
    let prefix = unsafe { buffer.cast::<LuaLBufferPrefix>().read() };
    // SAFETY：固定 header 的 init 緊接四欄前綴；指標只作位址計算。
    let init = unsafe { buffer.cast::<u8>().add(size_of::<LuaLBufferPrefix>()) };
    Ok(BufferSnapshot {
        b: prefix.b.cast(),
        size: prefix.size,
        n: prefix.n,
        state: prefix.state,
        init,
    })
}

const EXTRASPACE: usize = size_of::<*mut c_void>();
const LUAL_BUFFERSIZE: usize = match 16usize.checked_mul(size_of::<*mut c_void>()) {
    Some(pointer_bytes) => match pointer_bytes.checked_mul(size_of::<f64>()) {
        Some(size) => size,
        None => panic!("固定 Lua 緩衝區大小溢位"),
    },
    None => panic!("固定 Lua 緩衝區大小溢位"),
};
const _: () = {
    assert!(offset_of!(LuaLBufferPrefix, b) == 0);
    assert!(offset_of!(LuaLBufferPrefix, size) == size_of::<usize>());
    assert!(offset_of!(LuaLBufferPrefix, n) == 2 * size_of::<usize>());
    assert!(offset_of!(LuaLBufferPrefix, state) == 3 * size_of::<usize>());
    assert!(size_of::<LuaLBufferPrefix>() == 4 * size_of::<usize>());
    assert!(size_of::<LuaLBufferPrefix>() % align_of::<LuaLBufferPrefix>() == 0);
};
const MIN_STACK: usize = 20;
const MAX_STACK: usize = 1_000_000;
#[cfg(feature = "lua55")]
const NUMBER_BUFFER: usize = 64;
const LIVE_MAGIC: u64 = 0x5256_4c43_5354_4154;
static NEXT_STATE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: c_int = -(c_int::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: c_int = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_PROFILE_REGISTRY_INDEX: c_int = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_PROFILE_REGISTRY_INDEX: c_int = -(c_int::MAX / 2 + 1000);

const LUA_TNONE: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TBOOLEAN: c_int = 1;
const LUA_TLIGHTUSERDATA: c_int = 2;
const LUA_TNUMBER: c_int = 3;
const LUA_TSTRING: c_int = 4;
const LUA_TTABLE: c_int = 5;
const LUA_TFUNCTION: c_int = 6;
const LUA_TUSERDATA: c_int = 7;
const LUA_TTHREAD: c_int = 8;
const LUA_RIDX_GLOBALS: i64 = 2;
#[cfg(feature = "lua54")]
const LUA_RIDX_MAINTHREAD: i64 = 1;
#[cfg(feature = "lua55")]
const LUA_RIDX_MAINTHREAD: i64 = 3;
const LUA_NOREF: c_int = -2;
const LUA_REFNIL: c_int = -1;
type LuaCFunction = unsafe extern "C" fn(*mut lua_State) -> c_int;
type LuaKFunction = unsafe extern "C" fn(*mut lua_State, c_int, isize) -> c_int;
type LuaHook = unsafe extern "C" fn(*mut lua_State, *mut lua_Debug);

#[derive(Clone, Copy)]
struct HookBinding {
    callback: Option<LuaHook>,
    mask: c_int,
    count: c_int,
}

impl HookBinding {
    const fn disabled() -> Self {
        Self {
            callback: None,
            mask: 0,
            count: 0,
        }
    }
}
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct luaL_Reg {
    pub name: *const c_char,
    pub func: Option<LuaCFunction>,
}
const _: () = {
    assert!(size_of::<luaL_Reg>() == 2 * size_of::<*const c_void>());
    assert!(offset_of!(luaL_Reg, name) == 0);
    assert!(offset_of!(luaL_Reg, func) == size_of::<*const c_void>());
};
const EMPTY_UPVALUE_NAME: &[u8; 1] = b"\0";
const MEMORY_ERROR_BYTES: &[u8] = b"not enough memory";
const FIRST_REGISTRY_REF: i64 = 4;
#[cfg(feature = "lua55")]
const REF_FREELIST_KEY: i64 = 1;
#[cfg(feature = "lua54")]
const REF_FREELIST_KEY: i64 = LUA_RIDX_GLOBALS + 1;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StackError {
    InvalidState,
    Busy,
    InvalidIndex,
    PseudoIndexUnavailable,
    StackLimit,
    WrongVm,
    Layout,
    Runtime(VmError),
    Number(RuntimeError),
}

impl From<VmError> for StackError {
    fn from(error: VmError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RuntimeError> for StackError {
    fn from(error: RuntimeError) -> Self {
        Self::Number(error)
    }
}

struct StringView {
    bytes: Vec<u8>,
    len: usize,
    _base: HostAllocationCharge,
    _extra: Option<HostAllocationCharge>,
    _owner: HostAllocationCharge,
}

#[derive(Clone)]
enum SlotStringView {
    Owned(Rc<StringView>),
    External { pointer: *const c_char, len: usize },
}

impl SlotStringView {
    fn pointer_len(&self) -> (*const c_char, usize) {
        match self {
            Self::Owned(view) => (view.as_ptr(), view.len),
            Self::External { pointer, len } => (*pointer, *len),
        }
    }
}

#[cfg(feature = "lua55")]
struct ExternalStringOwner {
    pointer: *const c_char,
    len: usize,
    falloc: Option<LuaAlloc>,
    ud: *mut c_void,
    _charge: Option<HostAllocationCharge>,
}

#[cfg(feature = "lua55")]
impl ExternalStringStorage for ExternalStringOwner {
    fn bytes(&self) -> &[u8] {
        // SAFETY：有效 API 輸入在 owner 存活期間保證 len+1 bytes 不變；
        // 最後一個 Rc 釋放前不呼叫 falloc，借用不會超過 owner 生命週期。
        unsafe { std::slice::from_raw_parts(self.pointer.cast::<u8>(), self.len) }
    }

    fn nul_terminated_bytes(&self) -> Option<&[u8]> {
        // SAFETY：C 呼叫者保證有效的 len+1 bytes 與尾端 NUL；owner 在 callback 前
        // 保持該配置存活，並在最後借用結束後才由 Rc Drop 釋放。
        Some(unsafe { std::slice::from_raw_parts(self.pointer.cast::<u8>(), self.len + 1) })
    }
}

#[cfg(feature = "lua55")]
impl Drop for ExternalStringOwner {
    fn drop(&mut self) {
        if let Some(falloc) = self.falloc {
            // SAFETY：建立時保存原 falloc/ud；有效輸入保證 pointer 與 len+1；
            // Lua allocator 契約要求 callback 正常返回，不可跨 Rust frame longjmp。
            let _ = unsafe { falloc(self.ud, self.pointer.cast_mut().cast(), self.len + 1, 0) };
        }
    }
}

impl StringView {
    fn new(vm: &Vm, source: &[u8]) -> Result<Rc<Self>, StackError> {
        Self::new_parts(vm, &[source])
    }

    /// 先預備所有可計費容量，才短暫借讀 C／userdata bytes；不跨配置或 GC 保留 raw slice。
    unsafe fn new_raw(vm: &Vm, source: *const u8, len: usize) -> Result<Rc<Self>, StackError> {
        if source.is_null() && len != 0 {
            return Err(StackError::InvalidIndex);
        }
        Self::new_filled(vm, len, |bytes, _| {
            if len != 0 {
                // SAFETY：呼叫者保證來源在同步複製期間有效；容量已預留，extend 不配置。
                let source = unsafe { std::slice::from_raw_parts(source, len) };
                bytes.extend_from_slice(source);
            }
            Ok(())
        })
    }

    fn new_parts(vm: &Vm, parts: &[&[u8]]) -> Result<Rc<Self>, StackError> {
        let len = parts.iter().try_fold(0usize, |len, part| {
            len.checked_add(part.len()).ok_or(StackError::StackLimit)
        })?;
        Self::new_filled(vm, len, |bytes, limit| {
            for part in parts {
                append_view_bytes(bytes, limit, part)?;
            }
            Ok(())
        })
    }

    fn new_gsub(
        vm: &Vm,
        source: &[u8],
        pattern: &[u8],
        replacement: &[u8],
        len: usize,
    ) -> Result<Rc<Self>, StackError> {
        Self::new_filled(vm, len, |bytes, limit| {
            let mut cursor = 0;
            while let Some(start) = find_gsub_match(source, pattern, cursor) {
                append_view_bytes(bytes, limit, &source[cursor..start])?;
                append_view_bytes(bytes, limit, replacement)?;
                cursor = start
                    .checked_add(pattern.len())
                    .ok_or(StackError::StackLimit)?;
            }
            append_view_bytes(bytes, limit, &source[cursor..])
        })
    }

    fn new_filled(
        vm: &Vm,
        len: usize,
        fill: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), StackError>,
    ) -> Result<Rc<Self>, StackError> {
        let required = len.checked_add(1).ok_or(StackError::StackLimit)?;
        let base_ticket = vm.reserve_host_allocation(required)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(required)
            .map_err(|_| StackError::Runtime(base_ticket.rust_reserve_failure()))?;
        fill(&mut bytes, len)?;
        if bytes.len() != len {
            return Err(StackError::Layout);
        }
        bytes.push(0);
        let extra_bytes = bytes
            .capacity()
            .checked_sub(required)
            .ok_or(StackError::Layout)?;
        let extra_ticket = if extra_bytes == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra_bytes)?)
        };
        let header = Layout::array::<Cell<usize>>(2).map_err(|_| StackError::StackLimit)?;
        let (combined, _) = header
            .extend(Layout::new::<StringView>())
            .map_err(|_| StackError::StackLimit)?;
        let owner_ticket = vm.reserve_host_allocation(combined.pad_to_align().size())?;
        let extra = extra_ticket.map(|ticket| ticket.commit()).transpose()?;
        let base = base_ticket.commit()?;
        let owner = owner_ticket.commit()?;
        Ok(Rc::new(Self {
            bytes,
            len,
            _base: base,
            _extra: extra,
            _owner: owner,
        }))
    }

    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast::<c_char>()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn append_view_bytes(bytes: &mut Vec<u8>, limit: usize, part: &[u8]) -> Result<(), StackError> {
    let next_len = bytes
        .len()
        .checked_add(part.len())
        .ok_or(StackError::StackLimit)?;
    if next_len > limit {
        return Err(StackError::Layout);
    }
    bytes.extend_from_slice(part);
    Ok(())
}

fn find_gsub_match(source: &[u8], pattern: &[u8], cursor: usize) -> Option<usize> {
    if pattern.is_empty() {
        return None;
    }
    source
        .get(cursor..)?
        .windows(pattern.len())
        .position(|window| window == pattern)
        .and_then(|offset| cursor.checked_add(offset))
}

fn checked_gsub_output_len(
    source: &[u8],
    pattern: &[u8],
    replacement: &[u8],
) -> Result<usize, StackError> {
    if pattern.is_empty() {
        return Err(StackError::InvalidIndex);
    }
    let mut output_len = 0usize;
    let mut cursor = 0usize;
    while let Some(start) = find_gsub_match(source, pattern, cursor) {
        output_len = output_len
            .checked_add(start.checked_sub(cursor).ok_or(StackError::Layout)?)
            .and_then(|len| len.checked_add(replacement.len()))
            .ok_or(StackError::StackLimit)?;
        cursor = start
            .checked_add(pattern.len())
            .ok_or(StackError::StackLimit)?;
    }
    output_len
        .checked_add(source.len().checked_sub(cursor).ok_or(StackError::Layout)?)
        .ok_or(StackError::StackLimit)
}

#[derive(Clone, Copy)]
enum StackValue {
    Core(Value),
}

struct StackSlot {
    value: StackValue,
    // HostHandle 的 lease 在 slot drop 時退根；VM 可以先於 handle drop。
    root: Option<HostHandle<Value>>,
    // Rc 複製不重新配置 C view；不可變 Vec buffer 不隨 stack/heap 移動。
    string_view: Option<SlotStringView>,
}

struct PendingError {
    slot: StackSlot,
    class: ErrorClass,
    token: u64,
    original_top: usize,
}

impl StackSlot {
    fn new(vm: &mut Vm, value: StackValue) -> Result<Self, StackError> {
        if let StackValue::Core(Value::CFunction(id)) = value {
            if id.vm() != vm.id() {
                return Err(StackError::WrongVm);
            }
        }
        let root = match value {
            StackValue::Core(Value::Object(object)) => Some(HostHandle::new(vm, object)?),
            _ => None,
        };
        let string_view = match value {
            StackValue::Core(Value::Object(object))
                if vm.object_kind(object)? == ObjectKind::ByteString =>
            {
                vm.with_byte_string(object, |string| {
                    string
                        .external_pointer()
                        .map(|(pointer, len)| SlotStringView::External {
                            pointer: pointer.cast(),
                            len,
                        })
                })?
            }
            _ => None,
        };
        Ok(Self {
            value,
            root,
            string_view,
        })
    }

    fn checked_value(&self, vm: &Vm) -> Result<StackValue, StackError> {
        if let Some(root) = &self.root {
            root.as_value(vm)?;
        } else if let StackValue::Core(Value::Object(object)) = self.value {
            // 永久 Registry root 的 emergency slot 不另建 HostHandle；仍驗物件世代。
            vm.object_kind(object)?;
        }
        Ok(self.value)
    }

    fn permanent_rooted(
        vm: &Vm,
        object: ObjectRef,
        view: Rc<StringView>,
    ) -> Result<Self, StackError> {
        if vm.object_kind(object)? != ObjectKind::ByteString {
            return Err(StackError::Layout);
        }
        Ok(Self {
            value: StackValue::Core(Value::Object(object)),
            root: None,
            string_view: Some(SlotStringView::Owned(view)),
        })
    }

    fn try_clone(&self, vm: &mut Vm) -> Result<Self, StackError> {
        let value = self.checked_value(vm)?;
        let mut cloned = Self::new(vm, value)?;
        cloned.string_view = self.string_view.clone();
        Ok(cloned)
    }
}

#[derive(Clone, Copy)]
struct HostFunctionEntry {
    id: HostFunctionId,
    function: LuaCFunction,
}

struct HostFunctionRegistry {
    entries: Vec<HostFunctionEntry>,
    charge: Option<StackCapacityCharge>,
}

struct PreparedHostFunctionCapacity {
    entries: Vec<HostFunctionEntry>,
    charge: StackCapacityCharge,
}

impl HostFunctionRegistry {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            charge: None,
        }
    }

    fn find_function(&self, function: LuaCFunction) -> Option<HostFunctionId> {
        self.entries
            .iter()
            .find(|entry| std::ptr::fn_addr_eq(entry.function, function))
            .map(|entry| entry.id)
    }

    fn get(&self, id: HostFunctionId) -> Option<LuaCFunction> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.function)
    }

    fn prepare_capacity(
        &self,
        vm: &Vm,
    ) -> Result<Option<PreparedHostFunctionCapacity>, StackError> {
        if self.entries.len() < self.entries.capacity() {
            return Ok(None);
        }
        let capacity = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let base_bytes = capacity
            .checked_mul(size_of::<HostFunctionEntry>())
            .ok_or(StackError::StackLimit)?;
        let base_ticket = vm.reserve_host_allocation(base_bytes)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(base_ticket.rust_reserve_failure()))?;
        let actual_bytes = replacement
            .capacity()
            .checked_mul(size_of::<HostFunctionEntry>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual_bytes
            .checked_sub(base_bytes)
            .ok_or(StackError::Layout)?;
        let extra_ticket = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?)
        };
        let extra_charge = extra_ticket.map(|ticket| ticket.commit()).transpose()?;
        let base_charge = base_ticket.commit()?;
        Ok(Some(PreparedHostFunctionCapacity {
            entries: replacement,
            charge: StackCapacityCharge {
                _base: base_charge,
                _extra: extra_charge,
            },
        }))
    }

    fn publish(
        &mut self,
        prepared: Option<PreparedHostFunctionCapacity>,
        entry: HostFunctionEntry,
    ) {
        if let Some(mut prepared) = prepared {
            prepared.entries.append(&mut self.entries);
            self.entries = prepared.entries;
            self.charge = Some(prepared.charge);
        }
        self.entries.push(entry);
    }
}

struct StackCapacityCharge {
    _base: HostAllocationCharge,
    _extra: Option<HostAllocationCharge>,
}

struct NativeLeaseEntry {
    // 欄位順序使 library lease 先於其 retained 帳本費用釋放。
    _lease: Rc<dyn Any>,
    _retained_charge: HostAllocationCharge,
}

struct NativeLeases {
    entries: Vec<NativeLeaseEntry>,
    capacity_charge: Option<StackCapacityCharge>,
}

struct PreparedNativeLeaseCapacity {
    entries: Vec<NativeLeaseEntry>,
    charge: StackCapacityCharge,
}

impl NativeLeases {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            capacity_charge: None,
        }
    }

    fn prepare_capacity(&self, vm: &Vm) -> Result<Option<PreparedNativeLeaseCapacity>, StackError> {
        if self.entries.len() < self.entries.capacity() {
            return Ok(None);
        }
        let capacity = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let base_bytes = capacity
            .checked_mul(size_of::<NativeLeaseEntry>())
            .ok_or(StackError::StackLimit)?;
        let base_ticket = vm.reserve_host_allocation(base_bytes)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(base_ticket.rust_reserve_failure()))?;
        let actual_bytes = replacement
            .capacity()
            .checked_mul(size_of::<NativeLeaseEntry>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual_bytes
            .checked_sub(base_bytes)
            .ok_or(StackError::Layout)?;
        let extra_charge = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?.commit()?)
        };
        let base_charge = base_ticket.commit()?;
        Ok(Some(PreparedNativeLeaseCapacity {
            entries: replacement,
            charge: StackCapacityCharge {
                _base: base_charge,
                _extra: extra_charge,
            },
        }))
    }

    fn publish(&mut self, prepared: Option<PreparedNativeLeaseCapacity>, entry: NativeLeaseEntry) {
        if let Some(mut prepared) = prepared {
            prepared.entries.append(&mut self.entries);
            self.entries = prepared.entries;
            self.capacity_charge = Some(prepared.charge);
        }
        self.entries.push(entry);
    }
}

impl Drop for NativeLeases {
    fn drop(&mut self) {
        // provider 先發布、dependent 後發布；卸載順序必須相反。
        while let Some(entry) = self.entries.pop() {
            drop(entry);
        }
    }
}

/// dlopen 前的同 VM 配置票據；不持有 VM 或 StateGroup 的借用。
#[must_use]
pub struct NativeLeaseReservation {
    state: Weak<StateAllocation>,
    group: Weak<RefCell<StateGroup>>,
    state_generation: u64,
    group_generation: u64,
    entry_count: usize,
    retained: Option<HostAllocationReservation>,
    prepared: Option<PreparedNativeLeaseCapacity>,
}

impl NativeLeaseReservation {
    /// 成功載入後才發布；失敗時票據與 lease 一起釋放，原集合不變。
    pub fn publish(mut self, lease: Rc<dyn Any>) -> Result<(), StackError> {
        let state = self.state.upgrade().ok_or(StackError::InvalidState)?;
        state.control.validate()?;
        if state.control.state_generation != self.state_generation
            || state.control.group_generation != self.group_generation
        {
            return Err(StackError::InvalidState);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let current_group = state
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        if !Rc::ptr_eq(&group_owner, &current_group) {
            return Err(StackError::WrongVm);
        }
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if group.generation != self.group_generation
            || group.native_leases.entries.len() != self.entry_count
        {
            return Err(StackError::Busy);
        }
        let available = self
            .prepared
            .as_ref()
            .map_or(group.native_leases.entries.capacity(), |prepared| {
                prepared.entries.capacity()
            });
        if available <= self.entry_count {
            return Err(StackError::Busy);
        }
        let retained_charge = self
            .retained
            .take()
            .ok_or(StackError::InvalidState)?
            .commit()?;
        group.native_leases.publish(
            self.prepared.take(),
            NativeLeaseEntry {
                _lease: lease,
                _retained_charge: retained_charge,
            },
        );
        Ok(())
    }
}

struct PreparedStackCapacity {
    slots: Vec<StackSlot>,
    charge: StackCapacityCharge,
}

struct PreparedCloseMarkCapacity {
    positions: Vec<usize>,
    charge: StackCapacityCharge,
}

enum StackCapacityPlan {
    Deferred(usize),
    Prepared(Option<PreparedStackCapacity>),
}

struct StackStorage {
    slots: Vec<StackSlot>,
    charge: Option<StackCapacityCharge>,
    // Lua to-be-closed 標記屬於 stack 位置，不能隨 StackSlot 的值移動。
    close_marks: Vec<usize>,
    close_mark_charge: Option<StackCapacityCharge>,
}

impl StackStorage {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            charge: None,
            close_marks: Vec::new(),
            close_mark_charge: None,
        }
    }

    fn highest_close_mark(&self) -> Option<usize> {
        self.close_marks.last().copied()
    }

    fn prepare_close_mark_capacity(
        &self,
        vm: &Vm,
        required: usize,
    ) -> Result<Option<PreparedCloseMarkCapacity>, StackError> {
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        if required <= self.close_marks.capacity() {
            return Ok(None);
        }
        let capacity = required.max(self.close_marks.capacity().saturating_mul(2));
        let bytes = capacity
            .checked_mul(size_of::<usize>())
            .ok_or(StackError::StackLimit)?;
        let base_ticket = vm.reserve_host_allocation(bytes)?;
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(base_ticket.rust_reserve_failure()))?;
        let actual = positions
            .capacity()
            .checked_mul(size_of::<usize>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
        let extra_ticket = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?)
        };
        let extra_charge = extra_ticket.map(|ticket| ticket.commit()).transpose()?;
        let base_charge = base_ticket.commit()?;
        Ok(Some(PreparedCloseMarkCapacity {
            positions,
            charge: StackCapacityCharge {
                _base: base_charge,
                _extra: extra_charge,
            },
        }))
    }

    fn publish_close_mark(&mut self, prepared: Option<PreparedCloseMarkCapacity>, position: usize) {
        self.commit_close_mark_capacity(prepared);
        self.close_marks.push(position);
    }

    fn commit_close_mark_capacity(&mut self, prepared: Option<PreparedCloseMarkCapacity>) {
        if let Some(mut prepared) = prepared {
            prepared.positions.append(&mut self.close_marks);
            self.close_marks = prepared.positions;
            self.close_mark_charge = Some(prepared.charge);
        }
    }

    fn can_remove_from(&self, start: usize) -> bool {
        self.highest_close_mark().is_none_or(|mark| mark < start)
    }

    fn pop_close_mark(&mut self) -> Option<usize> {
        let mark = self.close_marks.pop();
        if self.close_marks.is_empty() {
            self.close_marks = Vec::new();
            self.close_mark_charge = None;
        }
        mark
    }

    fn prepare_capacity(
        &self,
        vm: &Vm,
        required: usize,
    ) -> Result<Option<PreparedStackCapacity>, StackError> {
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        if required <= self.slots.capacity()
            && !(required == MAX_STACK && self.slots.capacity() == MAX_STACK)
        {
            return Ok(None);
        }
        let logical_capacity = required
            .max(self.slots.capacity().saturating_mul(2))
            .max(MIN_STACK)
            .min(MAX_STACK);
        // 正常可見 top 仍受 MAX_STACK 限制；到達上限時，額外一格只供
        // 已存在的 C checkpoint 在錯誤 unwind 前暫存 pending error。
        let capacity = logical_capacity
            .checked_add(usize::from(logical_capacity == MAX_STACK))
            .ok_or(StackError::StackLimit)?;
        let base_bytes = capacity
            .checked_mul(size_of::<StackSlot>())
            .ok_or(StackError::StackLimit)?;
        let base_ticket = vm.reserve_host_allocation(base_bytes)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(base_ticket.rust_reserve_failure()))?;
        let actual_bytes = replacement
            .capacity()
            .checked_mul(size_of::<StackSlot>())
            .ok_or(StackError::StackLimit)?;
        let extra_bytes = actual_bytes
            .checked_sub(base_bytes)
            .ok_or(StackError::Layout)?;
        let extra_ticket = if extra_bytes == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra_bytes)?)
        };
        let extra = extra_ticket.map(|ticket| ticket.commit()).transpose()?;
        let base = base_ticket.commit()?;
        Ok(Some(PreparedStackCapacity {
            slots: replacement,
            charge: StackCapacityCharge {
                _base: base,
                _extra: extra,
            },
        }))
    }

    fn commit_capacity(&mut self, prepared: Option<PreparedStackCapacity>) {
        if let Some(mut prepared) = prepared {
            // 容量與帳款均已預備；發布後只移交既有 slots，不再配置。
            prepared.slots.append(&mut self.slots);
            self.slots = prepared.slots;
            self.charge = Some(prepared.charge);
        }
    }

    fn ensure_capacity(&mut self, vm: &Vm, required: usize) -> Result<(), StackError> {
        let prepared = self.prepare_capacity(vm, required)?;
        self.commit_capacity(prepared);
        Ok(())
    }

    fn release_empty_capacity(&mut self) {
        if self.slots.is_empty() {
            self.slots = Vec::new();
            self.charge = None;
        }
    }
}

struct StateGroup {
    vm: Vm,
    allocator: Rc<CAllocatorState>,
    registry_value: StackValue,
    registry_root: Option<RootId>,
    main_thread: ObjectRef,
    _main_thread_root: RootId,
    main_pointer: Rc<Cell<*mut lua_State>>,
    main_allocation: Weak<StateAllocation>,
    hook_bridge: ObjectRef,
    hook_bridge_id: HostFunctionId,
    _hook_bridge_root: RootId,
    emergency_error: ObjectRef,
    _emergency_root: RootId,
    emergency_view: Rc<StringView>,
    generation: u64,
    functions: HostFunctionRegistry,
    callback_frames: CallbackFrames,
    warning: WarningBindingB6,
    panic_callback: Option<LuaCFunction>,
    _charge: HostAllocationCharge,
    native_leases: NativeLeases,
}

impl StateGroup {
    fn registry_table(&self) -> Result<ObjectRef, StackError> {
        let StackValue::Core(Value::Object(table)) = self.registry_value else {
            return Err(StackError::InvalidIndex);
        };
        if self.vm.object_kind(table)? != ObjectKind::Table {
            return Err(StackError::InvalidIndex);
        }
        Ok(table)
    }

    fn registry_object(&self) -> Option<ObjectRef> {
        let StackValue::Core(Value::Object(object)) = self.registry_value else {
            return None;
        };
        Some(object)
    }

    fn replace_registry(&mut self, value: StackValue) -> Result<(), StackError> {
        if matches!(
            (self.registry_value, value),
            (StackValue::Core(Value::Object(old)), StackValue::Core(Value::Object(new))) if old == new
        ) {
            return Ok(());
        }
        let new_root = match value {
            StackValue::Core(Value::Object(object)) => {
                Some(self.vm.add_root(RootKind::Registry, object)?)
            }
            _ => None,
        };
        if let Some(old_root) = self.registry_root {
            if let Err(error) = self.vm.remove_root(old_root) {
                if let Some(root) = new_root {
                    self.vm.remove_root(root)?;
                }
                return Err(error.into());
            }
        }
        self.registry_value = value;
        self.registry_root = new_root;
        Ok(())
    }
}

type LuaWarnFunction = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct WarningBindingB6 {
    callback: Option<LuaWarnFunction>,
    ud: *mut c_void,
}

impl WarningBindingB6 {
    const fn disabled() -> Self {
        Self {
            callback: None,
            ud: std::ptr::null_mut(),
        }
    }
}

struct CallbackFrame {
    token: ExternalToken,
    depth: usize,
    owner_generation: u64,
    call_base: usize,
    saved_stack: StackStorage,
}

// call_base 是實際 stack index；最高位在可配置 stack 範圍外，借作 B11 暫態標記。
const B11_SELFCLOSE_RESTORED_FLAG: usize = 1usize << (usize::BITS - 1);

impl CallbackFrame {
    fn base(&self) -> usize {
        self.call_base & !B11_SELFCLOSE_RESTORED_FLAG
    }

    #[cfg(feature = "lua55")]
    fn selfclose_restored_b11(&self) -> bool {
        self.call_base & B11_SELFCLOSE_RESTORED_FLAG != 0
    }

    #[cfg(feature = "lua55")]
    fn mark_selfclose_restored_b11(&mut self) {
        self.call_base |= B11_SELFCLOSE_RESTORED_FLAG;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DebugTokenOrigin {
    External(ExternalToken),
    Coroutine(ObjectRef),
}

#[derive(Clone, Copy)]
struct DebugTokenEntry {
    key: usize,
    handle: DebugFrameHandle,
    origin: DebugTokenOrigin,
    level: usize,
    // 0 是目前 C callback 的 stack，1 是最內層 saved_stack，依此類推。
    c_rank: Option<usize>,
}

#[derive(Clone, Default)]
struct DebugPublication {
    source: Option<Rc<StringView>>,
    name: Option<Rc<StringView>>,
    namewhat: Option<Rc<StringView>>,
}

struct DebugState {
    tokens: Vec<DebugTokenEntry>,
    token_charge: Option<StackCapacityCharge>,
    publication: DebugPublication,
    local_name: Option<Rc<StringView>>,
    upvalue_name: Option<Rc<StringView>>,
    upvalue_strings: Vec<(ExternalToken, ObjectRef, Value, Rc<StringView>)>,
    upvalue_strings_charge: Option<StackCapacityCharge>,
}

impl DebugState {
    fn new() -> Self {
        Self {
            tokens: Vec::new(),
            token_charge: None,
            publication: DebugPublication::default(),
            local_name: None,
            upvalue_name: None,
            upvalue_strings: Vec::new(),
            upvalue_strings_charge: None,
        }
    }

    fn reserve_token(&mut self, vm: &Vm) -> Result<(), StackError> {
        if self.tokens.len() < self.tokens.capacity() {
            return Ok(());
        }
        let capacity = self
            .tokens
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let bytes = capacity
            .checked_mul(size_of::<DebugTokenEntry>())
            .ok_or(StackError::StackLimit)?;
        let ticket = vm.reserve_host_allocation(bytes)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
        let actual = replacement
            .capacity()
            .checked_mul(size_of::<DebugTokenEntry>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
        let extra_charge = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?.commit()?)
        };
        let base = ticket.commit()?;
        replacement.append(&mut self.tokens);
        self.tokens = replacement;
        self.token_charge = Some(StackCapacityCharge {
            _base: base,
            _extra: extra_charge,
        });
        Ok(())
    }

    fn reserve_upvalue_string(&mut self, vm: &Vm) -> Result<(), StackError> {
        if self.upvalue_strings.len() < self.upvalue_strings.capacity() {
            return Ok(());
        }
        let capacity = self
            .upvalue_strings
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let bytes = capacity
            .checked_mul(size_of::<(ExternalToken, ObjectRef, Value, Rc<StringView>)>())
            .ok_or(StackError::StackLimit)?;
        let ticket = vm.reserve_host_allocation(bytes)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
        let actual = replacement
            .capacity()
            .checked_mul(size_of::<(ExternalToken, ObjectRef, Value, Rc<StringView>)>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
        let extra_charge = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?.commit()?)
        };
        let base = ticket.commit()?;
        replacement.append(&mut self.upvalue_strings);
        self.upvalue_strings = replacement;
        self.upvalue_strings_charge = Some(StackCapacityCharge {
            _base: base,
            _extra: extra_charge,
        });
        Ok(())
    }

    fn remove_external(&mut self, token: ExternalToken) {
        self.tokens
            .retain(|entry| entry.origin != DebugTokenOrigin::External(token));
        if self.tokens.is_empty() {
            self.tokens = Vec::new();
            self.token_charge = None;
        }
        self.upvalue_strings
            .retain(|(owner, _, _, _)| *owner != token);
        if self.upvalue_strings.is_empty() {
            self.upvalue_strings = Vec::new();
            self.upvalue_strings_charge = None;
        }
    }

    fn register(
        &mut self,
        vm: &Vm,
        origin: DebugTokenOrigin,
        level: usize,
        handle: DebugFrameHandle,
        c_rank: Option<usize>,
    ) -> Result<usize, StackError> {
        if let Some(entry) = self
            .tokens
            .iter_mut()
            .find(|entry| entry.origin == origin && entry.level == level && entry.handle == handle)
        {
            return Ok(entry.key);
        }
        let replace_coroutine = self.tokens.iter().position(|entry| {
            matches!(origin, DebugTokenOrigin::Coroutine(_))
                && entry.origin == origin
                && entry.level == level
        });
        if replace_coroutine.is_none() {
            self.reserve_token(vm)?;
        }
        let sequence = NEXT_DEBUG_TOKEN_B10
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StackError::StackLimit)?;
        // 僅將整數序號當作不可解參照的 C opaque identity；永不形成 Rust 參照。
        let key = usize::try_from(sequence)
            .ok()
            .and_then(|value| value.checked_mul(16))
            .and_then(|value| value.checked_add(13))
            .ok_or(StackError::StackLimit)?;
        let entry = DebugTokenEntry {
            key,
            handle,
            origin,
            level,
            c_rank,
        };
        if let Some(index) = replace_coroutine {
            self.tokens[index] = entry;
        } else {
            self.tokens.push(entry);
        }
        Ok(key)
    }

    fn lookup(&self, key: usize) -> Result<DebugTokenEntry, StackError> {
        if key == 0 {
            return Err(StackError::InvalidIndex);
        }
        self.tokens
            .iter()
            .find(|entry| entry.key == key)
            .copied()
            .ok_or(StackError::InvalidIndex)
    }
}

static NEXT_DEBUG_TOKEN_B10: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct DebugSelectors {
    function_only: bool,
    name: bool,
    source: bool,
    line: bool,
    upvalues: bool,
    tail: bool,
    transfer: bool,
    function: bool,
    lines: bool,
}

impl DebugSelectors {
    fn parse(bytes: &[u8]) -> Result<Self, StackError> {
        let mut selectors = Self::default();
        let mut iter = bytes.iter().copied();
        if iter.next() == Some(b'>') {
            selectors.function_only = true;
        } else {
            iter = bytes.iter().copied();
        }
        for selector in iter {
            match selector {
                b'n' => selectors.name = true,
                b'S' => selectors.source = true,
                b'l' => selectors.line = true,
                b'u' => selectors.upvalues = true,
                b't' => selectors.tail = true,
                b'r' => selectors.transfer = true,
                b'f' => selectors.function = true,
                b'L' => selectors.lines = true,
                _ => return Err(StackError::InvalidIndex),
            }
        }
        Ok(selectors)
    }
}

impl DebugPublication {
    fn prepare(
        vm: &Vm,
        info: &DebugFrameInfo,
        selectors: &DebugSelectors,
        previous: &Self,
    ) -> Result<Self, StackError> {
        let source = if selectors.source {
            Some(match previous.source.as_ref() {
                Some(view) if view.as_bytes() == info.source => Rc::clone(view),
                _ => StringView::new(vm, &info.source)?,
            })
        } else {
            previous.source.clone()
        };
        let name = if selectors.name && !info.name.is_empty() {
            Some(match previous.name.as_ref() {
                Some(view) if view.as_bytes() == info.name => Rc::clone(view),
                _ => StringView::new(vm, &info.name)?,
            })
        } else if selectors.name {
            None
        } else {
            previous.name.clone()
        };
        let namewhat = if selectors.name && !info.namewhat.is_empty() {
            Some(match previous.namewhat.as_ref() {
                Some(view) if view.as_bytes() == info.namewhat => Rc::clone(view),
                _ => StringView::new(vm, &info.namewhat)?,
            })
        } else if selectors.name {
            None
        } else {
            previous.namewhat.clone()
        };
        Ok(Self {
            source,
            name,
            namewhat,
        })
    }
}

impl StateControl {
    fn continuation_push_a5(
        &self,
        continuation: LuaKFunction,
        context: isize,
        protected: bool,
        nresults: c_int,
        base: usize,
        handler: *mut c_void,
    ) -> Result<(), StackError> {
        self.validate()?;
        if self.main_control {
            return Err(StackError::InvalidState);
        }
        let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        let child = self.thread_identity.ok_or(StackError::InvalidState)?;
        if group.vm.coroutine_state(child)? != CoroutineState::Running
            || group
                .callback_frames
                .entries
                .last()
                .is_none_or(|frame| frame.owner_generation != self.state_generation)
        {
            return Err(StackError::Busy);
        }
        let mut records = self
            .continuations_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        let prepared = records.prepare(&group.vm)?;
        let owned_handler = if handler.is_null() {
            None
        } else {
            // SAFETY：private C caller 傳入 preflight 交出的 Box 指標；此處只借讀身分。
            let borrowed = unsafe { &*handler.cast::<PublicErrorHandlerA2>() };
            if borrowed.state_generation != self.state_generation || borrowed.vm_id != self.vm_id {
                return Err(StackError::WrongVm);
            }
            // SAFETY：容量與身分預檢已完成；成功後 ownership 恰一次由 C 移入記錄。
            Some(unsafe { Box::from_raw(handler.cast::<PublicErrorHandlerA2>()) })
        };
        records.push(
            prepared,
            ContinuationA5 {
                continuation,
                context,
                protected,
                nresults,
                base,
                callback_depth: group.callback_frames.entries.len(),
                handler: owned_handler,
            },
        );
        Ok(())
    }

    fn continuation_step_a5(
        &self,
        depth: usize,
        consume: bool,
    ) -> Result<ContinuationStepA5, StackError> {
        self.validate()?;
        let mut records = self
            .continuations_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        let Some(top) = records.entries.last() else {
            return Ok(ContinuationStepA5::none());
        };
        if top.callback_depth != depth {
            return Ok(ContinuationStepA5::none());
        }
        let step = ContinuationStepA5 {
            kind: 1,
            protected: c_int::from(top.protected),
            nresults: top.nresults,
            base: top.base,
            continuation: Some(top.continuation),
            context: top.context,
            handler: top
                .handler
                .as_ref()
                .map_or(std::ptr::null_mut(), |handler| {
                    (&**handler as *const PublicErrorHandlerA2)
                        .cast_mut()
                        .cast()
                }),
        };
        if consume {
            records.pop();
            Ok(ContinuationStepA5 {
                handler: std::ptr::null_mut(),
                ..step
            })
        } else {
            Ok(step)
        }
    }

    fn continuation_results_a5(&self) -> Result<c_int, StackError> {
        self.validate()?;
        let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        let depth = group.callback_frames.entries.len();
        let records = self
            .continuations_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?;
        Ok(records
            .entries
            .last()
            .filter(|entry| depth > entry.callback_depth)
            .map_or(-1, |entry| entry.nresults))
    }

    fn yield_prepare_a5(
        &self,
        nresults: c_int,
        continuation: Option<LuaKFunction>,
        context: isize,
    ) -> Result<(), StackError> {
        self.validate()?;
        if self.main_control {
            return Err(StackError::InvalidState);
        }
        let count = usize::try_from(nresults).map_err(|_| StackError::InvalidIndex)?;
        let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let child = self.thread_identity.ok_or(StackError::InvalidState)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if count > stack.slots.len() {
            return Err(StackError::InvalidIndex);
        }
        let mut suspended = self
            .suspended_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if suspended.is_some()
            || self
                .pending_error
                .try_borrow()
                .map_err(|_| StackError::Busy)?
                .is_some()
        {
            return Err(StackError::Busy);
        }
        let depth = group.callback_frames.entries.len();
        let callback_count = group
            .callback_frames
            .entries
            .iter()
            .rev()
            .take_while(|frame| frame.owner_generation == self.state_generation)
            .count();
        if callback_count == 0 {
            return Err(StackError::InvalidState);
        }
        let top_token = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?
            .token;
        group.vm.external_event(top_token)?;
        if group.vm.external_suspend_depth_a5(top_token, child)? != callback_count {
            return Err(StackError::Layout);
        }
        let mut frames = CallbackFrames::new();
        let prepared_frames = frames.prepare_additional(&group.vm, callback_count)?;
        let mut public = StackStorage::new();
        public.ensure_capacity(&group.vm, count)?;
        for slot in &stack.slots[stack.slots.len() - count..] {
            public.slots.push(slot.try_clone(&mut group.vm)?);
        }
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        group.vm.suspend_external_a5(top_token, child)?;
        frames.commit_prepared(prepared_frames);
        frames.entries.extend(
            group
                .callback_frames
                .entries
                .drain(depth - callback_count..),
        );
        for frame in &frames.entries {
            debug.remove_external(frame.token);
        }
        group.callback_frames.release_empty();
        let overlay = std::mem::replace(&mut *stack, public);
        *suspended = Some(SuspendedA5 {
            frames,
            overlay,
            continuation,
            context,
        });
        self.a5_status.set(1);
        Ok(())
    }

    fn resume_prepare_a5(
        &self,
        from: Option<&StateControl>,
        nargs: c_int,
    ) -> Result<ResumeSetupA5, StackError> {
        self.validate()?;
        if self.main_control {
            return Err(StackError::InvalidState);
        }
        if self
            .reset_public_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .is_some()
        {
            return Err(StackError::Busy);
        }
        let count = usize::try_from(nargs).map_err(|_| StackError::InvalidIndex)?;
        let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        if let Some(source) = from {
            source.validate()?;
            let source_owner = source.group.upgrade().ok_or(StackError::InvalidState)?;
            if !Rc::ptr_eq(&owner, &source_owner) {
                return Err(StackError::WrongVm);
            }
        }
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let child = self.thread_identity.ok_or(StackError::InvalidState)?;
        let state = group.vm.coroutine_state(child)?;
        if state != CoroutineState::Suspended {
            return Err(StackError::InvalidState);
        }
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if count > stack.slots.len() || group.vm.execution_running() {
            return Err(StackError::InvalidIndex);
        }
        let mut suspended = self
            .suspended_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if let Some(held) = suspended.as_mut() {
            let prepared_overlay = held.overlay.prepare_capacity(
                &group.vm,
                held.overlay
                    .slots
                    .len()
                    .checked_add(count)
                    .ok_or(StackError::StackLimit)?,
            )?;
            let prepared_frames = group
                .callback_frames
                .prepare_additional(&group.vm, held.frames.entries.len())?;
            let remap = group.vm.resume_external_a5(child)?;
            let k = held.continuation;
            let context = held.context;
            let base = held.frames.entries.first().map_or(0, CallbackFrame::base);
            let mut held = suspended.take().ok_or(StackError::InvalidState)?;
            held.overlay.commit_capacity(prepared_overlay);
            let start = stack.slots.len() - count;
            held.overlay.slots.extend(stack.slots.drain(start..));
            group.callback_frames.commit_prepared(prepared_frames);
            for mut frame in held.frames.entries.drain(..) {
                let new_token = remap
                    .mappings()
                    .iter()
                    .find_map(|(old, new)| (*old == frame.token).then_some(*new))
                    .ok_or(StackError::Layout)?;
                frame.token = new_token;
                frame.depth = group.callback_frames.entries.len() + 1;
                group.callback_frames.entries.push(frame);
            }
            *stack = held.overlay;
            self.a5_status.set(0);
            return Ok(ResumeSetupA5 {
                kind: 2,
                status: 0,
                nresults: 0,
                resume_args: nargs,
                base,
                step: CallbackStepB4::done(),
                continuation: k,
                context,
            });
        }
        let base = stack
            .slots
            .len()
            .checked_sub(count.checked_add(1).ok_or(StackError::StackLimit)?)
            .ok_or(StackError::InvalidIndex)?;
        let StackValue::Core(entry) = stack.slots[base].checked_value(&group.vm)?;
        let arguments = callback_values_b4(&group.vm, &stack.slots[base + 1..])?;
        group.vm.set_host_coroutine_entry_a5(child, entry)?;
        let outcome = group
            .vm
            .resume(Value::Object(child), &arguments.values)
            .and_then(|mut execution| execution.run());
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = group.vm.clear_host_coroutine_entry_a5(child, entry);
                return Err(error.into());
            }
        };
        match outcome {
            RunOutcome::External(_) => {
                let step = self.callback_outcome_b4(
                    &mut group,
                    &mut stack,
                    outcome,
                    base,
                    ResultMode::All,
                )?;
                self.a5_status.set(0);
                Ok(ResumeSetupA5 {
                    kind: 1,
                    status: 0,
                    nresults: 0,
                    resume_args: 0,
                    base,
                    step,
                    continuation: None,
                    context: 0,
                })
            }
            RunOutcome::Returned(values) => {
                let Some((Value::Boolean(success), results)) = values.split_first() else {
                    return Err(StackError::Layout);
                };
                let published =
                    callback_stack_b4(&mut group.vm, &mut stack, base, results, ResultMode::All)?;
                *stack = published;
                let status = if !success {
                    2
                } else if group.vm.coroutine_state(child)? == CoroutineState::Suspended {
                    1
                } else {
                    0
                };
                self.a5_status.set(status);
                Ok(ResumeSetupA5 {
                    kind: 0,
                    status,
                    nresults: c_int::try_from(results.len()).map_err(|_| StackError::StackLimit)?,
                    resume_args: 0,
                    base,
                    step: CallbackStepB4::done(),
                    continuation: None,
                    context: 0,
                })
            }
            RunOutcome::LuaError(error) => {
                let published = callback_stack_b4(
                    &mut group.vm,
                    &mut stack,
                    base,
                    &[error.value],
                    ResultMode::All,
                )?;
                *stack = published;
                self.a5_status.set(2);
                Ok(ResumeSetupA5 {
                    kind: 0,
                    status: 2,
                    nresults: 1,
                    resume_args: 0,
                    base,
                    step: CallbackStepB4::done(),
                    continuation: None,
                    context: 0,
                })
            }
            _ => Err(StackError::InvalidState),
        }
    }

    fn resume_finish_a5(
        &self,
        base: usize,
        frame_depth: usize,
        error_class: c_int,
    ) -> Result<ResumeFinishA5, StackError> {
        self.validate()?;
        let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        let child = self.thread_identity.ok_or(StackError::InvalidState)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if group.callback_frames.entries.len() != frame_depth
            || !stack.can_remove_from(base)
            || base >= stack.slots.len()
        {
            return Err(StackError::Busy);
        }
        if error_class != 0 {
            if stack.slots.len() < base.saturating_add(2)
                || group.vm.coroutine_state(child)? != CoroutineState::Dead
            {
                return Err(StackError::Layout);
            }
            let status = if error_class == ErrorClass::Allocation as c_int {
                4
            } else {
                2
            };
            self.a5_status.set(status);
            return Ok(ResumeFinishA5 {
                status,
                nresults: c_int::try_from(stack.slots.len() - base)
                    .map_err(|_| StackError::StackLimit)?,
            });
        }
        let StackValue::Core(Value::Boolean(success)) =
            stack.slots[base].checked_value(&group.vm)?
        else {
            return Err(StackError::Layout);
        };
        stack.slots.remove(base);
        let status = if !success {
            if error_class == ErrorClass::Allocation as c_int {
                4
            } else {
                2
            }
        } else if group.vm.coroutine_state(child)? == CoroutineState::Suspended {
            1
        } else {
            0
        };
        self.a5_status.set(status);
        Ok(ResumeFinishA5 {
            status,
            nresults: c_int::try_from(stack.slots.len() - base)
                .map_err(|_| StackError::StackLimit)?,
        })
    }

    fn callback_error_step_a2(&self, error: StackError) -> Result<CallbackStepB4, StackError> {
        if let Some(pending) = self
            .pending_error
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .as_ref()
        {
            return Ok(CallbackStepB4 {
                kind: -1,
                value: pending.class as c_int,
                ..CallbackStepB4::done()
            });
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if let StackError::Number(runtime) = error {
            return self.callback_pending_runtime_a2(&mut group, &mut stack, runtime);
        }
        let class = ErrorClass::from_code(operation_error_class_b5(error))
            .ok_or(StackError::InvalidState)?;
        let emergency = group.emergency_error;
        self.callback_pending_value_a2(&mut group, &mut stack, Value::Object(emergency), class)
    }

    fn callback_pending_value_a2(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        value: Value,
        class: ErrorClass,
    ) -> Result<CallbackStepB4, StackError> {
        let mut pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if pending.is_some() || self.checkpoint_token.get() == 0 {
            return Err(StackError::Busy);
        }
        let top = stack.slots.len();
        let error_top = top.checked_add(1).ok_or(StackError::StackLimit)?;
        if top == MAX_STACK {
            // 正常 push 不可超過 MAX_STACK；已建立的 checkpoint 可使用
            // backing 裡唯一的 emergency slot，待 unwind 後發布錯誤物件。
            if stack.slots.capacity() < error_top {
                return Err(StackError::StackLimit);
            }
        } else {
            stack.ensure_capacity(&group.vm, error_top)?;
        }
        let prepared = StackSlot::new(&mut group.vm, StackValue::Core(value));
        let (slot, class) = match prepared {
            Ok(slot) => (slot, class),
            Err(_) => (
                StackSlot::permanent_rooted(
                    &group.vm,
                    group.emergency_error,
                    Rc::clone(&group.emergency_view),
                )?,
                ErrorClass::Allocation,
            ),
        };
        *pending = Some(PendingError {
            slot,
            class,
            token: self.checkpoint_token.get(),
            original_top: top + 1,
        });
        Ok(CallbackStepB4 {
            kind: -1,
            value: class as c_int,
            ..CallbackStepB4::done()
        })
    }

    fn callback_pending_runtime_a2(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        error: RuntimeError,
    ) -> Result<CallbackStepB4, StackError> {
        let class = runtime_error_class_a2(error);
        if class == ErrorClass::Allocation {
            return self.callback_pending_value_a2(
                group,
                stack,
                Value::Object(group.emergency_error),
                class,
            );
        }
        if error.value != Value::Nil || error.kind == RuntimeErrorKind::Thrown {
            return self.callback_pending_value_a2(group, stack, error.value, class);
        }
        let mut pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if pending.is_some() || self.checkpoint_token.get() == 0 {
            return Err(StackError::Busy);
        }
        let top = stack.slots.len();
        if stack
            .ensure_capacity(&group.vm, top.checked_add(1).ok_or(StackError::StackLimit)?)
            .is_err()
        {
            drop(pending);
            return self.callback_pending_value_a2(
                group,
                stack,
                Value::Object(group.emergency_error),
                ErrorClass::Allocation,
            );
        }
        let message = if error.kind == RuntimeErrorKind::MetatableChainLimit {
            b"chain too long; possible loop".as_slice()
        } else {
            error.diagnostic_id.as_bytes()
        };
        let value = group
            .vm
            .with_unpublished_byte_string(message, |vm, object| {
                let slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                Ok::<_, StackError>(slot)
            });
        match value {
            Ok(slot) => {
                *pending = Some(PendingError {
                    slot,
                    class,
                    token: self.checkpoint_token.get(),
                    original_top: top + 1,
                });
                Ok(CallbackStepB4 {
                    kind: -1,
                    value: class as c_int,
                    ..CallbackStepB4::done()
                })
            }
            Err(_) => {
                drop(pending);
                self.callback_pending_value_a2(
                    group,
                    stack,
                    Value::Object(group.emergency_error),
                    ErrorClass::Allocation,
                )
            }
        }
    }

    fn debug_origin_frame(
        &self,
        group: &StateGroup,
        level: usize,
    ) -> Result<Option<(DebugTokenOrigin, DebugFrameHandle)>, StackError> {
        if let Some(callback) = group
            .callback_frames
            .entries
            .last()
            .filter(|callback| callback.owner_generation == self.state_generation)
        {
            let handle = group.vm.debug_frame_external(callback.token, level)?;
            return Ok(handle.map(|handle| (DebugTokenOrigin::External(callback.token), handle)));
        }
        let Some(thread) = self.thread_identity else {
            return Ok(None);
        };
        match group.vm.debug_frame_coroutine(thread, level) {
            Ok(handle) => Ok(handle.map(|handle| (DebugTokenOrigin::Coroutine(thread), handle))),
            Err(_) => Ok(None),
        }
    }

    fn debug_getstack(&self, level: c_int) -> Result<Option<usize>, StackError> {
        self.validate_debug()?;
        let level = usize::try_from(level).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let Some((origin, handle)) = self.debug_origin_frame(&group, level)? else {
            return Ok(None);
        };
        let info = group.vm.debug_frame_info(handle)?;
        let c_rank = if info.kind == DebugFrameKind::C {
            let DebugTokenOrigin::External(token) = origin else {
                return Ok(None);
            };
            let mut preceding = 0usize;
            for at in 0..level {
                let Some(previous) = group.vm.debug_frame_external(token, at)? else {
                    return Err(StackError::InvalidIndex);
                };
                if group.vm.debug_frame_info(previous)?.kind == DebugFrameKind::C {
                    preceding += 1;
                }
            }
            Some(preceding)
        } else {
            None
        };
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        debug
            .register(&group.vm, origin, level, handle, c_rank)
            .map(Some)
    }

    fn debug_token(&self, key: usize) -> Result<DebugTokenEntry, StackError> {
        self.debug
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .lookup(key)
    }

    fn debug_getinfo(
        &self,
        selectors: &DebugSelectors,
        token: Option<usize>,
    ) -> Result<Option<DebugInfoCommit>, StackError> {
        self.validate_debug()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let function_only = selectors.function_only;
        let (info, consume_function) = if function_only {
            let Some(slot) = stack.slots.last() else {
                return Ok(None);
            };
            if !stack.can_remove_from(stack.slots.len() - 1) {
                return Ok(None);
            }
            let StackValue::Core(function) = slot.checked_value(&group.vm)?;
            if checked_value_tag(&group.vm, function)? != LUA_TFUNCTION {
                return Ok(None);
            }
            (group.vm.debug_function_info(function)?, true)
        } else {
            let entry = self.debug_token(token.ok_or(StackError::InvalidIndex)?)?;
            (group.vm.debug_frame_info(entry.handle)?, false)
        };
        let required = stack
            .slots
            .len()
            .checked_sub(usize::from(consume_function))
            .and_then(|top| top.checked_add(usize::from(selectors.function)))
            .and_then(|top| top.checked_add(usize::from(selectors.lines)))
            .ok_or(StackError::StackLimit)?;
        let prepared_capacity = stack.prepare_capacity(&group.vm, required)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let previous = debug.publication.clone();
        let publication = DebugPublication::prepare(&group.vm, &info, selectors, &previous)?;
        let function_slot = if selectors.function {
            Some(StackSlot::new(
                &mut group.vm,
                StackValue::Core(info.function),
            )?)
        } else {
            None
        };
        let lines_slot = if selectors.lines {
            if let Value::Object(function) = info.function {
                if group.vm.object_kind(function)? == ObjectKind::Closure {
                    let (lines, root) = group
                        .vm
                        .prepare_unpublished_host_line_table(&info.active_lines)?;
                    Some(StackSlot {
                        value: StackValue::Core(Value::Object(lines)),
                        root: Some(root),
                        string_view: None,
                    })
                } else {
                    Some(StackSlot::new(&mut group.vm, StackValue::Core(Value::Nil))?)
                }
            } else {
                Some(StackSlot::new(&mut group.vm, StackValue::Core(Value::Nil))?)
            }
        } else {
            None
        };
        // 所有可失敗工作已完成；以下只移交 slot/backing 並寫入 caller 的 lua_Debug。
        stack.commit_capacity(prepared_capacity);
        if consume_function {
            stack.slots.pop();
        }
        if let Some(slot) = function_slot {
            stack.slots.push(slot);
        }
        if let Some(slot) = lines_slot {
            stack.slots.push(slot);
        }
        debug.publication = publication;
        Ok(Some(DebugInfoCommit {
            info,
            source: debug.publication.source.as_ref().map(|view| view.as_ptr()),
            name: debug.publication.name.as_ref().map(|view| view.as_ptr()),
            namewhat: debug
                .publication
                .namewhat
                .as_ref()
                .map(|view| view.as_ptr()),
        }))
    }

    fn debug_getlocal(
        &self,
        token: Option<usize>,
        index: c_int,
    ) -> Result<Option<*const c_char>, StackError> {
        self.validate_debug()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if token.is_none() {
            let Some(slot) = stack.slots.last() else {
                return Ok(None);
            };
            let StackValue::Core(function) = slot.checked_value(&group.vm)?;
            let Some(parameter) = group
                .vm
                .debug_function_parameter_name(function, i64::from(index))?
            else {
                return Ok(None);
            };
            let view = StringView::new(&group.vm, &parameter.name)?;
            let pointer = view.as_ptr();
            self.debug
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)?
                .local_name = Some(view);
            return Ok(Some(pointer));
        }
        let entry = self.debug_token(token.ok_or(StackError::InvalidIndex)?)?;
        let info = group.vm.debug_frame_info(entry.handle)?;
        if info.kind == DebugFrameKind::C {
            let Some(rank) = entry.c_rank else {
                return Ok(None);
            };
            let Some(position) = usize::try_from(index).ok().and_then(|n| n.checked_sub(1)) else {
                return Ok(None);
            };
            let slot = if rank == 0 {
                let Some(source_slot) = stack.slots.get(position) else {
                    return Ok(None);
                };
                source_slot.try_clone(&mut group.vm)?
            } else {
                let StateGroup {
                    vm,
                    callback_frames,
                    ..
                } = &mut *group;
                let Some(frame) = callback_frames
                    .entries
                    .len()
                    .checked_sub(rank)
                    .and_then(|at| callback_frames.entries.get(at))
                else {
                    return Ok(None);
                };
                let Some(source_slot) = frame.saved_stack.slots.get(position) else {
                    return Ok(None);
                };
                source_slot.try_clone(vm)?
            };
            let view = StringView::new(&group.vm, b"(C temporary)")?;
            let required = stack
                .slots
                .len()
                .checked_add(1)
                .ok_or(StackError::StackLimit)?;
            let prepared = stack.prepare_capacity(&group.vm, required)?;
            let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
            stack.commit_capacity(prepared);
            stack.slots.push(slot);
            let pointer = view.as_ptr();
            debug.local_name = Some(view);
            return Ok(Some(pointer));
        }
        let Some(local) = group.vm.debug_local_read(entry.handle, i64::from(index))? else {
            return Ok(None);
        };
        let view = StringView::new(&group.vm, &local.name)?;
        let slot = StackSlot::new(&mut group.vm, StackValue::Core(local.value))?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        stack.commit_capacity(prepared);
        stack.slots.push(slot);
        let pointer = view.as_ptr();
        debug.local_name = Some(view);
        Ok(Some(pointer))
    }

    fn debug_setlocal(
        &self,
        key: usize,
        index: c_int,
    ) -> Result<Option<*const c_char>, StackError> {
        self.validate_debug()?;
        let entry = self.debug_token(key)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let Some(source_position) = stack.slots.len().checked_sub(1) else {
            return Ok(None);
        };
        if !stack.can_remove_from(source_position) {
            return Ok(None);
        }
        let info = group.vm.debug_frame_info(entry.handle)?;
        if info.kind == DebugFrameKind::C {
            let Some(rank) = entry.c_rank else {
                return Ok(None);
            };
            let Some(position) = usize::try_from(index).ok().and_then(|n| n.checked_sub(1)) else {
                return Ok(None);
            };
            let target_len = if rank == 0 {
                stack.slots.len()
            } else {
                let Some(frame) = group
                    .callback_frames
                    .entries
                    .len()
                    .checked_sub(rank)
                    .and_then(|at| group.callback_frames.entries.get(at))
                else {
                    return Ok(None);
                };
                frame.saved_stack.slots.len()
            };
            if position >= target_len {
                return Ok(None);
            }
            let view = StringView::new(&group.vm, b"(C temporary)")?;
            let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let slot = stack.slots.pop().ok_or(StackError::InvalidIndex)?;
            if rank == 0 {
                if position < stack.slots.len() {
                    stack.slots[position] = slot;
                }
            } else {
                let at = group.callback_frames.entries.len() - rank;
                group.callback_frames.entries[at].saved_stack.slots[position] = slot;
            }
            stack.release_empty_capacity();
            let pointer = view.as_ptr();
            debug.local_name = Some(view);
            return Ok(Some(pointer));
        }
        let Some(local) = group.vm.debug_local_read(entry.handle, i64::from(index))? else {
            return Ok(None);
        };
        let view = StringView::new(&group.vm, &local.name)?;
        let StackValue::Core(value) = stack.slots[source_position].checked_value(&group.vm)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if group
            .vm
            .debug_local_write(entry.handle, i64::from(index), value)?
            .is_none()
        {
            return Ok(None);
        }
        stack.slots.pop();
        stack.release_empty_capacity();
        let pointer = view.as_ptr();
        debug.local_name = Some(view);
        Ok(Some(pointer))
    }

    fn hook_target(&self) -> Result<Option<ObjectRef>, StackError> {
        self.validate_debug()?;
        if self.main_control {
            Ok(None)
        } else {
            self.thread_identity
                .map(Some)
                .ok_or(StackError::InvalidState)
        }
    }

    fn hook_binding(&self) -> Result<HookBinding, StackError> {
        self.hook_target()?;
        Ok(self.hook.get())
    }

    fn set_hook(
        &self,
        callback: Option<LuaHook>,
        mask: c_int,
        count: c_int,
    ) -> Result<(), StackError> {
        let target = self.hook_target()?;
        let mask = c_int::from(mask as u8);
        let callback = if mask == 0 { None } else { callback };
        let mask = if callback.is_some() { mask } else { 0 };
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let config = callback.map(|_| DebugHookConfig {
            function: group.hook_bridge,
            call: mask & 1 != 0,
            ret: mask & 2 != 0,
            line: mask & 4 != 0,
            count: if mask & 8 != 0 {
                usize::try_from(count).unwrap_or(0)
            } else {
                0
            },
        });
        group.vm.debug_set_hook(target, config)?;
        self.hook.set(HookBinding {
            callback,
            mask,
            count,
        });
        Ok(())
    }
}

struct DebugInfoCommit {
    info: DebugFrameInfo,
    source: Option<*const c_char>,
    name: Option<*const c_char>,
    namewhat: Option<*const c_char>,
}

struct CallbackFrames {
    entries: Vec<CallbackFrame>,
    charge: Option<StackCapacityCharge>,
}

struct SuspendedA5 {
    frames: CallbackFrames,
    overlay: StackStorage,
    continuation: Option<LuaKFunction>,
    context: isize,
}

/// reset 預留每層 C overlay 的獨立 close stack；最內層先交給公開 stack。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResetStageA5 {
    Prepared,
    Closing,
}

struct ResetPublicA5 {
    public: StackStorage,
    outer_levels: Vec<StackStorage>,
    _levels_charge: Option<StackCapacityCharge>,
    boundary_token: Option<ExternalToken>,
    stage: ResetStageA5,
}

/// 僅在同組 parent C callback 同步 reset child 的 C driver 生命週期內使用。
#[derive(Clone, Copy)]
struct ResetPermitA5 {
    child_generation: u64,
    group_generation: u64,
    from_generation: u64,
    prefix_len: usize,
    prefix_token: ExternalToken,
    checkpoint_token: Option<u64>,
}

impl ResetPermitA5 {
    fn matches_prefix(self, state: &StateControl, group: &StateGroup) -> bool {
        self.child_generation == state.state_generation
            && self.group_generation == group.generation
            && self.prefix_len > 0
            && group.callback_frames.entries.len() == self.prefix_len
            && group.callback_frames.entries.last().is_some_and(|frame| {
                frame.owner_generation == self.from_generation
                    && frame.depth == self.prefix_len
                    && frame.token == self.prefix_token
            })
            && self.checkpoint_token.is_none_or(|token| {
                state.checkpoint_depth.get() > 1
                    || (state.checkpoint_depth.get() == 1 && state.checkpoint_token.get() == token)
            })
    }
}

struct ContinuationA5 {
    continuation: LuaKFunction,
    context: isize,
    protected: bool,
    nresults: c_int,
    base: usize,
    callback_depth: usize,
    handler: Option<Box<PublicErrorHandlerA2>>,
}

struct ContinuationStackA5 {
    entries: Vec<ContinuationA5>,
    charge: Option<StackCapacityCharge>,
}

impl ContinuationStackA5 {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            charge: None,
        }
    }

    fn prepare(
        &self,
        vm: &Vm,
    ) -> Result<Option<(Vec<ContinuationA5>, StackCapacityCharge)>, StackError> {
        if self.entries.len() < self.entries.capacity() {
            return Ok(None);
        }
        let capacity = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let bytes = capacity
            .checked_mul(size_of::<ContinuationA5>())
            .ok_or(StackError::StackLimit)?;
        let ticket = vm.reserve_host_allocation(bytes)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
        let actual = entries
            .capacity()
            .checked_mul(size_of::<ContinuationA5>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
        let extra = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?.commit()?)
        };
        Ok(Some((
            entries,
            StackCapacityCharge {
                _base: ticket.commit()?,
                _extra: extra,
            },
        )))
    }

    fn push(
        &mut self,
        prepared: Option<(Vec<ContinuationA5>, StackCapacityCharge)>,
        entry: ContinuationA5,
    ) {
        if let Some((mut entries, charge)) = prepared {
            entries.append(&mut self.entries);
            self.entries = entries;
            self.charge = Some(charge);
        }
        self.entries.push(entry);
    }

    fn pop(&mut self) -> Option<ContinuationA5> {
        let entry = self.entries.pop();
        if self.entries.is_empty() {
            self.entries = Vec::new();
            self.charge = None;
        }
        entry
    }
}

struct PreparedCallbackCapacity {
    entries: Vec<CallbackFrame>,
    charge: StackCapacityCharge,
}

impl CallbackFrames {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            charge: None,
        }
    }

    fn prepare_capacity(&self, vm: &Vm) -> Result<Option<PreparedCallbackCapacity>, StackError> {
        self.prepare_additional(vm, 1)
    }

    fn prepare_additional(
        &self,
        vm: &Vm,
        additional: usize,
    ) -> Result<Option<PreparedCallbackCapacity>, StackError> {
        let capacity = self
            .entries
            .len()
            .checked_add(additional)
            .ok_or(StackError::StackLimit)?;
        if capacity <= self.entries.capacity() {
            return Ok(None);
        }
        let bytes = capacity
            .checked_mul(size_of::<CallbackFrame>())
            .ok_or(StackError::StackLimit)?;
        let ticket = vm.reserve_host_allocation(bytes)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
        let actual = entries
            .capacity()
            .checked_mul(size_of::<CallbackFrame>())
            .ok_or(StackError::StackLimit)?;
        let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
        let extra = if extra == 0 {
            None
        } else {
            Some(vm.reserve_host_allocation(extra)?.commit()?)
        };
        let base = ticket.commit()?;
        Ok(Some(PreparedCallbackCapacity {
            entries,
            charge: StackCapacityCharge {
                _base: base,
                _extra: extra,
            },
        }))
    }

    fn commit_prepared(&mut self, prepared: Option<PreparedCallbackCapacity>) {
        if let Some(mut prepared) = prepared {
            prepared.entries.append(&mut self.entries);
            self.entries = prepared.entries;
            self.charge = Some(prepared.charge);
        }
    }

    fn push(&mut self, prepared: Option<PreparedCallbackCapacity>, frame: CallbackFrame) {
        if let Some(mut prepared) = prepared {
            prepared.entries.append(&mut self.entries);
            self.entries = prepared.entries;
            self.charge = Some(prepared.charge);
        }
        self.entries.push(frame);
    }

    fn release_empty(&mut self) {
        if self.entries.is_empty() {
            self.entries = Vec::new();
            self.charge = None;
        }
    }
}

struct StateControl {
    magic: Cell<u64>,
    live: Cell<bool>,
    c_owned: Cell<bool>,
    state_generation: u64,
    group_generation: u64,
    thread_owner: ThreadId,
    vm_id: VmId,
    group: Weak<RefCell<StateGroup>>,
    main_pointer: Rc<Cell<*mut lua_State>>,
    thread_identity: Option<ObjectRef>,
    main_control: bool,
    allocator: Rc<CAllocatorState>,
    stack: RefCell<StackStorage>,
    debug: RefCell<DebugState>,
    hook: Cell<HookBinding>,
    pending_error: RefCell<Option<PendingError>>,
    checkpoint_depth: Cell<u32>,
    checkpoint_token: Cell<u64>,
    next_checkpoint_token: Cell<u64>,
    a5_status: Cell<c_int>,
    suspended_a5: RefCell<Option<SuspendedA5>>,
    reset_public_a5: RefCell<Option<ResetPublicA5>>,
    reset_permit_a5: Cell<Option<ResetPermitA5>>,
    continuations_a5: RefCell<ContinuationStackA5>,
    test_fail_close_boundary_root_a5: Cell<bool>,
    _charge: Option<HostAllocationCharge>,
}

impl Drop for StateControl {
    fn drop(&mut self) {
        if self.main_control {
            self.main_pointer.set(std::ptr::null_mut());
        }
        self.live.set(false);
        self.magic.set(0);
        self.pending_error.get_mut().take();
        let stack = self.stack.get_mut();
        stack.slots.clear();
        stack.charge = None;
        // control 只持有 weak group；StateAllocation 的 strong owner 在其後釋放。
    }
}

fn checked_value_tag(vm: &Vm, value: Value) -> Result<c_int, StackError> {
    Ok(match value {
        Value::Nil => LUA_TNIL,
        Value::Boolean(_) => LUA_TBOOLEAN,
        Value::Integer(_) | Value::Float(_) => LUA_TNUMBER,
        Value::LightUserdata(_) => LUA_TLIGHTUSERDATA,
        Value::CFunction(id) if id.vm() == vm.id() => LUA_TFUNCTION,
        Value::CFunction(_) => return Err(StackError::WrongVm),
        Value::Object(object) => match vm.object_kind(object)? {
            ObjectKind::ByteString => LUA_TSTRING,
            ObjectKind::Table => LUA_TTABLE,
            ObjectKind::Closure | ObjectKind::CClosure | ObjectKind::Builtin => LUA_TFUNCTION,
            ObjectKind::Coroutine => LUA_TTHREAD,
            ObjectKind::Userdata | ObjectKind::File => LUA_TUSERDATA,
            ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => {
                return Err(StackError::InvalidIndex);
            }
        },
    })
}

impl StateControl {
    fn validate(&self) -> Result<(), StackError> {
        self.validate_identity(true)
    }

    fn validate_debug(&self) -> Result<(), StackError> {
        self.validate_identity(false)
    }

    fn validate_identity(&self, require_callback_owner: bool) -> Result<(), StackError> {
        if self.allocator.callback_active() {
            return Err(StackError::Busy);
        }
        if self.magic.get() != LIVE_MAGIC
            || !self.live.get()
            || self.state_generation == 0
            || self.thread_owner != thread::current().id()
        {
            return Err(StackError::InvalidState);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        if group.generation != self.group_generation || group.vm.id() != self.vm_id {
            return Err(StackError::WrongVm);
        }
        // 外層 C callback 可同步 reset 同組 child；permit 只在本次 reset C frame
        // 存活，且 parent prefix 的 owner、深度與 token 必須保持原狀。
        if require_callback_owner
            && group
                .callback_frames
                .entries
                .last()
                .is_some_and(|frame| frame.owner_generation != self.state_generation)
            && !self
                .reset_permit_a5
                .get()
                .is_some_and(|permit| permit.matches_prefix(self, &group))
        {
            return Err(StackError::Busy);
        }
        Ok(())
    }

    fn push_c_closure(&self, function: LuaCFunction, n: c_int) -> Result<(), StackError> {
        self.validate()?;
        let n = usize::try_from(n)
            .ok()
            .filter(|&n| n <= 255)
            .ok_or(StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.len();
        if n > top {
            return Err(StackError::InvalidIndex);
        }
        if n != 0 && !stack.can_remove_from(top - n) {
            return Err(StackError::InvalidIndex);
        }
        let previous = group.functions.find_function(function);
        let id = match previous {
            Some(id) => id,
            None => HostFunctionId::new_unique(group.vm.id())
                .ok_or(StackError::Runtime(VmError::IdentityExhausted))?,
        };
        let prepared_registry = if previous.is_none() {
            group.functions.prepare_capacity(&group.vm)?
        } else {
            None
        };
        if n == 0 {
            let required = top.checked_add(1).ok_or(StackError::StackLimit)?;
            let prepared_stack = stack.prepare_capacity(&group.vm, required)?;
            if let Some(prepared) = prepared_registry {
                group
                    .functions
                    .publish(Some(prepared), HostFunctionEntry { id, function });
            } else if previous.is_none() {
                group
                    .functions
                    .publish(None, HostFunctionEntry { id, function });
            }
            stack.commit_capacity(prepared_stack);
            stack.slots.push(StackSlot {
                value: StackValue::Core(Value::CFunction(id)),
                root: None,
                string_view: None,
            });
            return Ok(());
        }
        let mut captures = [Value::Nil; 255];
        for (offset, value) in captures.iter_mut().take(n).enumerate() {
            let StackValue::Core(capture) =
                stack.slots[top - n + offset].checked_value(&group.vm)?;
            if let Value::CFunction(captured_id) = capture {
                if group.functions.get(captured_id).is_none() {
                    return Err(StackError::WrongVm);
                }
            }
            *value = capture;
        }
        let StateGroup { vm, functions, .. } = &mut *group;
        vm.prepare_unpublished_c_closure::<StackError>(
            id,
            &captures[..n],
            |_, _| Ok(()),
            |closure, root| {
                if let Some(prepared) = prepared_registry {
                    functions.publish(Some(prepared), HostFunctionEntry { id, function });
                } else if previous.is_none() {
                    functions.publish(None, HostFunctionEntry { id, function });
                }
                stack.slots.truncate(top - n);
                stack.slots.push(StackSlot {
                    value: StackValue::Core(Value::Object(closure)),
                    root: Some(root),
                    string_view: None,
                });
            },
        )?;
        Ok(())
    }

    /// # Safety
    /// `entries` 為有效且以 null name 結尾的唯讀 luaL_Reg 陣列；每個非空
    /// name 指向呼叫期間有效、以 NUL 結尾的 C 字串。
    unsafe fn set_functions(&self, entries: *const luaL_Reg, nup: c_int) -> Result<(), StackError> {
        let n = usize::try_from(nup)
            .ok()
            .filter(|&n| n <= 255)
            .ok_or(StackError::InvalidIndex)?;
        self.check_stack(nup)?;
        if entries.is_null() {
            return Err(StackError::InvalidIndex);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.len();
        if top <= n {
            return Err(StackError::InvalidIndex);
        }
        if !stack.can_remove_from(top - n) {
            return Err(StackError::InvalidIndex);
        }
        let table = table_at_index((top - n) as c_int, &stack, &group)?;
        let has_metatable = group.vm.get_metatable(table)?.is_some();
        let mut captures = [Value::Nil; 255];
        for (offset, capture) in captures.iter_mut().take(n).enumerate() {
            let StackValue::Core(value) = stack.slots[top - n + offset].checked_value(&group.vm)?;
            if let Value::CFunction(id) = value {
                if group.functions.get(id).is_none() {
                    return Err(StackError::WrongVm);
                }
            }
            *capture = value;
        }
        let mut offset = 0usize;
        loop {
            // SAFETY：呼叫者保證陣列從 entries 起連續、正確對齊並完整初始化，
            // 直到第一個 null name sentinel；只讀取當前元素，且呼叫期間不失效。
            let entry = unsafe { entries.add(offset) };
            // SAFETY：entry 指向上述有效元素；只讀 name 欄位，sentinel 的 func 不讀取。
            let name = unsafe { (*entry).name };
            if name.is_null() {
                break;
            }
            if has_metatable {
                return Err(StackError::InvalidIndex);
            }
            let next_offset = offset.checked_add(1).ok_or(StackError::StackLimit)?;
            // SAFETY：非空 name 指向呼叫期間有效、以 NUL 結尾的唯讀 C 字串。
            let name = unsafe { CStr::from_ptr(name) }.to_bytes();
            // SAFETY：非 sentinel 元素的 func 欄位已初始化；函式指標只保存，不解參或呼叫。
            let function = unsafe { (*entry).func };
            if let Some(function) = function {
                let previous = group.functions.find_function(function);
                let id = match previous {
                    Some(id) => id,
                    None => HostFunctionId::new_unique(group.vm.id())
                        .ok_or(StackError::Runtime(VmError::IdentityExhausted))?,
                };
                let prepared_registry = if previous.is_none() {
                    group.functions.prepare_capacity(&group.vm)?
                } else {
                    None
                };
                let StateGroup { vm, functions, .. } = &mut *group;
                if n == 0 {
                    vm.raw_set_byte_string_key(table, name, Value::CFunction(id))?;
                    if previous.is_none() {
                        functions.publish(prepared_registry, HostFunctionEntry { id, function });
                    }
                } else {
                    vm.prepare_unpublished_c_closure::<StackError>(
                        id,
                        &captures[..n],
                        |vm, closure| {
                            vm.raw_set_byte_string_key(table, name, Value::Object(closure))?;
                            Ok(())
                        },
                        |_, root| {
                            if previous.is_none() {
                                functions
                                    .publish(prepared_registry, HostFunctionEntry { id, function });
                            }
                            drop(root);
                        },
                    )?;
                }
            } else {
                group
                    .vm
                    .raw_set_byte_string_key(table, name, Value::Boolean(false))?;
            }
            offset = next_offset;
        }
        stack.slots.truncate(top - n);
        stack.release_empty_capacity();
        Ok(())
    }

    fn c_function(&self, index: c_int) -> Result<Option<LuaCFunction>, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = match resolve_read_index(index, stack.slots.len()) {
            Ok(position) => position,
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => return Ok(None),
            Err(error) => return Err(error),
        };
        let StackValue::Core(value) = read_at_index(position, &stack, &group)?;
        let id = match value {
            Value::CFunction(id) => id,
            Value::Object(object) if group.vm.object_kind(object)? == ObjectKind::CClosure => {
                group.vm.capi_c_closure_function(object)?
            }
            _ => return Ok(None),
        };
        if id.vm() != group.vm.id() {
            return Ok(None);
        }
        Ok(group.functions.get(id))
    }

    fn get_c_upvalue(&self, index: c_int, n: c_int) -> Result<*const c_char, StackError> {
        self.validate()?;
        let upvalue = usize::try_from(n).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(Value::Object(function)) = read_at_index(position, &stack, &group)?
        else {
            return Err(StackError::InvalidIndex);
        };
        let name = match group.vm.object_kind(function)? {
            ObjectKind::CClosure => {
                let id = group.vm.capi_c_closure_function(function)?;
                if group.functions.get(id).is_none() {
                    return Err(StackError::WrongVm);
                }
                None
            }
            ObjectKind::Closure => {
                let bytes = group
                    .vm
                    .capi_lua_upvalue_name(function, upvalue)?
                    .ok_or(StackError::InvalidIndex)?;
                Some(StringView::new(&group.vm, bytes)?)
            }
            _ => return Err(StackError::InvalidIndex),
        };
        let cell = group
            .vm
            .capi_upvalue_cell(Value::Object(function), upvalue)?
            .ok_or(StackError::InvalidIndex)?;
        let value = group.vm.capi_read_upvalue(cell)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        stack.slots.push(slot);
        debug.upvalue_name = name;
        Ok(debug
            .upvalue_name
            .as_ref()
            .map_or(EMPTY_UPVALUE_NAME.as_ptr().cast(), |name| name.as_ptr()))
    }

    fn set_c_upvalue(&self, index: c_int, n: c_int) -> Result<*const c_char, StackError> {
        self.validate()?;
        let upvalue = usize::try_from(n).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.len();
        if top == 0 {
            return Err(StackError::InvalidIndex);
        }
        let position = resolve_read_index(index, top)?;
        let StackValue::Core(Value::Object(function)) = read_at_index(position, &stack, &group)?
        else {
            return Err(StackError::InvalidIndex);
        };
        let name = match group.vm.object_kind(function)? {
            ObjectKind::CClosure => {
                let id = group.vm.capi_c_closure_function(function)?;
                if group.functions.get(id).is_none() {
                    return Err(StackError::WrongVm);
                }
                None
            }
            ObjectKind::Closure => {
                let bytes = group
                    .vm
                    .capi_lua_upvalue_name(function, upvalue)?
                    .ok_or(StackError::InvalidIndex)?;
                Some(StringView::new(&group.vm, bytes)?)
            }
            _ => return Err(StackError::InvalidIndex),
        };
        let cell = group
            .vm
            .capi_upvalue_cell(Value::Object(function), upvalue)?
            .ok_or(StackError::InvalidIndex)?;
        let StackValue::Core(value) = stack.slots[top - 1].checked_value(&group.vm)?;
        if !stack.can_remove_from(top - 1) {
            return Err(StackError::InvalidIndex);
        }
        if let Value::CFunction(captured_id) = value {
            if group.functions.get(captured_id).is_none() {
                return Err(StackError::WrongVm);
            }
        }
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        group.vm.capi_set_upvalue(cell, value)?;
        stack.slots.pop();
        stack.release_empty_capacity();
        debug.upvalue_name = name;
        Ok(debug
            .upvalue_name
            .as_ref()
            .map_or(EMPTY_UPVALUE_NAME.as_ptr().cast(), |name| name.as_ptr()))
    }

    fn upvalue_id(&self, index: c_int, n: c_int) -> Result<*mut c_void, StackError> {
        self.validate()?;
        let upvalue = usize::try_from(n).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(value) = read_at_index(position, &stack, &group)?;
        if let Value::Object(object) = value {
            if group.vm.object_kind(object)? == ObjectKind::CClosure {
                let id = group.vm.capi_c_closure_function(object)?;
                if group.functions.get(id).is_none() {
                    return Err(StackError::WrongVm);
                }
            }
        }
        let Some(cell) = group.vm.capi_upvalue_cell(value, upvalue)? else {
            return Ok(std::ptr::null_mut());
        };
        let token = group.vm.capi_upvalue_identity_token(cell)?;
        let address = usize::try_from(token.get()).map_err(|_| StackError::Layout)?;
        Ok(std::ptr::with_exposed_provenance_mut(address))
    }

    fn join_lua_upvalues(
        &self,
        first_index: c_int,
        first_n: c_int,
        second_index: c_int,
        second_n: c_int,
    ) -> Result<(), StackError> {
        self.validate()?;
        let first_n = usize::try_from(first_n).map_err(|_| StackError::InvalidIndex)?;
        let second_n = usize::try_from(second_n).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let first = read_at_index(
            resolve_read_index(first_index, stack.slots.len())?,
            &stack,
            &group,
        )?;
        let second = read_at_index(
            resolve_read_index(second_index, stack.slots.len())?,
            &stack,
            &group,
        )?;
        let (StackValue::Core(Value::Object(first)), StackValue::Core(Value::Object(second))) =
            (first, second)
        else {
            return Err(StackError::InvalidIndex);
        };
        if !group
            .vm
            .capi_join_lua_upvalues(first, first_n, second, second_n)?
        {
            return Err(StackError::InvalidIndex);
        }
        Ok(())
    }

    fn push(&self, value: StackValue) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if let StackValue::Core(Value::CFunction(id)) = value {
            if group.functions.get(id).is_none() {
                return Err(StackError::WrongVm);
            }
        }
        let slot = StackSlot::new(&mut group.vm, value)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        stack.slots.push(slot);
        Ok(())
    }

    fn push_index(&self, index: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let slot = match resolve_read_index(index, stack.slots.len())? {
            ReadIndex::Stack(source) => stack.slots[source].try_clone(&mut group.vm)?,
            ReadIndex::Registry => {
                let registry = group.registry_value;
                StackSlot::new(&mut group.vm, registry)?
            }
            ReadIndex::Upvalue(upvalue) => {
                let frame = group
                    .callback_frames
                    .entries
                    .last()
                    .ok_or(StackError::PseudoIndexUnavailable)?;
                let value = group
                    .vm
                    .external_capture(frame.token, upvalue)?
                    .unwrap_or(Value::Nil);
                StackSlot::new(&mut group.vm, StackValue::Core(value))?
            }
        };
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        stack.slots.push(slot);
        Ok(())
    }

    fn push_string(&self, bytes: &[u8]) -> Result<*const c_char, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let view = StringView::new(&group.vm, bytes)?;
        Self::publish_string_view(
            &mut group,
            &mut stack,
            view,
            StackCapacityPlan::Deferred(required),
        )
    }

    #[cfg(feature = "lua55")]
    fn push_external_string(
        &self,
        mut owner: ExternalStringOwner,
    ) -> Result<*const c_char, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let header = Layout::array::<Cell<usize>>(2).map_err(|_| StackError::StackLimit)?;
        let (combined, _) = header
            .extend(Layout::new::<ExternalStringOwner>())
            .map_err(|_| StackError::StackLimit)?;
        let metadata = group
            .vm
            .reserve_host_allocation(combined.pad_to_align().size())?
            .commit()?;
        owner._charge = Some(metadata);
        let pointer = owner.pointer;
        let owner: Rc<dyn ExternalStringStorage> = Rc::new(owner);
        group
            .vm
            .with_unpublished_external_byte_string(owner, |vm, object| {
                let slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                stack.ensure_capacity(vm, required)?;
                stack.slots.push(slot);
                Ok(pointer)
            })
    }

    fn tolstring_fallback_b5(
        &self,
        index: c_int,
        pointer_bytes: &[u8],
    ) -> Result<TolstringFallbackB5, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(value) = read_at_index(position, &stack, &group)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        if let Value::Object(object) = value {
            if group.vm.object_kind(object)? == ObjectKind::ByteString {
                if let Some((pointer, len)) = group
                    .vm
                    .with_byte_string(object, |string| string.external_pointer())?
                {
                    let slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
                    let prepared = stack.prepare_capacity(&group.vm, required)?;
                    stack.commit_capacity(prepared);
                    stack.slots.push(slot);
                    return Ok(TolstringFallbackB5::success(pointer.cast(), len));
                }
                let view = group.vm.with_byte_string(object, |string| {
                    StringView::new(&group.vm, string.as_bytes())
                })??;
                let mut slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
                slot.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                let prepared = stack.prepare_capacity(&group.vm, required)?;
                stack.commit_capacity(prepared);
                stack.slots.push(slot);
                return Ok(TolstringFallbackB5::success(view.as_ptr(), view.len));
            }
        }
        let view = match value {
            Value::Integer(_) | Value::Float(_) => {
                let (bytes, len) = group.vm.format_lua_number(value)?;
                StringView::new(&group.vm, &bytes[..len])?
            }
            Value::Boolean(true) => StringView::new(&group.vm, b"true")?,
            Value::Boolean(false) => StringView::new(&group.vm, b"false")?,
            Value::Nil => StringView::new(&group.vm, b"nil")?,
            _ => {
                let name = if let Value::Object(object) = value {
                    if matches!(
                        group.vm.object_kind(object)?,
                        ObjectKind::Table | ObjectKind::Userdata | ObjectKind::File
                    ) {
                        group.vm.lookup_raw_metafield(object, b"__name")?
                    } else {
                        Value::Nil
                    }
                } else {
                    Value::Nil
                };
                let name_object = match name {
                    Value::Object(object)
                        if group.vm.object_kind(object)? == ObjectKind::ByteString =>
                    {
                        Some(object)
                    }
                    _ => None,
                };
                let static_name = lua_type_name_bytes(checked_value_tag(&group.vm, value)?);
                let name_len = if let Some(object) = name_object {
                    group.vm.with_byte_string(object, |string| {
                        string
                            .as_bytes()
                            .iter()
                            .position(|byte| *byte == 0)
                            .unwrap_or(string.len())
                    })?
                } else {
                    static_name.len()
                };
                let len = name_len
                    .checked_add(2)
                    .and_then(|n| n.checked_add(pointer_bytes.len()))
                    .ok_or(StackError::StackLimit)?;
                StringView::new_filled(&group.vm, len, |bytes, limit| {
                    if let Some(object) = name_object {
                        group.vm.with_byte_string(object, |string| {
                            append_view_bytes(bytes, limit, &string.as_bytes()[..name_len])
                        })??;
                    } else {
                        append_view_bytes(bytes, limit, static_name)?;
                    }
                    append_view_bytes(bytes, limit, b": ")?;
                    append_view_bytes(bytes, limit, pointer_bytes)
                })?
            }
        };
        let length = view.len;
        let pointer = Self::publish_string_view(
            &mut group,
            &mut stack,
            view,
            StackCapacityPlan::Deferred(required),
        )?;
        Ok(TolstringFallbackB5::success(pointer, length))
    }

    fn push_gsub(
        &self,
        source: &[u8],
        pattern: &[u8],
        replacement: &[u8],
    ) -> Result<*const c_char, StackError> {
        self.validate()?;
        let len = checked_gsub_output_len(source, pattern, replacement)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let view = StringView::new_gsub(&group.vm, source, pattern, replacement, len)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        Self::publish_string_view(
            &mut group,
            &mut stack,
            view,
            StackCapacityPlan::Prepared(prepared),
        )
    }

    fn publish_string_view(
        group: &mut StateGroup,
        stack: &mut StackStorage,
        view: Rc<StringView>,
        capacity_plan: StackCapacityPlan,
    ) -> Result<*const c_char, StackError> {
        let pointer = view.as_ptr();
        let slot_view = Rc::clone(&view);
        group
            .vm
            .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                let mut slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                slot.string_view = Some(SlotStringView::Owned(slot_view));
                match capacity_plan {
                    StackCapacityPlan::Deferred(required) => stack.ensure_capacity(vm, required)?,
                    StackCapacityPlan::Prepared(prepared) => stack.commit_capacity(prepared),
                }
                stack.slots.push(slot);
                Ok(pointer)
            })
    }

    fn push_file_result_failure(
        &self,
        errno: c_int,
        fname: *const c_char,
    ) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(3)
            .ok_or(StackError::StackLimit)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        const NO_EXTRA_INFO: &[u8] = b"(no extra info)";
        let error_bytes = if errno == 0 {
            NO_EXTRA_INFO
        } else {
            // SAFETY：errno 是入口先保存的 C 錯誤碼；libc 的非 null 回傳為 NUL 結尾文字，
            // 僅於本次呼叫借讀，隨即交給已計費的 StringView 複製，不存入狀態。
            unsafe {
                let pointer = strerror(errno);
                if pointer.is_null() {
                    NO_EXTRA_INFO
                } else {
                    CStr::from_ptr(pointer).to_bytes()
                }
            }
        };
        let view = if fname.is_null() {
            StringView::new_parts(&group.vm, &[error_bytes])?
        } else {
            // SAFETY：此處 state 已驗證且 group/stack 已成功借用；非 null fname 由 C 呼叫者
            // 保證在呼叫期間為有效 NUL 結尾字串，只在 new_parts 當下借讀並立即複製。
            unsafe {
                let fname_bytes = CStr::from_ptr(fname).to_bytes();
                StringView::new_parts(&group.vm, &[fname_bytes, b": ", error_bytes])?
            }
        };
        let string_slot =
            group
                .vm
                .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                    let mut slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                    slot.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                    Ok::<StackSlot, StackError>(slot)
                })?;
        let nil_slot = StackSlot {
            value: StackValue::Core(Value::Nil),
            root: None,
            string_view: None,
        };
        let errno_slot = StackSlot {
            value: StackValue::Core(Value::Integer(i64::from(errno))),
            root: None,
            string_view: None,
        };
        // 三個 slot、root、view 與容量均已備妥；自此只搬移所有權，不再有可失敗操作。
        stack.commit_capacity(prepared);
        stack.slots.push(nil_slot);
        stack.slots.push(string_slot);
        stack.slots.push(errno_slot);
        Ok(())
    }

    fn create_table(&self, array: c_int, hash: c_int) -> Result<(), StackError> {
        self.validate()?;
        let array = usize::try_from(array).map_err(|_| StackError::StackLimit)?;
        let hash = usize::try_from(hash).map_err(|_| StackError::StackLimit)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let (table, root) = group.vm.prepare_unpublished_host_table(array, hash, |vm| {
            stack.ensure_capacity(vm, required)
        })?;
        stack.slots.push(StackSlot {
            value: StackValue::Core(Value::Object(table)),
            root: Some(root),
            string_view: None,
        });
        Ok(())
    }

    fn new_thread(&self) -> Result<*mut lua_State, StackError> {
        self.validate()?;
        if self.thread_identity.is_none() {
            return Err(StackError::InvalidState);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let main_allocation = group
            .main_allocation
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        let extraspace = main_allocation.extraspace.get();
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        let ticket = group
            .vm
            .reserve_host_allocation(size_of::<StateAllocation>())?;
        let generation = next_generation()?;
        let vm_id = group.vm.id();
        let group_generation = group.generation;
        let allocator = Rc::clone(&group.allocator);
        let main_pointer = Rc::clone(&group.main_pointer);
        let weak_group = Rc::downgrade(&group_owner);
        let mut result_pointer = std::ptr::null_mut();
        group.vm.prepare_unpublished_host_coroutine(
            |_, object| {
                let charge = ticket.commit()?;
                let allocation = Rc::new(StateAllocation {
                    extraspace: Cell::new(extraspace),
                    control: StateControl {
                        magic: Cell::new(LIVE_MAGIC),
                        live: Cell::new(true),
                        c_owned: Cell::new(false),
                        state_generation: generation,
                        group_generation,
                        thread_owner: thread::current().id(),
                        vm_id,
                        group: weak_group,
                        main_pointer,
                        thread_identity: Some(object),
                        main_control: false,
                        allocator,
                        stack: RefCell::new(StackStorage::new()),
                        debug: RefCell::new(DebugState::new()),
                        hook: Cell::new(HookBinding::disabled()),
                        pending_error: RefCell::new(None),
                        checkpoint_depth: Cell::new(0),
                        checkpoint_token: Cell::new(0),
                        next_checkpoint_token: Cell::new(0),
                        a5_status: Cell::new(0),
                        suspended_a5: RefCell::new(None),
                        reset_public_a5: RefCell::new(None),
                        reset_permit_a5: Cell::new(None),
                        continuations_a5: RefCell::new(ContinuationStackA5::new()),
                        test_fail_close_boundary_root_a5: Cell::new(false),
                        _charge: None,
                    },
                    group_owner: None,
                });
                let pointer = (&allocation.control as *const StateControl)
                    .cast_mut()
                    .cast::<lua_State>();
                let attachment = CoroutineStateAttachment {
                    allocation: Some(allocation),
                    charge: Some(charge),
                };
                Ok::<_, StackError>((pointer, Some(Box::new(attachment) as Box<dyn Any>)))
            },
            |object, root, pointer| {
                stack.commit_capacity(prepared);
                stack.slots.push(StackSlot {
                    value: StackValue::Core(Value::Object(object)),
                    root: Some(root),
                    string_view: None,
                });
                result_pointer = pointer;
            },
        )?;
        Ok(result_pointer)
    }

    fn to_thread(&self, index: c_int) -> Result<*mut lua_State, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let Ok(position) = resolve_stack_index(index, stack.slots.len()) else {
            return Ok(std::ptr::null_mut());
        };
        let StackValue::Core(Value::Object(object)) =
            stack.slots[position].checked_value(&group.vm)?
        else {
            return Ok(std::ptr::null_mut());
        };
        if group.vm.object_kind(object)? != ObjectKind::Coroutine {
            return Ok(std::ptr::null_mut());
        }
        if object == group.main_thread {
            return Ok(if group.main_allocation.upgrade().is_some() {
                group.main_pointer.get()
            } else {
                std::ptr::null_mut()
            });
        }
        Ok(group
            .vm
            .with_coroutine_host_attachment::<CoroutineStateAttachment, _>(
                object,
                |attachment| {
                    attachment
                        .and_then(|attachment| attachment.allocation.as_ref())
                        .map_or(std::ptr::null_mut(), |allocation| {
                            (&allocation.control as *const StateControl)
                                .cast_mut()
                                .cast::<lua_State>()
                        })
                },
            )?)
    }

    fn push_thread(&self) -> Result<c_int, StackError> {
        self.validate()?;
        let object = self.thread_identity.ok_or(StackError::InvalidState)?;
        self.push(StackValue::Core(Value::Object(object)))?;
        Ok(c_int::from(self.main_control))
    }

    fn new_userdata(&self, size: usize, nuvalue: c_int) -> Result<*mut c_void, StackError> {
        self.validate()?;
        if !(0..c_int::from(c_short::MAX)).contains(&nuvalue) {
            return Err(StackError::StackLimit);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let (userdata, root, pointer) =
            group
                .vm
                .prepare_unpublished_host_userdata(size, nuvalue as usize, |vm| {
                    stack.ensure_capacity(vm, required)
                })?;
        stack.slots.push(StackSlot {
            value: StackValue::Core(Value::Object(userdata)),
            root: Some(root),
            string_view: None,
        });
        Ok(pointer.cast())
    }

    fn userdata_pointer(&self, index: c_int) -> Result<*mut c_void, StackError> {
        let value = self.read(index)?;
        match value {
            StackValue::Core(Value::LightUserdata(address)) => {
                Ok(std::ptr::with_exposed_provenance_mut(address))
            }
            StackValue::Core(Value::Object(object)) => {
                let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
                let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
                if group.vm.object_kind(object)? == ObjectKind::Userdata {
                    Ok(group.vm.userdata_ptr(object)?.cast())
                } else {
                    Ok(std::ptr::null_mut())
                }
            }
            _ => Ok(std::ptr::null_mut()),
        }
    }

    fn object_pointer(&self, index: c_int) -> Result<*const c_void, StackError> {
        let value = self.read(index)?;
        match value {
            StackValue::Core(Value::LightUserdata(address)) => {
                Ok(std::ptr::with_exposed_provenance(address))
            }
            StackValue::Core(Value::CFunction(function)) => {
                let owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
                let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
                let pointer = group.functions.get(function).ok_or(StackError::WrongVm)?;
                // 此資訊指標僅供 %p／身分比較，不解參照 C 函式位址。
                Ok(std::ptr::with_exposed_provenance(pointer as usize))
            }
            StackValue::Core(Value::Object(object)) => {
                let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
                let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
                match group.vm.object_kind(object)? {
                    ObjectKind::Userdata => Ok(group.vm.userdata_ptr(object)?.cast_const().cast()),
                    ObjectKind::ByteString
                    | ObjectKind::Table
                    | ObjectKind::Closure
                    | ObjectKind::CClosure
                    | ObjectKind::Builtin
                    | ObjectKind::Coroutine
                    | ObjectKind::File => {
                        let token = group
                            .vm
                            .opaque_identity_token(object)?
                            .ok_or(StackError::InvalidIndex)?;
                        let address =
                            usize::try_from(token.get()).map_err(|_| StackError::Layout)?;
                        // 資訊指標只供 C 端比較／雜湊；此位址沒有可解參照的 Rust 配置。
                        Ok(std::ptr::with_exposed_provenance(address))
                    }
                    ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => {
                        Ok(std::ptr::null())
                    }
                }
            }
            _ => Ok(std::ptr::null()),
        }
    }

    fn get_uservalue(&self, index: c_int, n: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        // 必須先依 push 前的 top 解析 target；只有 full userdata 能進入 nil 回傳路徑。
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(Value::Object(object)) = read_at_index(position, &stack, &group)?
        else {
            return Err(StackError::InvalidIndex);
        };
        let value = match group.vm.object_kind(object)? {
            ObjectKind::Userdata => match usize::try_from(n) {
                Ok(n) => group.vm.get_uservalue(object, n)?,
                Err(_) => None,
            },
            ObjectKind::File => None,
            _ => return Err(StackError::InvalidIndex),
        };
        let (value, tag) = match value {
            Some(value) => (value, checked_value_tag(&group.vm, value)?),
            None => (Value::Nil, LUA_TNONE),
        };
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        let slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
        stack.commit_capacity(prepared);
        stack.slots.push(slot);
        Ok(tag)
    }

    fn set_uservalue(&self, index: c_int, n: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(Value::Object(object)) = read_at_index(position, &stack, &group)?
        else {
            return Err(StackError::InvalidIndex);
        };
        let kind = group.vm.object_kind(object)?;
        if !matches!(kind, ObjectKind::Userdata | ObjectKind::File) {
            return Err(StackError::InvalidIndex);
        }
        let StackValue::Core(value) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        let assigned = match kind {
            ObjectKind::Userdata => match usize::try_from(n) {
                Ok(n) => group.vm.set_uservalue(object, n, value)?,
                Err(_) => false,
            },
            ObjectKind::File => false,
            _ => return Err(StackError::InvalidIndex),
        };
        // runtime barrier 已成功，或索引無效；此後才移除呼叫前的 top value。
        stack.slots.pop();
        stack.release_empty_capacity();
        Ok(c_int::from(assigned))
    }

    fn raw_get_integer(&self, index: c_int, key: i64) -> Result<c_int, StackError> {
        self.raw_get_explicit_key(index, Value::Integer(key))
    }

    fn raw_get_explicit_key(&self, index: c_int, key: Value) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let table = table_at_index(index, &stack, &group)?;
        let value = group.vm.raw_get(table, key)?;
        let tag = checked_value_tag(&group.vm, value)?;
        let slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        stack.slots.push(slot);
        Ok(tag)
    }

    fn raw_get_stack_key(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let table = table_at_index(index, &stack, &group)?;
        let StackValue::Core(key) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        let value = group.vm.raw_get(table, key)?;
        let tag = checked_value_tag(&group.vm, value)?;
        let replacement = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
        let top = stack.slots.last_mut().ok_or(StackError::InvalidIndex)?;
        *top = replacement;
        Ok(tag)
    }

    fn get_named_field(&self, index: Option<c_int>, name: &[u8]) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let table = match index {
            Some(index) => table_at_index(index, &stack, &group)?,
            None => globals_table(&group)?,
        };
        let (slot, tag) = group.vm.with_temporary_byte_string(name, |vm, key| {
            let value = vm.raw_get(table, Value::Object(key))?;
            let tag = checked_value_tag(vm, value)?;
            let slot = StackSlot::new(vm, StackValue::Core(value))?;
            let required = stack
                .slots
                .len()
                .checked_add(1)
                .ok_or(StackError::StackLimit)?;
            stack.ensure_capacity(vm, required)?;
            Ok::<_, StackError>((slot, tag))
        })?;
        stack.slots.push(slot);
        Ok(tag)
    }

    fn get_subtable(&self, index: c_int, name: &[u8]) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        // 先依呼叫前 top 解析 target；任何失敗都不可移動既有 slots。
        let table = table_at_index(index, &stack, &group)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let mut prepared_capacity = None;
        let (subtable, root, existed) =
            group
                .vm
                .get_or_create_byte_named_subtable(table, name, |vm| {
                    prepared_capacity = stack.prepare_capacity(vm, required)?;
                    Ok::<(), StackError>(())
                })?;
        // runtime 欄位已發布；以下只有已預備容量的 Vec 移交與 push。
        stack.commit_capacity(prepared_capacity);
        stack.slots.push(StackSlot {
            value: StackValue::Core(Value::Object(subtable)),
            root: Some(root),
            string_view: None,
        });
        Ok(c_int::from(existed))
    }

    fn new_metatable(&self, borrowed_name: &[u8]) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        // C 字串只在本次呼叫借用；複製完成後才允許 VM 配置、GC 或 mutation。
        let name = StringView::new(&group.vm, borrowed_name)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if required > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        let registry = group.registry_table()?;
        let mut prepared_capacity = None;
        let (value, root, created) =
            group
                .vm
                .new_named_metatable(registry, name.as_bytes(), |vm| {
                    prepared_capacity = stack.prepare_capacity(vm, required)?;
                    Ok::<(), StackError>(())
                })?;
        // registry 成功發布後僅移交預備容量與結果 root，不再配置。
        stack.commit_capacity(prepared_capacity);
        stack.slots.push(StackSlot {
            value: StackValue::Core(value),
            root,
            string_view: None,
        });
        Ok(c_int::from(created))
    }

    fn set_named_metatable(&self, borrowed_name: &[u8]) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let target = match stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?
        {
            StackValue::Core(Value::Object(object))
                if matches!(
                    group.vm.object_kind(object)?,
                    ObjectKind::Table | ObjectKind::Userdata | ObjectKind::File
                ) =>
            {
                object
            }
            _ => return Err(StackError::InvalidIndex),
        };
        // 先複製 C 名稱，再允許查表期間配置、GC；查詢 key 必須在設定 edge 前清理。
        let name = StringView::new(&group.vm, borrowed_name)?;
        let registry = group.registry_table()?;
        let (metatable, result_root) = group.vm.with_temporary_byte_string(
            name.as_bytes(),
            |vm, key| -> Result<_, StackError> {
                match vm.raw_get(registry, Value::Object(key))? {
                    Value::Nil => Ok((None, None)),
                    Value::Object(object) if vm.object_kind(object)? == ObjectKind::Table => {
                        let root = HostHandle::<Value>::new(vm, object)?;
                        Ok((Some(object), Some(root)))
                    }
                    _ => Err(StackError::InvalidIndex),
                }
            },
        )?;
        group.vm.set_metatable(target, metatable)?;
        drop(result_root);
        Ok(())
    }

    fn test_userdata(&self, index: c_int, borrowed_name: &[u8]) -> Result<*mut c_void, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let StackValue::Core(Value::Object(target)) = read_at_index(position, &stack, &group)?
        else {
            return Ok(std::ptr::null_mut());
        };
        if group.vm.object_kind(target)? != ObjectKind::Userdata {
            return Ok(std::ptr::null_mut());
        }
        let Some(metatable) = group.vm.get_metatable(target)? else {
            return Ok(std::ptr::null_mut());
        };
        // 呼叫者的 C 名稱可能指向仍有 stack root 的 userdata bytes；先複製再配置暫時 key。
        let name = StringView::new(&group.vm, borrowed_name)?;
        let registry = group.registry_table()?;
        let registered = group
            .vm
            .with_temporary_byte_string(name.as_bytes(), |vm, key| {
                vm.raw_get(registry, Value::Object(key))
            })?;
        if registered != Value::Object(metatable) {
            return Ok(std::ptr::null_mut());
        }
        Ok(group.vm.userdata_ptr(target)?.cast())
    }

    fn raw_next(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let table = table_at_index(index, &stack, &group)?;
        let StackValue::Core(previous) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        match group.vm.raw_next_value(table, previous)? {
            None => {
                stack.slots.pop();
                stack.release_empty_capacity();
                Ok(0)
            }
            Some((key, value)) => {
                let key_slot = StackSlot::new(&mut group.vm, StackValue::Core(key))?;
                let value_slot = StackSlot::new(&mut group.vm, StackValue::Core(value))?;
                let required = stack
                    .slots
                    .len()
                    .checked_add(1)
                    .ok_or(StackError::StackLimit)?;
                stack.ensure_capacity(&group.vm, required)?;
                let old_key = stack.slots.last_mut().ok_or(StackError::InvalidIndex)?;
                *old_key = key_slot;
                stack.slots.push(value_slot);
                Ok(1)
            }
        }
    }

    fn raw_set_integer(&self, index: c_int, key: i64) -> Result<(), StackError> {
        self.raw_set_explicit_key(index, Value::Integer(key))
    }

    fn raw_set_explicit_key(&self, index: c_int, key: Value) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if stack.slots.is_empty() {
            return Err(StackError::InvalidIndex);
        }
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        let table = table_at_index(index, &stack, &group)?;
        let StackValue::Core(value) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        group.vm.raw_set(table, key, value)?;
        stack.slots.pop();
        stack.release_empty_capacity();
        Ok(())
    }

    fn raw_set_stack_key(&self, index: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if stack.slots.len() < 2 {
            return Err(StackError::InvalidIndex);
        }
        if !stack.can_remove_from(stack.slots.len() - 2) {
            return Err(StackError::InvalidIndex);
        }
        let table = table_at_index(index, &stack, &group)?;
        let StackValue::Core(key) = stack.slots[stack.slots.len() - 2].checked_value(&group.vm)?;
        let StackValue::Core(value) =
            stack.slots[stack.slots.len() - 1].checked_value(&group.vm)?;
        group.vm.raw_set(table, key, value)?;
        let new_len = stack.slots.len() - 2;
        stack.slots.truncate(new_len);
        stack.release_empty_capacity();
        Ok(())
    }

    fn set_named_field(&self, index: Option<c_int>, name: &[u8]) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if stack.slots.is_empty() {
            return Err(StackError::InvalidIndex);
        }
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        let table = match index {
            Some(index) => table_at_index(index, &stack, &group)?,
            None => globals_table(&group)?,
        };
        let StackValue::Core(value) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        group.vm.raw_set_byte_string_key(table, name, value)?;
        stack.slots.pop();
        stack.release_empty_capacity();
        Ok(())
    }

    fn reference(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let table = table_at_index(index, &stack, &group)?;
        let StackValue::Core(value) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidIndex)?
            .checked_value(&group.vm)?;
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        if value == Value::Nil {
            stack.slots.pop();
            stack.release_empty_capacity();
            return Ok(LUA_REFNIL);
        }

        let header = group.vm.raw_get(table, Value::Integer(REF_FREELIST_KEY))?;
        let missing_header =
            header == Value::Nil || (cfg!(feature = "lua55") && header == Value::Boolean(false));
        let head = match header {
            Value::Integer(value) if (0..=i64::from(c_int::MAX)).contains(&value) => value,
            _ if missing_header => 0,
            _ => return Err(StackError::InvalidIndex),
        };
        let (reference, next_head) = if head != 0 {
            if head == REF_FREELIST_KEY
                || (Some(table) == group.registry_object() && head < FIRST_REGISTRY_REF)
            {
                return Err(StackError::InvalidIndex);
            }
            let next = freelist_next(&group.vm, table, head)?;
            if next == head
                || next == REF_FREELIST_KEY
                || (Some(table) == group.registry_object()
                    && next != 0
                    && next < FIRST_REGISTRY_REF)
            {
                return Err(StackError::InvalidIndex);
            }
            (head, next)
        } else {
            // 初始化 header 仍只是預備值；依預備後的 table 邊界選新 ref。
            let mut border = 0_i64;
            loop {
                let next = border.checked_add(1).ok_or(StackError::InvalidIndex)?;
                if next > i64::from(c_int::MAX) {
                    return Err(StackError::InvalidIndex);
                }
                let field = if missing_header && next == REF_FREELIST_KEY {
                    Value::Integer(0)
                } else {
                    group.vm.raw_get(table, Value::Integer(next))?
                };
                if field == Value::Nil {
                    break;
                }
                border = next;
            }
            let mut reference = border.checked_add(1).ok_or(StackError::InvalidIndex)?;
            if Some(table) == group.registry_object() {
                reference = reference.max(FIRST_REGISTRY_REF);
                while reference <= i64::from(c_int::MAX)
                    && group.vm.raw_get(table, Value::Integer(reference))? != Value::Nil
                {
                    reference = reference.checked_add(1).ok_or(StackError::InvalidIndex)?;
                }
            }
            if reference > i64::from(c_int::MAX) {
                return Err(StackError::InvalidIndex);
            }
            (reference, 0)
        };
        let reference_c = c_int::try_from(reference).map_err(|_| StackError::InvalidIndex)?;
        group.vm.raw_set_ref_pair(
            table,
            (REF_FREELIST_KEY, Value::Integer(next_head)),
            (reference, value),
        )?;
        stack.slots.pop();
        stack.release_empty_capacity();
        Ok(reference_c)
    }

    fn unreference(&self, index: c_int, reference: c_int) -> Result<(), StackError> {
        if reference < 0 {
            return Ok(());
        }
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let table = table_at_index(index, &stack, &group)?;
        if reference == 0
            || i64::from(reference) == REF_FREELIST_KEY
            || (Some(table) == group.registry_object() && i64::from(reference) < FIRST_REGISTRY_REF)
        {
            return Err(StackError::InvalidIndex);
        }
        let head = match group.vm.raw_get(table, Value::Integer(REF_FREELIST_KEY))? {
            Value::Integer(value) if (0..=i64::from(c_int::MAX)).contains(&value) => value,
            _ => return Err(StackError::InvalidIndex),
        };
        // 官方自由串列由非負整數終止於 0；拒絕重複釋放與已損壞的循環。
        let mut slow = head;
        let mut fast = head;
        while slow != 0 {
            if slow == i64::from(reference) {
                return Err(StackError::InvalidIndex);
            }
            slow = freelist_next(&group.vm, table, slow)?;
            for _ in 0..2 {
                if fast == 0 {
                    break;
                }
                if fast == i64::from(reference) {
                    return Err(StackError::InvalidIndex);
                }
                fast = freelist_next(&group.vm, table, fast)?;
            }
            if slow != 0 && slow == fast {
                return Err(StackError::InvalidIndex);
            }
        }
        let reference = i64::from(reference);
        if group.vm.raw_get(table, Value::Integer(reference))? == Value::Nil {
            return Err(StackError::InvalidIndex);
        }
        group.vm.raw_set_ref_pair(
            table,
            (reference, Value::Integer(head)),
            (REF_FREELIST_KEY, Value::Integer(reference)),
        )?;
        Ok(())
    }

    fn raw_equal(&self, left: c_int, right: c_int) -> Result<bool, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let left = match resolve_read_index(left, stack.slots.len()) {
            Ok(index) => index,
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => return Ok(false),
            Err(error) => return Err(error),
        };
        let right = match resolve_read_index(right, stack.slots.len()) {
            Ok(index) => index,
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => return Ok(false),
            Err(error) => return Err(error),
        };
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let StackValue::Core(left) = read_at_index(left, &stack, &group)?;
        let StackValue::Core(right) = read_at_index(right, &stack, &group)?;
        Ok(group.vm.raw_equal_value(left, right)?)
    }

    fn get_metatable(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let target = metatable_target_at_index(index, &stack, &group)?;
        let Some(metatable) = group.vm.get_metatable_for_value(target)? else {
            return Ok(0);
        };
        let slot = StackSlot::new(&mut group.vm, StackValue::Core(Value::Object(metatable)))?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        stack.slots.push(slot);
        Ok(1)
    }

    fn get_metafield(&self, index: c_int, event: &[u8]) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let target = metatable_target_at_index(index, &stack, &group)?;
        let Some(metatable) = group.vm.get_metatable_for_value(target)? else {
            return Ok(LUA_TNIL);
        };
        let prepared = group.vm.with_temporary_byte_string(event, |vm, key| {
            let value = vm.raw_get(metatable, Value::Object(key))?;
            if value == Value::Nil {
                return Ok::<_, StackError>(None);
            }
            let tag = checked_value_tag(vm, value)?;
            let slot = StackSlot::new(vm, StackValue::Core(value))?;
            let required = stack
                .slots
                .len()
                .checked_add(1)
                .ok_or(StackError::StackLimit)?;
            stack.ensure_capacity(vm, required)?;
            Ok(Some((slot, tag)))
        })?;
        let Some((slot, tag)) = prepared else {
            return Ok(LUA_TNIL);
        };
        stack.slots.push(slot);
        Ok(tag)
    }

    fn set_metatable(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.last().ok_or(StackError::InvalidIndex)?;
        if !stack.can_remove_from(stack.slots.len() - 1) {
            return Err(StackError::InvalidIndex);
        }
        let target = metatable_target_at_index(index, &stack, &group)?;
        let metatable = match top.checked_value(&group.vm)? {
            StackValue::Core(Value::Nil) => None,
            StackValue::Core(Value::Object(object))
                if group.vm.object_kind(object)? == ObjectKind::Table =>
            {
                Some(object)
            }
            _ => return Err(StackError::InvalidIndex),
        };
        group.vm.set_metatable_for_value(target, metatable)?;
        stack.slots.pop();
        stack.release_empty_capacity();
        Ok(1)
    }

    fn raw_len(&self, index: c_int) -> Result<u64, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let StackValue::Core(value) = read_at_index(
            resolve_read_index(index, stack.slots.len())?,
            &stack,
            &group,
        )?;
        u64::try_from(group.vm.raw_len_value(value)?)
            .map_err(|_| StackError::Runtime(VmError::ArithmeticOverflow))
    }

    fn top(&self) -> Result<usize, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(stack.slots.len())
    }

    fn read(&self, index: c_int) -> Result<StackValue, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        read_at_index(
            resolve_read_index(index, stack.slots.len())?,
            &stack,
            &group,
        )
    }

    fn set_top(&self, index: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let current = stack.slots.len();
        let target = if index >= 0 {
            index as usize
        } else {
            let target = current as i64 + index as i64 + 1;
            usize::try_from(target).map_err(|_| StackError::InvalidIndex)?
        };
        if target > MAX_STACK {
            return Err(StackError::StackLimit);
        }
        if target < current {
            if !stack.can_remove_from(target) {
                return Err(StackError::InvalidIndex);
            }
            stack.slots.truncate(target);
            stack.release_empty_capacity();
        } else if target > current {
            stack.ensure_capacity(&group.vm, target)?;
            stack.slots.resize_with(target, || StackSlot {
                value: StackValue::Core(Value::Nil),
                root: None,
                string_view: None,
            });
        } else if target == 0 {
            stack.release_empty_capacity();
        }
        // 持有 VM borrow 直到被移除的 HostHandle 已退根，避免 GC 與釋放交錯。
        let _ = &mut group;
        Ok(())
    }

    fn toclose_prepare_b7(&self, index: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_stack_index(index, stack.slots.len())?;
        if stack
            .highest_close_mark()
            .is_some_and(|mark| position <= mark)
        {
            return Err(StackError::InvalidIndex);
        }
        let StackValue::Core(value) = stack.slots[position].checked_value(&group.vm)?;
        if matches!(value, Value::Nil | Value::Boolean(false)) {
            return Ok(());
        }
        let prepared = stack.prepare_close_mark_capacity(&group.vm, stack.close_marks.len() + 1)?;
        let Value::Object(object) = value else {
            return Err(StackError::InvalidIndex);
        };
        if group
            .vm
            .with_host_result_rooting(|vm| lookup_close_method_b7(vm, object))?
            == Value::Nil
        {
            return Err(StackError::InvalidIndex);
        }
        stack.publish_close_mark(prepared, position);
        Ok(())
    }

    fn close_next_b7(
        &self,
        target: usize,
        error_position: Option<usize>,
        nil_slot: bool,
    ) -> Result<CloseStepB7, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let Some(position) = stack.highest_close_mark() else {
            return Ok(CloseStepB7::none());
        };
        if position < target {
            return Ok(CloseStepB7::none());
        }
        if nil_slot && position != target {
            return Err(StackError::InvalidIndex);
        }
        let StackValue::Core(value) = stack.slots[position].checked_value(&group.vm)?;
        if matches!(value, Value::Nil | Value::Boolean(false)) {
            if nil_slot {
                stack.slots[position] =
                    StackSlot::new(&mut group.vm, StackValue::Core(Value::Nil))?;
            }
            stack.pop_close_mark();
            return Ok(CloseStepB7::skip());
        }
        let Value::Object(object) = value else {
            return Err(StackError::InvalidIndex);
        };
        let method = group
            .vm
            .with_host_result_rooting(|vm| lookup_close_method_b7(vm, object));
        let method = match method {
            Ok(Value::Nil) => return Err(StackError::InvalidIndex),
            Ok(method) => method,
            Err(error) => return Err(error.into()),
        };
        let error_argument = if let Some(error_position) = error_position {
            Some(
                stack
                    .slots
                    .get(error_position)
                    .ok_or(StackError::InvalidIndex)?
                    .try_clone(&mut group.vm)?,
            )
        } else {
            None
        };
        let nargs = if error_argument.is_some() || cfg!(feature = "lua54") {
            2
        } else {
            1
        };
        let method_slot = StackSlot::new(&mut group.vm, StackValue::Core(method))?;
        let self_slot = stack.slots[position].try_clone(&mut group.vm)?;
        let error_slot = error_argument.unwrap_or(StackSlot {
            value: StackValue::Core(Value::Nil),
            root: None,
            string_view: None,
        });
        let required = stack
            .slots
            .len()
            .checked_add(1 + nargs)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        // 所有可失敗的準備都完成後才移除標記；handler 本身執行時標記已不再活躍。
        stack.pop_close_mark();
        if nil_slot {
            stack.slots[position] = StackSlot {
                value: StackValue::Core(Value::Nil),
                root: None,
                string_view: None,
            };
        }
        stack.slots.push(method_slot);
        stack.slots.push(self_slot);
        if nargs == 2 {
            stack.slots.push(error_slot);
        }
        Ok(CloseStepB7::invoke(nargs as c_int))
    }

    fn check_stack(&self, additional: c_int) -> Result<(), StackError> {
        self.validate()?;
        let n = usize::try_from(additional).map_err(|_| StackError::StackLimit)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(n)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)
    }

    fn rotate(&self, index: c_int, count: c_int) -> Result<(), StackError> {
        self.validate()?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_stack_index(index, stack.slots.len())?;
        if stack
            .highest_close_mark()
            .is_some_and(|mark| position <= mark)
        {
            return Err(StackError::InvalidIndex);
        }
        let length = stack.slots.len() - position;
        if length == 0 {
            return Err(StackError::InvalidIndex);
        }
        let right = count.rem_euclid(length as c_int) as usize;
        stack.slots[position..].rotate_right(right);
        Ok(())
    }

    fn copy(&self, source: c_int, destination: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let from = resolve_read_index(source, stack.slots.len())?;
        if destination == REGISTRY_INDEX {
            if matches!(from, ReadIndex::Registry) {
                return Ok(());
            }
            let value = read_at_index(from, &stack, &group)?;
            return group.replace_registry(value);
        }
        if let ReadIndex::Upvalue(index) = resolve_read_index(destination, stack.slots.len())? {
            let frame = group
                .callback_frames
                .entries
                .last()
                .ok_or(StackError::PseudoIndexUnavailable)?;
            let cell = group
                .vm
                .external_capture_cell(frame.token, index)?
                .ok_or(StackError::InvalidIndex)?;
            let StackValue::Core(value) = read_at_index(from, &stack, &group)?;
            if let Value::CFunction(id) = value {
                if group.functions.get(id).is_none() {
                    return Err(StackError::WrongVm);
                }
            }
            if !group.vm.capi_set_closed_upvalue(cell, value)? {
                return Err(StackError::InvalidIndex);
            }
            return Ok(());
        }
        let to = resolve_stack_index(destination, stack.slots.len())?;
        if stack.highest_close_mark() == Some(to) || stack.close_marks.binary_search(&to).is_ok() {
            return Err(StackError::InvalidIndex);
        }
        if matches!(from, ReadIndex::Stack(position) if position == to) {
            return Ok(());
        }
        let replacement = match from {
            ReadIndex::Stack(position) => stack.slots[position].try_clone(&mut group.vm)?,
            ReadIndex::Registry => {
                let registry = group.registry_value;
                StackSlot::new(&mut group.vm, registry)?
            }
            ReadIndex::Upvalue(index) => {
                let frame = group
                    .callback_frames
                    .entries
                    .last()
                    .ok_or(StackError::PseudoIndexUnavailable)?;
                let value = group
                    .vm
                    .external_capture(frame.token, index)?
                    .unwrap_or(Value::Nil);
                StackSlot::new(&mut group.vm, StackValue::Core(value))?
            }
        };
        stack.slots[to] = replacement;
        Ok(())
    }

    fn coerce_number(&self, index: c_int) -> Result<Option<Value>, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let StackValue::Core(value) = read_at_index(position, &stack, &group)?;
        Ok(group.vm.coerce_lua_number(value)?)
    }

    fn coerce_integer(&self, index: c_int) -> Result<Option<i64>, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let StackValue::Core(value) = read_at_index(position, &stack, &group)?;
        Ok(group
            .vm
            .coerce_lua_number(value)?
            .and_then(|number| group.vm.lua_integer_from_value(number)))
    }

    fn is_none_or_nil(&self, index: c_int) -> Result<bool, StackError> {
        self.validate()?;
        if index == OTHER_PROFILE_REGISTRY_INDEX {
            return Err(StackError::PseudoIndexUnavailable);
        }
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = match resolve_read_index(index, stack.slots.len()) {
            Ok(ReadIndex::Registry) => return Ok(false),
            Err(StackError::InvalidIndex) => return Ok(true),
            Err(error) => return Err(error),
            Ok(position) => position,
        };
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(matches!(
            read_at_index(position, &stack, &group)?,
            StackValue::Core(Value::Nil)
        ))
    }

    fn ensure_available(&self) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let _group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let _stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(())
    }

    fn checked_number(&self, index: c_int) -> Result<f64, StackError> {
        match self.coerce_number(index)? {
            Some(Value::Integer(value)) => Ok(value as f64),
            Some(Value::Float(value)) => Ok(value),
            _ => Err(StackError::InvalidIndex),
        }
    }

    fn opt_number(&self, index: c_int, default: f64) -> Result<f64, StackError> {
        if self.is_none_or_nil(index)? {
            Ok(default)
        } else {
            self.checked_number(index)
        }
    }

    fn checked_integer(&self, index: c_int) -> Result<i64, StackError> {
        self.coerce_integer(index)?.ok_or(StackError::InvalidIndex)
    }

    fn opt_integer(&self, index: c_int, default: i64) -> Result<i64, StackError> {
        if self.is_none_or_nil(index)? {
            Ok(default)
        } else {
            self.checked_integer(index)
        }
    }

    #[cfg(feature = "lua55")]
    fn number_bytes(&self, index: c_int) -> Result<Option<([u8; 128], usize)>, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        match read_at_index(position, &stack, &group)? {
            StackValue::Core(value @ (Value::Integer(_) | Value::Float(_))) => {
                Ok(Some(group.vm.format_lua_number(value)?))
            }
            _ => Ok(None),
        }
    }

    fn to_string(&self, index: c_int) -> Result<Option<(*const c_char, usize)>, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = resolve_read_index(index, stack.slots.len())?;
        if let ReadIndex::Upvalue(upvalue) = position {
            let frame = group
                .callback_frames
                .entries
                .last()
                .ok_or(StackError::PseudoIndexUnavailable)?;
            let token = frame.token;
            let Some(cell) = group.vm.external_capture_cell(token, upvalue)? else {
                return Ok(None);
            };
            let value = group.vm.capi_read_upvalue(cell)?;
            let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
            if let Some((_, _, _, view)) =
                debug
                    .upvalue_strings
                    .iter()
                    .find(|(owner, object, cached, _)| {
                        *owner == token && *object == cell && *cached == value
                    })
            {
                return Ok(Some((view.as_ptr(), view.len)));
            }
            // 同一 cell 改值後保留舊 view，直到 callback 退出才釋放既有指標。
            debug.reserve_upvalue_string(&group.vm)?;
            let (value, view) = match value {
                Value::Object(object)
                    if group.vm.object_kind(object)? == ObjectKind::ByteString =>
                {
                    let view = group.vm.with_byte_string(object, |string| {
                        StringView::new(&group.vm, string.as_bytes())
                    })??;
                    (value, view)
                }
                Value::Integer(_) | Value::Float(_) => {
                    let (bytes, len) = group.vm.format_lua_number(value)?;
                    let view = StringView::new(&group.vm, &bytes[..len])?;
                    let object =
                        group
                            .vm
                            .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                                vm.capi_set_upvalue(cell, Value::Object(object))?;
                                Ok::<_, StackError>(object)
                            })?;
                    (Value::Object(object), view)
                }
                _ => return Ok(None),
            };
            let pointer = view.as_ptr();
            let len = view.len;
            debug.upvalue_strings.push((token, cell, value, view));
            return Ok(Some((pointer, len)));
        }
        let ReadIndex::Stack(position) = position else {
            return Ok(None);
        };
        let slot = &mut stack.slots[position];
        match slot.checked_value(&group.vm)? {
            StackValue::Core(Value::Object(object))
                if group.vm.object_kind(object)? == ObjectKind::ByteString =>
            {
                if slot.string_view.is_none() {
                    let view = group.vm.with_byte_string(object, |string| {
                        if let Some((pointer, len)) = string.external_pointer() {
                            Ok(SlotStringView::External {
                                pointer: pointer.cast(),
                                len,
                            })
                        } else {
                            StringView::new(&group.vm, string.as_bytes()).map(SlotStringView::Owned)
                        }
                    })??;
                    slot.string_view = Some(view);
                }
                let view = slot.string_view.as_ref().ok_or(StackError::Layout)?;
                Ok(Some(view.pointer_len()))
            }
            StackValue::Core(value @ (Value::Integer(_) | Value::Float(_))) => {
                let (bytes, len) = group.vm.format_lua_number(value)?;
                let view = StringView::new(&group.vm, &bytes[..len])?;
                let pointer = view.as_ptr();
                group
                    .vm
                    .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                        let mut replacement =
                            StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                        replacement.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                        *slot = replacement;
                        Ok(Some((pointer, len)))
                    })
            }
            _ => Ok(None),
        }
    }

    fn checked_lstring(&self, index: c_int) -> Result<(*const c_char, usize), StackError> {
        self.to_string(index)?.ok_or(StackError::InvalidIndex)
    }

    fn value_type(&self, index: c_int) -> Result<c_int, StackError> {
        self.validate()?;
        let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let position = match resolve_read_index(index, stack.slots.len()) {
            Ok(position) => position,
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                return Ok(LUA_TNONE);
            }
            Err(error) => return Err(error),
        };
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        if let ReadIndex::Upvalue(upvalue) = position {
            let Some(frame) = group.callback_frames.entries.last() else {
                return Ok(LUA_TNONE);
            };
            if group
                .vm
                .external_capture_cell(frame.token, upvalue)?
                .is_none()
            {
                return Ok(LUA_TNONE);
            }
        }
        match read_at_index(position, &stack, &group)? {
            StackValue::Core(Value::LightUserdata(_)) => Ok(LUA_TLIGHTUSERDATA),
            StackValue::Core(Value::Nil) => Ok(LUA_TNIL),
            StackValue::Core(Value::Boolean(_)) => Ok(LUA_TBOOLEAN),
            StackValue::Core(Value::Integer(_) | Value::Float(_)) => Ok(LUA_TNUMBER),
            StackValue::Core(Value::CFunction(id)) => Ok(if group.functions.get(id).is_some() {
                LUA_TFUNCTION
            } else {
                LUA_TNONE
            }),
            StackValue::Core(Value::Object(object)) => Ok(match group.vm.object_kind(object)? {
                ObjectKind::ByteString => LUA_TSTRING,
                ObjectKind::Table => LUA_TTABLE,
                ObjectKind::Closure | ObjectKind::CClosure | ObjectKind::Builtin => LUA_TFUNCTION,
                ObjectKind::Coroutine => LUA_TTHREAD,
                ObjectKind::Userdata | ObjectKind::File => LUA_TUSERDATA,
                ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => LUA_TNONE,
            }),
        }
    }
}

#[repr(C)]
struct StateAllocation {
    extraspace: Cell<[u8; EXTRASPACE]>,
    control: StateControl,
    group_owner: Option<Rc<RefCell<StateGroup>>>,
}

struct CoroutineStateAttachment {
    allocation: Option<Rc<StateAllocation>>,
    charge: Option<HostAllocationCharge>,
}

impl Drop for CoroutineStateAttachment {
    fn drop(&mut self) {
        drop(self.allocation.take());
        drop(self.charge.take());
    }
}

/// Rust 所有的有效 C state；C constructor 可將同一配置移交給 C 持有。
#[doc(hidden)]
pub struct StateOwner {
    allocation: Option<Rc<StateAllocation>>,
}

fn release_state_owner_allocation(allocation: Rc<StateAllocation>) {
    if allocation.control.main_control {
        allocation.control.main_pointer.set(std::ptr::null_mut());
        if let Some(group) = allocation.control.group.upgrade() {
            if let Ok(mut group) = group.try_borrow_mut() {
                group.main_allocation = Weak::new();
            }
        }
    }
    if let Ok(mut allocation) = Rc::try_unwrap(allocation) {
        let charge = allocation.control._charge.take();
        drop(allocation);
        // StateAllocation backing 已釋放；state token 最後才退還。
        drop(charge);
    }
}

impl Drop for StateOwner {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.take() {
            release_state_owner_allocation(allocation);
        }
    }
}

impl StateOwner {
    pub fn new() -> Result<Self, StackError> {
        Self::new_with_vm_setup(|_| {})
    }

    /// 由 Rust owner 明確執行 Lua shutdown finalizers，再依原群組次序釋放 native leases。
    /// 成功後本 owner 失效；失敗時仍可清除故障條件並重試。
    pub fn close_with_finalizers(&mut self) -> Result<(), StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        if !allocation.control.main_control || allocation.control.c_owned.get() {
            return Err(StackError::InvalidState);
        }
        let pointer = self.as_ptr();
        // SAFETY：本 owner 的 Rc 在整段同步 preflight 期間保活 main state。
        unsafe { close_main_preflight_b11(pointer, false)? };
        let previous_failure = {
            let group_owner = allocation
                .control
                .group
                .upgrade()
                .ok_or(StackError::InvalidState)?;
            let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
            group.vm.allocation_trace().last_failure
        };

        // SAFETY：額外 raw strong 僅供原 C close_drop 消耗；Rust owner 自己的
        // strong 保證 C driver 返回前後 control 位址有效。失敗時由本函式取回。
        let raw = Rc::into_raw(Rc::clone(allocation));
        allocation.control.c_owned.set(true);
        // SAFETY：沒有 VM／RefCell 借用跨純 C coordinator；它同步執行 Lua callback。
        let closed = unsafe { rivetlua_capi_close_status_b2(pointer) } == 1;
        if closed {
            let owned = self.allocation.take().ok_or(StackError::InvalidState)?;
            release_state_owner_allocation(owned);
            return Ok(());
        }

        // SAFETY：C driver 只在回傳成功時由 close_drop 消耗額外 strong；失敗
        // 時 state 仍 live，raw 正好是本函式剛移交且尚未還原的一份 Rc。
        unsafe { drop(Rc::from_raw(raw)) };
        allocation.control.c_owned.set(false);
        let current_failure = {
            let group_owner = allocation
                .control
                .group
                .upgrade()
                .ok_or(StackError::InvalidState)?;
            let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
            group.vm.allocation_trace().last_failure
        };
        if current_failure != previous_failure {
            if let Some(failure) = current_failure {
                return Err(StackError::Runtime(match failure.kind {
                    AllocationFailureKind::Injection => {
                        VmError::InjectedAllocation(failure.attempt)
                    }
                    AllocationFailureKind::Arithmetic => VmError::ArithmeticOverflow,
                    _ => VmError::AllocationFailed,
                }));
            }
        }
        Err(StackError::InvalidState)
    }

    pub fn new_with_allocator(
        function: LuaAlloc,
        user_data: *mut c_void,
    ) -> Result<Self, StackError> {
        Self::new_with_allocator_setup(Rc::new(CAllocatorState::new(function, user_data)), |_| {})
    }

    /// 測試用建構入口：在 state 配置前調整 VM 額度，不借出 VM 的 heap 指標。
    #[doc(hidden)]
    pub fn new_with_vm_setup(setup: impl FnOnce(&mut Vm)) -> Result<Self, StackError> {
        Self::new_with_allocator_setup(Rc::new(crate::allocator::default_state()), setup)
    }

    fn new_with_allocator_setup(
        allocator: Rc<CAllocatorState>,
        setup: impl FnOnce(&mut Vm),
    ) -> Result<Self, StackError> {
        let profile = if cfg!(feature = "lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mut vm = Vm::new_with_profile_and_admission(profile, allocator.clone())?;
        setup(&mut vm);
        let generation = next_generation()?;
        let group_bytes = group_accounted_bytes()?;
        let charge = vm.reserve_host_allocation(group_bytes)?.commit()?;
        let (registry, registry_host) =
            vm.prepare_unpublished_host_table(0, 0, |_| Ok::<(), StackError>(()))?;
        let (globals, globals_host) =
            vm.prepare_unpublished_host_table(0, 0, |_| Ok::<(), StackError>(()))?;
        vm.raw_set(
            registry,
            Value::Integer(LUA_RIDX_GLOBALS),
            Value::Object(globals),
        )?;
        #[cfg(feature = "lua55")]
        vm.raw_set(
            registry,
            Value::Integer(REF_FREELIST_KEY),
            Value::Boolean(false),
        )?;
        let registry_root = vm.add_root(RootKind::Registry, registry)?;
        let emergency_view = StringView::new(&vm, MEMORY_ERROR_BYTES)?;
        let (emergency_error, emergency_root) =
            vm.with_unpublished_byte_string(emergency_view.as_bytes(), |vm, object| {
                let root = vm.add_root(RootKind::Registry, object)?;
                Ok::<_, StackError>((object, root))
            })?;
        let main_thread = vm.prepare_unpublished_host_coroutine(
            |vm, object| {
                vm.raw_set(
                    registry,
                    Value::Integer(LUA_RIDX_MAINTHREAD),
                    Value::Object(object),
                )?;
                Ok::<_, StackError>(((), None))
            },
            |_, _, _| {},
        )?;
        let main_thread_root = vm.add_root(RootKind::Coroutine, main_thread)?;
        let hook_bridge_id = HostFunctionId::new_unique(vm.id())
            .ok_or(StackError::Runtime(VmError::IdentityExhausted))?;
        let mut hook_bridge_host = None;
        let hook_bridge = vm.prepare_unpublished_c_closure::<StackError>(
            hook_bridge_id,
            &[Value::Nil],
            |_, _| Ok(()),
            |_, root| hook_bridge_host = Some(root),
        )?;
        let hook_bridge_root = vm.add_root(RootKind::Registry, hook_bridge)?;
        drop(hook_bridge_host);
        drop(globals_host);
        drop(registry_host);
        let main_pointer = Rc::new(Cell::new(std::ptr::null_mut()));
        let group = Rc::new(RefCell::new(StateGroup {
            vm,
            allocator,
            registry_value: StackValue::Core(Value::Object(registry)),
            registry_root: Some(registry_root),
            main_thread,
            _main_thread_root: main_thread_root,
            main_pointer,
            main_allocation: Weak::new(),
            hook_bridge,
            hook_bridge_id,
            _hook_bridge_root: hook_bridge_root,
            emergency_error,
            _emergency_root: emergency_root,
            emergency_view,
            generation,
            functions: HostFunctionRegistry::new(),
            callback_frames: CallbackFrames::new(),
            warning: WarningBindingB6::disabled(),
            panic_callback: None,
            _charge: charge,
            native_leases: NativeLeases::new(),
        }));
        let owner = Self::attach(Rc::clone(&group), Some(main_thread), true)?;
        if let Some(allocation) = owner.allocation.as_ref() {
            group
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)?
                .main_allocation = Rc::downgrade(allocation);
        }
        Ok(owner)
    }

    /// 測試用邏輯配置元件大小；Rc 配器額外內部成本不屬於此帳本契約。
    #[doc(hidden)]
    pub const fn allocation_component_sizes() -> (usize, usize, usize, usize) {
        (
            size_of::<StateGroup>(),
            size_of::<RefCell<StateGroup>>(),
            align_of::<RefCell<StateGroup>>(),
            size_of::<StateAllocation>(),
        )
    }

    /// 建立同一 VM 的另一個 overlay state，供 xmove 的本片基礎測試使用。
    pub fn new_sibling(&self) -> Result<Self, StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let group = allocation
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        Self::attach(group, None, false)
    }

    /// 在載入 native library 前預留保留量與一筆 lease entry；票據不借用 VM。
    pub fn reserve_native_lease(
        &self,
        retained_bytes: usize,
    ) -> Result<NativeLeaseReservation, StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let group_owner = allocation
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let retained = group.vm.reserve_host_allocation(retained_bytes)?;
        let prepared = group.native_leases.prepare_capacity(&group.vm)?;
        Ok(NativeLeaseReservation {
            state: Rc::downgrade(allocation),
            group: Rc::downgrade(&group_owner),
            state_generation: allocation.control.state_generation,
            group_generation: group.generation,
            entry_count: group.native_leases.entries.len(),
            retained: Some(retained),
            prepared,
        })
    }

    /// 將 P05 已驗證 root closure 發布至 C stack，成功後由 slot HostHandle 持根。
    pub fn push_verified_module(&self, module: VerifiedModule) -> Result<(), StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let expected_profile = if cfg!(feature = "lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        if module.format_version() != RVLU_V2 || module.profile() != expected_profile {
            return Err(StackError::Number(RuntimeError::new(
                RuntimeErrorKind::UnsupportedFormat,
            )));
        }
        let group_owner = allocation
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = allocation
            .control
            .stack
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        let registry = group.registry_table()?;
        let Value::Object(environment) = group
            .vm
            .raw_get(registry, Value::Integer(LUA_RIDX_GLOBALS))?
        else {
            return Err(StackError::InvalidIndex);
        };
        if group.vm.object_kind(environment)? != ObjectKind::Table {
            return Err(StackError::InvalidIndex);
        }
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        let (closure, temporary_root) = group
            .vm
            .capi_loaded_chunk_closure(module, Value::Object(environment))?;
        let prepared = StackSlot::new(&mut group.vm, StackValue::Core(Value::Object(closure)));
        let removed = group.vm.remove_root(temporary_root);
        let slot = match (prepared, removed) {
            (Ok(slot), Ok(_)) => slot,
            (Err(error), Ok(_)) => return Err(error),
            (_, Err(error)) => return Err(error.into()),
        };
        stack.slots.push(slot);
        Ok(())
    }

    /// 在純 C checkpoint 執行 `luaL_requiref`，回傳 Lua status 並保留結果或錯誤 slot。
    ///
    /// # Safety
    /// `opener` 與其 library lease 必須在整個呼叫及後續 C binding 期間有效，且遵守
    /// 固定的 CNoUnwind 契約。Lua longjmp 只能返回本函式呼叫的純 C checkpoint，
    /// 不得跳過任何持有 Rust 資源的 live frame；native constructor 亦須遵守此約束。
    /// `name` 的借用須涵蓋同步 C driver 返回，driver 不得保存其指標。
    pub unsafe fn requiref_protected(
        &self,
        name: &CStr,
        opener: unsafe extern "C" fn(*mut lua_State) -> c_int,
        global: bool,
    ) -> Result<c_int, StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let pointer = self.as_ptr();
        // SAFETY：呼叫者保證 opener／library 有效且 CNoUnwind；driver 在純 C
        // checkpoint 捕捉 Lua 跳轉並同步返回，不保存 name 指標。此處沒有
        // StateGroup／VM／stack 的 Rust 借用。
        let status = unsafe {
            rivetlua_capi_requiref_protected_b2(pointer, name.as_ptr(), opener, c_int::from(global))
        };
        if status < 0 {
            Err(StackError::InvalidState)
        } else {
            Ok(status)
        }
    }

    /// B10b1 測試專用：暫時把同 VM 已保根的 coroutine 綁為 sibling state。
    /// 呼叫者須持有原 HostHandle，且同一 object 同時只建立一個此類 owner；
    /// 這不是正式 C thread attachment，不能由公開 C ABI 取得或延長物件生命週期。
    #[doc(hidden)]
    pub fn debug_test_attach_suspended_coroutine_once(
        &self,
        object: ObjectRef,
    ) -> Result<Self, StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let group = allocation
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        {
            let borrowed = group.try_borrow().map_err(|_| StackError::Busy)?;
            if borrowed.vm.id() != allocation.control.vm_id
                || borrowed.vm.object_kind(object)? != ObjectKind::Coroutine
                || borrowed
                    .vm
                    .with_coroutine_host_attachment::<CoroutineStateAttachment, _>(
                        object,
                        |attachment| attachment.is_some(),
                    )?
            {
                return Err(StackError::WrongVm);
            }
        }
        Self::attach(group, Some(object), false)
    }

    fn attach(
        group: Rc<RefCell<StateGroup>>,
        thread_identity: Option<ObjectRef>,
        main_control: bool,
    ) -> Result<Self, StackError> {
        if offset_of!(StateAllocation, control) != EXTRASPACE
            || align_of::<StateAllocation>() < align_of::<StateControl>()
            || size_of::<StateAllocation>() < EXTRASPACE + size_of::<StateControl>()
        {
            return Err(StackError::Layout);
        }
        let generation = next_generation()?;
        let (vm_id, group_generation, charge, allocator, main_pointer) = {
            let group = group.try_borrow().map_err(|_| StackError::Busy)?;
            let charge = group
                .vm
                .reserve_host_allocation(size_of::<StateAllocation>())?
                .commit()?;
            (
                group.vm.id(),
                group.generation,
                charge,
                Rc::clone(&group.allocator),
                Rc::clone(&group.main_pointer),
            )
        };
        let allocation = Rc::new(StateAllocation {
            extraspace: Cell::new([0; EXTRASPACE]),
            control: StateControl {
                magic: Cell::new(LIVE_MAGIC),
                live: Cell::new(true),
                c_owned: Cell::new(false),
                state_generation: generation,
                group_generation,
                thread_owner: thread::current().id(),
                vm_id,
                group: Rc::downgrade(&group),
                main_pointer: Rc::clone(&main_pointer),
                thread_identity,
                main_control,
                allocator,
                stack: RefCell::new(StackStorage::new()),
                debug: RefCell::new(DebugState::new()),
                hook: Cell::new(HookBinding::disabled()),
                pending_error: RefCell::new(None),
                checkpoint_depth: Cell::new(0),
                checkpoint_token: Cell::new(0),
                next_checkpoint_token: Cell::new(0),
                a5_status: Cell::new(0),
                suspended_a5: RefCell::new(None),
                reset_public_a5: RefCell::new(None),
                reset_permit_a5: Cell::new(None),
                continuations_a5: RefCell::new(ContinuationStackA5::new()),
                test_fail_close_boundary_root_a5: Cell::new(false),
                _charge: Some(charge),
            },
            group_owner: Some(group),
        });
        if main_control {
            main_pointer.set(
                (&allocation.control as *const StateControl)
                    .cast_mut()
                    .cast(),
            );
        }
        Ok(Self {
            allocation: Some(allocation),
        })
    }

    /// 指標只在此 owner 存活期間有效；移動 owner 不改變 control 位址。
    pub fn as_ptr(&self) -> *mut lua_State {
        self.allocation
            .as_ref()
            .map_or(std::ptr::null_mut(), |allocation| {
                (&allocation.control as *const StateControl)
                    .cast_mut()
                    .cast::<lua_State>()
            })
    }

    fn into_c_ptr(mut self) -> *mut lua_State {
        let Some(allocation) = self.allocation.take() else {
            return std::ptr::null_mut();
        };
        allocation.control.c_owned.set(true);
        let pointer = (&allocation.control as *const StateControl)
            .cast_mut()
            .cast::<lua_State>();
        // Rc::into_raw 只移交唯一 strong；lua_close 依同一來源還原 Rc 並 drop。
        let _allocation = Rc::into_raw(allocation);
        pointer
    }

    /// 整合測試與後續 C adapter 使用的受控 VM 借用；期間重入 C API 會 fail-closed。
    pub fn with_vm<R>(&self, f: impl FnOnce(&mut Vm) -> R) -> Result<R, StackError> {
        let allocation = self.allocation.as_ref().ok_or(StackError::InvalidState)?;
        allocation.control.validate()?;
        let group_owner = allocation
            .control
            .group
            .upgrade()
            .ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        Ok(f(&mut group.vm))
    }

    pub fn push_value(&self, value: Value) -> Result<(), StackError> {
        self.allocation
            .as_ref()
            .ok_or(StackError::InvalidState)?
            .control
            .push(StackValue::Core(value))
    }
}

fn group_accounted_bytes() -> Result<usize, StackError> {
    // Rc 的邏輯配置包括 strong/weak 兩個計數器和完整 RefCell payload，
    // 並納入 payload 對齊填充；不承諾 Rust Rc 私有實作或配器 metadata 大小。
    let header = Layout::array::<Cell<usize>>(2).map_err(|_| StackError::StackLimit)?;
    let (combined, _) = header
        .extend(Layout::new::<RefCell<StateGroup>>())
        .map_err(|_| StackError::StackLimit)?;
    Ok(combined.pad_to_align().size())
}

impl Drop for StateAllocation {
    fn drop(&mut self) {
        self.control.live.set(false);
        self.control.magic.set(0);
        // Box、slot handle 與配置票據依 RAII 退還；close 後的裸指標不再可用。
    }
}

fn next_generation() -> Result<u64, StackError> {
    NEXT_STATE_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| StackError::Runtime(VmError::IdentityExhausted))
}

fn resolve_stack_index(index: c_int, top: usize) -> Result<usize, StackError> {
    if index <= REGISTRY_INDEX {
        return Err(StackError::PseudoIndexUnavailable);
    }
    if index > 0 {
        let position = index as usize - 1;
        return (position < top)
            .then_some(position)
            .ok_or(StackError::InvalidIndex);
    }
    if index < 0 {
        let position = top as i64 + index as i64;
        return usize::try_from(position)
            .ok()
            .filter(|&position| position < top)
            .ok_or(StackError::InvalidIndex);
    }
    Err(StackError::InvalidIndex)
}

#[derive(Clone, Copy)]
enum ReadIndex {
    Stack(usize),
    Registry,
    Upvalue(usize),
}

fn resolve_read_index(index: c_int, top: usize) -> Result<ReadIndex, StackError> {
    if index == REGISTRY_INDEX {
        Ok(ReadIndex::Registry)
    } else if index < REGISTRY_INDEX {
        let distance = REGISTRY_INDEX
            .checked_sub(index)
            .ok_or(StackError::PseudoIndexUnavailable)?;
        let upvalue = usize::try_from(distance)
            .ok()
            .filter(|&distance| (1..=255).contains(&distance))
            .ok_or(StackError::PseudoIndexUnavailable)?;
        Ok(ReadIndex::Upvalue(upvalue - 1))
    } else {
        resolve_stack_index(index, top).map(ReadIndex::Stack)
    }
}

fn read_at_index(
    index: ReadIndex,
    stack: &StackStorage,
    group: &StateGroup,
) -> Result<StackValue, StackError> {
    match index {
        ReadIndex::Stack(position) => stack.slots[position].checked_value(&group.vm),
        ReadIndex::Registry => Ok(group.registry_value),
        ReadIndex::Upvalue(index) => {
            let frame = group
                .callback_frames
                .entries
                .last()
                .ok_or(StackError::PseudoIndexUnavailable)?;
            Ok(StackValue::Core(
                group
                    .vm
                    .external_capture(frame.token, index)?
                    .unwrap_or(Value::Nil),
            ))
        }
    }
}

fn table_at_index(
    index: c_int,
    stack: &StackStorage,
    group: &StateGroup,
) -> Result<ObjectRef, StackError> {
    let StackValue::Core(Value::Object(table)) =
        read_at_index(resolve_read_index(index, stack.slots.len())?, stack, group)?
    else {
        return Err(StackError::InvalidIndex);
    };
    if group.vm.object_kind(table)? != ObjectKind::Table {
        return Err(StackError::InvalidIndex);
    }
    Ok(table)
}

fn metatable_target_at_index(
    index: c_int,
    stack: &StackStorage,
    group: &StateGroup,
) -> Result<Value, StackError> {
    let StackValue::Core(value) =
        read_at_index(resolve_read_index(index, stack.slots.len())?, stack, group)?
    else {
        return Err(StackError::InvalidIndex);
    };
    checked_value_tag(&group.vm, value)?;
    Ok(value)
}

fn lookup_close_method_b7(vm: &mut Vm, object: ObjectRef) -> Result<Value, StackError> {
    let Some(metatable) = vm.get_metatable(object)? else {
        return Ok(Value::Nil);
    };
    vm.with_temporary_byte_string(b"__close", |vm, key| {
        vm.raw_get(metatable, Value::Object(key))
            .map_err(StackError::from)
    })
}

fn globals_table(group: &StateGroup) -> Result<ObjectRef, StackError> {
    let registry = group.registry_table()?;
    let Value::Object(globals) = group
        .vm
        .raw_get(registry, Value::Integer(LUA_RIDX_GLOBALS))?
    else {
        return Err(StackError::InvalidIndex);
    };
    if group.vm.object_kind(globals)? != ObjectKind::Table {
        return Err(StackError::InvalidIndex);
    }
    Ok(globals)
}

fn freelist_next(vm: &Vm, table: ObjectRef, reference: i64) -> Result<i64, StackError> {
    match vm.raw_get(table, Value::Integer(reference))? {
        Value::Integer(next) if (0..=i64::from(c_int::MAX)).contains(&next) => Ok(next),
        _ => Err(StackError::InvalidIndex),
    }
}

/// 只有固定生命週期內的有效 `lua_State*` 可進入；任意偽造或已關閉指標屬呼叫者無效操作。
unsafe fn checked_state<'a>(pointer: *mut lua_State) -> Result<&'a StateControl, StackError> {
    // SAFETY：前置條件與下方共用驗證器相同。
    unsafe { checked_state_mode(pointer, false) }
}

unsafe fn checked_debug_state<'a>(pointer: *mut lua_State) -> Result<&'a StateControl, StackError> {
    // SAFETY：debug 入口可觀測同 group 的另一個 state，但不能借用它的 C callback frame。
    unsafe { checked_state_mode(pointer, true) }
}

unsafe fn checked_state_mode<'a>(
    pointer: *mut lua_State,
    debug: bool,
) -> Result<&'a StateControl, StackError> {
    if pointer.is_null() {
        return Err(StackError::InvalidState);
    }
    // SAFETY：有效 state 指標是 C 呼叫者的前置條件；在建立含 RefCell 的共享參照前，
    // 僅讀取建立後不變的執行緒身分，避免跨執行緒產生非 Sync 參照。
    let owner =
        unsafe { std::ptr::addr_of!((*pointer.cast::<StateControl>()).thread_owner).read() };
    if owner != thread::current().id() {
        return Err(StackError::InvalidState);
    }
    // SAFETY：C 呼叫者保證 pointer 指向仍存活的 StateAllocation.control，
    // 且其對齊、來源及生命週期有效；只建立共享參照，變動透過 Cell/RefCell 管理。
    let control = unsafe { &*pointer.cast::<StateControl>() };
    if debug {
        control.validate_debug()?;
    } else {
        control.validate()?;
    }
    Ok(control)
}

fn ffi_boundary<R: Copy>(default: R, operation: impl FnOnce() -> Result<R, StackError>) -> R {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(_)) | Err(_) => default,
    }
}

fn with_state<R: Copy>(
    pointer: *mut lua_State,
    default: R,
    operation: impl FnOnce(&StateControl) -> Result<R, StackError>,
) -> R {
    ffi_boundary(default, || {
        // SAFETY：有效期間的 C state 是此 API 的前置條件；checked_state 再驗 magic／身分。
        let control = unsafe { checked_state(pointer)? };
        operation(control)
    })
}

fn with_debug_state<R: Copy>(
    pointer: *mut lua_State,
    default: R,
    operation: impl FnOnce(&StateControl) -> Result<R, StackError>,
) -> R {
    ffi_boundary(default, || {
        // SAFETY：有效 C state 為入口前置條件；debug 特例仍核對 thread/group/generation。
        let control = unsafe { checked_debug_state(pointer)? };
        operation(control)
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CallbackStepB4 {
    kind: c_int,
    value: c_int,
    function: Option<LuaCFunction>,
    hook: Option<LuaHook>,
    event: c_int,
    currentline: c_int,
    token: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ResumeSetupA5 {
    kind: c_int,
    status: c_int,
    nresults: c_int,
    resume_args: c_int,
    base: usize,
    step: CallbackStepB4,
    continuation: Option<LuaKFunction>,
    context: isize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ResumeFinishA5 {
    status: c_int,
    nresults: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ContinuationStepA5 {
    kind: c_int,
    protected: c_int,
    nresults: c_int,
    base: usize,
    continuation: Option<LuaKFunction>,
    context: isize,
    handler: *mut c_void,
}

impl ContinuationStepA5 {
    fn none() -> Self {
        Self {
            kind: 0,
            protected: 0,
            nresults: -1,
            base: 0,
            continuation: None,
            context: 0,
            handler: std::ptr::null_mut(),
        }
    }
}

impl ResumeSetupA5 {
    fn rejected(error: StackError) -> Self {
        Self {
            kind: -1,
            status: if operation_error_class_b5(error) == ErrorClass::Allocation as c_int {
                4
            } else {
                2
            },
            nresults: 0,
            resume_args: 0,
            base: 0,
            step: CallbackStepB4::done(),
            continuation: None,
            context: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PublicCallSetupA2 {
    kind: c_int,
    base: usize,
    handler: *mut c_void,
}

struct PublicErrorHandlerA2 {
    state_generation: u64,
    vm_id: VmId,
    slot: Option<StackSlot>,
    _charge: HostAllocationCharge,
}

impl PublicCallSetupA2 {
    fn rejected(error: StackError, base: usize) -> Self {
        Self {
            kind: -operation_error_class_b5(error),
            base,
            handler: std::ptr::null_mut(),
        }
    }
}

const _: () = {
    assert!(offset_of!(CallbackStepB4, function) == 2 * size_of::<c_int>());
    assert!(offset_of!(CallbackStepB4, hook) == 2 * size_of::<c_int>() + size_of::<LuaCFunction>());
    assert!(
        offset_of!(CallbackStepB4, event)
            == offset_of!(CallbackStepB4, hook) + size_of::<LuaHook>()
    );
    assert!(
        offset_of!(CallbackStepB4, token)
            == offset_of!(CallbackStepB4, event) + 2 * size_of::<c_int>()
    );
};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CloseStepB7 {
    kind: c_int,
    value: c_int,
}

impl CloseStepB7 {
    fn none() -> Self {
        Self { kind: 0, value: 0 }
    }

    fn skip() -> Self {
        Self { kind: 1, value: 0 }
    }

    fn invoke(nargs: c_int) -> Self {
        Self {
            kind: 2,
            value: nargs,
        }
    }

    fn error(error: StackError) -> Self {
        Self {
            kind: -1,
            value: operation_error_class_b5(error),
        }
    }
}

impl CallbackStepB4 {
    fn done() -> Self {
        Self {
            kind: 0,
            value: 0,
            function: None,
            hook: None,
            event: 0,
            currentline: 0,
            token: std::ptr::null_mut(),
        }
    }

    fn operation_done_b5() -> Self {
        Self {
            kind: 0,
            value: 1,
            function: None,
            ..Self::done()
        }
    }

    fn invoke(function: LuaCFunction) -> Self {
        Self {
            kind: 1,
            value: 0,
            function: Some(function),
            ..Self::done()
        }
    }

    fn close_boundary_a5(failed: bool) -> Self {
        Self {
            kind: 3,
            value: if failed { 2 } else { 0 },
            ..Self::done()
        }
    }

    fn invoke_hook(hook: LuaHook, event: c_int, currentline: c_int, token: usize) -> Self {
        Self {
            kind: 2,
            hook: Some(hook),
            event,
            currentline,
            token: token as *mut c_void,
            ..Self::done()
        }
    }

    fn error() -> Self {
        Self {
            kind: -1,
            value: -1,
            function: None,
            ..Self::done()
        }
    }

    fn operation_error_b5(error: StackError) -> Self {
        Self {
            kind: -1,
            value: operation_error_class_b5(error),
            function: None,
            ..Self::done()
        }
    }
}

fn operation_error_class_b5(error: StackError) -> c_int {
    let allocation = version_error_allocation_failed(error)
        || matches!(
            error,
            StackError::Number(RuntimeError {
                kind: RuntimeErrorKind::Heap(
                    VmError::AllocationFailed
                        | VmError::IdentityExhausted
                        | VmError::RootIdExhausted
                        | VmError::ArithmeticOverflow
                        | VmError::InjectedFailure(_)
                        | VmError::InjectedAllocation(_)
                ),
                ..
            })
        );
    if allocation {
        ErrorClass::Allocation as c_int
    } else {
        ErrorClass::Lua as c_int
    }
}

fn runtime_error_class_a2(error: RuntimeError) -> ErrorClass {
    if operation_error_class_b5(StackError::Number(error)) == ErrorClass::Allocation as c_int {
        return ErrorClass::Allocation;
    }
    match error.kind {
        RuntimeErrorKind::HostPolicyOutput
        | RuntimeErrorKind::HostPolicyEntropy
        | RuntimeErrorKind::HostPolicyLoad
        | RuntimeErrorKind::HostPolicyReader
        | RuntimeErrorKind::HostPolicyRepository
        | RuntimeErrorKind::HostPolicyNative
        | RuntimeErrorKind::HostPolicyIo
        | RuntimeErrorKind::HostPolicyOs
        | RuntimeErrorKind::HostPolicyDebug
        | RuntimeErrorKind::HostPolicyStringDump
        | RuntimeErrorKind::HostPathDenied => ErrorClass::Policy,
        RuntimeErrorKind::HostOutputFailed
        | RuntimeErrorKind::HostEntropyFailed
        | RuntimeErrorKind::HostIoFailed
        | RuntimeErrorKind::HostLoadFailed
        | RuntimeErrorKind::HostCancelled
        | RuntimeErrorKind::HostDeadline
        | RuntimeErrorKind::HostResourceBudget
        | RuntimeErrorKind::HostPlatformDifference
        | RuntimeErrorKind::HostUnsupported => ErrorClass::Host,
        _ => ErrorClass::Lua,
    }
}

fn callback_mode_b4(nresults: c_int) -> Result<ResultMode, StackError> {
    if nresults == -1 {
        Ok(ResultMode::All)
    } else {
        let count = u16::try_from(nresults).map_err(|_| StackError::InvalidIndex)?;
        Ok(ResultMode::Fixed(count))
    }
}

struct CallbackValuesB4 {
    values: Vec<Value>,
    _charge: HostAllocationCharge,
}

fn callback_values_b4(vm: &Vm, slots: &[StackSlot]) -> Result<CallbackValuesB4, StackError> {
    let bytes = slots
        .len()
        .checked_mul(size_of::<Value>())
        .ok_or(StackError::StackLimit)?;
    let ticket = vm.reserve_host_allocation(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(slots.len())
        .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
    let actual = values
        .capacity()
        .checked_mul(size_of::<Value>())
        .ok_or(StackError::StackLimit)?;
    if actual != bytes {
        return Err(StackError::Layout);
    }
    let charge = ticket.commit()?;
    let mut owned = CallbackValuesB4 {
        values,
        _charge: charge,
    };
    for slot in slots {
        let StackValue::Core(value) = slot.checked_value(vm)?;
        owned.values.push(value);
    }
    Ok(owned)
}

fn callback_core_values_b5(vm: &Vm, source: &[Value]) -> Result<CallbackValuesB4, StackError> {
    let bytes = source
        .len()
        .checked_mul(size_of::<Value>())
        .ok_or(StackError::StackLimit)?;
    let ticket = vm.reserve_host_allocation(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(source.len())
        .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
    if values.capacity().checked_mul(size_of::<Value>()) != Some(bytes) {
        return Err(StackError::Layout);
    }
    let charge = ticket.commit()?;
    values.extend_from_slice(source);
    Ok(CallbackValuesB4 {
        values,
        _charge: charge,
    })
}

fn operation_decode_b5(kind: c_int, operation: c_int) -> Result<ValueOperation, StackError> {
    match kind {
        0 => Ok(match operation {
            0 => ValueOperation::Binary(BinaryOperation::Add),
            1 => ValueOperation::Binary(BinaryOperation::Subtract),
            2 => ValueOperation::Binary(BinaryOperation::Multiply),
            3 => ValueOperation::Binary(BinaryOperation::Modulo),
            4 => ValueOperation::Binary(BinaryOperation::Power),
            5 => ValueOperation::Binary(BinaryOperation::Divide),
            6 => ValueOperation::Binary(BinaryOperation::FloorDivide),
            7 => ValueOperation::Binary(BinaryOperation::Ampersand),
            8 => ValueOperation::Binary(BinaryOperation::Pipe),
            9 => ValueOperation::Binary(BinaryOperation::BitXor),
            10 => ValueOperation::Binary(BinaryOperation::ShiftLeft),
            11 => ValueOperation::Binary(BinaryOperation::ShiftRight),
            12 => ValueOperation::Unary(UnaryOperation::Negate),
            13 => ValueOperation::Unary(UnaryOperation::BitNot),
            _ => return Err(StackError::InvalidIndex),
        }),
        1 => Ok(ValueOperation::Concat),
        2 | 4 => Ok(ValueOperation::Unary(UnaryOperation::Length)),
        3 => Ok(ValueOperation::Binary(match operation {
            0 => BinaryOperation::Equal,
            1 => BinaryOperation::Less,
            2 => BinaryOperation::LessEqual,
            _ => return Err(StackError::InvalidIndex),
        })),
        _ => Err(StackError::InvalidIndex),
    }
}

fn callback_event_values_b4(
    vm: &Vm,
    token: ExternalToken,
) -> Result<(HostFunctionId, CallbackValuesB4), StackError> {
    let view = vm.external_event(token)?;
    let bytes = view
        .args
        .len()
        .checked_mul(size_of::<Value>())
        .ok_or(StackError::StackLimit)?;
    let ticket = vm.reserve_host_allocation(bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(view.args.len())
        .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
    let actual = values
        .capacity()
        .checked_mul(size_of::<Value>())
        .ok_or(StackError::StackLimit)?;
    if actual != bytes {
        return Err(StackError::Layout);
    }
    let charge = ticket.commit()?;
    values.extend_from_slice(view.args);
    Ok((
        view.function,
        CallbackValuesB4 {
            values,
            _charge: charge,
        },
    ))
}

fn hook_event_b10(
    vm: &Vm,
    token: ExternalToken,
    bridge_id: HostFunctionId,
    bridge: ObjectRef,
) -> Result<Option<(c_int, c_int)>, StackError> {
    let view = vm.external_event(token)?;
    if view.function != bridge_id {
        return Ok(None);
    }
    if view.closure != Some(bridge) || view.args.len() != 2 {
        return Err(StackError::InvalidState);
    }
    let Value::Object(name) = view.args[0] else {
        return Err(StackError::InvalidState);
    };
    let event = vm.with_byte_string(name, |string| match string.as_bytes() {
        b"call" => Some(0),
        b"return" => Some(1),
        b"line" => Some(2),
        b"count" => Some(3),
        b"tail call" => Some(4),
        _ => None,
    })?;
    let event = event.ok_or(StackError::InvalidState)?;
    let currentline = if event == 2 {
        let Value::Integer(line) = view.args[1] else {
            return Err(StackError::InvalidState);
        };
        c_int::try_from(line).map_err(|_| StackError::InvalidState)?
    } else {
        if view.args[1] != Value::Nil {
            return Err(StackError::InvalidState);
        }
        -1
    };
    Ok(Some((event, currentline)))
}

fn callback_stack_b4(
    vm: &mut Vm,
    existing: &mut StackStorage,
    prefix_len: usize,
    append: &[Value],
    mode: ResultMode,
) -> Result<StackStorage, StackError> {
    let output_count = match mode {
        ResultMode::Fixed(count) => usize::from(count),
        ResultMode::All => append.len(),
    };
    let required = prefix_len
        .checked_add(output_count)
        .ok_or(StackError::StackLimit)?;
    vm.with_host_result_rooting(|vm| {
        let mut replacement = StackStorage::new();
        let prepared = replacement.prepare_capacity(vm, required)?;
        replacement.commit_capacity(prepared);
        let mark_count = existing
            .close_marks
            .partition_point(|&position| position < prefix_len);
        let prepared_marks = replacement.prepare_close_mark_capacity(vm, mark_count)?;
        replacement.commit_close_mark_capacity(prepared_marks);
        replacement
            .close_marks
            .extend_from_slice(&existing.close_marks[..mark_count]);
        for index in 0..output_count {
            let value = append.get(index).copied().unwrap_or(Value::Nil);
            replacement
                .slots
                .push(StackSlot::new(vm, StackValue::Core(value))?);
        }
        // 所有可失敗的配置已完成，搬移未受影響的前段 slot 以保留 Host root 身分。
        replacement.slots.extend(existing.slots.drain(..prefix_len));
        replacement.slots.rotate_right(prefix_len);
        Ok::<StackStorage, StackError>(replacement)
    })
}

impl StateControl {
    fn gc_prepare_b8(
        &self,
        what: c_int,
        bytes: usize,
        first: c_int,
        second: c_int,
        third: c_int,
    ) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let profile = if cfg!(feature = "lua54") {
            rivetlua_core::LuaProfile::Lua54
        } else {
            rivetlua_core::LuaProfile::Lua55
        };
        let control = match (profile, what) {
            (_, 0) => GcControl::Stop,
            (_, 1) => GcControl::Restart,
            (_, 2) => GcControl::Collect,
            (_, 3) => GcControl::Count,
            (_, 4) => GcControl::CountBytes,
            (_, 5) => GcControl::Step(bytes),
            (rivetlua_core::LuaProfile::Lua54, 6) => GcControl::SetPause(first),
            (rivetlua_core::LuaProfile::Lua54, 7) => GcControl::SetStepMultiplier(first),
            (rivetlua_core::LuaProfile::Lua54, 9) | (rivetlua_core::LuaProfile::Lua55, 6) => {
                GcControl::IsRunning
            }
            (rivetlua_core::LuaProfile::Lua54, 10) => GcControl::Generational {
                minor_mul: first,
                minor_major: second,
            },
            (rivetlua_core::LuaProfile::Lua54, 11) => GcControl::Incremental {
                pause: first,
                step_mul: second,
                step_size: third,
            },
            (rivetlua_core::LuaProfile::Lua55, 7) => GcControl::Generational {
                minor_mul: 0,
                minor_major: 0,
            },
            (rivetlua_core::LuaProfile::Lua55, 8) => GcControl::Incremental {
                pause: 0,
                step_mul: 0,
                step_size: 0,
            },
            (rivetlua_core::LuaProfile::Lua55, 9) => GcControl::Parameter {
                index: first,
                value: second,
            },
            _ => {
                return Ok(CallbackStepB4 {
                    kind: 0,
                    value: -1,
                    function: None,
                    ..CallbackStepB4::done()
                });
            }
        };
        let GcControlResult::Integer(answer) = match group.vm.gc_control(control) {
            Ok(result) => result,
            Err(VmError::FinalizerGcReentry | VmError::InvalidGcConfig) => {
                return Ok(CallbackStepB4 {
                    kind: 0,
                    value: -1,
                    function: None,
                    ..CallbackStepB4::done()
                });
            }
            Err(error) => return Err(error.into()),
        };
        if !matches!(
            control,
            GcControl::Collect
                | GcControl::Step(_)
                | GcControl::Generational { .. }
                | GcControl::Incremental { .. }
        ) || !group.vm.gc_finalizers_pending()
        {
            return Ok(CallbackStepB4 {
                kind: 0,
                value: answer,
                function: None,
                ..CallbackStepB4::done()
            });
        }
        let parent = group
            .callback_frames
            .entries
            .last()
            .map(|frame| frame.token);
        let outcome = {
            let mut execution = group.vm.gc_finalizer_execution(parent)?;
            execution.run()?
        };
        match outcome {
            RunOutcome::Returned(_) => Ok(CallbackStepB4 {
                kind: 0,
                value: answer,
                function: None,
                ..CallbackStepB4::done()
            }),
            RunOutcome::External(_) => {
                let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
                let base = stack.slots.len();
                let mut step = self.callback_outcome_b4(
                    &mut group,
                    &mut stack,
                    outcome,
                    base,
                    ResultMode::Fixed(0),
                )?;
                step.value = answer;
                Ok(step)
            }
            _ => Err(StackError::InvalidState),
        }
    }

    fn gc_resume_error_b8(&self) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?;
        if frame.owner_generation != self.state_generation
            || frame.depth != group.callback_frames.entries.len()
        {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        let pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take()
            .ok_or(StackError::InvalidState)?;
        let StackValue::Core(value) = pending.slot.checked_value(&group.vm)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let outcome = group
            .vm
            .continue_external(token, ExternalCommand::Error(value));
        let frame = group
            .callback_frames
            .entries
            .pop()
            .ok_or(StackError::InvalidState)?;
        debug.remove_external(frame.token);
        drop(debug);
        let base = frame.base();
        *stack = frame.saved_stack;
        group.callback_frames.release_empty();
        drop(pending);
        self.callback_outcome_b4(&mut group, &mut stack, outcome?, base, ResultMode::Fixed(0))
    }

    fn operation_prepare_b5(
        &self,
        kind: c_int,
        operation: c_int,
        left: c_int,
        right: c_int,
        count: c_int,
    ) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        if kind == 5 {
            let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
            let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let top = stack.slots.len();
            let index = resolve_read_index(left, top)?;
            let StackValue::Core(value) = read_at_index(index, &stack, &group)?;
            let event = if let Value::Object(object) = value {
                if matches!(
                    group.vm.object_kind(object)?,
                    ObjectKind::Table | ObjectKind::Userdata | ObjectKind::File
                ) {
                    group.vm.lookup_raw_metafield(object, b"__tostring")?
                } else {
                    Value::Nil
                }
            } else {
                Value::Nil
            };
            if event == Value::Nil {
                return Ok(CallbackStepB4::done());
            }
            let mut args = callback_core_values_b5(&group.vm, &[value])?;
            let token = group
                .callback_frames
                .entries
                .last()
                .map(|frame| frame.token);
            let outcome = if let Some(token) = token {
                group.vm.continue_external(
                    token,
                    ExternalCommand::NestedCall {
                        target: event,
                        args: std::mem::take(&mut args.values),
                        results: ResultMode::Fixed(1),
                    },
                )?
            } else {
                let mut execution = group.vm.call(event, &args.values)?;
                execution.run()?
            };
            let mut step = self.callback_outcome_b4(
                &mut group,
                &mut stack,
                outcome,
                top,
                ResultMode::Fixed(1),
            )?;
            if step.kind == 0 {
                step = CallbackStepB4::operation_done_b5();
            }
            return Ok(step);
        }
        let operation = operation_decode_b5(kind, operation)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.len();
        let (base, mut args) = match kind {
            0 | 1 => {
                let needed = if kind == 0 {
                    if matches!(operation, ValueOperation::Unary(_)) {
                        1
                    } else {
                        2
                    }
                } else {
                    usize::try_from(count).map_err(|_| StackError::InvalidIndex)?
                };
                let base = top.checked_sub(needed).ok_or(StackError::InvalidIndex)?;
                (base, callback_values_b4(&group.vm, &stack.slots[base..])?)
            }
            2 | 4 => {
                let index = resolve_read_index(left, top)?;
                let StackValue::Core(value) = read_at_index(index, &stack, &group)?;
                (top, callback_core_values_b5(&group.vm, &[value])?)
            }
            3 => {
                let first = match resolve_read_index(left, top) {
                    Ok(index) => index,
                    Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                        return Ok(CallbackStepB4::done());
                    }
                    Err(error) => return Err(error),
                };
                let second = match resolve_read_index(right, top) {
                    Ok(index) => index,
                    Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                        return Ok(CallbackStepB4::done());
                    }
                    Err(error) => return Err(error),
                };
                let first = match read_at_index(first, &stack, &group) {
                    Ok(StackValue::Core(value)) => value,
                    Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                        return Ok(CallbackStepB4::done());
                    }
                    Err(error) => return Err(error),
                };
                let second = match read_at_index(second, &stack, &group) {
                    Ok(StackValue::Core(value)) => value,
                    Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                        return Ok(CallbackStepB4::done());
                    }
                    Err(error) => return Err(error),
                };
                (top, callback_core_values_b5(&group.vm, &[first, second])?)
            }
            _ => return Err(StackError::InvalidIndex),
        };
        let token = group
            .callback_frames
            .entries
            .last()
            .map(|frame| frame.token);
        let outcome = if let Some(token) = token {
            group.vm.continue_external(
                token,
                ExternalCommand::NestedOperation {
                    operation,
                    args: std::mem::take(&mut args.values),
                },
            )?
        } else {
            let mut execution = group.vm.value_operation(operation, &args.values)?;
            execution.run()?
        };
        let mut step =
            self.callback_outcome_b4(&mut group, &mut stack, outcome, base, ResultMode::Fixed(1))?;
        if step.kind == 0 {
            step = CallbackStepB4::operation_done_b5();
        }
        Ok(step)
    }

    fn table_outcome_a4a(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        outcome: RunOutcome,
        base: usize,
        setter: bool,
    ) -> Result<CallbackStepB4, StackError> {
        if matches!(
            &outcome,
            RunOutcome::LuaError(error) | RunOutcome::NestedErrored(error)
                if error.kind == RuntimeErrorKind::MetatableChainLimit
        ) {
            return self.callback_pending_runtime_a2(
                group,
                stack,
                RuntimeError::new(RuntimeErrorKind::MetatableChainLimit),
            );
        }
        if let RunOutcome::LuaError(error) | RunOutcome::NestedErrored(error) = &outcome {
            let runtime = RuntimeError::new(error.kind);
            if runtime_error_class_a2(runtime) == ErrorClass::Allocation {
                return self.callback_pending_runtime_a2(group, stack, runtime);
            }
        }
        if setter
            && matches!(
                outcome,
                RunOutcome::Returned(_) | RunOutcome::NestedReturned(_)
            )
        {
            if !stack.can_remove_from(base) {
                return Err(StackError::InvalidIndex);
            }
            stack.slots.truncate(base);
            stack.release_empty_capacity();
            return Ok(CallbackStepB4::operation_done_b5());
        }
        let mode = if setter {
            ResultMode::Fixed(0)
        } else {
            ResultMode::Fixed(1)
        };
        let mut step = self.callback_outcome_public_a2(group, stack, outcome, base, mode)?;
        if step.kind == 0 {
            step = CallbackStepB4::operation_done_b5();
        }
        Ok(step)
    }

    fn table_operation_prepare_a4a(
        &self,
        index: c_int,
        setter: bool,
    ) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let top = stack.slots.len();
        let base = top
            .checked_sub(if setter { 2 } else { 1 })
            .ok_or(StackError::InvalidIndex)?;
        if !stack.can_remove_from(base) {
            return Err(StackError::InvalidIndex);
        }
        let StackValue::Core(target) =
            read_at_index(resolve_read_index(index, top)?, &stack, &group)?;
        let StackValue::Core(key) = stack.slots[base].checked_value(&group.vm)?;
        let mut args = if setter {
            let StackValue::Core(value) = stack.slots[base + 1].checked_value(&group.vm)?;
            callback_core_values_b5(&group.vm, &[target, key, value])?
        } else {
            callback_core_values_b5(&group.vm, &[target, key])?
        };
        let operation = if setter {
            ValueOperation::TableSet
        } else {
            ValueOperation::TableGet
        };
        let token = group
            .callback_frames
            .entries
            .last()
            .map(|frame| frame.token);
        let outcome = if let Some(token) = token {
            group.vm.continue_external(
                token,
                ExternalCommand::NestedOperation {
                    operation,
                    args: std::mem::take(&mut args.values),
                },
            )
        } else {
            group
                .vm
                .value_operation(operation, &args.values)
                .and_then(|mut execution| execution.run())
        };
        match outcome {
            Ok(outcome) => self.table_outcome_a4a(&mut group, &mut stack, outcome, base, setter),
            Err(error) => self.callback_pending_runtime_a2(&mut group, &mut stack, error),
        }
    }

    fn operation_abort_to_b5(&self, depth: usize) -> Result<(), StackError> {
        self.callback_abort_to_b7(depth)
    }

    fn callback_outcome_b4(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        outcome: RunOutcome,
        base: usize,
        mode: ResultMode,
    ) -> Result<CallbackStepB4, StackError> {
        match outcome {
            RunOutcome::CloseBoundaryA5 { token, error } => {
                self.reset_boundary_outcome_a5(group, stack, token, error)
            }
            RunOutcome::External(token) => {
                let hook_event =
                    match hook_event_b10(&group.vm, token, group.hook_bridge_id, group.hook_bridge)
                    {
                        Ok(event) => event,
                        Err(error) => {
                            group.vm.abort_external(token)?;
                            return Err(error);
                        }
                    };
                if let Some((event, currentline)) = hook_event {
                    let prepared = self.callback_hook_outcome_b10(
                        group,
                        stack,
                        token,
                        base,
                        event,
                        currentline,
                    );
                    if prepared.is_err() {
                        if let Ok(mut debug) = self.debug.try_borrow_mut() {
                            debug.remove_external(token);
                        }
                        group.vm.abort_external(token)?;
                    }
                    return prepared;
                }
                let (function, args) = match callback_event_values_b4(&group.vm, token) {
                    Ok(values) => values,
                    Err(error) => {
                        group.vm.abort_external(token)?;
                        return Err(error);
                    }
                };
                let Some(c_function) = group.functions.get(function) else {
                    group.vm.abort_external(token)?;
                    return Err(StackError::WrongVm);
                };
                let prepared = match group.callback_frames.prepare_capacity(&group.vm) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        group.vm.abort_external(token)?;
                        return Err(error);
                    }
                };
                let callback_stack = match callback_stack_b4(
                    &mut group.vm,
                    &mut StackStorage::new(),
                    0,
                    &args.values,
                    ResultMode::All,
                ) {
                    Ok(stack) => stack,
                    Err(error) => {
                        group.vm.abort_external(token)?;
                        return Err(error);
                    }
                };
                let saved_stack = std::mem::replace(stack, callback_stack);
                let depth = group.callback_frames.entries.len() + 1;
                group.callback_frames.push(
                    prepared,
                    CallbackFrame {
                        token,
                        depth,
                        owner_generation: self.state_generation,
                        call_base: base,
                        saved_stack,
                    },
                );
                Ok(CallbackStepB4::invoke(c_function))
            }
            RunOutcome::Returned(values) | RunOutcome::NestedReturned(values) => {
                if !stack.can_remove_from(base) {
                    return Err(StackError::InvalidIndex);
                }
                let replacement = callback_stack_b4(&mut group.vm, stack, base, &values, mode)?;
                *stack = replacement;
                Ok(CallbackStepB4::done())
            }
            _ => Err(StackError::InvalidIndex),
        }
    }

    fn reset_boundary_outcome_a5(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        token: ExternalToken,
        error: Option<Value>,
    ) -> Result<CallbackStepB4, StackError> {
        let mut reset = self
            .reset_public_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        let held = reset.as_mut().ok_or(StackError::InvalidState)?;
        if held.boundary_token.is_some() {
            return Err(StackError::Busy);
        }
        let next = held.outer_levels.last_mut().ok_or(StackError::Layout)?;
        if let Some(value) = error {
            next.ensure_capacity(&group.vm, next.slots.len() + 1)?;
            // 同一 parked close core 的 error_root 持續保活此值；C checkpoint
            // 尚未交回 walker 前借用，不在已執行 handler 後新增 root 配額失敗點。
            next.slots.push(StackSlot {
                value: StackValue::Core(value),
                root: None,
                string_view: None,
            });
        }
        *stack = held.outer_levels.pop().ok_or(StackError::Layout)?;
        held.boundary_token = Some(token);
        Ok(CallbackStepB4::close_boundary_a5(error.is_some()))
    }

    fn callback_outcome_public_a2(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        outcome: RunOutcome,
        base: usize,
        mode: ResultMode,
    ) -> Result<CallbackStepB4, StackError> {
        match outcome {
            RunOutcome::LuaError(error) | RunOutcome::NestedErrored(error) => {
                self.callback_pending_value_a2(group, stack, error.value, ErrorClass::Lua)
            }
            RunOutcome::NestedFailed(error) => {
                self.callback_pending_runtime_a2(group, stack, error)
            }
            RunOutcome::Aborted(_) => {
                self.callback_pending_value_a2(group, stack, Value::Nil, ErrorClass::Aborted)
            }
            outcome => self.callback_outcome_b4(group, stack, outcome, base, mode),
        }
    }

    fn callback_hook_outcome_b10(
        &self,
        group: &mut StateGroup,
        stack: &mut StackStorage,
        token: ExternalToken,
        base: usize,
        event: c_int,
        currentline: c_int,
    ) -> Result<CallbackStepB4, StackError> {
        let hook = self.hook.get().callback.ok_or(StackError::InvalidState)?;
        let handle = group
            .vm
            .debug_hook_frame(token)?
            .ok_or(StackError::InvalidState)?;
        let prepared = group.callback_frames.prepare_capacity(&group.vm)?;
        let depth = group
            .callback_frames
            .entries
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let mut hook_stack = StackStorage::new();
        hook_stack.ensure_capacity(&group.vm, 1)?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let key = debug.register(
            &group.vm,
            DebugTokenOrigin::External(token),
            0,
            handle,
            None,
        )?;
        let saved_stack = std::mem::replace(stack, hook_stack);
        group.callback_frames.push(
            prepared,
            CallbackFrame {
                token,
                depth,
                owner_generation: self.state_generation,
                call_base: base,
                saved_stack,
            },
        );
        Ok(CallbackStepB4::invoke_hook(hook, event, currentline, key))
    }

    fn callback_prepare_b4(
        &self,
        nargs: c_int,
        nresults: c_int,
        public: bool,
    ) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let mode = callback_mode_b4(nresults)?;
        let nargs = usize::try_from(nargs).map_err(|_| StackError::InvalidIndex)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let base = stack
            .slots
            .len()
            .checked_sub(nargs.checked_add(1).ok_or(StackError::StackLimit)?)
            .ok_or(StackError::InvalidIndex)?;
        let StackValue::Core(target) = stack.slots[base].checked_value(&group.vm)?;
        let mut args = callback_values_b4(&group.vm, &stack.slots[base + 1..])?;
        let boundary_token = self
            .reset_public_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .as_ref()
            .and_then(|reset| reset.boundary_token);
        let token = if boundary_token.is_some() {
            None
        } else {
            group
                .callback_frames
                .entries
                .last()
                .map(|frame| frame.token)
        };
        let outcome = if let Some(token) = token {
            group.vm.continue_external(
                token,
                ExternalCommand::NestedCall {
                    target,
                    args: std::mem::take(&mut args.values),
                    results: mode,
                },
            )
        } else {
            group
                .vm
                .call(target, &args.values)
                .and_then(|mut execution| execution.run())
        };
        match outcome {
            Ok(outcome) if public => {
                self.callback_outcome_public_a2(&mut group, &mut stack, outcome, base, mode)
            }
            Ok(outcome) => self.callback_outcome_b4(&mut group, &mut stack, outcome, base, mode),
            Err(error) if public => self.callback_pending_runtime_a2(&mut group, &mut stack, error),
            Err(error) => Err(error.into()),
        }
    }

    fn public_call_preflight_a2(
        &self,
        nargs: c_int,
        nresults: c_int,
        errfunc: c_int,
    ) -> Result<PublicCallSetupA2, (StackError, usize)> {
        self.validate().map_err(|error| (error, 0))?;
        callback_mode_b4(nresults).map_err(|error| (error, 0))?;
        let nargs = usize::try_from(nargs).map_err(|_| (StackError::InvalidIndex, 0))?;
        let group_owner = self.group.upgrade().ok_or((StackError::InvalidState, 0))?;
        let mut group = group_owner
            .try_borrow_mut()
            .map_err(|_| (StackError::Busy, 0))?;
        let mut stack = self
            .stack
            .try_borrow_mut()
            .map_err(|_| (StackError::Busy, 0))?;
        let top = stack.slots.len();
        let base = top
            .checked_sub(nargs.checked_add(1).ok_or((StackError::StackLimit, 0))?)
            .ok_or((StackError::InvalidIndex, 0))?;
        // 無效 handler 必須在任何配置前拒絕，且不能更改 stack。
        let source = if errfunc == 0 {
            None
        } else {
            let index = resolve_stack_index(errfunc, top).map_err(|error| (error, 0))?;
            let source = stack
                .slots
                .get(index)
                .ok_or((StackError::InvalidIndex, 0))?;
            let StackValue::Core(value) = source
                .checked_value(&group.vm)
                .map_err(|error| (error, 0))?;
            if checked_value_tag(&group.vm, value).map_err(|error| (error, 0))? != LUA_TFUNCTION {
                return Err((StackError::InvalidIndex, 0));
            }
            Some(source)
        };
        let prepared = stack
            .prepare_capacity(
                &group.vm,
                top.checked_add(1).ok_or((StackError::StackLimit, base))?,
            )
            .map_err(|error| (error, base))?;
        let handler = if errfunc == 0 {
            None
        } else {
            let source = source.ok_or((StackError::InvalidState, 0))?;
            let ticket = group
                .vm
                .reserve_host_allocation(size_of::<PublicErrorHandlerA2>())
                .map_err(|error| (error.into(), base))?;
            let slot = source
                .try_clone(&mut group.vm)
                .map_err(|error| (error, base))?;
            let charge = ticket.commit().map_err(|error| (error.into(), base))?;
            Some(Box::new(PublicErrorHandlerA2 {
                state_generation: self.state_generation,
                vm_id: self.vm_id,
                slot: Some(slot),
                _charge: charge,
            }))
        };
        stack.commit_capacity(prepared);
        Ok(PublicCallSetupA2 {
            kind: 1,
            base,
            handler: handler
                .map(Box::into_raw)
                .unwrap_or(std::ptr::null_mut())
                .cast(),
        })
    }

    fn public_settle_error_a2(&self, base: usize) -> Result<(), StackError> {
        self.validate()?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if base >= stack.slots.len().saturating_sub(1) || !stack.can_remove_from(base) {
            return Err(StackError::InvalidIndex);
        }
        let error = stack.slots.pop().ok_or(StackError::InvalidIndex)?;
        stack.slots.truncate(base);
        stack.slots.push(error);
        Ok(())
    }

    fn public_settle_preflight_allocation_a2(&self, base: usize) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if base >= stack.slots.len() || !stack.can_remove_from(base) {
            return Err(StackError::InvalidIndex);
        }
        let error = StackSlot::permanent_rooted(
            &group.vm,
            group.emergency_error,
            Rc::clone(&group.emergency_view),
        )?;
        stack.slots.truncate(base);
        stack.slots.push(error);
        Ok(())
    }

    fn public_push_handler_a2(
        &self,
        handler: &mut PublicErrorHandlerA2,
        base: usize,
    ) -> Result<(), StackError> {
        self.validate()?;
        if handler.state_generation != self.state_generation || handler.vm_id != self.vm_id {
            return Err(StackError::WrongVm);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if base + 1 != stack.slots.len() || handler.slot.is_none() {
            return Err(StackError::InvalidIndex);
        }
        stack.ensure_capacity(
            &group.vm,
            base.checked_add(2).ok_or(StackError::StackLimit)?,
        )?;
        let slot = handler.slot.take().ok_or(StackError::InvalidState)?;
        stack.slots.insert(base, slot);
        Ok(())
    }

    fn callback_resume_b4(
        &self,
        count: c_int,
        nresults: c_int,
        public: bool,
        table_setter: Option<bool>,
    ) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let mode = callback_mode_b4(nresults)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?;
        if frame.owner_generation != self.state_generation
            || frame.depth != group.callback_frames.entries.len()
        {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        let count = usize::try_from(count)
            .ok()
            .filter(|&count| count <= stack.slots.len())
            .ok_or(StackError::InvalidIndex)?;
        let mut values = callback_values_b4(&group.vm, &stack.slots[stack.slots.len() - count..])?;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let outcome = group.vm.continue_external(
            token,
            ExternalCommand::Return(std::mem::take(&mut values.values)),
        );
        let frame = group
            .callback_frames
            .entries
            .pop()
            .ok_or(StackError::InvalidState)?;
        debug.remove_external(frame.token);
        drop(debug);
        let base = frame.base();
        *stack = frame.saved_stack;
        group.callback_frames.release_empty();
        match outcome {
            Ok(outcome) if let Some(setter) = table_setter => {
                self.table_outcome_a4a(&mut group, &mut stack, outcome, base, setter)
            }
            Ok(outcome) if public => {
                self.callback_outcome_public_a2(&mut group, &mut stack, outcome, base, mode)
            }
            Ok(outcome) => self.callback_outcome_b4(&mut group, &mut stack, outcome, base, mode),
            Err(error) if table_setter.is_some() => {
                self.callback_pending_runtime_a2(&mut group, &mut stack, error)
            }
            Err(error) if public => self.callback_pending_runtime_a2(&mut group, &mut stack, error),
            Err(error) => Err(error.into()),
        }
    }

    fn callback_resume_error_a2(&self, nresults: c_int) -> Result<CallbackStepB4, StackError> {
        self.validate()?;
        let mode = callback_mode_b4(nresults)?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?;
        if frame.owner_generation != self.state_generation
            || frame.depth != group.callback_frames.entries.len()
        {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        let pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take()
            .ok_or(StackError::InvalidState)?;
        let StackValue::Core(value) = pending.slot.checked_value(&group.vm)?;
        let class = pending.class;
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let outcome = group
            .vm
            .continue_external(token, ExternalCommand::Error(value));
        let frame = group
            .callback_frames
            .entries
            .pop()
            .ok_or(StackError::InvalidState)?;
        debug.remove_external(frame.token);
        drop(debug);
        let base = frame.base();
        *stack = frame.saved_stack;
        group.callback_frames.release_empty();
        drop(pending);
        match outcome {
            Ok(RunOutcome::LuaError(error) | RunOutcome::NestedErrored(error))
                if error.value == value && error.kind == RuntimeErrorKind::Thrown =>
            {
                self.callback_pending_value_a2(&mut group, &mut stack, error.value, class)
            }
            Ok(outcome) => {
                self.callback_outcome_public_a2(&mut group, &mut stack, outcome, base, mode)
            }
            Err(error) => self.callback_pending_runtime_a2(&mut group, &mut stack, error),
        }
    }

    fn callback_abort_to_b7(&self, depth: usize) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if depth > group.callback_frames.entries.len() {
            return Err(StackError::InvalidIndex);
        }
        let mut debug = self.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        while group.callback_frames.entries.len() > depth {
            let frame = group
                .callback_frames
                .entries
                .pop()
                .ok_or(StackError::InvalidState)?;
            debug.remove_external(frame.token);
            *stack = frame.saved_stack;
            group.vm.abort_external_nested_callback(frame.token)?;
        }
        drop(debug);
        group.callback_frames.release_empty();
        if let Some(pending) = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .as_mut()
        {
            if stack.slots.capacity() <= stack.slots.len() {
                return Err(StackError::StackLimit);
            }
            pending.original_top = stack.slots.len() + 1;
        }
        Ok(())
    }

    fn callback_abort_b4(&self) -> Result<(), StackError> {
        self.callback_abort_to_b7(0)
    }

    fn close_capture_error_b7(&self, trim_top: usize) -> Result<c_int, StackError> {
        self.validate()?;
        let mut pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        pending.as_ref().ok_or(StackError::InvalidState)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if trim_top > stack.slots.len() || trim_top == stack.slots.capacity() {
            return Err(StackError::InvalidIndex);
        }
        let error = pending.take().ok_or(StackError::InvalidState)?;
        stack.slots.truncate(trim_top);
        stack.slots.push(error.slot);
        Ok(error.class as c_int)
    }

    fn close_finalize_error_b7(
        &self,
        trim_top: usize,
        token: u64,
        class: c_int,
    ) -> Result<(), StackError> {
        self.validate()?;
        let class = ErrorClass::from_code(class).ok_or(StackError::InvalidIndex)?;
        let mut pending = self
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if pending.is_some() {
            return Err(StackError::Busy);
        }
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if trim_top >= stack.slots.len() || trim_top >= stack.slots.capacity() {
            return Err(StackError::InvalidIndex);
        }
        let error = stack.slots.pop().ok_or(StackError::InvalidIndex)?;
        stack.slots.truncate(trim_top);
        *pending = Some(PendingError {
            slot: error,
            class,
            token,
            original_top: trim_top + 1,
        });
        Ok(())
    }
}

/// 私有 B4 C driver step；任何 Rust panic 都在 ABI 邊界收斂為失敗。
/// B8 C varargs 已在純 C 解碼；這裡只處理型別化命令與同步 finalizer step。
///
/// # Safety
/// pointer 必須指向有效期內的 C state；入口以 checked_state 驗證且不保存指標。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_gc_prepare_b8(
    pointer: *mut lua_State,
    what: c_int,
    bytes: usize,
    first: c_int,
    second: c_int,
    third: c_int,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        Ok(
            match state.gc_prepare_b8(what, bytes, first, second, third) {
                Ok(step) => step,
                Err(error) => CallbackStepB4::operation_error_b5(error),
            },
        )
    })
}

/// C finalizer 錯誤由純 C checkpoint 收斂後，以相同 parked core 的 protected boundary 續接。
///
/// # Safety
/// pointer 必須是目前最上層 callback 所屬的有效 C state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_gc_resume_error_b8(
    pointer: *mut lua_State,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        Ok(match state.gc_resume_error_b8() {
            Ok(step) => step,
            Err(error) => CallbackStepB4::operation_error_b5(error),
        })
    })
}

/// 私有 B4 C driver step；任何 Rust panic 都在 ABI 邊界收斂為失敗。
///
/// # Safety
/// pointer 必須是有效的 lua_State，C driver 同步使用且不使其提前釋放。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_prepare_b4(
    pointer: *mut lua_State,
    nargs: c_int,
    nresults: c_int,
) -> CallbackStepB4 {
    ffi_boundary(CallbackStepB4::error(), || {
        // SAFETY：有效 state 是 C driver 的前置條件；checked_state 驗身分。
        unsafe { checked_state(pointer)? }.callback_prepare_b4(nargs, nresults, false)
    })
}

/// 私有 B4 C driver callback 完成 step；C 函式指標已返回且無 Rust 借用跨越。
///
/// # Safety
/// pointer 必須是有效的 lua_State，count 為 callback 回傳的整數。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_resume_b4(
    pointer: *mut lua_State,
    count: c_int,
    nresults: c_int,
) -> CallbackStepB4 {
    ffi_boundary(CallbackStepB4::error(), || {
        // SAFETY：有效 state 是 C driver 的前置條件；checked_state 驗身分。
        unsafe { checked_state(pointer)? }.callback_resume_b4(count, nresults, false, None)
    })
}

/// public call 使用同一 B4 parked execution，但保留可發布的 typed 錯誤。
///
/// # Safety
/// pointer 是 C coordinator 保活的 live state；Rust step 不保存它。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_prepare_a2(
    pointer: *mut lua_State,
    nargs: c_int,
    nresults: c_int,
) -> CallbackStepB4 {
    ffi_boundary(CallbackStepB4::error(), || {
        // SAFETY：live state 為 C 呼叫者前置條件。
        let state = unsafe { checked_state(pointer)? };
        state
            .callback_prepare_b4(nargs, nresults, true)
            .or_else(|error| state.callback_error_step_a2(error))
    })
}

/// public callback 完成後，按 B4 相同 token 與 frame 續接。
///
/// # Safety
/// pointer 必須是目前 callback 所屬的 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_resume_a2(
    pointer: *mut lua_State,
    count: c_int,
    nresults: c_int,
) -> CallbackStepB4 {
    ffi_boundary(CallbackStepB4::error(), || {
        // SAFETY：live state 為 C driver 前置條件。
        let state = unsafe { checked_state(pointer)? };
        state
            .callback_resume_b4(count, nresults, true, None)
            .or_else(|error| state.callback_error_step_a2(error))
    })
}

/// C-only checkpoint 擷取 callback 錯誤後，續接原 parked core；Rust frame 已由 C 重新進入。
///
/// # Safety
/// pointer 必須是目前最上層 callback 的 live state，C driver 持續保活它。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_resume_error_a2(
    pointer: *mut lua_State,
    nresults: c_int,
) -> CallbackStepB4 {
    ffi_boundary(CallbackStepB4::error(), || {
        // SAFETY：有效 state 為 C driver 前置條件；checked_state 再驗身分。
        let state = unsafe { checked_state(pointer)? };
        state
            .callback_resume_error_a2(nresults)
            .or_else(|error| state.callback_error_step_a2(error))
    })
}

/// public call 事前解析 errfunc、保根 handler，所有可能失敗的配置在 stack 變更前完成。
///
/// # Safety
/// pointer 是同步呼叫期間有效的 C state；C 端須在使用完 handler 後恰好釋放一次。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_public_preflight_a2(
    pointer: *mut lua_State,
    nargs: c_int,
    nresults: c_int,
    errfunc: c_int,
) -> PublicCallSetupA2 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：live pointer 為 C 呼叫者前置條件；checked_state 核對 thread/identity。
        unsafe { checked_state(pointer).map_err(|error| (error, 0))? }
            .public_call_preflight_a2(nargs, nresults, errfunc)
    })) {
        Ok(Ok(setup)) => setup,
        Ok(Err((error, base))) => PublicCallSetupA2::rejected(error, base),
        Err(_) => PublicCallSetupA2::rejected(StackError::InvalidState, 0),
    }
}

/// 配置失敗時，不再配置即以永久保根的緊急錯誤取代函式與參數。
///
/// # Safety
/// pointer 必須是同次 public preflight 的 live state，base 為其有效 function 位置。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_public_settle_preflight_allocation_a2(
    pointer: *mut lua_State,
    base: usize,
) -> c_int {
    with_state(pointer, 0, |state| {
        state.public_settle_preflight_allocation_a2(base)?;
        Ok(1)
    })
}

/// traceback 只讀同一 VM group 的 frame；不同組或 busy state 不修改目標 stack。
///
/// # Safety
/// 兩個指標須是呼叫期間仍存活的 C state；checked_state 核對執行緒與世代。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_traceback_preflight_a3(
    destination: *mut lua_State,
    source: *mut lua_State,
) -> c_int {
    with_state(destination, 0, |target| {
        // SAFETY：C caller 保活 source；checked_state 核對其身分後才建立參照。
        let source = unsafe { checked_state(source)? };
        source.validate_debug()?;
        let target_group = target.group.upgrade().ok_or(StackError::InvalidState)?;
        let source_group = source.group.upgrade().ok_or(StackError::InvalidState)?;
        if !Rc::ptr_eq(&target_group, &source_group) {
            return Err(StackError::WrongVm);
        }
        Ok(1)
    })
}

/// 錯誤 slot 已從 pending 取回；無配置地以它替換 function 與 arguments。
///
/// # Safety
/// pointer 必須是目前 public call 的 live state，base 來自同次 preflight。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_public_settle_error_a2(
    pointer: *mut lua_State,
    base: usize,
) -> c_int {
    with_state(pointer, 0, |state| {
        state.public_settle_error_a2(base)?;
        Ok(1)
    })
}

/// handler slot 由 Rust allocation 唯一持有；成功後轉移到 overlay stack。
///
/// # Safety
/// handler 必須是同次 preflight 回傳且尚未釋放的唯一指標。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_public_push_handler_a2(
    pointer: *mut lua_State,
    handler: *mut c_void,
    base: usize,
) -> c_int {
    with_state(pointer, 0, |state| {
        if handler.is_null() {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：唯一 handler 指標由 C coordinator 保存；此處只借用，drop 仍由它執行。
        let handler = unsafe { &mut *handler.cast::<PublicErrorHandlerA2>() };
        state.public_push_handler_a2(handler, base)?;
        Ok(1)
    })
}

/// 回收未轉移或已轉移 slot 的 handler 容器與 ledger charge。
///
/// # Safety
/// handler 非空時必須是 preflight 回傳的唯一指標，只能呼叫一次。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_public_drop_handler_a2(handler: *mut c_void) {
    if !handler.is_null() {
        // SAFETY：C coordinator 對同一 preflight 結果只呼叫一次；Box drop 精確退根退帳。
        drop(unsafe { Box::from_raw(handler.cast::<PublicErrorHandlerA2>()) });
    }
}

/// 固定 C fixture 專用：於目前 VM 的下一個計費配置點注入一次失敗。
///
/// # Safety
/// pointer 必須指向同步 callback 期間仍存活的 state；測試不得與其他執行緒共用它。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_inject_next_allocation_a2(
    pointer: *mut lua_State,
) -> c_int {
    with_state(pointer, 0, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let ordinal = group.vm.allocation_trace().next_ordinal;
        group.vm.inject_allocation_failure_at(ordinal);
        Ok(1)
    })
}

/// A4a protected C fixture 專用：在 callback 內設定相對 ordinal 並回報起點。
///
/// # Safety
/// pointer 必須是同步存活的 state；offset 由測試限制於有效 u64 範圍。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_inject_offset_a4a(
    pointer: *mut lua_State,
    offset: u64,
) -> u64 {
    with_state(pointer, 0, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let start = group.vm.allocation_trace().next_ordinal;
        let ordinal = start.checked_add(offset).ok_or(StackError::StackLimit)?;
        group.vm.inject_allocation_failure_at(ordinal);
        Ok(start)
    })
}

/// A4a 測試夾具在 C callback 內擷取目前配置序號，不啟用 failpoint。
///
/// # Safety
/// pointer 必須是同步存活的 state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_current_ordinal_a4a(
    pointer: *mut lua_State,
) -> u64 {
    with_state(pointer, 0, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(group.vm.allocation_trace().next_ordinal)
    })
}

/// A4a protected C fixture 專用：於 callback 內指定單次配置失敗點。
///
/// # Safety
/// pointer 必須是同步存活的 state；code 只接受下列測試矩陣的固定值。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_inject_point_a4a(
    pointer: *mut lua_State,
    code: c_int,
) -> c_int {
    with_state(pointer, 0, |state| {
        let point = match code {
            0 => FailPoint::SlotReserve,
            1 => FailPoint::ObjectReserve,
            2 => FailPoint::ObjectInitialize,
            3 => FailPoint::RootReserve,
            4 => FailPoint::HostLease,
            5 => FailPoint::ClosureCapturesReserve,
            6 => FailPoint::StringBytesReserve,
            7 => FailPoint::TableHashGrow,
            8 => FailPoint::TableRehash,
            9 => FailPoint::TableInsert,
            10 => FailPoint::MarkReserve,
            11 => FailPoint::WorkReserve,
            12 => FailPoint::RememberedReserve,
            13 => FailPoint::TableArrayReserve,
            14 => FailPoint::TableHashReserve,
            15 => FailPoint::TableArrayGrow,
            _ => return Err(StackError::InvalidIndex),
        };
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        group.vm.inject_failure_once(point);
        Ok(1)
    })
}

/// A4b 測試專用：觀察 callback 字串發表 cache 是否已於離開時清空。
///
/// # Safety
/// pointer 必須是同執行緒仍存活的 state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_upvalue_cache_len_a4b(
    pointer: *mut lua_State,
) -> usize {
    with_state(pointer, usize::MAX, |state| {
        Ok(state
            .debug
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .upvalue_strings
            .len())
    })
}

/// group-wide panic 指標只做 POD snapshot；C 必須在此函式返回後才呼叫它。
///
/// # Safety
/// pointer 必須是 live state，不能跨執行緒或 close 後使用。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_panic_snapshot_a2(
    pointer: *mut lua_State,
) -> Option<LuaCFunction> {
    with_state(pointer, None, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(group.panic_callback)
    })
}

/// Lua 5.4/5.5 的 panic binding 位於同一 StateGroup，siblings 共享。
///
/// # Safety
/// pointer 必須是 live state；callback 為符合 C ABI 的函式指標或 NULL。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_atpanic(
    pointer: *mut lua_State,
    callback: Option<LuaCFunction>,
) -> Option<LuaCFunction> {
    with_state(pointer, None, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        Ok(std::mem::replace(&mut group.panic_callback, callback))
    })
}

/// B4 driver 失敗後退回最外層已保存的 C stack，並使所有 callback token 失效。
///
/// # Safety
/// pointer 必須是仍存活的同一 state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_abort_b4(pointer: *mut lua_State) -> c_int {
    ffi_boundary(0, || {
        // SAFETY：有效 state 是 C driver 前置條件，checked_state 再核對身分。
        unsafe { checked_state(pointer)? }.callback_abort_b4()?;
        Ok(1)
    })
}

/// B7 標記預備；失敗時保持 stack 與標記不變。
///
/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_toclose_prepare_b7(
    pointer: *mut lua_State,
    index: c_int,
) -> c_int {
    with_state(pointer, -2, |state| {
        Ok(match state.toclose_prepare_b7(index) {
            Ok(()) => 1,
            Err(error) => -operation_error_class_b5(error),
        })
    })
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_close_next_b7(
    pointer: *mut lua_State,
    target: usize,
    error_position: usize,
    nil_slot: c_int,
) -> CloseStepB7 {
    with_state(
        pointer,
        CloseStepB7::error(StackError::InvalidState),
        |state| {
            Ok(
                match state.close_next_b7(target, error_position.checked_sub(1), nil_slot != 0) {
                    Ok(step) => step,
                    Err(error) => CloseStepB7::error(error),
                },
            )
        },
    )
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_close_capture_error_b7(
    pointer: *mut lua_State,
    trim_top: usize,
) -> c_int {
    with_state(pointer, 0, |state| state.close_capture_error_b7(trim_top))
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_close_finalize_error_b7(
    pointer: *mut lua_State,
    trim_top: usize,
    token: u64,
    class: c_int,
) -> c_int {
    with_state(pointer, 0, |state| {
        state.close_finalize_error_b7(trim_top, token, class)?;
        Ok(1)
    })
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_depth_b7(pointer: *mut lua_State) -> c_int {
    with_state(pointer, -1, |state| {
        let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        c_int::try_from(group.callback_frames.entries.len()).map_err(|_| StackError::StackLimit)
    })
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_call_abort_to_b7(
    pointer: *mut lua_State,
    depth: c_int,
) -> c_int {
    with_state(pointer, 0, |state| {
        state
            .callback_abort_to_b7(usize::try_from(depth).map_err(|_| StackError::InvalidIndex)?)?;
        Ok(1)
    })
}

/// # Safety
/// pointer 必須是同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_settop_direct_b7(
    pointer: *mut lua_State,
    index: c_int,
) -> c_int {
    with_state(pointer, -2, |state| {
        Ok(match state.set_top(index) {
            Ok(()) => 1,
            Err(error) => -operation_error_class_b5(error),
        })
    })
}

/// B5 純 C driver 的預備階段；所有 VM／stack 借用均在回傳 POD 前釋放。
///
/// # Safety
/// pointer 須為同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_operation_prepare_b5(
    pointer: *mut lua_State,
    kind: c_int,
    operation: c_int,
    left: c_int,
    right: c_int,
    count: c_int,
) -> CallbackStepB4 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C driver 同步保活 state，checked_state 驗證身分。
        unsafe { checked_state(pointer)? }.operation_prepare_b5(kind, operation, left, right, count)
    })) {
        Ok(Ok(step)) => step,
        Ok(Err(error)) => CallbackStepB4::operation_error_b5(error),
        Err(_) => CallbackStepB4::error(),
    }
}

/// B5 C callback 已完整返回後，續接同一 parked execution。
///
/// # Safety
/// pointer 須為同步使用且仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_operation_resume_b5(
    pointer: *mut lua_State,
    count: c_int,
) -> CallbackStepB4 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C driver 同步保活 state，checked_state 驗證身分。
        let state = unsafe { checked_state(pointer)? };
        let mut step = state.callback_resume_b4(count, 1, false, None)?;
        if step.kind == 0 {
            step = CallbackStepB4::operation_done_b5();
        }
        Ok(step)
    })) {
        Ok(Ok(step)) => step,
        Ok(Err(error)) => CallbackStepB4::operation_error_b5(error),
        Err(_) => CallbackStepB4::error(),
    }
}

/// A4a public table operation 在 C frame 中驅動；Rust step 返回 POD 後才可呼叫 metamethod。
///
/// # Safety
/// pointer 須為同步存活的 state；index 由本入口在原 stack top 解析。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_table_prepare_a4a(
    pointer: *mut lua_State,
    index: c_int,
    setter: c_int,
) -> CallbackStepB4 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C facade 保活 state，checked_state 驗身分後不保存 pointer。
        unsafe { checked_state(pointer)? }.table_operation_prepare_a4a(index, setter != 0)
    })) {
        Ok(Ok(step)) => step,
        Ok(Err(error)) => CallbackStepB4::operation_error_b5(error),
        Err(_) => CallbackStepB4::error(),
    }
}

/// A4a C callback 完整返回後續接同一 parked table operation。
///
/// # Safety
/// pointer 須為目前 C driver 保活的 state，count 是 callback 回傳值數。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_table_resume_a4a(
    pointer: *mut lua_State,
    count: c_int,
    setter: c_int,
) -> CallbackStepB4 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C driver 同步保活 state；所有借用在回傳 POD 前釋放。
        unsafe { checked_state(pointer)? }.callback_resume_b4(
            count,
            if setter != 0 { 0 } else { 1 },
            false,
            Some(setter != 0),
        )
    })) {
        Ok(Ok(step)) => step,
        Ok(Err(error)) => CallbackStepB4::operation_error_b5(error),
        Err(_) => CallbackStepB4::error(),
    }
}

/// 取得 operation 進入前的 callback 深度，供失敗時精確回復 C stack。
///
/// # Safety
/// pointer 須為仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_operation_depth_b5(pointer: *mut lua_State) -> c_int {
    with_state(pointer, -1, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = owner.try_borrow().map_err(|_| StackError::Busy)?;
        c_int::try_from(group.callback_frames.entries.len()).map_err(|_| StackError::StackLimit)
    })
}

/// 只清理 operation 自身新增的 callback frame；外層 C callback 由外層 checkpoint 擁有。
///
/// # Safety
/// pointer 須為仍存活的 lua_State。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_operation_abort_to_b5(
    pointer: *mut lua_State,
    depth: c_int,
) -> c_int {
    with_state(pointer, -1, |state| {
        let depth = usize::try_from(depth).map_err(|_| StackError::InvalidIndex)?;
        state.operation_abort_to_b5(depth)?;
        Ok(0)
    })
}

/// Rust 錯誤資訊已脫離借用；在外層 C checkpoint 準備 Lua 錯誤訊息。
///
/// # Safety
/// pointer 須為仍存活的 lua_State，generation/token 來自當前 C checkpoint。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_operation_error_b5(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    class: c_int,
    message: c_int,
) -> RawStrictResult {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C facade 保活 state；checked_state 核對身分後才取內部控制區。
        let state = unsafe { checked_state(pointer) }.map_err(|_| Reject::Stale)?;
        let checkpoint = Checkpoint {
            state: pointer,
            generation,
            token,
        };
        let class = ErrorClass::from_code(class).unwrap_or(ErrorClass::Lua);
        let message: &[u8] = if class == ErrorClass::Allocation {
            MEMORY_ERROR_BYTES
        } else {
            match message {
                1 => b"object length is not an integer",
                2 => b"'__tostring' must return a string",
                _ => b"value operation failed",
            }
        };
        let mut prepared = strict_prepare_parts(state, checkpoint, &[message], class);
        if prepared.kind == codes::ACTION_REJECT && prepared.value == Reject::StackChanged as i32 {
            // A4a 同步 API 可於滿 stack 的 C callback 內遇到配置錯誤；
            // 先預留單一錯誤槽，再沿原 pending/longjmp 契約發布錯誤。
            let group_owner = state.group.upgrade().ok_or(Reject::Stale)?;
            let group = group_owner.try_borrow().map_err(|_| Reject::Busy)?;
            let mut stack = state.stack.try_borrow_mut().map_err(|_| Reject::Busy)?;
            let required = stack
                .slots
                .len()
                .checked_add(1)
                .ok_or(Reject::StackChanged)?;
            stack
                .ensure_capacity(&group.vm, required)
                .map_err(|_| Reject::CheckpointAllocation)?;
            drop(stack);
            drop(group);
            prepared = strict_prepare_parts(state, checkpoint, &[message], class);
        }
        Ok::<_, Reject>(prepared)
    })) {
        Ok(Ok(result)) => result,
        Ok(Err(reject)) => RawStrictResult::rejected(reject),
        Err(_) => RawStrictResult::rejected(Reject::Panic),
    }
}

/// B5 無 `__tostring` 時交易式發布 vendor fallback 字串。
///
/// # Safety
/// pointer 須為有效 state；bytes 非空時須可讀 length 位元組，僅在此呼叫內借用。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_tolstring_fallback_b5(
    pointer: *mut lua_State,
    index: c_int,
    bytes: *const u8,
    length: usize,
) -> TolstringFallbackB5 {
    match catch_unwind(AssertUnwindSafe(|| {
        if bytes.is_null() && length != 0 {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：非空 slice 的可讀性由 C 同步呼叫保證；零長度不解參照空指標。
        let bytes = if length == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(bytes, length) }
        };
        // SAFETY：C facade 保活 state；checked_state 再驗證身分。
        unsafe { checked_state(pointer)? }.tolstring_fallback_b5(index, bytes)
    })) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => TolstringFallbackB5::failed(error),
        Err(_) => TolstringFallbackB5::error(),
    }
}

fn callback_fixture_module_b4(
    profile: LuaProfile,
    selector: c_int,
) -> Result<rivetlua_core::VerifiedModule, StackError> {
    use rivetlua_core::{
        BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule,
        BytecodePrototype, BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, ConstId,
        EnvironmentSource, FrameLayout, Instruction, NativeDebugCandidate, NativeLocal,
        NativePrototypeDebug, OfficialWorkBudget, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register,
        UpvalueId, VerifyLimits, encode_module, verify_module,
    };
    let tail_debug = selector == 2;
    let native_debug = selector == 2 || selector == 4 || selector == 5 || selector == 6;
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let root_binding = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let child_binding = BytecodeBindingId {
        function: 1,
        ordinal: 0,
    };
    let captured_binding = BytecodeBindingId {
        function: 0,
        ordinal: 1,
    };
    let first_binding = BytecodeBindingId {
        function: 1,
        ordinal: 1,
    };
    let second_binding = BytecodeBindingId {
        function: 1,
        ordinal: 2,
    };
    let instructions = |instructions: &[Instruction]| {
        instructions
            .iter()
            .cloned()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect()
    };
    let root = BytecodePrototype {
        id: ProtoId(0),
        function: 0,
        parent: None,
        span,
        register_count: 4,
        parameter_count: 0,
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(4),
            dynamic_top: Register(4),
            return_base: Register(0),
            environment: Register(3),
            environment_source: EnvironmentSource::RootExternal,
            registers_start_as_nil: true,
        },
        global_environment: Register(3),
        global_environment_binding: root_binding,
        binding_registers: if selector == 6 || selector == 7 {
            vec![(root_binding, Register(3)), (captured_binding, Register(1))]
        } else {
            vec![(root_binding, Register(3))]
        },
        constants: if selector == 6 || selector == 7 {
            vec![BytecodeConstant::Integer(17)]
        } else {
            vec![]
        },
        upvalues: vec![],
        instructions: instructions(&{
            let mut code = Vec::new();
            if selector == 6 || selector == 7 {
                code.push(Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(0),
                });
            }
            code.extend([
                Instruction::Closure {
                    dest: Register(0),
                    proto: ProtoId(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ]);
            code
        }),
        close_paths: vec![],
    };
    let child = BytecodePrototype {
        id: ProtoId(1),
        function: 1,
        parent: Some(ProtoId(0)),
        span,
        register_count: if selector == 5 { 9 } else { 4 },
        parameter_count: if selector == 6 || selector == 7 { 0 } else { 2 },
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(if selector == 5 { 9 } else { 4 }),
            dynamic_top: Register(if selector == 5 { 9 } else { 4 }),
            return_base: Register(0),
            environment: Register(3),
            environment_source: EnvironmentSource::ParentFrame {
                parent: ProtoId(0),
                register: Register(3),
            },
            registers_start_as_nil: true,
        },
        global_environment: Register(3),
        global_environment_binding: child_binding,
        binding_registers: if native_debug && selector != 6 {
            vec![
                (child_binding, Register(3)),
                (first_binding, Register(1)),
                (second_binding, Register(2)),
            ]
        } else {
            vec![(child_binding, Register(3))]
        },
        constants: if selector == 5 {
            vec![BytecodeConstant::Name(b"m".to_vec())]
        } else {
            vec![]
        },
        upvalues: if selector == 6 || selector == 7 {
            vec![BytecodeUpvalue {
                id: UpvalueId(0),
                source: BytecodeUpvalueSource::ParentLocal(captured_binding),
            }]
        } else {
            vec![]
        },
        instructions: instructions(&{
            let mut code = if selector == 3 || selector == 5 || selector == 6 || selector == 7 {
                // 這兩個 selector 的呼叫指令由下方分支建立。
                Vec::new()
            } else {
                vec![
                    Instruction::Move {
                        dest: Register(0),
                        src: Register(1),
                    },
                    Instruction::Move {
                        dest: Register(1),
                        src: Register(2),
                    },
                ]
            };
            if selector == 6 || selector == 7 {
                code.extend([
                    Instruction::GetUpvalue {
                        dest: Register(0),
                        upvalue: UpvalueId(0),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ]);
            } else if selector == 5 {
                code.extend([
                    Instruction::LoadConst {
                        dest: Register(4),
                        constant: ConstId(0),
                    },
                    Instruction::GetTable {
                        dest: Register(5),
                        table: Register(1),
                        key: Register(4),
                    },
                    Instruction::Move {
                        dest: Register(6),
                        src: Register(5),
                    },
                    Instruction::Move {
                        dest: Register(7),
                        src: Register(1),
                    },
                    Instruction::Move {
                        dest: Register(8),
                        src: Register(2),
                    },
                    Instruction::Call {
                        base: Register(6),
                        arg_count: 2,
                        result_mode: ResultMode::Fixed(1),
                    },
                    Instruction::Return {
                        base: Register(6),
                        result_mode: ResultMode::Fixed(1),
                    },
                ]);
            } else if selector == 3 {
                code.push(Instruction::Call {
                    base: Register(0),
                    arg_count: 0,
                    result_mode: ResultMode::Fixed(1),
                });
                code.push(Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                });
            } else if tail_debug {
                code.push(Instruction::TailCall {
                    base: Register(0),
                    arg_count: 1,
                    result_mode: ResultMode::All,
                });
            } else {
                code.push(Instruction::Call {
                    base: Register(0),
                    arg_count: 1,
                    result_mode: ResultMode::Fixed(1),
                });
                code.push(Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                });
            }
            code
        }),
        close_paths: vec![],
    };
    let module = BytecodeModule {
        format_version: RVLU_V2,
        profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        span,
        function_prototypes: vec![(0, ProtoId(0)), (1, ProtoId(1))],
        prototypes: vec![root, child],
    };
    let limits = VerifyLimits::default();
    if !native_debug {
        return verify_module(module, profile, &limits).map_err(|_| StackError::Layout);
    }
    let encoded = encode_module(module, profile, &limits).map_err(|_| StackError::Layout)?;
    let metadata = NativeDebugCandidate {
        source_name: b"@debug_api_b10.lua".to_vec(),
        prototypes: vec![
            NativePrototypeDebug {
                prototype: ProtoId(0),
                line_defined: 0,
                last_line_defined: 0,
                lines: vec![1; if selector == 6 { 3 } else { 2 }],
                locals: if selector == 6 {
                    vec![NativeLocal {
                        binding: captured_binding,
                        register: Register(1),
                        slot: 0,
                        initialized_pc: 0,
                        start_pc: 0,
                        end_pc: 3,
                        name: b"x".to_vec(),
                    }]
                } else {
                    vec![]
                },
                upvalue_names: vec![],
                max_active_locals: if selector == 6 { 1 } else { 0 },
            },
            NativePrototypeDebug {
                prototype: ProtoId(1),
                line_defined: 2,
                last_line_defined: 3,
                lines: vec![
                    3;
                    if selector == 6 {
                        2
                    } else if tail_debug {
                        3
                    } else if selector == 5 {
                        7
                    } else {
                        4
                    }
                ],
                locals: if selector == 6 {
                    vec![]
                } else {
                    vec![
                        NativeLocal {
                            binding: first_binding,
                            register: Register(1),
                            slot: 0,
                            initialized_pc: 0,
                            start_pc: 0,
                            end_pc: if tail_debug {
                                3
                            } else if selector == 5 {
                                7
                            } else {
                                4
                            },
                            name: b"first".to_vec(),
                        },
                        NativeLocal {
                            binding: second_binding,
                            register: Register(2),
                            slot: 1,
                            initialized_pc: 0,
                            start_pc: 0,
                            end_pc: if tail_debug {
                                3
                            } else if selector == 5 {
                                7
                            } else {
                                4
                            },
                            name: b"second".to_vec(),
                        },
                    ]
                },
                upvalue_names: if selector == 6 {
                    vec![Some(b"x".to_vec())]
                } else {
                    vec![]
                },
                max_active_locals: if selector == 6 { 0 } else { 2 },
            },
        ],
        temporaries: vec![],
        initializer_temporaries: vec![],
        non_counted_pcs: vec![],
    };
    Ok(encoded
        .with_native_debug(metadata, &limits, &mut OfficialWorkBudget::new(u64::MAX))
        .map_err(|_| StackError::Layout)?
        .verified()
        .clone())
}

/// 測試專用：外層 Lua frame 在呼叫 C callback 時保有可讀寫的 open x cell。
fn callback_open_fixture_module_a4b(
    profile: LuaProfile,
) -> Result<rivetlua_core::VerifiedModule, StackError> {
    use rivetlua_core::{
        BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule,
        BytecodePrototype, BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, ConstId,
        EnvironmentSource, FrameLayout, Instruction, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2,
        Register, UpvalueId, VerifyLimits, verify_module,
    };
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let root_env = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let child_env = BytecodeBindingId {
        function: 1,
        ordinal: 0,
    };
    let x = BytecodeBindingId {
        function: 1,
        ordinal: 1,
    };
    let grandchild_env = BytecodeBindingId {
        function: 2,
        ordinal: 0,
    };
    let code = |instructions: &[Instruction]| {
        instructions
            .iter()
            .cloned()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect()
    };
    let root = BytecodePrototype {
        id: ProtoId(0),
        function: 0,
        parent: None,
        span,
        register_count: 4,
        parameter_count: 0,
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(4),
            dynamic_top: Register(4),
            return_base: Register(0),
            environment: Register(3),
            environment_source: EnvironmentSource::RootExternal,
            registers_start_as_nil: true,
        },
        global_environment: Register(3),
        global_environment_binding: root_env,
        binding_registers: vec![(root_env, Register(3))],
        constants: vec![],
        upvalues: vec![],
        instructions: code(&[
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]),
        close_paths: vec![],
    };
    let child = BytecodePrototype {
        id: ProtoId(1),
        function: 1,
        parent: Some(ProtoId(0)),
        span,
        register_count: 6,
        parameter_count: 1,
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(6),
            dynamic_top: Register(6),
            return_base: Register(0),
            environment: Register(5),
            environment_source: EnvironmentSource::ParentFrame {
                parent: ProtoId(0),
                register: Register(3),
            },
            registers_start_as_nil: true,
        },
        global_environment: Register(5),
        global_environment_binding: child_env,
        binding_registers: vec![(child_env, Register(5)), (x, Register(2))],
        constants: vec![BytecodeConstant::Integer(17)],
        upvalues: vec![],
        instructions: code(&[
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::Closure {
                dest: Register(3),
                proto: ProtoId(2),
            },
            Instruction::Move {
                dest: Register(0),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(1),
                src: Register(3),
            },
            Instruction::Call {
                base: Register(0),
                arg_count: 1,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Return {
                base: Register(2),
                result_mode: ResultMode::Fixed(2),
            },
        ]),
        close_paths: vec![],
    };
    let grandchild = BytecodePrototype {
        id: ProtoId(2),
        function: 2,
        parent: Some(ProtoId(1)),
        span,
        register_count: 2,
        parameter_count: 0,
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(2),
            dynamic_top: Register(2),
            return_base: Register(0),
            environment: Register(1),
            environment_source: EnvironmentSource::ParentFrame {
                parent: ProtoId(1),
                register: Register(5),
            },
            registers_start_as_nil: true,
        },
        global_environment: Register(1),
        global_environment_binding: grandchild_env,
        binding_registers: vec![(grandchild_env, Register(1))],
        constants: vec![],
        upvalues: vec![BytecodeUpvalue {
            id: UpvalueId(0),
            source: BytecodeUpvalueSource::ParentLocal(x),
        }],
        instructions: code(&[
            Instruction::GetUpvalue {
                dest: Register(0),
                upvalue: UpvalueId(0),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]),
        close_paths: vec![],
    };
    verify_module(
        BytecodeModule {
            format_version: RVLU_V2,
            profile,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0)), (1, ProtoId(1)), (2, ProtoId(2))],
            prototypes: vec![root, child, grandchild],
        },
        profile,
        &VerifyLimits::default(),
    )
    .map_err(|_| StackError::Layout)
}

/// A5 私有測試：固定已編譯 RVLU，入口為 `function(inner, marker)`，
/// Lua `<close>` marker 包住 inner C callback，open upvalue 傳給 inner。
fn callback_mixed_close_fixture_a5(
    profile: LuaProfile,
) -> Result<rivetlua_core::VerifiedModule, StackError> {
    const HEX: &str = concat!(
        "52564c550200010100000000000000007200000000000000eb03000003000000a7000000000000000000000000000000000000000072000000000000",
        "000400000001000010020002000000010000010100000000000000000004000000000000004c000000030000000c0300010000003171000000000000",
        "007200000000000000000202000300000000000000000000720000000000000000100200000100000000000000000000720000000000000000160000",
        "000100000000000000000000000100000000000000000084020000010000000100000001000000001f0000000000000072000000000000000d000200",
        "0000001006000600000005000100000000010001050000000000000000000d00000001000000000900000000000000d0010000100000000206000200",
        "001f000000000000003700000000000000000203000600001f00000000000000370000000000000001001f0000000000000037000000000000000000",
        "000001000000000100000001000000020000000100000003000106000100001f000000000000003700000000000000000c0800020000003159000000",
        "000000005a000000000000000002070008000059000000000000005a000000000000000002040007000059000000000000005a000000000000000001",
        "070002000059000000000000005a00000000000000000209000100005c00000000000000640000000000000000020a000400005c0000000000000064",
        "00000000000000000d090001000000003c5c000000000000006400000000000000000109000400005c00000000000000640000000000000000000c00",
        "00000000006d000000000000006e0000000000000000020b000c000066000000000000006e000000000000000011030000003c66000000000000006e",
        "000000000000000011030001003c66000000000000006e00000000000000010166000000000000006e00000000000000000000000001000000010000",
        "0002000000010000000300100b000001000066000000000000006e00000000000000005c000000040000000100000000000000010001000000010000",
        "000200010000000200000003000100000003000000040000000000010000000166000000000000006e00000000000000000000000001000000010000",
        "0002000000010000000300b0000000020000000200000001010000004e000000000000005a0000000000000004000000000000100200020000000100",
        "01010000000500010100000000000000000004000000000000004a000000030000000303000000005500000000000000560000000000000000020200",
        "0300004e00000000000000560000000000000000100200000100004e0000000000000056000000000000000017000000000000000100000000000001",
        "0000000200000000000000",
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(HEX.len() / 2)
        .map_err(|_| StackError::Runtime(VmError::AllocationFailed))?;
    let mut pairs = HEX.as_bytes().chunks_exact(2);
    for pair in &mut pairs {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = nibble(pair[0]).ok_or(StackError::Layout)?;
        let low = nibble(pair[1]).ok_or(StackError::Layout)?;
        bytes.push((high << 4) | low);
    }
    if !pairs.remainder().is_empty() || bytes.len() != 1031 {
        return Err(StackError::Layout);
    }
    bytes[6] = if profile == LuaProfile::Lua54 { 1 } else { 0 };
    rivetlua_core::decode_module(&bytes, profile, &rivetlua_core::VerifyLimits::default())
        .map_err(|_| StackError::Layout)
}

/// 私有 C fixture：selector=1 保留 B4 函式；2 為 native-debug tail-call；
/// 3 為在 Lua bytecode 內直接呼叫 nil 的錯誤函式；4 為帶 native-debug 的普通呼叫；
/// 5 為帶 native-debug 的 table method 呼叫；6/7 為有／無名稱的閉合 Lua upvalue；
/// 8 在 Lua frame 尚停放時把 open closure 傳給 C callback；9 為 A5 混合關閉順序。
///
/// # Safety
/// pointer 必須是存活的 state；不接受外部 bytecode 或任意 Lua 原始碼。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_push_lua_b4(
    pointer: *mut lua_State,
    selector: c_int,
) -> c_int {
    ffi_boundary(0, || {
        if !(1..=9).contains(&selector) {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：有效 state 是 C fixture 前置條件，checked_state 再核對身分。
        let state = unsafe { checked_state(pointer)? };
        let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        let profile = if cfg!(feature = "lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let module = if selector == 9 {
            callback_mixed_close_fixture_a5(profile)?
        } else if selector == 8 {
            callback_open_fixture_module_a4b(profile)?
        } else {
            callback_fixture_module_b4(profile, selector)?
        };
        let produced = (|| -> Result<StackSlot, StackError> {
            let outcome = {
                let mut execution = group.vm.load(module)?;
                execution.run()?
            };
            let RunOutcome::Returned(values) = outcome else {
                return Err(StackError::Layout);
            };
            let [value @ Value::Object(_)] = values.as_slice() else {
                return Err(StackError::Layout);
            };
            group
                .vm
                .with_host_result_rooting(|vm| StackSlot::new(vm, StackValue::Core(*value)))
        })();
        let slot = match produced {
            Ok(slot) => slot,
            Err(error) => {
                group.vm.collect_major()?;
                return Err(error);
            }
        };
        stack.commit_capacity(prepared);
        stack.slots.push(slot);
        Ok(1)
    })
}

/// 私有 error 入口只接受仍存活的 state；跨執行緒先讀不變的 owner，再建立參照。
unsafe fn private_state<'a>(pointer: *mut lua_State) -> Result<&'a StateControl, Reject> {
    if pointer.is_null() {
        return Err(Reject::Null);
    }
    // SAFETY：有效 state 是私有入口前置條件；先只讀初始化後不變的 owner，
    // 避免在錯誤執行緒建立指向非 Sync control 的共享參照。
    let owner =
        unsafe { std::ptr::addr_of!((*pointer.cast::<StateControl>()).thread_owner).read() };
    if owner != thread::current().id() {
        return Err(Reject::WrongThread);
    }
    // SAFETY：呼叫者保證 pointer 在尚未 close 的配置內；checked_state 再驗 magic、世代與 group。
    unsafe { checked_state(pointer) }.map_err(|error| match error {
        StackError::Busy => Reject::Busy,
        StackError::WrongVm => Reject::WrongGeneration,
        _ => Reject::Stale,
    })
}

/// B3 C coordinator 每次進入 Rust 時才短借 VM；返回後 reader／writer 可重入。
///
/// # Safety
/// `pointer` 必須指向同執行緒的存活 state，且呼叫者不跨此函式保存 VM 借用。
pub(crate) unsafe fn load_with_vm<R, E>(
    pointer: *mut lua_State,
    operation: impl FnOnce(&mut Vm) -> Result<R, E>,
) -> Result<R, E>
where
    E: From<StackError>,
{
    // SAFETY：C coordinator 保活 state；private_state 再核對身分與執行緒。
    let state = unsafe { private_state(pointer) }.map_err(|_| E::from(StackError::InvalidState))?;
    let group_owner = state
        .group
        .upgrade()
        .ok_or_else(|| E::from(StackError::InvalidState))?;
    let mut group = group_owner
        .try_borrow_mut()
        .map_err(|_| E::from(StackError::Busy))?;
    operation(&mut group.vm)
}

/// 宿主私有設定只接受完全閒置的 live state，避免 callback 中重配既有 load session。
///
/// # Safety
/// `pointer` 必須指向同執行緒的存活 state。
pub(crate) unsafe fn load_configure_limits(
    pointer: *mut lua_State,
    limits: rivetlua_runtime::LoadLimits,
) -> Result<(), StackError> {
    // SAFETY：呼叫者保活 state；private_state 驗證 thread、身分及 allocator callback。
    let state = unsafe { private_state(pointer) }.map_err(|_| StackError::InvalidState)?;
    if state.checkpoint_depth.get() != 0
        || state
            .pending_error
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .is_some()
    {
        return Err(StackError::Busy);
    }
    let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
    let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
    if !group.callback_frames.entries.is_empty() {
        return Err(StackError::Busy);
    }
    group.vm.capi_configure_load_limits(limits)?;
    Ok(())
}

/// 5.5 reader 返回後還原 stack，同時保留 checkpoint 的錯誤 slot 容量。
///
/// # Safety
/// `pointer` 是同執行緒存活 state，`original_top` 由本次 load 入口保存。
pub(crate) unsafe fn load_restore_reader_stack(
    pointer: *mut lua_State,
    original_top: usize,
) -> Result<(), StackError> {
    // SAFETY：C coordinator 保活 state；private_state 核對 thread 與身分。
    let state = unsafe { private_state(pointer) }.map_err(|_| StackError::InvalidState)?;
    let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
    let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
    let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
    if stack.slots.len() < original_top || !stack.can_remove_from(original_top) {
        return Err(StackError::InvalidIndex);
    }
    let error_capacity = original_top.checked_add(1).ok_or(StackError::StackLimit)?;
    stack.ensure_capacity(&group.vm, error_capacity)?;
    stack.slots.truncate(original_top);
    // 被移除 HostHandle 的 Drop 已在 VM 借用期間退根；容量保留給 pending error。
    let _ = &mut group;
    Ok(())
}

/// B3 已預付 retained 容量交給 VM module，最後由公開 stack slot 持根。
///
/// # Safety
/// `pointer` 必須是同執行緒存活 state，`module` 與 `charges` 同 VM 帳本。
pub(crate) unsafe fn load_publish_charged(
    pointer: *mut lua_State,
    module: VerifiedModule,
    charges: AllocationCharges,
) -> Result<(), StackError> {
    // SAFETY：C coordinator 保活 state；private_state 再核對身分與執行緒。
    let state = unsafe { private_state(pointer) }.map_err(|_| StackError::InvalidState)?;
    let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
    let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
    let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
    let registry = group.registry_table()?;
    let Value::Object(environment) = group
        .vm
        .raw_get(registry, Value::Integer(LUA_RIDX_GLOBALS))?
    else {
        return Err(StackError::InvalidIndex);
    };
    if group.vm.object_kind(environment)? != ObjectKind::Table {
        return Err(StackError::InvalidIndex);
    }
    let required = stack
        .slots
        .len()
        .checked_add(1)
        .ok_or(StackError::StackLimit)?;
    stack.ensure_capacity(&group.vm, required)?;
    let (closure, temporary_root) =
        group
            .vm
            .capi_loaded_chunk_closure_charged(module, Value::Object(environment), charges)?;
    let prepared = StackSlot::new(&mut group.vm, StackValue::Core(Value::Object(closure)));
    let removed = group.vm.remove_root(temporary_root);
    let slot = match (prepared, removed) {
        (Ok(slot), Ok(_)) => slot,
        (Err(error), Ok(_)) => return Err(error),
        (_, Err(error)) => return Err(error.into()),
    };
    stack.slots.push(slot);
    Ok(())
}

/// B3 以既有 pending error 配置／emergency 退路保留唯一結果 slot。
///
/// # Safety
/// checkpoint 必須是目前 C coordinator 的有效 frame。
pub(crate) unsafe fn load_prepare_error(
    checkpoint: Checkpoint,
    bytes: &[u8],
    class: ErrorClass,
) -> Result<ErrorClass, Reject> {
    // SAFETY：checkpoint 來自目前純 C frame，private_state 再核對身分。
    let state = unsafe { private_state(checkpoint.state)? };
    prepare_message_pending(state, checkpoint, bytes, class)
}

/// B3 dump 在借用 VM 內擷取 top closure，回傳已計費且獨立持有的 bytes。
///
/// # Safety
/// `pointer` 必須是同執行緒存活 state。
pub(crate) unsafe fn dump_top_bytes(
    pointer: *mut lua_State,
    strip: bool,
) -> Result<CapiDumpBytes, StackError> {
    // SAFETY：C coordinator 保活 state；private_state 再核對身分與執行緒。
    let state = unsafe { private_state(pointer) }.map_err(|_| StackError::InvalidState)?;
    let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
    let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
    let stack = state.stack.try_borrow().map_err(|_| StackError::Busy)?;
    let Some(slot) = stack.slots.last() else {
        return Err(StackError::InvalidIndex);
    };
    let StackValue::Core(Value::Object(closure)) = slot.checked_value(&group.vm)? else {
        return Err(StackError::InvalidIndex);
    };
    if group.vm.object_kind(closure)? != ObjectKind::Closure {
        return Err(StackError::InvalidIndex);
    }
    Ok(group.vm.capi_dump_closure(closure, strip)?)
}

impl StateControl {
    fn enter_checkpoint(&self) -> Result<(u64, u64, u64), Reject> {
        if self
            .pending_error
            .try_borrow()
            .map_err(|_| Reject::Busy)?
            .is_some()
        {
            return Err(Reject::Pending);
        }
        let depth = self
            .checkpoint_depth
            .get()
            .checked_add(1)
            .ok_or(Reject::Busy)?;
        let token = self
            .next_checkpoint_token
            .get()
            .checked_add(1)
            .ok_or(Reject::Stale)?;
        let previous = self.checkpoint_token.get();
        // action 執行前先保證一個可觀察錯誤 slot；失敗不更改 token/depth。
        let group_owner = self.group.upgrade().ok_or(Reject::Stale)?;
        let group = group_owner.try_borrow().map_err(|_| Reject::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| Reject::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(Reject::CheckpointAllocation)?;
        if stack.slots.len() == MAX_STACK {
            // 一般 Lua stack 已滿；checkpoint 只需預留既有的 emergency backing。
            if stack.slots.capacity() < required {
                return Err(Reject::CheckpointAllocation);
            }
        } else {
            stack
                .ensure_capacity(&group.vm, required)
                .map_err(|_| Reject::CheckpointAllocation)?;
        }
        self.next_checkpoint_token.set(token);
        self.checkpoint_token.set(token);
        self.checkpoint_depth.set(depth);
        Ok((self.state_generation, token, previous))
    }

    fn exit_checkpoint(&self, generation: u64, token: u64, previous: u64) -> Result<(), Reject> {
        if self.state_generation != generation {
            return Err(Reject::WrongGeneration);
        }
        let depth = self.checkpoint_depth.get();
        if depth == 0 || self.checkpoint_token.get() != token {
            return Err(Reject::Stale);
        }
        if (depth == 1 && previous != 0) || (depth > 1 && previous == 0) {
            return Err(Reject::Stale);
        }
        let release_capacity = depth == 1
            && self
                .pending_error
                .try_borrow()
                .map_err(|_| Reject::Busy)?
                .is_none();
        let mut stack = if release_capacity {
            Some(self.stack.try_borrow_mut().map_err(|_| Reject::Busy)?)
        } else {
            None
        };
        // 所有可失敗借用已完成，退出 checkpoint 的身分更新與容量釋放才提交。
        self.checkpoint_depth.set(depth - 1);
        self.checkpoint_token.set(previous);
        if let Some(stack) = stack.as_mut() {
            stack.release_empty_capacity();
        }
        Ok(())
    }

    fn rewind_checkpoint_a5(
        &self,
        generation: u64,
        token: u64,
        skipped: u32,
    ) -> Result<(), Reject> {
        if self.state_generation != generation
            || token == 0
            || self
                .pending_error
                .try_borrow()
                .map_err(|_| Reject::Busy)?
                .is_some()
        {
            return Err(Reject::Stale);
        }
        let depth = self
            .checkpoint_depth
            .get()
            .checked_sub(skipped)
            .filter(|depth| *depth > 0)
            .ok_or(Reject::Stale)?;
        let current = self.checkpoint_token.get();
        if token > current || (skipped == 0 && token != current) {
            return Err(Reject::Stale);
        }
        self.checkpoint_depth.set(depth);
        self.checkpoint_token.set(token);
        Ok(())
    }
}

/// C 僅在已跳離內層純 C checkpoint 的 yield 路徑呼叫；不碰 Lua stack。
///
/// # Safety
/// pointer 必須仍有效，generation/token 與 C resume target 同一有效 frame。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_checkpoint_rewind_a5(
    pointer: *mut c_void,
    generation: u64,
    token: u64,
    skipped: c_uint,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C caller 保證 live state；private_state 再核對身分與 thread。
        let state = unsafe { private_state(pointer.cast())? };
        state.rewind_checkpoint_a5(generation, token, skipped)
    })) {
        Ok(Ok(())) => codes::OK,
        Ok(Err(reject)) => reject as c_int,
        Err(_) => Reject::Panic as c_int,
    }
}

/// # Safety
/// checkpoint.state 必須仍存活；C top 的精確比對已在呼叫者完成，此處再驗 Rust state。
pub(crate) unsafe fn prepare_pending(
    checkpoint: Checkpoint,
    class: ErrorClass,
) -> Result<(), Reject> {
    // SAFETY：有效 state 為呼叫者前置條件，private_state 驗證 thread 與世代。
    let state = unsafe { private_state(checkpoint.state)? };
    if state.state_generation != checkpoint.generation {
        return Err(Reject::WrongGeneration);
    }
    if state.checkpoint_depth.get() == 0 || state.checkpoint_token.get() != checkpoint.token {
        return Err(Reject::Stale);
    }
    let mut pending = state
        .pending_error
        .try_borrow_mut()
        .map_err(|_| Reject::Busy)?;
    if pending.is_some() {
        return Err(Reject::Pending);
    }
    let group_owner = state.group.upgrade().ok_or(Reject::Stale)?;
    let group = group_owner.try_borrow().map_err(|_| Reject::Busy)?;
    let mut stack = state.stack.try_borrow_mut().map_err(|_| Reject::Busy)?;
    let original_top = stack.slots.len();
    let Some(slot) = stack.slots.last() else {
        return Err(Reject::StackChanged);
    };
    if !stack.can_remove_from(original_top - 1) {
        return Err(Reject::StackChanged);
    }
    slot.checked_value(&group.vm).map_err(|_| Reject::Stale)?;
    // 所有驗證已完成；Vec::pop 不縮容量，HostHandle 與 string view 原封不動移入 pending。
    let slot = stack.slots.pop().ok_or(Reject::StackChanged)?;
    *pending = Some(PendingError {
        slot,
        class,
        token: checkpoint.token,
        original_top,
    });
    Ok(())
}

fn version_error_allocation_failed(error: StackError) -> bool {
    matches!(
        error,
        StackError::StackLimit
            | StackError::Runtime(
                VmError::AllocationFailed
                    | VmError::IdentityExhausted
                    | VmError::RootIdExhausted
                    | VmError::ArithmeticOverflow
                    | VmError::InjectedFailure(_)
                    | VmError::InjectedAllocation(_)
            )
    )
}

/// 從固定 byte 訊息原子建立 pending slot；配置失敗時改用已計費的永久 emergency 物件。
///
/// # Safety
/// checkpoint.state 必須仍存活；C top 身分由呼叫者先行檢查，這裡再核對 Rust state。
pub(crate) unsafe fn prepare_version_pending(
    checkpoint: Checkpoint,
    bytes: &[u8],
) -> Result<ErrorClass, Reject> {
    // SAFETY：有效 state 為呼叫者前置條件；private_state 核對執行緒、存活與世代。
    let state = unsafe { private_state(checkpoint.state)? };
    prepare_message_pending(state, checkpoint, bytes, ErrorClass::Lua)
}

fn prepare_message_pending(
    state: &StateControl,
    checkpoint: Checkpoint,
    bytes: &[u8],
    requested_class: ErrorClass,
) -> Result<ErrorClass, Reject> {
    prepare_parts_pending(state, checkpoint, &[bytes], requested_class)
}

fn prepare_parts_pending(
    state: &StateControl,
    checkpoint: Checkpoint,
    parts: &[&[u8]],
    requested_class: ErrorClass,
) -> Result<ErrorClass, Reject> {
    if state.state_generation != checkpoint.generation {
        return Err(Reject::WrongGeneration);
    }
    if state.checkpoint_depth.get() == 0 || state.checkpoint_token.get() != checkpoint.token {
        return Err(Reject::Stale);
    }
    let mut pending = state
        .pending_error
        .try_borrow_mut()
        .map_err(|_| Reject::Busy)?;
    if pending.is_some() {
        return Err(Reject::Pending);
    }
    let group_owner = state.group.upgrade().ok_or(Reject::Stale)?;
    let mut group = group_owner.try_borrow_mut().map_err(|_| Reject::Busy)?;
    let stack = state.stack.try_borrow().map_err(|_| Reject::Busy)?;
    let original_top = stack
        .slots
        .len()
        .checked_add(1)
        .ok_or(Reject::StackChanged)?;
    if original_top > stack.slots.capacity() {
        // A48 action 必須立即檢查版本；中途消耗預留 slot 不在本片契約內。
        return Err(Reject::StackChanged);
    }
    let prepared = StringView::new_parts(&group.vm, parts).and_then(|view| {
        group
            .vm
            .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                let mut slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                slot.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                Ok::<_, StackError>(slot)
            })
    });
    let (slot, class) = match prepared {
        Ok(slot) => (slot, requested_class),
        Err(error) if version_error_allocation_failed(error) => (
            StackSlot::permanent_rooted(
                &group.vm,
                group.emergency_error,
                Rc::clone(&group.emergency_view),
            )
            .map_err(|_| Reject::Stale)?,
            ErrorClass::Allocation,
        ),
        Err(_) => return Err(Reject::Stale),
    };
    // slot、root 與容量均備妥；發布 pending 後不再執行可能失敗的操作。
    *pending = Some(PendingError {
        slot,
        class,
        token: checkpoint.token,
        original_top,
    });
    Ok(class)
}

/// # Safety
/// state 必須仍存活；呼叫者不得在 close 後使用 pointer。
pub(crate) unsafe fn consume_pending(pointer: *mut lua_State) -> Result<ErrorClass, Reject> {
    // SAFETY：有效 pointer 為呼叫者前置條件；private_state 驗證 thread 與身分。
    let state = unsafe { private_state(pointer)? };
    let mut pending = state
        .pending_error
        .try_borrow_mut()
        .map_err(|_| Reject::Busy)?;
    let Some(error) = pending.as_ref() else {
        return Err(Reject::NoPending);
    };
    let mut stack = state.stack.try_borrow_mut().map_err(|_| Reject::Busy)?;
    if stack.slots.len().checked_add(1) != Some(error.original_top)
        || stack.slots.len() == stack.slots.capacity()
    {
        return Err(Reject::StackChanged);
    }
    let error = pending.take().ok_or(Reject::NoPending)?;
    stack.slots.push(error.slot);
    Ok(error.class)
}

/// C checkpoint 在 action 返回後確認 pending 與其 status 完全對應，才准在 C frame 跳轉。
///
/// # Safety
/// 非空 state 必須仍存活；C 保護框架維持其生命週期。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_pending_matches_a1(
    pointer: *mut c_void,
    generation: u64,
    token: u64,
    status: i32,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：有效 state 為 C 呼叫者前置條件；private_state 驗證 thread 與身分。
        let state = unsafe { private_state(pointer.cast())? };
        if state.state_generation != generation {
            return Err(Reject::WrongGeneration);
        }
        let pending = state.pending_error.try_borrow().map_err(|_| Reject::Busy)?;
        match pending.as_ref() {
            Some(error) if error.token == token && error.class as i32 == status => Ok(()),
            Some(_) => Err(Reject::Stale),
            None => Err(Reject::InvalidAction),
        }
    })) {
        Ok(Ok(())) => codes::OK,
        Ok(Err(reject)) => reject as i32,
        Err(_) => Reject::Panic as i32,
    }
}

/// action 非 raise 或被 panic 攔下時，只取消屬於目前 token 的 pending。
///
/// # Safety
/// 非空 state 必須仍存活；C frame 在 checkpoint 退鏈前同步呼叫。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_pending_cancel_a1(
    pointer: *mut c_void,
    generation: u64,
    token: u64,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：有效 state 為 C 呼叫者前置條件；private_state 驗證 thread 與身分。
        let state = unsafe { private_state(pointer.cast())? };
        if state.state_generation != generation {
            return Err(Reject::WrongGeneration);
        }
        let own_pending = state
            .pending_error
            .try_borrow()
            .map_err(|_| Reject::Busy)?
            .as_ref()
            .is_some_and(|error| error.token == token);
        if !own_pending {
            return Ok(false);
        }
        // SAFETY：state 仍存活且屬於目前 C checkpoint；consume 會檢查原 stack top。
        unsafe { consume_pending(pointer.cast())? };
        Ok(true)
    })) {
        Ok(Ok(true)) => codes::CANCELLED,
        Ok(Ok(false)) => codes::OK,
        Ok(Err(reject)) => reject as i32,
        Err(_) => Reject::Panic as i32,
    }
}

/// C 建立 stack-local checkpoint 前先取得此 state 的唯一 token。
///
/// # Safety
/// 非空 pointer 必須指向有效 state，三個 out pointer 必須對齊、可寫且互不重疊。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_checkpoint_enter_a1(
    pointer: *mut c_void,
    generation: *mut u64,
    token: *mut u64,
    previous: *mut u64,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        if generation.is_null() || token.is_null() || previous.is_null() {
            return Err(Reject::Null);
        }
        // SAFETY：有效 state 為 C 呼叫者前置條件；private_state 驗證 thread 與身分。
        let state = unsafe { private_state(pointer.cast())? };
        let (state_generation, new_token, previous_token) = state.enter_checkpoint()?;
        // SAFETY：三個輸出指標由本 crate C frame 的獨立、對齊 stack 欄位提供，僅各寫一次。
        unsafe {
            generation.write(state_generation);
            token.write(new_token);
            previous.write(previous_token);
        }
        Ok(())
    })) {
        Ok(Ok(())) => codes::OK,
        Ok(Err(reject)) => reject as i32,
        Err(_) => Reject::Panic as i32,
    }
}

/// C checkpoint 正常或捕捉後退鏈，恢復同 state 外層 token。
///
/// # Safety
/// 非空 pointer 必須指向同一存活 state；只有原 C frame 可傳回其 token。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_checkpoint_exit_a1(
    pointer: *mut c_void,
    generation: u64,
    token: u64,
    previous: u64,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：有效 state 為 C 呼叫者前置條件；private_state 驗證 thread 與身分。
        let state = unsafe { private_state(pointer.cast())? };
        state.exit_checkpoint(generation, token, previous)
    })) {
        Ok(Ok(())) => codes::OK,
        Ok(Err(reject)) => reject as i32,
        Err(_) => Reject::Panic as i32,
    }
}

/// reset 結束時仍以一次性 permit 驗證 parent prefix，再退出 child checkpoint。
///
/// # Safety
/// pointer 必須是目前 reset C checkpoint 的 live child；generation/token/previous
/// 只能由建立此 checkpoint 的同一 C frame 傳回。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_checkpoint_exit_a5(
    pointer: *mut c_void,
    generation: u64,
    token: u64,
    previous: u64,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：有效 child state 與目前 C reset frame 的生命週期由呼叫者保證。
        let state =
            unsafe { checked_debug_state(pointer.cast()) }.map_err(|error| match error {
                StackError::Busy => Reject::Busy,
                StackError::WrongVm => Reject::WrongGeneration,
                _ => Reject::Stale,
            })?;
        if let Some(permit) = state.reset_permit_a5.take() {
            let owner = state.group.upgrade().ok_or(Reject::Stale)?;
            let group = owner.try_borrow().map_err(|_| Reject::Busy)?;
            if generation != permit.child_generation
                || state.checkpoint_token.get() != token
                || !permit.matches_prefix(state, &group)
            {
                return Err(Reject::Stale);
            }
        } else {
            state.validate().map_err(|_| Reject::Stale)?;
        }
        state.exit_checkpoint(generation, token, previous)
    })) {
        Ok(Ok(())) => codes::OK,
        Ok(Err(reject)) => reject as i32,
        Err(_) => Reject::Panic as i32,
    }
}

/// 建立由 C 持有的預設主 state；失敗或 panic 回 null，不跨越 ABI。
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn luaL_newstate() -> *mut lua_State {
    ffi_boundary(std::ptr::null_mut(), || {
        let owner = StateOwner::new()?;
        // SAFETY：新建 live state 尚未交出；C installer 僅存入 POD 函式指標，
        // 不在持有此 Rust frame 時呼叫 panic callback。
        unsafe { rivetlua_capi_default_panic_install_a2(owner.as_ptr()) };
        // SAFETY：owner 在呼叫期間持有有效 state；C installer 僅透過無配置的
        // lua_setwarnf 設定完整 callback/ud 配對，返回後才將 owner 交給 C。
        unsafe { rivetlua_capi_default_warning_install_b6(owner.as_ptr()) };
        Ok(owner.into_c_ptr())
    })
}

/// 更換同一 global state 的 warning callback；不配置、不改 VM 或 C stack。
///
/// # Safety
/// state 必須仍有效；callback 與 ud 由 C 呼叫者保證在後續同步呼叫時可用。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_setwarnf(
    pointer: *mut lua_State,
    callback: Option<LuaWarnFunction>,
    ud: *mut c_void,
) {
    with_state(pointer, (), |state| {
        let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        group.warning = WarningBindingB6 { callback, ud };
        Ok(())
    });
}

/// Rust 借用釋放前只複製 POD；C facade 在本函式返回後才呼叫 callback。
///
/// # Safety
/// 非空 state 必須在呼叫期間有效；無效/null state 回停用 binding。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_warning_snapshot_b6(
    pointer: *mut lua_State,
) -> WarningBindingB6 {
    with_state(pointer, WarningBindingB6::disabled(), |state| {
        let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        Ok(group.warning)
    })
}

/// 依 Lua 5.4 ABI 安裝自訂 allocator，於第一筆 VM 配置之前生效。
///
/// # Safety
/// f/ud 必須在 state 存活期間可呼叫；callback 不得跨 ABI unwind 或 longjmp。
#[cfg(feature = "lua54")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_newstate(f: Option<LuaAlloc>, ud: *mut c_void) -> *mut lua_State {
    ffi_boundary(std::ptr::null_mut(), || {
        let function = f.ok_or(StackError::InvalidState)?;
        Ok(StateOwner::new_with_allocator(function, ud)?.into_c_ptr())
    })
}

/// Lua 5.5 的 seed 不參與本片 allocator 綁定；VM 既有 profile 規則保持不變。
///
/// # Safety
/// f/ud 必須在 state 存活期間可呼叫；callback 不得跨 ABI unwind 或 longjmp。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_newstate(
    f: Option<LuaAlloc>,
    ud: *mut c_void,
    _seed: c_uint,
) -> *mut lua_State {
    ffi_boundary(std::ptr::null_mut(), || {
        let function = f.ok_or(StackError::InvalidState)?;
        Ok(StateOwner::new_with_allocator(function, ud)?.into_c_ptr())
    })
}

/// # Safety
/// 非空 pointer 必須指向仍存活的 state；非空 ud 必須指向可寫 pointer slot。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_getallocf(
    pointer: *mut lua_State,
    ud: *mut *mut c_void,
) -> Option<LuaAlloc> {
    ffi_boundary(None, || {
        // SAFETY：有效 pointer 與 ud 為 C 呼叫者前置條件；checked_state 驗證 thread/state。
        let state = unsafe { checked_state(pointer)? };
        let (function, user_data) = state.allocator.current();
        if !ud.is_null() {
            // SAFETY：非空 ud 由呼叫者保證可寫一個 pointer。
            unsafe { ud.write(user_data) };
        }
        Ok(function)
    })
}

/// # Safety
/// pointer 必須指向仍存活的 state；新 f/ud 必須在後續配置與釋放期間有效。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_setallocf(
    pointer: *mut lua_State,
    f: Option<LuaAlloc>,
    ud: *mut c_void,
) {
    ffi_boundary((), || {
        // SAFETY：有效 pointer 為 C 呼叫者前置條件；checked_state 驗證 thread/state。
        let state = unsafe { checked_state(pointer)? };
        let function = f.ok_or(StackError::InvalidState)?;
        if !state.allocator.set_current(function, ud) {
            return Err(StackError::Busy);
        }
        Ok(())
    });
}

/// 依固定 Lua 輔助 API 將 C 呼叫結果推回 stack；失敗時三個結果一次發布。
///
/// # Safety
/// 非空 state 必須在呼叫期間有效；只有 stat 為零、入口未因無效 state 或借用衝突
/// 先行拒絕，且確實執行 fname 原始讀取時，非空 fname 才須在讀取期間指向有效的
/// NUL 結尾 C 位元組字串。
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn luaL_fileresult(
    pointer: *mut lua_State,
    stat: c_int,
    fname: *const c_char,
) -> c_int {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    with_state(pointer, 0, |state| {
        if stat != 0 {
            state.push(StackValue::Core(Value::Boolean(true)))?;
            return Ok(1);
        }
        state.push_file_result_failure(errno, fname)?;
        Ok(3)
    })
}

unsafe extern "C" {
    /// 公開 close/reset 由純 C coordinator 定義，Rust 僅提供短借用 step。
    pub fn lua_close(pointer: *mut lua_State);
    pub fn lua_closethread(pointer: *mut lua_State, from: *mut lua_State) -> c_int;
    #[cfg(feature = "lua54")]
    pub fn lua_resetthread(pointer: *mut lua_State) -> c_int;
}

fn close_public_status_b11(error: StackError) -> c_int {
    if operation_error_class_b5(error) == ErrorClass::Allocation as c_int {
        4
    } else {
        2
    }
}

fn compact_reset_close_level_a5(
    vm: &mut Vm,
    source: &StackStorage,
) -> Result<StackStorage, StackError> {
    let count = source.close_marks.len();
    let mut prepared = StackStorage::new();
    prepared.ensure_capacity(vm, count.saturating_add(1))?;
    let close_capacity = prepared.prepare_close_mark_capacity(vm, count)?;
    prepared.commit_close_mark_capacity(close_capacity);
    for &position in &source.close_marks {
        let slot = source.slots.get(position).ok_or(StackError::Layout)?;
        prepared.slots.push(slot.try_clone(vm)?);
        prepared.close_marks.push(prepared.slots.len() - 1);
    }
    Ok(prepared)
}

/// reset admission 不改動 thread 的 Lua frame；只預留最終單錯誤 slot。
///
/// # Safety
/// 非空 pointer／from 須是呼叫期間 live 的 state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_preflight_b11(
    pointer: *mut lua_State,
    from: *mut lua_State,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：reset 可指向同 group 未執行的 child；後續確認 child 自身無 callback frame。
        let state = unsafe { checked_debug_state(pointer)? };
        if state.checkpoint_depth.get() != 0
            || state
                .pending_error
                .try_borrow()
                .map_err(|_| StackError::Busy)?
                .is_some()
        {
            return Err(StackError::Busy);
        }
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let from_generation = if !from.is_null() {
            // SAFETY：非 NULL from 須是同執行緒存活 state。
            let source = unsafe { checked_state(from)? };
            let source_owner = source.group.upgrade().ok_or(StackError::InvalidState)?;
            if !Rc::ptr_eq(&owner, &source_owner) {
                return Err(StackError::WrongVm);
            }
            Some(source.state_generation)
        } else {
            None
        };
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        if state.reset_permit_a5.get().is_some() {
            return Err(StackError::Busy);
        }
        if group
            .callback_frames
            .entries
            .iter()
            .any(|frame| frame.owner_generation == state.state_generation)
            || group.vm.execution_running()
            || group.vm.finalizer_running()
            || matches!(
                group.vm.coroutine_state(identity)?,
                CoroutineState::Running | CoroutineState::Normal
            )
        {
            return Err(StackError::Busy);
        }
        let parent_permit = if let Some(parent) = group.callback_frames.entries.last() {
            if Some(parent.owner_generation) != from_generation
                || parent.depth != group.callback_frames.entries.len()
            {
                return Err(StackError::Busy);
            }
            Some(ResetPermitA5 {
                child_generation: state.state_generation,
                group_generation: group.generation,
                from_generation: parent.owner_generation,
                prefix_len: group.callback_frames.entries.len(),
                prefix_token: parent.token,
                checkpoint_token: None,
            })
        } else {
            None
        };
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        let suspended = state
            .suspended_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?;
        let mut reset_public = state
            .reset_public_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if reset_public.is_some() {
            return Err(StackError::Busy);
        }
        let mut reset_levels = None;
        if let Some(held) = suspended.as_ref() {
            let count = held.frames.entries.len().saturating_sub(1);
            let mut levels = Vec::new();
            let levels_charge = if count == 0 {
                None
            } else {
                let bytes = count
                    .checked_mul(size_of::<StackStorage>())
                    .ok_or(StackError::StackLimit)?;
                let ticket = group.vm.reserve_host_allocation(bytes)?;
                levels
                    .try_reserve_exact(count)
                    .map_err(|_| StackError::Runtime(ticket.rust_reserve_failure()))?;
                let actual = levels
                    .capacity()
                    .checked_mul(size_of::<StackStorage>())
                    .ok_or(StackError::StackLimit)?;
                let extra = actual.checked_sub(bytes).ok_or(StackError::Layout)?;
                let extra = if extra == 0 {
                    None
                } else {
                    Some(group.vm.reserve_host_allocation(extra)?.commit()?)
                };
                Some(StackCapacityCharge {
                    _base: ticket.commit()?,
                    _extra: extra,
                })
            };
            for frame in held.frames.entries.iter().skip(1) {
                levels.push(compact_reset_close_level_a5(
                    &mut group.vm,
                    &frame.saved_stack,
                )?);
            }
            let innermost = compact_reset_close_level_a5(&mut group.vm, &held.overlay)?;
            reset_levels = Some((innermost, levels, levels_charge));
        }
        if let Some((innermost, outer_levels, levels_charge)) = reset_levels {
            let public = std::mem::replace(&mut *stack, innermost);
            *reset_public = Some(ResetPublicA5 {
                public,
                outer_levels,
                _levels_charge: levels_charge,
                boundary_token: None,
                stage: ResetStageA5::Prepared,
            });
        } else {
            group.vm.prepare_thread_reset_b11(identity)?;
        }
        state.reset_permit_a5.set(parent_permit);
        Ok(())
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => close_public_status_b11(error),
        Err(_) => 2,
    }
}

/// C checkpoint 建立成功後、首個 C `__close` 前，標記 reset 已不可回滾。
///
/// # Safety
/// pointer 必須是剛完成 reset preflight 的 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_start_a5(pointer: *mut lua_State) -> c_int {
    with_state(pointer, 2, |state| {
        if let Some(mut permit) = state.reset_permit_a5.get() {
            if state.checkpoint_depth.get() != 1 || state.checkpoint_token.get() == 0 {
                return Err(StackError::InvalidState);
            }
            permit.checkpoint_token = Some(state.checkpoint_token.get());
            state.reset_permit_a5.set(Some(permit));
        }
        let mut reset = state
            .reset_public_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?;
        if let Some(held) = reset.as_mut() {
            if held.stage != ResetStageA5::Prepared {
                return Err(StackError::InvalidState);
            }
            held.stage = ResetStageA5::Closing;
        }
        Ok(0)
    })
}

/// 固定 C fixture 在外層 close handler 要求下一次 boundary error root 配額失敗。
///
/// # Safety
/// pointer 必須是目前 reset C checkpoint 中的 live child state。
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_test_fail_next_close_boundary_root_a5(
    pointer: *mut lua_State,
) -> c_int {
    with_state(pointer, 0, |state| {
        let reset = state
            .reset_public_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?;
        if !reset
            .as_ref()
            .is_some_and(|held| held.stage == ResetStageA5::Closing)
        {
            return Err(StackError::InvalidState);
        }
        state.test_fail_close_boundary_root_a5.set(true);
        Ok(1)
    })
}

/// Lua 5.5 self-close 只接受正停在此 child C callback 的 resume。
///
/// # Safety
/// pointer 必須是仍存活的 C child state。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_selfclose_preflight_b11(
    pointer: *mut lua_State,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：C caller 持有存活 state。
        let state = unsafe { checked_state(pointer)? };
        if state
            .pending_error
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .is_some()
        {
            return Err(StackError::Busy);
        }
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::Busy)?;
        if frame.selfclose_restored_b11() {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        if !group.vm.self_close_external_ready(token, identity) {
            return Err(StackError::Busy);
        }
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        let StateGroup {
            vm,
            callback_frames,
            ..
        } = &mut *group;
        let saved = &mut callback_frames
            .entries
            .last_mut()
            .ok_or(StackError::Busy)?
            .saved_stack;
        let required = saved
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        saved.ensure_capacity(vm, required)?;
        Ok(())
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => close_public_status_b11(error),
        Err(_) => 2,
    }
}

/// C callback stack 的 marks 關閉後，回復其保存的 thread overlay，保留 parked token。
///
/// # Safety
/// pointer 須是 self-close preflight 成功的 live child。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_selfclose_restore_b11(
    pointer: *mut lua_State,
    overlay_status: c_int,
) -> c_int {
    with_state(pointer, 2, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if !stack.close_marks.is_empty() {
            return Err(StackError::Busy);
        }
        let frame = group
            .callback_frames
            .entries
            .last_mut()
            .ok_or(StackError::InvalidState)?;
        if frame.selfclose_restored_b11() {
            return Err(StackError::Busy);
        }
        std::mem::swap(&mut *stack, &mut frame.saved_stack);
        if overlay_status != 0 {
            let error = frame
                .saved_stack
                .slots
                .pop()
                .ok_or(StackError::InvalidState)?;
            stack.slots.push(error);
        }
        frame.mark_selfclose_restored_b11();
        Ok(0)
    })
}

/// C overlay 兩層 marks 皆關閉後，沿 runtime close walker 結束目前 coroutine。
///
/// # Safety
/// pointer 須是 self-close restore 完成的 live child。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_selfclose_prepare_b11(
    pointer: *mut lua_State,
    overlay_status: c_int,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?;
        if !frame.selfclose_restored_b11() {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if !stack.close_marks.is_empty() {
            return Err(StackError::Busy);
        }
        let original = if overlay_status == 0 {
            None
        } else {
            let slot = stack.slots.last().ok_or(StackError::InvalidState)?;
            let StackValue::Core(value) = slot.checked_value(&group.vm)?;
            Some(value)
        };
        let mut debug = state.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .pop()
            .ok_or(StackError::InvalidState)?;
        if frame.token != token {
            return Err(StackError::Busy);
        }
        debug.remove_external(token);
        group.callback_frames.release_empty();
        drop(debug);
        let outcome = group.vm.self_close_external_with_error(token, original);
        state.callback_outcome_b4(&mut group, &mut stack, outcome?, 0, ResultMode::All)
    })
}

/// 固定 C fixture 將 B4 的 `function(f, arg) return f(arg)` 綁到 child identity。
///
/// # Safety
/// pointer 必須是存活且尚未啟動的 C child。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_set_entry_b11(pointer: *mut lua_State) -> c_int {
    with_state(pointer, 0, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        let module = callback_fixture_module_b4(LuaProfile::Lua55, 1)?;
        let outcome = {
            let mut execution = group.vm.load(module)?;
            execution.run()?
        };
        let RunOutcome::Returned(values) = outcome else {
            return Err(StackError::Layout);
        };
        let [Value::Object(function)] = values.as_slice() else {
            return Err(StackError::Layout);
        };
        let rooted = HostHandle::<Value>::new(&mut group.vm, *function)?;
        let result = group
            .vm
            .set_host_coroutine_entry_b11(identity, Value::Object(*function));
        drop(rooted);
        result?;
        Ok(1)
    })
}

/// 固定 C fixture 將頂端值接到 child 的 runtime close frame；保留 C stack 原值。
///
/// # Safety
/// pointer 須是存活且 idle 的 child state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_install_runtime_close_b11(
    pointer: *mut lua_State,
) -> c_int {
    with_state(pointer, 0, |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let stack = state.stack.try_borrow().map_err(|_| StackError::Busy)?;
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        let slot = stack.slots.last().ok_or(StackError::InvalidIndex)?;
        let StackValue::Core(value) = slot.checked_value(&group.vm)?;
        group
            .vm
            .install_host_thread_close_fixture_b11(identity, value)?;
        Ok(1)
    })
}

/// 固定 C fixture 以 child stack 頂端 C function 啟動 coroutine；不公開 P16-3 resume。
///
/// # Safety
/// pointer 必須是已設 entry 的存活 C child。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_test_resume_prepare_b11(
    pointer: *mut lua_State,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if !group.callback_frames.entries.is_empty() || stack.slots.is_empty() {
            return Err(StackError::Busy);
        }
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        let StackValue::Core(callback) = stack
            .slots
            .last()
            .ok_or(StackError::InvalidState)?
            .checked_value(&group.vm)?;
        let outcome = {
            let mut execution = group
                .vm
                .resume(Value::Object(identity), &[callback, Value::Nil])?;
            execution.run()?
        };
        state.callback_outcome_b4(&mut group, &mut stack, outcome, 0, ResultMode::All)
    })
}

/// 純 C close driver 已處理 overlay marks 與 pending error，現在驅動 runtime walker。
///
/// # Safety
/// pointer 必須是 preflight 成功的同一 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_prepare_b11(
    pointer: *mut lua_State,
    overlay_status: c_int,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        let prepared = (|| -> Result<CallbackStepB4, StackError> {
            let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
            let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
            if !stack.close_marks.is_empty() {
                return Err(StackError::Busy);
            }
            let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
            let original = if overlay_status == 0 {
                None
            } else {
                let slot = stack.slots.last().ok_or(StackError::InvalidState)?;
                let StackValue::Core(value) = slot.checked_value(&group.vm)?;
                Some(value)
            };
            let pending_a5 = state
                .reset_public_a5
                .try_borrow()
                .map_err(|_| StackError::Busy)?
                .is_some();
            let outcome = if pending_a5 {
                let mut suspended = state
                    .suspended_a5
                    .try_borrow_mut()
                    .map_err(|_| StackError::Busy)?;
                let held = suspended.as_mut().ok_or(StackError::InvalidState)?;
                held.overlay = StackStorage::new();
                *state
                    .continuations_a5
                    .try_borrow_mut()
                    .map_err(|_| StackError::Busy)? = ContinuationStackA5::new();
                group.vm.close_suspended_external_a5(identity, original)?
            } else {
                group.vm.run_prepared_thread_reset_b11(identity, original)?
            };
            self::StateControl::callback_outcome_b4(
                state,
                &mut group,
                &mut stack,
                outcome,
                0,
                ResultMode::All,
            )
        })();
        Ok(prepared.unwrap_or_else(CallbackStepB4::operation_error_b5))
    })
}

/// 尚未執行的 reset frame 在 C checkpoint 建立失敗時須先撤銷。
///
/// # Safety
/// pointer 須是 preflight 成功的 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_cancel_b11(pointer: *mut lua_State) -> c_int {
    with_debug_state(pointer, 2, |state| {
        // checkpoint 尚未建立時由取消路徑撤銷；建立後由唯一的 exit 退鏈。
        if state.checkpoint_depth.get() == 0 {
            state.reset_permit_a5.take();
        }
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        if let Some(reset) = state
            .reset_public_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take()
        {
            state.test_fail_close_boundary_root_a5.set(false);
            if reset.stage == ResetStageA5::Prepared {
                *state.stack.try_borrow_mut().map_err(|_| StackError::Busy)? = reset.public;
                return Ok(0);
            }
            let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
            group.vm.abort_closing_external_a5(identity)?;
            let emergency = StackSlot::permanent_rooted(
                &group.vm,
                group.emergency_error,
                Rc::clone(&group.emergency_view),
            )?;
            let mut public = reset.public;
            if public.slots.capacity() == 0 {
                return Err(StackError::Layout);
            }
            public.slots.clear();
            public.close_marks.clear();
            public.slots.push(emergency);
            *state.stack.try_borrow_mut().map_err(|_| StackError::Busy)? = public;
            state
                .suspended_a5
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)?
                .take();
            *state
                .continuations_a5
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)? = ContinuationStackA5::new();
            state
                .pending_error
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)?
                .take();
            *state.debug.try_borrow_mut().map_err(|_| StackError::Busy)? = DebugState::new();
            let owned = group
                .callback_frames
                .entries
                .iter()
                .rev()
                .take_while(|frame| frame.owner_generation == state.state_generation)
                .count();
            let keep = group.callback_frames.entries.len() - owned;
            if group.callback_frames.entries[..keep]
                .iter()
                .any(|frame| frame.owner_generation == state.state_generation)
            {
                return Err(StackError::Layout);
            }
            group.callback_frames.entries.truncate(keep);
            group.callback_frames.release_empty();
            group.vm.finalize_thread_reset(Value::Object(identity))?;
            state.a5_status.set(0);
            return Ok(0);
        }
        group.vm.cancel_prepared_thread_reset_b11()?;
        Ok(0)
    })
}

/// callback 以 C-only checkpoint 捕獲的 Lua error 續接同一 runtime close unwind。
///
/// # Safety
/// pointer 必須是目前 reset callback 所屬 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_resume_error_b11(
    pointer: *mut lua_State,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let frame = group
            .callback_frames
            .entries
            .last()
            .ok_or(StackError::InvalidState)?;
        if frame.owner_generation != state.state_generation
            || frame.depth != group.callback_frames.entries.len()
        {
            return Err(StackError::Busy);
        }
        let token = frame.token;
        let pending = state
            .pending_error
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take()
            .ok_or(StackError::InvalidState)?;
        let StackValue::Core(value) = pending.slot.checked_value(&group.vm)?;
        let mut debug = state.debug.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let outcome = group
            .vm
            .continue_external(token, ExternalCommand::Error(value));
        let frame = group
            .callback_frames
            .entries
            .pop()
            .ok_or(StackError::InvalidState)?;
        debug.remove_external(frame.token);
        drop(debug);
        let base = frame.base();
        *stack = frame.saved_stack;
        group.callback_frames.release_empty();
        drop(pending);
        state.callback_outcome_b4(&mut group, &mut stack, outcome?, base, ResultMode::All)
    })
}

/// C-only driver 關完上一層 overlay 後，將最終錯誤交還同一 Lua close walker。
///
/// # Safety
/// pointer 必須是目前 reset checkpoint 所屬的 live child state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_resume_boundary_a5(
    pointer: *mut lua_State,
    overlay_status: c_int,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        let prepared = (|| -> Result<CallbackStepB4, StackError> {
            let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
            let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
            if !stack.close_marks.is_empty() {
                return Err(StackError::Busy);
            }
            let error = if overlay_status == 0 {
                None
            } else {
                let slot = stack.slots.last().ok_or(StackError::InvalidState)?;
                let StackValue::Core(value) = slot.checked_value(&group.vm)?;
                Some(value)
            };
            let token = state
                .reset_public_a5
                .try_borrow_mut()
                .map_err(|_| StackError::Busy)?
                .as_mut()
                .ok_or(StackError::InvalidState)?
                .boundary_token
                .take()
                .ok_or(StackError::InvalidState)?;
            {
                let mut suspended = state
                    .suspended_a5
                    .try_borrow_mut()
                    .map_err(|_| StackError::Busy)?;
                let held = suspended.as_mut().ok_or(StackError::InvalidState)?;
                held.frames.entries.pop().ok_or(StackError::Layout)?;
                held.frames.release_empty();
            }
            *stack = StackStorage::new();
            if state.test_fail_close_boundary_root_a5.replace(false) {
                if error.is_none() {
                    return Err(StackError::Layout);
                }
                let ordinal = group.vm.allocation_trace().next_ordinal;
                group.vm.inject_allocation_failure_at(ordinal);
            }
            let outcome = group.vm.continue_external_close_boundary_a5(token, error)?;
            state.callback_outcome_b4(&mut group, &mut stack, outcome, 0, ResultMode::All)
        })();
        Ok(prepared.unwrap_or_else(CallbackStepB4::operation_error_b5))
    })
}

/// 將 runtime 的 protected close tuple 轉為 Lua stack/status，最後清除 thread 執行欄位。
///
/// # Safety
/// pointer 必須是 reset driver 已取得終端 step 的 live state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_reset_finish_b11(
    pointer: *mut lua_State,
    latest_error_status: c_int,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| -> Result<c_int, StackError> {
        // SAFETY：有效 state 是 C driver 前置條件。
        let state = unsafe { checked_state(pointer)? };
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let identity = state.thread_identity.ok_or(StackError::InvalidState)?;
        let success = match stack.slots.as_slice() {
            [first] => matches!(
                first.checked_value(&group.vm)?,
                StackValue::Core(Value::Boolean(true))
            ),
            [first, _] => {
                if !matches!(
                    first.checked_value(&group.vm)?,
                    StackValue::Core(Value::Boolean(false))
                ) {
                    return Err(StackError::Layout);
                }
                false
            }
            _ => return Err(StackError::Layout),
        };
        if let Some(reset) = state
            .reset_public_a5
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .as_ref()
        {
            if reset.boundary_token.is_some() || !reset.outer_levels.is_empty() {
                return Err(StackError::Layout);
            }
            let suspended = state
                .suspended_a5
                .try_borrow()
                .map_err(|_| StackError::Busy)?;
            if suspended
                .as_ref()
                .is_some_and(|held| held.frames.entries.len() != 1)
            {
                return Err(StackError::Layout);
            }
        }
        group.vm.finalize_thread_reset(Value::Object(identity))?;
        state
            .suspended_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take();
        state
            .reset_public_a5
            .try_borrow_mut()
            .map_err(|_| StackError::Busy)?
            .take();
        state.test_fail_close_boundary_root_a5.set(false);
        state.a5_status.set(0);
        if success {
            stack.slots.clear();
            stack.release_empty_capacity();
            Ok(0)
        } else {
            if stack.slots.len() != 2 {
                return Err(StackError::Layout);
            }
            stack.slots.remove(0);
            Ok(if latest_error_status == 4 { 4 } else { 2 })
        }
    })) {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => close_public_status_b11(error),
        Err(_) => 2,
    }
}

/// 關閉 preflight 在任何 C mark callback 之前完成；Rust owner 與 C-owned
/// main 共用此檢查，配置失敗保留原本的結構化錯誤。
///
/// # Safety
/// pointer 必須是存活的 state，且呼叫期間不可從其他執行緒釋放。
unsafe fn close_main_preflight_b11(
    pointer: *mut lua_State,
    expected_c_owned: bool,
) -> Result<*mut lua_State, StackError> {
    // SAFETY：呼叫者保證 state 在本次同步 preflight 期間保持有效。
    let state = unsafe { checked_state(pointer)? };
    let main_pointer = state.main_pointer.get();
    // SAFETY：同組 main 配置須在 group 存活期間保持有效。
    let main = unsafe { checked_state(main_pointer)? };
    if !main.main_control || main.c_owned.get() != expected_c_owned {
        return Err(StackError::InvalidState);
    }
    if state.checkpoint_depth.get() != 0 || main.checkpoint_depth.get() != 0 {
        return Err(StackError::Busy);
    }
    if state
        .pending_error
        .try_borrow()
        .map_err(|_| StackError::Busy)?
        .is_some()
        || main
            .pending_error
            .try_borrow()
            .map_err(|_| StackError::Busy)?
            .is_some()
    {
        return Err(StackError::Busy);
    }
    let owner = main.group.upgrade().ok_or(StackError::InvalidState)?;
    let other = state.group.upgrade().ok_or(StackError::InvalidState)?;
    if !Rc::ptr_eq(&owner, &other) {
        return Err(StackError::WrongVm);
    }
    let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
    if !group.callback_frames.entries.is_empty()
        || group.vm.execution_running()
        || group.vm.finalizer_running()
    {
        return Err(StackError::Busy);
    }
    let mut stack = main.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
    let required = stack
        .slots
        .len()
        .checked_add(1)
        .ok_or(StackError::StackLimit)?;
    stack.ensure_capacity(&group.vm, required)?;
    group.vm.preflight_shutdown_finalizers()?;
    Ok(main_pointer)
}

/// 關閉 preflight 返回同組 C-owned main。
///
/// # Safety
/// pointer 必須是存活的 C state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_close_main_b11(
    pointer: *mut lua_State,
) -> *mut lua_State {
    ffi_boundary(std::ptr::null_mut(), || {
        // SAFETY：有效 C state 是本入口的前置條件。
        unsafe { close_main_preflight_b11(pointer, true) }
    })
}

/// 一次 shutdown queue/drain step；新註冊物件由純 C coordinator 再次呼叫本入口。
///
/// # Safety
/// pointer 必須是 live C-owned main，且目前無 Rust 借用跨 C callback。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_shutdown_prepare_b11(
    pointer: *mut lua_State,
) -> CallbackStepB4 {
    with_state(pointer, CallbackStepB4::error(), |state| {
        if !state.main_control || !state.c_owned.get() {
            return Err(StackError::InvalidState);
        }
        let owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        group.vm.queue_shutdown_finalizers()?;
        if !group.vm.gc_finalizers_pending() {
            return Ok(CallbackStepB4::done());
        }
        let outcome = {
            let mut execution = group.vm.gc_finalizer_execution(None)?;
            execution.run()?
        };
        match outcome {
            RunOutcome::Returned(_) => {
                // 本輪同步排空有進展；C coordinator 須再掃描 callback 新註冊的物件。
                let mut step = CallbackStepB4::done();
                step.value = 1;
                Ok(step)
            }
            RunOutcome::External(_) => {
                let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
                let base = stack.slots.len();
                state.callback_outcome_b4(
                    &mut group,
                    &mut stack,
                    outcome,
                    base,
                    ResultMode::Fixed(0),
                )
            }
            _ => Err(StackError::InvalidState),
        }
    })
}

/// 最終釋放只在 C coordinator 已完成 callback 與 checkpoint 後執行。
///
/// # Safety
/// pointer 必須是 `StateOwner::into_c_ptr` 移交，或由
/// `StateOwner::close_with_finalizers` 暫交額外 raw strong 的 live main pointer；
/// `c_owned` 與 `live` 檢查確保這份 raw strong 只在成功路徑消耗一次。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_close_drop_b11(pointer: *mut lua_State) -> c_int {
    ffi_boundary(0, || {
        {
            // SAFETY：有效 pointer 是 C 呼叫者前置條件；checked_state 先核對 thread 再建立共享參照。
            let state = unsafe { checked_state(pointer)? };
            if !state.main_control || !state.c_owned.get() {
                return Err(StackError::InvalidState);
            }
            if state.checkpoint_depth.get() != 0
                || state
                    .pending_error
                    .try_borrow()
                    .map_err(|_| StackError::Busy)?
                    .is_some()
            {
                return Err(StackError::Busy);
            }
            // 同時取得兩個可變借用，確保借用中的 VM／stack 不被 close 釋放。
            let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
            let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let _stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
            if !group.callback_frames.entries.is_empty()
                || group.vm.execution_running()
                || group.vm.finalizer_running()
            {
                return Err(StackError::Busy);
            }
            group.vm.queue_shutdown_finalizers()?;
            if group.vm.gc_finalizers_pending() {
                return Err(StackError::Busy);
            }
            group.generation = 0;
            group.main_allocation = Weak::new();
            state.main_pointer.set(std::ptr::null_mut());
            state.live.set(false);
            state.magic.set(0);
        }
        // SAFETY：此 pointer 對應 into_c_ptr 移交或 close_with_finalizers
        // 暫交的 Rc::into_raw strong；StateAllocation 為 repr(C)，control
        // 的固定偏移已由 attach 驗證。c_owned 與 live 已確認，且只有
        // 成功 close 才到此處，故僅還原並消耗該 raw strong 一次。
        unsafe {
            let allocation = pointer
                .cast::<u8>()
                .sub(offset_of!(StateAllocation, control))
                .cast::<StateAllocation>();
            let allocation = Rc::from_raw(allocation);
            if let Ok(mut allocation) = Rc::try_unwrap(allocation) {
                let charge = allocation.control._charge.take();
                drop(allocation);
                // state backing 已釋放；最後退還其 allocator token。
                drop(charge);
            }
        }
        Ok(1)
    })
}

/// SAFETY：非空 pointer 必須指向仍存活的 state；既有 with_state 核對執行緒與 VM 身分。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_status(pointer: *mut lua_State) -> c_int {
    with_state(pointer, 0, |state| {
        if state.main_control {
            return Ok(0);
        }
        Ok(state.a5_status.get())
    })
}

/// 純 C resume checkpoint 呼叫此步後，Rust 借用與 frame 皆已結束，才准 C 跳轉。
///
/// # Safety
/// pointer 必須是目前 live child；continuation 是固定 Lua ABI 的 C 函式指標。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_yield_prepare_a5(
    pointer: *mut lua_State,
    nresults: c_int,
    context: isize,
    continuation: Option<LuaKFunction>,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：C caller 保證有效 state，checked_state 再核對 thread 與世代。
        let state = unsafe { checked_state(pointer)? };
        state.yield_prepare_a5(nresults, continuation, context)
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => -operation_error_class_b5(error),
        Err(_) => -(ErrorClass::Lua as c_int),
    }
}

/// callk／pcallk 在仍可 yield 的 C callback 內，將 POD K 與 handler ownership 交給 child。
///
/// # Safety
/// state 必須 live；非空 handler 必須是本次 public preflight 唯一交出的 Box。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_continuation_push_a5(
    pointer: *mut lua_State,
    continuation: Option<LuaKFunction>,
    context: isize,
    protected: c_int,
    nresults: c_int,
    base: usize,
    handler: *mut c_void,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：C wrapper 在同一 live callback 中同步呼叫。
        let state = unsafe { checked_state(pointer)? };
        state.continuation_push_a5(
            continuation.ok_or(StackError::InvalidIndex)?,
            context,
            protected != 0,
            nresults,
            base,
            handler,
        )
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => -operation_error_class_b5(error),
        Err(_) => -(ErrorClass::Lua as c_int),
    }
}

/// 只讀或消耗目前 callback 深度的 K；消耗時 handler Box 隨記錄釋放。
///
/// # Safety
/// pointer 必須 live，depth 為 C driver 從同一 state 讀得的 callback 深度。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_continuation_step_a5(
    pointer: *mut lua_State,
    depth: usize,
    consume: c_int,
) -> ContinuationStepA5 {
    with_state(pointer, ContinuationStepA5::none(), |state| {
        state.continuation_step_a5(depth, consume != 0)
    })
}

/// 內層 callback 歸還結果時，使用目前 callk／pcallk 既定結果數。
///
/// # Safety
/// pointer 必須 live；C resume checkpoint 持有 callback 狀態。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_continuation_results_a5(
    pointer: *mut lua_State,
) -> c_int {
    with_state(pointer, -1, StateControl::continuation_results_a5)
}

/// 公開 C resume 的單次 Rust step；只回傳 POD，C callback 僅由 C driver 呼叫。
///
/// # Safety
/// pointer 與非空 from 必須是呼叫期間 live 的 C state。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_resume_prepare_a5(
    pointer: *mut lua_State,
    from: *mut lua_State,
    nargs: c_int,
) -> ResumeSetupA5 {
    match catch_unwind(AssertUnwindSafe(|| -> Result<ResumeSetupA5, StackError> {
        // SAFETY：有效 C state 是公開 API 前置條件；checked_state 驗證世代與 thread。
        let state = unsafe { checked_state(pointer)? };
        let source = if from.is_null() {
            None
        } else {
            // SAFETY：非空 from 的有效期由 C caller 保證。
            Some(unsafe { checked_state(from)? })
        };
        state.resume_prepare_a5(source, nargs)
    })) {
        Ok(Ok(setup)) => setup,
        Ok(Err(error)) => ResumeSetupA5::rejected(error),
        Err(_) => ResumeSetupA5::rejected(StackError::InvalidState),
    }
}

/// 最外層 runtime resume 結束後移除私有成功旗標，發布公開 status／nresults。
///
/// # Safety
/// pointer 必須是目前 C resume checkpoint 保活的 child。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_resume_finish_a5(
    pointer: *mut lua_State,
    base: usize,
    frame_depth: usize,
    error_class: c_int,
) -> ResumeFinishA5 {
    let rejected = ResumeFinishA5 {
        status: -1,
        nresults: 0,
    };
    match catch_unwind(AssertUnwindSafe(
        || -> Result<ResumeFinishA5, StackError> {
            // SAFETY：live child 是 C driver 前置條件；checked_state 重新驗證身分。
            unsafe { checked_state(pointer)? }.resume_finish_a5(base, frame_depth, error_class)
        },
    )) {
        Ok(Ok(result)) => result,
        _ => rejected,
    }
}

/// 依固定 Lua 5.4.9 契約忽略 limit 並回傳 `LUAI_MAXCCALLS`（200），不修改 state 或限制實際呼叫深度。
///
/// # Safety
/// 非空 pointer 必須在呼叫期間指向有效 state；共用 `with_state` 邊界會驗證其身分、世代、執行緒與 VM 借用狀態。
#[cfg(feature = "lua54")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_setcstacklimit(pointer: *mut lua_State, _limit: c_uint) -> c_int {
    with_state(pointer, 0, |_| Ok(200))
}

/// SAFETY：非空 pointer 必須指向仍存活的 state；僅有真實 child thread 可回報可 yield。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_isyieldable(pointer: *mut lua_State) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(c_int::from(
            !state.main_control && state.thread_identity.is_some(),
        ))
    })
}

impl StateControl {
    fn buffer_anchor(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
        snapshot: BufferSnapshot,
        group: &StateGroup,
        stack: &StackStorage,
        above: usize,
    ) -> Result<usize, StackError> {
        if snapshot.state != state_pointer || snapshot.n > snapshot.size {
            return Err(StackError::Layout);
        }
        let position = stack
            .slots
            .len()
            .checked_sub(above + 1)
            .ok_or(StackError::InvalidIndex)?;
        let value = stack.slots[position].checked_value(&group.vm)?;
        if snapshot.b == snapshot.init && snapshot.size == LUAL_BUFFERSIZE {
            if !matches!(value, StackValue::Core(Value::LightUserdata(address)) if address == buffer as usize)
            {
                return Err(StackError::InvalidIndex);
            }
        } else {
            let StackValue::Core(Value::Object(object)) = value else {
                return Err(StackError::InvalidIndex);
            };
            if group.vm.object_kind(object)? != ObjectKind::Userdata
                || group.vm.userdata_len(object)? != snapshot.size
                || group.vm.userdata_ptr(object)? != snapshot.b
            {
                return Err(StackError::InvalidIndex);
            }
        }
        Ok(position)
    }

    fn buffer_init(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
    ) -> Result<(), StackError> {
        self.validate()?;
        if buffer.is_null() || (buffer as usize) % LUAL_BUFFER_ALIGN != 0 {
            return Err(StackError::Layout);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        stack.ensure_capacity(&group.vm, required)?;
        let anchor = StackSlot::new(
            &mut group.vm,
            StackValue::Core(Value::LightUserdata(buffer as usize)),
        )?;
        stack.slots.push(anchor);
        // SAFETY：呼叫者提供完整、對齊、可寫的固定 header buffer；上方操作均成功，
        // 四欄與 init 位址寫入後沒有可失敗步驟，沒有 raw borrow 跨配置。
        unsafe {
            let init = buffer
                .cast::<u8>()
                .add(size_of::<LuaLBufferPrefix>())
                .cast::<c_char>();
            let prefix = buffer.cast::<LuaLBufferPrefix>();
            std::ptr::addr_of_mut!((*prefix).b).write(init);
            std::ptr::addr_of_mut!((*prefix).size).write(LUAL_BUFFERSIZE);
            std::ptr::addr_of_mut!((*prefix).n).write(0);
            std::ptr::addr_of_mut!((*prefix).state).write(state_pointer);
        }
        Ok(())
    }

    fn buffer_prep(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
        requested: usize,
        source: Option<*const u8>,
        above: usize,
    ) -> Result<*mut c_char, BufferFailure> {
        self.validate()?;
        // SAFETY：C 呼叫者保證 buffer 在同步呼叫期間有效且已初始化。
        let snapshot = unsafe { buffer_snapshot(buffer)? };
        let new_len = snapshot
            .n
            .checked_add(requested)
            .ok_or(BufferFailure::TooLarge)?;
        if new_len > isize::MAX as usize {
            return Err(BufferFailure::TooLarge);
        }
        if source.is_some_and(|source| source.is_null() && requested != 0) {
            return Err(StackError::InvalidIndex.into());
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position =
            self.buffer_anchor(state_pointer, buffer, snapshot, &group, &stack, above)?;
        if stack.close_marks.binary_search(&position).is_ok()
            || (source.is_some() && above == 1 && !stack.can_remove_from(stack.slots.len() - 1))
        {
            return Err(StackError::InvalidIndex.into());
        }
        if snapshot.size - snapshot.n >= requested {
            // SAFETY：n+requested 已檢查不越過 size；copy 可處理來源與目標重疊。
            let destination = unsafe { snapshot.b.add(snapshot.n) };
            if let Some(source) = source {
                if requested != 0 {
                    // SAFETY：C 呼叫者保證來源有 requested bytes；目的已驗容量，copy 支援 overlap。
                    unsafe { std::ptr::copy(source, destination, requested) };
                }
                // SAFETY：已完成複製且 n+requested 在容量內；只寫固定前綴欄位。
                unsafe {
                    std::ptr::addr_of_mut!((*buffer.cast::<LuaLBufferPrefix>()).n).write(new_len)
                };
                if above == 1 {
                    stack.slots.pop();
                }
            }
            return Ok(destination.cast());
        }
        let minimum = new_len
            .checked_add(usize::from(cfg!(feature = "lua55")))
            .ok_or(BufferFailure::TooLarge)?;
        if minimum > isize::MAX as usize {
            return Err(BufferFailure::TooLarge);
        }
        let grown = snapshot
            .size
            .checked_add(snapshot.size / 2)
            .unwrap_or(minimum);
        let new_size = grown.max(minimum);
        if new_size > isize::MAX as usize {
            return Err(BufferFailure::TooLarge);
        }
        let (object, root, destination) = group.vm.prepare_unpublished_host_userdata(
            new_size,
            0,
            |_| Ok::<(), StackError>(()),
        )?;
        // 舊 box 的 stack root 與 addvalue 來源 slot 在下方複製完成前都仍存活。
        // SAFETY：新 userdata 有 new_size bytes；舊 buffer 有 n bytes；兩邊均受有效
        // stack anchor 保活。ptr::copy 同時處理來源位於舊 buffer 的 alias。
        unsafe {
            if snapshot.n != 0 {
                std::ptr::copy(snapshot.b, destination, snapshot.n);
            }
            if let Some(source) = source {
                if requested != 0 {
                    std::ptr::copy(source, destination.add(snapshot.n), requested);
                }
            }
        }
        stack.slots[position] = StackSlot {
            value: StackValue::Core(Value::Object(object)),
            root: Some(root),
            string_view: None,
        };
        if source.is_some() && above == 1 {
            stack.slots.pop();
        }
        // SAFETY：所有配置、複製與 root 建立已成功；此後只發布固定前綴欄位。
        unsafe {
            let prefix = buffer.cast::<LuaLBufferPrefix>();
            std::ptr::addr_of_mut!((*prefix).b).write(destination.cast());
            std::ptr::addr_of_mut!((*prefix).size).write(new_size);
            if source.is_some() {
                std::ptr::addr_of_mut!((*prefix).n).write(new_len);
            }
            Ok(destination.add(snapshot.n).cast())
        }
    }

    fn buffer_pushresult(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
        extra: usize,
    ) -> Result<(), BufferFailure> {
        self.validate()?;
        // SAFETY：C 呼叫者保證已初始化 buffer 在同步呼叫期間有效。
        let snapshot = unsafe { buffer_snapshot(buffer)? };
        let result_len = snapshot
            .n
            .checked_add(extra)
            .ok_or(BufferFailure::TooLarge)?;
        if result_len > snapshot.size {
            return Err(BufferFailure::TooLarge);
        }
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let position = self.buffer_anchor(state_pointer, buffer, snapshot, &group, &stack, 0)?;
        if stack.close_marks.binary_search(&position).is_ok() {
            return Err(StackError::InvalidIndex.into());
        }
        // SAFETY：inline buffer 或 rooted userdata 在此時有 result_len 個可讀 bytes；
        // new_raw 預留容量後才短暫複製 raw bytes。
        let view = unsafe { StringView::new_raw(&group.vm, snapshot.b, result_len)? };
        group
            .vm
            .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                let mut slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                slot.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                stack.slots[position] = slot;
                Ok::<(), StackError>(())
            })?;
        // SAFETY：結果字串與 root 均已發布；對 pushresultsize 精確提交 n。
        unsafe { std::ptr::addr_of_mut!((*buffer.cast::<LuaLBufferPrefix>()).n).write(result_len) };
        Ok(())
    }

    fn buffer_addvalue(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
    ) -> Result<(), BufferFailure> {
        self.validate()?;
        // SAFETY：C 呼叫者保證已初始化 buffer 有效；此處僅複製四欄值。
        let snapshot = unsafe { buffer_snapshot(buffer)? };
        {
            let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
            let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
            let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
            self.buffer_anchor(state_pointer, buffer, snapshot, &group, &stack, 1)?;
        }
        let (source, len) = self.checked_lstring(-1)?;
        self.buffer_prep(state_pointer, buffer, len, Some(source.cast()), 1)?;
        Ok(())
    }

    fn buffer_addgsub(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
        source: *const c_char,
        pattern: *const c_char,
        replacement: *const c_char,
    ) -> Result<(), BufferFailure> {
        self.validate()?;
        if source.is_null() || pattern.is_null() || replacement.is_null() {
            return Err(StackError::InvalidIndex.into());
        }
        // SAFETY：C 呼叫者保證三個來源均為有效 NUL 結尾字串；只取得長度，
        // 之後各自建立已計費複本，絕不跨配置保留 raw slice。
        let lengths = unsafe {
            (
                CStr::from_ptr(source).to_bytes().len(),
                CStr::from_ptr(pattern).to_bytes().len(),
                CStr::from_ptr(replacement).to_bytes().len(),
            )
        };
        let (source, pattern, replacement) = {
            let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
            let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
            // SAFETY：raw 指標在本次同步呼叫有效；new_raw 各自在配置後才複製。
            unsafe {
                (
                    StringView::new_raw(&group.vm, source.cast(), lengths.0)?,
                    StringView::new_raw(&group.vm, pattern.cast(), lengths.1)?,
                    StringView::new_raw(&group.vm, replacement.cast(), lengths.2)?,
                )
            }
        };
        let source = source.as_bytes();
        let pattern = pattern.as_bytes();
        let replacement = replacement.as_bytes();
        let mut cursor = 0;
        loop {
            let next = if pattern.is_empty() {
                Some(cursor)
            } else {
                find_gsub_match(source, pattern, cursor)
            };
            let Some(start) = next else {
                let tail = &source[cursor..];
                self.buffer_prep(state_pointer, buffer, tail.len(), Some(tail.as_ptr()), 0)?;
                return Ok(());
            };
            let prefix = &source[cursor..start];
            self.buffer_prep(
                state_pointer,
                buffer,
                prefix.len(),
                Some(prefix.as_ptr()),
                0,
            )?;
            self.buffer_prep(
                state_pointer,
                buffer,
                replacement.len(),
                Some(replacement.as_ptr()),
                0,
            )?;
            cursor = start
                .checked_add(pattern.len())
                .ok_or(BufferFailure::TooLarge)?;
        }
    }

    fn buffer_cleanup(
        &self,
        state_pointer: *mut lua_State,
        buffer: *mut luaL_Buffer,
    ) -> Result<(), Reject> {
        // 錯誤跳轉前清除本 buffer 的 placeholder/box 及可能尚在頂端的 addvalue 來源。
        // SAFETY：公開 C buffer API 的有效 buffer 是同步呼叫前置條件。
        let snapshot = unsafe { buffer_snapshot(buffer) }.map_err(|_| Reject::Stale)?;
        let group_owner = self.group.upgrade().ok_or(Reject::Stale)?;
        let group = group_owner.try_borrow().map_err(|_| Reject::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| Reject::Busy)?;
        for above in [0, 1] {
            if let Ok(position) =
                self.buffer_anchor(state_pointer, buffer, snapshot, &group, &stack, above)
            {
                if !stack.can_remove_from(position) {
                    return Err(Reject::StackChanged);
                }
                stack.slots.truncate(position);
                return Ok(());
            }
        }
        Err(Reject::StackChanged)
    }
}

/// 初始化固定 header 公開的 `luaL_Buffer` 前綴並放入 stack placeholder。
///
/// # Safety
/// 非空 `pointer` 必須在整次呼叫期間指向仍存活且不會被釋放的 state allocation；跨執行緒
/// 呼叫只可在 state 無其他同時存取時進行，以便安全 fail-closed。非空 `buffer` 必須在整次
/// 呼叫期間指向可寫、完整、依固定 header layout 與最大對齊配置的 `luaL_Buffer`，且不得與
/// state 或其他同時存取者別名；其公開前綴之後須至少有 `LUAL_BUFFERSIZE` 個可寫 bytes。
#[allow(non_snake_case)]
pub unsafe fn luaL_buffinit(pointer: *mut lua_State, buffer: *mut luaL_Buffer) {
    with_state(pointer, (), |state| state.buffer_init(pointer, buffer));
}

/// # Safety
/// buffer 必須是有效期內且已初始化的固定 header buffer。
unsafe fn buffer_with_state<R: Copy>(
    buffer: *mut luaL_Buffer,
    default: R,
    operation: impl FnOnce(&StateControl, *mut lua_State) -> Result<R, BufferFailure>,
) -> R {
    // SAFETY：呼叫者保證 buffer 已初始化且仍存活；只複製固定欄位取得 state。
    let Ok(snapshot) = (unsafe { buffer_snapshot(buffer) }) else {
        return default;
    };
    with_state(snapshot.state, default, |state| {
        operation(state, snapshot.state).map_err(|error| match error {
            BufferFailure::TooLarge => StackError::StackLimit,
            BufferFailure::Stack(error) => error,
        })
    })
}

/// # Safety
/// buffer 須已初始化且有效，回傳區域只在下一次 buffer mutation 前有效。
#[allow(non_snake_case)]
pub unsafe fn luaL_prepbuffsize(buffer: *mut luaL_Buffer, size: usize) -> *mut c_char {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 有效。
    unsafe {
        buffer_with_state(buffer, std::ptr::null_mut(), |state, pointer| {
            state.buffer_prep(pointer, buffer, size, None, 0)
        })
    }
}

/// # Safety
/// source 非空時須有 len bytes 可讀；buffer 必須有效且已初始化。
#[allow(non_snake_case)]
pub unsafe fn luaL_addlstring(buffer: *mut luaL_Buffer, source: *const c_char, len: usize) {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 與來源有效。
    unsafe {
        buffer_with_state(buffer, (), |state, pointer| {
            state.buffer_prep(pointer, buffer, len, Some(source.cast()), 0)?;
            Ok(())
        })
    }
}

/// # Safety
/// source 須指向有效 NUL 結尾字串；buffer 必須有效且已初始化。
#[allow(non_snake_case)]
pub unsafe fn luaL_addstring(buffer: *mut luaL_Buffer, source: *const c_char) {
    if source.is_null() {
        return;
    }
    // SAFETY：呼叫者保證 source NUL 結尾；僅取長度，不跨配置借用。
    let len = unsafe { CStr::from_ptr(source).to_bytes().len() };
    // SAFETY：由同一 C ABI 前置條件保證 buffer 與來源有效。
    unsafe { luaL_addlstring(buffer, source, len) };
}

/// # Safety
/// buffer 須已初始化；頂端值須可依 Lua 規則轉成字串。
#[allow(non_snake_case)]
pub unsafe fn luaL_addvalue(buffer: *mut luaL_Buffer) {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 有效。
    unsafe {
        buffer_with_state(buffer, (), |state, pointer| {
            state.buffer_addvalue(pointer, buffer)
        })
    }
}

/// # Safety
/// buffer 須已初始化且在 stack 頂端持有其 placeholder 或 box。
#[allow(non_snake_case)]
pub unsafe fn luaL_pushresult(buffer: *mut luaL_Buffer) {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 有效。
    unsafe {
        buffer_with_state(buffer, (), |state, pointer| {
            state.buffer_pushresult(pointer, buffer, 0)
        })
    }
}

/// # Safety
/// buffer 須已初始化，最後 size bytes 已寫入 prepbuffsize 回傳的區域。
#[allow(non_snake_case)]
pub unsafe fn luaL_pushresultsize(buffer: *mut luaL_Buffer, size: usize) {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 有效。
    unsafe {
        buffer_with_state(buffer, (), |state, pointer| {
            state.buffer_pushresult(pointer, buffer, size)
        })
    }
}

/// # Safety
/// state 與 buffer 必須有效，回傳區域只在下一次 buffer mutation 前有效。
#[allow(non_snake_case)]
pub unsafe fn luaL_buffinitsize(
    pointer: *mut lua_State,
    buffer: *mut luaL_Buffer,
    size: usize,
) -> *mut c_char {
    with_state(pointer, std::ptr::null_mut(), |state| {
        state.buffer_init(pointer, buffer)?;
        state
            .buffer_prep(pointer, buffer, size, None, 0)
            .map_err(|error| match error {
                BufferFailure::TooLarge => StackError::StackLimit,
                BufferFailure::Stack(error) => error,
            })
    })
}

/// # Safety
/// buffer 須已初始化；source、pattern、replacement 均為有效 NUL 結尾字串。
#[allow(non_snake_case)]
pub unsafe fn luaL_addgsub(
    buffer: *mut luaL_Buffer,
    source: *const c_char,
    pattern: *const c_char,
    replacement: *const c_char,
) {
    // SAFETY：由同一 C ABI 前置條件保證 buffer 與三個來源有效。
    unsafe {
        buffer_with_state(buffer, (), |state, pointer| {
            state.buffer_addgsub(pointer, buffer, source, pattern, replacement)
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawBufferResult {
    pub kind: i32,
    pub value: i32,
    pub pointer: *mut c_char,
}

impl RawBufferResult {
    fn returned(pointer: *mut c_char) -> Self {
        Self {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer,
        }
    }

    fn raised(class: ErrorClass) -> Self {
        Self {
            kind: codes::ACTION_RAISE,
            value: class as i32,
            pointer: std::ptr::null_mut(),
        }
    }

    fn rejected(reject: Reject) -> Self {
        Self {
            kind: codes::ACTION_REJECT,
            value: reject as i32,
            pointer: std::ptr::null_mut(),
        }
    }
}

fn buffer_dispatch_inner(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    buffer: *mut luaL_Buffer,
    operation: i32,
    source: *const c_char,
    pattern: *const c_char,
    replacement: *const c_char,
    size: usize,
) -> RawBufferResult {
    // buffinit 與 buffinitsize 的公開 prefix 在 buffer_init 成功前可能尚未初始化；
    // 只有已發布 anchor 的操作可在錯誤路徑讀取 prefix 並清理 stack。
    let mut cleanup = !matches!(operation, codes::BUFFER_INIT | codes::BUFFER_BUFFINITSIZE);
    let result = with_state(
        pointer,
        Err(BufferFailure::Stack(StackError::InvalidState)),
        |state| {
            let result = match operation {
                codes::BUFFER_INIT => state
                    .buffer_init(pointer, buffer)
                    .map(|()| std::ptr::null_mut())
                    .map_err(BufferFailure::from),
                codes::BUFFER_PREP => state.buffer_prep(pointer, buffer, size, None, 0),
                codes::BUFFER_ADDLSTRING => state
                    .buffer_prep(pointer, buffer, size, Some(source.cast()), 0)
                    .map(|_| std::ptr::null_mut()),
                codes::BUFFER_ADDSTRING => {
                    if source.is_null() {
                        Err(BufferFailure::Stack(StackError::InvalidIndex))
                    } else {
                        // SAFETY：C 呼叫者保證 source 是有效 NUL 結尾字串；
                        // 只取長度，借用在任何配置前結束。
                        let len = unsafe { CStr::from_ptr(source).to_bytes().len() };
                        state
                            .buffer_prep(pointer, buffer, len, Some(source.cast()), 0)
                            .map(|_| std::ptr::null_mut())
                    }
                }
                codes::BUFFER_ADDVALUE => state
                    .buffer_addvalue(pointer, buffer)
                    .map(|()| std::ptr::null_mut()),
                codes::BUFFER_PUSHRESULT => state
                    .buffer_pushresult(pointer, buffer, 0)
                    .map(|()| std::ptr::null_mut()),
                codes::BUFFER_PUSHRESULTSIZE => state
                    .buffer_pushresult(pointer, buffer, size)
                    .map(|()| std::ptr::null_mut()),
                codes::BUFFER_BUFFINITSIZE => match state.buffer_init(pointer, buffer) {
                    Ok(()) => {
                        cleanup = true;
                        state.buffer_prep(pointer, buffer, size, None, 0)
                    }
                    Err(error) => Err(error.into()),
                },
                codes::BUFFER_ADDGSUB => state
                    .buffer_addgsub(pointer, buffer, source, pattern, replacement)
                    .map(|()| std::ptr::null_mut()),
                _ => Err(BufferFailure::Stack(StackError::InvalidIndex)),
            };
            Ok(result)
        },
    );
    let failure = match result {
        Ok(pointer) => return RawBufferResult::returned(pointer),
        Err(failure) => failure,
    };
    let (message, requested_class) = match failure {
        BufferFailure::TooLarge => (b"resulting string too large".as_slice(), ErrorClass::Lua),
        BufferFailure::Stack(StackError::StackLimit) => {
            (b"resulting string too large".as_slice(), ErrorClass::Lua)
        }
        BufferFailure::Stack(error) if version_error_allocation_failed(error) => {
            (MEMORY_ERROR_BYTES, ErrorClass::Allocation)
        }
        BufferFailure::Stack(StackError::Busy) => return RawBufferResult::rejected(Reject::Busy),
        _ => return RawBufferResult::rejected(Reject::InvalidAction),
    };
    let checkpoint = Checkpoint {
        state: pointer,
        generation,
        token,
    };
    if let Err(reject) = crate::trampoline::probe(checkpoint) {
        return RawBufferResult::rejected(reject);
    }
    let prepared: Result<ErrorClass, Reject> = with_state(pointer, Err(Reject::Stale), |state| {
        Ok((|| {
            if cleanup {
                state.buffer_cleanup(pointer, buffer)?;
            }
            prepare_message_pending(state, checkpoint, message, requested_class)
        })())
    });
    match prepared {
        Ok(class) => RawBufferResult::raised(class),
        Err(reject) => RawBufferResult::rejected(reject),
    }
}

/// 固定 header C facade 的私有執行入口；只回 POD，不在 Rust frame 內跳轉。
///
/// # Safety
/// pointer／buffer／C 字串在同步呼叫期間有效；buffer 依固定 header 對齊且已初始化，
/// 唯獨 INIT／BUFFINITSIZE 可接收未初始化 buffer。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_buffer_dispatch_a49(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    buffer: *mut luaL_Buffer,
    operation: i32,
    source: *const c_char,
    pattern: *const c_char,
    replacement: *const c_char,
    size: usize,
) -> RawBufferResult {
    catch_unwind(AssertUnwindSafe(|| {
        buffer_dispatch_inner(
            pointer,
            generation,
            token,
            buffer,
            operation,
            source,
            pattern,
            replacement,
            size,
        )
    }))
    .unwrap_or(RawBufferResult::rejected(Reject::Panic))
}

/// SAFETY：固定 header 符號名稱唯一；所有指標讀取經 with_state 驗證，panic 不跨 ABI。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_absindex(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        if index > 0 || index <= REGISTRY_INDEX {
            return Ok(index);
        }
        let top = state.top()? as i64;
        c_int::try_from(top + index as i64 + 1).map_err(|_| StackError::InvalidIndex)
    })
}

/// SAFETY：固定 header 符號名稱唯一；state 前置條件由 with_state 檢查。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_gettop(pointer: *mut lua_State) -> c_int {
    with_state(pointer, 0, |state| {
        c_int::try_from(state.top()?).map_err(|_| StackError::StackLimit)
    })
}

/// SAFETY：有效 state 為 C ABI 前置條件；設定先提交 runtime，再發布 state binding。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_sethook(
    pointer: *mut lua_State,
    callback: Option<LuaHook>,
    mask: c_int,
    count: c_int,
) {
    with_debug_state(pointer, (), |state| state.set_hook(callback, mask, count));
}

/// SAFETY：有效 state 為 C ABI 前置條件；getter 不配置或借出內部物件。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_gethook(pointer: *mut lua_State) -> Option<LuaHook> {
    with_debug_state(pointer, None, |state| Ok(state.hook_binding()?.callback))
}

/// SAFETY：有效 state 為 C ABI 前置條件；未知 mask bits 依固定 vendor 保留低 8 bits。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_gethookmask(pointer: *mut lua_State) -> c_int {
    with_debug_state(pointer, 0, |state| Ok(state.hook_binding()?.mask))
}

/// SAFETY：有效 state 為 C ABI 前置條件；count 保存原始傳入值。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_gethookcount(pointer: *mut lua_State) -> c_int {
    with_debug_state(pointer, 0, |state| Ok(state.hook_binding()?.count))
}

/// SAFETY：`ar` 由 C 呼叫者提供完整且可寫的固定 profile lua_Debug；只寫 opaque token。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_getstack(
    pointer: *mut lua_State,
    level: c_int,
    ar: *mut lua_Debug,
) -> c_int {
    if ar.is_null() {
        return 0;
    }
    with_debug_state(pointer, 0, |state| {
        let Some(key) = state.debug_getstack(level)? else {
            return Ok(0);
        };
        // SAFETY：非 null ar 是呼叫者的可寫完整 ABI 結構；key 只當整數身分回傳。
        unsafe { (*ar).i_ci = key as *mut c_void };
        Ok(1)
    })
}

/// SAFETY：呼叫者提供對齊且可寫的固定 profile lua_Debug，selectors 已經驗證。
unsafe fn publish_debug_info_b10(
    ar: *mut lua_Debug,
    selectors: &DebugSelectors,
    commit: &DebugInfoCommit,
) {
    // SAFETY：C ABI 前置條件保證 ar 指向完整結構；本函式只寫 selector 指定欄位。
    let ar = unsafe { &mut *ar };
    let info = &commit.info;
    if selectors.name {
        ar.name = commit.name.unwrap_or(std::ptr::null());
        ar.namewhat = commit.namewhat.unwrap_or(c"".as_ptr());
    }
    if selectors.source {
        ar.what = match info.kind {
            DebugFrameKind::C => c"C".as_ptr(),
            DebugFrameKind::Lua => c"Lua".as_ptr(),
            DebugFrameKind::Main => c"main".as_ptr(),
            DebugFrameKind::Tail => c"tail".as_ptr(),
        };
        ar.source = commit.source.unwrap_or(std::ptr::null());
        ar.srclen = info.source.len();
        ar.linedefined = c_int::try_from(info.linedefined).unwrap_or(c_int::MAX);
        ar.lastlinedefined = c_int::try_from(info.lastlinedefined).unwrap_or(c_int::MAX);
        ar.short_src.fill(0);
        for (target, &byte) in ar.short_src[..59].iter_mut().zip(info.short_source.iter()) {
            *target = byte as c_char;
        }
    }
    if selectors.line {
        ar.currentline = c_int::try_from(info.currentline).unwrap_or(-1);
    }
    if selectors.upvalues {
        ar.nups = u8::try_from(info.nups).unwrap_or(u8::MAX);
        ar.nparams = u8::try_from(info.nparams).unwrap_or(u8::MAX);
        ar.isvararg = c_char::from(info.isvararg);
    }
    if selectors.tail {
        ar.istailcall = c_char::from(info.istailcall);
        #[cfg(feature = "lua55")]
        {
            ar.extraargs = u8::try_from(info.extraargs).unwrap_or(u8::MAX);
        }
    }
    if selectors.transfer {
        #[cfg(feature = "lua54")]
        {
            ar.ftransfer = u16::try_from(info.ftransfer).unwrap_or(u16::MAX);
            ar.ntransfer = u16::try_from(info.ntransfer).unwrap_or(u16::MAX);
        }
        #[cfg(feature = "lua55")]
        {
            ar.ftransfer = c_int::try_from(info.ftransfer).unwrap_or(c_int::MAX);
            ar.ntransfer = c_int::try_from(info.ntransfer).unwrap_or(c_int::MAX);
        }
    }
}

/// SAFETY：`what` 是有效 NUL 字串、`ar` 是對齊可寫的固定 profile ABI 結構。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_getinfo(
    pointer: *mut lua_State,
    what: *const c_char,
    ar: *mut lua_Debug,
) -> c_int {
    if what.is_null() || ar.is_null() {
        return 0;
    }
    with_debug_state(pointer, 0, |state| {
        // SAFETY：C 呼叫者保證 what 在本次同步呼叫中是有效 NUL 結尾字串。
        let selectors = DebugSelectors::parse(unsafe { CStr::from_ptr(what).to_bytes() })?;
        let key = if selectors.function_only {
            None
        } else {
            // SAFETY：ar 非 null 且符合目前編譯 profile 的完整固定 ABI。
            Some(unsafe { (*ar).i_ci as usize })
        };
        let Some(commit) = state.debug_getinfo(&selectors, key)? else {
            return Ok(0);
        };
        // SAFETY：發布所需的 root/backing/capacity 已備齊；此時只寫指定欄位。
        unsafe { publish_debug_info_b10(ar, &selectors, &commit) };
        Ok(1)
    })
}

/// SAFETY：非 null ar 須為固定 profile ABI 結構；null ar 依官方規格使用 stack top 函式。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_getlocal(
    pointer: *mut lua_State,
    ar: *const lua_Debug,
    index: c_int,
) -> *const c_char {
    with_debug_state(pointer, std::ptr::null(), |state| {
        let token = if ar.is_null() {
            None
        } else {
            // SAFETY：非 null ar 的完整結構由 C 呼叫者在本次呼叫保活。
            Some(unsafe { (*ar).i_ci as usize })
        };
        Ok(state
            .debug_getlocal(token, index)?
            .unwrap_or(std::ptr::null()))
    })
}

/// SAFETY：非 null ar 須為固定 profile ABI 結構；只有完整寫入成功才彈出 stack top。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_setlocal(
    pointer: *mut lua_State,
    ar: *const lua_Debug,
    index: c_int,
) -> *const c_char {
    if ar.is_null() {
        return std::ptr::null();
    }
    with_debug_state(pointer, std::ptr::null(), |state| {
        // SAFETY：非 null ar 的完整結構由 C 呼叫者在本次呼叫保活。
        let key = unsafe { (*ar).i_ci as usize };
        Ok(state
            .debug_setlocal(key, index)?
            .unwrap_or(std::ptr::null()))
    })
}

// SAFETY：公開 lua_settop 由純 C trampoline 定義；呼叫者須保證 state 仍存活。
unsafe extern "C" {
    pub fn lua_settop(pointer: *mut lua_State, index: c_int);
}

/// SAFETY：固定 header 符號名稱唯一；預留失敗回傳 0，無 FFI unwind。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_checkstack(pointer: *mut lua_State, additional: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        state.check_stack(additional)?;
        Ok(1)
    })
}

/// SAFETY：固定 header 符號名稱唯一；msg 保持不讀取，state 由 with_state 驗證。
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_checkstack(
    pointer: *mut lua_State,
    space: c_int,
    msg: *const c_char,
) {
    let _ = msg;
    with_state(pointer, (), |state| {
        state.check_stack(space)?;
        Ok(())
    });
}

// SAFETY：public auxiliary helper 由純 C facade 定義；呼叫者保活 sentinel 結尾陣列。
unsafe extern "C" {
    pub fn luaL_setfuncs(pointer: *mut lua_State, entries: *const luaL_Reg, nup: c_int);
}

// SAFETY：六個公開 auxiliary 入口由 C facade 定義；錯誤跳轉只在 C checkpoint。
unsafe extern "C" {
    pub fn luaL_checknumber(pointer: *mut lua_State, arg: c_int) -> f64;
    pub fn luaL_optnumber(pointer: *mut lua_State, arg: c_int, default: f64) -> f64;
    pub fn luaL_checkinteger(pointer: *mut lua_State, arg: c_int) -> i64;
    pub fn luaL_optinteger(pointer: *mut lua_State, arg: c_int, default: i64) -> i64;
    pub fn luaL_checklstring(pointer: *mut lua_State, arg: c_int, len: *mut usize)
    -> *const c_char;
    pub fn luaL_optlstring(
        pointer: *mut lua_State,
        arg: c_int,
        default: *const c_char,
        len: *mut usize,
    ) -> *const c_char;
}

/// SAFETY：固定 header 符號唯一；只重排 capi-owned slot 與其 root 所有權。
pub unsafe extern "C" fn lua_rotate(pointer: *mut lua_State, index: c_int, count: c_int) {
    with_state(pointer, (), |state| state.rotate(index, count));
}

/// SAFETY：兩指標各須在有效期內；先驗同一 Rc VM，再轉移 slot/root 所有權。
pub unsafe extern "C" fn lua_xmove(from: *mut lua_State, to: *mut lua_State, count: c_int) {
    ffi_boundary((), || {
        // SAFETY：兩個有效 C state 指標是 lua_xmove 的呼叫前置條件。
        unsafe { xmove_inner_a3(from, to, count) }
    });
}

/// # Safety
/// 兩個 state 指標由同步 C caller 保活；只在確認同組 VM 後轉移 slots。
unsafe fn xmove_inner_a3(
    from: *mut lua_State,
    to: *mut lua_State,
    count: c_int,
) -> Result<(), StackError> {
    // SAFETY：兩個有效 C state 指標是 lua_xmove 的呼叫前置條件。
    let from_state = unsafe { checked_state(from)? };
    // SAFETY：同上；相同指標只建立共享參照，資料透過 RefCell 管理。
    let to_state = unsafe { checked_state(to)? };
    let count = usize::try_from(count).map_err(|_| StackError::InvalidIndex)?;
    let from_group = from_state.group.upgrade().ok_or(StackError::InvalidState)?;
    let to_group = to_state.group.upgrade().ok_or(StackError::InvalidState)?;
    if !Rc::ptr_eq(&from_group, &to_group) || from_state.vm_id != to_state.vm_id {
        return Err(StackError::WrongVm);
    }
    if std::ptr::eq(from_state, to_state) {
        return (count <= from_state.top()?)
            .then_some(())
            .ok_or(StackError::InvalidIndex);
    }
    if count == 0 {
        return Ok(());
    }
    let group = from_group.try_borrow().map_err(|_| StackError::Busy)?;
    let mut source = from_state
        .stack
        .try_borrow_mut()
        .map_err(|_| StackError::Busy)?;
    let mut destination = to_state
        .stack
        .try_borrow_mut()
        .map_err(|_| StackError::Busy)?;
    if count > source.slots.len() {
        return Err(StackError::InvalidIndex);
    }
    let target = destination
        .slots
        .len()
        .checked_add(count)
        .ok_or(StackError::StackLimit)?;
    destination.ensure_capacity(&group.vm, target)?;
    let start = source.slots.len() - count;
    if !source.can_remove_from(start) {
        return Err(StackError::InvalidIndex);
    }
    destination.slots.extend(source.slots.drain(start..));
    source.release_empty_capacity();
    Ok(())
}

/// SAFETY：固定 header 符號名稱唯一；新增純 nil slot，不借出 VM heap 指標。
pub unsafe extern "C" fn lua_pushnil(pointer: *mut lua_State) {
    with_state(pointer, (), |state| {
        state.push(StackValue::Core(Value::Nil))
    });
}

/// SAFETY：固定 header 符號名稱唯一；整數 C ABI 為 c_int，非零值映射 true。
pub unsafe extern "C" fn lua_pushboolean(pointer: *mut lua_State, value: c_int) {
    with_state(pointer, (), |state| {
        state.push(StackValue::Core(Value::Boolean(value != 0)))
    });
}

/// SAFETY：固定 header 符號名稱唯一；固定 i64 Lua integer 由值傳入。
pub unsafe extern "C" fn lua_pushinteger(pointer: *mut lua_State, value: i64) {
    with_state(pointer, (), |state| {
        state.push(StackValue::Core(Value::Integer(value)))
    });
}

/// SAFETY：固定 header 符號名稱唯一；固定 f64 Lua number 保留 NaN 與正負零。
pub unsafe extern "C" fn lua_pushnumber(pointer: *mut lua_State, value: f64) {
    with_state(pointer, (), |state| {
        state.push(StackValue::Core(Value::Float(value)))
    });
}

/// SAFETY：固定 header 符號名稱唯一；指標僅作 opaque 值保存，絕不解參照。
pub unsafe extern "C" fn lua_pushlightuserdata(pointer: *mut lua_State, value: *mut c_void) {
    with_state(pointer, (), |state| {
        state.push(StackValue::Core(Value::LightUserdata(
            value.expose_provenance(),
        )))
    });
}

/// SAFETY：有效 state 由 with_state 驗證；無效 index／busy 回 false。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_iscfunction(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(c_int::from(state.c_function(index)?.is_some()))
    })
}

/// SAFETY：僅取回 registry 原先保存的 typed C 函式指標，絕不從整數重建指標。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_tocfunction(
    pointer: *mut lua_State,
    index: c_int,
) -> Option<LuaCFunction> {
    with_state(pointer, None, |state| state.c_function(index))
}

/// SAFETY：固定 header 符號唯一；非空來源須含 `len` 個有效 bytes，先複製後才配置 Lua 物件。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_pushlstring(
    pointer: *mut lua_State,
    source: *const c_char,
    len: usize,
) -> *const c_char {
    with_state(pointer, std::ptr::null(), |state| {
        let bytes = if len == 0 {
            &[][..]
        } else {
            if source.is_null() {
                return Err(StackError::InvalidIndex);
            }
            // SAFETY：C 呼叫者保證非空來源在呼叫期間可讀 len bytes；只在本函式內借用。
            unsafe { std::slice::from_raw_parts(source.cast::<u8>(), len) }
        };
        state.push_string(bytes)
    })
}

/// SAFETY：固定 header 符號唯一；非空來源須為有效 NUL 結尾 C 字串。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_pushstring(
    pointer: *mut lua_State,
    source: *const c_char,
) -> *const c_char {
    with_state(pointer, std::ptr::null(), |state| {
        if source.is_null() {
            state.push(StackValue::Core(Value::Nil))?;
            return Ok(std::ptr::null());
        }
        // SAFETY：C 呼叫者保證 source 指向可讀的 NUL 結尾字串；內部立即複製。
        let bytes = unsafe { CStr::from_ptr(source) }.to_bytes();
        state.push_string(bytes)
    })
}

/// SAFETY：有效 state 先由 with_state 驗證；非空輸入須是呼叫期間有效的 NUL 結尾 C 字串。
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_gsub(
    pointer: *mut lua_State,
    source: *const c_char,
    pattern: *const c_char,
    replacement: *const c_char,
) -> *const c_char {
    with_state(pointer, std::ptr::null(), |state| {
        if source.is_null() || pattern.is_null() || replacement.is_null() {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：呼叫者保證 source 在本次呼叫期間可讀且 NUL 結尾；只借讀首個 NUL 前 bytes。
        let source = unsafe { CStr::from_ptr(source) }.to_bytes();
        // SAFETY：呼叫者保證 pattern 在本次呼叫期間可讀且 NUL 結尾；只借讀首個 NUL 前 bytes。
        let pattern = unsafe { CStr::from_ptr(pattern) }.to_bytes();
        // SAFETY：呼叫者保證 replacement 在本次呼叫期間可讀且 NUL 結尾；只借讀首個 NUL 前 bytes。
        let replacement = unsafe { CStr::from_ptr(replacement) }.to_bytes();
        state.push_gsub(source, pattern, replacement)
    })
}

/// SAFETY：固定 header 符號唯一；兩個 hint 非負，失敗時不發布未根住的 table。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_createtable(pointer: *mut lua_State, array: c_int, hash: c_int) {
    with_state(pointer, (), |state| state.create_table(array, hash));
}

/// SAFETY：固定 ABI 入口；with_state 驗證 state，成功時 stack root 保活
/// 16-byte 對齊的 full userdata bytes。呼叫者只可在物件仍可達時使用回傳位址。
pub unsafe extern "C" fn lua_newuserdatauv(
    pointer: *mut lua_State,
    size: usize,
    nuvalue: c_int,
) -> *mut c_void {
    with_state(pointer, std::ptr::null_mut(), |state| {
        state.new_userdata(size, nuvalue)
    })
}

/// 有效 index 的 coroutine 才映回其穩定位址；borrow 在回傳前結束。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_tothread(pointer: *mut lua_State, index: c_int) -> *mut lua_State {
    with_state(pointer, std::ptr::null_mut(), |state| {
        state.to_thread(index)
    })
}

#[repr(C)]
pub(crate) struct RawNewThreadResult {
    kind: i32,
    value: i32,
    pointer: *mut lua_State,
}

#[repr(C)]
pub(crate) struct RawPushThreadResult {
    kind: i32,
    value: i32,
    answer: c_int,
}

fn thread_allocation_action(pointer: *mut lua_State, generation: u64, token: u64) -> (i32, i32) {
    let checkpoint = Checkpoint {
        state: pointer,
        generation,
        token,
    };
    if let Err(reject) = crate::trampoline::probe(checkpoint) {
        return (codes::ACTION_REJECT, reject as i32);
    }
    let prepared = with_state(pointer, Err(Reject::Stale), |state| {
        Ok(prepare_message_pending(
            state,
            checkpoint,
            MEMORY_ERROR_BYTES,
            ErrorClass::Allocation,
        ))
    });
    match prepared {
        Ok(class) => (codes::ACTION_RAISE, class as i32),
        Err(reject) => (codes::ACTION_REJECT, reject as i32),
    }
}

/// 配置失敗先在 Rust 準備 pending；C facade 收到 POD 後才可 longjmp。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_newthread_dispatch_b3(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
) -> RawNewThreadResult {
    let result = with_state(pointer, Err(StackError::InvalidState), |state| {
        Ok(state.new_thread())
    });
    match result {
        Ok(pointer) => RawNewThreadResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer,
        },
        Err(error) if version_error_allocation_failed(error) => {
            let (kind, value) = thread_allocation_action(pointer, generation, token);
            RawNewThreadResult {
                kind,
                value,
                pointer: std::ptr::null_mut(),
            }
        }
        Err(_) => RawNewThreadResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer: std::ptr::null_mut(),
        },
    }
}

/// 主 thread 成功值為 1，child 成功值為 0；錯誤由 C facade 處理。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_pushthread_dispatch_b3(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
) -> RawPushThreadResult {
    let result = with_state(pointer, Err(StackError::InvalidState), |state| {
        Ok(state.push_thread())
    });
    match result {
        Ok(answer) => RawPushThreadResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            answer,
        },
        Err(error) if version_error_allocation_failed(error) => {
            let (kind, value) = thread_allocation_action(pointer, generation, token);
            RawPushThreadResult {
                kind,
                value,
                answer: 0,
            }
        }
        Err(_) => RawPushThreadResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            answer: 0,
        },
    }
}

#[repr(C)]
pub(crate) struct RawUserdataResult {
    kind: i32,
    value: i32,
    pointer: *mut c_void,
}

#[cfg(feature = "lua55")]
#[repr(C)]
pub(crate) struct RawExternalStringResult {
    kind: i32,
    value: i32,
    pointer: *const c_char,
}

/// external owner 在任何可失敗配置之前接管有效輸入；配置失敗由 C facade 跳轉。
///
/// # Safety
/// 非空 source 必須在 owner 存活期間提供不可變的 len+1 bytes 並以 NUL 結尾；
/// falloc/ud 須遵守 Lua allocator 正常返回契約，C facade 僅在 Rust 返回後 longjmp。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_pushexternalstring_dispatch_b9(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    source: *const c_char,
    len: usize,
    falloc: Option<LuaAlloc>,
    ud: *mut c_void,
) -> RawExternalStringResult {
    if source.is_null() || len > i64::MAX as usize || len.checked_add(1).is_none() {
        return RawExternalStringResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer: std::ptr::null(),
        };
    }
    let result = with_state(pointer, Err(StackError::InvalidState), |state| {
        Ok(state.push_external_string(ExternalStringOwner {
            pointer: source,
            len,
            falloc,
            ud,
            _charge: None,
        }))
    });
    match result {
        Ok(pointer) => RawExternalStringResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer,
        },
        Err(error) if version_error_allocation_failed(error) => {
            let (kind, value) = thread_allocation_action(pointer, generation, token);
            RawExternalStringResult {
                kind,
                value,
                pointer: std::ptr::null(),
            }
        }
        Err(_) => RawExternalStringResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer: std::ptr::null(),
        },
    }
}

/// C facade 取得純 POD 結果；配置錯誤的 pending slot 在任何 C 跳轉前建立。
///
/// # Safety
/// 非空 state 必須在同步呼叫期間有效；C facade 僅在本函式返回後跳轉。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_newuserdata_dispatch_a50(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    size: usize,
    nuvalue: c_int,
) -> RawUserdataResult {
    let result = with_state(pointer, Err(StackError::InvalidState), |state| {
        Ok(state.new_userdata(size, nuvalue))
    });
    match result {
        Ok(value) => RawUserdataResult {
            kind: codes::ACTION_RETURN,
            value: 0,
            pointer: value,
        },
        Err(error) => {
            let outcome = generic_error_a3(pointer, generation, token, 0, std::ptr::null(), error);
            RawUserdataResult {
                kind: outcome.kind,
                value: outcome.value,
                pointer: std::ptr::null_mut(),
            }
        }
    }
}

enum StrictActualName {
    Static(&'static [u8]),
    Named(Rc<StringView>),
}

impl StrictActualName {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Static(bytes) => bytes,
            Self::Named(view) => {
                let bytes = view.as_bytes();
                &bytes[..bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len())]
            }
        }
    }
}

impl StateControl {
    fn strict_actual_name(&self, index: c_int) -> Result<StrictActualName, StackError> {
        let tag = self.value_type(index)?;
        if matches!(tag, LUA_TTABLE | LUA_TUSERDATA) {
            let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
            let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
            let stack = self.stack.try_borrow().map_err(|_| StackError::Busy)?;
            if let Ok(position) = resolve_stack_index(index, stack.slots.len()) {
                if let StackValue::Core(Value::Object(object)) =
                    stack.slots[position].checked_value(&group.vm)?
                {
                    if let Some(metatable) = group.vm.get_metatable(object)? {
                        let name = group.vm.with_temporary_byte_string(b"__name", |vm, key| {
                            vm.raw_get(metatable, Value::Object(key))
                        })?;
                        if let Value::Object(name) = name {
                            if group.vm.object_kind(name)? == ObjectKind::ByteString {
                                let len = group
                                    .vm
                                    .with_byte_string(name, |string| string.as_bytes().len())?;
                                let view = StringView::new_filled(&group.vm, len, |bytes, _| {
                                    group.vm.with_byte_string(name, |string| {
                                        bytes.extend_from_slice(string.as_bytes());
                                    })?;
                                    Ok(())
                                })?;
                                return Ok(StrictActualName::Named(view));
                            }
                        }
                    }
                }
            }
        }
        let name: &'static [u8] = match tag {
            LUA_TNONE => b"no value",
            LUA_TNIL => b"nil",
            LUA_TBOOLEAN => b"boolean",
            LUA_TLIGHTUSERDATA => b"light userdata",
            LUA_TNUMBER => b"number",
            LUA_TSTRING => b"string",
            LUA_TTABLE => b"table",
            LUA_TFUNCTION => b"function",
            LUA_TUSERDATA => b"userdata",
            LUA_TTHREAD => b"thread",
            _ => b"no value",
        };
        Ok(StrictActualName::Static(name))
    }
}

#[repr(C)]
pub(crate) struct RawStrictResult {
    kind: i32,
    value: i32,
    pointer: *mut c_void,
}

impl RawStrictResult {
    fn returned(value: i32, pointer: *mut c_void) -> Self {
        Self {
            kind: codes::ACTION_RETURN,
            value,
            pointer,
        }
    }

    fn raised(class: ErrorClass) -> Self {
        Self {
            kind: codes::ACTION_RAISE,
            value: class as i32,
            pointer: std::ptr::null_mut(),
        }
    }

    fn rejected(reject: Reject) -> Self {
        Self {
            kind: codes::ACTION_REJECT,
            value: reject as i32,
            pointer: std::ptr::null_mut(),
        }
    }
}

// A3b POD opcode 只涵蓋已盤點、不依賴 A4 target/upvalue/metamethod 的公開入口。
const A3_CHECKSTACK: c_int = 1;
const A3_ROTATE: c_int = 2;
const A3_XMOVE: c_int = 3;
const A3_PUSHNIL: c_int = 4;
const A3_PUSHBOOLEAN: c_int = 5;
const A3_PUSHINTEGER: c_int = 6;
const A3_PUSHNUMBER: c_int = 7;
const A3_PUSHLIGHTUSERDATA: c_int = 8;
const A3_GSUB: c_int = 9;
const A3_NEWMETATABLE: c_int = 10;
const A3_SETMETATABLE: c_int = 11;
const A3_NEXT: c_int = 12;
const A4B_PUSHVALUE: c_int = 13;
const A4B_COPY: c_int = 14;
const A4B_REF: c_int = 15;
const A4B_UNREF: c_int = 16;
const A4B_GETMETATABLE: c_int = 17;
const A4B_SETMETATABLE: c_int = 18;
const A4B_GETUSERVALUE: c_int = 19;
const A4B_SETUSERVALUE: c_int = 20;
const A4B_GETMETAFIELD: c_int = 21;
const A4B_TESTUDATA: c_int = 22;

fn generic_error_a3(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: c_int,
    message: *const c_char,
    error: StackError,
) -> RawStrictResult {
    if matches!(
        error,
        StackError::Busy | StackError::InvalidState | StackError::WrongVm
    ) {
        return RawStrictResult::rejected(Reject::InvalidAction);
    }
    let checkpoint = Checkpoint {
        state: pointer,
        generation,
        token,
    };
    let prepared = (|| -> Result<ErrorClass, Reject> {
        // SAFETY：C facade 保活 state；產品操作已返回，這裡沒有存活的 VM 借用。
        let state = unsafe { private_state(pointer)? };
        if matches!(error, StackError::Number(_)) || version_error_allocation_failed(error) {
            let step = state
                .callback_error_step_a2(error)
                .map_err(|_| Reject::InvalidAction)?;
            return ErrorClass::from_code(step.value).ok_or(Reject::InvalidAction);
        }
        let class = ErrorClass::Lua;
        let default = if operation == A3_NEXT {
            b"invalid key to 'next'".as_slice()
        } else {
            b"value operation failed".as_slice()
        };
        let prepared = if operation == A3_CHECKSTACK {
            if message.is_null() {
                prepare_message_pending(state, checkpoint, b"stack overflow", class)
            } else {
                // SAFETY：msg 是同步 C caller 保活的 NUL 結尾字串；只讀到 pending 建立完畢。
                let msg = unsafe { CStr::from_ptr(message) }.to_bytes();
                prepare_parts_pending(state, checkpoint, &[b"stack overflow (", msg, b")"], class)
            }
        } else {
            prepare_message_pending(state, checkpoint, default, class)
        };
        if matches!(prepared, Err(Reject::StackChanged)) {
            let step = state
                .callback_error_step_a2(error)
                .map_err(|_| Reject::InvalidAction)?;
            ErrorClass::from_code(step.value).ok_or(Reject::InvalidAction)
        } else {
            prepared
        }
    })();
    match prepared {
        Ok(class) => RawStrictResult::raised(class),
        Err(reject) => RawStrictResult::rejected(reject),
    }
}

#[repr(C)]
pub(crate) struct RawAuxValueA4b {
    kind: i32,
    value: i32,
    number: f64,
    integer: i64,
    pointer: *const c_char,
    length: usize,
}

/// 六個 auxiliary 值轉換共用 POD，借用與字串配置在返回 C 前結束。
///
/// # Safety
/// pointer 必須為同步有效的 state；非空 default 是同步有效的 NUL 結尾字串。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_aux_value_dispatch_a4b(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: c_int,
    arg: c_int,
    default_number: f64,
    default_integer: i64,
    default_string: *const c_char,
) -> RawAuxValueA4b {
    let empty = |result: RawStrictResult| RawAuxValueA4b {
        kind: result.kind,
        value: result.value,
        number: 0.0,
        integer: 0,
        pointer: std::ptr::null(),
        length: 0,
    };
    let outcome = catch_unwind(AssertUnwindSafe(
        || -> Result<RawAuxValueA4b, StackError> {
            // SAFETY：C facade 保活 state；checked_state 核對身分與執行緒。
            let state = unsafe { checked_state(pointer)? };
            let mut result = empty(RawStrictResult::returned(0, std::ptr::null_mut()));
            match operation {
                1 => result.number = state.checked_number(arg)?,
                2 => result.number = state.opt_number(arg, default_number)?,
                3 => result.integer = state.checked_integer(arg)?,
                4 => result.integer = state.opt_integer(arg, default_integer)?,
                5 => (result.pointer, result.length) = state.checked_lstring(arg)?,
                6 => {
                    state.ensure_available()?;
                    if state.is_none_or_nil(arg)? {
                        result.pointer = default_string;
                        if !default_string.is_null() {
                            // SAFETY：非空 default 的 NUL 結尾及同步存活是公開 C API 前置條件。
                            result.length =
                                unsafe { CStr::from_ptr(default_string) }.to_bytes().len();
                        }
                    } else {
                        (result.pointer, result.length) = state.checked_lstring(arg)?;
                    }
                }
                _ => return Err(StackError::Layout),
            }
            Ok(result)
        },
    ));
    match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(StackError::InvalidIndex)) => {
            // 官方 interror：數值可轉 number、卻無整數表示時用專屬 argerror。
            let integer_representation = if matches!(operation, 3 | 4) {
                // SAFETY：前次借用已釋放；同一同步 C 呼叫保活 state。
                unsafe { checked_state(pointer) }
                    .ok()
                    .and_then(|state| state.coerce_number(arg).ok().flatten())
                    .is_some()
            } else {
                false
            };
            let mut result = empty(RawStrictResult::returned(0, std::ptr::null_mut()));
            result.kind = AUX_SEMANTIC_ERROR_A3;
            result.value = i32::from(integer_representation);
            result
        }
        Ok(Err(error)) => empty(generic_error_a3(
            pointer,
            generation,
            token,
            0,
            std::ptr::null(),
            error,
        )),
        Err(_) => empty(generic_error_a3(
            pointer,
            generation,
            token,
            0,
            std::ptr::null(),
            StackError::Layout,
        )),
    }
}

/// Upvalue API 將名稱／identity 轉成 POD；錯誤 pending 完成後才由 C checkpoint 跳轉。
///
/// # Safety
/// pointer 須在同步呼叫期間有效；回傳的名稱由 state 的 publication 保活，identity 不可解參。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_upvalue_dispatch_a4b(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: c_int,
    first: c_int,
    first_n: c_int,
    second: c_int,
    second_n: c_int,
) -> RawStrictResult {
    let outcome = catch_unwind(AssertUnwindSafe(
        || -> Result<RawStrictResult, StackError> {
            // SAFETY：C facade 持有有效 state；借用與所有可失敗操作在回傳 POD 前結束。
            let state = unsafe { checked_state(pointer)? };
            let value = match operation {
                1 => state.get_c_upvalue(first, first_n)?.cast_mut().cast(),
                2 => state.set_c_upvalue(first, first_n)?.cast_mut().cast(),
                3 => state.upvalue_id(first, first_n)?,
                4 => {
                    state.join_lua_upvalues(first, first_n, second, second_n)?;
                    std::ptr::null_mut()
                }
                _ => return Err(StackError::InvalidIndex),
            };
            Ok(RawStrictResult::returned(0, value))
        },
    ));
    match outcome {
        Ok(Ok(value)) => value,
        Ok(Err(StackError::InvalidIndex)) if (1..=3).contains(&operation) => {
            RawStrictResult::returned(0, std::ptr::null_mut())
        }
        Ok(Err(error)) => generic_error_a3(pointer, generation, token, 0, std::ptr::null(), error),
        Err(_) => generic_error_a3(
            pointer,
            generation,
            token,
            0,
            std::ptr::null(),
            StackError::Layout,
        ),
    }
}

/// C closure 捕獲與函式 registry 預備全在 Rust 完成；失敗由 C facade 於返回後跳轉。
///
/// # Safety
/// pointer 須為同步存活的 state；function 只保存原 typed 函式指標，不在此處執行。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_pushcclosure_dispatch_a4b(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    function: Option<LuaCFunction>,
    n: c_int,
) -> RawStrictResult {
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：C facade 保活 state；checked_state 核對身分及執行緒。
        let state = unsafe { checked_state(pointer)? };
        state.push_c_closure(function.ok_or(StackError::InvalidIndex)?, n)
    }));
    match outcome {
        Ok(Ok(())) => RawStrictResult::returned(0, std::ptr::null_mut()),
        Ok(Err(error)) => generic_error_a3(pointer, generation, token, 0, std::ptr::null(), error),
        Err(_) => generic_error_a3(
            pointer,
            generation,
            token,
            0,
            std::ptr::null(),
            StackError::Layout,
        ),
    }
}

/// 共用 A3b 私有 dispatch；所有 VM 借用、暫存 root 與 unwind 都在返回 POD 前結束。
///
/// # Safety
/// pointer/other 須為同步呼叫期間仍存活的 state；非空文字指標由 C caller 保證
/// NUL 結尾且保活至本函式返回，opaque 僅作不解參照的 lightuserdata 值。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_generic_dispatch_a3(
    pointer: *mut lua_State,
    other: *mut lua_State,
    generation: u64,
    token: u64,
    operation: c_int,
    first: c_int,
    second: c_int,
    integer: i64,
    number: f64,
    opaque: *mut c_void,
    text1: *const c_char,
    text2: *const c_char,
    text3: *const c_char,
) -> RawStrictResult {
    let outcome = catch_unwind(AssertUnwindSafe(
        || -> Result<RawStrictResult, StackError> {
            // SAFETY：同步 C facade 保活有效 state；checked_state 驗執行緒與世代。
            let state = unsafe { checked_state(pointer)? };
            let returned = |value, pointer| Ok(RawStrictResult::returned(value, pointer));
            match operation {
                A3_CHECKSTACK => {
                    state.check_stack(first)?;
                    returned(0, std::ptr::null_mut())
                }
                A3_ROTATE => {
                    state.rotate(first, second)?;
                    returned(0, std::ptr::null_mut())
                }
                A3_XMOVE => {
                    // SAFETY：兩個 state 由 C caller 保活；helper 驗證相同 VM group。
                    unsafe { xmove_inner_a3(pointer, other, first)? };
                    returned(0, std::ptr::null_mut())
                }
                A3_PUSHNIL => {
                    state.push(StackValue::Core(Value::Nil))?;
                    returned(0, std::ptr::null_mut())
                }
                A3_PUSHBOOLEAN => {
                    state.push(StackValue::Core(Value::Boolean(first != 0)))?;
                    returned(0, std::ptr::null_mut())
                }
                A3_PUSHINTEGER => {
                    state.push(StackValue::Core(Value::Integer(integer)))?;
                    returned(0, std::ptr::null_mut())
                }
                A3_PUSHNUMBER => {
                    state.push(StackValue::Core(Value::Float(number)))?;
                    returned(0, std::ptr::null_mut())
                }
                A3_PUSHLIGHTUSERDATA => {
                    state.push(StackValue::Core(Value::LightUserdata(
                        opaque.expose_provenance(),
                    )))?;
                    returned(0, std::ptr::null_mut())
                }
                A3_GSUB => {
                    if text1.is_null() || text2.is_null() || text3.is_null() {
                        return Err(StackError::InvalidIndex);
                    }
                    // SAFETY：三個 C 字串由 caller 在同步呼叫期間保活；不逸出 dispatch。
                    let source = unsafe { CStr::from_ptr(text1) }.to_bytes();
                    let pattern = unsafe { CStr::from_ptr(text2) }.to_bytes();
                    let replacement = unsafe { CStr::from_ptr(text3) }.to_bytes();
                    let result = state.push_gsub(source, pattern, replacement)?;
                    returned(0, result.cast_mut().cast())
                }
                A3_NEWMETATABLE | A3_SETMETATABLE => {
                    if text1.is_null() {
                        return Err(StackError::InvalidIndex);
                    }
                    // SAFETY：名稱由 caller 保活；StateControl 在任何 GC 前複製 bytes。
                    let name = unsafe { CStr::from_ptr(text1) }.to_bytes();
                    if operation == A3_NEWMETATABLE {
                        returned(state.new_metatable(name)?, std::ptr::null_mut())
                    } else {
                        state.set_named_metatable(name)?;
                        returned(0, std::ptr::null_mut())
                    }
                }
                A3_NEXT => returned(state.raw_next(first)?, std::ptr::null_mut()),
                A4B_PUSHVALUE => {
                    state.push_index(first)?;
                    returned(0, std::ptr::null_mut())
                }
                A4B_COPY => {
                    state.copy(first, second)?;
                    returned(0, std::ptr::null_mut())
                }
                A4B_REF => returned(state.reference(first)?, std::ptr::null_mut()),
                A4B_UNREF => {
                    state.unreference(first, second)?;
                    returned(0, std::ptr::null_mut())
                }
                A4B_GETMETATABLE => returned(state.get_metatable(first)?, std::ptr::null_mut()),
                A4B_SETMETATABLE => returned(state.set_metatable(first)?, std::ptr::null_mut()),
                A4B_GETUSERVALUE => {
                    returned(state.get_uservalue(first, second)?, std::ptr::null_mut())
                }
                A4B_SETUSERVALUE => {
                    returned(state.set_uservalue(first, second)?, std::ptr::null_mut())
                }
                A4B_GETMETAFIELD | A4B_TESTUDATA => {
                    if text1.is_null() {
                        return Err(StackError::InvalidIndex);
                    }
                    // SAFETY：C facade 保活 NUL 結尾名稱；helper 在同步呼叫中複製。
                    let name = unsafe { CStr::from_ptr(text1) }.to_bytes();
                    if operation == A4B_GETMETAFIELD {
                        returned(state.get_metafield(first, name)?, std::ptr::null_mut())
                    } else {
                        returned(0, state.test_userdata(first, name)?)
                    }
                }
                _ => Err(StackError::InvalidIndex),
            }
        },
    ));
    match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => generic_error_a3(pointer, generation, token, operation, text1, error),
        Err(_) => generic_error_a3(
            pointer,
            generation,
            token,
            operation,
            text1,
            StackError::InvalidState,
        ),
    }
}

/// A4a auxiliary 組合內的 checked push；只供 C facade 在公開 API 呼叫之間使用。
///
/// # Safety
/// pointer 須由同步 C caller 保活；function 只存入當前 VM registry，不在此呼叫。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_aux_push_a4a(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: c_int,
    index: c_int,
    function: Option<LuaCFunction>,
    nup: c_int,
) -> RawStrictResult {
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<(), StackError> {
        // SAFETY：C facade 在本次同步呼叫保活 state；checked_state 驗身分與執行緒。
        let state = unsafe { checked_state(pointer)? };
        match operation {
            1 => state.push_index(index),
            2 => state.push_c_closure(function.ok_or(StackError::InvalidIndex)?, nup),
            3 => state.create_table(0, 0),
            _ => Err(StackError::InvalidIndex),
        }
    }));
    match outcome {
        Ok(Ok(())) => RawStrictResult::returned(0, std::ptr::null_mut()),
        Ok(Err(error)) => generic_error_a3(
            pointer,
            generation,
            token,
            operation,
            std::ptr::null(),
            error,
        ),
        Err(_) => generic_error_a3(
            pointer,
            generation,
            token,
            operation,
            std::ptr::null(),
            StackError::InvalidState,
        ),
    }
}

/// 無 checkpoint 的公開錯誤在 C panic callback 前發布永久保根錯誤字串。
///
/// # Safety
/// pointer 必須是 live state；C caller 只在此函式返回後執行 panic callback 與 abort。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_generic_panic_error_a3(
    pointer: *mut lua_State,
) -> c_int {
    with_state(pointer, 0, |state| {
        let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
        let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
        let mut stack = state.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let error = StackSlot::permanent_rooted(
            &group.vm,
            group.emergency_error,
            Rc::clone(&group.emergency_view),
        )?;
        let required = stack
            .slots
            .len()
            .checked_add(1)
            .ok_or(StackError::StackLimit)?;
        if stack.ensure_capacity(&group.vm, required).is_err() {
            let top = stack
                .slots
                .len()
                .checked_sub(1)
                .ok_or(StackError::StackLimit)?;
            if !stack.can_remove_from(top) {
                return Err(StackError::InvalidIndex);
            }
            stack.slots.pop();
        }
        stack.slots.push(error);
        Ok(1)
    })
}

fn strict_arg_digits(arg: c_int) -> ([u8; 12], usize) {
    let mut bytes = [0_u8; 12];
    let negative = arg < 0;
    let mut number = i64::from(arg).unsigned_abs();
    let mut at = bytes.len();
    loop {
        at -= 1;
        bytes[at] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    if negative {
        at -= 1;
        bytes[at] = b'-';
    }
    let len = bytes.len() - at;
    bytes.copy_within(at.., 0);
    (bytes, len)
}

fn strict_prepare_parts(
    state: &StateControl,
    checkpoint: Checkpoint,
    parts: &[&[u8]],
    class: ErrorClass,
) -> RawStrictResult {
    if let Err(reject) = crate::trampoline::probe(checkpoint) {
        return RawStrictResult::rejected(reject);
    }
    match prepare_parts_pending(state, checkpoint, parts, class) {
        Ok(class) => RawStrictResult::raised(class),
        Err(reject) => RawStrictResult::rejected(reject),
    }
}

fn strict_arg_error(
    state: &StateControl,
    checkpoint: Checkpoint,
    arg: c_int,
    message: &[&[u8]],
) -> RawStrictResult {
    let (digits, len) = strict_arg_digits(arg);
    let mut parts: [&[u8]; 8] = [&[]; 8];
    parts[0] = b"bad argument #";
    parts[1] = &digits[..len];
    parts[2] = b" (";
    let mut count = 3;
    for part in message {
        parts[count] = part;
        count += 1;
    }
    parts[count] = b")";
    strict_prepare_parts(state, checkpoint, &parts[..=count], ErrorClass::Lua)
}

fn strict_type_error(
    state: &StateControl,
    checkpoint: Checkpoint,
    arg: c_int,
    expected: &[u8],
) -> RawStrictResult {
    let actual = match state.strict_actual_name(arg) {
        Ok(name) => name,
        Err(error) => return strict_stack_error(state, checkpoint, error),
    };
    strict_arg_error(
        state,
        checkpoint,
        arg,
        &[expected, b" expected, got ", actual.as_bytes()],
    )
}

// Rust 辨識後交回 C facade 呼叫官方 argerror/typeerror；不得跨 Rust FFI longjmp。
const AUX_SEMANTIC_ERROR_A3: i32 = 40;
const AUX_OPTION_TYPE_A3: i32 = 1;
const AUX_OPTION_INVALID_A3: i32 = 2;

fn strict_semantic_a3(value: i32) -> RawStrictResult {
    RawStrictResult {
        kind: AUX_SEMANTIC_ERROR_A3,
        value,
        pointer: std::ptr::null_mut(),
    }
}

fn strict_stack_error(
    state: &StateControl,
    checkpoint: Checkpoint,
    error: StackError,
) -> RawStrictResult {
    if version_error_allocation_failed(error) {
        strict_prepare_parts(
            state,
            checkpoint,
            &[MEMORY_ERROR_BYTES],
            ErrorClass::Allocation,
        )
    } else {
        RawStrictResult::rejected(match error {
            StackError::Busy => Reject::Busy,
            _ => Reject::InvalidAction,
        })
    }
}

fn strict_aux_inner(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: i32,
    arg: c_int,
    tag: c_int,
    name: *const c_char,
    choices: *const *const c_char,
    public: bool,
) -> RawStrictResult {
    // SAFETY：公開 C facade 的有效 state 在同步呼叫期間存活；private_state 再驗執行緒與世代。
    let state = match unsafe { private_state(pointer) } {
        Ok(state) => state,
        Err(reject) => return RawStrictResult::rejected(reject),
    };
    let checkpoint = Checkpoint {
        state: pointer,
        generation,
        token,
    };
    match operation {
        codes::AUX_CHECKTYPE => match state.value_type(arg) {
            Ok(actual) if actual == tag => RawStrictResult::returned(0, std::ptr::null_mut()),
            Ok(_) => {
                if public {
                    strict_semantic_a3(0)
                } else {
                    strict_type_error(state, checkpoint, arg, lua_type_name_bytes(tag))
                }
            }
            Err(error) => strict_stack_error(state, checkpoint, error),
        },
        codes::AUX_CHECKANY => match state.value_type(arg) {
            Ok(LUA_TNONE) => {
                if public {
                    strict_semantic_a3(0)
                } else {
                    strict_arg_error(state, checkpoint, arg, &[b"value expected"])
                }
            }
            Ok(_) => RawStrictResult::returned(0, std::ptr::null_mut()),
            Err(error) => strict_stack_error(state, checkpoint, error),
        },
        codes::AUX_CHECKUDATA => {
            if name.is_null() {
                return RawStrictResult::rejected(Reject::InvalidAction);
            }
            // SAFETY：有效 tname 是 C 呼叫者前置條件，借用只活於同步呼叫。
            let expected = unsafe { CStr::from_ptr(name) }.to_bytes();
            match state.test_userdata(arg, expected) {
                Ok(found) if !found.is_null() => RawStrictResult::returned(0, found),
                Ok(_) | Err(StackError::InvalidIndex) => {
                    if public {
                        strict_semantic_a3(0)
                    } else {
                        strict_type_error(state, checkpoint, arg, expected)
                    }
                }
                Err(error) => strict_stack_error(state, checkpoint, error),
            }
        }
        codes::AUX_CHECKOPTION => {
            if choices.is_null() {
                return RawStrictResult::rejected(Reject::InvalidAction);
            }
            let use_default = match state.is_none_or_nil(arg) {
                Ok(value) => value && !name.is_null(),
                Err(error) => return strict_stack_error(state, checkpoint, error),
            };
            let selected = if use_default {
                name
            } else {
                match state.checked_lstring(arg) {
                    Ok((value, _)) => value,
                    Err(StackError::InvalidIndex) => {
                        return if public {
                            strict_semantic_a3(AUX_OPTION_TYPE_A3)
                        } else {
                            strict_type_error(state, checkpoint, arg, b"string")
                        };
                    }
                    Err(error) => return strict_stack_error(state, checkpoint, error),
                }
            };
            // SAFETY：有效 default、字串 slot 及 NULL sentinel list 為 C API 呼叫者前置條件。
            let selected = unsafe { CStr::from_ptr(selected) }.to_bytes();
            let mut at = 0usize;
            loop {
                // SAFETY：呼叫者保證 list 以 NULL 結尾且每項為有效 NUL 結尾字串。
                let candidate = unsafe { *choices.add(at) };
                if candidate.is_null() {
                    break;
                }
                // SAFETY：上方 list 前置條件保證此字串有效。
                if unsafe { CStr::from_ptr(candidate) }.to_bytes() == selected {
                    return match i32::try_from(at) {
                        Ok(index) => RawStrictResult::returned(index, std::ptr::null_mut()),
                        Err(_) => RawStrictResult::rejected(Reject::InvalidAction),
                    };
                }
                at += 1;
            }
            if public {
                strict_semantic_a3(AUX_OPTION_INVALID_A3)
            } else {
                strict_arg_error(
                    state,
                    checkpoint,
                    arg,
                    &[b"invalid option '", selected, b"'"],
                )
            }
        }
        _ => RawStrictResult::rejected(Reject::InvalidAction),
    }
}

fn lua_type_name_bytes(tag: c_int) -> &'static [u8] {
    match tag {
        LUA_TNONE => b"no value",
        LUA_TNIL => b"nil",
        LUA_TBOOLEAN => b"boolean",
        LUA_TLIGHTUSERDATA => b"userdata",
        LUA_TNUMBER => b"number",
        LUA_TSTRING => b"string",
        LUA_TTABLE => b"table",
        LUA_TFUNCTION => b"function",
        LUA_TUSERDATA => b"userdata",
        LUA_TTHREAD => b"thread",
        _ => b"no value",
    }
}

/// # Safety
/// state、tname、default 與 sentinel list 必須符合固定 C API 生命週期；所有 raw 借用
/// 只活於同步呼叫，panic 不跨 ABI，錯誤只準備 pending 而不從 Rust 跳轉。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_aux_dispatch_b2(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: i32,
    arg: c_int,
    tag: c_int,
    name: *const c_char,
    choices: *const *const c_char,
) -> RawStrictResult {
    catch_unwind(AssertUnwindSafe(|| {
        strict_aux_inner(
            pointer, generation, token, operation, arg, tag, name, choices, false,
        )
    }))
    .unwrap_or(RawStrictResult::rejected(Reject::Panic))
}

/// 公開 strict facade 的語意錯誤交由 C 呼叫官方 auxiliary error 鏈。
///
/// # Safety
/// pointer 與 C 字串／選項在同步呼叫期間有效；本函式只回傳 POD，不跨 ABI 跳轉。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_aux_dispatch_public_a3(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    operation: i32,
    arg: c_int,
    tag: c_int,
    name: *const c_char,
    choices: *const *const c_char,
) -> RawStrictResult {
    catch_unwind(AssertUnwindSafe(|| {
        strict_aux_inner(
            pointer, generation, token, operation, arg, tag, name, choices, true,
        )
    }))
    .unwrap_or(RawStrictResult::rejected(Reject::Panic))
}

/// # Safety
/// C facade 保證 buffer 已初始化並位於此 state 頂端；message 借用同步有效。
/// 僅在完成 buffer cleanup 後準備 pending，C 於本函式返回後跳轉。
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rivetlua_capi_format_error_b2(
    pointer: *mut lua_State,
    generation: u64,
    token: u64,
    buffer: *mut luaL_Buffer,
    message: *const c_char,
    len: usize,
) -> RawStrictResult {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY：C facade 保有有效 state、buffer 與 message，Rust 同步複製 message。
        let state = match unsafe { private_state(pointer) } {
            Ok(state) => state,
            Err(reject) => return RawStrictResult::rejected(reject),
        };
        let checkpoint = Checkpoint {
            state: pointer,
            generation,
            token,
        };
        if let Err(reject) = crate::trampoline::probe(checkpoint) {
            return RawStrictResult::rejected(reject);
        }
        if let Err(reject) = state.buffer_cleanup(pointer, buffer) {
            return RawStrictResult::rejected(reject);
        }
        // SAFETY：message 的 len bytes 由 C 呼叫者保證可讀，本次呼叫內完成複製。
        let bytes = unsafe { std::slice::from_raw_parts(message.cast::<u8>(), len) };
        match prepare_message_pending(state, checkpoint, bytes, ErrorClass::Lua) {
            Ok(class) => RawStrictResult::raised(class),
            Err(reject) => RawStrictResult::rejected(reject),
        }
    }))
    .unwrap_or(RawStrictResult::rejected(Reject::Panic))
}

/// SAFETY：固定 header 符號唯一；table index 在 push 前解析，失敗不改 stack。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawgeti(pointer: *mut lua_State, index: c_int, key: i64) -> c_int {
    with_state(pointer, LUA_TNONE, |state| {
        state.raw_get_integer(index, key)
    })
}

/// SAFETY：固定 header 符號唯一；先依呼叫前 top 解析 table，再以查值取代 key slot。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawget(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, LUA_TNONE, |state| state.raw_get_stack_key(index))
}

// SAFETY：public 同步表 API 由純 C facade 定義；其 Rust step 返回 POD 後才執行 callback。
unsafe extern "C" {
    pub fn lua_pushcclosure(pointer: *mut lua_State, function: Option<LuaCFunction>, n: c_int);
    pub fn lua_pushvalue(pointer: *mut lua_State, index: c_int);
    pub fn lua_copy(pointer: *mut lua_State, source: c_int, destination: c_int);
    pub fn luaL_ref(pointer: *mut lua_State, index: c_int) -> c_int;
    pub fn luaL_unref(pointer: *mut lua_State, index: c_int, reference: c_int);
    pub fn lua_getmetatable(pointer: *mut lua_State, index: c_int) -> c_int;
    pub fn lua_setmetatable(pointer: *mut lua_State, index: c_int) -> c_int;
    pub fn lua_getiuservalue(pointer: *mut lua_State, index: c_int, n: c_int) -> c_int;
    pub fn lua_setiuservalue(pointer: *mut lua_State, index: c_int, n: c_int) -> c_int;
    pub fn luaL_getmetafield(pointer: *mut lua_State, index: c_int, event: *const c_char) -> c_int;
    pub fn luaL_testudata(
        pointer: *mut lua_State,
        index: c_int,
        tname: *const c_char,
    ) -> *mut c_void;
    pub fn lua_getupvalue(pointer: *mut lua_State, index: c_int, n: c_int) -> *const c_char;
    pub fn lua_setupvalue(pointer: *mut lua_State, index: c_int, n: c_int) -> *const c_char;
    pub fn lua_upvalueid(pointer: *mut lua_State, index: c_int, n: c_int) -> *mut c_void;
    pub fn lua_upvaluejoin(
        pointer: *mut lua_State,
        first_index: c_int,
        first_n: c_int,
        second_index: c_int,
        second_n: c_int,
    );
    pub fn lua_getglobal(pointer: *mut lua_State, name: *const c_char) -> c_int;
    pub fn lua_gettable(pointer: *mut lua_State, index: c_int) -> c_int;
    pub fn lua_getfield(pointer: *mut lua_State, index: c_int, name: *const c_char) -> c_int;
    pub fn lua_geti(pointer: *mut lua_State, index: c_int, key: i64) -> c_int;
    pub fn lua_settable(pointer: *mut lua_State, index: c_int);
    pub fn lua_seti(pointer: *mut lua_State, index: c_int, key: i64);
    pub fn lua_setglobal(pointer: *mut lua_State, name: *const c_char);
    pub fn lua_setfield(pointer: *mut lua_State, index: c_int, name: *const c_char);
}

/// SAFETY：固定 header 符號唯一；成功前先驗 table/key 並備妥 roots 與 stack 容量。
pub unsafe extern "C" fn lua_next(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| state.raw_next(index))
}

/// SAFETY：固定 header 符號唯一；指標只作地址鍵，絕不解參照。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawgetp(
    pointer: *mut lua_State,
    index: c_int,
    key: *const c_void,
) -> c_int {
    with_state(pointer, LUA_TNONE, |state| {
        state.raw_get_explicit_key(index, Value::LightUserdata(key.expose_provenance()))
    })
}

/// SAFETY：固定 header 符號唯一；先解析 table index，runtime mutation 成功後才移除 value slot。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawseti(pointer: *mut lua_State, index: c_int, key: i64) {
    with_state(pointer, (), |state| state.raw_set_integer(index, key));
}

/// SAFETY：固定 header 符號唯一；table mutation 成功後才 pop 兩個 slot。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawset(pointer: *mut lua_State, index: c_int) {
    with_state(pointer, (), |state| state.raw_set_stack_key(index));
}

/// SAFETY：固定 header 符號唯一；指標只作地址鍵，mutation 成功後才 pop value。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawsetp(pointer: *mut lua_State, index: c_int, key: *const c_void) {
    with_state(pointer, (), |state| {
        state.raw_set_explicit_key(index, Value::LightUserdata(key.expose_provenance()))
    });
}

/// SAFETY：固定 header 符號唯一；只借用 stack 與 VM 身分，不配置或執行 metamethod。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawequal(pointer: *mut lua_State, left: c_int, right: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(c_int::from(state.raw_equal(left, right)?))
    })
}

/// B5 C facade 在純 C checkpoint 內執行比較及 metamethod。
///
/// # Safety
/// pointer 須為同步存活的 lua_State。
pub unsafe extern "C" fn lua_compare(
    pointer: *mut lua_State,
    left: c_int,
    right: c_int,
    operation: c_int,
) -> c_int {
    // SAFETY：C facade 驗證 index，所有 Rust step 返回後才可能呼叫 C metamethod。
    unsafe { c_lua_compare(pointer, left, right, operation) }
}

// SAFETY：public auxiliary helper 由純 C facade 組合一般 get/set；呼叫者保活名稱。
unsafe extern "C" {
    pub fn luaL_getsubtable(pointer: *mut lua_State, index: c_int, fname: *const c_char) -> c_int;
}

/// SAFETY：有效 state 指標由 with_state 驗身分／世代／執行緒；非空 tname 須由
/// 同程序呼叫者提供本次呼叫可讀且 NUL 結尾的 C 字串，不跨程序傳遞 pointer。
/// 只借用至 new_metatable 立即複製，不跨 callback／GC 保留借用、不解參其他原始指標；
/// with_state 驗執行緒並擋住 panic/unwind 跨 ABI。
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_newmetatable(pointer: *mut lua_State, tname: *const c_char) -> c_int {
    with_state(pointer, -1, |state| {
        if tname.is_null() {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：非空 tname 的可讀 NUL 結尾儲存由 C 呼叫者保證；此 borrow
        // 在 StateControl 複製 bytes 後立即結束，無 callback／GC、別名寫入或跨執行緒逸出。
        let bytes = unsafe { CStr::from_ptr(tname) }.to_bytes();
        state.new_metatable(bytes)
    })
}

/// SAFETY：有效 state 由 with_state 驗世代與執行緒；非空 tname 須為同程序呼叫者
/// 在本次呼叫提供的可讀 NUL 結尾字串。名稱立即複製；借用不跨 callback、GC、
/// 別名寫入或執行緒，with_state 防止 panic/unwind 逸出 C ABI。
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_setmetatable(pointer: *mut lua_State, tname: *const c_char) {
    with_state(pointer, (), |state| {
        if tname.is_null() {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：非空 tname 的可讀 NUL 結尾儲存由 C 呼叫者保證；
        // StateControl 立即複製，借用不跨 callback／GC／別名寫入或執行緒。
        let bytes = unsafe { CStr::from_ptr(tname) }.to_bytes();
        state.set_named_metatable(bytes)
    })
}

/// SAFETY：固定 header 符號唯一；只讀取有效 stack／registry index，錯誤回零。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_rawlen(pointer: *mut lua_State, index: c_int) -> u64 {
    with_state(pointer, 0, |state| state.raw_len(index))
}

/// SAFETY：固定 header 符號名稱唯一；registry pseudo-index 可讀，upvalue／callback pseudo-index 仍 fail-closed。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_type(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, LUA_TNONE, |state| state.value_type(index))
}

/// SAFETY：有效 state 由 with_state 驗證；opaque token 僅是不可解參照的資訊指標。
/// Full userdata 回傳由 stack root 保活的 user-memory block，lightuserdata 保留原指標。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_topointer(pointer: *mut lua_State, index: c_int) -> *const c_void {
    with_state(pointer, std::ptr::null(), |state| {
        state.object_pointer(index)
    })
}

/// SAFETY：固定 header 符號唯一；數值字串沿用 runtime `tonumber` 解析。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_isnumber(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(c_int::from(state.coerce_number(index)?.is_some()))
    })
}

/// SAFETY：固定 header 符號唯一；number 與 string 類型均可作字串。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_isstring(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(c_int::from(matches!(
            state.value_type(index)?,
            LUA_TNUMBER | LUA_TSTRING
        )))
    })
}

/// SAFETY：固定 header 符號名稱唯一；回傳靜態 NUL 結尾位元組，無 heap borrow。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_typename(pointer: *mut lua_State, ty: c_int) -> *const c_char {
    with_state(pointer, std::ptr::null(), |state| {
        state.validate()?;
        let name: &'static [u8] = match ty {
            LUA_TNIL => b"nil\0",
            LUA_TBOOLEAN => b"boolean\0",
            LUA_TLIGHTUSERDATA => b"userdata\0",
            LUA_TNUMBER => b"number\0",
            LUA_TSTRING => b"string\0",
            LUA_TTABLE => b"table\0",
            LUA_TFUNCTION => b"function\0",
            LUA_TUSERDATA => b"userdata\0",
            LUA_TTHREAD => b"thread\0",
            LUA_TNONE => b"no value\0",
            _ => return Err(StackError::InvalidIndex),
        };
        Ok(name.as_ptr().cast::<c_char>())
    })
}

/// SAFETY：固定 header 符號名稱唯一；官方契約忽略 `L`，不讀取或解參照 state pointer。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_version(_pointer: *mut lua_State) -> f64 {
    #[cfg(feature = "lua55")]
    {
        505.0
    }
    #[cfg(feature = "lua54")]
    {
        504.0
    }
}

/// SAFETY：固定 header 符號名稱唯一；state 與 index 均經 with_state／value_type 驗證，不解參照 C 指標。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_isuserdata(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        let tag = state.value_type(index)?;
        Ok(c_int::from(matches!(
            tag,
            LUA_TLIGHTUSERDATA | LUA_TUSERDATA
        )))
    })
}

/// SAFETY：固定 header 符號名稱唯一；僅真正 Integer tag 回傳 1。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_isinteger(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(i32::from(matches!(
            state.read(index),
            Ok(StackValue::Core(Value::Integer(_)))
        )))
    })
}

/// SAFETY：固定 header 符號名稱唯一；boolean 判斷不解參照 C 指標。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_toboolean(pointer: *mut lua_State, index: c_int) -> c_int {
    with_state(pointer, 0, |state| {
        Ok(i32::from(match state.read(index) {
            Ok(StackValue::Core(value)) => value.is_truthy(),
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => false,
            Err(error) => return Err(error),
        }))
    })
}

/// SAFETY：固定 header 符號名稱唯一；只回傳 lightuserdata 原位址或由 stack
/// root 保活的 full userdata bytes 位址，不解參照 C 指標。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_touserdata(pointer: *mut lua_State, index: c_int) -> *mut c_void {
    with_state(pointer, std::ptr::null_mut(), |state| {
        match state.userdata_pointer(index) {
            Ok(pointer) => Ok(pointer),
            Err(StackError::InvalidIndex | StackError::PseudoIndexUnavailable) => {
                Ok(std::ptr::null_mut())
            }
            Err(error) => Err(error),
        }
    })
}

/// SAFETY：固定 header 符號名稱唯一；數值字串沿用 runtime 解析，isnum 指標由 C 呼叫者保證可寫。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_tonumberx(
    pointer: *mut lua_State,
    index: c_int,
    isnum: *mut c_int,
) -> f64 {
    let result = with_state(pointer, None, |state| {
        Ok(match state.coerce_number(index)? {
            Some(Value::Integer(value)) => Some(value as f64),
            Some(Value::Float(value)) => Some(value),
            _ => None,
        })
    });
    if !isnum.is_null() {
        // SAFETY：C 呼叫者提供可寫且對齊的 int 指標；僅在函式內寫入一個值。
        unsafe { *isnum = i32::from(result.is_some()) };
    }
    result.unwrap_or(0.0)
}

/// SAFETY：固定 header 符號名稱唯一；數值字串沿用 runtime 解析，isnum 指標由 C 呼叫者保證可寫。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_tointegerx(
    pointer: *mut lua_State,
    index: c_int,
    isnum: *mut c_int,
) -> i64 {
    let result = with_state(pointer, None, |state| state.coerce_integer(index));
    if !isnum.is_null() {
        // SAFETY：C 呼叫者提供可寫且對齊的 int 指標；僅在函式內寫入一個值。
        unsafe { *isnum = i32::from(result.is_some()) };
    }
    result.unwrap_or(0)
}

/// SAFETY：固定 header 符號唯一；len 非空時由 C 呼叫者保證可寫一個 size_t。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_tolstring(
    pointer: *mut lua_State,
    index: c_int,
    len: *mut usize,
) -> *const c_char {
    let result = with_state(pointer, None, |state| state.to_string(index));
    if !len.is_null() {
        // SAFETY：C 呼叫者提供對齊且可寫的 size_t 指標；僅寫入一次。
        unsafe { *len = result.map_or(0, |(_, size)| size) };
    }
    result.map_or(std::ptr::null(), |(string, _)| string)
}

/// SAFETY：固定 header 符號唯一；非空來源須為有效 NUL 結尾 C 字串。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_stringtonumber(
    pointer: *mut lua_State,
    source: *const c_char,
) -> usize {
    with_state(pointer, 0, |state| {
        if source.is_null() {
            return Err(StackError::InvalidIndex);
        }
        // SAFETY：C 呼叫者保證 source 指向可讀的 NUL 結尾字串；解析只借用 bytes。
        let bytes = unsafe { CStr::from_ptr(source) }.to_bytes();
        let number = {
            state.validate()?;
            let group_owner = state.group.upgrade().ok_or(StackError::InvalidState)?;
            let group = group_owner.try_borrow().map_err(|_| StackError::Busy)?;
            group.vm.parse_lua_number_bytes(bytes)
        };
        let Some(number) = number else {
            return Ok(0);
        };
        let consumed = bytes.len().checked_add(1).ok_or(StackError::StackLimit)?;
        state.push(StackValue::Core(number))?;
        Ok(consumed)
    })
}

/// SAFETY：Lua 5.5 固定 header 的 buff 須對齊、可寫且至少 64 bytes。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lua_numbertocstring(
    pointer: *mut lua_State,
    index: c_int,
    buff: *mut c_char,
) -> c_uint {
    if buff.is_null() {
        return 0;
    }
    let result = with_state(pointer, None, |state| state.number_bytes(index));
    let Some((bytes, len)) = result else {
        return 0;
    };
    let Some(total) = len.checked_add(1).filter(|total| *total <= NUMBER_BUFFER) else {
        return 0;
    };
    let Ok(total_uint) = c_uint::try_from(total) else {
        return 0;
    };
    // SAFETY：C 呼叫者提供至少 LUA_N2SBUFFSZ bytes；total 已檢查不超過 64。
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buff.cast::<u8>(), len);
        *buff.add(len) = 0;
    }
    total_uint
}

fn decode_posix_wait_status(stat: c_int) -> (bool, &'static [u8], c_int) {
    let termination = stat & 0x7f;
    if termination == 0 {
        let code = (stat & 0xff00) >> 8;
        (code == 0, b"exit", code)
    } else if termination != 0x7f {
        (false, b"signal", termination)
    } else {
        // stopped 等未解碼狀態沿官方 fallback 保留原始 stat。
        (false, b"exit", stat)
    }
}

impl StateControl {
    fn push_exec_result(&self, stat: c_int) -> Result<(), StackError> {
        self.validate()?;
        let group_owner = self.group.upgrade().ok_or(StackError::InvalidState)?;
        let mut group = group_owner.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let mut stack = self.stack.try_borrow_mut().map_err(|_| StackError::Busy)?;
        let required = stack
            .slots
            .len()
            .checked_add(3)
            .ok_or(StackError::StackLimit)?;
        let prepared = stack.prepare_capacity(&group.vm, required)?;
        let (success, what, code) = decode_posix_wait_status(stat);
        let view = StringView::new(&group.vm, what)?;
        let string_slot =
            group
                .vm
                .with_unpublished_byte_string(view.as_bytes(), |vm, object| {
                    let mut slot = StackSlot::new(vm, StackValue::Core(Value::Object(object)))?;
                    slot.string_view = Some(SlotStringView::Owned(Rc::clone(&view)));
                    Ok::<StackSlot, StackError>(slot)
                })?;
        let result_slot = StackSlot {
            value: StackValue::Core(if success {
                Value::Boolean(true)
            } else {
                Value::Nil
            }),
            root: None,
            string_view: None,
        };
        let code_slot = StackSlot {
            value: StackValue::Core(Value::Integer(i64::from(code))),
            root: None,
            string_view: None,
        };
        // 容量、字串與 root 均已備妥；commit 後只搬移既有 slot，不再有可失敗操作。
        stack.commit_capacity(prepared);
        stack.slots.push(result_slot);
        stack.slots.push(string_slot);
        stack.slots.push(code_slot);
        Ok(())
    }
}

/// 依固定 Lua 輔助 API 將 POSIX wait status 推為 result、原因與 code 三槽。
///
/// # Safety
/// 非空 state 必須在呼叫期間有效；有效入口由 with_state 驗證世代、執行緒與 VM。
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn luaL_execresult(pointer: *mut lua_State, stat: c_int) -> c_int {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    with_state(pointer, 0, |state| {
        if stat != 0 && errno != 0 {
            state.push_file_result_failure(errno, std::ptr::null())?;
        } else {
            state.push_exec_result(stat)?;
        }
        Ok(3)
    })
}

/// B5 C facade 先走 lua_len，再依 lua_tointegerx 精確檢查並移除暫存值。
///
/// # Safety
/// 非空 pointer 必須在呼叫期間指向有效 state；共用入口會驗證其身分、世代、執行緒與 VM 借用狀態。
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_len(pointer: *mut lua_State, index: c_int) -> i64 {
    // SAFETY：C facade 在純 C checkpoint 中同步執行，pointer 由呼叫者保活。
    unsafe { c_lual_len(pointer, index) }
}

#[cfg(test)]
mod checkpoint_atomicity_tests {
    use super::{Reject, StateOwner};

    #[test]
    fn checkpoint_exit_busy_keeps_token_and_capacity_until_retry() {
        let owner = StateOwner::new().unwrap();
        let state = &owner.allocation.as_ref().unwrap().control;
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        let (generation, token, previous) = state.enter_checkpoint().unwrap();
        let reserved = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        assert!(reserved.committed > before.committed);
        {
            let _pending_borrow = state.pending_error.borrow_mut();
            assert_eq!(
                state.exit_checkpoint(generation, token, previous),
                Err(Reject::Busy)
            );
            assert_eq!(state.checkpoint_depth.get(), 1);
            assert_eq!(state.checkpoint_token.get(), token);
        }
        {
            let _stack_borrow = state.stack.borrow_mut();
            assert_eq!(
                state.exit_checkpoint(generation, token, previous),
                Err(Reject::Busy)
            );
            assert_eq!(state.checkpoint_depth.get(), 1);
            assert_eq!(state.checkpoint_token.get(), token);
        }
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), reserved);
        assert_eq!(state.exit_checkpoint(generation, token, previous), Ok(()));
        assert_eq!(state.checkpoint_depth.get(), 0);
        assert_eq!(state.checkpoint_token.get(), previous);
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);
    }
}

#[cfg(test)]
mod c_owned_state_tests {
    use super::{StateOwner, lua_close, lua_createtable, lua_gettop};

    #[test]
    fn c_owned_close_busy_retry_drops_group_and_refunds_ledger() {
        let owner = StateOwner::new().unwrap();
        let group = owner.allocation.as_ref().unwrap().control.group.clone();
        let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        let state = owner.into_c_ptr();
        // SAFETY：state 由本測試移交 C 持有，busy 呼叫後仍有效。
        unsafe { lua_createtable(state, 0, 0) };
        {
            let active = group.upgrade().unwrap();
            let _borrow = active.borrow_mut();
            // SAFETY：state 存活；busy VM 借用須令 close 保持原狀。
            unsafe { lua_close(state) };
            assert!(group.upgrade().is_some());
        }
        // SAFETY：busy close 未釋放 state；重試後不得再用該 pointer。
        unsafe {
            assert_eq!(lua_gettop(state), 1);
            lua_close(state);
        }
        assert!(group.upgrade().is_none());
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}

#[cfg(test)]
mod lightuserdata_tests {
    use super::{
        StateOwner, lua_gettop, lua_pushlightuserdata, lua_settop, lua_touserdata, lua_type,
    };

    #[test]
    fn pointer_scalar_roundtrips_without_lua_heap_or_root_charge() {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let mut token = 1_u8;
        let pointer = (&mut token as *mut u8).cast();
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
        // SAFETY：state 與 token 在所有呼叫期間有效；API 不解參照 lightuserdata。
        unsafe {
            lua_pushlightuserdata(state, std::ptr::null_mut());
            lua_pushlightuserdata(state, pointer);
            assert_eq!(lua_gettop(state), 2);
            assert_eq!(lua_type(state, -2), 2);
            assert_eq!(lua_type(state, -1), 2);
            assert_eq!(lua_touserdata(state, -2), std::ptr::null_mut());
            assert_eq!(lua_touserdata(state, -1), pointer);
        }
        assert_eq!(
            owner
                .with_vm(|vm| vm.ledger_snapshot().lua_heap_bytes)
                .unwrap(),
            before.lua_heap_bytes
        );
        assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
        // SAFETY：兩個 stack slot 都在有效 state 內。
        unsafe { lua_settop(state, 0) };
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);
    }
}
