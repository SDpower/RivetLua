//! P16-3A1 私有錯誤狀態；公開 Lua error API 留待 A2。

use std::ffi::{c_char, c_int, c_void};
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::stack::{self, lua_State};
use crate::trampoline::{self, Action, Checkpoint};

unsafe extern "C" {
    fn snprintf(target: *mut c_char, capacity: usize, format: *const c_char, ...) -> c_int;
    fn strtod(source: *const c_char, end: *mut *mut c_char) -> f64;
}

const LUAL_NUMSIZES: usize = size_of::<i64>() * 16 + size_of::<f64>();
const INCOMPATIBLE_NUMBERS: &[u8] = b"core and library have incompatible numeric types";
const VERSION_PREFIX: &[u8] = b"version mismatch: app. needs ";
const VERSION_MIDDLE: &[u8] = b", Lua core provides ";

fn append_fixed(target: &mut [u8], at: usize, bytes: &[u8]) -> Result<usize, Reject> {
    let end = at.checked_add(bytes.len()).ok_or(Reject::InvalidAction)?;
    target
        .get_mut(at..end)
        .ok_or(Reject::InvalidAction)?
        .copy_from_slice(bytes);
    Ok(end)
}

fn lua_decimal_point() -> Result<u8, Reject> {
    let mut decimal = [0_i8; 8];
    // SAFETY：固定格式與有效 stack buffer；snprintf 最多寫入 8 bytes。
    let len = unsafe {
        snprintf(
            decimal.as_mut_ptr(),
            decimal.len(),
            c"%.1f".as_ptr(),
            0.0_f64,
        )
    };
    if len < 3 {
        return Err(Reject::InvalidAction);
    }
    Ok(decimal[1] as u8)
}

fn lua_number_bytes(number: f64, target: &mut [u8]) -> Result<usize, Reject> {
    let mut number_bytes = [0_i8; 64];
    let format = if cfg!(feature = "lua55") {
        c"%.15g"
    } else {
        c"%.14g"
    };
    // SAFETY：固定格式與有效 stack buffer；C 只寫入指定容量。
    let mut len = unsafe {
        snprintf(
            number_bytes.as_mut_ptr(),
            number_bytes.len(),
            format.as_ptr(),
            number,
        )
    };
    if len < 0
        || usize::try_from(len)
            .ok()
            .is_none_or(|len| len >= number_bytes.len())
    {
        return Err(Reject::InvalidAction);
    }
    if cfg!(feature = "lua55") {
        // Lua 5.5 先用 15 位有效數字；無法 round-trip 才改用 17 位。
        // SAFETY：snprintf 已寫入 NUL；strtod 只借讀此 stack buffer。
        let parsed = unsafe { strtod(number_bytes.as_ptr(), std::ptr::null_mut()) };
        if parsed != number {
            // SAFETY：同上；17 位格式仍在固定 stack buffer 內。
            len = unsafe {
                snprintf(
                    number_bytes.as_mut_ptr(),
                    number_bytes.len(),
                    c"%.17g".as_ptr(),
                    number,
                )
            };
            if len < 0
                || usize::try_from(len)
                    .ok()
                    .is_none_or(|len| len >= number_bytes.len())
            {
                return Err(Reject::InvalidAction);
            }
        }
    }
    let len = usize::try_from(len).map_err(|_| Reject::InvalidAction)?;
    if len > target.len() {
        return Err(Reject::InvalidAction);
    }
    for (dest, source) in target.iter_mut().zip(number_bytes.iter()).take(len) {
        *dest = *source as u8;
    }
    let integer_looking = len > 0
        && target[..len]
            .iter()
            .all(|byte| *byte == b'-' || byte.is_ascii_digit());
    if integer_looking {
        let extra = target.get_mut(len..len + 2).ok_or(Reject::InvalidAction)?;
        extra.copy_from_slice(&[lua_decimal_point()?, b'0']);
        Ok(len + 2)
    } else {
        Ok(len)
    }
}

fn version_message(version: f64, core: f64) -> Result<([u8; 128], usize), Reject> {
    let mut bytes = [0_u8; 128];
    let mut len = append_fixed(&mut bytes, 0, VERSION_PREFIX)?;
    len += lua_number_bytes(version, &mut bytes[len..])?;
    len = append_fixed(&mut bytes, len, VERSION_MIDDLE)?;
    len += lua_number_bytes(core, &mut bytes[len..])?;
    Ok((bytes, len))
}

pub(crate) mod codes {
    include!(concat!(env!("OUT_DIR"), "/trampoline_codes.rs"));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ErrorClass {
    Lua = codes::ERROR_LUA,
    Host = codes::ERROR_HOST,
    Policy = codes::ERROR_POLICY,
    Allocation = codes::ERROR_ALLOCATION,
    Aborted = codes::ERROR_ABORTED,
}

impl ErrorClass {
    pub(crate) fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            codes::ERROR_LUA => Self::Lua,
            codes::ERROR_HOST => Self::Host,
            codes::ERROR_POLICY => Self::Policy,
            codes::ERROR_ALLOCATION => Self::Allocation,
            codes::ERROR_ABORTED => Self::Aborted,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Reject {
    Null = codes::REJECT_NULL,
    WrongThread = codes::REJECT_WRONG_THREAD,
    Busy = codes::REJECT_BUSY,
    WrongState = codes::REJECT_WRONG_STATE,
    WrongGeneration = codes::REJECT_WRONG_GENERATION,
    Stale = codes::REJECT_STALE,
    NoCheckpoint = codes::REJECT_NO_CHECKPOINT,
    Pending = codes::REJECT_PENDING,
    InvalidAction = codes::REJECT_INVALID_ACTION,
    Panic = codes::REJECT_PANIC,
    NoPending = codes::REJECT_NO_PENDING,
    StackChanged = codes::REJECT_STACK_CHANGED,
    CheckpointAllocation = codes::REJECT_CHECKPOINT_ALLOCATION,
}

impl Reject {
    pub(crate) fn from_code(code: i32) -> Self {
        match code {
            codes::REJECT_NULL => Self::Null,
            codes::REJECT_WRONG_THREAD => Self::WrongThread,
            codes::REJECT_BUSY => Self::Busy,
            codes::REJECT_WRONG_STATE => Self::WrongState,
            codes::REJECT_WRONG_GENERATION => Self::WrongGeneration,
            codes::REJECT_STALE => Self::Stale,
            codes::REJECT_NO_CHECKPOINT => Self::NoCheckpoint,
            codes::REJECT_PENDING => Self::Pending,
            codes::REJECT_PANIC => Self::Panic,
            codes::REJECT_NO_PENDING => Self::NoPending,
            codes::REJECT_STACK_CHANGED => Self::StackChanged,
            codes::REJECT_CHECKPOINT_ALLOCATION => Self::CheckpointAllocation,
            _ => Self::InvalidAction,
        }
    }
}

const _: () = {
    assert!(ErrorClass::Lua as i32 == codes::ERROR_LUA);
    assert!(ErrorClass::Aborted as i32 == codes::ERROR_ABORTED);
    assert!(Reject::Null as i32 == codes::REJECT_NULL);
    assert!(Reject::StackChanged as i32 == codes::REJECT_STACK_CHANGED);
};

/// 將頂端 slot 移到同 state 的 pending；成功時 C action 返回後才執行跳轉。
///
/// # Safety
/// checkpoint.state 必須是仍存活的 C state；不能在其關閉後使用。其餘身分、執行緒、
/// token 與頂端 checkpoint 由私有入口重驗。
pub unsafe fn prepare(checkpoint: Checkpoint, class: ErrorClass) -> Action {
    if let Err(reject) = trampoline::probe(checkpoint) {
        return Action::Reject(reject);
    }
    // SAFETY：呼叫者保證 state 存活；stack helper 再核對 pointer、世代、token 及借用。
    match unsafe { stack::prepare_pending(checkpoint, class) } {
        Ok(()) => Action::Raise(class),
        Err(reject) => Action::Reject(reject),
    }
}

/// P16-2A48 的固定版本檢查；成功不碰 state，失敗將完整 error slot 原子交給 checkpoint。
///
/// # Safety
/// mismatch 時 checkpoint.state 必須是仍存活的 state；C top、thread、generation 與 token
/// 均由 probe 和 stack helper 重驗。相容成功路徑依官方 lua_version 契約忽略 state pointer。
pub unsafe fn prepare_checkversion(checkpoint: Checkpoint, version: f64, sizes: usize) -> Action {
    let core = if cfg!(feature = "lua55") {
        505.0
    } else {
        504.0
    };
    if sizes == LUAL_NUMSIZES && version == core {
        return Action::Return(0);
    }
    if let Err(reject) = trampoline::probe(checkpoint) {
        return Action::Reject(reject);
    }
    let mut formatted = [0_u8; 128];
    let message = if sizes != LUAL_NUMSIZES {
        INCOMPATIBLE_NUMBERS
    } else {
        let (bytes, len) = match version_message(version, core) {
            Ok(result) => result,
            Err(reject) => return Action::Reject(reject),
        };
        formatted[..len].copy_from_slice(&bytes[..len]);
        &formatted[..len]
    };
    // SAFETY：checkpoint 在 probe 後仍屬同一同步 C action，helper 再驗 Rust state 身分。
    match unsafe { stack::prepare_version_pending(checkpoint, message) } {
        Ok(class) => Action::Raise(class),
        Err(reject) => Action::Reject(reject),
    }
}

/// 將同一 slot、HostHandle 與 root 無配置地搬回原 stack 頂端。
///
/// # Safety
/// state 必須為尚未關閉的有效 state；錯誤、thread 與 borrow 由 helper 檢查。
pub unsafe fn consume(state: *mut lua_State) -> Result<ErrorClass, Reject> {
    // SAFETY：有效 pointer 是呼叫者前置條件；helper 驗證存活與執行緒。
    unsafe { stack::consume_pending(state) }
}

/// C fixture 的私有 prepare 入口；只回狀態碼，絕不從 Rust 執行跳轉。
///
/// # Safety
/// 非空 state 必須在呼叫期間有效；C 呼叫者不能在關閉後再使用。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_error_prepare_a1(
    state: *mut c_void,
    generation: u64,
    token: u64,
    class: i32,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        let Some(class) = ErrorClass::from_code(class) else {
            return Reject::InvalidAction as i32;
        };
        // SAFETY：C fixture 有效 state 為前置條件；prepare 驗證 checkpoint 身分。
        match unsafe {
            prepare(
                Checkpoint {
                    state: state.cast(),
                    generation,
                    token,
                },
                class,
            )
        } {
            Action::Raise(_) => codes::OK,
            Action::Reject(reject) => reject as i32,
            Action::Return(_) => Reject::InvalidAction as i32,
        }
    })) {
        Ok(code) => code,
        Err(_) => Reject::Panic as i32,
    }
}

/// C fixture 的私有 consume 入口；只在成功後寫入 status。
///
/// # Safety
/// state 必須存活；非空 out_class 必須可寫且對齊 i32。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rivetlua_capi_error_consume_a1(
    state: *mut c_void,
    out_class: *mut i32,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        if out_class.is_null() {
            return Reject::Null as i32;
        }
        // SAFETY：呼叫者保證有效 state；consume 驗證 thread、slot 與原 top。
        let result = unsafe { consume(state.cast()) };
        match result {
            Ok(class) => {
                // SAFETY：非空 out_class 由 C 呼叫者保證對齊可寫，且只寫入一次。
                unsafe { out_class.write(class as i32) };
                codes::OK
            }
            Err(reject) => reject as i32,
        }
    })) {
        Ok(code) => code,
        Err(_) => Reject::Panic as i32,
    }
}
