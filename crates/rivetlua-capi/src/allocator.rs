//! C state 的目前 lua_Alloc 綁定；runtime 僅持有安全的 admission 介面。

use core::cell::Cell;
use core::num::NonZeroUsize;
use std::ffi::c_void;

use rivetlua_runtime::AllocationAdmission;

pub type LuaAlloc = unsafe extern "C" fn(
    ud: *mut c_void,
    ptr: *mut c_void,
    osize: usize,
    nsize: usize,
) -> *mut c_void;

/// 所有已提交 token 只記錄大小；釋放時重新讀取目前 f/ud。
pub struct CAllocatorState {
    function: Cell<Option<LuaAlloc>>,
    user_data: Cell<*mut c_void>,
    callback_active: Cell<bool>,
}

struct CallbackGuard<'a>(&'a Cell<bool>);

impl Drop for CallbackGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl CAllocatorState {
    pub fn new(function: LuaAlloc, user_data: *mut c_void) -> Self {
        Self {
            function: Cell::new(Some(function)),
            user_data: Cell::new(user_data),
            callback_active: Cell::new(false),
        }
    }

    pub fn current(&self) -> (Option<LuaAlloc>, *mut c_void) {
        (self.function.get(), self.user_data.get())
    }

    pub fn set_current(&self, function: LuaAlloc, user_data: *mut c_void) -> bool {
        if self.callback_active.get() {
            return false;
        }
        self.function.set(Some(function));
        self.user_data.set(user_data);
        true
    }

    pub fn callback_active(&self) -> bool {
        self.callback_active.get()
    }
}

impl AllocationAdmission for CAllocatorState {
    fn admit(&self, bytes: usize) -> Option<NonZeroUsize> {
        if bytes == 0 || self.callback_active.replace(true) {
            return None;
        }
        let _guard = CallbackGuard(&self.callback_active);
        let function = self.function.get()?;
        // SAFETY：Lua host 提供的 callback 在 state 存活期間有效；新 token 傳 NULL/0，
        // callback_active 令所有同 state C API 重入在借用 VM 之前 fail-closed。
        let token = unsafe { function(self.user_data.get(), core::ptr::null_mut(), 0, bytes) };
        NonZeroUsize::new(token.expose_provenance())
    }

    fn release(&self, token: NonZeroUsize, bytes: usize) {
        // 只有被禁止的 callback 重入才可能於 active 期間釋放 token；有效路徑
        // 均在同一執行緒、上一個 callback 返回後進入此處。
        if self.callback_active.replace(true) {
            std::process::abort();
        }
        let _guard = CallbackGuard(&self.callback_active);
        let Some(function) = self.function.get() else {
            std::process::abort();
        };
        let pointer = core::ptr::with_exposed_provenance_mut::<c_void>(token.get());
        // SAFETY：pointer 為該 state 前次成功 admission 的尚未釋放 token；
        // osize 是原 admission 大小，nsize=0 依 Lua allocator ABI 釋放。
        unsafe {
            function(self.user_data.get(), pointer, bytes, 0);
        }
    }
}

#[cfg(feature = "lua54")]
unsafe extern "C" {
    fn free(ptr: *mut c_void);
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
}

#[cfg(feature = "lua54")]
unsafe extern "C" fn default_allocator(
    _ud: *mut c_void,
    ptr: *mut c_void,
    _osize: usize,
    nsize: usize,
) -> *mut c_void {
    if nsize == 0 {
        // SAFETY：ptr 為同一 C allocator 先前取得的 token，或 NULL。
        unsafe { free(ptr) };
        core::ptr::null_mut()
    } else {
        // SAFETY：ptr 為同一 C allocator 先前取得的 token，或 NULL。
        unsafe { realloc(ptr, nsize) }
    }
}

#[cfg(feature = "lua55")]
use crate::luaL_alloc as default_allocator;

pub fn default_state() -> CAllocatorState {
    CAllocatorState::new(default_allocator, core::ptr::null_mut())
}
