//! C state 的目前 lua_Alloc 綁定與 runtime admission 橋接。

use std::ffi::c_void;
use std::rc::Rc;

use rivetlua_alloc::{AdmissionToken, LuaBinding, LuaBindingRef, StateAllocator, UninitBlock};
use rivetlua_runtime::AllocationAdmission;

pub use rivetlua_alloc::LuaAlloc;

#[derive(Clone)]
pub struct CAllocatorState {
    binding: LuaBindingRef,
}

impl CAllocatorState {
    /// # Safety
    /// `function`/`user_data` 須符合 `LuaBinding::new` 的 callback 與生命週期契約。
    pub unsafe fn new(function: LuaAlloc, user_data: *mut c_void) -> Self {
        Self {
            // SAFETY：由本函式的呼叫者保證 callback 與 user_data 契約。
            binding: LuaBindingRef::from(Rc::new(unsafe { LuaBinding::new(function, user_data) })),
        }
    }

    /// # Safety
    /// callback 與 ud 須符合 LuaBindingRef::bootstrap 契約；失敗時兩塊皆不發布。
    pub unsafe fn bootstrap<T>(function: LuaAlloc, user_data: *mut c_void)
        -> Option<(Self, UninitBlock<T>)>
    {
        // SAFETY：由此函式的 C 呼叫者保證 callback/ud 契約。
        let (binding, main) = unsafe { LuaBindingRef::bootstrap::<T>(function, user_data) }?;
        Some((Self { binding }, main))
    }

    pub fn current(&self) -> (Option<LuaAlloc>, *mut c_void) {
        self.binding.current()
    }

    /// # Safety
    /// 新 binding 須符合 `LuaBinding::set_current` 的既有 block 與生命週期契約。
    pub unsafe fn set_current(&self, function: LuaAlloc, user_data: *mut c_void) -> bool {
        // SAFETY：由本函式的呼叫者保證新 callback 能處理既有 block。
        unsafe { self.binding.set_current(function, user_data) }
    }

    pub fn callback_active(&self) -> bool {
        self.binding.callback_active()
    }

    pub fn backing_allocator(&self) -> StateAllocator {
        StateAllocator::Lua(self.binding.clone())
    }

    pub fn binding(&self) -> &LuaBindingRef {
        &self.binding
    }
}

impl AllocationAdmission for CAllocatorState {
    fn admit(&self, bytes: usize) -> Option<AdmissionToken> {
        self.binding.admit(bytes)
    }

    fn release(&self, token: AdmissionToken, _bytes: usize) {
        drop(token)
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
        // SAFETY：ptr 為同一 C allocator 先前取得的 block，或 NULL。
        unsafe { free(ptr) };
        core::ptr::null_mut()
    } else {
        // SAFETY：ptr 為同一 C allocator 先前取得的 block，或 NULL。
        unsafe { realloc(ptr, nsize) }
    }
}

#[cfg(feature = "lua55")]
use crate::luaL_alloc as default_allocator;

pub fn default_state() -> CAllocatorState {
    // SAFETY：專案內建 callback 不讀取 ud，並能處理此 state 的所有既有 block。
    unsafe { CAllocatorState::new(default_allocator, core::ptr::null_mut()) }
}

pub fn bootstrap_default_state<T>() -> Option<(CAllocatorState, UninitBlock<T>)> {
    // SAFETY：內建 callback 不解參照 ud，且處理自己建立的所有 block。
    unsafe { CAllocatorState::bootstrap(default_allocator, core::ptr::null_mut()) }
}
