//! Lua callback 配置的實體 backing；不向 VM 或編譯器擴散原始指標操作。

#![no_std]

extern crate alloc;

#[cfg(all(not(feature = "std"), panic = "unwind"))]
compile_error!("rivetlua-alloc 的 no_std 組態需要 panic=abort");

pub mod c_ctype;
#[cfg(feature = "test-support")]
pub mod test_support;

use alloc::rc::Rc;
use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};
use allocator_api2::vec::Vec as AllocVec;
use core::any::{Any, TypeId};
use core::cell::Cell;
use core::borrow::Borrow;
use core::ffi::c_void;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};

#[cfg(feature = "std")]
unsafe extern "C" {
    safe fn abort() -> !;
}

#[cfg(not(feature = "std"))]
#[cold]
#[inline(never)]
fn abort() -> ! {
    panic!("配置器內部不變條件遭破壞");
}

pub type LuaAlloc = unsafe extern "C" fn(
    ud: *mut c_void,
    ptr: *mut c_void,
    osize: usize,
    nsize: usize,
) -> *mut c_void;

/// 同步借用的穩定 user-memory backing；只攜帶位址與長度，不取得所有權。
#[derive(Clone, Copy)]
pub struct BorrowedBytes<'a> {
    pointer: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'a Cell<[u8; 16]>>,
}

impl<'a> BorrowedBytes<'a> {
    /// # Safety
    /// `pointer` 須非空，`len` 個 byte 在整個 `'a` 期間不搬移、由真實 owner 保活。
    /// buffer 必須具備宿主宣告的 native userdata 格式；其中 handle 與 close callback
    /// 在開啟狀態有效；關閉狀態 callback 為空，未完成 opener 的前綴可為空 handle。
    /// 呼叫者須排除同時釋放及
    /// 未經同步的修改。此型別不驗證格式，也不取得 handle 所有權。
    pub unsafe fn from_raw_parts(pointer: *mut u8, len: usize) -> Self {
        Self {
            // SAFETY：上述契約保證非空。
            pointer: unsafe { NonNull::new_unchecked(pointer) },
            len,
            _borrow: PhantomData,
        }
    }

    pub fn as_mut_ptr(self) -> *mut u8 { self.pointer.as_ptr() }
    pub fn len(self) -> usize { self.len }
}

/// Lua 5.5 external string 的原始 buffer 所有權；不配置或複製 buffer。
/// 此值須移入最後一個引用才會釋放的 owner block。
pub struct CExternalBytesOwner {
    pointer: NonNull<u8>,
    len: usize,
    falloc: Option<LuaAlloc>,
    ud: *mut c_void,
}

impl CExternalBytesOwner {
    /// # Safety
    /// `pointer` 非空，`len + 1 <= isize::MAX`，且涵蓋有效、不可變、末端為 NUL 的 bytes。
    /// 若提供 `falloc`，它與 `ud` 必須是此 buffer 的原配置器，能正常返回並接受
    /// 恰一次 `(pointer, len + 1, 0)` 釋放；若沒有 `falloc`，呼叫者須保活 buffer。
    /// 呼叫後所有權立即交給回傳值，建構本身不會失敗。
    pub unsafe fn from_raw_parts(
        pointer: *const u8,
        len: usize,
        falloc: Option<LuaAlloc>,
        ud: *mut c_void,
    ) -> Self {
        debug_assert!(!pointer.is_null() && len.checked_add(1).is_some_and(|n| n <= isize::MAX as usize));
        Self {
            // SAFETY：呼叫者保證 pointer 非空。
            pointer: unsafe { NonNull::new_unchecked(pointer.cast_mut()) },
            len,
            falloc,
            ud,
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.pointer.as_ptr().cast_const()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY：建構契約保證 buffer 有效且最後 owner 存活期間不可變。
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    pub fn nul_terminated_bytes(&self) -> &[u8] {
        // SAFETY：建構契約保證 len + 1 bytes 有效，並含末端 NUL。
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.len + 1) }
    }
}

impl Drop for CExternalBytesOwner {
    fn drop(&mut self) {
        if let Some(falloc) = self.falloc {
            // SAFETY：唯一 owner 保存原 falloc/ud，且建構時驗證 len + 1 可表示。
            let _ = unsafe {
                falloc(self.ud, self.pointer.as_ptr().cast(), self.len + 1, 0)
            };
        }
    }
}

/// 配置器只負責實體 block；宿主在可回收的安全點決定是否執行 GC。
pub trait AllocationRecovery {
    type Error;

    fn allocator(&self) -> StateAllocator;
    fn recover_after_refusal(&mut self, before: u64) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Default)]
pub struct GlobalAllocation;

impl AllocationRecovery for GlobalAllocation {
    type Error = core::convert::Infallible;

    fn allocator(&self) -> StateAllocator {
        StateAllocator::Global
    }

    fn recover_after_refusal(&mut self, _before: u64) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReserveError<E> {
    AllocatorMismatch,
    CallbackRefused,
    AllocationFailed,
    Recovery(E),
}

/// 呼叫端須先完成既有 budget/failpoint；拒絕後仍保留同一容器與其舊 block。
pub fn try_reserve_exact_with<T, R: AllocationRecovery>(
    values: &mut AllocVec<T, StateAllocator>,
    additional: usize,
    recovery: &mut R,
) -> Result<(), ReserveError<R::Error>> {
    let allocator = values.allocator().clone();
    if !allocator.same_binding(&recovery.allocator()) {
        return Err(ReserveError::AllocatorMismatch);
    }
    let before = allocator.refusal_count();
    if values.try_reserve_exact(additional).is_ok() {
        return Ok(());
    }
    if !allocator.is_lua() || allocator.refusal_count() == before {
        return Err(ReserveError::AllocationFailed);
    }
    if !recovery
        .recover_after_refusal(before)
        .map_err(ReserveError::Recovery)?
    {
        return Err(ReserveError::CallbackRefused);
    }
    let retry_before = allocator.refusal_count();
    values.try_reserve_exact(additional).map_err(|_| {
        if allocator.refusal_count() != retry_before {
            ReserveError::CallbackRefused
        } else {
            ReserveError::AllocationFailed
        }
    })
}

/// 在移入值之前，以同一低階配置請求建立共享 block。
pub fn try_shared_uninit_with<T, R: AllocationRecovery>(
    recovery: &mut R,
    tag: usize,
) -> Result<SharedUninitBlock<T>, ReserveError<R::Error>> {
    let allocator = recovery.allocator();
    let before = allocator.refusal_count();
    if let Ok(block) = allocator.clone().shared_uninit(tag) {
        return Ok(block);
    }
    if !allocator.is_lua() || allocator.refusal_count() == before {
        return Err(ReserveError::AllocationFailed);
    }
    if !recovery
        .recover_after_refusal(before)
        .map_err(ReserveError::Recovery)?
    {
        return Err(ReserveError::CallbackRefused);
    }
    let retry_before = allocator.refusal_count();
    allocator.clone().shared_uninit(tag).map_err(|_| {
        if allocator.refusal_count() != retry_before {
            ReserveError::CallbackRefused
        } else {
            ReserveError::AllocationFailed
        }
    })
}

pub struct LuaBinding {
    function: Cell<Option<LuaAlloc>>,
    user_data: Cell<*mut c_void>,
    callback_active: Cell<bool>,
    refusals: Cell<u64>,
    raw_live_bytes: Cell<usize>,
    #[cfg(feature = "test-support")]
    _test_owner: Option<Rc<core::cell::RefCell<test_support::TestState>>>,
}

struct CallbackBindingOwner {
    references: Cell<usize>,
    base: NonNull<u8>,
    bytes: usize,
    binding: LuaBinding,
}

enum LuaBindingOwner {
    Callback(NonNull<CallbackBindingOwner>),
    RustHost(Rc<LuaBinding>),
}

/// Lua callback 的不透明共享 handle；callback owner 不以自己的 StateAllocator 保活。
pub struct LuaBindingRef(LuaBindingOwner);

impl LuaBindingRef {
    pub fn is_callback_owned(&self) -> bool {
        matches!(&self.0, LuaBindingOwner::Callback(_))
    }

    /// 此 binding 目前成功配置、尚未釋放的 lua_Alloc 實體 nsize 總和。
    pub fn raw_live_bytes(&self) -> usize {
        self.raw_live_bytes.get()
    }

    /// # Safety
    /// callback 與 user_data 必須符合 LuaBinding::new 的契約，直到最後一個 handle 消失。
    /// 主配置先以 tag 8 請求，binding owner 隨後以 tag 0 請求；發布前不重試。
    pub unsafe fn bootstrap<T>(function: LuaAlloc, user_data: *mut c_void)
        -> Option<(Self, UninitBlock<T>)>
    {
        // SAFETY：由呼叫者保證 callback/ud 的生命週期與 ABI。
        let binding = unsafe { LuaBinding::new(function, user_data) };
        let main = StateAllocator::allocate_lua(&binding, Layout::new::<T>(), 8).ok()?;
        let owner = match StateAllocator::allocate_lua(
            &binding, Layout::new::<CallbackBindingOwner>(), 0,
        ) {
            Ok(owner) => owner.cast::<CallbackBindingOwner>(),
            Err(_) => {
                // SAFETY：main 尚未交出，header 記錄首次配置的原 base 與實際 bytes。
                let header = unsafe { StateAllocator::header(main.cast()) };
                binding.free(header.base.as_ptr(), header.bytes);
                return None;
            }
        };
        // SAFETY：owner 是尚未初始化、正確對齊的獨占 callback block。
        let header = unsafe { StateAllocator::header(owner.cast()) };
        unsafe {
            owner.as_ptr().write(CallbackBindingOwner {
                references: Cell::new(1),
                base: header.base,
                bytes: header.bytes,
                binding,
            });
        }
        let handle = Self(LuaBindingOwner::Callback(owner));
        let pending = UninitBlock {
            pointer: main.cast(),
            allocator: StateAllocator::Lua(handle.clone()),
            _marker: PhantomData,
        };
        Some((handle, pending))
    }

    pub fn same_binding(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (LuaBindingOwner::Callback(left), LuaBindingOwner::Callback(right)) => left == right,
            (LuaBindingOwner::RustHost(left), LuaBindingOwner::RustHost(right)) => Rc::ptr_eq(left, right),
            _ => false,
        }
    }

    pub fn admit(&self, bytes: usize) -> Option<AdmissionToken> {
        if bytes == 0 { return None; }
        self.call(ptr::null_mut(), 0, bytes).map(|pointer| AdmissionToken {
            kind: AdmissionTokenKind::Callback {
                binding: self.clone(), pointer, bytes,
            },
        })
    }
}

impl From<Rc<LuaBinding>> for LuaBindingRef {
    fn from(binding: Rc<LuaBinding>) -> Self {
        Self(LuaBindingOwner::RustHost(binding))
    }
}

impl Clone for LuaBindingRef {
    fn clone(&self) -> Self {
        match &self.0 {
            LuaBindingOwner::RustHost(binding) => Self::from(Rc::clone(binding)),
            LuaBindingOwner::Callback(pointer) => {
                // SAFETY：現存 handle 保證 owner 有效，且 Cell 僅在同一執行緒使用。
                let owner = unsafe { pointer.as_ref() };
                owner.references.set(owner.references.get().checked_add(1).unwrap_or_else(|| abort()));
                Self(LuaBindingOwner::Callback(*pointer))
            }
        }
    }
}

impl Deref for LuaBindingRef {
    type Target = LuaBinding;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            LuaBindingOwner::RustHost(binding) => binding,
            // SAFETY：此 handle 持有一份 references，owner 仍有效。
            LuaBindingOwner::Callback(pointer) => unsafe { &pointer.as_ref().binding },
        }
    }
}

impl Drop for LuaBindingRef {
    fn drop(&mut self) {
        let LuaBindingOwner::Callback(pointer) = &self.0 else { return; };
        // SAFETY：最後一份 handle 獨占釋放權；釋放 callback owner 後不再存取其欄位。
        unsafe {
            let owner = pointer.as_ptr();
            let count = (*owner).references.get();
            if count == 0 { abort(); }
            if count > 1 {
                (*owner).references.set(count - 1);
                return;
            }
            let binding = &mut (*owner).binding;
            if binding.callback_active.replace(true) { abort(); }
            let (function, user_data) = binding.current();
            let Some(function) = function else { abort() };
            let base = (*owner).base;
            let bytes = (*owner).bytes;
            #[cfg(feature = "test-support")]
            let test_owner = binding._test_owner.take();
            // 這是最後一份 handle；owner 本身釋放後不可再讀寫 binding。
            let remaining = binding.raw_live_bytes.get().checked_sub(bytes)
                .unwrap_or_else(|| abort());
            if remaining != 0 { abort(); }
            binding.raw_live_bytes.set(0);
            function(user_data, base.as_ptr().cast(), bytes, 0);
            #[cfg(feature = "test-support")]
            drop(test_owner);
        }
    }
}

/// admission 的唯一 owner；callback block 僅能由成功的 LuaBindingRef::admit 建立。
pub struct AdmissionToken {
    kind: AdmissionTokenKind,
}

enum AdmissionTokenKind {
    Logical(NonZeroUsize),
    Callback {
        binding: LuaBindingRef,
        pointer: NonNull<u8>,
        bytes: usize,
    },
}

impl AdmissionToken {
    /// 純邏輯 admission 的識別值，不持有 callback 指標。
    pub fn logical(tag: NonZeroUsize) -> Self {
        Self { kind: AdmissionTokenKind::Logical(tag) }
    }

    pub fn logical_tag(&self) -> Option<NonZeroUsize> {
        match &self.kind {
            AdmissionTokenKind::Logical(tag) => Some(*tag),
            AdmissionTokenKind::Callback { .. } => None,
        }
    }
}

impl Drop for AdmissionToken {
    fn drop(&mut self) {
        if let AdmissionTokenKind::Callback { binding, pointer, bytes } = &self.kind {
            binding.free(pointer.as_ptr(), *bytes);
        }
    }
}

struct CallbackGuard<'a>(&'a Cell<bool>);

impl Drop for CallbackGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl LuaBinding {
    /// # Safety
    /// `function` 須遵守 lua_Alloc 契約，且不得 unwind 或 longjmp；`user_data` 須在
    /// 此 binding 所有 callback block 存活及釋放期間對該函式有效。
    pub unsafe fn new(function: LuaAlloc, user_data: *mut c_void) -> Self {
        Self {
            function: Cell::new(Some(function)),
            user_data: Cell::new(user_data),
            callback_active: Cell::new(false),
            refusals: Cell::new(0),
            raw_live_bytes: Cell::new(0),
            #[cfg(feature = "test-support")]
            _test_owner: None,
        }
    }

    pub fn current(&self) -> (Option<LuaAlloc>, *mut c_void) {
        (self.function.get(), self.user_data.get())
    }

    /// # Safety
    /// 新 `function`/`user_data` 須在此 binding 後續配置及釋放期間有效；新函式亦須能
    /// 依 lua_Alloc 契約處理此前由此 binding 建立但尚未釋放的 block，且不得 unwind 或 longjmp。
    pub unsafe fn set_current(&self, function: LuaAlloc, user_data: *mut c_void) -> bool {
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

    fn call(&self, pointer: *mut u8, osize: usize, nsize: usize) -> Option<NonNull<u8>> {
        if self.callback_active.replace(true) {
            return None;
        }
        let _guard = CallbackGuard(&self.callback_active);
        let function = self.function.get()?;
        // NULL 的 osize 是 Lua 類型標記；只有既存 block 的 osize 才是舊尺寸。
        let old_bytes = if pointer.is_null() { 0 } else { osize };
        let remaining = self.raw_live_bytes.get().checked_sub(old_bytes)
            .unwrap_or_else(|| abort());
        let Some(next_live_bytes) = remaining.checked_add(nsize) else {
            self.refusals.set(self.refusals.get().wrapping_add(1));
            return None;
        };
        // SAFETY：宿主保證 callback/ud 在所有由此 binding 配置的 block 存活期間有效。
        // 同步重入由 callback_active 拒絕；舊 block 只能由同一 binding 的所有者傳入。
        let result = NonNull::new(unsafe {
            function(self.user_data.get(), pointer.cast(), osize, nsize).cast()
        });
        if result.is_none() && nsize != 0 {
            self.refusals.set(self.refusals.get().wrapping_add(1));
        } else if result.is_some() {
            self.raw_live_bytes.set(next_live_bytes);
        }
        result
    }

    fn free(&self, pointer: *mut u8, bytes: usize) {
        if self.callback_active.replace(true) {
            // 釋放不能回報失敗；重入代表 callback 違反目前 state 的配置契約。
            abort();
        }
        let _guard = CallbackGuard(&self.callback_active);
        let Some(function) = self.function.get() else {
            abort();
        };
        // SAFETY：pointer 是尚未釋放的 callback block，bytes 為其最後一次成功配置尺寸。
        unsafe { function(self.user_data.get(), pointer.cast(), bytes, 0) };
        let remaining = self.raw_live_bytes.get().checked_sub(bytes)
            .unwrap_or_else(|| abort());
        self.raw_live_bytes.set(remaining);
    }
}

#[derive(Clone)]
pub enum StateAllocator {
    Global,
    Lua(LuaBindingRef),
}

#[derive(Clone, Copy)]
struct Header {
    base: NonNull<u8>,
    bytes: usize,
    offset: usize,
}

impl StateAllocator {
    pub fn same_binding(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Global, Self::Global) => true,
            (Self::Lua(left), Self::Lua(right)) => left.same_binding(right),
            _ => false,
        }
    }

    fn raw_size(layout: Layout) -> Result<usize, AllocError> {
        layout
            .size()
            .max(1)
            .checked_add(layout.align() - 1)
            .and_then(|bytes| bytes.checked_add(size_of::<Header>()))
            .ok_or(AllocError)
    }

    fn aligned(base: NonNull<u8>, bytes: usize, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        let start = base.as_ptr() as usize;
        let address = start
            .checked_add(size_of::<Header>())
            .and_then(|address| address.checked_add(layout.align() - 1))
            .map(|address| address & !(layout.align() - 1))
            .ok_or(AllocError)?;
        let offset = address - start;
        if offset.checked_add(layout.size()).is_none_or(|end| end > bytes) {
            return Err(AllocError);
        }
        // SAFETY：offset 位於 callback 給出的 block；計算後的 address 符合 layout 對齊。
        Ok(unsafe { NonNull::new_unchecked(base.as_ptr().add(offset)) })
    }

    fn allocate_lua(
        binding: &LuaBinding,
        layout: Layout,
        tag: usize,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let bytes = Self::raw_size(layout)?;
        let base = binding.call(ptr::null_mut(), tag, bytes).ok_or(AllocError)?;
        let pointer = match Self::aligned(base, bytes, layout) {
            Ok(pointer) => pointer,
            Err(error) => {
                binding.free(base.as_ptr(), bytes);
                return Err(error);
            }
        };
        let header = Header {
            base,
            bytes,
            offset: pointer.as_ptr() as usize - base.as_ptr() as usize,
        };
        // SAFETY：header 位於已配置 block 的資料區之前；unaligned 存取不要求 callback
        // 回傳的 base 有 Rust Header 的自然對齊。
        unsafe { pointer.as_ptr().sub(size_of::<Header>()).cast::<Header>().write_unaligned(header) };
        Ok(NonNull::slice_from_raw_parts(pointer, layout.size()))
    }

    unsafe fn header(pointer: NonNull<u8>) -> Header {
        // SAFETY：呼叫端保證 pointer 由本配置器成功回傳且尚未釋放。
        unsafe { pointer.as_ptr().sub(size_of::<Header>()).cast::<Header>().read_unaligned() }
    }

    unsafe fn resize_lua(
        binding: &LuaBinding,
        pointer: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
        zero_new: bool,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // SAFETY：Allocator::grow/shrink 的呼叫者保證舊 pointer/layout 有效。
        let old = unsafe { Self::header(pointer) };
        let copy_bytes = old_layout.size().min(new_layout.size());
        let bytes = Self::raw_size(new_layout)?
            .max(old.offset.checked_add(copy_bytes).ok_or(AllocError)?);
        let base = binding.call(old.base.as_ptr(), old.bytes, bytes).ok_or(AllocError)?;
        // callback 已成功 realloc；舊 block 此時可能失效。raw_size 與保留舊 offset
        // 已證明有效 callback block 容得下對齊資料，故不能再以可恢復錯誤返回。
        let aligned = match Self::aligned(base, bytes, new_layout) {
            Ok(pointer) => pointer,
            Err(_) => abort(),
        };
        // SAFETY：callback 成功 realloc 會保留前 copy_bytes；raw 尺寸特意保留舊 offset
        // 的這段內容。copy 支援新舊資料區重疊。
        unsafe {
            ptr::copy(base.as_ptr().add(old.offset), aligned.as_ptr(), copy_bytes);
            if zero_new && new_layout.size() > old_layout.size() {
                aligned
                    .as_ptr()
                    .add(old_layout.size())
                    .write_bytes(0, new_layout.size() - old_layout.size());
            }
            aligned
                .as_ptr()
                .sub(size_of::<Header>())
                .cast::<Header>()
                .write_unaligned(Header {
                    base,
                    bytes,
                    offset: aligned.as_ptr() as usize - base.as_ptr() as usize,
                });
        }
        Ok(NonNull::slice_from_raw_parts(aligned, new_layout.size()))
    }

    pub fn is_lua(&self) -> bool {
        matches!(self, Self::Lua(_))
    }

    pub fn binding(&self) -> Option<&LuaBindingRef> {
        match self {
            Self::Lua(binding) => Some(binding),
            Self::Global => None,
        }
    }

    pub fn refusal_count(&self) -> u64 {
        self.binding().map_or(0, |binding| binding.refusals.get())
    }

    pub fn uninit<T>(self, tag: usize) -> Result<UninitBlock<T>, AllocError> {
        let layout = Layout::new::<T>();
        let pointer = if let Self::Lua(binding) = &self {
            Self::allocate_lua(binding, layout, tag)?
        } else {
            self.allocate(layout)?
        };
        Ok(UninitBlock {
            pointer: pointer.cast(),
            allocator: self,
            _marker: PhantomData,
        })
    }

    /// 僅首次實體 Vec backing 帶 Lua 類型標記；後續 grow/free 沿原 allocator header。
    pub fn tagged_vec_with_capacity<T>(self, capacity: usize, tag: usize) -> Result<AllocVec<T, Self>, AllocError> {
        if capacity == 0 || size_of::<T>() == 0 || !self.is_lua() {
            let mut values = AllocVec::new_in(self);
            values.try_reserve_exact(capacity).map_err(|_| AllocError)?;
            return Ok(values);
        }
        let layout = Layout::array::<T>(capacity).map_err(|_| AllocError)?;
        if layout.size() > isize::MAX as usize {
            return Err(AllocError);
        }
        let Self::Lua(binding) = &self else { return Err(AllocError) };
        let pointer = Self::allocate_lua(binding, layout, tag)?;
        // SAFETY：指標由同一 StateAllocator 按 Layout::array::<T>(capacity) 配置，
        // cap 與配置大小相符；目前沒有已初始化元素，唯一 Vec owner 接管整個 block。
        // 原 header 保留 base／實際大小，之後 grow/free 仍由相同 Lua binding 處理。
        Ok(unsafe { AllocVec::from_raw_parts_in(pointer.cast::<T>().as_ptr(), 0, capacity, self) })
    }
}

// SAFETY：每個成功配置保留 base、真實大小與資料 offset；grow/shrink 傳原 base
// 給 callback，失敗時保留舊 block；deallocate 使用當前 binding 釋放同一 base。
unsafe impl Allocator for StateAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Global => Global.allocate(layout),
            Self::Lua(binding) => Self::allocate_lua(binding, layout, 0),
        }
    }

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let pointer = self.allocate(layout)?;
        // SAFETY：allocate 成功回傳至少 layout.size() 可寫 byte。
        unsafe { pointer.cast::<u8>().as_ptr().write_bytes(0, layout.size()) };
        Ok(pointer)
    }

    unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
        match self {
            Self::Global => {
                // SAFETY：原 pointer/layout 由 Global 配置。
                unsafe { Global.deallocate(pointer, layout) }
            }
            Self::Lua(binding) => {
                // SAFETY：原 pointer/layout 由相同 StateAllocator 配置。
                let header = unsafe { Self::header(pointer) };
                binding.free(header.base.as_ptr(), header.bytes);
            }
        }
    }

    unsafe fn grow(
        &self,
        pointer: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Global => unsafe { Global.grow(pointer, old_layout, new_layout) },
            Self::Lua(binding) => unsafe {
                Self::resize_lua(binding, pointer, old_layout, new_layout, false)
            },
        }
    }

    unsafe fn grow_zeroed(
        &self,
        pointer: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Global => unsafe { Global.grow_zeroed(pointer, old_layout, new_layout) },
            Self::Lua(binding) => unsafe {
                Self::resize_lua(binding, pointer, old_layout, new_layout, true)
            },
        }
    }

    unsafe fn shrink(
        &self,
        pointer: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Global => unsafe { Global.shrink(pointer, old_layout, new_layout) },
            Self::Lua(binding) => unsafe {
                Self::resize_lua(binding, pointer, old_layout, new_layout, false)
            },
        }
    }
}

pub struct UninitBlock<T> {
    pointer: NonNull<T>,
    allocator: StateAllocator,
    _marker: PhantomData<T>,
}

impl<T> UninitBlock<T> {
    pub fn write(self, value: T) -> Block<T> {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY：pointer 指向恰一個已配置、符合 T 對齊的尚未初始化 slot。
        unsafe { this.pointer.as_ptr().write(value) };
        Block {
            pointer: this.pointer,
            // SAFETY：ManuallyDrop 僅阻止釋放 slot；此處移出唯一 allocator owner。
            allocator: unsafe { ptr::read(&this.allocator) },
        }
    }
}

impl<T> Drop for UninitBlock<T> {
    fn drop(&mut self) {
        // SAFETY：slot 尚未初始化，但實體 backing 由此物件獨佔。
        unsafe { self.allocator.deallocate(self.pointer.cast(), Layout::new::<T>()) };
    }
}

pub struct Block<T> {
    pointer: NonNull<T>,
    allocator: StateAllocator,
}

struct BlockRelease<'a> {
    pointer: NonNull<u8>,
    allocator: &'a StateAllocator,
    layout: Layout,
}

impl Drop for BlockRelease<'_> {
    fn drop(&mut self) {
        // SAFETY：Block::drop 的唯一 T 已析構或正因 panic 展開；guard
        // 唯一持有原 backing 的釋放責任，allocator 欄位此時仍有效。
        unsafe { self.allocator.deallocate(self.pointer, self.layout) };
    }
}

impl<T> Deref for Block<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY：write 已初始化，且 Block 獨佔 T 直到 drop。
        unsafe { self.pointer.as_ref() }
    }
}

impl<T> DerefMut for Block<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY：Block 獨佔已初始化的 T。
        unsafe { self.pointer.as_mut() }
    }
}

impl<T> Drop for Block<T> {
    fn drop(&mut self) {
        let _release = BlockRelease {
            pointer: self.pointer.cast(),
            allocator: &self.allocator,
            layout: Layout::new::<T>(),
        };
        // SAFETY：此 block 的唯一 T 在 backing 仍有效時析構；guard 在正常及
        // panic 展開時釋放原 callback base。
        unsafe {
            ptr::drop_in_place(self.pointer.as_ptr());
        }
    }
}

struct ThinBlockInner<T> {
    allocator: StateAllocator,
    value: T,
}

/// 只在 owner 端保存一個指標；allocator 隨實體 block 存放並一同釋放。
pub struct ThinBlock<T> {
    pointer: NonNull<ThinBlockInner<T>>,
}

impl<T> ThinBlock<T> {
    pub fn into_raw(self) -> *mut T {
        let inner = self.pointer.as_ptr();
        core::mem::forget(self);
        // SAFETY：inner 指向已初始化的唯一 block；只計算 value 欄位位址。
        unsafe { ptr::addr_of_mut!((*inner).value) }
    }

    /// # Safety
    /// `value` 必須是同型別 `ThinBlock::into_raw` 交出的有效指標，且恰好重建一次。
    pub unsafe fn from_raw(value: *mut T) -> Self {
        // SAFETY：value 位於仍存活的 ThinBlockInner<T> 中；offset_of 精確回推配置基址。
        let inner = unsafe { value.cast::<u8>().sub(offset_of!(ThinBlockInner<T>, value)) }
            .cast::<ThinBlockInner<T>>();
        Self {
            // SAFETY：into_raw 保證 value 與回推的 inner 非空且對齊。
            pointer: unsafe { NonNull::new_unchecked(inner) },
        }
    }
}

/// 擦除 value 型別後，仍獨占原 ThinBlock 的配置與析構責任。
pub struct ErasedThinBlock {
    pointer: NonNull<()>,
    type_id: TypeId,
    drop_block: unsafe fn(NonNull<()>),
}

impl ErasedThinBlock {
    pub fn from_block<T: Any>(block: ThinBlock<T>) -> Self {
        let type_id = TypeId::of::<T>();
        let pointer = block.into_raw();
        Self {
            // SAFETY：ThinBlock::into_raw 交出已初始化 value 的非空唯一指標。
            pointer: unsafe { NonNull::new_unchecked(pointer) }.cast(),
            type_id,
            drop_block: Self::drop_typed::<T>,
        }
    }

    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        if self.type_id != TypeId::of::<T>() { return None; }
        // SAFETY：TypeId 對應原 T，且共享借用不能移動或析構唯一 owner。
        Some(unsafe { &*self.pointer.cast::<T>().as_ptr() })
    }

    pub fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        if self.type_id != TypeId::of::<T>() {
            return None;
        }
        // SAFETY：TypeId 相同即為原 T；&mut self 保證此唯一 owner 的排他借用。
        Some(unsafe { &mut *self.pointer.cast::<T>().as_ptr() })
    }

    unsafe fn drop_typed<T: Any>(pointer: NonNull<()>) {
        // SAFETY：此函式只由 from_block 配對原 T，且 ErasedThinBlock 僅析構一次。
        drop(unsafe { ThinBlock::from_raw(pointer.cast::<T>().as_ptr()) });
    }
}

impl Drop for ErasedThinBlock {
    fn drop(&mut self) {
        // SAFETY：pointer 與 drop_block 在同一次 from_block 建立後保持配對且獨占。
        unsafe { (self.drop_block)(self.pointer) };
    }
}

pub struct ThinUninitBlock<T> {
    pointer: NonNull<ThinBlockInner<T>>,
    allocator: StateAllocator,
}

impl<T> ThinUninitBlock<T> {
    pub fn write(self, value: T) -> ThinBlock<T> {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY：pointer 是唯一未初始化 backing；allocator owner 從 wrapper 移入
        // block 前綴，使返回的 ThinBlock 能在唯一 Drop 中釋放自身。
        unsafe {
            this.pointer.as_ptr().write(ThinBlockInner {
                allocator: ptr::read(&this.allocator),
                value,
            });
        }
        ThinBlock {
            pointer: this.pointer,
        }
    }
}

impl<T> Drop for ThinUninitBlock<T> {
    fn drop(&mut self) {
        // SAFETY：write 尚未執行；此 wrapper 唯一持有未初始化實體 block。
        unsafe {
            self.allocator
                .deallocate(self.pointer.cast(), Layout::new::<ThinBlockInner<T>>());
        }
    }
}

struct ThinBlockRelease<T> {
    pointer: NonNull<ThinBlockInner<T>>,
    allocator: StateAllocator,
}

impl<T> Drop for ThinBlockRelease<T> {
    fn drop(&mut self) {
        // SAFETY：ThinBlock::drop 已移出 allocator 且此 guard 是唯一釋放 owner。
        unsafe {
            self.allocator
                .deallocate(self.pointer.cast(), Layout::new::<ThinBlockInner<T>>());
        }
    }
}

impl StateAllocator {
    pub const fn thin_block_size<T>() -> usize {
        size_of::<ThinBlockInner<T>>()
    }

    pub fn thin_uninit<T>(self, tag: usize) -> Result<ThinUninitBlock<T>, AllocError> {
        let layout = Layout::new::<ThinBlockInner<T>>();
        let pointer = if let Self::Lua(binding) = &self {
            Self::allocate_lua(binding, layout, tag)?
        } else {
            self.allocate(layout)?
        }
        .cast::<ThinBlockInner<T>>();
        Ok(ThinUninitBlock {
            pointer,
            allocator: self,
        })
    }

    pub fn thin_block<T>(self, value: T, tag: usize) -> Result<ThinBlock<T>, AllocError> {
        Ok(self.thin_uninit(tag)?.write(value))
    }
}

impl<T> Deref for ThinBlock<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY：thin_block 已初始化且唯一 owner 仍存活。
        unsafe { &self.pointer.as_ref().value }
    }
}

impl<T> DerefMut for ThinBlock<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY：唯一 owner 提供排他借用。
        unsafe { &mut self.pointer.as_mut().value }
    }
}

impl<T> Drop for ThinBlock<T> {
    fn drop(&mut self) {
        // SAFETY：先移出 block 自帶的 allocator owner，再析構 value；最後以相同
        // layout 釋放此唯一 block。allocator 的 Rc 保活目前 callback binding。
        unsafe {
            let inner = self.pointer.as_ptr();
            let allocator = ptr::read(&(*inner).allocator);
            let _release = ThinBlockRelease {
                pointer: self.pointer,
                allocator,
            };
            ptr::drop_in_place(&mut (*inner).value);
        }
    }
}

struct SharedBlockInner<T> {
    allocator: StateAllocator,
    strong: Cell<usize>,
    weak: Cell<usize>,
    value: core::mem::ManuallyDrop<T>,
}

/// 單執行緒的共享 callback block；clone 只增加同一實體 block 的 strong 計數。
pub struct SharedBlock<T> {
    pointer: NonNull<SharedBlockInner<T>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

/// 同一 typed backing 的弱 handle；strong 歸零後只保留無 payload 的墓碑。
pub struct SharedWeak<T> {
    pointer: Option<NonNull<SharedBlockInner<T>>>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<T> SharedWeak<T> {
    pub const fn new() -> Self {
        Self { pointer: None, _not_send_sync: PhantomData }
    }

    pub fn upgrade(&self) -> Option<SharedBlock<T>> {
        let pointer = self.pointer?;
        // SAFETY：weak handle 保留 header；strong>0 才允許借用 payload。
        let inner = unsafe { pointer.as_ref() };
        let strong = inner.strong.get();
        if strong == 0 { return None; }
        inner.strong.set(strong.checked_add(1).unwrap_or_else(|| abort()));
        Some(SharedBlock { pointer, _not_send_sync: PhantomData })
    }
}

impl<T> Default for SharedWeak<T> {
    fn default() -> Self { Self::new() }
}

impl<T> Clone for SharedWeak<T> {
    fn clone(&self) -> Self {
        if let Some(pointer) = self.pointer {
            // SAFETY：weak handle 保留 header，弱計數尚大於零。
            let inner = unsafe { pointer.as_ref() };
            inner.weak.set(inner.weak.get().checked_add(1).unwrap_or_else(|| abort()));
        }
        Self { pointer: self.pointer, _not_send_sync: PhantomData }
    }
}

impl<T> Drop for SharedWeak<T> {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            // SAFETY：此 weak 擁有一份計數；只有最後一份在 strong=0 時釋放 backing。
            unsafe { release_shared_weak(pointer) };
        }
    }
}

unsafe fn release_shared_weak<T>(pointer: NonNull<SharedBlockInner<T>>) {
    // SAFETY：呼叫者持有一份 weak 或最後 strong 的隱含 weak，header 仍有效。
    let inner = unsafe { &*pointer.as_ptr() };
    let weak = inner.weak.get();
    if weak == 0 { abort(); }
    if weak > 1 {
        inner.weak.set(weak - 1);
        return;
    }
    if inner.strong.get() != 0 { abort(); }
    let allocator = unsafe { ptr::read(&inner.allocator) };
    unsafe { allocator.deallocate(pointer.cast(), Layout::new::<SharedBlockInner<T>>()) };
}

pub struct SharedUninitBlock<T> {
    pointer: NonNull<SharedBlockInner<T>>,
    allocator: StateAllocator,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<T> SharedUninitBlock<T> {
    pub fn write(self, value: T) -> SharedBlock<T> {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY：此 wrapper 唯一持有未初始化 block；allocator 一同移入 block，
        // strong=1 使返回值成為唯一初始 owner。
        unsafe {
            this.pointer.as_ptr().write(SharedBlockInner {
                allocator: ptr::read(&this.allocator),
                strong: Cell::new(1),
                weak: Cell::new(1),
                value: core::mem::ManuallyDrop::new(value),
            });
        }
        SharedBlock {
            pointer: this.pointer,
            _not_send_sync: PhantomData,
        }
    }
}

impl<T> Drop for SharedUninitBlock<T> {
    fn drop(&mut self) {
        // SAFETY：write 尚未執行；此 wrapper 獨佔 backing。
        unsafe {
            self.allocator
                .deallocate(self.pointer.cast(), Layout::new::<SharedBlockInner<T>>());
        }
    }
}

impl StateAllocator {
    pub const fn shared_block_size<T>() -> usize {
        size_of::<SharedBlockInner<T>>()
    }

    pub fn shared_uninit<T>(self, tag: usize) -> Result<SharedUninitBlock<T>, AllocError> {
        let layout = Layout::new::<SharedBlockInner<T>>();
        let pointer = if let Self::Lua(binding) = &self {
            Self::allocate_lua(binding, layout, tag)?
        } else {
            self.allocate(layout)?
        }
        .cast();
        Ok(SharedUninitBlock {
            pointer,
            allocator: self,
            _not_send_sync: PhantomData,
        })
    }
}

impl<T> Clone for SharedBlock<T> {
    fn clone(&self) -> Self {
        // SAFETY：每個 live SharedBlock 都持有一份 strong；Cell 僅在同一執行緒存取。
        let strong = unsafe { self.pointer.as_ref().strong.get() };
        let Some(next) = strong.checked_add(1) else {
            abort();
        };
        if next == 0 {
            abort();
        }
        unsafe { self.pointer.as_ref().strong.set(next) };
        Self {
            pointer: self.pointer,
            _not_send_sync: PhantomData,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for SharedBlock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(f)
    }
}

impl<T: PartialEq> PartialEq for SharedBlock<T> {
    fn eq(&self, other: &Self) -> bool {
        self.deref().eq(other.deref())
    }
}

impl<T: Eq> Eq for SharedBlock<T> {}

impl<const N: usize> PartialEq<[u8; N]> for SharedBlock<AllocVec<u8, StateAllocator>> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for SharedBlock<AllocVec<u8, StateAllocator>> {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == *other
    }
}

impl<T: Hash> Hash for SharedBlock<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state);
    }
}

impl Borrow<[u8]> for SharedBlock<AllocVec<u8, StateAllocator>> {
    fn borrow(&self) -> &[u8] {
        self.deref().as_slice()
    }
}

impl<T> SharedBlock<T> {
    pub fn allocator(&self) -> &StateAllocator {
        // SAFETY：每個 SharedBlock 持有一份 strong，inner 在此 handle 存活期間有效。
        unsafe { &self.pointer.as_ref().allocator }
    }

    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.pointer == right.pointer
    }

    pub fn downgrade(&self) -> SharedWeak<T> {
        // SAFETY：self 持有 strong，header 有效且隱含 weak 仍存在。
        let inner = unsafe { self.pointer.as_ref() };
        inner.weak.set(inner.weak.get().checked_add(1).unwrap_or_else(|| abort()));
        SharedWeak { pointer: Some(self.pointer), _not_send_sync: PhantomData }
    }

    pub fn into_raw(self) -> *const T {
        let pointer = self.pointer;
        core::mem::forget(self);
        // SAFETY：強 handle 已移交 raw pointer；value 地址在 backing 存活期間固定。
        unsafe { ptr::addr_of!((*pointer.as_ptr()).value).cast::<T>() }
    }

    /// # Safety
    /// pointer 必須來自同型別 SharedBlock::into_raw，且這一份 strong 只能重建一次。
    pub unsafe fn from_raw(value: *const T) -> Self {
        // SAFETY：原 raw strong 保活 backing；offset_of 從 payload 精確回推 header。
        let inner = unsafe { value.cast::<u8>().sub(offset_of!(SharedBlockInner<T>, value)) }
            .cast_mut().cast::<SharedBlockInner<T>>();
        Self { pointer: unsafe { NonNull::new_unchecked(inner) }, _not_send_sync: PhantomData }
    }

    pub fn try_unwrap(self) -> Result<T, Self> {
        // SAFETY：self 持有 strong；唯有 strong=1 才可移出 payload。
        let inner = unsafe { self.pointer.as_ref() };
        if inner.strong.get() != 1 { return Err(self); }
        inner.strong.set(0);
        let pointer = self.pointer;
        core::mem::forget(self);
        let value = unsafe { ptr::read(ptr::addr_of!((*pointer.as_ptr()).value).cast::<T>()) };
        // SAFETY：payload 已移出且 strong=0；退還最後 strong 的隱含 weak。
        unsafe { release_shared_weak(pointer) };
        Ok(value)
    }
}

impl<T> Deref for SharedBlock<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY：strong>0 時 value 已初始化並保持存活。
        unsafe { &self.pointer.as_ref().value }
    }
}

impl<T> AsRef<T> for SharedBlock<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T> Drop for SharedBlock<T> {
    fn drop(&mut self) {
        // SAFETY：同執行緒 strong 計數與 clone/drop 配對；最後一份唯一負責析構。
        unsafe {
            let inner = self.pointer.as_ptr();
            let strong = (*inner).strong.get();
            if strong == 0 {
                abort();
            }
            if strong > 1 {
                (*inner).strong.set(strong - 1);
                return;
            }
            (*inner).strong.set(0);
            let _release = SharedBlockRelease { pointer: self.pointer };
            core::mem::ManuallyDrop::drop(&mut (*inner).value);
        }
    }
}

struct SharedBlockRelease<T> {
    pointer: NonNull<SharedBlockInner<T>>,
}

impl<T> Drop for SharedBlockRelease<T> {
    fn drop(&mut self) {
        // SAFETY：最後一份 SharedBlock 已析構 value；即使析構 panic 亦退還隱含 weak。
        unsafe { release_shared_weak(self.pointer) };
    }
}


