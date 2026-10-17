//! 已驗證原生碼的頁面發布與生命週期；只接受 codegen 的密封輸出。

use crate::abi::{self, NativeError, NativeExit, NativeState};
use crate::artifact::ValidatedCode;
#[cfg(target_os = "linux")]
use core::ptr::NonNull;

const HARD_CODE_LIMIT: usize = 16 * 1024 * 1024;

struct PagePlan {
    allocation: usize,
    capacity: usize,
}

pub(crate) struct PlannedUsage {
    pub(crate) code_bytes: usize,
    pub(crate) metadata_bytes: usize,
}

/// 在配置可執行頁面前檢查封閉的目標、額度與目前程序的平台能力。
pub(crate) fn preflight(code: &ValidatedCode, code_limit_bytes: usize) -> Result<(), NativeError> {
    let plan = page_plan(code, code_limit_bytes)?;
    platform_preflight()?;
    #[cfg(target_os = "macos")]
    {
        mac::check_existing_capacity(plan.capacity)?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = plan;
    Ok(())
}

pub(crate) fn planned_usage(
    code: &ValidatedCode,
    code_limit_bytes: usize,
) -> Result<PlannedUsage, NativeError> {
    let plan = page_plan(code, code_limit_bytes)?;
    #[cfg(target_os = "macos")]
    {
        let free_slots = plan
            .capacity
            .checked_div(page_size()?)
            .and_then(|n| n.checked_add(1))
            .ok_or(NativeError::InvalidCode)?;
        let free_bytes = free_slots
            .checked_mul(core::mem::size_of::<(usize, usize)>())
            .ok_or(NativeError::InvalidCode)?;
        let metadata_bytes = core::mem::size_of::<ExecutableCode>()
            .checked_add(core::mem::size_of::<
                std::sync::OnceLock<std::sync::Mutex<mac::Arena>>,
            >())
            .and_then(|n| n.checked_add(free_bytes))
            .ok_or(NativeError::InvalidCode)?;
        Ok(PlannedUsage {
            code_bytes: plan.capacity,
            metadata_bytes,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(PlannedUsage {
            code_bytes: plan.allocation,
            metadata_bytes: core::mem::size_of::<ExecutableCode>(),
        })
    }
}

/// 可在 codegen 前呼叫；不接觸 guest，也不分配可執行頁面。
pub(crate) fn platform_preflight() -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        return mac::preflight();
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok(());
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Err(NativeError::Unsupported(
            "Linux AArch64 指令快取同步能力尚未確認",
        ));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return Err(NativeError::Unsupported("此平台不支援原生碼頁面"));
    }
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        Err(NativeError::Unsupported("此 Linux 架構不支援原生碼頁面"))
    }
}

fn page_plan(code: &ValidatedCode, code_limit_bytes: usize) -> Result<PagePlan, NativeError> {
    if code.bytes().is_empty()
        || code.entry_offset() >= code.bytes().len()
        || code.entry_pc() > code.max_pc()
        || code.register_count() == 0
        || code.register_count() > 4096
        || !code.required_cpu_features().is_empty()
    {
        return Err(NativeError::InvalidCode);
    }
    if code.target() != host_target() {
        return Err(NativeError::Unsupported("原生碼目標與主機不符"));
    }
    let page = page_size()?;
    let allocation = code
        .bytes()
        .len()
        .checked_add(page - 1)
        .map(|n| n / page * page)
        .ok_or(NativeError::InvalidCode)?;
    let capacity = code_limit_bytes.min(HARD_CODE_LIMIT) / page * page;
    if capacity == 0 || allocation > capacity {
        return Err(NativeError::Unsupported("原生碼超出頁面配額"));
    }
    Ok(PagePlan {
        allocation,
        capacity,
    })
}

#[cfg(unix)]
fn page_size() -> Result<usize, NativeError> {
    // SAFETY: sysconf 只讀取目前程序的頁面大小，沒有指標或子程序。
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).map_err(|_| NativeError::Unsupported("無法取得頁面大小"))?;
    if !size.is_power_of_two() {
        return Err(NativeError::Unsupported("不支援的頁面大小"));
    }
    Ok(size)
}

#[cfg(not(unix))]
fn page_size() -> Result<usize, NativeError> {
    Err(NativeError::Unsupported("此平台不支援原生碼頁面"))
}

pub(crate) fn host_target() -> &'static str {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        return "aarch64-apple-darwin";
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        return "x86_64-apple-darwin";
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        return "aarch64-unknown-linux-gnu";
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        return "x86_64-unknown-linux-gnu";
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
    )))]
    {
        "unsupported"
    }
}

pub(crate) struct ExecutableCode {
    entry: *const u8,
    entry_pc: u64,
    max_pc: u64,
    register_count: usize,
    allocation: usize,
    #[cfg(target_os = "linux")]
    mapping: NonNull<libc::c_void>,
    #[cfg(target_os = "macos")]
    offset: usize,
}

impl ExecutableCode {
    pub(crate) fn publish(
        code: &ValidatedCode,
        code_limit_bytes: usize,
    ) -> Result<Self, NativeError> {
        preflight(code, code_limit_bytes)?;
        let plan = page_plan(code, code_limit_bytes)?;
        #[cfg(target_os = "linux")]
        {
            // SAFETY: 尺寸已由配額及頁面溢位檢查限制；匿名私有映射由 Drop 擁有。
            let raw = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    plan.allocation,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if raw == libc::MAP_FAILED {
                return Err(NativeError::AllocationFailed);
            }
            let Some(mapping) = NonNull::new(raw) else {
                // SAFETY: mmap 成功後必須釋放，即使平台意外回傳零位址。
                unsafe { libc::munmap(raw, plan.allocation) };
                return Err(NativeError::AllocationFailed);
            };
            // SAFETY: 來源為已密封機器碼；映射可寫且至少 allocation 位元組。
            unsafe {
                core::ptr::copy_nonoverlapping(
                    code.bytes().as_ptr(),
                    raw.cast::<u8>(),
                    code.bytes().len(),
                )
            };
            // SAFETY: 同一映射由目前執行緒獨占；由 W 轉 RX，不建立 RWX 頁面。
            if unsafe { libc::mprotect(raw, plan.allocation, libc::PROT_READ | libc::PROT_EXEC) }
                != 0
            {
                // SAFETY: 保護切換失敗仍由本函式獨占映射。
                unsafe { libc::munmap(raw, plan.allocation) };
                return Err(NativeError::ProtectionFailed);
            }
            // SAFETY: offset 已檢查落在剛發布的映射內。
            let entry = unsafe { raw.cast::<u8>().add(code.entry_offset()).cast_const() };
            return Ok(Self {
                entry,
                entry_pc: code.entry_pc(),
                max_pc: code.max_pc(),
                register_count: code.register_count(),
                allocation: plan.allocation,
                mapping,
            });
        }
        #[cfg(target_os = "macos")]
        {
            let allocation = plan.allocation;
            let (entry, offset) = mac::publish(code.bytes(), code.entry_offset(), plan)?;
            return Ok(Self {
                entry,
                entry_pc: code.entry_pc(),
                max_pc: code.max_pc(),
                register_count: code.register_count(),
                allocation,
                offset,
            });
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = plan;
            Err(NativeError::Unsupported("此平台不支援原生碼頁面"))
        }
    }

    pub(crate) fn execute(&self, state: &mut NativeState<'_>) -> Result<NativeExit, NativeError> {
        abi::call_entry(
            self.entry,
            state,
            self.entry_pc,
            self.max_pc,
            self.register_count,
        )
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        #[cfg(target_os = "macos")]
        {
            mac::reserved_bytes()
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.allocation
        }
    }

    pub(crate) fn metadata_bytes(&self) -> usize {
        #[cfg(target_os = "macos")]
        {
            core::mem::size_of::<Self>() + mac::metadata_bytes()
        }
        #[cfg(not(target_os = "macos"))]
        {
            core::mem::size_of::<Self>()
        }
    }
}

impl Drop for ExecutableCode {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        // SAFETY: 映射由此物件獨占，&self 執行借用阻止它在呼叫期間被釋放。
        unsafe {
            libc::munmap(self.mapping.as_ptr(), self.allocation);
        }
        #[cfg(target_os = "macos")]
        mac::release(self.offset, self.allocation);
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{NativeError, PagePlan};
    use core::ptr::NonNull;
    use std::sync::{Mutex, OnceLock};

    const ALLOW_JIT: &[u8] = b"com.apple.security.cs.allow-jit\0";
    const JIT_WRITE_ALLOWLIST: &[u8] = b"com.apple.security.cs.jit-write-allowlist\0";
    const UTF8: u32 = 0x0800_0100;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecTaskCreateFromSelf(allocator: *const libc::c_void) -> *const libc::c_void;
        fn SecTaskCopyValueForEntitlement(
            task: *const libc::c_void,
            entitlement: *const libc::c_void,
            error: *mut *const libc::c_void,
        ) -> *const libc::c_void;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            allocator: *const libc::c_void,
            text: *const libc::c_char,
            encoding: u32,
        ) -> *const libc::c_void;
        fn CFGetTypeID(value: *const libc::c_void) -> usize;
        fn CFBooleanGetTypeID() -> usize;
        fn CFBooleanGetValue(value: *const libc::c_void) -> u8;
        fn CFRelease(value: *const libc::c_void);
    }
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
    }

    struct CfOwned(*const libc::c_void);
    impl Drop for CfOwned {
        fn drop(&mut self) {
            // SAFETY: 僅持有 Create/Copy 規則取得且非空的 CoreFoundation 參照。
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn entitlement(task: *const libc::c_void, name: &[u8]) -> Option<bool> {
        // SAFETY: name 是零結尾 ASCII，CoreFoundation 與 Security API 不保留借用指標。
        let key = CfOwned(unsafe {
            CFStringCreateWithCString(core::ptr::null(), name.as_ptr().cast(), UTF8)
        });
        if key.0.is_null() {
            return None;
        }
        let mut error = core::ptr::null();
        // SAFETY: task/key 在呼叫期間有效；回傳值遵守 Copy 規則。
        let raw = unsafe { SecTaskCopyValueForEntitlement(task, key.0, &mut error) };
        if !error.is_null() {
            // SAFETY: 非空 error 為 Security API 傳出的 CFErrorRef。
            unsafe { CFRelease(error) };
            if !raw.is_null() {
                unsafe { CFRelease(raw) }
            };
            return None;
        }
        if raw.is_null() {
            return Some(false);
        }
        let value = CfOwned(raw);
        // SAFETY: 比對型別後才從 CFBoolean 讀取值。
        if unsafe { CFGetTypeID(value.0) } != unsafe { CFBooleanGetTypeID() } {
            return None;
        }
        Some(unsafe { CFBooleanGetValue(value.0) != 0 })
    }

    pub(super) fn preflight() -> Result<(), NativeError> {
        // SAFETY: 查詢目前程序實際簽章 entitlement，不呼叫任何外部工具。
        let task = CfOwned(unsafe { SecTaskCreateFromSelf(core::ptr::null()) });
        if task.0.is_null() || entitlement(task.0, ALLOW_JIT) != Some(true) {
            return Err(NativeError::Unsupported(
                "目前程序沒有可確認的 allow-jit entitlement",
            ));
        }
        if entitlement(task.0, JIT_WRITE_ALLOWLIST) != Some(false) {
            return Err(NativeError::Unsupported("JIT 寫入保護能力不可確認"));
        }
        // SAFETY: 此 Apple API 僅查詢目前執行緒的 MAP_JIT 寫入保護支援。
        if unsafe { libc::pthread_jit_write_protect_supported_np() } == 0 {
            return Err(NativeError::Unsupported("目前平台沒有 JIT 寫入保護"));
        }
        Ok(())
    }

    pub(super) struct Arena {
        base: Option<NonNull<u8>>,
        capacity: usize,
        free: Vec<(usize, usize)>,
        live: usize,
    }

    // SAFETY: 原始映射僅在 Mutex 內分配／退役；每個活躍 lease 由 ExecutableCode 擁有。
    unsafe impl Send for Arena {}

    fn arena() -> &'static Mutex<Arena> {
        static ARENA: OnceLock<Mutex<Arena>> = OnceLock::new();
        ARENA.get_or_init(|| {
            Mutex::new(Arena {
                base: None,
                capacity: 0,
                free: Vec::new(),
                live: 0,
            })
        })
    }

    pub(super) fn check_existing_capacity(limit: usize) -> Result<(), NativeError> {
        let guard = arena().lock().map_err(|_| NativeError::ProtectionFailed)?;
        if guard.base.is_some() && guard.capacity > limit {
            return Err(NativeError::Unsupported("現有 MAP_JIT arena 超出本次配額"));
        }
        Ok(())
    }

    pub(super) fn reserved_bytes() -> usize {
        let guard = arena().lock().unwrap_or_else(|poison| poison.into_inner());
        guard.capacity
    }

    pub(super) fn metadata_bytes() -> usize {
        let guard = arena().lock().unwrap_or_else(|poison| poison.into_inner());
        core::mem::size_of::<OnceLock<Mutex<Arena>>>()
            + guard.free.capacity() * core::mem::size_of::<(usize, usize)>()
    }

    struct WriteWindow;
    impl WriteWindow {
        fn open() -> Self {
            // SAFETY: preflight 已確認執行緒支援；僅本執行緒暫時開啟既有 MAP_JIT 頁面寫入。
            unsafe { libc::pthread_jit_write_protect_np(0) };
            Self
        }
    }
    impl Drop for WriteWindow {
        fn drop(&mut self) {
            // SAFETY: 關閉本執行緒的 MAP_JIT 寫入視窗，包含 panic 清理路徑。
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }
    }

    pub(super) fn publish(
        bytes: &[u8],
        entry_offset: usize,
        plan: PagePlan,
    ) -> Result<(*const u8, usize), NativeError> {
        let mut arena = arena().lock().map_err(|_| NativeError::ProtectionFailed)?;
        if arena.base.is_none() {
            let page = super::page_size()?;
            arena
                .free
                .try_reserve_exact(plan.capacity / page + 1)
                .map_err(|_| NativeError::AllocationFailed)?;
            // 事前 RAM 預算以此上界計費；allocator 若給更多容量就不能發布映射。
            if arena.free.capacity() > plan.capacity / page + 1 {
                arena.free = Vec::new();
                return Err(NativeError::AllocationFailed);
            }
            // SAFETY: quota/頁面對齊已檢查；MAP_JIT 映射只在這個 arena 建立一次。
            let raw = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    plan.capacity,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            if raw == libc::MAP_FAILED {
                arena.free = Vec::new();
                return Err(NativeError::AllocationFailed);
            }
            let Some(base) = NonNull::new(raw.cast::<u8>()) else {
                unsafe { libc::munmap(raw, plan.capacity) };
                arena.free = Vec::new();
                return Err(NativeError::AllocationFailed);
            };
            arena.base = Some(base);
            arena.capacity = plan.capacity;
            arena.free.push((0, plan.capacity));
        }
        if arena.capacity > plan.capacity {
            return Err(NativeError::Unsupported("現有 MAP_JIT arena 超出本次配額"));
        }
        let index = arena
            .free
            .iter()
            .position(|&(_, len)| len >= plan.allocation)
            .ok_or(NativeError::AllocationFailed)?;
        let (offset, len) = arena.free[index];
        if len == plan.allocation {
            arena.free.remove(index);
        } else {
            arena.free[index] = (offset + plan.allocation, len - plan.allocation);
        }
        let base = arena.base.expect("映射已建立");
        // SAFETY: free list 保證 [offset, offset+allocation) 落於有效映射且沒有重疊 lease。
        let destination = unsafe { base.as_ptr().add(offset) };
        {
            let _window = WriteWindow::open();
            // SAFETY: 來源及目的長度已驗證，且本執行緒的 MAP_JIT 寫入視窗已開啟。
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
        }
        // SAFETY: 寫入視窗已關閉，發布前同步完整實際程式碼範圍的指令快取。
        unsafe { sys_icache_invalidate(destination.cast(), bytes.len()) };
        arena.live += 1;
        // SAFETY: entry_offset 已在 page_plan 驗證小於 bytes.len()。
        Ok((
            unsafe { destination.add(entry_offset).cast_const() },
            offset,
        ))
    }

    pub(super) fn release(offset: usize, len: usize) {
        let mut arena = arena().lock().unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(arena.live > 0);
        arena.live -= 1;
        if arena.live == 0 {
            if let Some(base) = arena.base.take() {
                // SAFETY: 所有 lease 已退役；此映射不再有可執行借用。
                unsafe { libc::munmap(base.as_ptr().cast(), arena.capacity) };
            }
            arena.capacity = 0;
            arena.free = Vec::new();
            return;
        }
        // 容量在 arena 建立時已預留足夠頁數，退役路徑不需要配置。
        arena.free.push((offset, len));
        arena.free.sort_unstable_by_key(|range| range.0);
        // 以原有預留緩衝區原地合併，避免 Drop 時額外配置。
        let mut write = 0;
        for read in 0..arena.free.len() {
            let (start, size) = arena.free[read];
            if write > 0 && arena.free[write - 1].0 + arena.free[write - 1].1 == start {
                arena.free[write - 1].1 += size;
            } else {
                arena.free[write] = (start, size);
                write += 1;
            }
        }
        arena.free.truncate(write);
    }
}
