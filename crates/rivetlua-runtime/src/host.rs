//! 每個 VM 明確注入的宿主能力。

use crate::rust_alloc::boxed::Box;
use crate::rust_alloc::vec::Vec;

use rivetlua_alloc::{ErasedThinBlock, StateAllocator};
use rivetlua_core::{LuaProfile, VerifiedModule, VerifyLimits};

use crate::VmError;
use crate::alloc::{AllocationCharges, AllocationLedger};
use crate::policy::{ExportPolicy, OutputBudget, PolicyCapabilities, PolicyClock, VmPolicy};
use rivetlua_core::VmId;

#[doc(hidden)]
pub use crate::stdlib::package::LoadBuffer as HostLoadSource;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLoadErrorKind {
    PolicyDenied,
    Failed,
    Compile,
    Budget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLoadError {
    pub kind: HostLoadErrorKind,
    pub diagnostic: Vec<u8>,
}

pub(crate) enum LoadServiceError {
    PolicyDenied,
    Host(HostLoadError),
}

impl HostLoadError {
    pub fn new(kind: HostLoadErrorKind, diagnostic: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            diagnostic: diagnostic.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadLimits {
    pub max_source_bytes: usize,
    pub max_encoded_bytes: usize,
    pub max_module_allocation_bytes: usize,
    pub max_temporary_bytes: usize,
    pub max_work_units: usize,
    pub max_reader_chunks: usize,
    pub max_path_candidates: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024,
            max_encoded_bytes: 4 * 1024 * 1024,
            max_module_allocation_bytes: 8 * 1024 * 1024,
            max_temporary_bytes: 1024 * 1024,
            // Lua 5.5 的獨立 global 名稱預付後，短來源仍須能在預設額度內編譯。
            max_work_units: 128 * 1024,
            max_reader_chunks: 256,
            max_path_candidates: 256,
        }
    }
}

/// 宿主 callback 必須在每段工作與暫存配置前扣除額度。
/// compiler 與 reader 都逐筆扣除 fuel 與 ledger 的額度。
/// 任一扣除失敗會持續記錄，callback 即使吞掉錯誤也不能回傳成功結果。
pub struct LoadBudget<'a> {
    state: LoadBudgetState,
    fuel: &'a mut u64,
    finalizer_steps: &'a mut u64,
    finalizer_running: bool,
}

pub(crate) struct LoadBudgetState {
    work_left: usize,
    temporary_left: usize,
    temporary_claimed: usize,
    module_allocation_limit: usize,
    module_claimed: usize,
    ledger: AllocationLedger,
    temporary_charge: AllocationCharges,
    module_charge: AllocationCharges,
    stop: Option<LoadBudgetStop>,
}

pub(crate) struct LoadTemporaryCharge {
    charges: AllocationCharges,
}

impl LoadTemporaryCharge {
    pub(crate) fn charges_mut(&mut self) -> &mut AllocationCharges {
        &mut self.charges
    }

    pub(crate) fn absorb(&mut self, other: &mut Self) -> Result<(), VmError> {
        self.charges.try_absorb(&mut other.charges)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoadBudgetStop {
    Limit,
    Fuel,
    Allocation(VmError),
    Terminal,
}

impl<'a> LoadBudget<'a> {
    pub(crate) fn resume(
        state: LoadBudgetState,
        fuel: &'a mut u64,
        finalizer_steps: &'a mut u64,
        finalizer_running: bool,
    ) -> Self {
        Self { state, fuel, finalizer_steps, finalizer_running }
    }

    pub(crate) fn into_state(self) -> LoadBudgetState {
        self.state
    }

    pub(crate) fn metered(
        work: usize,
        temporary: usize,
        fuel: &'a mut u64,
        finalizer_steps: &'a mut u64,
        finalizer_running: bool,
        ledger: AllocationLedger,
    ) -> Self {
        Self {
            state: LoadBudgetState::metered(work, temporary, ledger),
            fuel,
            finalizer_steps,
            finalizer_running,
        }
    }

    pub(crate) fn stop(&self) -> Option<LoadBudgetStop> {
        self.state.stop()
    }

    pub(crate) fn claimed_temporary(&self) -> usize {
        self.state.claimed_temporary()
    }

    pub(crate) fn take_temporary_charge(&mut self) -> Option<LoadTemporaryCharge> {
        Some(self.state.take_temporary_charge())
    }

    pub(crate) fn with_module_limit(mut self, limit: usize) -> Self {
        self.state = self.state.with_module_limit(limit);
        self
    }

    pub(crate) fn module_claimed(&self) -> usize {
        self.state.module_claimed()
    }

    pub(crate) fn take_module_charge(&mut self) -> Option<LoadTemporaryCharge> {
        Some(self.state.take_module_charge())
    }

    pub fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        self.state.claim_module_allocation(bytes)
    }

    #[doc(hidden)]
    pub fn record_allocator_failure(&mut self, error: VmError) -> HostLoadError {
        self.state.record_allocator_failure(error)
    }

    #[doc(hidden)]
    pub fn record_source_limit_failure(&mut self) -> HostLoadError {
        self.state.fail(LoadBudgetStop::Limit)
    }

    pub fn spend_work(&mut self, units: usize) -> Result<(), HostLoadError> {
        self.state.spend_work(
            units,
            &mut *self.fuel,
            &mut *self.finalizer_steps,
            self.finalizer_running,
        )
    }

    pub fn claim_temporary(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        self.state.claim_temporary(bytes)
    }

    #[doc(hidden)]
    pub fn compile_diagnostic(
        &mut self, chunkname: &[u8], line: usize, message: &[u8],
    ) -> Result<HostLoadError, HostLoadError> {
        let name = match chunkname.first() {
            Some(&b'=') | Some(&b'@') => &chunkname[1..],
            _ => chunkname,
        };
        let mut digits = [0u8; 40];
        let mut remaining = line;
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 { break; }
        }
        let line_bytes = &digits[start..];
        let needed = name.len().checked_add(line_bytes.len())
            .and_then(|value| value.checked_add(message.len()))
            .and_then(|value| value.checked_add(3))
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
        self.spend_work(needed.checked_add(1)
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?)?;
        self.claim_temporary(needed)?;
        let mut diagnostic = Vec::new();
        diagnostic.try_reserve_exact(needed)
            .map_err(|_| self.record_allocator_failure(VmError::AllocationFailed))?;
        if diagnostic.capacity() > needed {
            self.claim_temporary(diagnostic.capacity() - needed)?;
        }
        diagnostic.extend_from_slice(name);
        diagnostic.push(b':');
        diagnostic.extend_from_slice(line_bytes);
        diagnostic.extend_from_slice(b": ");
        diagnostic.extend_from_slice(message);
        Ok(HostLoadError::new(HostLoadErrorKind::Compile, diagnostic))
    }

    pub const fn module_allocation_limit(&self) -> usize {
        self.state.module_allocation_limit()
    }
}

impl LoadBudgetState {
    pub(crate) fn metered(work: usize, temporary: usize, ledger: AllocationLedger) -> Self {
        let allocator = ledger.backing_allocator();
        Self {
            work_left: work,
            temporary_left: temporary,
            temporary_claimed: 0,
            module_allocation_limit: 0,
            module_claimed: 0,
            ledger,
            temporary_charge: AllocationCharges::new_in(allocator.clone()),
            module_charge: AllocationCharges::new_in(allocator),
            stop: None,
        }
    }

    pub(crate) fn with_module_limit(mut self, limit: usize) -> Self {
        self.module_allocation_limit = limit;
        self
    }

    pub(crate) fn stop(&self) -> Option<LoadBudgetStop> {
        self.stop
    }

    pub(crate) fn claimed_temporary(&self) -> usize {
        self.temporary_claimed
    }

    pub(crate) fn take_temporary_charge(&mut self) -> LoadTemporaryCharge {
        LoadTemporaryCharge {
            charges: self.temporary_charge.take_preserving_allocator(),
        }
    }

    pub(crate) fn module_claimed(&self) -> usize {
        self.module_claimed
    }

    pub(crate) fn take_module_charge(&mut self) -> LoadTemporaryCharge {
        LoadTemporaryCharge {
            charges: self.module_charge.take_preserving_allocator(),
        }
    }

    pub(crate) fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(claimed) = self.module_claimed.checked_add(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        if claimed > self.module_allocation_limit {
            return Err(self.fail(LoadBudgetStop::Limit));
        }
        if bytes != 0 {
            let reservation = match self.ledger.reserve(bytes) {
                Ok(reservation) => reservation,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            let charge = match reservation.commit_charge() {
                Ok(charge) => charge,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            if let Err((error, charge)) = self.module_charge.try_push(charge) {
                drop(charge);
                return Err(self.fail(LoadBudgetStop::Allocation(error)));
            }
        }
        self.module_claimed = claimed;
        Ok(())
    }

    fn fail(&mut self, stop: LoadBudgetStop) -> HostLoadError {
        self.stop.get_or_insert(stop);
        HostLoadError::new(HostLoadErrorKind::Budget, Vec::new())
    }

    pub(crate) fn record_allocator_failure(&mut self, error: VmError) -> HostLoadError {
        self.fail(LoadBudgetStop::Allocation(error))
    }

    pub(crate) fn record_source_limit_failure(&mut self) -> HostLoadError {
        self.fail(LoadBudgetStop::Limit)
    }

    pub(crate) fn spend_work(
        &mut self,
        units: usize,
        fuel: &mut u64,
        finalizer_steps: &mut u64,
        finalizer_running: bool,
    ) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(remaining) = self.work_left.checked_sub(units) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        let cost = u64::try_from(units).unwrap_or(u64::MAX);
        if finalizer_running {
            *finalizer_steps = finalizer_steps.saturating_add(cost);
            if *finalizer_steps > 1_000_000 {
                return Err(self.fail(LoadBudgetStop::Terminal));
            }
        } else if *fuel < cost {
            *fuel = 0;
            return Err(self.fail(LoadBudgetStop::Fuel));
        } else {
            *fuel -= cost;
        }
        self.work_left = remaining;
        Ok(())
    }

    pub(crate) fn claim_temporary(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(remaining) = self.temporary_left.checked_sub(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        let Some(claimed) = self.temporary_claimed.checked_add(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        if bytes != 0 {
            let reservation = match self.ledger.reserve(bytes) {
                Ok(reservation) => reservation,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            let charge = match reservation.commit_charge() {
                Ok(charge) => charge,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            if let Err((error, charge)) = self.temporary_charge.try_push(charge) {
                drop(charge);
                return Err(self.fail(LoadBudgetStop::Allocation(error)));
            }
        }
        self.temporary_left = remaining;
        self.temporary_claimed = claimed;
        Ok(())
    }

    pub(crate) const fn module_allocation_limit(&self) -> usize {
        self.module_allocation_limit
    }
}

pub struct HostLoadJobContext<'a, 'b> {
    pub source: &'a mut HostLoadSource,
    pub budget: &'a mut LoadBudget<'b>,
    pub allocator: StateAllocator,
    pub recover: &'a mut dyn FnMut(u64) -> Result<bool, VmError>,
    pub profile: LuaProfile,
    pub max_source_bytes: usize,
}

pub enum HostLoadProgress {
    NeedInput { minimum_total: usize },
    Complete(VerifiedModule),
}

pub struct HostLoadAdvance {
    pub consumed: usize,
    pub progress: HostLoadProgress,
}

pub trait HostLoadJobDriver: core::any::Any {
    fn advance(
        &mut self, available: &[u8], eof: bool, chunkname: &[u8],
        context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<HostLoadAdvance, HostLoadError>;
    fn consumed_total(&self) -> usize;
}

type HostLoadAdvanceFn = fn(
    &mut ErasedThinBlock, &[u8], bool, &[u8], &mut HostLoadJobContext<'_, '_>, &mut usize,
) -> Result<HostLoadAdvance, HostLoadError>;

pub struct HostLoadJob {
    state: ErasedThinBlock,
    advance: HostLoadAdvanceFn,
    consumed_total: usize,
}

impl HostLoadJob {
    pub fn new<T: HostLoadJobDriver>(
        state: T, context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<Self, HostLoadError> {
        let size = StateAllocator::thin_block_size::<T>();
        context.budget.claim_temporary(size)?;
        let allocator = context.allocator.clone();
        let before = allocator.refusal_count();
        let uninit = match allocator.clone().thin_uninit::<T>(0) {
            Ok(block) => block,
            Err(_) if allocator.is_lua() && allocator.refusal_count() != before => {
                let recovered = (context.recover)(before)
                    .map_err(|error| context.budget.record_allocator_failure(error))?;
                if !recovered {
                    return Err(context.budget.record_allocator_failure(VmError::AllocationFailed));
                }
                allocator.thin_uninit::<T>(0)
                    .map_err(|_| context.budget.record_allocator_failure(VmError::AllocationFailed))?
            }
            Err(_) => return Err(context.budget.record_allocator_failure(VmError::AllocationFailed)),
        };
        Ok(Self {
            state: ErasedThinBlock::from_block(uninit.write(state)),
            advance: Self::advance_typed::<T>,
            consumed_total: 0,
        })
    }

    pub fn advance(
        &mut self, available: &[u8], eof: bool, chunkname: &[u8],
        context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<HostLoadAdvance, HostLoadError> {
        (self.advance)(&mut self.state, available, eof, chunkname, context, &mut self.consumed_total)
    }

    pub fn consumed_total(&self) -> usize { self.consumed_total }

    fn advance_typed<T: HostLoadJobDriver>(
        state: &mut ErasedThinBlock, available: &[u8], eof: bool, chunkname: &[u8],
        context: &mut HostLoadJobContext<'_, '_>, consumed_total: &mut usize,
    ) -> Result<HostLoadAdvance, HostLoadError> {
        let Some(state) = state.downcast_mut::<T>() else {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        };
        let result = state.advance(available, eof, chunkname, context);
        *consumed_total = state.consumed_total();
        result
    }
}

pub trait HostLoadCompiler {
    fn begin_reader(
        &mut self, _context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<Option<HostLoadJob>, HostLoadError> {
        Ok(None)
    }

    /// 輸出 VerifiedModule 前，應依 `module_allocation_limit` 控制保留配置；
    /// compiler 的每段工作與暫存配置須先呼叫 budget，VM 再核對實際 nested 容量。
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError>;

    /// 既有宿主編譯器仍沿用 compile；需要 C state 實體 backing 者覆寫此入口。
    fn compile_with_recovery(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
        _allocator: StateAllocator,
        _recover: &mut dyn FnMut(u64) -> Result<bool, VmError>,
    ) -> Result<VerifiedModule, HostLoadError> {
        self.compile(source, chunkname, profile, budget)
    }
}

pub trait HostSourceReader {
    /// 建立回傳 Vec 前先逐筆 claim_temporary，回傳的 capacity 不得超過申報總量。
    /// 錯誤 diagnostic Vec 也遵守相同規則，VM 在複製完成前持續保留原 buffer 費用。
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError>;

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadFormat {
    Source,
    RivetBytecode,
    OfficialBytecode,
}

pub struct HostModuleBytes {
    pub data: Vec<u8>,
    pub loader_data: Vec<u8>,
    pub format: LoadFormat,
}

pub trait HostModuleRepository {
    /// 回傳的 data 與 loader_data 皆須在配置前向 budget 申報合計 capacity。
    /// 每個候選路徑由 VM 獨立呼叫；無匹配回傳 None。
    fn search(
        &mut self,
        modname: &[u8],
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError>;

    /// 僅判定候選路徑是否可讀；既有宿主預設沿用完整搜尋的結果。
    fn readable(
        &mut self,
        modname: &[u8],
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<bool, HostLoadError> {
        let Some(found) = self.search(modname, path, budget)? else {
            return Ok(false);
        };
        let reported = found
            .data
            .capacity()
            .checked_add(found.loader_data.capacity())
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
        if reported > budget.claimed_temporary() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        Ok(true)
    }
}

pub struct HostNativeModule {
    pub module: VerifiedModule,
    pub loader_data: Vec<u8>,
}

/// Runtime 只停放請求；宿主在 execution drop 後驗 grant 並以同 VM 續接。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForeignNativeKind {
    LoadLib,
    Searcher,
    RootSearcher,
}

/// 純 Rust 封閉服務；runtime 不開啟動態函式庫，也不使用 FFI。
pub trait HostNativeLoader {
    /// VerifiedModule 的巢狀配置不得超過 budget.module_allocation_limit；
    /// loader_data 配置前須申報 temporary capacity。
    fn search(
        &mut self,
        modname: &[u8],
        root: bool,
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostNativeModule>, HostLoadError>;
}

pub struct LoadCapability {
    pub(crate) compiler: Option<Box<dyn HostLoadCompiler>>,
    pub(crate) reader: Option<Box<dyn HostSourceReader>>,
    pub(crate) repository: Option<Box<dyn HostModuleRepository>>,
    pub(crate) native: Option<Box<dyn HostNativeLoader>>,
    pub(crate) foreign_native_cpath: Option<Vec<u8>>,
    pub(crate) allow_bytecode: bool,
    pub(crate) allow_official_bytecode: bool,
    pub(crate) limits: LoadLimits,
    pub(crate) limits_explicit: bool,
    pub(crate) verify_limits: VerifyLimits,
    pub(crate) verify_limits_explicit: bool,
}

impl Default for LoadCapability {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl LoadCapability {
    pub fn deny_all() -> Self {
        Self {
            compiler: None,
            reader: None,
            repository: None,
            native: None,
            foreign_native_cpath: None,
            allow_bytecode: false,
            allow_official_bytecode: false,
            limits: LoadLimits::default(),
            limits_explicit: false,
            verify_limits: VerifyLimits::default(),
            verify_limits_explicit: false,
        }
    }

    pub fn and_compiler(mut self, compiler: impl HostLoadCompiler + 'static) -> Self {
        self.compiler = Some(Box::new(compiler));
        self
    }

    pub fn and_reader(mut self, reader: impl HostSourceReader + 'static) -> Self {
        self.reader = Some(Box::new(reader));
        self
    }

    pub fn and_repository(mut self, repository: impl HostModuleRepository + 'static) -> Self {
        self.repository = Some(Box::new(repository));
        self
    }

    pub fn and_native_loader(mut self, native: impl HostNativeLoader + 'static) -> Self {
        self.native = Some(Box::new(native));
        self
    }

    /// 僅註冊同 VM foreign opener 的 opaque parked request；實際載入仍須宿主票據。
    pub fn with_foreign_native_cpath(mut self, initial_cpath: Vec<u8>) -> Self {
        self.foreign_native_cpath = Some(initial_cpath);
        self
    }

    pub fn with_bytecode(mut self, allow: bool) -> Self {
        self.allow_bytecode = allow;
        self
    }

    pub fn with_official_bytecode(mut self, allow: bool) -> Self {
        self.allow_official_bytecode = allow;
        self
    }

    pub fn with_limits(mut self, limits: LoadLimits) -> Self {
        self.limits = limits;
        self.limits_explicit = true;
        self
    }

    #[doc(hidden)]
    pub fn with_capi_compatibility_limits(mut self, limits: LoadLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_verify_limits(mut self, limits: VerifyLimits) -> Self {
        self.verify_limits = limits;
        self.verify_limits_explicit = true;
        self
    }
}

/// `string.dump` 的上限准入：呼叫前須預扣完整工作與暫存上限，
/// 結束後依實際工作量退還未用額度。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DumpLimits {
    pub max_work_units: usize,
    pub max_temporary_bytes: usize,
    pub max_encoded_bytes: usize,
}

impl Default for DumpLimits {
    fn default() -> Self {
        Self {
            max_work_units: 200_000,
            max_temporary_bytes: 4 * 1024 * 1024,
            max_encoded_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DumpCapability {
    pub(crate) allowed: bool,
    pub(crate) limits: DumpLimits,
    pub(crate) limits_explicit: bool,
}

impl Default for DumpCapability {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl DumpCapability {
    pub fn deny_all() -> Self {
        Self {
            allowed: false,
            limits: DumpLimits::default(),
            limits_explicit: false,
        }
    }

    /// 獨立允許官方 bytecode 輸出；不變更載入權限。
    pub fn with_official_bytecode(mut self, allow: bool) -> Self {
        self.allowed = allow;
        self
    }

    /// 設定預扣上限；成功或錯誤時只保留本次實際耗用的工作額度。
    pub fn with_limits(mut self, limits: DumpLimits) -> Self {
        self.limits = limits;
        self.limits_explicit = true;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOutputError {
    WriteFailed,
}

pub trait HostOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError>;

    fn flush(&mut self) -> Result<(), HostOutputError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostWarningError {
    WriteFailed,
    OutputLimit,
}

/// 純 Rust 宿主的 warning 端點；C native session 使用獨立的 lua_warning 橋接。
pub trait HostWarning {
    fn write(&mut self, message: &[u8], tocont: bool) -> Result<(), HostWarningError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEntropyError {
    ReadFailed,
}

pub trait HostEntropy {
    fn seed(&mut self) -> Result<u64, HostEntropyError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
/// 各權限只開啟下列受限操作；缺少可靠 RVLU metadata 的選項仍拒絕。
pub enum DebugPermission {
    /// 查詢已驗證的函式來源、行號、參數與身分資料。
    Info,
    /// 查詢目前執行緒的數值 stack level 與實際呼叫位置。
    StackInspection,
    /// 查詢已驗證 native local、參數與暫停中協程的 frame/vararg。
    LocalInspection,
    /// 修改已驗證 native local 或 vararg，維持 frame root 與協程 GC 強邊。
    LocalMutation,
    /// 修改 closure 的 open/closed upvalue，沿用 frame root 與 GC barrier。
    UpvalueMutation,
    /// 查詢或改接 closure 共享的 upvalue 物件身分。
    UpvalueIdentity,
    /// 讀取 VM 專屬、由 root 保護的 guest-owned 相容 registry。
    RegistryRead,
    /// 讀取 File userdata；因無 uservalue 槽而回傳 nil。
    UserValueRead,
    /// 嘗試修改 File userdata；因無 uservalue 槽而回傳 nil。
    UserValueWrite,
    /// `getupvalue` 只讀取無獨立 environment 的 closure 捕捉值；
    /// 名稱固定為 `(no name)`，其餘明確拒絕。
    Upvalues,
    /// 只輸出帶 prototype/PC 的即時 RVLU Lua frame。
    Traceback,
    /// 開啟 instruction-count hook；hook 自身 yield 拒絕。
    /// 任一 hook callback 執行期間會抑制整個 VM 的巢狀 hook；其他 coroutine 仍可 yield。
    CountHook,
    /// 開啟已驗證來源行號的 line hook 與 call/return hook。
    EventHook,
    /// 只讀取目前可驗證的 table/file/string metatable。
    MetatableRead,
    /// 允許 table 與一般 userdata 各自的 metatable 設定，沿既有 write barrier。
    TableMetatableWrite,
    /// 受信任宿主明示允許透過既有標準 I/O 在同一 VM 執行 Lua 偵錯命令。
    Console,
    /// 讀取非 table／userdata 值依型別共用的 metatable。
    TypeMetatableRead,
    /// 修改非 table／userdata 值依型別共用的 metatable。
    TypeMetatableWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebugLimits {
    pub max_frames: usize,
    pub max_trace_bytes: usize,
    pub max_work_units: usize,
    pub max_hook_count: usize,
}

impl Default for DebugLimits {
    fn default() -> Self {
        Self {
            max_frames: 64,
            max_trace_bytes: 16 * 1024,
            max_work_units: 100_000,
            max_hook_count: (1 << 24) - 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// 預設全部拒絕；`allow` 只解除相應受限操作的 host policy。
pub struct DebugCapability {
    permissions: u32,
    limits: DebugLimits,
}

impl DebugCapability {
    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn allow(mut self, permission: DebugPermission) -> Self {
        self.permissions |= 1_u32 << permission as u8;
        self
    }

    pub fn with_limits(mut self, limits: DebugLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn allows(self, permission: DebugPermission) -> bool {
        self.permissions & (1_u32 << permission as u8) != 0
    }

    pub(crate) fn limits(self) -> DebugLimits {
        self.limits
    }
}

#[derive(Default)]
pub struct HostServices {
    output: Option<Box<dyn HostOutput>>,
    warning: Option<Box<dyn HostWarning>>,
    entropy: Option<Box<dyn HostEntropy>>,
    pub(crate) load: LoadCapability,
    pub(crate) resource: ResourceCapability,
    pub(crate) debug: DebugCapability,
    pub(crate) dump: DumpCapability,
    policy: VmPolicy,
    policy_capabilities: Option<PolicyCapabilities>,
    policy_clock: Option<Box<dyn PolicyClock>>,
    output_budget: Option<OutputBudget>,
    export_policy: ExportPolicy,
    pub(crate) initial_package_path: Option<Vec<u8>>,
}

impl HostServices {
    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn with_output(output: impl HostOutput + 'static) -> Self {
        Self::deny_all().and_output(output)
    }

    pub fn with_entropy(entropy: impl HostEntropy + 'static) -> Self {
        Self::deny_all().and_entropy(entropy)
    }

    pub fn and_output(mut self, output: impl HostOutput + 'static) -> Self {
        self.output = Some(Box::new(output));
        self
    }

    pub fn and_warning(mut self, warning: impl HostWarning + 'static) -> Self {
        self.warning = Some(Box::new(warning));
        self
    }

    pub fn and_entropy(mut self, entropy: impl HostEntropy + 'static) -> Self {
        self.entropy = Some(Box::new(entropy));
        self
    }

    pub fn and_load(mut self, load: LoadCapability) -> Self {
        self.load = load;
        self
    }

    pub fn with_package_path(mut self, path: Vec<u8>) -> Self {
        self.initial_package_path = Some(path);
        self
    }

    pub fn and_resource(mut self, resource: ResourceCapability) -> Self {
        self.resource = resource;
        self
    }

    pub fn and_debug(mut self, debug: DebugCapability) -> Self {
        self.debug = debug;
        self
    }

    pub fn and_dump(mut self, dump: DumpCapability) -> Self {
        self.dump = dump;
        self
    }

    pub fn and_policy(mut self, policy: VmPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn and_policy_capabilities(mut self, capabilities: PolicyCapabilities) -> Self {
        self.policy_capabilities = Some(capabilities);
        self
    }

    pub fn and_policy_clock(mut self, clock: impl PolicyClock + 'static) -> Self {
        self.policy_clock = Some(Box::new(clock));
        self
    }

    pub fn and_output_budget(mut self, budget: OutputBudget) -> Self {
        self.output_budget = Some(budget);
        self
    }

    pub fn and_export_policy(mut self, policy: ExportPolicy) -> Self {
        self.export_policy = policy;
        self
    }

    pub fn policy(&self) -> VmPolicy {
        self.policy
    }

    pub(crate) fn effective_output_budget(&self) -> OutputBudget {
        self.output_budget.unwrap_or_else(|| {
            if self.policy == VmPolicy::Compatibility {
                OutputBudget::unlimited()
            } else {
                OutputBudget::default()
            }
        })
    }

    pub(crate) fn explicit_output_budget(&self) -> bool {
        self.output_budget.is_some()
    }

    pub(crate) fn export_policy(&self) -> ExportPolicy {
        self.export_policy
    }

    pub(crate) fn apply_policy_restrictions(&mut self) {
        if self.policy == VmPolicy::Compatibility {
            return;
        }
        self.debug = DebugCapability::deny_all();
        self.dump = DumpCapability::deny_all();
        self.load.native = None;
        self.load.foreign_native_cpath = None;
        self.load.allow_bytecode = false;
        self.load.allow_official_bytecode = false;
    }

    pub(crate) fn policy_issuer(&self) -> Option<VmId> {
        self.policy_capabilities
            .as_ref()
            .map(|capabilities| capabilities.issuer)
    }

    pub(crate) fn policy_now(&self) -> Option<u64> {
        self.policy_clock.as_ref().map(|clock| clock.now())
    }

    pub(crate) fn entropy_seed(&mut self) -> Result<u64, HostEntropyServiceError> {
        let Some(entropy) = self.entropy.as_mut() else {
            return Err(HostEntropyServiceError::PolicyDenied);
        };
        entropy
            .seed()
            .map_err(|_| HostEntropyServiceError::EntropyFailed)
    }

    pub(crate) fn output(&mut self, bytes: &[u8]) -> Result<(), HostServiceError> {
        let Some(output) = self.output.as_mut() else {
            return Err(HostServiceError::PolicyDenied);
        };
        output
            .write(bytes)
            .map_err(|_| HostServiceError::OutputFailed)
    }

    pub(crate) fn output_flush(&mut self) -> Result<(), HostServiceError> {
        let Some(output) = self.output.as_mut() else {
            return Err(HostServiceError::PolicyDenied);
        };
        output.flush().map_err(|_| HostServiceError::OutputFailed)
    }

    pub(crate) fn output_allowed(&self) -> bool {
        self.output.is_some()
    }

    pub(crate) fn warning(&mut self, message: &[u8], tocont: bool) -> Result<(), HostWarningError> {
        let Some(warning) = self.warning.as_mut() else {
            return Ok(());
        };
        warning.write(message, tocont)
    }

    pub(crate) fn has_warning(&self) -> bool {
        self.warning.is_some()
    }
}



#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostServiceError {
    PolicyDenied,
    OutputFailed,
    OutputLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostEntropyServiceError {
    PolicyDenied,
    EntropyFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostResourceErrorKind {
    PolicyDenied,
    Unsupported,
    PathDenied,
    IoFailure,
    PlatformDifference,
    Cancelled,
    Deadline,
    Budget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostResourceError {
    pub kind: HostResourceErrorKind,
    pub diagnostic: Vec<u8>,
    pub io_failure: Option<HostIoFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostIoFailure {
    pub errno: i64,
    pub written: Option<usize>,
}

impl HostResourceError {
    pub fn new(kind: HostResourceErrorKind, diagnostic: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            diagnostic: diagnostic.into(),
            io_failure: None,
        }
    }

    pub fn io_failure(diagnostic: impl Into<Vec<u8>>, errno: i64) -> Self {
        Self {
            kind: HostResourceErrorKind::IoFailure,
            diagnostic: diagnostic.into(),
            io_failure: Some(HostIoFailure {
                errno,
                written: None,
            }),
        }
    }

    pub fn write_failure(diagnostic: impl Into<Vec<u8>>, errno: i64, written: usize) -> Self {
        Self {
            kind: HostResourceErrorKind::IoFailure,
            diagnostic: diagnostic.into(),
            io_failure: Some(HostIoFailure {
                errno,
                written: Some(written),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_work_units: usize,
    pub max_temporary_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEncoding {
    Utf8,
    RawBytes,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_work_units: 100_000,
            max_temporary_bytes: 1024 * 1024,
            max_retained_bytes: 1024 * 1024,
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
        }
    }
}

pub struct ResourceBudget<'a> {
    inner: LoadBudget<'a>,
}

impl<'a> ResourceBudget<'a> {
    pub(crate) fn metered(
        limits: ResourceLimits,
        fuel: &'a mut u64,
        finalizer_steps: &'a mut u64,
        finalizer_running: bool,
        ledger: AllocationLedger,
    ) -> Self {
        Self {
            inner: LoadBudget::metered(
                limits.max_work_units,
                limits.max_temporary_bytes,
                fuel,
                finalizer_steps,
                finalizer_running,
                ledger,
            )
            .with_module_limit(limits.max_retained_bytes),
        }
    }

    pub fn spend_work(&mut self, units: usize) -> Result<(), HostResourceError> {
        self.inner
            .spend_work(units)
            .map_err(|_| Self::budget_error())
    }

    pub fn claim_temporary(&mut self, bytes: usize) -> Result<(), HostResourceError> {
        self.inner
            .claim_temporary(bytes)
            .map_err(|_| Self::budget_error())
    }

    pub fn claim_retained(&mut self, bytes: usize) -> Result<(), HostResourceError> {
        self.inner
            .claim_module_allocation(bytes)
            .map_err(|_| Self::budget_error())
    }

    #[doc(hidden)]
    pub fn record_allocator_failure(&mut self, error: VmError) -> HostResourceError {
        self.inner.record_allocator_failure(error);
        Self::budget_error()
    }

    pub(crate) fn stop(&self) -> Option<LoadBudgetStop> {
        self.inner.stop()
    }
    pub(crate) fn ensure_active(&self) -> Result<(), HostResourceError> {
        if self.stop().is_some() {
            Err(Self::budget_error())
        } else {
            Ok(())
        }
    }
    pub(crate) fn claimed_temporary(&self) -> usize {
        self.inner.claimed_temporary()
    }
    pub(crate) fn claimed_retained(&self) -> usize {
        self.inner.module_claimed()
    }
    pub(crate) fn take_temporary_charge(&mut self) -> Option<LoadTemporaryCharge> {
        self.inner.take_temporary_charge()
    }
    pub(crate) fn take_retained_charge(&mut self) -> Option<LoadTemporaryCharge> {
        self.inner.take_module_charge()
    }

    fn budget_error() -> HostResourceError {
        HostResourceError::new(HostResourceErrorKind::Budget, Vec::new())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileReadFormat {
    Bytes(usize),
    Line { keep_newline: bool },
    All,
    Number,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSeekOrigin {
    Set,
    Current,
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileOperation {
    Read,
    Write,
    Seek,
    Flush,
    Close,
    SetVBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCloseResult {
    File,
    Process {
        success: bool,
        signaled: bool,
        code: i64,
    },
}

/// VM 已驗證同一 FILE* registry metatable 與最小 userdata 長度的同步檢視。
/// 原始位址僅供宿主能力在當次呼叫借用；不可保存到 lease、iterator 或 callback。
#[derive(Clone, Copy)]
pub struct NativeFileView<'a> {
    pointer: *mut core::ffi::c_void,
    len: usize,
    _borrow: core::marker::PhantomData<&'a ()>,
}

impl<'a> NativeFileView<'a> {
    pub(crate) const fn checked_userdata<T>(
        pointer: *mut core::ffi::c_void,
        len: usize,
        _owner: &'a T,
    ) -> Self {
        Self { pointer, len, _borrow: core::marker::PhantomData }
    }

    pub(crate) fn from_lease(bytes: rivetlua_alloc::BorrowedBytes<'a>) -> Self {
        Self {
            pointer: bytes.as_mut_ptr().cast(),
            len: bytes.len(),
            _borrow: core::marker::PhantomData,
        }
    }

    pub const fn pointer(self) -> *mut core::ffi::c_void {
        self.pointer
    }

    pub const fn len(self) -> usize {
        self.len
    }
}

/// 每個 lease 只屬於一個 VM file payload。`close` 消耗 Box；未 close 時由實作者的 Drop 釋放。
pub trait HostFileLease {
    /// 只有具真正 C stream 前綴的宿主 lease 提供此檢視；建構者須承擔
    /// `BorrowedBytes::from_raw_parts` 的格式、handle 與生命週期安全契約。
    fn native_userdata(&self) -> Option<rivetlua_alloc::BorrowedBytes<'_>> {
        None
    }
    /// 尚未完成 opener 的 C 前綴仍屬未關閉 userdata；IO 不可解參其空 FILE*。
    fn native_handle_open(&self) -> bool {
        true
    }
    /// 僅供顯示用途的原生 handle 數值；不在 runtime 解參照。
    fn native_handle_token(&self) -> Option<usize> {
        None
    }
    fn authorize(
        &mut self,
        operation: FileOperation,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError>;
    fn read(
        &mut self,
        format: FileReadFormat,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError>;
    /// 成功時回報完整寫入數；部分寫入須以 `HostResourceError::write_failure` 回報。
    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError>;
    fn seek(
        &mut self,
        origin: FileSeekOrigin,
        offset: i64,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError>;
    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError>;
    fn close(
        self: Box<Self>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError>;
    fn setvbuf(
        &mut self,
        _mode: &[u8],
        _size: usize,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::Unsupported,
            Vec::new(),
        ))
    }
}

pub trait HostIo {
    /// C state 建立時把其實體配置器綁定至檔案前綴；其他宿主能力不需實作。
    fn bind_state_allocator(&mut self, _allocator: StateAllocator) {}

    /// 只在同步 callback 借用 VM 已驗證的 userdata；不配置第二個 lease backing。
    fn with_native_file(
        &mut self,
        _view: NativeFileView<'_>,
        _callback: &mut dyn FnMut(&mut dyn HostFileLease),
    ) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(HostResourceErrorKind::Unsupported, Vec::new()))
    }
    fn authorize_path(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError>;
    fn open(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError>;
    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError>;
    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError>;
    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError>;
    fn tmpfile(
        &mut self,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::Unsupported,
            Vec::new(),
        ))
    }
    fn authorize_process(
        &mut self,
        _command: &[u8],
        _mode: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::PolicyDenied,
            Vec::new(),
        ))
    }
    fn popen(
        &mut self,
        _command: &[u8],
        _mode: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::Unsupported,
            Vec::new(),
        ))
    }
}

pub trait HostDeadline {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOsOperation<'a> {
    Exit(HostExitRequest),
    GetEnv(&'a [u8]),
    Clock,
    Date(&'a [u8], Option<i64>),
    Time(Option<HostCalendar>),
    Locale(Option<&'a [u8]>, Option<&'a [u8]>),
    Remove(&'a [u8]),
    Rename(&'a [u8], &'a [u8]),
    Execute(Option<&'a [u8]>),
    TmpName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCalendar {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    pub weekday: Option<i64>,
    pub year_day: Option<i64>,
    pub daylight_saving: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExitStatus {
    pub success: bool,
    pub signaled: bool,
    pub code: i64,
}

/// 宿主已授權的 Lua 終止請求；是否關閉 Lua 狀態與程序狀態碼分開保存。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExitRequest {
    pub status: i32,
    pub close: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HostOsValue {
    ExitRequest(HostExitRequest),
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    Bytes(Vec<u8>),
    Calendar(HostCalendar),
    Exit(HostExitStatus),
    Time {
        epoch: i64,
        normalized: Option<HostCalendar>,
    },
}

pub trait HostOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError>;
    fn authorize_path(
        &mut self,
        _path: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::PathDenied,
            Vec::new(),
        ))
    }
    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError>;
}

pub struct ResourceCapability {
    pub(crate) io: Option<Box<dyn HostIo>>,
    pub(crate) os: Option<Box<dyn HostOs>>,
    pub(crate) deadline: Option<Box<dyn HostDeadline>>,
    pub(crate) limits: ResourceLimits,
    pub(crate) path_encoding: PathEncoding,
}

impl Default for ResourceCapability {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl ResourceCapability {
    pub fn deny_all() -> Self {
        Self {
            io: None,
            os: None,
            deadline: None,
            limits: ResourceLimits::default(),
            path_encoding: PathEncoding::Utf8,
        }
    }
    pub fn and_io(mut self, io: impl HostIo + 'static) -> Self {
        self.io = Some(Box::new(io));
        self
    }
    pub fn and_os(mut self, os: impl HostOs + 'static) -> Self {
        self.os = Some(Box::new(os));
        self
    }
    pub fn and_deadline(mut self, deadline: impl HostDeadline + 'static) -> Self {
        self.deadline = Some(Box::new(deadline));
        self
    }
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }
    pub fn with_path_encoding(mut self, encoding: PathEncoding) -> Self {
        self.path_encoding = encoding;
        self
    }
}


