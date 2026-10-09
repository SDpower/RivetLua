//! 每個 VM 明確注入的宿主能力。

use rivetlua_core::{LuaProfile, VerifiedModule, VerifyLimits};

use crate::VmError;
use crate::alloc::{AllocationCharges, AllocationLedger};

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
            max_work_units: 100_000,
            max_reader_chunks: 256,
            max_path_candidates: 256,
        }
    }
}

/// 宿主 callback 必須在每段工作與暫存配置前扣除額度。
/// compiler 與 reader 都逐筆扣除 fuel 與 ledger 的額度。
/// 任一扣除失敗會持續記錄，callback 即使吞掉錯誤也不能回傳成功結果。
pub struct LoadBudget<'a> {
    work_left: usize,
    temporary_left: usize,
    temporary_claimed: usize,
    module_allocation_limit: usize,
    module_claimed: usize,
    meter: Option<LoadMeter<'a>>,
    stop: Option<LoadBudgetStop>,
}

struct LoadMeter<'a> {
    fuel: &'a mut u64,
    finalizer_steps: &'a mut u64,
    finalizer_running: bool,
    ledger: AllocationLedger,
    temporary_charge: AllocationCharges,
    module_charge: AllocationCharges,
}

pub(crate) struct LoadTemporaryCharge {
    charges: AllocationCharges,
}

impl LoadTemporaryCharge {
    pub(crate) fn transfer(&mut self, actual: usize) -> Result<AllocationCharges, VmError> {
        self.charges.normalize(actual)
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
    pub(crate) fn metered(
        work: usize,
        temporary: usize,
        fuel: &'a mut u64,
        finalizer_steps: &'a mut u64,
        finalizer_running: bool,
        ledger: AllocationLedger,
    ) -> Self {
        Self {
            work_left: work,
            temporary_left: temporary,
            temporary_claimed: 0,
            module_allocation_limit: 0,
            module_claimed: 0,
            meter: Some(LoadMeter {
                fuel,
                finalizer_steps,
                finalizer_running,
                ledger,
                temporary_charge: AllocationCharges::new(),
                module_charge: AllocationCharges::new(),
            }),
            stop: None,
        }
    }

    pub(crate) fn stop(&self) -> Option<LoadBudgetStop> {
        self.stop
    }

    pub(crate) fn claimed_temporary(&self) -> usize {
        self.temporary_claimed
    }

    pub(crate) fn take_temporary_charge(&mut self) -> Option<LoadTemporaryCharge> {
        self.meter.as_mut().map(|meter| LoadTemporaryCharge {
            charges: core::mem::take(&mut meter.temporary_charge),
        })
    }

    pub(crate) fn with_module_limit(mut self, limit: usize) -> Self {
        self.module_allocation_limit = limit;
        self
    }

    pub(crate) fn module_claimed(&self) -> usize {
        self.module_claimed
    }

    pub(crate) fn take_module_charge(&mut self) -> Option<LoadTemporaryCharge> {
        self.meter.as_mut().map(|meter| LoadTemporaryCharge {
            charges: core::mem::take(&mut meter.module_charge),
        })
    }

    pub fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(claimed) = self.module_claimed.checked_add(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        if claimed > self.module_allocation_limit {
            return Err(self.fail(LoadBudgetStop::Limit));
        }
        if let Some(meter) = self.meter.as_mut() {
            let reservation = match meter.ledger.reserve(bytes) {
                Ok(reservation) => reservation,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            let charge = match reservation.commit_charge() {
                Ok(charge) => charge,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            if let Err((error, charge)) = meter.module_charge.try_push(charge) {
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

    pub fn spend_work(&mut self, units: usize) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(remaining) = self.work_left.checked_sub(units) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        if let Some(meter) = self.meter.as_mut() {
            let cost = u64::try_from(units).unwrap_or(u64::MAX);
            if meter.finalizer_running {
                *meter.finalizer_steps = meter.finalizer_steps.saturating_add(cost);
                if *meter.finalizer_steps > 1_000_000 {
                    return Err(self.fail(LoadBudgetStop::Terminal));
                }
            } else if *meter.fuel < cost {
                *meter.fuel = 0;
                return Err(self.fail(LoadBudgetStop::Fuel));
            } else {
                *meter.fuel -= cost;
            }
        }
        self.work_left = remaining;
        Ok(())
    }

    pub fn claim_temporary(&mut self, bytes: usize) -> Result<(), HostLoadError> {
        if self.stop.is_some() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        let Some(remaining) = self.temporary_left.checked_sub(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        let Some(claimed) = self.temporary_claimed.checked_add(bytes) else {
            return Err(self.fail(LoadBudgetStop::Limit));
        };
        if let Some(meter) = self.meter.as_mut() {
            let reservation = match meter.ledger.reserve(bytes) {
                Ok(reservation) => reservation,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            let charge = match reservation.commit_charge() {
                Ok(charge) => charge,
                Err(error) => return Err(self.fail(LoadBudgetStop::Allocation(error))),
            };
            if let Err((error, charge)) = meter.temporary_charge.try_push(charge) {
                drop(charge);
                return Err(self.fail(LoadBudgetStop::Allocation(error)));
            }
        }
        self.temporary_left = remaining;
        self.temporary_claimed = claimed;
        Ok(())
    }

    pub const fn module_allocation_limit(&self) -> usize {
        self.module_allocation_limit
    }
}

pub trait HostLoadCompiler {
    /// 輸出 VerifiedModule 前，應依 `module_allocation_limit` 控制保留配置；
    /// compiler 的每段工作與暫存配置須先呼叫 budget，VM 再核對實際 nested 容量。
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError>;
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
}

pub struct HostNativeModule {
    pub module: VerifiedModule,
    pub loader_data: Vec<u8>,
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
    pub(crate) allow_bytecode: bool,
    pub(crate) allow_official_bytecode: bool,
    pub(crate) limits: LoadLimits,
    pub(crate) verify_limits: VerifyLimits,
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
            allow_bytecode: false,
            allow_official_bytecode: false,
            limits: LoadLimits::default(),
            verify_limits: VerifyLimits::default(),
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
        self
    }

    pub fn with_verify_limits(mut self, limits: VerifyLimits) -> Self {
        self.verify_limits = limits;
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
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOutputError {
    WriteFailed,
}

pub trait HostOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError>;
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
    /// 只允許 table 的 metatable 設定，沿既有 write barrier。
    TableMetatableWrite,
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
    entropy: Option<Box<dyn HostEntropy>>,
    pub(crate) load: LoadCapability,
    pub(crate) resource: ResourceCapability,
    pub(crate) debug: DebugCapability,
    pub(crate) dump: DumpCapability,
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

    pub fn and_entropy(mut self, entropy: impl HostEntropy + 'static) -> Self {
        self.entropy = Some(Box::new(entropy));
        self
    }

    pub fn and_load(mut self, load: LoadCapability) -> Self {
        self.load = load;
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

    pub(crate) fn output_allowed(&self) -> bool {
        self.output.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostServiceError {
    PolicyDenied,
    OutputFailed,
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

/// 每個 lease 只屬於一個 VM file payload。`close` 消耗 Box；未 close 時由實作者的 Drop 釋放。
pub trait HostFileLease {
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

#[derive(Clone, Debug, PartialEq)]
pub enum HostOsValue {
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
