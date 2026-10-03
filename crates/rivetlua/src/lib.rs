#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use rivetlua_compiler::{Diagnostic, IrError};
use rivetlua_core::{BytecodeError, ProtoId, VerifiedModule};
use rivetlua_runtime::{HostHandle, Vm as RuntimeVm};

mod compile;
mod transport;

pub use compile::{CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits};
pub use rivetlua_compiler::{CompileLimits, IrLimits};
pub use rivetlua_core::{
    BytecodeVersion, InputErrorKind, InputFormat, LuaProfile, ModuleOrigin, OfficialChunkLimits,
    RVLU_V2, TransportErrorKind, TransportLimits, Value, ValueKind, VerifyLimits, classify_input,
};
pub use rivetlua_runtime::{
    AbortReason, AllocationAttempt, AllocationFailure, AllocationFailureKind, AllocationLedger,
    AllocationTrace, CallbackContext, CallbackContinuation, CallbackFn, CallbackResult,
    DebugCapability, DebugLimits, DebugPermission, DumpCapability, DumpLimits, Execution,
    FileOperation, FileReadFormat, FileSeekOrigin, HostCalendar, HostCloseResult, HostDeadline,
    HostEntropy, HostEntropyError, HostExitStatus, HostFileLease, HostIo, HostIoFailure,
    HostLoadCompiler, HostLoadError, HostLoadErrorKind, HostModuleBytes, HostModuleRepository,
    HostNativeLoader, HostNativeModule, HostOs, HostOsOperation, HostOsValue, HostOutput,
    HostOutputError, HostResourceError, HostResourceErrorKind, HostServices, HostSourceReader,
    LedgerSnapshot, LoadBudget, LoadCapability, LoadFormat, LoadLimits, LuaError, PathEncoding,
    ResourceBudget, ResourceCapability, ResourceLimits, RunOutcome, RuntimeError, RuntimeErrorKind,
    VmError,
};
pub use transport::{ContainerError, ContainerErrorKind, ContainerLimits, TransportBudget};

/// 可轉換為 SDK Lua 值的 primitive host 值。
pub trait IntoValue {
    fn into_value(self) -> Value;
}

impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}

impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::Boolean(self)
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::Integer(self)
    }
}

impl IntoValue for f64 {
    fn into_value(self) -> Value {
        Value::Float(self)
    }
}

impl IntoValue for () {
    fn into_value(self) -> Value {
        Value::Nil
    }
}

/// 將 primitive Lua 值轉回 host 型別；物件不會隱式複製或解開。
pub trait FromValue: Sized {
    fn from_value(value: Value) -> Option<Self>;
}

impl FromValue for Value {
    fn from_value(value: Value) -> Option<Self> {
        Some(value)
    }
}

impl FromValue for bool {
    fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Boolean(value) => Some(value),
            _ => None,
        }
    }
}

impl FromValue for i64 {
    fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Integer(value) => Some(value),
            _ => None,
        }
    }
}

impl FromValue for f64 {
    fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Float(value) => Some(value),
            Value::Integer(value) => Some(value as f64),
            _ => None,
        }
    }
}

impl FromValue for () {
    fn from_value(value: Value) -> Option<Self> {
        matches!(value, Value::Nil).then_some(())
    }
}

/// 明確 profile 與編譯、IR、RVLU 驗證限額的編譯引擎。
#[derive(Clone, Debug)]
pub struct Engine {
    profile: LuaProfile,
    compile_limits: CompileLimits,
    ir_limits: IrLimits,
    verify_limits: VerifyLimits,
}

impl Engine {
    /// 以明確 Lua profile 與各階段預設限額建立引擎。
    pub fn new(profile: LuaProfile) -> Self {
        Self {
            profile,
            compile_limits: CompileLimits::default(),
            ir_limits: IrLimits::default(),
            verify_limits: VerifyLimits::default(),
        }
    }

    /// 設定 lexer/parser/resolver、IR 與 RVLU verifier 各自的輸入上限。
    pub fn with_limits(
        mut self,
        compile_limits: CompileLimits,
        ir_limits: IrLimits,
        verify_limits: VerifyLimits,
    ) -> Self {
        self.compile_limits = compile_limits;
        self.ir_limits = ir_limits;
        self.verify_limits = verify_limits;
        self
    }

    pub const fn profile(&self) -> LuaProfile {
        self.profile
    }

    /// 執行既有 lex → parse → resolve → lower → RVLU_V2 emit/verify 流程。
    pub fn compile(&self, source: &[u8]) -> Result<Module, CompileError> {
        self.compile_named(source, b"=(rivetlua-sdk)")
    }

    /// 編譯並將指定來源名稱保留在 P05 驗證的 guest debug metadata。
    pub fn compile_named(&self, source: &[u8], chunk_name: &[u8]) -> Result<Module, CompileError> {
        self.compile_named_with_budget(source, chunk_name, &CompileBudget::default())
    }

    /// 建立以相同 profile 執行、預設拒絕所有可選宿主服務的 VM。
    pub fn new_vm(&self) -> Result<Vm, SdkError> {
        self.new_vm_with_services(HostServices::deny_all())
    }

    /// 建立以相同 profile 執行並明確注入宿主能力的 VM。
    pub fn new_vm_with_services(&self, services: HostServices) -> Result<Vm, SdkError> {
        Vm::with_host_services(self.profile, services)
    }
}

/// 私有持有 P05 verifier 建立的不可變 RVLU 模組，可安全地在 VM 間共享。
#[derive(Clone, Debug)]
pub struct Module {
    verified: Arc<VerifiedModule>,
}

impl Module {
    pub fn profile(&self) -> LuaProfile {
        self.verified.profile()
    }

    pub fn format_version(&self) -> BytecodeVersion {
        self.verified.format_version()
    }

    pub fn origin(&self) -> ModuleOrigin {
        self.verified.origin()
    }

    /// 取得 P05 驗證模組之 root prototype source name；不複製或解碼 bytecode。
    pub fn source_name(&self) -> Option<&[u8]> {
        self.verified
            .native_debug()
            .map(|debug| debug.source_name())
            .or_else(|| {
                self.verified
                    .official_artifact()
                    .and_then(|artifact| artifact.effective_source(ProtoId(0)))
            })
    }

    /// 取得 P05 驗證模組之 root prototype 定義行範圍。
    pub fn main_line_range(&self) -> Option<(u32, u32)> {
        self.verified
            .native_debug()
            .and_then(|debug| debug.prototype(ProtoId(0)))
            .map(|prototype| (prototype.line_defined, prototype.last_line_defined))
            .or_else(|| {
                self.verified
                    .official_artifact()
                    .and_then(|artifact| artifact.prototype(ProtoId(0)))
                    .map(|prototype| (prototype.line_defined, prototype.last_line_defined))
            })
    }
}

/// 由 host 持有的 VM 綁定 root；不公開 runtime handle 或 heap 位址。
pub struct Root {
    handle: HostHandle<Value>,
}

impl Root {
    /// 驗證 VM 身分、root lease 及物件世代後，取得可暫時傳遞的 Lua 值。
    pub fn value(&self, vm: &Vm) -> Result<Value, SdkError> {
        self.handle
            .as_value(&vm.runtime)
            .map_err(SdkError::RuntimeVm)
    }

    /// 在相同 VM 中建立另一筆獨立 root。
    pub fn try_clone(&self, vm: &mut Vm) -> Result<Self, SdkError> {
        self.handle
            .try_clone(&mut vm.runtime)
            .map(|handle| Self { handle })
            .map_err(SdkError::RuntimeVm)
    }
}

/// 單一 profile 的獨立 runtime，並以 RAII root 持有 VM-local globals table。
pub struct Vm {
    runtime: RuntimeVm,
    profile: LuaProfile,
    globals: Root,
}

impl Vm {
    /// 建立預設 deny-all host services 的 VM。
    pub fn new(profile: LuaProfile) -> Result<Self, SdkError> {
        Self::with_host_services(profile, HostServices::deny_all())
    }

    /// 建立帶有明確宿主服務的 VM。
    pub fn with_host_services(
        profile: LuaProfile,
        host_services: HostServices,
    ) -> Result<Self, SdkError> {
        let mut runtime =
            RuntimeVm::new_with_services(profile, host_services).map_err(SdkError::RuntimeVm)?;
        let globals_object = runtime.allocate_table().map_err(SdkError::RuntimeVm)?;
        let globals = Root {
            handle: HostHandle::new(&mut runtime, globals_object).map_err(SdkError::RuntimeVm)?,
        };
        let Value::Object(environment) = globals
            .handle
            .as_value(&runtime)
            .map_err(SdkError::RuntimeVm)?
        else {
            return Err(SdkError::NotObject);
        };
        runtime
            .install_error_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_basic_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_coroutine_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_string_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_table_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_math_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_utf8_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_package_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_io_os_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        runtime
            .install_debug_builtins(environment)
            .map_err(SdkError::RuntimeVm)?;
        Ok(Self {
            runtime,
            profile,
            globals,
        })
    }

    pub const fn profile(&self) -> LuaProfile {
        self.profile
    }

    /// 取得 VM-local globals 的唯讀 root 票據。
    pub const fn globals(&self) -> &Root {
        &self.globals
    }

    /// 將 VM 回傳的物件值立即提升為 host root；primitive 值無須 root。
    pub fn root(&mut self, value: Value) -> Result<Root, SdkError> {
        let Value::Object(object) = value else {
            return Err(SdkError::NotObject);
        };
        HostHandle::new(&mut self.runtime, object)
            .map(|handle| Root { handle })
            .map_err(SdkError::RuntimeVm)
    }

    pub fn new_table(&mut self) -> Result<Root, SdkError> {
        let object = self.runtime.allocate_table().map_err(SdkError::RuntimeVm)?;
        self.root(Value::Object(object))
    }

    pub fn new_string(&mut self, bytes: &[u8]) -> Result<Root, SdkError> {
        let object = self
            .runtime
            .allocate_byte_string(bytes)
            .map_err(SdkError::RuntimeVm)?;
        self.root(Value::Object(object))
    }

    /// 載入 profile 相符的 immutable verified module，使用此 VM 的 globals table。
    pub fn load_module(&mut self, module: &Module) -> Result<Execution<'_>, SdkError> {
        self.load_module_with_args(module, &[])
    }

    /// 以此 VM 的 globals table 載入 verified module，並將參數交給 root chunk。
    pub fn load_module_with_args(
        &mut self,
        module: &Module,
        args: &[Value],
    ) -> Result<Execution<'_>, SdkError> {
        self.ensure_profile(module)?;
        let environment = self
            .globals
            .handle
            .as_value(&self.runtime)
            .map_err(SdkError::RuntimeVm)?;
        self.runtime
            .load_with_environment_and_args(module.verified.as_ref().clone(), environment, args)
            .map_err(SdkError::Runtime)
    }

    /// 呼叫 VM 中已 root 的函式值。執行期間的 arguments 依 runtime frame 規則追蹤。
    pub fn call(&mut self, function: &Root, args: &[Value]) -> Result<Execution<'_>, SdkError> {
        let function = function
            .handle
            .as_value(&self.runtime)
            .map_err(SdkError::RuntimeVm)?;
        self.runtime.call(function, args).map_err(SdkError::Runtime)
    }

    /// 註冊帶有明確 Lua captures 的 callback。物件 capture 在登錄時由 runtime 驗證並追蹤。
    pub fn register_callback(
        &mut self,
        captures: &[Value],
        callback: Rc<CallbackFn>,
    ) -> Result<Root, SdkError> {
        self.runtime
            .register_callback(captures, callback)
            .map(|handle| Root { handle })
            .map_err(SdkError::RuntimeVm)
    }

    /// 建立 host 可持有的 VM-local coroutine root。
    pub fn new_coroutine(&mut self, function: &Root) -> Result<Root, SdkError> {
        let function = function
            .handle
            .as_value(&self.runtime)
            .map_err(SdkError::RuntimeVm)?;
        self.runtime
            .new_coroutine(function)
            .map(|handle| Root { handle })
            .map_err(SdkError::RuntimeVm)
    }

    /// 開始或續跑 coroutine；結果仍遵循 runtime `RunOutcome` 的錯誤與中止分類。
    pub fn resume(&mut self, coroutine: &Root, args: &[Value]) -> Result<Execution<'_>, SdkError> {
        let coroutine = coroutine
            .handle
            .as_value(&self.runtime)
            .map_err(SdkError::RuntimeVm)?;
        self.runtime
            .resume(coroutine, args)
            .map_err(SdkError::Runtime)
    }

    /// 要求 runtime 執行一次完整 GC cycle。
    pub fn collect(&mut self) -> Result<usize, SdkError> {
        self.runtime.collect().map_err(SdkError::RuntimeVm)
    }

    /// 設定 VM heap 與宿主配置共用的 runtime ledger 上限。
    pub fn set_allocation_limit(&mut self, bytes: usize) {
        self.runtime.set_allocation_limit(bytes);
    }

    /// 將下一次 runtime 邏輯配置設為一次性失敗，供宿主檢查錯誤清理與重試。
    pub fn inject_next_allocation_failure(&mut self) {
        let next = self.runtime.allocation_trace().next_ordinal;
        self.runtime.inject_allocation_failure_at(next);
    }

    /// 讀取目前配置帳本快照，不會借出 heap 或可變 runtime 狀態。
    pub fn allocation_snapshot(&self) -> LedgerSnapshot {
        self.runtime.ledger_snapshot()
    }

    /// 以 VM-local globals 進行安全 raw lookup；回傳物件值仍須由宿主提升為 Root。
    pub fn get_global(&mut self, name: &[u8]) -> Result<Value, SdkError> {
        let key = self
            .runtime
            .allocate_byte_string(name)
            .map_err(SdkError::RuntimeVm)?;
        let _key_root =
            HostHandle::<Value>::new(&mut self.runtime, key).map_err(SdkError::RuntimeVm)?;
        let Value::Object(globals) = self.globals.value(self)? else {
            return Err(SdkError::NotObject);
        };
        self.runtime
            .raw_get(globals, Value::Object(key))
            .map_err(SdkError::RuntimeVm)
    }

    /// 以 VM-local globals 進行安全 raw write；物件輸入先驗證並暫時保根。
    pub fn set_global(&mut self, name: &[u8], value: Value) -> Result<(), SdkError> {
        let _value_root = temporary_root(&mut self.runtime, value)?;
        let key = self
            .runtime
            .allocate_byte_string(name)
            .map_err(SdkError::RuntimeVm)?;
        let _key_root =
            HostHandle::<Value>::new(&mut self.runtime, key).map_err(SdkError::RuntimeVm)?;
        let Value::Object(globals) = self.globals.value(self)? else {
            return Err(SdkError::NotObject);
        };
        self.runtime
            .raw_set(globals, Value::Object(key), value)
            .map_err(SdkError::RuntimeVm)
    }

    /// 對 rooted table 執行既有 runtime raw lookup，不會借出 heap 參照。
    pub fn table_raw_get(&self, table: &Root, key: Value) -> Result<Value, SdkError> {
        let Value::Object(table) = table.value(self)? else {
            return Err(SdkError::NotObject);
        };
        self.runtime
            .raw_get(table, key)
            .map_err(SdkError::RuntimeVm)
    }

    /// 對 rooted table 執行既有 runtime raw write，並在可能配置前驗證、保根物件輸入。
    pub fn table_raw_set(
        &mut self,
        table: &Root,
        key: Value,
        value: Value,
    ) -> Result<(), SdkError> {
        let Value::Object(table_object) = table.value(self)? else {
            return Err(SdkError::NotObject);
        };
        let _key_root = temporary_root(&mut self.runtime, key)?;
        let _value_root = temporary_root(&mut self.runtime, value)?;
        self.runtime
            .raw_set(table_object, key, value)
            .map_err(SdkError::RuntimeVm)
    }

    /// 將 rooted ByteString 複製為宿主擁有的位元組，不會逸出 heap borrow。
    pub fn read_byte_string(&self, string: &Root) -> Result<Vec<u8>, SdkError> {
        let Value::Object(object) = string.value(self)? else {
            return Err(SdkError::NotObject);
        };
        self.runtime
            .with_byte_string(object, |bytes| bytes.as_bytes().to_vec())
            .map_err(SdkError::RuntimeVm)
    }

    fn ensure_profile(&self, module: &Module) -> Result<(), SdkError> {
        if self.profile == module.profile() {
            Ok(())
        } else {
            Err(SdkError::ProfileMismatch {
                vm: self.profile,
                module: module.profile(),
            })
        }
    }
}

fn temporary_root(
    runtime: &mut RuntimeVm,
    value: Value,
) -> Result<Option<HostHandle<Value>>, SdkError> {
    match value {
        Value::Object(object) => HostHandle::new(runtime, object)
            .map(Some)
            .map_err(SdkError::RuntimeVm),
        Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::Float(_) => Ok(None),
    }
}

/// 編譯流程的結構化失敗。
#[derive(Debug)]
pub enum CompileError {
    Diagnostic(Diagnostic),
    Ir(IrError),
    Bytecode(BytecodeError),
    Budget(CompileBudgetErrorKind),
    AdmissionOverflow,
    AdmissionUnderestimated,
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostic(error) => write!(formatter, "編譯診斷：{}", error.message),
            Self::Ir(error) => write!(formatter, "IR lowering 失敗：{error}"),
            Self::Bytecode(error) => write!(formatter, "RVLU 驗證失敗：{error}"),
            Self::Budget(error) => write!(formatter, "編譯額度錯誤：{error}"),
            Self::AdmissionOverflow => formatter.write_str("編譯資源准入計算溢位"),
            Self::AdmissionUnderestimated => formatter.write_str("編譯資源准入低估實際容量"),
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Diagnostic(_) => None,
            Self::Ir(error) => Some(error),
            Self::Bytecode(error) => Some(error),
            Self::Budget(error) => Some(error),
            Self::AdmissionOverflow | Self::AdmissionUnderestimated => None,
        }
    }
}

impl From<Diagnostic> for CompileError {
    fn from(error: Diagnostic) -> Self {
        Self::Diagnostic(error)
    }
}

impl From<IrError> for CompileError {
    fn from(error: IrError) -> Self {
        Self::Ir(error)
    }
}

impl From<BytecodeError> for CompileError {
    fn from(error: BytecodeError) -> Self {
        Self::Bytecode(error)
    }
}

/// SDK 邊界錯誤；Lua error 與 runtime abort 仍由 `RunOutcome` 分開表示。
#[derive(Debug)]
pub enum SdkError {
    RuntimeVm(VmError),
    Runtime(RuntimeError),
    ProfileMismatch { vm: LuaProfile, module: LuaProfile },
    NotObject,
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeVm(error) => write!(formatter, "VM handle 錯誤：{error:?}"),
            Self::Runtime(error) => write!(formatter, "runtime 錯誤：{}", error.diagnostic_id),
            Self::ProfileMismatch { vm, module } => {
                write!(
                    formatter,
                    "VM profile {vm:?} 與 module profile {module:?} 不符"
                )
            }
            Self::NotObject => formatter.write_str("primitive 值不需要且不能建立物件 root"),
        }
    }
}

impl Error for SdkError {}

impl From<RuntimeError> for SdkError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// 由編譯引擎建立的 VM 可直接傳入 SDK host API 的 Lua primitive 值。
pub const fn nil() -> Value {
    Value::Nil
}

pub const fn boolean(value: bool) -> Value {
    Value::Boolean(value)
}

pub const fn integer(value: i64) -> Value {
    Value::Integer(value)
}

pub const fn float(value: f64) -> Value {
    Value::Float(value)
}
