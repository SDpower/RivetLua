#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::{Arc, Weak};

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
use rivetlua_capi::stack::{NativeSession, NativeSessionFactory, StateOwner};
use rivetlua_compiler::{Diagnostic, IrError};
use rivetlua_core::{BytecodeError, ProtoId, VerifiedModule};
use rivetlua_runtime::{HostHandle, Vm as RuntimeVm};

mod compile;
mod transport;

pub use compile::{CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits};
pub use rivetlua_compiler::{CompileLimits, IrLimits};
pub use rivetlua_core::sha256_bytes;
pub use rivetlua_core::{
    BoardConfig, BytecodeVersion, COMPATIBILITY_VERSION, CompatibilityEntry, DeploymentStatus,
    Endian, ExecMemoryPolicy, InputErrorKind, InputFormat, LuaProfile, ModuleOrigin,
    OfficialChunkLimits, RVLU_NUMERIC_I64_F64, RVLU_V2, TargetDescriptor, TargetError,
    TransportErrorKind, TransportLimits, Value, ValueKind, VerifyLimits, classify_input,
    compatibility_entries,
};
#[cfg(feature = "aot")]
pub use rivetlua_native::{AotArtifact, AotError, AotManifest, NativeError, TrustedAotBuild};
pub use rivetlua_runtime::{
    AbortReason, AllocationAttempt, AllocationFailure, AllocationFailureKind, AllocationLedger,
    AllocationPeaks, AllocationTrace, CallbackContext, CallbackContinuation, CallbackFn,
    CallbackResult, CapabilityGrant, DebugCapability, DebugLimits, DebugPermission, DumpCapability,
    DumpLimits, Execution, ExportPolicy, ExternalCommand, ExternalEventView, ExternalToken,
    FileOperation, FileReadFormat, FileSeekOrigin, ForeignNativeKind, GcTrace, HostCalendar,
    HostCloseResult, HostDeadline, HostEntropy, HostEntropyError, HostExitRequest, HostExitStatus,
    HostFileLease, HostIo, HostIoFailure, HostLoadAdvance, HostLoadCompiler, HostLoadError,
    HostLoadErrorKind, HostLoadJob, HostLoadJobContext, HostLoadJobDriver, HostLoadProgress,
    HostModuleBytes, HostModuleRepository, HostNativeLoader, HostNativeModule, HostOs,
    HostOsOperation, HostOsValue, HostOutput, HostOutputError, HostResourceError,
    HostResourceErrorKind, HostServices, HostSourceReader, HostWarning, HostWarningError,
    LedgerSnapshot, LoadBudget, LoadCapability, LoadFormat, LoadLimits, LuaError,
    OpaqueServiceHandle, OutputAudit, OutputBudget, OutputError, PathEncoding, PolicyCapabilities,
    PolicyClock, PrivateService, ResourceBudget, ResourceCapability, ResourceLimits, RunOutcome,
    RuntimeError, RuntimeErrorKind, SafeDiagnostic, ServiceAccessError, ServiceAudience,
    ServiceOperation, VmError, VmPolicy,
};
#[cfg(any(feature = "jit", feature = "aot"))]
pub use rivetlua_runtime::{JitEligibility, JitFallbackReason, JitPolicy, JitStats};
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

    /// 原生 feature 的同 VM C session 在第一筆配置前共用 admission。
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    pub fn new_vm_with_native_services(&self, services: HostServices) -> Result<Vm, SdkError> {
        Vm::with_native_host_services(self.profile, services)
    }
}

/// 私有持有 P05 verifier 建立的不可變 RVLU 模組，可安全地在 VM 間共享。
#[derive(Clone, Debug)]
pub struct Module {
    verified: Arc<VerifiedModule>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportDestination {
    HostBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportResourceClass {
    Module,
    PrivateService,
    Closure,
    ExecutionState,
    SourceMap,
    Ast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    Denied,
    OutputLimit,
}

impl ExportError {
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::Denied => "E_EXPORT_DENIED",
            Self::OutputLimit => "E_OUTPUT_LIMIT",
        }
    }
}

pub struct ExportRequest {
    owner: rivetlua_core::VmId,
    issuer: PolicyCapabilities,
    module: Weak<VerifiedModule>,
    class: ExportResourceClass,
    policy: ExportPolicy,
    destination: ExportDestination,
}

pub struct ExportResult {
    pub bytes: Vec<u8>,
}

impl Module {
    #[cfg(feature = "aot-builder")]
    pub fn build_aot(
        &self,
        target: &TargetDescriptor,
        prototype_index: usize,
        entry_pc: usize,
    ) -> Result<AotArtifact, AotError> {
        rivetlua_native::build_aot(rivetlua_native::AotBuildInput {
            module: self.verified.as_ref(),
            prototype_index,
            entry_pc,
            target,
        })
    }

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
struct RuntimeSlot(Option<RuntimeVm>);

impl RuntimeSlot {
    fn occupied(vm: RuntimeVm) -> Self {
        Self(Some(vm))
    }

    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    fn take(&mut self) -> Result<RuntimeVm, SdkError> {
        self.0.take().ok_or(SdkError::Busy)
    }

    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    fn restore(&mut self, vm: RuntimeVm) -> Result<(), RuntimeVm> {
        if self.0.is_some() {
            Err(vm)
        } else {
            self.0 = Some(vm);
            Ok(())
        }
    }
}

impl Deref for RuntimeSlot {
    type Target = RuntimeVm;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("SDK 獨占 loan 期間不可再呼叫 VM")
    }
}

impl DerefMut for RuntimeSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("SDK 獨占 loan 期間不可再呼叫 VM")
    }
}

pub struct Vm {
    runtime: RuntimeSlot,
    profile: LuaProfile,
    policy: VmPolicy,
    owned_modules: Vec<Weak<VerifiedModule>>,
    owned_modules_charge: Option<(
        rivetlua_runtime::HostAllocationCharge,
        rivetlua_runtime::HostAllocationCharge,
    )>,
    globals: Root,
    drop_shutdown_suppressed: bool,
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    native_session: Option<NativeSession>,
}

impl Vm {
    #[cfg(any(feature = "jit", feature = "aot"))]
    pub fn set_jit_policy(&mut self, policy: JitPolicy) -> Result<(), SdkError> {
        let runtime = self.runtime.0.as_mut().ok_or(SdkError::Busy)?;
        runtime.set_jit_policy(policy).map_err(SdkError::RuntimeVm)
    }

    #[cfg(feature = "aot")]
    pub fn install_aot(
        &mut self,
        module: &Module,
        bytes: &[u8],
        target: &TargetDescriptor,
        trust: &TrustedAotBuild,
    ) -> Result<(), AotError> {
        let runtime = self
            .runtime
            .0
            .as_mut()
            .ok_or(AotError::Unsupported("SDK VM busy"))?;
        runtime.install_aot(module.verified.as_ref(), bytes, target, trust)
    }

    /// 將已核准的終止請求收束在同一 VM；只有 standalone 宿主決定程序退出。
    pub fn finish_exit(&mut self, request: HostExitRequest) -> Result<HostExitRequest, SdkError> {
        if !request.close {
            return Ok(request);
        }
        Ok(self.finish_shutdown()?.unwrap_or(request))
    }

    /// 明確完成正常關閉，使宿主可取得 finalizer 中後到的退出請求。
    pub fn finish_shutdown(&mut self) -> Result<Option<HostExitRequest>, SdkError> {
        let current = self.exit_request();
        if current.is_some_and(|request| !request.close) {
            return Ok(current);
        }
        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        if self.native_session.is_some() {
            return self.close_native_inner();
        }
        let runtime = self.runtime.0.as_mut().ok_or(SdkError::Busy)?;
        let lua_error = match runtime.drain_exit_parked_close() {
            Ok(error) => error,
            Err(error) => {
                runtime.abort_exit_parked_close();
                self.drop_shutdown_suppressed = true;
                return Err(SdkError::Runtime(error));
            }
        };
        if let Err(error) = runtime.drain_shutdown_finalizers() {
            runtime.abort_exit_parked_close();
            self.drop_shutdown_suppressed = true;
            return Err(SdkError::RuntimeVm(error));
        }
        if let Some(error) = lua_error {
            return Err(SdkError::Lua(error));
        }
        Ok(runtime.exit_request())
    }

    pub fn exit_request(&self) -> Option<HostExitRequest> {
        self.runtime
            .0
            .as_ref()
            .and_then(|runtime| runtime.exit_request())
    }

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
        let policy = runtime.policy();
        Self::from_runtime(profile, &mut runtime).map(|globals| Self {
            runtime: RuntimeSlot::occupied(runtime),
            profile,
            policy,
            owned_modules: Vec::new(),
            owned_modules_charge: None,
            globals,
            drop_shutdown_suppressed: false,
            #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
            native_session: None,
        })
    }

    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    pub fn with_native_host_services(
        profile: LuaProfile,
        host_services: HostServices,
    ) -> Result<Self, SdkError> {
        let factory = NativeSessionFactory::new();
        let mut runtime =
            RuntimeVm::new_with_services_and_admission(profile, host_services, factory.admission())
                .map_err(SdkError::RuntimeVm)?;
        let policy = runtime.policy();
        let globals = Self::from_runtime(profile, &mut runtime)?;
        let Value::Object(environment) = globals
            .handle
            .as_value(&runtime)
            .map_err(SdkError::RuntimeVm)?
        else {
            return Err(SdkError::NotObject);
        };
        let session = factory
            .attach(&mut runtime, environment)
            .map_err(|error| SdkError::NativeSession(format!("{error:?}")))?;
        Ok(Self {
            runtime: RuntimeSlot::occupied(runtime),
            profile,
            policy,
            owned_modules: Vec::new(),
            owned_modules_charge: None,
            globals,
            drop_shutdown_suppressed: false,
            native_session: Some(session),
        })
    }

    pub const fn policy(&self) -> VmPolicy {
        self.policy
    }

    pub fn output_audit(&self) -> OutputAudit {
        self.runtime
            .0
            .as_ref()
            .map(RuntimeVm::output_audit)
            .unwrap_or_default()
    }

    pub fn charge_output(
        &mut self,
        bytes: usize,
        depth: usize,
        work: usize,
    ) -> Result<(), OutputError> {
        self.runtime
            .0
            .as_mut()
            .ok_or(OutputError::Sink)?
            .charge_output(bytes, depth, work)
    }

    pub fn safe_diagnostic(&mut self, public_code: &'static str) -> SafeDiagnostic {
        self.runtime.safe_diagnostic(public_code)
    }

    pub fn register_private_service(
        &mut self,
        issuer: &PolicyCapabilities,
        service: impl PrivateService + 'static,
    ) -> Result<OpaqueServiceHandle, ServiceAccessError> {
        self.runtime
            .0
            .as_mut()
            .ok_or(ServiceAccessError::Denied)?
            .register_private_service(issuer, service)
    }

    pub fn issue_service_grant(
        &self,
        issuer: &PolicyCapabilities,
        handle: &OpaqueServiceHandle,
        operation: ServiceOperation,
        audience: ServiceAudience,
        limits: ResourceLimits,
        expires_at: u64,
    ) -> Result<CapabilityGrant, ServiceAccessError> {
        self.runtime
            .0
            .as_ref()
            .ok_or(ServiceAccessError::Denied)?
            .issue_service_grant(issuer, handle, operation, audience, limits, expires_at)
    }

    pub fn dispatch_private_service(
        &mut self,
        handle: &OpaqueServiceHandle,
        grant: &mut CapabilityGrant,
        operation: ServiceOperation,
        audience: ServiceAudience,
        input: &[u8],
    ) -> Result<Vec<u8>, ServiceAccessError> {
        self.runtime
            .0
            .as_mut()
            .ok_or(ServiceAccessError::Denied)?
            .dispatch_private_service(handle, grant, operation, audience, input)
    }

    pub fn revoke_private_service(
        &mut self,
        handle: &OpaqueServiceHandle,
    ) -> Result<(), ServiceAccessError> {
        self.runtime
            .0
            .as_mut()
            .ok_or(ServiceAccessError::Denied)?
            .revoke_private_service(handle)
    }

    pub fn prepare_module_export(
        &mut self,
        issuer: &PolicyCapabilities,
        module: &Module,
        destination: ExportDestination,
    ) -> Result<ExportRequest, ExportError> {
        let runtime = self.runtime.0.as_ref().ok_or(ExportError::Denied)?;
        let identity = Arc::downgrade(&module.verified);
        if !runtime.authorizes_module_export(issuer)
            || !self
                .owned_modules
                .iter()
                .any(|owned| owned.ptr_eq(&identity))
        {
            return Err(ExportError::Denied);
        }
        Ok(ExportRequest {
            owner: runtime.id(),
            issuer: issuer.clone(),
            module: identity,
            class: ExportResourceClass::Module,
            policy: ExportPolicy::OwnerModules,
            destination,
        })
    }

    pub fn export_module(
        &mut self,
        request: &ExportRequest,
        module: &Module,
    ) -> Result<ExportResult, ExportError> {
        let runtime = self.runtime.0.as_ref().ok_or(ExportError::Denied)?;
        let identity = Arc::downgrade(&module.verified);
        if request.owner != runtime.id()
            || request.class != ExportResourceClass::Module
            || request.policy != ExportPolicy::OwnerModules
            || request.destination != ExportDestination::HostBytes
            || !runtime.authorizes_module_export(&request.issuer)
            || !request.module.ptr_eq(&identity)
            || !self
                .owned_modules
                .iter()
                .any(|owned| owned.ptr_eq(&identity))
        {
            return Err(ExportError::Denied);
        }
        // 只編碼已驗證的 RVLU 主體，不攜帶 debug sidecar、source map 或 AST。
        let encoded = rivetlua_core::encode_module(
            module.verified.module().clone(),
            module.profile(),
            &VerifyLimits::default(),
        )
        .map_err(|_| ExportError::Denied)?;
        let len = encoded.bytes().len();
        self.charge_output(len, 0, len.max(1))
            .map_err(|_| ExportError::OutputLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ExportError::Denied)?;
        bytes.extend_from_slice(encoded.bytes());
        Ok(ExportResult { bytes })
    }

    /// 僅對已授權的 owner export 保存模組身分；Vec backing 由同一 VM ledger 持有。
    fn track_exportable_module(&mut self, module: &Module) -> Result<bool, SdkError> {
        if !self.runtime.module_export_enabled() {
            return Ok(false);
        }
        let identity = Arc::downgrade(&module.verified);
        if self
            .owned_modules
            .iter()
            .any(|owned| owned.strong_count() != 0 && owned.ptr_eq(&identity))
        {
            return Ok(false);
        }
        let live_count = self
            .owned_modules
            .iter()
            .filter(|owned| owned.strong_count() != 0)
            .count();
        if live_count == self.owned_modules.capacity() {
            let needed = live_count
                .checked_add(1)
                .ok_or(SdkError::RuntimeVm(VmError::ArithmeticOverflow))?;
            let element_bytes = std::mem::size_of::<Weak<VerifiedModule>>();
            let base_bytes = needed
                .checked_mul(element_bytes)
                .ok_or(SdkError::RuntimeVm(VmError::ArithmeticOverflow))?;
            let base_reservation = self
                .runtime
                .reserve_host_allocation(base_bytes)
                .map_err(SdkError::RuntimeVm)?;
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(needed)
                .map_err(|_| SdkError::RuntimeVm(base_reservation.rust_reserve_failure()))?;
            let actual_bytes = replacement
                .capacity()
                .checked_mul(element_bytes)
                .ok_or(SdkError::RuntimeVm(VmError::ArithmeticOverflow))?;
            let extra_bytes = actual_bytes
                .checked_sub(base_bytes)
                .ok_or(SdkError::RuntimeVm(VmError::ArithmeticOverflow))?;
            let extra_reservation = self
                .runtime
                .reserve_host_allocation(extra_bytes)
                .map_err(SdkError::RuntimeVm)?;
            replacement.extend(
                self.owned_modules
                    .iter()
                    .filter(|owned| owned.strong_count() != 0)
                    .cloned(),
            );
            replacement.push(identity);
            let base_charge = base_reservation.commit().map_err(SdkError::RuntimeVm)?;
            let extra_charge = extra_reservation.commit().map_err(SdkError::RuntimeVm)?;
            let old = std::mem::replace(&mut self.owned_modules, replacement);
            let old_charge = self
                .owned_modules_charge
                .replace((base_charge, extra_charge));
            drop(old);
            drop(old_charge);
        } else {
            self.owned_modules.retain(|owned| owned.strong_count() != 0);
            self.owned_modules.push(identity);
        }
        Ok(true)
    }

    /// 獨占借用排除同時執行任何 SDK API；`Execution` 須已 drop。
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    pub fn native_loan(&mut self) -> Result<NativeVmLoan<'_>, SdkError> {
        let Some(session) = self.native_session.as_ref() else {
            return Err(SdkError::NativeSession("此 VM 沒有 native session".into()));
        };
        let runtime = self.runtime.take()?;
        if let Err((error, runtime)) = session.loan_native_vm(runtime) {
            if self.runtime.restore(runtime).is_err() {
                std::process::abort();
            }
            return Err(SdkError::NativeSession(format!("{error:?}")));
        }
        Ok(NativeVmLoan {
            sdk: self,
            returned: false,
        })
    }

    /// 消耗 VM 並執行 finalizer；失敗時交還原 VM，宿主可解除故障後重試。
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    pub fn try_close_native(mut self) -> Result<(), (Self, SdkError)> {
        match self.close_native_inner() {
            Ok(_) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }

    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    fn close_native_inner(&mut self) -> Result<Option<HostExitRequest>, SdkError> {
        let Some(session) = self.native_session.as_mut() else {
            return Ok(None);
        };
        let runtime = self.runtime.take()?;
        if let Err((error, mut runtime)) = session.loan_native_vm(runtime) {
            self.drop_shutdown_suppressed = true;
            runtime.abort_exit_parked_close();
            if self.runtime.restore(runtime).is_err() {
                std::process::abort();
            }
            return Err(SdkError::NativeSession(format!("{error:?}")));
        }
        let final_request = match session.close_with_exit_request() {
            Ok(request) => request,
            Err(error) => {
                self.drop_shutdown_suppressed = true;
                let runtime = session.return_native_vm().map_err(|return_error| {
                    SdkError::NativeSession(format!("close {error:?}；VM 歸還 {return_error:?}"))
                })?;
                let mut runtime = runtime;
                runtime.abort_exit_parked_close();
                if self.runtime.restore(runtime).is_err() {
                    std::process::abort();
                }
                return Err(SdkError::NativeSession(format!("{error:?}")));
            }
        };
        self.native_session = None;
        Ok(final_request)
    }

    fn from_runtime(profile: LuaProfile, runtime: &mut RuntimeVm) -> Result<Root, SdkError> {
        if runtime.language_profile() != profile {
            return Err(SdkError::ProfileMismatch {
                vm: runtime.language_profile(),
                module: profile,
            });
        }
        let globals_object = runtime.allocate_table().map_err(SdkError::RuntimeVm)?;
        let globals = Root {
            handle: HostHandle::new(runtime, globals_object).map_err(SdkError::RuntimeVm)?,
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
        Ok(globals)
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
        let recorded = self.track_exportable_module(module)?;
        match self.runtime.load_with_environment_and_args(
            module.verified.as_ref().clone(),
            environment,
            args,
        ) {
            Ok(execution) => Ok(execution),
            Err(error) => {
                if recorded {
                    self.owned_modules.pop();
                }
                Err(SdkError::Runtime(error))
            }
        }
    }

    /// 在原 root chunk frame 上安裝受保護 message handler；正常返回值不加 pcall 標記。
    pub fn load_module_with_args_and_error_handler(
        &mut self,
        module: &Module,
        args: &[Value],
        handler: &Root,
    ) -> Result<Execution<'_>, SdkError> {
        let handler = handler.value(self)?;
        let mut execution = self.load_module_with_args(module, args)?;
        execution
            .install_host_entry_error_handler(handler)
            .map_err(SdkError::Runtime)?;
        Ok(execution)
    }

    /// 呼叫 VM 中已 root 的函式值。執行期間的 arguments 依 runtime frame 規則追蹤。
    pub fn call(&mut self, function: &Root, args: &[Value]) -> Result<Execution<'_>, SdkError> {
        let function = function
            .handle
            .as_value(&self.runtime)
            .map_err(SdkError::RuntimeVm)?;
        self.runtime.call(function, args).map_err(SdkError::Runtime)
    }

    /// 對宿主直接呼叫使用相同受保護 handler，原函式與參數仍在其原始 frame。
    pub fn call_with_error_handler(
        &mut self,
        function: &Root,
        args: &[Value],
        handler: &Root,
    ) -> Result<Execution<'_>, SdkError> {
        let handler = handler.value(self)?;
        let mut execution = self.call(function, args)?;
        execution
            .install_host_entry_error_handler(handler)
            .map_err(SdkError::Runtime)?;
        Ok(execution)
    }

    /// 停放事件仍由同一 VM 持有；宿主須先 drop `Execution` 才能續接。
    pub fn external_event(&self, token: ExternalToken) -> Result<ExternalEventView<'_>, SdkError> {
        self.runtime
            .external_event(token)
            .map_err(SdkError::Runtime)
    }

    pub fn foreign_native_kind(
        &self,
        function: rivetlua_core::HostFunctionId,
    ) -> Option<ForeignNativeKind> {
        self.runtime.foreign_native_kind(function)
    }

    pub fn continue_external(
        &mut self,
        token: ExternalToken,
        command: ExternalCommand,
    ) -> Result<RunOutcome, SdkError> {
        self.runtime
            .continue_external(token, command)
            .map_err(SdkError::Runtime)
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

    pub fn allocation_peaks(&self) -> AllocationPeaks {
        self.runtime.allocation_peaks()
    }

    /// 讀取目前 GC 追蹤計數，不會修改 runtime 狀態。
    pub fn gc_trace(&self) -> GcTrace {
        self.runtime.gc_trace()
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

impl Drop for Vm {
    fn drop(&mut self) {
        if self.drop_shutdown_suppressed {
            // 已回報硬性關閉失敗；只依欄位順序回收 VM graph 與 native leases。
            return;
        }
        if self
            .runtime
            .0
            .as_ref()
            .and_then(|runtime| runtime.exit_request())
            .is_some_and(|request| !request.close)
        {
            // os.exit(false) 只釋放宿主資源，不再執行任何 Lua 關閉 callback。
            // 依欄位順序先 drop VM graph 與 roots，最後才釋放 native session／leases。
            return;
        }
        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        if self.native_session.is_some() {
            // 無法回報的關閉錯誤由呼叫端以 try_close_native 取得；Drop 至少
            // 依欄位順序先釋放 VM graph，再釋放 session 及 native leases。
            let _ = self.close_native_inner();
            return;
        }
        if let Some(runtime) = self.runtime.0.as_mut() {
            // 無 native session 時安全地 drain；Drop 仍以根與 ledger 原有清理收尾。
            if runtime.drain_exit_parked_close().is_ok() {
                let _ = runtime.drain_shutdown_finalizers();
            }
        }
    }
}

/// 持有 SDK `&mut Vm` 的同 VM C session loan；不得跨純 C checkpoint 保留 Rust 借用。
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub struct NativeVmLoan<'a> {
    sdk: &'a mut Vm,
    returned: bool,
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
impl NativeVmLoan<'_> {
    pub fn state_owner(&self) -> &StateOwner {
        self.sdk
            .native_session
            .as_ref()
            .expect("loan 持有 native session")
            .state_owner()
    }

    pub fn try_return(&mut self) -> Result<(), SdkError> {
        if self.returned {
            return Ok(());
        }
        let runtime = self
            .sdk
            .native_session
            .as_ref()
            .expect("loan 持有 native session")
            .return_native_vm()
            .map_err(|error| SdkError::NativeSession(format!("{error:?}")))?;
        if self.sdk.runtime.restore(runtime).is_err() {
            std::process::abort();
        }
        self.returned = true;
        Ok(())
    }
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
impl Drop for NativeVmLoan<'_> {
    fn drop(&mut self) {
        if !self.returned && self.try_return().is_err() {
            // 安全宿主取消 loan 時，閒置 C stack 可能仍有 slot；先退根再歸還原 VM。
            // 活 C frame／to-be-closed slot 不可跳過 Lua 收尾並卸載 library。
            if self
                .sdk
                .native_session
                .as_ref()
                .expect("loan 持有 native session")
                .discard_idle_native_stack()
                .is_err()
                || self.try_return().is_err()
            {
                std::process::abort();
            }
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
        Value::LightUserdata(_) | Value::CFunction(_) => Ok(None),
    }
}

#[cfg(test)]
mod temporary_root_tests {
    use super::{Engine, LuaProfile, Value, temporary_root};
    use rivetlua_core::HostFunctionId;

    #[test]
    fn sdk_temporary_root_keeps_non_collectable_values_unrooted_for_both_profiles() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let engine = Engine::new(profile);
            let mut vm = engine.new_vm().unwrap();
            let Value::Object(globals) = vm.globals().value(&vm).unwrap() else {
                panic!("SDK globals 必須是 heap object");
            };
            let vm_id = globals.identity().unwrap().vm;
            let c_function = Value::CFunction(HostFunctionId::new_unique(vm_id).unwrap());
            let light_userdata = Value::LightUserdata(0x1234);
            let values = [light_userdata, c_function];
            let roots_before = vm.runtime.roots().total_count();

            for value in values {
                let retained_value = value;
                assert!(temporary_root(&mut vm.runtime, value).unwrap().is_none());
                assert_eq!(retained_value, value);
                assert_eq!(vm.runtime.roots().total_count(), roots_before);
            }

            vm.set_global(b"host_light_userdata", light_userdata)
                .unwrap();
            vm.set_global(b"host_c_function", c_function).unwrap();
            assert_eq!(
                vm.get_global(b"host_light_userdata").unwrap(),
                light_userdata
            );
            assert_eq!(vm.get_global(b"host_c_function").unwrap(), c_function);

            let table = vm.new_table().unwrap();
            let roots_with_table = vm.runtime.roots().total_count();
            vm.table_raw_set(&table, light_userdata, c_function)
                .unwrap();
            vm.table_raw_set(&table, c_function, light_userdata)
                .unwrap();
            assert_eq!(
                vm.table_raw_get(&table, light_userdata).unwrap(),
                c_function
            );
            assert_eq!(
                vm.table_raw_get(&table, c_function).unwrap(),
                light_userdata
            );
            assert_eq!(vm.runtime.roots().total_count(), roots_with_table);
        }
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
    Lua(LuaError),
    Busy,
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    NativeSession(String),
    ProfileMismatch {
        vm: LuaProfile,
        module: LuaProfile,
    },
    NotObject,
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeVm(error) => write!(formatter, "VM handle 錯誤：{error:?}"),
            Self::Runtime(error) => write!(formatter, "runtime 錯誤：{}", error.diagnostic_id),
            Self::Lua(error) => write!(formatter, "runtime 錯誤：{}", error.diagnostic_id),
            Self::Busy => formatter.write_str("VM 暫時借出"),
            #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
            Self::NativeSession(error) => write!(formatter, "native session 錯誤：{error}"),
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

#[cfg(test)]
mod p17_host_entry_tests {
    use super::*;
    use rivetlua_core::HostFunctionId;
    use std::cell::{Cell, RefCell};

    #[test]
    fn p17_host_entry_nested_body_returns_and_error() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let engine = Engine::new(profile);
            let mut vm = engine.new_vm().unwrap();
            let calls = Rc::new(Cell::new(0));
            let handler_calls = Rc::clone(&calls);
            let handler = vm
                .register_callback(
                    &[],
                    Rc::new(move |_, _| {
                        handler_calls.set(handler_calls.get() + 1);
                        CallbackResult::Return(vec![Value::Integer(41)])
                    }),
                )
                .unwrap();
            let plain_error = engine.compile(b"error('plain')").unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&plain_error, &[], &handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("原入口錯誤須交 handler");
            };
            assert_eq!(error.value, Value::Integer(41));
            assert_eq!(calls.get(), 1);
            let preserve_error = vm
                .register_callback(
                    &[],
                    Rc::new(|_, args| {
                        CallbackResult::Return(vec![args.first().copied().unwrap_or(Value::Nil)])
                    }),
                )
                .unwrap();
            for (source, expected) in [
                (b"error('msg')".as_slice(), b"LUA_INIT:1: msg".as_slice()),
                (
                    b"local a = 1\nerror('later')".as_slice(),
                    b"LUA_INIT:2: later".as_slice(),
                ),
                (b"error('raw', 0)".as_slice(), b"raw".as_slice()),
            ] {
                let module = engine.compile_named(source, b"=LUA_INIT").unwrap();
                let RunOutcome::LuaError(error) = vm
                    .load_module_with_args_and_error_handler(&module, &[], &preserve_error)
                    .unwrap()
                    .run()
                    .unwrap()
                else {
                    panic!("原入口字串錯誤須交 handler");
                };
                let message = vm.root(error.value).unwrap();
                assert_eq!(vm.read_byte_string(&message).unwrap(), expected);
                drop(message);
                drop(error);
            }
            let object = vm.new_table().unwrap();
            let object_value = object.value(&vm).unwrap();
            let object_error = engine.compile_named(b"error(...)", b"=LUA_INIT").unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(
                    &object_error,
                    &[object_value],
                    &preserve_error,
                )
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("非字串錯誤須交 handler");
            };
            assert_eq!(error.value, object_value);
            drop(error);
            drop(object);
            drop(preserve_error);
            let args = [Value::Integer(8), Value::Integer(9)];
            for (source, expected) in [
                (
                    b"return ...".as_slice(),
                    [Value::Integer(8), Value::Integer(9)].as_slice(),
                ),
                (
                    b"local n=(function() return 7 end)(); return n, ...".as_slice(),
                    [Value::Integer(7), Value::Integer(8), Value::Integer(9)].as_slice(),
                ),
                (
                    b"local a,b=...; local n=(function() return 7 end)(); return n,a,b"
                        .as_slice(),
                    [Value::Integer(7), Value::Integer(8), Value::Integer(9)].as_slice(),
                ),
                (
                    b"local debug=require'debug'\nlocal function helper() return 7 end\nlocal n=helper()\nreturn n,..."
                        .as_slice(),
                    [Value::Integer(7), Value::Integer(8), Value::Integer(9)].as_slice(),
                ),
            ] {
                let module = engine
                    .compile_named(source, b"@p17-entry-return.lua")
                    .unwrap();
                let module_data = module.verified.module();
                let root_id = module_data
                    .function_prototypes
                    .iter()
                    .find(|(function, _)| *function == 0)
                    .unwrap()
                    .1;
                let root = module_data
                    .prototypes
                    .iter()
                    .find(|proto| proto.id == root_id)
                    .unwrap();
                assert!(root.is_variadic);
                assert_eq!(root.parameter_count, 0);
                assert_eq!(
                    vm.load_module_with_args(&module, &args).unwrap().run().unwrap(),
                    RunOutcome::Returned(expected.to_vec())
                );
                assert_eq!(
                    vm.load_module_with_args_and_error_handler(&module, &args, &handler)
                        .unwrap()
                        .run()
                        .unwrap(),
                    RunOutcome::Returned(expected.to_vec())
                );
            }
            let resumed_require = engine
                .compile(
                    b"package.preload.p17_entry_loader = function() return { value = 23 } end\nlocal loaded = require('p17_entry_loader')\nlocal after = 19\nreturn loaded.value, after",
                )
                .unwrap();
            assert_eq!(
                vm.load_module_with_args_and_error_handler(&resumed_require, &[], &handler)
                    .unwrap()
                    .run()
                    .unwrap(),
                RunOutcome::Returned(vec![Value::Integer(23), Value::Integer(19)]),
                "require 的內部 searcher 返回後須續行原入口剩餘語句"
            );
            assert_eq!(calls.get(), 1);

            let callable_module = engine
                .compile(
                    b"return function(a,b) local n=(function() return 7 end)(); return n,a,b end",
                )
                .unwrap();
            let RunOutcome::Returned(function_values) =
                vm.load_module(&callable_module).unwrap().run().unwrap()
            else {
                panic!("須取得可直接呼叫的函式");
            };
            let function = vm.root(function_values[0]).unwrap();
            assert_eq!(
                vm.call_with_error_handler(&function, &args, &handler)
                    .unwrap()
                    .run()
                    .unwrap(),
                RunOutcome::Returned(vec![Value::Integer(7), args[0], args[1]])
            );
            drop(function);

            let failed = engine
                .compile_named(
                    b"local debug = require'debug'\nlocal function helper() return 7 end\nlocal nested = helper()\nerror('entry failure')",
                    b"@p17-entry-error.lua",
                )
                .unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&failed, &[], &handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("原入口錯誤須交 handler，再回傳 LuaError");
            };
            assert_eq!(error.value, Value::Integer(41));
            assert_eq!(calls.get(), 2);
        }
    }

    struct EntryOutput(Rc<RefCell<Vec<Vec<u8>>>>);

    impl HostOutput for EntryOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            self.0.borrow_mut().push(bytes.to_vec());
            Ok(())
        }
    }

    struct FailingEntryOutput(Rc<RefCell<Vec<Vec<u8>>>>);

    impl HostOutput for FailingEntryOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            if bytes == b"later\n" {
                return Err(HostOutputError::WriteFailed);
            }
            self.0.borrow_mut().push(bytes.to_vec());
            Ok(())
        }
    }

    struct EntryExitOs;

    impl HostOs for EntryExitOs {
        fn authorize(
            &mut self,
            operation: HostOsOperation<'_>,
            budget: &mut ResourceBudget<'_>,
        ) -> Result<(), HostResourceError> {
            budget.spend_work(1)?;
            if matches!(operation, HostOsOperation::Exit(_)) {
                Ok(())
            } else {
                Err(HostResourceError::new(
                    HostResourceErrorKind::PolicyDenied,
                    Vec::new(),
                ))
            }
        }

        fn perform(
            &mut self,
            operation: HostOsOperation<'_>,
            budget: &mut ResourceBudget<'_>,
        ) -> Result<HostOsValue, HostResourceError> {
            budget.spend_work(1)?;
            let HostOsOperation::Exit(request) = operation else {
                return Err(HostResourceError::new(
                    HostResourceErrorKind::PolicyDenied,
                    Vec::new(),
                ));
            };
            Ok(HostOsValue::ExitRequest(request))
        }
    }

    struct EntryDeadline;

    impl HostDeadline for EntryDeadline {
        fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
            budget.spend_work(1)
        }
    }

    #[test]
    fn p17_host_entry_handler_precedes_close_and_releases_roots() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let engine = Engine::new(profile);
            let mut vm = engine
                .new_vm_with_services(HostServices::with_output(EntryOutput(Rc::clone(&events))))
                .unwrap();
            let ledger = vm.runtime.ledger_probe();
            let marker = vm.new_table().unwrap();
            let marker_value = marker.value(&vm).unwrap();
            let handler_events = Rc::clone(&events);
            let handler = vm
                .register_callback(
                    &[marker_value],
                    Rc::new(move |ctx, _| {
                        handler_events.borrow_mut().push(b"handler".to_vec());
                        CallbackResult::Return(vec![ctx.capture(0).unwrap()])
                    }),
                )
                .unwrap();
            let plain_error = engine.compile(b"error('plain')").unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&plain_error, &[], &handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("無 close 的 handler 結果應是 LuaError");
            };
            assert_eq!(error.value, marker_value);
            drop(error);
            events.borrow_mut().clear();
            let module = engine
                .compile_named(
                    b"local x <close> = setmetatable({}, {__close=function() print('close') end})\nerror('first')",
                    b"@p17-entry-close.lua",
                )
                .unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&module, &[], &handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("handler 結果須保留為 LuaError");
            };
            assert_eq!(error.value, marker_value);
            assert_eq!(
                events.borrow().as_slice(),
                [b"handler".as_slice(), b"close\n"]
            );
            drop(error);

            events.borrow_mut().clear();
            let close_error = engine
                .compile_named(
                    b"local earlier <close> = setmetatable({}, {__close=function() print('earlier') end})\nlocal later <close> = setmetatable({}, {__close=function() print('later'); error('late') end})\nerror('first')",
                    b"@p17-entry-close-error.lua",
                )
                .unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("關閉錯誤仍須經同一有效 handler");
            };
            assert_eq!(error.value, marker_value);
            assert_eq!(
                events.borrow().as_slice(),
                [b"handler".as_slice(), b"later\n", b"handler", b"earlier\n",]
            );
            drop(error);

            events.borrow_mut().clear();
            let coroutine_handler_module = engine
                .compile(
                    b"local co=coroutine.create(function() collectgarbage('collect'); coroutine.yield(3); collectgarbage('collect'); return 4 end)\nreturn function(e) local ok,n=coroutine.resume(co); assert(ok); print(n); return e end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&coroutine_handler_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得有 coroutine 狀態的 Lua handler");
            };
            let coroutine_handler = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &coroutine_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("coroutine resume 不可結束外層 close walker");
            };
            assert_eq!(
                events.borrow().as_slice(),
                [b"3\n".as_slice(), b"later\n", b"4\n", b"earlier\n",]
            );
            drop(error);
            drop(coroutine_handler);

            events.borrow_mut().clear();
            let gc_handler_module = engine
                .compile(b"return function(e) collectgarbage('collect'); return e end")
                .unwrap();
            let RunOutcome::Returned(handler_values) =
                vm.load_module(&gc_handler_module).unwrap().run().unwrap()
            else {
                panic!("須取得會觸發 GC 的 Lua handler");
            };
            let gc_handler = vm.root(handler_values[0]).unwrap();
            let gc_marker = vm.new_table().unwrap();
            let gc_marker_value = gc_marker.value(&vm).unwrap();
            let gc_module = engine
                .compile(
                    b"local x <close> = setmetatable({}, {__close=function() print('gc-close') end}); collectgarbage('collect'); error(...)"
                )
                .unwrap();
            let mut execution = vm
                .load_module_with_args_and_error_handler(
                    &gc_module,
                    &[gc_marker_value],
                    &gc_handler,
                )
                .unwrap();
            drop(gc_marker);
            let outcome = execution.run().unwrap();
            drop(execution);
            let RunOutcome::LuaError(error) = outcome else {
                panic!("GC 期間的錯誤物件須保留到宿主接收");
            };
            vm.collect().unwrap();
            assert_eq!(error.value, gc_marker_value);
            assert_eq!(events.borrow().as_slice(), [b"gc-close\n".as_slice()]);
            drop(error);
            drop(gc_handler);

            events.borrow_mut().clear();
            let xpcall_close = engine
                .compile(
                    b"local ok,e=xpcall(function() local x <close> = setmetatable({}, {__close=function() print('xclose') end}); error('boom') end, function(e) print('xhandler'); return e end); return ok",
                )
                .unwrap();
            assert_eq!(
                vm.load_module(&xpcall_close).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![Value::Boolean(false)])
            );
            assert_eq!(
                events.borrow().as_slice(),
                [b"xhandler\n".as_slice(), b"xclose\n"]
            );

            events.borrow_mut().clear();
            let closing_handler_module = engine
                .compile(
                    b"return function(e) local x <close> = setmetatable({}, {__close=function() print('handler-close') end}); return e end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&closing_handler_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得帶 close 的 Lua handler");
            };
            let closing_handler = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &closing_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("handler 的 close 不可中斷外層 close walker");
            };
            assert_eq!(
                events.borrow().as_slice(),
                [
                    b"handler-close\n".as_slice(),
                    b"later\n",
                    b"handler-close\n",
                    b"earlier\n",
                ]
            );
            drop(error);
            drop(closing_handler);

            events.borrow_mut().clear();
            let throwing_handler_module = engine
                .compile(
                    b"local count=0\nreturn function(e) count=count+1; if count==1 then local x <close> = setmetatable({}, {__close=function() print('handler-error-close') end}); error('handler-fail') end; print('retry'); return e end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&throwing_handler_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得第一次會失敗的 Lua handler");
            };
            let throwing_handler = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &throwing_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("handler 自身失敗仍須關閉其 TBC 並繼續外層關閉");
            };
            assert_eq!(
                events.borrow().as_slice(),
                [
                    b"handler-error-close\n".as_slice(),
                    b"retry\n",
                    b"later\n",
                    b"retry\n",
                    b"earlier\n",
                ]
            );
            drop(error);
            drop(throwing_handler);

            events.borrow_mut().clear();
            let throwing_closer_module = engine
                .compile(
                    b"local count=0\nreturn function(e) count=count+1; if count==1 then local x <close> = setmetatable({}, {__close=function() print('handler-close-throws'); error('handler-close-fail') end}); error('handler-fail') end; print('retry'); return e end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&throwing_closer_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得關閉期間再次出錯的 Lua handler");
            };
            let throwing_closer = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &throwing_closer)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("handler 的 TBC 錯誤仍須交 handler 並完成外層 close");
            };
            assert_eq!(
                events.borrow().as_slice(),
                [
                    b"handler-close-throws\n".as_slice(),
                    b"retry\n",
                    b"later\n",
                    b"retry\n",
                    b"earlier\n",
                ]
            );
            drop(error);
            drop(throwing_closer);

            let recursive_closer_module = engine
                .compile(
                    b"return function(e) local x <close> = setmetatable({}, {__close=function() error('close-loop') end}); error('again') end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&recursive_closer_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得持續失敗的 close handler");
            };
            let recursive_closer = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&plain_error, &[], &recursive_closer)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("巢狀錯誤處理須在既有上限返回 LuaError");
            };
            assert_eq!(error.kind, RuntimeErrorKind::ErrorHandlerLoop);
            drop(error);
            drop(recursive_closer);

            events.borrow_mut().clear();
            let nested_closer_module = engine
                .compile(
                    b"local count=0\nreturn function(e) count=count+1; if count==2 then local x <close> = setmetatable({}, {__close=function() print('nested-handler-close'); error('nested-close-fail') end}); error('handler-fail') end; print('retry'); return e end",
                )
                .unwrap();
            let RunOutcome::Returned(handler_values) = vm
                .load_module(&nested_closer_module)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("須取得在外層 close 已暫停時再次出錯的 handler");
            };
            let nested_closer = vm.root(handler_values[0]).unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&close_error, &[], &nested_closer)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("兩層暫停 close walker 須依 LIFO 完成");
            };
            assert_eq!(
                events.borrow().as_slice(),
                [
                    b"retry\n".as_slice(),
                    b"later\n",
                    b"nested-handler-close\n",
                    b"retry\n",
                    b"earlier\n",
                ]
            );
            drop(error);
            drop(nested_closer);

            let replacement = vm.new_table().unwrap();
            let replacement_value = replacement.value(&vm).unwrap();
            let handler_attempts = Rc::new(Cell::new(0));
            let attempts = Rc::clone(&handler_attempts);
            let retry_handler = vm
                .register_callback(
                    &[replacement_value],
                    Rc::new(move |ctx, args| {
                        let count = attempts.get();
                        attempts.set(count + 1);
                        if count == 0 {
                            CallbackResult::Throw(ctx.capture(0).unwrap())
                        } else {
                            CallbackResult::Return(vec![args[0]])
                        }
                    }),
                )
                .unwrap();
            let failed = engine.compile(b"error('first')").unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&failed, &[], &retry_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("handler 自身 Lua error 須再經相同有效 handler");
            };
            assert_eq!(handler_attempts.get(), 2);
            assert_eq!(error.value, replacement_value);
            drop(error);
            drop(retry_handler);
            drop(replacement);

            let loop_handler = vm
                .register_callback(
                    &[],
                    Rc::new(|_, _| CallbackResult::Throw(Value::Integer(9))),
                )
                .unwrap();
            let RunOutcome::LuaError(error) = vm
                .load_module_with_args_and_error_handler(&failed, &[], &loop_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("重複失敗的 handler 須在既有上限終止");
            };
            assert_eq!(error.kind, RuntimeErrorKind::ErrorHandlerLoop);
            drop(error);
            drop(loop_handler);

            // 外部 C 回呼停泊期間仍須持有原 handler、錯誤值及 close walker。
            let external_events = Rc::new(RefCell::new(Vec::new()));
            let mut external_vm = engine
                .new_vm_with_services(HostServices::with_output(EntryOutput(Rc::clone(
                    &external_events,
                ))))
                .unwrap();
            let external_ledger = external_vm.runtime.ledger_probe();
            let native = HostFunctionId::new_unique(external_vm.runtime.id()).unwrap();
            let external_handler = external_vm
                .register_callback(
                    &[],
                    Rc::new(move |_, _| CallbackResult::Call {
                        target: Value::CFunction(native),
                        args: vec![],
                        continuation: CallbackContinuation::new(
                            vec![],
                            Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                        ),
                    }),
                )
                .unwrap();
            let external_marker = external_vm.new_table().unwrap();
            let external_value = external_marker.value(&external_vm).unwrap();
            let mut outcome = external_vm
                .load_module_with_args_and_error_handler(&close_error, &[], &external_handler)
                .unwrap()
                .run()
                .unwrap();
            for _ in 0..2 {
                let RunOutcome::External(token) = outcome else {
                    panic!("兩次 handler 都須經同一外部 C 續接");
                };
                outcome = external_vm
                    .continue_external(token, ExternalCommand::Return(vec![external_value]))
                    .unwrap();
            }
            let RunOutcome::LuaError(error) = outcome else {
                panic!("外部 handler 完成後仍須回傳 LuaError");
            };
            external_vm.collect().unwrap();
            assert_eq!(error.value, external_value);
            assert_eq!(
                external_events.borrow().as_slice(),
                [b"later\n".as_slice(), b"earlier\n".as_slice()]
            );
            drop(error);
            drop(external_marker);
            drop(external_handler);
            drop(external_vm);
            assert_eq!(external_ledger.snapshot().committed, 0);
            assert_eq!(external_ledger.snapshot().reserved, 0);

            // 既有 HostOutputFailed 是可處理的 Lua error；較早的 close 仍須完成。
            let fatal_events = Rc::new(RefCell::new(Vec::new()));
            let mut fatal_vm = engine
                .new_vm_with_services(HostServices::with_output(FailingEntryOutput(Rc::clone(
                    &fatal_events,
                ))))
                .unwrap();
            let fatal_ledger = fatal_vm.runtime.ledger_probe();
            let fatal_handler = fatal_vm
                .register_callback(
                    &[],
                    Rc::new(|_, args| CallbackResult::Return(vec![args[0]])),
                )
                .unwrap();
            let RunOutcome::LuaError(fatal_error) = fatal_vm
                .load_module_with_args_and_error_handler(&close_error, &[], &fatal_handler)
                .unwrap()
                .run()
                .unwrap()
            else {
                panic!("HostOutputFailed 須遵循既有 Lua error 契約");
            };
            assert_eq!(fatal_error.kind, RuntimeErrorKind::HostOutputFailed);
            assert_eq!(fatal_events.borrow().as_slice(), [b"earlier\n".as_slice()]);
            drop(fatal_error);
            drop(fatal_handler);
            drop(fatal_vm);
            assert_eq!(fatal_ledger.snapshot().committed, 0);
            assert_eq!(fatal_ledger.snapshot().reserved, 0);

            // fuel 真正耗盡不進入 Lua handler，也不執行任何 guest close。
            let fuel_events = Rc::new(RefCell::new(Vec::new()));
            let mut fuel_vm = engine
                .new_vm_with_services(HostServices::with_output(EntryOutput(Rc::clone(
                    &fuel_events,
                ))))
                .unwrap();
            let fuel_ledger = fuel_vm.runtime.ledger_probe();
            let fuel_handler = fuel_vm
                .register_callback(
                    &[],
                    Rc::new(|_, args| CallbackResult::Return(vec![args[0]])),
                )
                .unwrap();
            let mut execution = fuel_vm
                .load_module_with_args_and_error_handler(&close_error, &[], &fuel_handler)
                .unwrap();
            execution.set_fuel(0).unwrap();
            assert_eq!(
                execution.run().unwrap(),
                RunOutcome::Aborted(AbortReason::FuelExhausted)
            );
            drop(execution);
            assert!(fuel_events.borrow().is_empty());
            drop(fuel_handler);
            drop(fuel_vm);
            assert_eq!(fuel_ledger.snapshot().committed, 0);
            assert_eq!(fuel_ledger.snapshot().reserved, 0);

            // 關閉期間後到的批准退出不交給 Lua handler，也不再執行較早的 close。
            let exit_events = Rc::new(RefCell::new(Vec::new()));
            let exit_services = HostServices::with_output(EntryOutput(Rc::clone(&exit_events)))
                .and_resource(
                    ResourceCapability::deny_all()
                        .and_os(EntryExitOs)
                        .and_deadline(EntryDeadline),
                );
            let mut exit_vm = engine.new_vm_with_services(exit_services).unwrap();
            let exit_ledger = exit_vm.runtime.ledger_probe();
            let exit_handler = exit_vm
                .register_callback(
                    &[],
                    Rc::new(|_, args| CallbackResult::Return(vec![args[0]])),
                )
                .unwrap();
            let exit_module = engine
                .compile(
                    b"local earlier <close> = setmetatable({}, {__close=function() print('earlier') end}); local later <close> = setmetatable({}, {__close=function() os.exit(6,false) end}); error('first')",
                )
                .unwrap();
            assert_eq!(
                exit_vm
                    .load_module_with_args_and_error_handler(&exit_module, &[], &exit_handler)
                    .unwrap()
                    .run()
                    .unwrap(),
                RunOutcome::Exited(HostExitRequest {
                    status: 6,
                    close: false,
                })
            );
            assert!(exit_events.borrow().is_empty());
            drop(exit_handler);
            drop(exit_vm);
            assert_eq!(exit_ledger.snapshot().committed, 0);
            assert_eq!(exit_ledger.snapshot().reserved, 0);

            drop(handler);
            drop(marker);
            drop(vm);
            assert_eq!(ledger.snapshot().committed, 0);
            assert_eq!(ledger.snapshot().reserved, 0);
        }
    }
}

#[cfg(test)]
mod p17_exit_shutdown_tests {
    use super::*;
    use rivetlua_core::HostFunctionId;
    use rivetlua_runtime::ObjectKind;
    use std::cell::RefCell;

    struct ExitOs;

    impl HostOs for ExitOs {
        fn authorize(
            &mut self,
            operation: HostOsOperation<'_>,
            budget: &mut ResourceBudget<'_>,
        ) -> Result<(), HostResourceError> {
            budget.spend_work(1)?;
            if matches!(operation, HostOsOperation::Exit(_)) {
                Ok(())
            } else {
                Err(HostResourceError::new(
                    HostResourceErrorKind::PolicyDenied,
                    Vec::new(),
                ))
            }
        }

        fn perform(
            &mut self,
            operation: HostOsOperation<'_>,
            budget: &mut ResourceBudget<'_>,
        ) -> Result<HostOsValue, HostResourceError> {
            budget.spend_work(1)?;
            let HostOsOperation::Exit(request) = operation else {
                return Err(HostResourceError::new(
                    HostResourceErrorKind::PolicyDenied,
                    Vec::new(),
                ));
            };
            Ok(HostOsValue::ExitRequest(request))
        }
    }

    struct ActiveDeadline;

    impl HostDeadline for ActiveDeadline {
        fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
            budget.spend_work(1)
        }
    }

    struct CaptureOutput(Rc<RefCell<Vec<u8>>>);

    impl HostOutput for CaptureOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }
    }

    fn exited_parked_vm(profile: LuaProfile, source: &[u8], output: Rc<RefCell<Vec<u8>>>) -> Vm {
        let services = HostServices::with_output(CaptureOutput(output)).and_resource(
            ResourceCapability::deny_all()
                .and_os(ExitOs)
                .and_deadline(ActiveDeadline),
        );
        let engine = Engine::new(profile);
        let mut vm = engine.new_vm_with_services(services).unwrap();
        let native = HostFunctionId::new_unique(vm.runtime.id()).unwrap();
        vm.set_global(b"native", Value::CFunction(native)).unwrap();
        let module = engine.compile(source).unwrap();
        let RunOutcome::External(token) = vm.load_module(&module).unwrap().run().unwrap() else {
            panic!("主執行須停泊在 C callback");
        };
        let target = vm.runtime.external_event(token).unwrap().args[0];
        assert_eq!(
            vm.runtime
                .call_with_parked_parent(token, target, &[])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Exited(HostExitRequest {
                status: 7,
                close: true,
            })
        );
        vm
    }

    #[test]
    fn p17_exit_shutdown_error_keeps_lua_object_root() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let mut vm = exited_parked_vm(
                profile,
                b"local continued <close> = setmetatable({}, {__close=function() print('CLOSE_CONTINUED') end}); local guard <close> = setmetatable({}, {__close=function() error({tag=17}) end}); native(function() os.exit(7,true) end)",
                Rc::clone(&output),
            );
            let error = vm.finish_shutdown().unwrap_err();
            assert_eq!(&*output.borrow(), b"CLOSE_CONTINUED\n");
            let Value::Object(object) = (match &error {
                SdkError::Lua(error) => error.value,
                other => panic!("應取得 Lua 關閉錯誤：{other:?}"),
            }) else {
                panic!("錯誤物件必須保留原身分");
            };
            vm.runtime.collect_major().unwrap();
            assert_eq!(vm.runtime.object_kind(object), Ok(ObjectKind::Table));
            drop(error);
            vm.runtime.collect_major().unwrap();
            assert!(matches!(
                vm.runtime.object_kind(object),
                Err(VmError::StaleObject)
            ));
            let probe = vm.runtime.ledger_probe();
            drop(vm);
            assert_eq!(probe.snapshot().committed, 0);
            assert_eq!(probe.snapshot().reserved, 0);
        }
    }

    #[test]
    fn p17_exit_shutdown_fatal_drop_skips_guest_callbacks() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let mut vm = exited_parked_vm(
                profile,
                b"collectgarbage('stop'); garbage=setmetatable({}, {__gc=function() print('SHOULD_NOT_RUN') end}); local guard <close> = setmetatable({}, {__close=function() return string.rep('x',100) end}); native(function() os.exit(7,true) end)",
                Rc::clone(&output),
            );
            let probe = vm.runtime.ledger_probe();
            let committed = vm.allocation_snapshot().committed;
            vm.set_allocation_limit(committed);
            let error = vm.finish_shutdown().unwrap_err();
            assert!(matches!(error, SdkError::Runtime(_)), "{error:?}");
            vm.set_allocation_limit(usize::MAX);
            drop(vm);
            assert!(output.borrow().is_empty(), "fatal 後不得重跑 GC callback");
            assert_eq!(probe.snapshot().committed, 0);
            assert_eq!(probe.snapshot().reserved, 0);
        }

        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        {
            let profile = if cfg!(feature = "native-lua55") {
                LuaProfile::Lua55
            } else {
                LuaProfile::Lua54
            };
            let output = Rc::new(RefCell::new(Vec::new()));
            let engine = Engine::new(profile);
            let mut vm = engine
                .new_vm_with_native_services(HostServices::with_output(CaptureOutput(Rc::clone(
                    &output,
                ))))
                .unwrap();
            let module = engine
                .compile(
                    b"collectgarbage('stop'); garbage=setmetatable({}, {__gc=function() print('SHOULD_NOT_RUN') end})",
                )
                .unwrap();
            assert_eq!(
                vm.load_module(&module).unwrap().run().unwrap(),
                RunOutcome::Returned(Vec::new())
            );
            let probe = vm.runtime.ledger_probe();
            let committed = vm.allocation_snapshot().committed;
            vm.set_allocation_limit(committed);
            let (mut vm, error) = match vm.try_close_native() {
                Ok(()) => panic!("native shutdown preflight 應拒絕配置"),
                Err(failed) => failed,
            };
            assert!(matches!(error, SdkError::NativeSession(_)), "{error:?}");
            vm.set_allocation_limit(usize::MAX);
            drop(vm);
            assert!(
                output.borrow().is_empty(),
                "native fatal 後不得重跑 GC callback"
            );
            assert_eq!(probe.snapshot().committed, 0);
            assert_eq!(probe.snapshot().reserved, 0);
        }
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

#[cfg(all(test, any(feature = "native-lua55", feature = "native-lua54")))]
mod native_loan_tests {
    use super::*;
    use std::cell::RefCell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    #[test]
    fn p17_native_loan_preserves_vm_and_globals() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mut vm = Engine::new(profile)
            .new_vm_with_native_services(HostServices::deny_all())
            .expect("建立同 VM session");
        vm.set_global(b"loan_identity", Value::Integer(17))
            .expect("寫入 SDK globals");
        let original_id = vm.runtime.id();
        let session = vm.native_session.as_ref().expect("已有 session");
        assert!(matches!(
            session.state_owner().with_vm(|_| ()),
            Err(rivetlua_capi::stack::StackError::Busy)
        ));
        let mut loan = vm.native_loan().expect("移入相同 VM");
        assert_eq!(
            loan.state_owner().with_vm(|runtime| runtime.id()).unwrap(),
            original_id
        );
        loan.try_return().expect("歸還原 VM");
        drop(loan);
        assert_eq!(vm.runtime.id(), original_id);
        assert_eq!(vm.get_global(b"loan_identity").unwrap(), Value::Integer(17));
        vm.try_close_native()
            .unwrap_or_else(|(_, error)| panic!("finalizer 後關閉 session：{error}"));
    }

    #[test]
    fn p17_native_loan_returns_same_vm_after_host_panic() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mut vm = Engine::new(profile)
            .new_vm_with_native_services(HostServices::deny_all())
            .unwrap();
        vm.set_global(b"panic_identity", Value::Integer(23))
            .unwrap();
        let original_id = vm.runtime.id();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let loan = vm.native_loan().unwrap();
            assert_eq!(
                loan.state_owner().with_vm(|runtime| runtime.id()).unwrap(),
                original_id
            );
            panic!("P17_EXPECTED_HOST_PANIC");
        }));
        assert!(panic.is_err());
        assert_eq!(vm.runtime.id(), original_id);
        assert_eq!(
            vm.get_global(b"panic_identity").unwrap(),
            Value::Integer(23)
        );
        vm.try_close_native()
            .unwrap_or_else(|(_, error)| panic!("panic 後關閉 session：{error}"));
    }

    #[test]
    fn p17_native_loan_drop_discards_idle_c_stack() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let engine = Engine::new(profile);
        let module = engine.compile(b"return 1").unwrap();
        let mut vm = engine
            .new_vm_with_native_services(HostServices::deny_all())
            .unwrap();
        let original_id = vm.runtime.id();
        let probe = vm.runtime.ledger_probe();
        let marker = Rc::new(());
        let weak = Rc::downgrade(&marker);
        let loan = vm.native_loan().unwrap();
        loan.state_owner()
            .reserve_native_lease(1)
            .unwrap()
            .publish(marker)
            .unwrap();
        loan.state_owner()
            .push_verified_module(module.verified.as_ref().clone())
            .unwrap();
        drop(loan);
        assert_eq!(vm.runtime.id(), original_id);
        vm.set_global(b"idle_stack_returned", Value::Integer(1))
            .unwrap();
        assert_eq!(
            vm.get_global(b"idle_stack_returned").unwrap(),
            Value::Integer(1)
        );
        drop(vm);
        assert!(weak.upgrade().is_none());
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    #[test]
    fn p17_native_loan_panic_discards_idle_c_stack() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let engine = Engine::new(profile);
        let module = engine.compile(b"return 1").unwrap();
        let mut vm = engine
            .new_vm_with_native_services(HostServices::deny_all())
            .unwrap();
        let original_id = vm.runtime.id();
        let probe = vm.runtime.ledger_probe();
        let marker = Rc::new(());
        let weak = Rc::downgrade(&marker);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let loan = vm.native_loan().unwrap();
            loan.state_owner()
                .reserve_native_lease(1)
                .unwrap()
                .publish(marker)
                .unwrap();
            loan.state_owner()
                .push_verified_module(module.verified.as_ref().clone())
                .unwrap();
            panic!("P17_EXPECTED_DIRTY_STACK_PANIC");
        }));
        assert!(panic.is_err());
        assert_eq!(vm.runtime.id(), original_id);
        vm.set_global(b"panic_stack_returned", Value::Integer(1))
            .unwrap();
        assert_eq!(
            vm.get_global(b"panic_stack_returned").unwrap(),
            Value::Integer(1)
        );
        drop(vm);
        assert!(weak.upgrade().is_none());
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    #[test]
    fn p17_native_close_failure_returns_vm_for_retry() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mut vm = Engine::new(profile)
            .new_vm_with_native_services(HostServices::deny_all())
            .unwrap();
        let id = vm.runtime.id();
        let baseline = vm.allocation_snapshot();
        vm.set_allocation_limit(baseline.committed);
        let (mut vm, error) = match vm.try_close_native() {
            Ok(()) => panic!("配置上限應在 shutdown preflight 拒絕關閉"),
            Err(failed) => failed,
        };
        assert!(matches!(error, SdkError::NativeSession(_)));
        assert_eq!(vm.runtime.id(), id);
        assert!(vm.native_session.is_some());
        vm.set_allocation_limit(usize::MAX);
        vm.try_close_native()
            .unwrap_or_else(|(_, error)| panic!("解除配置故障後關閉失敗：{error}"));
    }

    #[test]
    fn p17_native_drop_failure_releases_vm_and_library_lease() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mut vm = Engine::new(profile)
            .new_vm_with_native_services(HostServices::deny_all())
            .unwrap();
        let marker = Rc::new(());
        let weak = Rc::downgrade(&marker);
        let mut loan = vm.native_loan().unwrap();
        loan.state_owner()
            .reserve_native_lease(17)
            .unwrap()
            .publish(marker)
            .unwrap();
        loan.try_return().unwrap();
        drop(loan);
        let probe = vm.runtime.ledger_probe();
        let committed = vm.allocation_snapshot().committed;
        vm.set_allocation_limit(committed);
        drop(vm);
        assert!(weak.upgrade().is_none());
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    #[test]
    fn p17_native_shutdown_handles_guest_finalizer_error() {
        struct FinalizerOutput(Rc<RefCell<Vec<u8>>>);

        impl HostOutput for FinalizerOutput {
            fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
                self.0.borrow_mut().extend_from_slice(bytes);
                Ok(())
            }
        }

        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let engine = Engine::new(profile);
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut vm = engine
            .new_vm_with_native_services(HostServices::with_output(FinalizerOutput(Rc::clone(
                &output,
            ))))
            .unwrap();
        let probe = vm.runtime.ledger_probe();
        let module = engine
            .compile(
                b"finalizable=setmetatable({}, {__gc=function() print('P17_GC_RAN'); error('P17_EXPECTED_GC_ERROR') end}); return 1",
            )
            .unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        drop(vm);
        assert!(
            output
                .borrow()
                .windows(b"P17_GC_RAN".len())
                .any(|bytes| bytes == b"P17_GC_RAN")
        );
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
