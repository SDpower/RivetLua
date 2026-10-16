#![forbid(unsafe_code)]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("native-lua55 與 native-lua54 不可同時啟用");

pub mod package_runner;

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
mod native_grant;
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
mod trusted_host;

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
use rivetlua::{ExternalCommand, ForeignNativeKind};
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub use rivetlua_capi::native::{AttestedNative, VerifiedNative};
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
use rivetlua_capi::native::{self, NativeLibrary, SymbolVisibility};
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
use std::ffi::CString;
use std::rc::Rc;

use rivetlua::{
    AbortReason, CallbackContext, CallbackContinuation, CallbackFn, CallbackResult, CompileBudget,
    ContainerLimits, DebugCapability, DebugPermission, DumpCapability,
    DumpLimits, Engine, FileOperation, FileReadFormat, FileSeekOrigin, HostCloseResult,
    HostDeadline, HostEntropy, HostEntropyError, HostExitRequest, HostFileLease, HostIo,
    HostLoadError, HostLoadErrorKind, HostModuleBytes, HostModuleRepository, HostOs,
    HostOsOperation, HostOsValue, HostOutput, HostOutputError, HostResourceError,
    HostResourceErrorKind, HostServices, HostSourceReader, HostWarning, HostWarningError,
    InputFormat, LoadBudget, LoadCapability, LoadFormat, LoadLimits, LuaProfile, Module,
    ResourceBudget, ResourceCapability, RunOutcome, RuntimeErrorKind, SdkError, TransportBudget,
    Value, Vm, VmError,
};

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_READER_BYTES: usize = 4 * 1024 * 1024;
const MAX_HOST_LOAD_TEMPORARY_BYTES: usize = 256 * 1024 * 1024;
const MAX_HOST_LOAD_WORK_UNITS: usize = 2 * 1024 * 1024 * 1024;
const CLI_EXECUTION_FUEL: u64 = 8_000_000_000;
const MAX_SCRIPT_ARGUMENTS: i64 = 1_000_000;
const READ_CHUNK_BYTES: usize = 1024;
const DEFAULT_LUA_PATH: &[u8] = b"./?.lua;./?/init.lua";
const DEFAULT_LUA_CPATH: &[u8] = b"";

struct StandaloneSignal {
    active: AtomicBool,
    seen: AtomicBool,
    pending: Arc<AtomicBool>,
}

impl StandaloneSignal {
    fn record_interrupt(&self) -> bool {
        if !self.active.load(Ordering::Acquire) || self.seen.swap(true, Ordering::AcqRel) {
            return true;
        }
        self.pending.store(true, Ordering::Release);
        false
    }
}

static STANDALONE_SIGNAL: OnceLock<Arc<StandaloneSignal>> = OnceLock::new();

thread_local! {
    static CURRENT_STANDALONE_SIGNAL: RefCell<Option<Arc<StandaloneSignal>>> = const { RefCell::new(None) };
}

struct StandaloneSignalSession(Arc<StandaloneSignal>);

impl StandaloneSignalSession {
    fn install() -> CliResult<Self> {
        let signal = if let Some(existing) = STANDALONE_SIGNAL.get() {
            existing.clone()
        } else {
            let signal = Arc::new(StandaloneSignal {
                active: AtomicBool::new(false),
                seen: AtomicBool::new(false),
                pending: Arc::new(AtomicBool::new(false)),
            });
            let handler_signal = signal.clone();
            ctrlc::set_handler(move || {
                if handler_signal.record_interrupt() {
                    std::process::exit(130);
                }
            })
            .map_err(|error| CliFailure::failed(format!("SIGINT 處理器初始化失敗：{error}")))?;
            STANDALONE_SIGNAL
                .set(signal.clone())
                .map_err(|_| CliFailure::failed("SIGINT 處理器重複初始化"))?;
            signal
        };
        CURRENT_STANDALONE_SIGNAL.with(|current| *current.borrow_mut() = Some(signal.clone()));
        Ok(Self(signal))
    }
}

impl Drop for StandaloneSignalSession {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
        self.0.pending.store(false, Ordering::Release);
        self.0.seen.store(false, Ordering::Release);
        CURRENT_STANDALONE_SIGNAL.with(|current| *current.borrow_mut() = None);
    }
}

struct SignalEpochGuard(Option<Arc<StandaloneSignal>>);

impl SignalEpochGuard {
    fn begin() -> Self {
        let signal = CURRENT_STANDALONE_SIGNAL.with(|current| current.borrow().clone());
        let Some(signal) = signal else {
            return Self(None);
        };
        if signal.active.load(Ordering::Acquire) {
            return Self(None);
        }
        signal.pending.store(false, Ordering::Release);
        signal.seen.store(false, Ordering::Release);
        signal.active.store(true, Ordering::Release);
        Self(Some(signal))
    }
}

impl Drop for SignalEpochGuard {
    fn drop(&mut self) {
        if let Some(signal) = &self.0 {
            signal.active.store(false, Ordering::Release);
            signal.pending.store(false, Ordering::Release);
            signal.seen.store(false, Ordering::Release);
        }
    }
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
struct NativeBridge<'a> {
    grant: Option<native_grant::NativeGrant>,
    attestor: Option<&'a mut dyn FnMut(VerifiedNative) -> AttestedNative>,
    loaded: Vec<(PathBuf, Rc<NativeLibrary>)>,
    cache_root: PathBuf,
}

#[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
struct NativeBridge<'a>(std::marker::PhantomData<&'a ()>);

#[derive(Debug)]
struct CliFailure {
    status: u8,
    message: Vec<u8>,
    requested_exit: Option<HostExitRequest>,
}

type CliResult<T> = Result<T, CliFailure>;

struct CliErrorHandler {
    root: rivetlua::Root,
    program_name: Vec<u8>,
}

fn cli_error_handler(vm: &mut Vm, program_name: &[u8], tostring: &rivetlua::Root) -> CliResult<CliErrorHandler> {
    let mut roots = Vec::new();
    for kind in ["nil", "boolean", "table", "userdata", "thread", "function", "number"] {
        roots.push(vm.new_string(format!("(error object is a {kind} value)").as_bytes()).map_err(sdk_failure)?);
    }
    let invalid_result = vm.new_string(b"'__tostring' must return a string").map_err(sdk_failure)?;
    let mut captures = vec![tostring.value(vm).map_err(sdk_failure)?];
    for root in &roots {
        captures.push(root.value(vm).map_err(sdk_failure)?);
    }
    captures.push(invalid_result.value(vm).map_err(sdk_failure)?);
    let continuation: Rc<CallbackFn> = Rc::new(|ctx: &mut CallbackContext<'_>, values: &[Value]| {
        let value = values.first().copied().unwrap_or(Value::Nil);
        match ctx.value_type(value) {
            Ok("string") => CallbackResult::Return(vec![value]),
            Ok(_) => CallbackResult::Throw(ctx.capture(1).unwrap_or(Value::Nil)),
            Err(_) => CallbackResult::Return(Vec::new()),
        }
    });
    let callback: Rc<CallbackFn> = Rc::new(move |ctx: &mut CallbackContext<'_>, values: &[Value]| {
        let value = values.first().copied().unwrap_or(Value::Nil);
        let kind = match ctx.value_type(value) {
            Ok(kind) => kind,
            Err(_) => return CallbackResult::Return(Vec::new()),
        };
        let method = match ctx.raw_metamethod(value, b"__tostring") {
            Ok(method) => method,
            Err(_) => return CallbackResult::Return(Vec::new()),
        };
        if method != Value::Nil {
            return ctx.call(method, vec![value], CallbackContinuation::new(vec![value, ctx.capture(8).unwrap_or(Value::Nil)], Rc::clone(&continuation)));
        }
        if kind == "string" {
            return CallbackResult::Return(vec![value]);
        }
        if kind == "number" {
            return ctx.call(ctx.capture(0).unwrap_or(Value::Nil), vec![value], CallbackContinuation::new(vec![value, ctx.capture(8).unwrap_or(Value::Nil)], Rc::clone(&continuation)));
        }
        let index = match kind {
            "nil" => 1, "boolean" => 2, "table" => 3, "userdata" => 4,
            "thread" => 5, "function" => 6, _ => 7,
        };
        CallbackResult::Return(vec![ctx.capture(index).unwrap_or(Value::Nil)])
    });
    let root = vm.register_callback(&captures, callback).map_err(sdk_failure)?;
    Ok(CliErrorHandler { root, program_name: program_name.to_vec() })
}

impl CliFailure {
    fn usage(message: impl ToString) -> Self {
        Self {
            status: 2,
            message: message.to_string().into_bytes(),
            requested_exit: None,
        }
    }

    fn failed(message: impl ToString) -> Self {
        Self {
            status: 1,
            message: message.to_string().into_bytes(),
            requested_exit: None,
        }
    }

    fn exited(request: HostExitRequest) -> Self {
        Self {
            status: 0,
            message: Vec::new(),
            requested_exit: Some(request),
        }
    }
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
impl NativeBridge<'_> {
    fn from_env(
        profile: LuaProfile,
        attestor: Option<&mut dyn FnMut(VerifiedNative) -> AttestedNative>,
    ) -> CliResult<NativeBridge<'_>> {
        let grant = native_grant::NativeGrant::from_env(profile).map_err(CliFailure::failed)?;
        if let Some(grant) = &grant {
            grant.preflight_all().map_err(CliFailure::failed)?;
            if attestor.is_none() {
                return Err(CliFailure::failed(
                    "native-grant: 宿主未提供 CNoUnwind attestator",
                ));
            }
        }
        Ok(NativeBridge {
            grant,
            attestor,
            loaded: Vec::new(),
            cache_root: std::env::temp_dir(),
        })
    }

    fn grant_cpath(&self) -> Option<Vec<u8>> {
        self.grant
            .as_ref()
            .map(native_grant::NativeGrant::cpath_bytes)
    }

    fn ensure_loaded(&mut self, vm: &mut Vm, index: usize) -> Result<Rc<NativeLibrary>, String> {
        let grant = self.grant.as_ref().ok_or("native grant 未授權")?;
        let module = grant
            .modules
            .get(index)
            .ok_or("native grant 模組索引無效")?;
        if let Some((_, lease)) = self.loaded.iter().find(|(path, _)| *path == module.path) {
            return Ok(Rc::clone(lease));
        }
        let path = module.path.clone();
        let dependency_paths = module.dependencies.clone();
        let mut dependencies = Vec::with_capacity(dependency_paths.len());
        for path in dependency_paths {
            let dependency_index = self
                .grant
                .as_ref()
                .ok_or("native grant 未授權")?
                .modules
                .iter()
                .position(|entry| entry.path == path)
                .ok_or("native grant dependency 遺失")?;
            dependencies.push(self.ensure_loaded(vm, dependency_index)?);
        }
        let verified = self
            .grant
            .as_ref()
            .ok_or("native grant 未授權")?
            .preflight_module(&self.grant.as_ref().ok_or("native grant 未授權")?.modules[index])?;
        let attestor = self
            .attestor
            .as_deref_mut()
            .ok_or("native host attestator 遺失")?;
        let attested = attestor(verified);
        let mut loan = vm
            .native_loan()
            .map_err(|error| format!("native VM loan 失敗：{error}"))?;
        let result = native::load_and_bind(
            loan.state_owner(),
            attested,
            &self.cache_root,
            None,
            &dependencies,
        )
        .map_err(|error| format!("native-grant: load {} 失敗：{error:?}", path.display()));
        loan.try_return()
            .map_err(|error| format!("native VM 歸還失敗：{error}"))?;
        let (lease, _) = result?;
        self.loaded.push((path, Rc::clone(&lease)));
        Ok(lease)
    }

    fn load_opener(
        &mut self,
        vm: &mut Vm,
        candidate: &Path,
        symbol: &[u8],
    ) -> Result<Value, String> {
        let grant = self.grant.as_ref().ok_or("native grant 未授權")?;
        let module = grant.match_candidate(candidate)?;
        let index = grant
            .modules
            .iter()
            .position(|entry| entry.path == module.path)
            .ok_or("native grant 模組索引遺失")?;
        let symbol_name = std::str::from_utf8(symbol).map_err(|_| "native symbol 非 UTF-8")?;
        if !module.exports.iter().any(|export| export == symbol_name) {
            return Err(format!(
                "native-grant: symbol {symbol_name} 不在 export 白名單"
            ));
        }
        let lease = self.ensure_loaded(vm, index)?;
        let symbol = CString::new(symbol).map_err(|_| "native symbol 含 NUL")?;
        let opener = lease
            .bind_symbol(&symbol)
            .map_err(|error| format!("native-grant: symbol 查詢失敗：{error:?}"))?;
        let mut loan = vm
            .native_loan()
            .map_err(|error| format!("native VM loan 失敗：{error}"))?;
        let value = loan
            .state_owner()
            .bind_native_opener(&opener)
            .map_err(|error| format!("native opener 綁定失敗：{error:?}"));
        loan.try_return()
            .map_err(|error| format!("native VM 歸還失敗：{error}"))?;
        value
    }
}

/// 將已預檢的原生授權綁定至單一 VM，由宿主提供 CNoUnwind attestor。
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub struct NativeDriver<'a> {
    bridge: NativeBridge<'a>,
    profile: LuaProfile,
    vm_root: Option<rivetlua::Root>,
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
impl<'a> NativeDriver<'a> {
    pub fn from_path(
        profile: LuaProfile,
        grant_path: &Path,
        cache_root: &Path,
        attestor: &'a mut dyn FnMut(VerifiedNative) -> AttestedNative,
    ) -> Result<Self, String> {
        let grant = native_grant::NativeGrant::read(grant_path, profile)?;
        grant.preflight_all()?;
        if !cache_root.is_absolute()
            || !cache_root.is_dir()
            || cache_root.as_os_str().as_encoded_bytes().len() > native::MAX_PATH_BYTES / 2
        {
            return Err("native cache root 必須是長度可接受的絕對目錄".into());
        }
        Ok(Self {
            bridge: NativeBridge {
                grant: Some(grant),
                attestor: Some(attestor),
                loaded: Vec::new(),
                cache_root: cache_root.to_path_buf(),
            },
            profile,
            vm_root: None,
        })
    }

    pub fn initial_cpath(&self) -> Vec<u8> {
        self.bridge.grant_cpath().unwrap_or_default()
    }

    pub(crate) fn check_tree(&self, profile: LuaProfile, tree: &Path) -> Result<(), String> {
        if profile != self.profile {
            return Err("native-grant: profile 與 runner 不符".into());
        }
        let lib = tree.join("lib/lua").join(match profile {
            LuaProfile::Lua54 => "5.4",
            LuaProfile::Lua55 => "5.5",
        });
        let meta = fs::symlink_metadata(&lib).map_err(|_| "native-grant: tree 原生目錄缺失")?;
        if !meta.is_dir() || meta.file_type().is_symlink()
            || fs::canonicalize(&lib).map_err(|_| "native-grant: tree 原生目錄不可讀")? != lib
        {
            return Err("native-grant: tree 原生目錄不安全".into());
        }
        let grant = self.bridge.grant.as_ref().ok_or("native grant 未授權")?;
        if grant.modules.iter().any(|module| !module.path.starts_with(&lib)
            || module.path.extension() != Some(OsStr::new("so")))
            || grant.cpath.iter().any(|template| {
                let path = Path::new(template);
                !path.starts_with(&lib)
                    || path.components().any(|part| matches!(part, std::path::Component::ParentDir))
            })
        {
            return Err("native-grant: 模組或 cpath 不在指定 tree".into());
        }
        Ok(())
    }

    pub fn drive(&mut self, vm: &mut Vm, outcome: RunOutcome) -> Result<RunOutcome, String> {
        if vm.profile() != self.profile {
            return Err("native-grant: profile 與 VM 不符".into());
        }
        if let Some(root) = &self.vm_root {
            root.value(vm)
                .map_err(|_| "native driver 已綁定其他 VM".to_string())?;
        } else {
            let globals = vm.globals().value(vm).map_err(|error| error.to_string())?;
            self.vm_root = Some(vm.root(globals).map_err(|error| error.to_string())?);
        }
        drive_native_external(vm, outcome, &mut self.bridge).map_err(|error| error.to_string())
    }
}

impl std::fmt::Display for CliFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.message))
    }
}

#[derive(Debug)]
enum Action {
    Execute(Vec<u8>),
    Require(Vec<u8>),
    WarningOn,
}

#[derive(Debug)]
struct Options {
    profile: LuaProfile,
    ignore_environment: bool,
    show_version: bool,
    interactive: bool,
    actions: Vec<Action>,
    script_index: usize,
    script: Option<OsString>,
    stdin_as_file_after_double_dash: bool,
}

#[cfg(feature = "default-lua54")]
const fn default_profile() -> LuaProfile {
    LuaProfile::Lua54
}

#[cfg(not(feature = "default-lua54"))]
const fn default_profile() -> LuaProfile {
    LuaProfile::Lua55
}

fn os_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn os_from_bytes(value: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(value.to_vec())
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(value).into_owned())
    }
}

fn parse_options(args: &[OsString]) -> CliResult<Options> {
    let mut profile = default_profile();
    let mut ignore_environment = false;
    let mut show_version = false;
    let mut interactive = false;
    let mut actions = Vec::new();
    let mut i = 1;
    let mut stdin_as_file_after_double_dash = false;
    let mut script_index = 0;
    let mut script = None;

    while i < args.len() {
        let bytes = os_bytes(&args[i]);
        if bytes == b"--" {
            if i + 1 < args.len() {
                script_index = i + 1;
                script = Some(args[i + 1].clone());
                stdin_as_file_after_double_dash = os_bytes(&args[i + 1]) == b"-";
            }
            break;
        }
        if bytes == b"-" || !bytes.starts_with(b"-") {
            script_index = i;
            script = Some(args[i].clone());
            break;
        }
        if bytes == b"-E" {
            ignore_environment = true;
        } else if bytes == b"-W" {
            actions.push(Action::WarningOn);
        } else if bytes == b"-v" {
            show_version = true;
        } else if bytes == b"-i" {
            interactive = true;
            show_version = true;
        } else if bytes == b"-e"
            || bytes == b"-l"
            || bytes.starts_with(b"-e")
            || bytes.starts_with(b"-l")
        {
            let is_execute = bytes[1] == b'e';
            let missing_argument = if is_execute {
                "-e 需要程式文字 ('-e' needs argument)"
            } else {
                "-l 需要模組名稱 ('-l' needs argument)"
            };
            let attached = &bytes[2..];
            let value = if attached.is_empty() {
                i += 1;
                let Some(next) = args.get(i) else {
                    return Err(CliFailure::usage(missing_argument.to_string()));
                };
                let next = os_bytes(next);
                if next.starts_with(b"-") {
                    return Err(CliFailure::usage(missing_argument.to_string()));
                }
                next
            } else {
                attached.to_vec()
            };
            actions.push(if is_execute {
                Action::Execute(value)
            } else {
                Action::Require(value)
            });
        } else if bytes == b"--profile" {
            i += 1;
            let Some(value) = args.get(i).map(|arg| os_bytes(arg)) else {
                return Err(CliFailure::usage("--profile 需要 lua54 或 lua55"));
            };
            profile = parse_profile(&value)?;
        } else if bytes.starts_with(b"--profile=") {
            profile = parse_profile(&bytes[b"--profile=".len()..])?;
        } else {
            let flag = String::from_utf8_lossy(&bytes);
            return Err(CliFailure::usage(format!(
                "不支援的選項：{flag} (unrecognized option '{flag}')"
            )));
        }
        i += 1;
    }

    if script.is_none() {
        script_index = 0;
    }
    Ok(Options {
        profile,
        ignore_environment,
        show_version,
        interactive,
        actions,
        script_index,
        script,
        stdin_as_file_after_double_dash,
    })
}

fn parse_profile(value: &[u8]) -> CliResult<LuaProfile> {
    match value {
        b"lua54" => Ok(LuaProfile::Lua54),
        b"lua55" => Ok(LuaProfile::Lua55),
        _ => Err(CliFailure::usage("--profile 只接受 lua54 或 lua55")),
    }
}

struct StdoutOutput;

impl HostOutput for StdoutOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        io::stdout()
            .lock()
            .write_all(bytes)
            .map_err(|_| HostOutputError::WriteFailed)
    }
}

struct OsEntropy;

impl HostEntropy for OsEntropy {
    fn seed(&mut self) -> Result<u64, HostEntropyError> {
        #[cfg(unix)]
        {
            let mut source =
                File::open("/dev/urandom").map_err(|_| HostEntropyError::ReadFailed)?;
            read_entropy_seed(&mut source)
        }
        #[cfg(not(unix))]
        {
            Err(HostEntropyError::ReadFailed)
        }
    }
}

#[cfg(any(unix, test))]
fn read_entropy_seed(source: &mut impl Read) -> Result<u64, HostEntropyError> {
    let mut bytes = [0_u8; 8];
    source
        .read_exact(&mut bytes)
        .map_err(|_| HostEntropyError::ReadFailed)?;
    Ok(u64::from_ne_bytes(bytes))
}

struct CliOs;

impl HostOs for CliOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        match operation {
            HostOsOperation::Clock
            | HostOsOperation::Exit(_)
            | HostOsOperation::Time(None)
            | HostOsOperation::Locale(_, _) => Ok(()),
            _ => Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            )),
        }
    }

    fn authorize_path(
        &mut self,
        _path: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        Err(HostResourceError::new(
            HostResourceErrorKind::PolicyDenied,
            Vec::new(),
        ))
    }

    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        budget.spend_work(1)?;
        match operation {
            HostOsOperation::Exit(request) => Ok(HostOsValue::ExitRequest(request)),
            HostOsOperation::Clock => {
                #[cfg(any(unix, windows))]
                {
                    let process_time = cpu_time::ProcessTime::try_now().map_err(|_| {
                        HostResourceError::new(HostResourceErrorKind::IoFailure, Vec::new())
                    })?;
                    let seconds = process_time.as_duration().as_secs_f64();
                    if !seconds.is_finite() || seconds < 0.0 {
                        return Err(HostResourceError::new(
                            HostResourceErrorKind::IoFailure,
                            Vec::new(),
                        ));
                    }
                    Ok(HostOsValue::Number(seconds))
                }
                #[cfg(not(any(unix, windows)))]
                {
                    Err(HostResourceError::new(
                        HostResourceErrorKind::Unsupported,
                        Vec::new(),
                    ))
                }
            }
            HostOsOperation::Time(None) => Ok(HostOsValue::Time {
                epoch: unix_epoch_seconds(SystemTime::now())?,
                normalized: None,
            }),
            HostOsOperation::Locale(None, _) | HostOsOperation::Locale(Some(b"C"), _) => {
                budget.claim_temporary(1)?;
                Ok(HostOsValue::Bytes(b"C".to_vec()))
            }
            HostOsOperation::Locale(Some(_), _) => Ok(HostOsValue::Nil),
            _ => Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            )),
        }
    }
}

fn unix_epoch_seconds(time: SystemTime) -> Result<i64, HostResourceError> {
    let range_error =
        || HostResourceError::new(HostResourceErrorKind::PlatformDifference, Vec::new());
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).map_err(|_| range_error()),
        Err(error) => {
            let duration = error.duration();
            let magnitude = if duration.subsec_nanos() == 0 {
                duration.as_secs()
            } else {
                duration.as_secs().checked_add(1).ok_or_else(range_error)?
            };
            let min_magnitude = 1_u64 << 63;
            if magnitude > min_magnitude {
                Err(range_error())
            } else if magnitude == min_magnitude {
                Ok(i64::MIN)
            } else {
                Ok(-i64::try_from(magnitude).map_err(|_| range_error())?)
            }
        }
    }
}

struct CliResourceDeadline {
    expires_at: Option<Instant>,
}

impl CliResourceDeadline {
    fn from_now() -> Self {
        Self {
            expires_at: Instant::now().checked_add(Duration::from_secs(3600)),
        }
    }
}

impl HostDeadline for CliResourceDeadline {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        match self.expires_at {
            Some(expires_at) if Instant::now() < expires_at => Ok(()),
            _ => Err(HostResourceError::new(
                HostResourceErrorKind::Deadline,
                Vec::new(),
            )),
        }
    }
}

fn cli_resource_capability(deadline: CliResourceDeadline) -> ResourceCapability {
    ResourceCapability::deny_all()
        .and_os(CliOs)
        .and_io(NoGrantStandardIo)
        .and_deadline(deadline)
}

/// 無 native grant 的 CLI 只將原本可寫的程序 stdout 建為 Lua 標準流。
/// 檔案路徑、暫存檔、管線與其他標準流仍沒有宿主操作權限。
struct NoGrantStandardIo;

#[derive(Clone, Copy, Eq, PartialEq)]
enum NoGrantStandardStream {
    Denied,
    Stdout,
}

struct NoGrantStandardLease {
    stream: NoGrantStandardStream,
}

impl NoGrantStandardIo {
    fn denied() -> HostResourceError {
        HostResourceError::new(HostResourceErrorKind::PolicyDenied, Vec::new())
    }

    fn standard(
        stream: NoGrantStandardStream,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        budget.claim_retained(std::mem::size_of::<NoGrantStandardLease>().max(1))?;
        Ok(Box::new(NoGrantStandardLease { stream }))
    }

    fn output_failure(
        error: io::Error,
        written: Option<usize>,
        budget: &mut ResourceBudget<'_>,
    ) -> HostResourceError {
        const MESSAGE: &[u8] = b"standard output failed";
        if let Err(error) = budget.claim_temporary(MESSAGE.len()) {
            return error;
        }
        let errno = i64::from(error.raw_os_error().unwrap_or(0));
        match written {
            Some(written) => HostResourceError::write_failure(MESSAGE.to_vec(), errno, written),
            None => HostResourceError::io_failure(MESSAGE.to_vec(), errno),
        }
    }
}

impl HostIo for NoGrantStandardIo {
    fn authorize_path(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(path.len().saturating_add(mode.len()).saturating_add(1))?;
        Err(Self::denied())
    }

    fn open(
        &mut self,
        _path: &[u8],
        _mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Err(Self::denied())
    }

    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Self::standard(NoGrantStandardStream::Denied, budget)
    }

    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Self::standard(NoGrantStandardStream::Stdout, budget)
    }

    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Self::standard(NoGrantStandardStream::Denied, budget)
    }

    fn tmpfile(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Err(Self::denied())
    }

    fn authorize_process(
        &mut self,
        command: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(command.len().saturating_add(mode.len()).saturating_add(1))?;
        Err(Self::denied())
    }

    fn popen(
        &mut self,
        _command: &[u8],
        _mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Err(Self::denied())
    }
}

impl Drop for NoGrantStandardLease {
    fn drop(&mut self) {
        if self.stream == NoGrantStandardStream::Stdout {
            let _ = io::stdout().flush();
        }
    }
}

impl HostFileLease for NoGrantStandardLease {
    fn authorize(
        &mut self,
        operation: FileOperation,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if operation == FileOperation::Close
            || (self.stream == NoGrantStandardStream::Stdout
                && matches!(operation, FileOperation::Write | FileOperation::Flush))
        {
            Ok(())
        } else {
            Err(NoGrantStandardIo::denied())
        }
    }

    fn read(
        &mut self,
        _format: FileReadFormat,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError> {
        budget.spend_work(1)?;
        Err(NoGrantStandardIo::denied())
    }

    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError> {
        budget.spend_work(bytes.len().saturating_add(1))?;
        if self.stream != NoGrantStandardStream::Stdout {
            return Err(NoGrantStandardIo::denied());
        }
        let mut output = io::stdout().lock();
        let mut written = 0;
        while written < bytes.len() {
            match output.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(NoGrantStandardIo::output_failure(
                        io::Error::from(io::ErrorKind::WriteZero),
                        Some(written),
                        budget,
                    ));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(NoGrantStandardIo::output_failure(
                        error,
                        Some(written),
                        budget,
                    ));
                }
            }
        }
        Ok(written)
    }

    fn seek(
        &mut self,
        _origin: FileSeekOrigin,
        _offset: i64,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError> {
        budget.spend_work(1)?;
        Err(NoGrantStandardIo::denied())
    }

    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if self.stream != NoGrantStandardStream::Stdout {
            return Err(NoGrantStandardIo::denied());
        }
        io::stdout()
            .flush()
            .map_err(|error| NoGrantStandardIo::output_failure(error, None, budget))
    }

    fn close(
        mut self: Box<Self>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError> {
        budget.spend_work(1)?;
        if self.stream == NoGrantStandardStream::Stdout {
            self.flush(budget)?;
        }
        Ok(HostCloseResult::File)
    }
}

struct FsSourceReader;

impl HostSourceReader for FsSourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        if path.len() > MAX_CANDIDATE_BYTES {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        admit_path_access(path.len(), budget)?;
        with_path_bytes(path, |path| read_path_with_metadata(path, budget))
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut bytes = read_budgeted(&mut input, budget, MAX_READER_BYTES)?;
        preprocess_file_input_budgeted(&mut bytes, budget)?;
        Ok(bytes)
    }
}

fn read_path_with_metadata(
    path: &Path,
    budget: &mut LoadBudget<'_>,
) -> Result<Vec<u8>, HostLoadError> {
    let metadata = fs::metadata(path)
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
    read_path_after_metadata(path, &metadata, budget)
}

fn read_path_after_metadata(
    path: &Path,
    metadata: &Metadata,
    budget: &mut LoadBudget<'_>,
) -> Result<Vec<u8>, HostLoadError> {
    let expected = usize::try_from(metadata.len())
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    if expected > MAX_READER_BYTES {
        return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
    }
    let mut bytes = read_budgeted(
        File::open(path).map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?,
        budget,
        expected,
    )?;
    preprocess_file_input_budgeted(&mut bytes, budget)?;
    Ok(bytes)
}

fn admit_path_access(path_len: usize, budget: &mut LoadBudget<'_>) -> Result<(), HostLoadError> {
    let work = path_len
        .checked_mul(2)
        .and_then(|units| units.checked_add(2))
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    budget.spend_work(work)
}

#[cfg(unix)]
fn with_path_bytes<T>(
    path: &[u8],
    f: impl FnOnce(&Path) -> Result<T, HostLoadError>,
) -> Result<T, HostLoadError> {
    use std::os::unix::ffi::OsStrExt;
    f(Path::new(OsStr::from_bytes(path)))
}

#[cfg(not(unix))]
fn with_path_bytes<T>(
    path: &[u8],
    f: impl FnOnce(&Path) -> Result<T, HostLoadError>,
) -> Result<T, HostLoadError> {
    let path = std::str::from_utf8(path)
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
    f(Path::new(path))
}

fn read_budgeted(
    mut reader: impl Read,
    budget: &mut LoadBudget<'_>,
    allocation_limit: usize,
) -> Result<Vec<u8>, HostLoadError> {
    let chunk_count = allocation_limit
        .checked_add(READ_CHUNK_BYTES - 1)
        .map(|value| value / READ_CHUNK_BYTES)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    let work_upper = chunk_count
        .checked_mul(READ_CHUNK_BYTES + 1)
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    budget.claim_temporary(allocation_limit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(allocation_limit)
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
    if bytes.capacity() > allocation_limit {
        return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
    }
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    let mut work_paid = 0usize;
    loop {
        let next_work = work_paid
            .checked_add(chunk.len() + 1)
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
        if next_work > work_upper {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        budget.spend_work(chunk.len() + 1)?;
        work_paid = next_work;
        let count = reader
            .read(&mut chunk)
            .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
        if count == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(count)
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
        if next > allocation_limit {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

struct FsRepository;

impl HostModuleRepository for FsRepository {
    fn search(
        &mut self,
        _modname: &[u8],
        candidate_path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        if candidate_path.is_empty() || candidate_path.len() > MAX_CANDIDATE_BYTES {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        admit_path_access(candidate_path.len(), budget)?;
        let module = with_path_bytes(candidate_path, |path| {
            let Ok(metadata) = fs::metadata(path) else {
                return Ok(None);
            };
            let length = usize::try_from(metadata.len())
                .map_err(|_| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
            if length > MAX_READER_BYTES {
                return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
            }
            let data = read_path_after_metadata(path, &metadata, budget)?;
            let loader_data = copy_loader_data(candidate_path, budget)?;
            Ok(Some((data, loader_data)))
        })?;
        let Some((data, loader_data)) = module else {
            return Ok(None);
        };
        let format = match rivetlua::classify_input(&data) {
            InputFormat::Source => LoadFormat::Source,
            InputFormat::RawRvlu => LoadFormat::RivetBytecode,
            InputFormat::Official => LoadFormat::OfficialBytecode,
            InputFormat::UnsupportedBinary => return Ok(None),
        };
        Ok(Some(HostModuleBytes {
            data,
            loader_data,
            format,
        }))
    }
}

const MAX_CANDIDATE_BYTES: usize = 4096;

fn copy_loader_data(path: &[u8], budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
    budget
        .claim_temporary(path.len())
        .and_then(|_| budget.spend_work(path.len()))?;
    let mut loader_data = Vec::new();
    loader_data
        .try_reserve_exact(path.len())
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
    if loader_data.capacity() > path.len() {
        return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
    }
    loader_data.extend_from_slice(path);
    Ok(loader_data)
}

fn load_limits() -> LoadLimits {
    LoadLimits {
        max_source_bytes: MAX_READER_BYTES,
        max_encoded_bytes: 64 * 1024 * 1024,
        max_module_allocation_bytes: 64 * 1024 * 1024,
        max_temporary_bytes: MAX_HOST_LOAD_TEMPORARY_BYTES,
        max_work_units: MAX_HOST_LOAD_WORK_UNITS,
        max_reader_chunks: 512,
        max_path_candidates: 512,
    }
}

fn dump_limits() -> DumpLimits {
    DumpLimits {
        max_work_units: 512 * 1024 * 1024,
        max_temporary_bytes: 4 * 1024 * 1024,
        max_encoded_bytes: 1024 * 1024,
    }
}

fn debug_capability() -> DebugCapability {
    DebugCapability::deny_all()
        .allow(DebugPermission::Info)
        .allow(DebugPermission::StackInspection)
        .allow(DebugPermission::LocalInspection)
        .allow(DebugPermission::LocalMutation)
        .allow(DebugPermission::Upvalues)
        .allow(DebugPermission::UpvalueMutation)
        .allow(DebugPermission::UpvalueIdentity)
        .allow(DebugPermission::RegistryRead)
        .allow(DebugPermission::UserValueRead)
        .allow(DebugPermission::UserValueWrite)
        .allow(DebugPermission::Traceback)
        .allow(DebugPermission::CountHook)
        .allow(DebugPermission::EventHook)
        .allow(DebugPermission::MetatableRead)
        .allow(DebugPermission::TableMetatableWrite)
}

fn host_services(engine: &Engine, native_cpath: Option<Vec<u8>>, trusted: bool) -> HostServices {
    let mut load = LoadCapability::deny_all()
        .and_compiler(engine.clone())
        .and_reader(FsSourceReader)
        .and_repository(FsRepository)
        .with_bytecode(true)
        .with_official_bytecode(true)
        .with_limits(load_limits());
    if let Some(cpath) = native_cpath {
        load = load.with_foreign_native_cpath(cpath);
    }
    let dump = DumpCapability::deny_all()
        .with_official_bytecode(true)
        .with_limits(dump_limits());
    let deadline = CliResourceDeadline::from_now();
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let resource = if trusted {
        trusted_host::capability(deadline)
    } else {
        cli_resource_capability(deadline)
    };
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let resource = {
        let _ = trusted;
        cli_resource_capability(deadline)
    };
    HostServices::with_output(StdoutOutput)
        .and_warning(CliWarning::default())
        .and_load(load)
        .and_entropy(OsEntropy)
        .and_resource(resource)
        .and_dump(dump)
        .and_debug(if trusted {
            debug_capability().allow(DebugPermission::Console)
        } else {
            debug_capability()
        })
}

#[derive(Default)]
struct CliWarning {
    enabled: bool,
    continuing: bool,
}

impl HostWarning for CliWarning {
    fn write(&mut self, message: &[u8], tocont: bool) -> Result<(), HostWarningError> {
        // 純 Rust CLI 的一般宿主 sink；native session 優先走 C warning callback。
        if !self.continuing && !tocont && message.starts_with(b"@") {
            match &message[1..] {
                b"on" => self.enabled = true,
                b"off" => self.enabled = false,
                _ => {}
            }
            return Ok(());
        }
        if !self.enabled {
            return Ok(());
        }
        let mut stderr = io::stderr().lock();
        if !self.continuing {
            stderr
                .write_all(b"Lua warning: ")
                .map_err(|_| HostWarningError::WriteFailed)?;
        }
        stderr
            .write_all(message)
            .map_err(|_| HostWarningError::WriteFailed)?;
        if !tocont {
            stderr
                .write_all(b"\n")
                .map_err(|_| HostWarningError::WriteFailed)?;
        }
        self.continuing = tocont;
        Ok(())
    }
}

fn version_line(profile: LuaProfile) -> &'static [u8] {
    match profile {
        LuaProfile::Lua54 => b"RivetLua 0.0.0 (Lua 5.4.9); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n",
        LuaProfile::Lua55 => b"RivetLua 0.0.0 (Lua 5.5.1); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n",
    }
}

fn env_value(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name).map(|value| os_bytes(&value))
}

fn configured_env(profile: LuaProfile, suffix: &str) -> Option<Vec<u8>> {
    let versioned = match profile {
        LuaProfile::Lua54 => format!("LUA_{suffix}_5_4"),
        LuaProfile::Lua55 => format!("LUA_{suffix}_5_5"),
    };
    env_value(&versioned).or_else(|| env_value(&format!("LUA_{suffix}")))
}

fn expand_default_path(value: &[u8], default: &[u8]) -> CliResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut i = 0;
    while i < value.len() {
        if value[i..].starts_with(b";;") {
            let separator_before = !output.is_empty() && output.last() != Some(&b';');
            let separator_after = i + 2 < value.len() && value[i + 2] != b';';
            let next = output
                .len()
                .checked_add(usize::from(separator_before))
                .and_then(|n| n.checked_add(default.len()))
                .and_then(|n| n.checked_add(usize::from(separator_after)))
                .ok_or_else(|| CliFailure::failed("package path 長度溢位"))?;
            if next > MAX_INPUT_BYTES {
                return Err(CliFailure::failed("package path 超出上限"));
            }
            if separator_before {
                output.push(b';');
            }
            output.extend_from_slice(default);
            if separator_after {
                output.push(b';');
            }
            i += 2;
        } else {
            output.push(value[i]);
            i += 1;
        }
    }
    Ok(output)
}

fn set_package_field(vm: &mut Vm, field: &[u8], value: &[u8]) -> CliResult<()> {
    let package = vm.get_global(b"package").map_err(sdk_failure)?;
    let package = vm.root(package).map_err(sdk_failure)?;
    let key = vm.new_string(field).map_err(sdk_failure)?;
    let value = vm.new_string(value).map_err(sdk_failure)?;
    vm.table_raw_set(
        &package,
        key.value(vm).map_err(sdk_failure)?,
        value.value(vm).map_err(sdk_failure)?,
    )
    .map_err(sdk_failure)
}

fn configure_package_paths(
    vm: &mut Vm,
    options: &Options,
    native_cpath: Option<&[u8]>,
) -> CliResult<()> {
    let path = if options.ignore_environment {
        DEFAULT_LUA_PATH.to_vec()
    } else {
        expand_default_path(
            configured_env(options.profile, "PATH")
                .as_deref()
                .unwrap_or(b";;"),
            DEFAULT_LUA_PATH,
        )?
    };
    let default_cpath = native_cpath.unwrap_or(DEFAULT_LUA_CPATH);
    let cpath = if options.ignore_environment {
        default_cpath.to_vec()
    } else {
        expand_default_path(
            configured_env(options.profile, "CPATH")
                .as_deref()
                .unwrap_or(b";;"),
            default_cpath,
        )?
    };
    set_package_field(vm, b"path", &path)?;
    set_package_field(vm, b"cpath", &cpath)
}

fn set_arg_table(vm: &mut Vm, args: &[OsString], script_index: usize) -> CliResult<rivetlua::Root> {
    let table = vm.new_table().map_err(sdk_failure)?;
    let script_index =
        i64::try_from(script_index).map_err(|_| CliFailure::failed("script index 溢位"))?;
    for (index, arg) in args.iter().enumerate() {
        let lua_index = i64::try_from(index)
            .ok()
            .and_then(|value| value.checked_sub(script_index))
            .ok_or_else(|| CliFailure::failed("命令列參數索引溢位"))?;
        let string = vm.new_string(&os_bytes(arg)).map_err(sdk_failure)?;
        vm.table_raw_set(
            &table,
            Value::Integer(lua_index),
            string.value(vm).map_err(sdk_failure)?,
        )
        .map_err(sdk_failure)?;
    }
    vm.set_global(b"arg", table.value(vm).map_err(sdk_failure)?)
        .map_err(sdk_failure)?;
    Ok(table)
}

fn capture_script_arg_length(
    engine: &Engine,
    vm: &mut Vm,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<rivetlua::Root> {
    let source = br#"
        local saved_type = type
        local saved_tointeger = math.tointeger
        local saved_error = error
        return function(value)
            if saved_type(value) ~= 'table' then
                saved_error("'arg' is not a table", 0)
            end
            local length = saved_tointeger(#value)
            if length == nil then
                saved_error('object length is not an integer', 0)
            end
            return length
        end
    "#;
    let module = compile_source(engine, source, b"=(rivetlua script args)")?;
    let values = run_module(vm, &module, &[], &mut io::sink(), errors, bridge, None)?;
    let function = values
        .first()
        .copied()
        .ok_or_else(|| CliFailure::failed("script args 長度函式未建立"))?;
    vm.root(function).map_err(sdk_failure)
}

fn script_values(
    vm: &mut Vm,
    length_function: &rivetlua::Root,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<(Vec<Value>, Vec<rivetlua::Root>)> {
    let _signal_epoch = SignalEpochGuard::begin();
    let arg = vm.get_global(b"arg").map_err(sdk_failure)?;
    let table = if matches!(arg, Value::Object(_)) {
        Some(vm.root(arg).map_err(sdk_failure)?)
    } else {
        None
    };
    let outcome = {
        let mut execution = vm.call(length_function, &[arg]).map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    }
    .map_err(|error| {
        CliFailure::failed(format!(
            "script args 長度執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    let length = match outcome {
        RunOutcome::Exited(request) => return Err(CliFailure::exited(request)),
        RunOutcome::Returned(values) => match values.as_slice() {
            [Value::Integer(length)] => *length,
            _ => return Err(CliFailure::failed("script args 長度不是整數")),
        },
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors, None)?;
            return Err(CliFailure::failed("script args 長度計算失敗"));
        }
        RunOutcome::Aborted(AbortReason::FuelExhausted) => {
            return Err(CliFailure::failed("script args 長度執行額度耗盡"));
        }
        RunOutcome::PendingClose(_) => {
            return Err(CliFailure::failed(
                "script args 長度等待 close continuation",
            ));
        }
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => {
            return Err(report_unsupported_run_outcome(
                "script args 長度",
                &outcome,
                errors,
            )?);
        }
    };
    if !(0..=MAX_SCRIPT_ARGUMENTS).contains(&length) {
        return Err(CliFailure::failed("script args 長度超出上限"));
    }
    let table = table.ok_or_else(|| CliFailure::failed("'arg' is not a table"))?;
    let length = usize::try_from(length).map_err(|_| CliFailure::failed("script args 長度溢位"))?;
    let mut values = Vec::new();
    let mut roots = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| CliFailure::failed("script args 配置失敗"))?;
    roots
        .try_reserve_exact(length)
        .map_err(|_| CliFailure::failed("script args root 配置失敗"))?;
    for index in 1..=length {
        let index = i64::try_from(index).map_err(|_| CliFailure::failed("script args 索引溢位"))?;
        let value = vm
            .table_raw_get(&table, Value::Integer(index))
            .map_err(sdk_failure)?;
        if matches!(value, Value::Object(_)) {
            roots.push(vm.root(value).map_err(sdk_failure)?);
        }
        values.push(value);
    }
    Ok((values, roots))
}

fn preprocess_source(bytes: &mut Vec<u8>) {
    if bytes.starts_with(b"\xef\xbb\xbf") {
        bytes.drain(..3);
    }
    if bytes.starts_with(b"#") {
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(bytes.len());
        for byte in &mut bytes[..end] {
            *byte = b' ';
        }
    }
}

fn file_input_prefix_len(bytes: &[u8]) -> usize {
    let bom_len = usize::from(bytes.starts_with(b"\xef\xbb\xbf")) * 3;
    if bytes.get(bom_len) != Some(&b'#') {
        return bom_len;
    }
    bytes[bom_len..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |line_end| bom_len + line_end + 1)
}

fn file_input_is_binary(bytes: &[u8], prefix_len: usize) -> bool {
    let payload = &bytes[prefix_len..];
    let format = if is_container_marker(payload) {
        None
    } else {
        Some(rivetlua::classify_input(payload))
    };
    format.is_none() || format.is_some_and(|value| value != InputFormat::Source)
}

fn apply_file_input_preprocessing(
    bytes: &mut Vec<u8>,
    prefix_len: usize,
    is_binary: bool,
) -> bool {
    if is_binary {
        bytes.drain(..prefix_len);
        true
    } else {
        preprocess_source(bytes);
        false
    }
}

fn preprocess_file_input(bytes: &mut Vec<u8>) -> bool {
    let prefix_len = file_input_prefix_len(bytes);
    let is_binary = file_input_is_binary(bytes, prefix_len);
    apply_file_input_preprocessing(bytes, prefix_len, is_binary)
}

fn preprocess_file_input_budgeted(
    bytes: &mut Vec<u8>,
    budget: &mut LoadBudget<'_>,
) -> Result<(), HostLoadError> {
    if file_input_is_binary(bytes, 0) {
        apply_file_input_preprocessing(bytes, 0, true);
        return Ok(());
    }
    let work = bytes
        .len()
        .checked_mul(4)
        .and_then(|units| units.checked_add(8))
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    budget.spend_work(work)?;
    let prefix_len = file_input_prefix_len(bytes);
    let is_binary = file_input_is_binary(bytes, prefix_len);
    apply_file_input_preprocessing(bytes, prefix_len, is_binary);
    Ok(())
}

fn is_container_marker(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"RVCT") {
        return false;
    }
    match bytes.get(4) {
        None => true,
        Some(byte) => !byte.is_ascii_graphic() && !byte.is_ascii_whitespace(),
    }
}

fn read_input(reader: &mut dyn Read, limit: usize) -> CliResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = reader
            .read(&mut chunk)
            .map_err(|error| CliFailure::failed(format!("讀取輸入失敗：{error}")))?;
        if count == 0 {
            break;
        }
        let next = result
            .len()
            .checked_add(count)
            .ok_or_else(|| CliFailure::failed("輸入長度溢位"))?;
        if next > limit {
            return Err(CliFailure::failed("輸入超出 CLI 限額"));
        }
        result
            .try_reserve_exact(count)
            .map_err(|_| CliFailure::failed("輸入配置失敗"))?;
        if result.capacity() > limit {
            return Err(CliFailure::failed("輸入實際配置超出 CLI 限額"));
        }
        result.extend_from_slice(&chunk[..count]);
    }
    Ok(result)
}

fn read_file(path: &Path, limit: usize) -> CliResult<Vec<u8>> {
    let metadata = fs::metadata(path)
        .map_err(|error| {
            CliFailure::failed(format!("讀取檔案資訊失敗（{}）：{error}", path.display()))
        })?;
    let size = usize::try_from(metadata.len()).map_err(|_| CliFailure::failed("檔案長度溢位"))?;
    if size > limit {
        return Err(CliFailure::failed("檔案超出 CLI 限額"));
    }
    let mut file = File::open(path).map_err(|error| {
        CliFailure::failed(format!("開啟檔案失敗（{}）：{error}", path.display()))
    })?;
    read_input(&mut file, limit)
}

fn compile_source(engine: &Engine, source: &[u8], chunk_name: &[u8]) -> CliResult<Module> {
    compile_source_raw(engine, source, chunk_name).map_err(|error| {
        let mut message = format!("編譯失敗：{error}");
        if matches!(&error, rivetlua::CompileError::Diagnostic(_)) {
            message.push_str(" (syntax error)");
        }
        if matches!(&error, rivetlua::CompileError::Diagnostic(diagnostic) if diagnostic.message == "未知詞法元素") {
            message.push_str(" (unexpected symbol)");
        }
        CliFailure::failed(message)
    })
}

fn compile_source_raw(
    engine: &Engine,
    source: &[u8],
    chunk_name: &[u8],
) -> Result<Module, rivetlua::CompileError> {
    let budget = CompileBudget::default();
    engine.compile_named_with_budget(source, chunk_name, &budget)
}

fn input_module(
    engine: &Engine,
    mut bytes: Vec<u8>,
    chunk_name: &[u8],
    file_mode: bool,
) -> CliResult<Module> {
    let is_binary = if file_mode {
        preprocess_file_input(&mut bytes)
    } else {
        let format = if is_container_marker(&bytes) {
            None
        } else {
            Some(rivetlua::classify_input(&bytes))
        };
        if format.is_none() || format.is_some_and(|value| value != InputFormat::Source) {
            true
        } else {
            preprocess_source(&mut bytes);
            false
        }
    };
    if is_binary {
        let budget = TransportBudget::new(ContainerLimits::default());
        return engine
            .load_binary_module(&bytes, &budget)
            .map_err(|error| CliFailure::failed(format!("binary 載入失敗：{error}")));
    }
    compile_source(engine, &bytes, chunk_name)
}

fn set_cli_execution_fuel(execution: &mut rivetlua::Execution<'_>) -> CliResult<()> {
    set_cli_execution_interrupt(execution)?;
    execution.set_fuel(CLI_EXECUTION_FUEL).map_err(|error| {
        CliFailure::failed(format!(
            "Execution fuel 設定失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })
}

fn set_cli_execution_interrupt(execution: &mut rivetlua::Execution<'_>) -> CliResult<()> {
    let signal = CURRENT_STANDALONE_SIGNAL.with(|current| current.borrow().clone());
    if let Some(signal) = signal {
        execution
            .set_interrupt_flag(signal.pending.clone())
            .map_err(|error| {
                CliFailure::failed(format!(
                    "Execution 中斷旗標設定失敗 {}：{:?}",
                    error.diagnostic_id, error.kind
                ))
            })?;
    }
    Ok(())
}

fn write_bytes(writer: &mut dyn Write, bytes: &[u8]) -> CliResult<()> {
    writer
        .write_all(bytes)
        .map_err(|error| CliFailure::failed(format!("輸出失敗：{error}")))
}

fn report_unsupported_run_outcome(
    operation: &str,
    outcome: &RunOutcome,
    errors: &mut dyn Write,
) -> CliResult<CliFailure> {
    let failure = CliFailure::failed(format!(
        "{operation} 遇到 CLI 不支援的 VM outcome：{outcome:?}"
    ));
    write_bytes(errors, b"rivetlua: ")?;
    write_bytes(errors, &failure.message)?;
    write_bytes(errors, b"\n")?;
    Ok(failure)
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn native_string(vm: &mut Vm, bytes: &[u8]) -> CliResult<(Value, rivetlua::Root)> {
    let root = vm.new_string(bytes).map_err(sdk_failure)?;
    let value = root.value(vm).map_err(sdk_failure)?;
    Ok((value, root))
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn native_arg_bytes(vm: &mut Vm, value: Value) -> CliResult<Vec<u8>> {
    let root = vm.root(value).map_err(sdk_failure)?;
    vm.read_byte_string(&root).map_err(sdk_failure)
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn native_package_cpath(vm: &mut Vm, package: Value) -> CliResult<Vec<u8>> {
    let package = vm.root(package).map_err(sdk_failure)?;
    let key = vm.new_string(b"cpath").map_err(sdk_failure)?;
    let value = vm
        .table_raw_get(&package, key.value(vm).map_err(sdk_failure)?)
        .map_err(sdk_failure)?;
    native_arg_bytes(vm, value)
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn native_symbol_name(name: &[u8]) -> Vec<u8> {
    let name = name
        .iter()
        .position(|byte| *byte == b'-')
        .map_or(name, |mark| &name[..mark]);
    let mut symbol = b"luaopen_".to_vec();
    symbol.extend(
        name.iter()
            .map(|byte| if *byte == b'.' { b'_' } else { *byte }),
    );
    symbol
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn native_searcher(
    bridge: &mut NativeBridge<'_>,
    vm: &mut Vm,
    name: &[u8],
    cpath: &[u8],
    root: bool,
) -> Result<(Option<(Value, Vec<u8>)>, Vec<u8>), String> {
    use std::os::unix::ffi::OsStringExt;
    if name.contains(&0) || cpath.contains(&0) {
        return Err("native 搜尋名稱或 cpath 含 NUL".into());
    }
    let root_name = if root {
        let Some(dot) = name.iter().position(|byte| *byte == b'.') else {
            return Ok((None, b"\n\tno all-in-one module".to_vec()));
        };
        &name[..dot]
    } else {
        name
    };
    let mut transformed = Vec::with_capacity(root_name.len());
    transformed.extend(
        root_name
            .iter()
            .map(|byte| if *byte == b'.' { b'/' } else { *byte }),
    );
    let symbol = native_symbol_name(name);
    let mut diagnostics = Vec::new();
    for template in cpath
        .split(|byte| *byte == b';')
        .filter(|entry| !entry.is_empty())
    {
        if template.iter().filter(|byte| **byte == b'?').count() != 1 {
            continue;
        }
        let candidate_len = template
            .len()
            .saturating_add(transformed.len())
            .saturating_sub(1);
        if candidate_len > native::MAX_PATH_BYTES {
            return Err("native 候選路徑超出上限".into());
        }
        let mut original = Vec::with_capacity(candidate_len);
        for byte in template {
            if *byte == b'?' {
                original.extend_from_slice(&transformed);
            } else {
                original.push(*byte);
            }
        }
        let candidate = PathBuf::from(OsString::from_vec(original.clone()));
        if candidate.is_file() {
            let loader = bridge.load_opener(vm, &candidate, &symbol)?;
            return Ok((Some((loader, original)), diagnostics));
        }
        diagnostics.extend_from_slice(b"\n\tno file '");
        diagnostics.extend_from_slice(&original);
        diagnostics.push(b'\'');
    }
    if diagnostics.is_empty() {
        diagnostics.extend_from_slice(if root {
            b"\n\tno all-in-one module"
        } else {
            b"\n\tno native module"
        });
    }
    Ok((None, diagnostics))
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn drive_native_external(
    vm: &mut Vm,
    mut outcome: RunOutcome,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<RunOutcome> {
    while let RunOutcome::External(token) = outcome {
        let event = vm.external_event(token).map_err(sdk_failure)?;
        let kind = vm.foreign_native_kind(event.function);
        let function = Value::CFunction(event.function);
        let args = event.args.to_vec();
        let package = event.captures.first().copied();
        drop(event);
        outcome = if let Some(kind) = kind {
            let mut roots = Vec::new();
            let command = match kind {
                ForeignNativeKind::LoadLib => {
                    let mut failure_stage = b"open".as_slice();
                    let result = (|| -> CliResult<Vec<Value>> {
                        if bridge.grant.is_none() {
                            return Err(CliFailure::failed(
                                "native-grant: preflight 缺少宿主原生授權",
                            ));
                        }
                        use std::os::unix::ffi::OsStringExt;
                        let filename = native_arg_bytes(
                            vm,
                            *args.first().ok_or_else(|| {
                                CliFailure::failed("package.loadlib 缺少 filename")
                            })?,
                        )?;
                        let symbol = native_arg_bytes(
                            vm,
                            *args
                                .get(1)
                                .ok_or_else(|| CliFailure::failed("package.loadlib 缺少 symbol"))?,
                        )?;
                        let candidate = PathBuf::from(OsString::from_vec(filename));
                        if bridge
                            .grant
                            .as_ref()
                            .is_some_and(|grant| grant.match_candidate(&candidate).is_ok())
                        {
                            failure_stage = b"init";
                        }
                        let loaded = if symbol == b"*" {
                            let grant = bridge
                                .grant
                                .as_ref()
                                .ok_or_else(|| CliFailure::failed("native grant 未授權"))?;
                            let module = grant
                                .match_candidate(&candidate)
                                .map_err(CliFailure::failed)?;
                            if module.visibility != SymbolVisibility::Global {
                                failure_stage = b"open";
                                return Err(CliFailure::failed(
                                    "native-grant: visibility global-symbol 載入未獲授權",
                                ));
                            }
                            let index = grant
                                .modules
                                .iter()
                                .position(|entry| entry.path == module.path)
                                .ok_or_else(|| CliFailure::failed("native grant 模組索引遺失"))?;
                            bridge
                                .ensure_loaded(vm, index)
                                .map_err(CliFailure::failed)?;
                            Value::Boolean(true)
                        } else {
                            bridge
                                .load_opener(vm, &candidate, &symbol)
                                .map_err(CliFailure::failed)?
                        };
                        Ok(vec![loaded])
                    })();
                    match result {
                        Ok(values) => ExternalCommand::Return(values),
                        Err(error) => {
                            let (message, root) = native_string(vm, &error.message)?;
                            roots.push(root);
                            let (where_value, where_root) = native_string(vm, failure_stage)?;
                            roots.push(where_root);
                            ExternalCommand::Return(vec![Value::Nil, message, where_value])
                        }
                    }
                }
                ForeignNativeKind::Searcher | ForeignNativeKind::RootSearcher => {
                    let result = (|| -> CliResult<Vec<Value>> {
                        let name = native_arg_bytes(
                            vm,
                            *args.first().ok_or_else(|| {
                                CliFailure::failed("native 搜尋器缺少 module 名稱")
                            })?,
                        )?;
                        let package = package.ok_or_else(|| {
                            CliFailure::failed("native 搜尋器缺少 package capture")
                        })?;
                        let cpath = native_package_cpath(vm, package)?;
                        let (found, diagnostic) = native_searcher(
                            bridge,
                            vm,
                            &name,
                            &cpath,
                            kind == ForeignNativeKind::RootSearcher,
                        )
                        .map_err(CliFailure::failed)?;
                        if let Some((loader, filename)) = found {
                            let (filename, root) = native_string(vm, &filename)?;
                            roots.push(root);
                            Ok(vec![loader, filename])
                        } else {
                            let (diagnostic, root) = native_string(vm, &diagnostic)?;
                            roots.push(root);
                            Ok(vec![diagnostic])
                        }
                    })();
                    match result {
                        Ok(values) => ExternalCommand::Return(values),
                        Err(error) => {
                            let (message, root) = native_string(vm, &error.message)?;
                            roots.push(root);
                            ExternalCommand::Error(message)
                        }
                    }
                }
            };
            let continued = vm.continue_external(token, command).map_err(sdk_failure)?;
            drop(roots);
            continued
        } else {
            if bridge.grant.is_none() {
                return Ok(RunOutcome::External(token));
            }
            let mut loan = vm.native_loan().map_err(sdk_failure)?;
            let called = loan
                .state_owner()
                .invoke_bound_native(token, function, &args)
                .map_err(|error| {
                    CliFailure::failed(format!("native C checkpoint 失敗：{error:?}"))
                });
            loan.try_return().map_err(sdk_failure)?;
            drop(loan);
            let called = called?;
            if let Some(request) = called.terminal_request() {
                if vm.exit_request() != Some(request) {
                    return Err(CliFailure::failed("native 終止請求與 VM 狀態不一致"));
                }
                return Ok(RunOutcome::Exited(request));
            }
            if vm.exit_request().is_some() {
                return Err(CliFailure::failed("native C checkpoint 未完成終止交付"));
            }
            let command = if called.status() == 0 {
                ExternalCommand::Return(called.values().to_vec())
            } else {
                ExternalCommand::Error(called.values().first().copied().unwrap_or(Value::Nil))
            };
            let continued = vm.continue_external(token, command).map_err(sdk_failure)?;
            continued
        };
    }
    Ok(outcome)
}

#[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
fn drive_native_external(
    _vm: &mut Vm,
    outcome: RunOutcome,
    _bridge: &mut NativeBridge<'_>,
) -> CliResult<RunOutcome> {
    Ok(outcome)
}

fn run_module(
    vm: &mut Vm,
    module: &Module,
    args: &[Value],
    _output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: Option<&CliErrorHandler>,
) -> CliResult<Vec<Value>> {
    let _signal_epoch = SignalEpochGuard::begin();
    let outcome = {
        let mut execution = if let Some(handler) = handler {
            vm.load_module_with_args_and_error_handler(module, args, &handler.root)
        } else {
            vm.load_module_with_args(module, args)
        }.map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "VM 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    match outcome {
        RunOutcome::Exited(request) => Err(CliFailure::exited(request)),
        RunOutcome::Returned(values) => Ok(values),
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors, handler.map(|handler| handler.program_name.as_slice()))?;
            Err(CliFailure::failed("Lua chunk 執行失敗"))
        }
        RunOutcome::Aborted(AbortReason::FuelExhausted) => {
            write_bytes(errors, "rivetlua: 執行額度耗盡\n".as_bytes())?;
            Err(CliFailure::failed("執行額度耗盡"))
        }
        RunOutcome::PendingClose(snapshot) => {
            write_bytes(
                errors,
                format!("rivetlua: close continuation 尚未完成：{snapshot:?}\n").as_bytes(),
            )?;
            Err(CliFailure::failed("close continuation 尚未完成"))
        }
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => {
            Err(report_unsupported_run_outcome("VM 執行", &outcome, errors)?)
        }
    }
}

fn print_interactive_values(
    vm: &mut Vm,
    print_module: &Module,
    values: &[Value],
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<()> {
    print_interactive_values_with_fuel(vm, print_module, values, errors, bridge, CLI_EXECUTION_FUEL)
}

fn print_interactive_values_with_fuel(
    vm: &mut Vm,
    print_module: &Module,
    values: &[Value],
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    fuel: u64,
) -> CliResult<()> {
    let _signal_epoch = SignalEpochGuard::begin();
    let mut value_roots = Vec::new();
    value_roots
        .try_reserve_exact(values.len())
        .map_err(|_| CliFailure::failed("REPL 結果 root 配置失敗"))?;
    for value in values {
        if matches!(value, Value::Object(_)) {
            value_roots.push(vm.root(*value).map_err(sdk_failure)?);
        }
    }

    let outcome = {
        let mut execution = vm
            .load_module_with_args(print_module, values)
            .map_err(sdk_failure)?;
        execution.set_fuel(fuel).map_err(|error| {
            CliFailure::failed(format!(
                "REPL print fuel 設定失敗 {}：{:?}",
                error.diagnostic_id, error.kind
            ))
        })?;
        set_cli_execution_interrupt(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "REPL print 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    match outcome {
        RunOutcome::Exited(request) => Err(CliFailure::exited(request)),
        RunOutcome::Returned(_) => Ok(()),
        RunOutcome::LuaError(error) => {
            write_bytes(errors, b"rivetlua: error calling 'print' (")?;
            write_lua_error_value(vm, &error, errors)?;
            write_bytes(errors, b")\n")?;
            if repl_recoverable_lua_error(error.kind) {
                Ok(())
            } else {
                Err(CliFailure::failed("REPL print 致命錯誤"))
            }
        }
        RunOutcome::Aborted(AbortReason::FuelExhausted) => {
            write_bytes(errors, "rivetlua: REPL print 執行額度耗盡\n".as_bytes())?;
            Err(CliFailure::failed("REPL print 執行額度耗盡"))
        }
        RunOutcome::PendingClose(snapshot) => {
            write_bytes(
                errors,
                format!("rivetlua: REPL print close continuation 尚未完成：{snapshot:?}\n")
                    .as_bytes(),
            )?;
            Err(CliFailure::failed("REPL print close continuation 尚未完成"))
        }
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => Err(report_unsupported_run_outcome(
            "REPL print",
            &outcome,
            errors,
        )?),
    }
}

fn write_lua_error(
    vm: &mut Vm,
    error: &rivetlua::LuaError,
    writer: &mut dyn Write,
    program_name: Option<&[u8]>,
) -> CliResult<()> {
    write_bytes(writer, program_name.unwrap_or(b"rivetlua"))?;
    write_bytes(writer, b": ")?;
    write_lua_error_value(vm, error, writer)?;
    write_bytes(writer, b"\n")
}

fn write_lua_error_value(
    vm: &mut Vm,
    error: &rivetlua::LuaError,
    writer: &mut dyn Write,
) -> CliResult<()> {
    match error.value {
        Value::Object(_) => {
            let root = vm.root(error.value).map_err(sdk_failure)?;
            if let Ok(bytes) = vm.read_byte_string(&root) {
                write_bytes(writer, &bytes)?;
            } else {
                write_bytes(
                    writer,
                    format!("{} ({:?})", error.diagnostic_id, error.kind).as_bytes(),
                )?;
            }
        }
        _ => write_bytes(
            writer,
            format!("{} ({:?})", error.diagnostic_id, error.kind).as_bytes(),
        )?,
    }
    Ok(())
}

fn repl_recoverable_lua_error(kind: RuntimeErrorKind) -> bool {
    matches!(
        kind,
        RuntimeErrorKind::Core(_)
            | RuntimeErrorKind::NumericForZeroStep
            | RuntimeErrorKind::InvalidNamedVarargCount
            | RuntimeErrorKind::InvalidGlobalNilCheck
            | RuntimeErrorKind::NotCallable
            | RuntimeErrorKind::StackLimit
            | RuntimeErrorKind::MetatableChainLimit
            | RuntimeErrorKind::MetamethodAbsent
            | RuntimeErrorKind::Thrown
            | RuntimeErrorKind::ErrorHandlerLoop
            | RuntimeErrorKind::CoroutineYield
            | RuntimeErrorKind::CoroutineClose
            | RuntimeErrorKind::DebugArgument
            | RuntimeErrorKind::IoArgument
            | RuntimeErrorKind::OsArgument
            | RuntimeErrorKind::IoClosed
            | RuntimeErrorKind::IoStandardClose
            | RuntimeErrorKind::LoadArgument
            | RuntimeErrorKind::LoadMode
            | RuntimeErrorKind::LoadReaderType
            | RuntimeErrorKind::LoadCompile
            | RuntimeErrorKind::LoadBytecode
            | RuntimeErrorKind::PackageArgument
            | RuntimeErrorKind::PackageSearchers
            | RuntimeErrorKind::ModuleNotFound
            | RuntimeErrorKind::BasicArgument
            | RuntimeErrorKind::MathArgument
            | RuntimeErrorKind::Utf8Argument
            | RuntimeErrorKind::Utf8Sequence
            | RuntimeErrorKind::StringArgument
            | RuntimeErrorKind::StringPattern
            | RuntimeErrorKind::StringFormat
            | RuntimeErrorKind::InvalidNextKey
            | RuntimeErrorKind::Heap(
                VmError::NilTableKey
                    | VmError::NaNTableKey
                    | VmError::WrongObjectType
                    | VmError::Interrupted
            )
    )
}

fn run_source(
    engine: &Engine,
    vm: &mut Vm,
    source: &[u8],
    name: &[u8],
    args: &[Value],
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: &CliErrorHandler,
) -> CliResult<()> {
    let module = compile_source(engine, source, name)?;
    run_module(vm, &module, args, output, errors, bridge, Some(handler)).map(|_| ())
}

fn run_path(
    engine: &Engine,
    vm: &mut Vm,
    path: &OsStr,
    length_function: &rivetlua::Root,
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: &CliErrorHandler,
) -> CliResult<()> {
    let pathbuf = PathBuf::from(path);
    let bytes = read_file(&pathbuf, MAX_INPUT_BYTES)?;
    let module = input_module(engine, bytes, &os_bytes(path), true)?;
    let (values, _roots) = script_values(vm, length_function, errors, bridge)?;
    run_module(vm, &module, &values, output, errors, bridge, Some(handler)).map(|_| ())
}

fn run_stdin_script(
    engine: &Engine,
    vm: &mut Vm,
    stdin: &mut dyn Read,
    length_function: Option<&rivetlua::Root>,
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: &CliErrorHandler,
) -> CliResult<()> {
    let bytes = read_input(stdin, MAX_INPUT_BYTES)?;
    let module = input_module(engine, bytes, b"=stdin", false)?;
    let (values, _roots) = if let Some(length_function) = length_function {
        script_values(vm, length_function, errors, bridge)?
    } else {
        (Vec::new(), Vec::new())
    };
    run_module(vm, &module, &values, output, errors, bridge, Some(handler)).map(|_| ())
}

fn run_exec_action(
    engine: &Engine,
    vm: &mut Vm,
    source: &[u8],
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: &CliErrorHandler,
) -> CliResult<()> {
    run_source(
        engine,
        vm,
        source,
        b"=(command line)",
        &[],
        output,
        errors,
        bridge,
        handler,
    )
}

fn run_require_action(
    vm: &mut Vm,
    argument: &[u8],
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<()> {
    let _signal_epoch = SignalEpochGuard::begin();
    let split = argument.iter().position(|byte| *byte == b'=');
    let (global, module_name) = if let Some(index) = split {
        (&argument[..index], &argument[index + 1..])
    } else {
        let suffix = argument.iter().position(|byte| *byte == b'-');
        let global = suffix.map_or(argument, |index| &argument[..index]);
        (global, argument)
    };
    if module_name.is_empty() || global.is_empty() {
        return Err(CliFailure::usage("-l 模組名稱或全域名稱不可為空"));
    }
    let require = vm.get_global(b"require").map_err(sdk_failure)?;
    let require = vm.root(require).map_err(sdk_failure)?;
    let module_arg = vm.new_string(module_name).map_err(sdk_failure)?;
    let outcome = {
        let mut execution = vm
            .call(&require, &[module_arg.value(vm).map_err(sdk_failure)?])
            .map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "require 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    match outcome {
        RunOutcome::Exited(request) => Err(CliFailure::exited(request)),
        RunOutcome::Returned(values) => {
            let value = values.first().copied().unwrap_or(Value::Nil);
            vm.set_global(global, value).map_err(sdk_failure)
        }
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors, None)?;
            Err(CliFailure::failed("-l 載入模組失敗"))
        }
        RunOutcome::Aborted(_) => Err(CliFailure::failed("-l 載入模組時執行額度耗盡")),
        RunOutcome::PendingClose(_) => {
            Err(CliFailure::failed("-l 載入模組等待 close continuation"))
        }
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => Err(report_unsupported_run_outcome(
            "-l 載入模組",
            &outcome,
            errors,
        )?),
    }
}

fn run_init(
    engine: &Engine,
    vm: &mut Vm,
    profile: LuaProfile,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    handler: &CliErrorHandler,
) -> CliResult<()> {
    let Some(init) = configured_env(profile, "INIT") else {
        return Ok(());
    };
    if init.first() == Some(&b'@') {
        let path = os_from_bytes(&init[1..]);
        let bytes = read_file(Path::new(&path), MAX_INPUT_BYTES)?;
        let module = input_module(engine, bytes, &init[1..], true)?;
        run_module(vm, &module, &[], &mut io::stdout(), errors, bridge, Some(handler)).map(|_| ())
    } else {
        run_source(
            engine,
            vm,
            &init,
            b"=LUA_INIT",
            &[],
            &mut io::stdout(),
            errors,
            bridge,
            handler,
        )
    }
}

fn call_original_warning(
    vm: &mut Vm,
    warning: &rivetlua::Root,
    command: &[u8],
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<()> {
    let _signal_epoch = SignalEpochGuard::begin();
    let argument = vm.new_string(command).map_err(sdk_failure)?;
    let value = argument.value(vm).map_err(sdk_failure)?;
    let outcome = {
        let mut execution = vm.call(warning, &[value]).map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    }
    .map_err(|error| {
        CliFailure::failed(format!(
            "CLI warning 控制失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    match outcome {
        RunOutcome::Returned(_) => Ok(()),
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors, None)?;
            Err(CliFailure::failed("CLI warning 控制發生 Lua 錯誤"))
        }
        other => Err(report_unsupported_run_outcome(
            "CLI warning 控制",
            &other,
            errors,
        )?),
    }
}

fn run_repl_module(
    vm: &mut Vm,
    module: &Module,
    print_module: &Module,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<()> {
    let _signal_epoch = SignalEpochGuard::begin();
    let outcome = {
        let mut execution = vm.load_module_with_args(module, &[]).map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "VM 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    let outcome = drive_native_external(vm, outcome, bridge)?;
    match outcome {
        RunOutcome::Exited(request) => Err(CliFailure::exited(request)),
        RunOutcome::Returned(values) => {
            if !values.is_empty() {
                print_interactive_values(vm, print_module, &values, errors, bridge)?;
            }
            Ok(())
        }
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors, None)?;
            if repl_recoverable_lua_error(error.kind) {
                Ok(())
            } else {
                Err(CliFailure::failed("REPL 致命錯誤"))
            }
        }
        RunOutcome::Aborted(AbortReason::FuelExhausted) => {
            write_bytes(errors, "rivetlua: 執行額度耗盡\n".as_bytes())?;
            Err(CliFailure::failed("執行額度耗盡"))
        }
        RunOutcome::PendingClose(snapshot) => {
            write_bytes(
                errors,
                format!("rivetlua: close continuation 尚未完成：{snapshot:?}\n").as_bytes(),
            )?;
            Err(CliFailure::failed("close continuation 尚未完成"))
        }
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => {
            Err(report_unsupported_run_outcome("VM 執行", &outcome, errors)?)
        }
    }
}

fn has_lua55_interactive_local_prefix(line: &[u8]) -> bool {
    let start = line
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(line.len());
    let declaration = &line[start..];
    declaration.starts_with(b"local")
        && matches!(
            declaration.get(5).copied(),
            None | Some(b' ') | Some(b'\t') | Some(0)
        )
}

fn write_repl_prompt(
    vm: &mut Vm,
    original_tostring: &rivetlua::Root,
    first_line: bool,
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
) -> CliResult<()> {
    let _signal_epoch = SignalEpochGuard::begin();
    let name = if first_line { b"_PROMPT".as_slice() } else { b"_PROMPT2".as_slice() };
    let value = vm.get_global(name).map_err(sdk_failure)?;
    let prompt = if matches!(value, Value::Nil) {
        if first_line { b"> ".to_vec() } else { b">> ".to_vec() }
    } else {
        let _value_root = if matches!(value, Value::Object(_)) {
            Some(vm.root(value).map_err(sdk_failure)?)
        } else {
            None
        };
        let outcome = {
            let mut execution = vm.call(original_tostring, &[value]).map_err(sdk_failure)?;
            set_cli_execution_fuel(&mut execution)?;
            execution.run()
        }
        .map_err(|error| {
            CliFailure::failed(format!(
                "REPL prompt 執行失敗 {}：{:?}",
                error.diagnostic_id, error.kind
            ))
        })?;
        match drive_native_external(vm, outcome, bridge)? {
            RunOutcome::Exited(request) => return Err(CliFailure::exited(request)),
            RunOutcome::Returned(values) => {
                let string = values
                    .first()
                    .copied()
                    .ok_or_else(|| CliFailure::failed("REPL prompt 未回傳字串"))?;
                let root = vm.root(string).map_err(sdk_failure)?;
                vm.read_byte_string(&root).map_err(sdk_failure)?
            }
            RunOutcome::LuaError(error) => {
                write_lua_error(vm, &error, errors, None)?;
                return Err(CliFailure::failed("REPL prompt 執行失敗"));
            }
            RunOutcome::Aborted(AbortReason::FuelExhausted) => {
                return Err(CliFailure::failed("REPL prompt 執行額度耗盡"));
            }
            RunOutcome::PendingClose(snapshot) => {
                return Err(CliFailure::failed(format!(
                    "REPL prompt close continuation 尚未完成：{snapshot:?}"
                )));
            }
            outcome @ (RunOutcome::External(_)
            | RunOutcome::CloseBoundaryA5 { .. }
            | RunOutcome::NestedReturned(_)
            | RunOutcome::NestedErrored(_)
            | RunOutcome::NestedFailed(_)) => {
                return Err(report_unsupported_run_outcome("REPL prompt", &outcome, errors)?);
            }
        }
    };
    let length = prompt.iter().position(|byte| *byte == 0).unwrap_or(prompt.len());
    write_bytes(output, &prompt[..length])?;
    output.flush().map_err(|error| CliFailure::failed(format!("REPL 輸出失敗：{error}")))
}

fn repl(
    engine: &Engine,
    vm: &mut Vm,
    input: &mut dyn Read,
    output: &mut dyn Write,
    errors: &mut dyn Write,
    bridge: &mut NativeBridge<'_>,
    original_tostring: &rivetlua::Root,
    force_prompts: bool,
) -> CliResult<()> {
    let terminal_input = io::stdin().is_terminal();
    let interactive_input = force_prompts || terminal_input;
    let echo_input = force_prompts && !terminal_input;
    let print_module = compile_source_raw(engine, b"return print(...)", b"=(REPL print)")
        .map_err(|error| CliFailure::failed(format!("REPL print 編譯失敗：{error}")))?;
    loop {
        if interactive_input {
            write_repl_prompt(vm, original_tostring, true, output, errors, bridge)?;
        }
        let (line, eof) = read_repl_line(input, output, echo_input)?;
        if eof && line.is_empty() {
            if interactive_input {
                write_repl_eof_newline(output)?;
            }
            break;
        }
        if line.is_empty() {
            continue;
        }
        let mut source = line;
        let mut local_warning_checked = false;
        loop {
            let expression = repl_expression_source(engine.profile(), &source)?;
            let compiled = match compile_source_raw(engine, &expression, b"=stdin") {
                Ok(module) => Ok(module),
                Err(_) => {
                    if !local_warning_checked {
                        local_warning_checked = true;
                        if matches!(engine.profile(), LuaProfile::Lua55)
                            && has_lua55_interactive_local_prefix(&source)
                        {
                            write_bytes(
                                errors,
                                b"warning: locals do not survive across lines in interactive mode\n",
                            )?;
                        }
                    }
                    compile_source_raw(engine, &source, b"=stdin")
                }
            };
            match compiled {
                Ok(module) => {
                    run_repl_module(vm, &module, &print_module, errors, bridge)?;
                    break;
                }
                Err(error) if is_incomplete(&error, source.len()) => {
                    if interactive_input {
                        write_repl_prompt(vm, original_tostring, false, output, errors, bridge)?;
                    }
                    let (continuation, eof) = read_repl_line(input, output, echo_input)?;
                    if eof && continuation.is_empty() {
                        if interactive_input {
                            write_repl_eof_newline(output)?;
                        }
                        write_bytes(
                            errors,
                            format!("rivetlua: 未完成的 REPL 輸入：{error} near <eof>\n")
                                .as_bytes(),
                        )?;
                        break;
                    }
                    let next_len = source
                        .len()
                        .checked_add(1)
                        .and_then(|len| len.checked_add(continuation.len()))
                        .ok_or_else(|| CliFailure::failed("REPL 輸入長度溢位"))?;
                    if next_len > MAX_INPUT_BYTES {
                        return Err(CliFailure::failed("REPL 輸入超出上限"));
                    }
                    source
                        .try_reserve_exact(next_len - source.len())
                        .map_err(|_| CliFailure::failed("REPL 多行輸入配置失敗"))?;
                    if source.capacity() > MAX_INPUT_BYTES {
                        return Err(CliFailure::failed("REPL 實際配置超出上限"));
                    }
                    source.push(b'\n');
                    source.extend_from_slice(&continuation);
                    continue;
                }
                Err(error) => {
                    write_bytes(errors, format!("rivetlua: 編譯失敗：{error}\n").as_bytes())?;
                    if !matches!(error, rivetlua::CompileError::Diagnostic(_)) {
                        return Err(CliFailure::failed("REPL 編譯失敗"));
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

fn write_repl_eof_newline(output: &mut dyn Write) -> CliResult<()> {
    write_bytes(output, b"\n")?;
    output
        .flush()
        .map_err(|error| CliFailure::failed(format!("REPL 輸出失敗：{error}")))
}

fn echo_repl_line(output: &mut dyn Write, line: &[u8]) -> CliResult<()> {
    write_bytes(output, line)?;
    write_bytes(output, b"\n")?;
    output
        .flush()
        .map_err(|error| CliFailure::failed(format!("REPL 輸出失敗：{error}")))
}

fn read_repl_line(
    input: &mut dyn Read,
    output: &mut dyn Write,
    echo_input: bool,
) -> CliResult<(Vec<u8>, bool)> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let count = input
            .read(&mut byte)
            .map_err(|error| CliFailure::failed(format!("REPL 讀取失敗：{error}")))?;
        if count == 0 {
            if echo_input && !line.is_empty() {
                echo_repl_line(output, &line)?;
            }
            return Ok((line, true));
        }
        if byte[0] == b'\n' {
            if echo_input {
                echo_repl_line(output, &line)?;
            }
            return Ok((line, false));
        }
        if line.len() >= MAX_INPUT_BYTES {
            return Err(CliFailure::failed("REPL 輸入超出上限"));
        }
        line.try_reserve(1)
            .map_err(|_| CliFailure::failed("REPL 輸入配置失敗"))?;
        if line.capacity() > MAX_INPUT_BYTES {
            return Err(CliFailure::failed("REPL 實際配置超出上限"));
        }
        line.push(byte[0]);
    }
}

fn repl_expression_source(profile: LuaProfile, source: &[u8]) -> CliResult<Vec<u8>> {
    let expression = if profile == LuaProfile::Lua54 && source.starts_with(b"=") {
        &source[1..]
    } else {
        source
    };
    let length = expression
        .len()
        .checked_add(b"return ".len())
        .ok_or_else(|| CliFailure::failed("REPL expression 長度溢位"))?;
    if length > MAX_INPUT_BYTES {
        return Err(CliFailure::failed("REPL expression 超出上限"));
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| CliFailure::failed("REPL expression 配置失敗"))?;
    if result.capacity() > MAX_INPUT_BYTES {
        return Err(CliFailure::failed("REPL expression 實際配置超出上限"));
    }
    result.extend_from_slice(b"return ");
    result.extend_from_slice(expression);
    Ok(result)
}

fn is_incomplete(error: &rivetlua::CompileError, source_len: usize) -> bool {
    let rivetlua::CompileError::Diagnostic(diagnostic) = error else {
        return false;
    };
    if diagnostic.span.end_byte != source_len {
        return false;
    }
    // parser 的 EOF token 是 source_len..source_len；末尾的其他 token 不可等待下一行。
    if matches!(diagnostic.message, "預期名稱" | "unexpected symbol") {
        return diagnostic.span.start_byte == source_len;
    }
    matches!(
        diagnostic.message,
        "缺少 block 結束關鍵字"
            | "缺少 table 結束符號"
            | "缺少結束符號"
            | "缺少結束關鍵字"
            | "預期運算式"
            | "短字串未結束"
            | "短字串 escape 未結束"
            | "long 字串未結束"
            | "long 註解未結束"
    )
}

fn sdk_failure(error: SdkError) -> CliFailure {
    CliFailure::failed(format!("SDK 錯誤：{error}"))
}

fn usage() -> &'static [u8] {
    "用法：rivetlua [--profile lua55|lua54] [-E] [-v] [-i] [-e 程式] [-l 模組] [--] [檔案 [參數...]]\n".as_bytes()
}

pub fn rivetlua_main() -> std::process::ExitCode {
    rivetlua_main_inner(false)
}

/// 獨立執行檔入口；只在確實執行 Lua 時安裝程序級 SIGINT 處理器。
pub fn rivetlua_standalone_main() -> std::process::ExitCode {
    rivetlua_main_inner(true)
}

fn rivetlua_main_inner(standalone_signal: bool) -> std::process::ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let result = run_interpreter_inner(
        &args,
        &mut stdin,
        &mut stdout,
        &mut stderr,
        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        None,
        standalone_signal,
    );
    match result {
        Ok(status) => std::process::ExitCode::from(status),
        Err(error) => {
            let _ = stderr.write_all(b"rivetlua: ");
            let _ = stderr.write_all(&error.message);
            if !error.message.ends_with(b"\n") {
                let _ = stderr.write_all(b"\n");
            }
            if error.status == 2 {
                let _ = stderr.write_all(usage());
            }
            std::process::ExitCode::from(error.status)
        }
    }
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub fn rivetlua_main_with_native_attestor(
    attestor: impl FnMut(VerifiedNative) -> AttestedNative,
) -> std::process::ExitCode {
    rivetlua_main_with_native_attestor_inner(attestor, false)
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub fn rivetlua_standalone_main_with_native_attestor(
    attestor: impl FnMut(VerifiedNative) -> AttestedNative,
) -> std::process::ExitCode {
    rivetlua_main_with_native_attestor_inner(attestor, true)
}

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn rivetlua_main_with_native_attestor_inner(
    mut attestor: impl FnMut(VerifiedNative) -> AttestedNative,
    standalone_signal: bool,
) -> std::process::ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let result = run_interpreter_inner(
        &args,
        &mut stdin,
        &mut stdout,
        &mut stderr,
        Some(&mut attestor),
        standalone_signal,
    );
    match result {
        Ok(status) => std::process::ExitCode::from(status),
        Err(error) => {
            let _ = stderr.write_all(b"rivetlua: ");
            let _ = stderr.write_all(&error.message);
            if !error.message.ends_with(b"\n") {
                let _ = stderr.write_all(b"\n");
            }
            if error.status == 2 {
                let _ = stderr.write_all(usage());
            }
            std::process::ExitCode::from(error.status)
        }
    }
}

pub fn rivetluac_main() -> std::process::ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    match run_compiler(&args, &mut stdin, &mut stdout) {
        Ok(status) => std::process::ExitCode::from(status),
        Err(error) => {
            let _ = stderr.write_all(b"rivetluac: ");
            let _ = stderr.write_all(&error.message);
            if !error.message.ends_with(b"\n") {
                let _ = stderr.write_all(b"\n");
            }
            std::process::ExitCode::from(error.status)
        }
    }
}

#[cfg(test)]
mod cli_unit_tests {
    #[cfg(not(unix))]
    use super::OsEntropy;
    use super::{
        CLI_EXECUTION_FUEL, CliResourceDeadline, atomic_write, cli_resource_capability,
        debug_capability, dump_limits, load_limits, read_entropy_seed,
        report_unsupported_run_outcome, unix_epoch_seconds,
    };
    use rivetlua::{
        DebugCapability, DebugPermission, Engine, HostEntropyError, HostOutput, HostOutputError,
        HostResourceErrorKind, HostServices, LuaProfile, ResourceCapability, ResourceLimits,
        RunOutcome, RuntimeErrorKind, Value,
    };
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::io::{self, Cursor, Read};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, UNIX_EPOCH};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    #[test]
    fn p18_native_driver_keeps_one_vm_affinity() {
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let engine = Engine::new(profile);
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        let other_profile = if profile == LuaProfile::Lua55 {
            LuaProfile::Lua54
        } else {
            LuaProfile::Lua55
        };
        let mut mismatched = Engine::new(other_profile).new_vm().unwrap();
        let mut driver = super::NativeDriver {
            bridge: super::NativeBridge {
                grant: None,
                attestor: None,
                loaded: Vec::new(),
                cache_root: std::env::temp_dir(),
            },
            profile,
            vm_root: None,
        };
        assert_eq!(
            driver
                .drive(&mut mismatched, RunOutcome::Returned(Vec::new()))
                .err()
                .as_deref(),
            Some("native-grant: profile 與 VM 不符")
        );
        assert!(driver.vm_root.is_none());
        assert!(matches!(
            driver.drive(&mut first, RunOutcome::Returned(Vec::new())),
            Ok(RunOutcome::Returned(_))
        ));
        assert!(matches!(
            driver.drive(&mut first, RunOutcome::Returned(Vec::new())),
            Ok(RunOutcome::Returned(_))
        ));
        assert_eq!(
            driver
                .drive(&mut second, RunOutcome::Returned(Vec::new()))
                .err()
                .as_deref(),
            Some("native driver 已綁定其他 VM")
        );
    }

    #[test]
    fn p17_standalone_signal_epoch_preserves_second_interrupt() {
        use super::{CURRENT_STANDALONE_SIGNAL, SignalEpochGuard, StandaloneSignal, StandaloneSignalSession};
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let signal = Arc::new(StandaloneSignal {
            active: AtomicBool::new(false),
            seen: AtomicBool::new(false),
            pending: Arc::new(AtomicBool::new(false)),
        });
        let _session = StandaloneSignalSession(signal.clone());
        CURRENT_STANDALONE_SIGNAL.with(|current| *current.borrow_mut() = Some(signal.clone()));
        assert!(signal.record_interrupt());
        {
            let _epoch = SignalEpochGuard::begin();
            assert!(!signal.record_interrupt());
            assert!(signal.pending.swap(false, Ordering::AcqRel));
            assert!(signal.record_interrupt());
        }
        assert!(!signal.active.load(Ordering::Acquire));
        {
            let _epoch = SignalEpochGuard::begin();
            assert!(!signal.record_interrupt());
            assert!(signal.pending.load(Ordering::Acquire));
        }
        assert!(!signal.pending.load(Ordering::Acquire));
    }

    #[test]
    fn p17_cli_host_entry_error_objects_keep_real_frames() {
        let source = b"debug=require'debug'\nm={x=0}\nsetmetatable(m,{__tostring=function(x)\n return tostring(debug.getinfo(4).currentline+x.x)\nend})\nerror(m)\n";
        for profile in ["lua55", "lua54"] {
            for (script, expected) in [
                (b"error('msg')\n".as_slice(), b"stdin:1: msg".as_slice()),
                (source.as_slice(), b"p17-cli-test: 6\n".as_slice()),
                (b"error{}\n".as_slice(), b"(error object is a table value)".as_slice()),
                (b"error(17)\n".as_slice(), b"17\n".as_slice()),
                (b"error(nil)\n".as_slice(), b"(error object is a nil value)".as_slice()),
                (
                    b"error(setmetatable({}, {__tostring=function() error('render failed') end}))\n"
                        .as_slice(),
                    b"render failed".as_slice(),
                ),
            ] {
                let args = [
                    OsString::from("p17-cli-test"),
                    OsString::from("--profile"),
                    OsString::from(profile),
                    OsString::from("-"),
                ];
                let mut stdin = Cursor::new(script);
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let result = super::run_interpreter(&args, &mut stdin, &mut stdout, &mut stderr);
                assert!(result.is_err(), "{profile}: {result:?}");
                assert!(stdout.is_empty(), "{profile}: {stdout:?}");
                assert!(
                    stderr.windows(expected.len()).any(|part| part == expected),
                    "{profile}: {}",
                    String::from_utf8_lossy(&stderr)
                );
            }
        }
    }

    #[test]
    fn p17_warning_stdout_no_grant_policy() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let engine = Engine::new(profile);
            // NoGrantStandardIo 的 authorize_process 與 popen 都只回 PolicyDenied；
            // 此測試不會建立 shell 或任何外部程序。
            let source = b"assert(io.type(io.stdout) == 'file')\nassert(io.type(io.stdin) == 'file')\nassert(io.type(io.stderr) == 'file')\nassert(io.stdout:write('P17_NO_GRANT_STDOUT\\n') == io.stdout)\nassert(io.stdout:flush())\nassert(not pcall(io.open, '/dev/null', 'r'))\nassert(not pcall(io.tmpfile))\nassert(not pcall(io.popen, 'true', 'r'))\nassert(not pcall(function() return io.stdin:read() end))\nassert(not pcall(function() io.stderr:write('denied') end))\nassert(not pcall(function() io.stdout:read() end))\nassert(not pcall(function() io.stdout:seek('set', 0) end))\nassert(not pcall(function() io.stdout:close() end))\nreturn 17";
            let module = engine.compile(source).unwrap();
            let mut vm = engine
                .new_vm_with_services(super::host_services(&engine, None, false))
                .unwrap();
            assert_eq!(
                vm.load_module(&module).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![Value::Integer(17)]),
                "profile={profile:?}",
            );
        }
    }

    #[test]
    fn p17_debug_console_trusted_optin() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let engine = Engine::new(profile);
            let module = engine.compile(b"debug.debug()").unwrap();
            for (trusted, expected) in [
                (false, RuntimeErrorKind::HostPolicyDebug),
                (true, RuntimeErrorKind::HostPolicyIo),
            ] {
                // 偵錯命令的權限檢查與標準輸入隔離；測試不接觸真實終端。
                let services = super::host_services(&engine, None, trusted)
                    .and_resource(ResourceCapability::deny_all());
                let mut vm = engine.new_vm_with_services(services).unwrap();
                let outcome = vm.load_module(&module).unwrap().run().unwrap();
                assert!(
                    matches!(&outcome, RunOutcome::LuaError(error) if error.kind == expected),
                    "profile={profile:?} trusted={trusted} outcome={outcome:?}",
                );
            }
        }
    }

    fn run_stdin_arg_case(
        profile: &str,
        action: Option<&str>,
        source: &[u8],
        script_args: &[&str],
    ) -> (super::CliResult<u8>, Vec<u8>) {
        let mut args = vec![
            OsString::from("rivetlua"),
            OsString::from("-E"),
            OsString::from("--profile"),
            OsString::from(profile),
        ];
        if let Some(action) = action {
            args.extend([OsString::from("-e"), OsString::from(action)]);
        }
        args.push(OsString::from("-"));
        args.extend(script_args.iter().map(OsString::from));
        let mut stdin = Cursor::new(source);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = super::run_interpreter(&args, &mut stdin, &mut stdout, &mut stderr);
        (result, stderr)
    }

    fn run_interactive_repl_case(
        profile: &str,
        source: &[u8],
    ) -> (super::CliResult<u8>, Vec<u8>, Vec<u8>) {
        run_interactive_repl_case_with_action(profile, source, None)
    }

    fn run_interactive_repl_case_with_action(
        profile: &str,
        source: &[u8],
        action: Option<&str>,
    ) -> (super::CliResult<u8>, Vec<u8>, Vec<u8>) {
        let mut args = vec![
            OsString::from("rivetlua"),
            OsString::from("-E"),
            OsString::from("--profile"),
            OsString::from(profile),
        ];
        if let Some(action) = action {
            args.extend([OsString::from("-e"), OsString::from(action)]);
        }
        args.push(OsString::from("-i"));
        let mut stdin = Cursor::new(source);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = super::run_interpreter(&args, &mut stdin, &mut stdout, &mut stderr);
        (result, stdout, stderr)
    }

    struct CapturedReplOutput(Rc<RefCell<Vec<u8>>>);

    impl HostOutput for CapturedReplOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }
    }

    fn run_repl_with_captured_output(source: &[u8]) -> (super::CliResult<()>, Vec<u8>, Vec<u8>) {
        run_repl_with_captured_output_for_profile(LuaProfile::Lua55, None, source)
    }

    fn run_repl_with_captured_output_for_profile(
        profile: LuaProfile,
        setup: Option<&str>,
        source: &[u8],
    ) -> (super::CliResult<()>, Vec<u8>, Vec<u8>) {
        let engine = Engine::new(profile);
        let captured = Rc::new(RefCell::new(Vec::new()));
        let mut vm = engine
            .new_vm_with_services(HostServices::with_output(CapturedReplOutput(Rc::clone(
                &captured,
            ))))
            .unwrap();
        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        let mut bridge = super::NativeBridge {
            grant: None,
            attestor: None,
            loaded: Vec::new(),
            cache_root: std::env::temp_dir(),
        };
        #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
        let mut bridge = super::NativeBridge(std::marker::PhantomData);
        if let Some(setup) = setup {
            let module = engine.compile(setup.as_bytes()).unwrap();
            assert!(matches!(
                vm.load_module(&module).unwrap().run().unwrap(),
                RunOutcome::Returned(_)
            ));
        }
        let tostring = vm.get_global(b"tostring").unwrap();
        let original_tostring = vm.root(tostring).unwrap();
        let mut input = Cursor::new(source);
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let result = super::repl(
            &engine,
            &mut vm,
            &mut input,
            &mut output,
            &mut errors,
            &mut bridge,
            &original_tostring,
            false,
        );
        (result, captured.borrow().clone(), errors)
    }

    #[test]
    fn p17_interactive_locals_warning() {
        let warning = b"warning: locals do not survive across lines in interactive mode\n";
        let (result, stdout, stderr) = run_interactive_repl_case("lua55", b"  \t\tlocal x\n");
        assert!(matches!(result, Ok(0)), "lua55: {result:?}");
        let version = b"RivetLua 0.0.0 (Lua 5.5.1); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n";
        assert!(
            stdout.starts_with(version),
            "lua55 stdout: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert_eq!(&stdout[version.len()..], b">   \t\tlocal x\n> \n");
        assert!(stderr.starts_with(warning));
        assert_eq!(
            stderr
                .windows(warning.len())
                .filter(|part| *part == warning)
                .count(),
            1
        );

        let (result, stdout, stderr) = run_interactive_repl_case("lua55", b"local\n");
        assert!(matches!(result, Ok(0)), "lua55 NUL boundary: {result:?}");
        assert!(
            stdout.starts_with(version),
            "lua55 stdout: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert!(stderr.starts_with(warning));
        assert_eq!(
            stderr
                .windows(warning.len())
                .filter(|part| *part == warning)
                .count(),
            1
        );

        let (result, stdout, stderr) = run_repl_with_captured_output(b"local1 = 10\nlocal1 + 3\n");
        assert!(matches!(result, Ok(())), "lua55 boundary: {result:?}");
        assert_eq!(stdout, b"13\n");
        assert!(
            stderr.is_empty(),
            "lua55 stderr: {}",
            String::from_utf8_lossy(&stderr)
        );

        let (result, stdout, stderr) = run_interactive_repl_case("lua54", b"  \t\tlocal x\n");
        assert!(matches!(result, Ok(0)), "lua54: {result:?}");
        let version = b"RivetLua 0.0.0 (Lua 5.4.9); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n";
        assert!(
            stdout.starts_with(version),
            "lua54 stdout: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert_eq!(&stdout[version.len()..], b">   \t\tlocal x\n> \n");
        assert!(
            stderr.is_empty(),
            "lua54 stderr: {}",
            String::from_utf8_lossy(&stderr)
        );

        let args = [
            OsString::from("rivetlua"),
            OsString::from("-E"),
            OsString::from("--profile"),
            OsString::from("lua55"),
            OsString::from("-"),
        ];
        let mut stdin = Cursor::new(b"  \t\tlocal x\n".as_slice());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = super::run_interpreter(&args, &mut stdin, &mut stdout, &mut stderr);
        assert!(matches!(result, Ok(0)), "lua55 script: {result:?}");
        assert!(
            stdout.is_empty(),
            "lua55 script stdout: {}",
            String::from_utf8_lossy(&stdout)
        );
        assert!(
            stderr.is_empty(),
            "lua55 script stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    #[test]
    fn p17_repl_bounded_print_abort_is_fatal() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let engine = Engine::new(profile);
            let mut vm = engine.new_vm().unwrap();
            #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
            let mut bridge = super::NativeBridge {
                grant: None,
                attestor: None,
                loaded: Vec::new(),
                cache_root: std::env::temp_dir(),
            };
            #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
            let mut bridge = super::NativeBridge(std::marker::PhantomData);
            let module = super::compile_source_raw(
                &engine,
                b"print = function() while true do end end",
                b"=p17-repl-setup",
            )
            .unwrap();
            let mut errors = Vec::new();
            super::run_module(
                &mut vm,
                &module,
                &[],
                &mut io::sink(),
                &mut errors,
                &mut bridge,
                None,
            )
            .unwrap();
            let print_module =
                super::compile_source_raw(&engine, b"return print(...)", b"=(REPL print)").unwrap();
            let result = super::print_interactive_values_with_fuel(
                &mut vm,
                &print_module,
                &[Value::Integer(1)],
                &mut errors,
                &mut bridge,
                32,
            );
            assert!(result.is_err(), "profile={profile:?}");
            assert!(
                errors
                    .windows("REPL print 執行額度耗盡".len())
                    .any(|part| part == "REPL print 執行額度耗盡".as_bytes()),
                "profile={profile:?}: {}",
                String::from_utf8_lossy(&errors)
            );
        }
    }

    #[test]
    fn p17_repl_error_classification_keeps_host_failures_fatal() {
        assert!(super::repl_recoverable_lua_error(RuntimeErrorKind::Thrown));
        assert!(super::repl_recoverable_lua_error(
            RuntimeErrorKind::NotCallable
        ));
        for kind in [
            RuntimeErrorKind::HostPolicyIo,
            RuntimeErrorKind::HostPolicyOs,
            RuntimeErrorKind::HostDeadline,
            RuntimeErrorKind::HostResourceBudget,
            RuntimeErrorKind::HostUnsupported,
            RuntimeErrorKind::Heap(rivetlua::VmError::AllocationFailed),
        ] {
            assert!(!super::repl_recoverable_lua_error(kind), "{kind:?}");
        }

        for profile in ["lua55", "lua54"] {
            let version = if profile == "lua55" {
                b"RivetLua 0.0.0 (Lua 5.5.1); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n".as_slice()
            } else {
                b"RivetLua 0.0.0 (Lua 5.4.9); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n".as_slice()
            };
            let (result, stdout, stderr) =
                run_interactive_repl_case(profile, b" --\na = 2\n");
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(
                stdout,
                [version, b">  --\n> a = 2\n> \n"].concat(),
                "{profile}"
            );
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            let (result, stdout, stderr) = run_interactive_repl_case_with_action(
                profile,
                b"a = {}\na.\nb = 1\n",
                Some("_PROMPT='alo'; _PROMPT2='cont'"),
            );
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(
                stdout,
                [version, b"aloa = {}\naloa.\ncontb = 1\nalo\n"].concat(),
                "{profile}"
            );
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            let (result, stdout, stderr) = run_interactive_repl_case_with_action(
                profile,
                b" --\na = 2\n",
                Some("_PROMPT=''; _PROMPT2=''"),
            );
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(stdout, [version, b" --\na = 2\n\n"].concat(), "{profile}");
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            let (result, stdout, stderr) = run_interactive_repl_case_with_action(
                profile,
                b" --\na = 2\n",
                Some("local n=0; _PROMPT=setmetatable({}, {__tostring=function() n=n+1; return tostring(n) end})"),
            );
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(
                stdout,
                [version, b"1 --\n2a = 2\n3\n"].concat(),
                "{profile}"
            );
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            let lua_profile = if profile == "lua55" {
                LuaProfile::Lua55
            } else {
                LuaProfile::Lua54
            };
            let (result, stdout, stderr) = run_repl_with_captured_output_for_profile(
                lua_profile,
                Some("p17_print_count=0; p17_original_print=print; print=function(...) p17_print_count=p17_print_count+1; return p17_original_print(...) end"),
                b"return(101)\ndo return 13, 22 end\nreturn nil, {}\na = 1\np17_print_count\n",
            );
            assert!(matches!(result, Ok(())), "{profile}: {result:?}");
            assert!(
                stdout.starts_with(b"101\n13\t22\nnil\ttable: "),
                "{profile}: {}",
                String::from_utf8_lossy(&stdout)
            );
            let object_line_end = stdout
                .iter()
                .position(|byte| *byte == b'\n')
                .and_then(|first_end| {
                    stdout[first_end + 1..]
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map(|second_end| first_end + 1 + second_end)
                })
                .and_then(|second_end| {
                    stdout[second_end + 1..]
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map(|third_end| second_end + 1 + third_end)
                })
                .expect("nil/object return must produce one output line");
            assert_eq!(
                &stdout[object_line_end + 1..],
                b"3\n",
                "{profile}: {}",
                String::from_utf8_lossy(&stdout)
            );
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            let (result, _, stderr) = run_interactive_repl_case_with_action(
                profile,
                b"",
                Some("_PROMPT=setmetatable({}, {__tostring=function() error('PROMPT_BROKEN') end})"),
            );
            assert!(result.is_err(), "{profile}: {result:?}");
            assert!(
                stderr.windows(b"PROMPT_BROKEN".len()).any(|part| part == b"PROMPT_BROKEN"),
                "{profile}: {}",
                String::from_utf8_lossy(&stderr)
            );

            let (result, stdout, stderr) =
                run_interactive_repl_case(profile, b"function p17_incomplete()\n");
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(
                stdout,
                [version, b"> function p17_incomplete()\n>> \n> \n"].concat(),
                "{profile}"
            );
            for required in ["未完成的 REPL 輸入".as_bytes(), b"near <eof>\n"] {
                assert!(
                    stderr.windows(required.len()).any(|part| part == required),
                    "{profile}: {}",
                    String::from_utf8_lossy(&stderr)
                );
            }

            let (result, stdout, stderr) = run_interactive_repl_case(
                profile,
                b"function p17_repl_multiline()\nend\n",
            );
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert_eq!(
                stdout,
                [version, b"> function p17_repl_multiline()\n>> end\n> \n"].concat(),
                "{profile}"
            );
            assert!(stderr.is_empty(), "{profile}: {}", String::from_utf8_lossy(&stderr));

            for source in [b"a.\n".as_slice(), b"a.".as_slice()] {
                let (result, _, stderr) = run_interactive_repl_case(profile, source);
                assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
                assert!(
                    stderr.windows("預期名稱".len()).any(|part| part == "預期名稱".as_bytes()),
                    "{profile}: {}",
                    String::from_utf8_lossy(&stderr)
                );
                assert!(
                    stderr.windows(b"near <eof>\n".len()).any(|part| part == b"near <eof>\n"),
                    "{profile}: {}",
                    String::from_utf8_lossy(&stderr)
                );
            }

            let (result, _, stderr) =
                run_interactive_repl_case(profile, b"a = {}\na.\nb = 1\nassert(a.b == 1)\n");
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert!(
                stderr.is_empty(),
                "{profile}: {}",
                String::from_utf8_lossy(&stderr)
            );

            let (result, _, stderr) = run_interactive_repl_case(profile, b"a.(\n");
            assert!(matches!(result, Ok(0)), "{profile}: {result:?}");
            assert!(
                stderr.windows("預期名稱".len()).any(|part| part == "預期名稱".as_bytes()),
                "{profile}: {}",
                String::from_utf8_lossy(&stderr)
            );
            assert!(
                !stderr.windows(b"near <eof>\n".len()).any(|part| part == b"near <eof>\n"),
                "{profile}: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    #[test]
    fn p17_script_args_reflect_preceding_action() {
        for profile in ["lua55", "lua54"] {
            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("arg[1] = 100"),
                b"local value = ...; assert(value == 100)",
                &[],
            );
            assert!(
                matches!(result, Ok(0)),
                "{profile}: {result:?}; stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    #[test]
    fn p17_script_args_use_current_table_raw_values_and_keep_objects_rooted() {
        for profile in ["lua55", "lua54"] {
            let action = "arg = setmetatable({[1] = true, [3] = {answer = 7}}, {__len = function() collectgarbage('collect'); return 3.0 end, __index = function() error('indexed') end})";
            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some(action),
                b"local a,b,c = ...; collectgarbage('collect'); assert(a == true and b == nil and type(c) == 'table' and c.answer == 7)",
                &["old", "values"],
            );
            assert!(
                matches!(result, Ok(0)),
                "{profile}: {result:?}; stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    #[test]
    fn p17_script_args_len_uses_original_table_after_global_replacement() {
        for profile in ["lua55", "lua54"] {
            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some(
                    "arg = setmetatable({[1] = 'original'}, {__len = function() arg = {[1] = 'replacement'}; collectgarbage('collect'); return 1 end})",
                ),
                b"local value = ...; assert(value == 'original')",
                &[],
            );
            assert!(
                matches!(result, Ok(0)),
                "{profile}: {result:?}; stderr={}",
                String::from_utf8_lossy(&stderr)
            );

            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("weak = setmetatable({arg}, {__mode = 'v'}); arg = {[1] = 'current'}"),
                b"collectgarbage('collect'); assert(weak[1] == nil); local value = ...; assert(value == 'current')",
                &[],
            );
            assert!(
                matches!(result, Ok(0)),
                "{profile}: {result:?}; stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    #[test]
    fn p17_script_args_captured_builtins_survive_preceding_action() {
        for profile in ["lua55", "lua54"] {
            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("arg = {[1] = 100}; type = nil; math.tointeger = nil; error = nil"),
                b"local value = ...; assert(value == 100)",
                &[],
            );
            assert!(
                matches!(result, Ok(0)),
                "{profile}: {result:?}; stderr={}",
                String::from_utf8_lossy(&stderr)
            );
        }
    }

    #[test]
    fn p17_script_args_len_failure_and_excess_do_not_run_script() {
        for profile in ["lua55", "lua54"] {
            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("arg = setmetatable({}, {__len = function() error('length failure') end})"),
                b"error('script ran')",
                &[],
            );
            assert!(
                matches!(result, Err(ref error) if error.status == 1),
                "{profile}: {result:?}"
            );
            assert!(
                stderr
                    .windows(b"length failure".len())
                    .any(|part| part == b"length failure")
            );
            assert!(
                stderr
                    .windows(b"command line".len())
                    .any(|part| part == b"command line")
            );
            assert!(
                !stderr
                    .windows(b"script ran".len())
                    .any(|part| part == b"script ran")
            );

            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("arg = setmetatable({}, {__len = function() return 1.5 end})"),
                b"error('script ran')",
                &[],
            );
            assert!(
                matches!(result, Err(ref error) if error.status == 1),
                "{profile}: {result:?}"
            );
            assert!(
                stderr
                    .windows(b"object length is not an integer".len())
                    .any(|part| part == b"object length is not an integer")
            );
            assert!(
                !stderr
                    .windows(b"rivetlua script args".len())
                    .any(|part| part == b"rivetlua script args")
            );
            assert!(
                !stderr
                    .windows(b"script ran".len())
                    .any(|part| part == b"script ran")
            );

            let (result, stderr) = run_stdin_arg_case(
                profile,
                Some("arg = setmetatable({}, {__len = function() return 1000001 end})"),
                b"error('script ran')",
                &[],
            );
            let limit = "上限".as_bytes();
            assert!(
                matches!(result, Err(ref error) if error.status == 1 && error.message.windows(limit.len()).any(|part| part == limit)),
                "{profile}: {result:?}"
            );
            assert!(
                !stderr
                    .windows(b"script ran".len())
                    .any(|part| part == b"script ran")
            );
        }
    }

    #[test]
    fn p17_script_args_load_error_precedes_arg_type_check() {
        for profile in ["lua55", "lua54"] {
            let (result, stderr) = run_stdin_arg_case(profile, Some("arg = 1"), b"return (", &[]);
            let compile_failure = "編譯失敗".as_bytes();
            assert!(
                matches!(result, Err(ref error) if error.status == 1 && error.message.windows(compile_failure.len()).any(|part| part == compile_failure)),
                "{profile}: {result:?}"
            );
            assert!(
                !stderr
                    .windows(b"'arg' is not a table".len())
                    .any(|part| part == b"'arg' is not a table")
            );

            let (result, stderr) = run_stdin_arg_case(profile, Some("arg = 1"), b"return 1", &[]);
            assert!(
                matches!(result, Err(ref error) if error.status == 1),
                "{profile}: {result:?}"
            );
            assert!(
                stderr
                    .windows(b"'arg' is not a table".len())
                    .any(|part| part == b"'arg' is not a table")
            );
            assert!(
                !stderr
                    .windows(b"rivetlua script args".len())
                    .any(|part| part == b"rivetlua script args")
            );
        }
    }

    #[test]
    fn p17_script_args_failed_collection_recovers_and_roots_returned_objects() {
        for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
            let engine = Engine::new(profile);
            let mut vm = engine.new_vm().unwrap();
            #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
            let mut bridge = super::NativeBridge {
                grant: None,
                attestor: None,
                loaded: Vec::new(),
                cache_root: std::env::temp_dir(),
            };
            #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
            let mut bridge = super::NativeBridge(std::marker::PhantomData);
            let mut errors = Vec::new();
            let table = super::set_arg_table(
                &mut vm,
                &[
                    OsString::from("rivetlua"),
                    OsString::from("-"),
                    OsString::from("held"),
                ],
                1,
            )
            .unwrap();
            let length_function =
                super::capture_script_arg_length(&engine, &mut vm, &mut errors, &mut bridge)
                    .unwrap();

            vm.set_global(b"arg", Value::Integer(1)).unwrap();
            assert!(
                super::script_values(&mut vm, &length_function, &mut errors, &mut bridge).is_err()
            );
            let table_value = table.value(&vm).unwrap();
            vm.set_global(b"arg", table_value).unwrap();
            vm.inject_next_allocation_failure();
            assert!(
                super::script_values(&mut vm, &length_function, &mut errors, &mut bridge).is_err()
            );

            let (values, roots) =
                super::script_values(&mut vm, &length_function, &mut errors, &mut bridge).unwrap();
            assert_eq!(values.len(), 1);
            assert_eq!(roots.len(), 1);
            vm.set_global(b"arg", Value::Nil).unwrap();
            drop(table);
            vm.collect().unwrap();
            assert_eq!(roots[0].value(&vm).unwrap(), values[0]);
            assert_eq!(vm.read_byte_string(&roots[0]).unwrap(), b"held");
        }
    }

    #[test]
    fn p17_preprocess_first_line_hash_after_optional_bom() {
        for (source, expected) in [
            (
                b"# comment!!\nprint(3)".as_slice(),
                b"           \nprint(3)".as_slice(),
            ),
            (
                b"\xef\xbb\xbf# comment!!\nprint(3)".as_slice(),
                b"           \nprint(3)".as_slice(),
            ),
            (
                b"#!lua\r\nprint(3)".as_slice(),
                b"      \nprint(3)".as_slice(),
            ),
            (b"# comment".as_slice(), b"         ".as_slice()),
        ] {
            let mut actual = source.to_vec();
            super::preprocess_source(&mut actual);
            assert_eq!(actual, expected, "首行 # 必須保留後續換行與行號");
        }
    }

    #[test]
    fn p17_binary_file_prefix_load_preserves_binary_validation() {
        let make_print_chunk = |profile| {
            let engine = Engine::new(profile);
            let generator = engine
                .compile(b"return string.dump(assert(load('print(3)')))")
                .unwrap();
            let services = HostServices::deny_all()
                .and_load(
                    super::LoadCapability::deny_all()
                        .and_compiler(engine.clone())
                        .with_limits(super::load_limits()),
                )
                .and_dump(super::DumpCapability::deny_all().with_official_bytecode(true));
            let mut vm = engine.new_vm_with_services(services).unwrap();
            let outcome = vm.load_module(&generator).unwrap().run().unwrap();
            let RunOutcome::Returned(values) = outcome else {
                panic!("string.dump 必須回傳官方 chunk: {outcome:?}");
            };
            let value = values.first().copied().expect("string.dump 回傳 binary");
            let root = vm.root(value).unwrap();
            let chunk = vm.read_byte_string(&root).unwrap();
            assert_eq!(rivetlua::classify_input(&chunk), super::InputFormat::Official);
            chunk
        };

        let prepend = |prefix: &[u8], payload: &[u8]| {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(payload);
            bytes
        };

        for (profile, other_profile) in [
            (LuaProfile::Lua55, LuaProfile::Lua54),
            (LuaProfile::Lua54, LuaProfile::Lua55),
        ] {
            let engine = Engine::new(profile);
            let chunk = make_print_chunk(profile);
            let other_chunk = make_print_chunk(other_profile);
            let prefixed_chunk = prepend(b"# comment\n", &chunk);
            assert!(
                super::file_input_is_binary(&chunk, 0),
                "{profile:?}: raw Official 固定標頭需走不掃描前綴的快速路徑"
            );
            assert!(
                !super::file_input_is_binary(&prefixed_chunk, 0),
                "{profile:?}: 前綴 binary 應先通過 budget admission 再掃描首行"
            );
            let run = |bytes| {
                let module = super::input_module(
                    &engine,
                    bytes,
                    b"=p17-binary-file-prefix",
                    true,
                )
                .unwrap();
                let captured = Rc::new(RefCell::new(Vec::new()));
                let mut vm = engine
                    .new_vm_with_services(HostServices::with_output(CapturedReplOutput(
                        Rc::clone(&captured),
                    )))
                    .unwrap();
                let outcome = vm.load_module(&module).unwrap().run().unwrap();
                assert!(matches!(outcome, RunOutcome::Returned(_)), "{outcome:?}");
                captured.borrow().clone()
            };
            let assert_binary_rejected = |bytes| {
                let error = super::input_module(
                    &engine,
                    bytes,
                    b"=p17-binary-file-prefix",
                    true,
                )
                .expect_err("prefixed binary must be rejected by the SDK");
                assert!(
                    error.message.starts_with("binary 載入失敗".as_bytes()),
                    "{profile:?}: {}",
                    String::from_utf8_lossy(&error.message)
                );
            };

            assert_eq!(run(chunk.clone()), b"3\n");
            assert_eq!(
                run(prepend(b"# comment\n", &chunk)),
                b"3\n",
                "{profile:?}: 首行 # 後的官方 chunk 應執行 print(3)"
            );
            assert_eq!(
                run(prepend(b"\xef\xbb\xbf# comment\n", &chunk)),
                b"3\n",
                "{profile:?}: BOM 與首行 # 後的官方 chunk 應執行 print(3)"
            );

            assert!(super::input_module(
                &engine,
                b"# line one\nprint(3)".to_vec(),
                b"=p17-prefix-source",
                true,
            )
            .is_ok());
            assert!(super::input_module(
                &engine,
                b"# comment".to_vec(),
                b"=p17-no-newline",
                true,
            )
            .is_ok());

            assert_binary_rejected(prepend(b"# comment\n", &other_chunk));
            let mut unsupported_version = chunk.clone();
            unsupported_version[4] = 0xff;
            assert_binary_rejected(prepend(b"# comment\n", &unsupported_version));
            let mut truncated = chunk.clone();
            truncated.truncate(8);
            assert_binary_rejected(prepend(b"# comment\n", &truncated));

            let non_file = super::input_module(
                &engine,
                prepend(b"# comment\n", &chunk),
                b"=p17-stdin-input",
                false,
            )
            .unwrap_err();
            assert!(
                non_file.message.starts_with("編譯失敗：".as_bytes()),
                "一般 stdin source 路徑不得擴大為可消費檔案前綴後的 binary: {}",
                String::from_utf8_lossy(&non_file.message)
            );
        }
    }

    #[test]
    fn p17_preprocess_preserves_other_source_prefixes() {
        for (source, expected) in [
            (b"".as_slice(), b"".as_slice()),
            (b"\xef\xbb\xbf".as_slice(), b"".as_slice()),
            (b"\xef\xbb\xbfprint(3)".as_slice(), b"print(3)".as_slice()),
            (b"\xef".as_slice(), b"\xef".as_slice()),
            (b"\xef\xbb".as_slice(), b"\xef\xbb".as_slice()),
            (b" # comment\n".as_slice(), b" # comment\n".as_slice()),
            (
                b"print(3)\n# comment\n".as_slice(),
                b"print(3)\n# comment\n".as_slice(),
            ),
        ] {
            let mut actual = source.to_vec();
            super::preprocess_source(&mut actual);
            assert_eq!(actual, expected, "只可移除完整 BOM 與首字節 # 行");
        }
    }

    #[test]
    fn p17_preprocess_cli_lexical_error_format() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let engine = Engine::new(profile);
            let lexical = super::compile_source_raw(&engine, b"\xef", b"=bad-bom").unwrap_err();
            assert!(
                matches!(&lexical, rivetlua::CompileError::Diagnostic(diagnostic) if diagnostic.message == "未知詞法元素")
            );
            let failure = super::compile_source(&engine, b"\xef", b"=bad-bom").unwrap_err();
            assert_eq!(
                failure.message,
                format!("編譯失敗：{lexical} (syntax error) (unexpected symbol)").as_bytes()
            );

            let parse = super::compile_source_raw(&engine, b"return (", b"=parse").unwrap_err();
            assert!(
                matches!(&parse, rivetlua::CompileError::Diagnostic(diagnostic) if diagnostic.message != "未知詞法元素")
            );
            let failure = super::compile_source(&engine, b"return (", b"=parse").unwrap_err();
            assert_eq!(
                failure.message,
                format!("編譯失敗：{parse} (syntax error)").as_bytes()
            );
        }
    }

    #[test]
    fn cli_dump_policy_uses_finite_work_temporary_and_encoded_limits() {
        assert_eq!(
            dump_limits(),
            rivetlua::DumpLimits {
                max_work_units: 512 * 1024 * 1024,
                max_temporary_bytes: 4 * 1024 * 1024,
                max_encoded_bytes: 1024 * 1024,
            }
        );
    }

    #[test]
    fn cli_load_policy_matches_finite_gc_work_temporary_and_fuel_caps() {
        assert_eq!(
            load_limits(),
            rivetlua::LoadLimits {
                max_source_bytes: 4 * 1024 * 1024,
                max_encoded_bytes: 64 * 1024 * 1024,
                max_module_allocation_bytes: 64 * 1024 * 1024,
                max_temporary_bytes: 256 * 1024 * 1024,
                max_work_units: 2 * 1024 * 1024 * 1024,
                max_reader_chunks: 512,
                max_path_candidates: 512,
            }
        );
        assert_eq!(CLI_EXECUTION_FUEL, 8_000_000_000);
    }

    #[test]
    fn cli_rejects_nested_returned_values_with_a_nonzero_diagnostic() {
        let outcome = RunOutcome::NestedReturned(vec![Value::Integer(42)]);
        let mut errors = Vec::new();

        let failure = report_unsupported_run_outcome("-l 載入模組", &outcome, &mut errors)
            .expect("診斷輸出應成功");

        assert_eq!(failure.status, 1);
        assert!(
            errors
                .windows(b"NestedReturned".len())
                .any(|window| window == b"NestedReturned")
        );
        assert!(errors.ends_with(b"\n"));
    }

    #[test]
    fn cli_debug_policy_matches_official_suite_capabilities() {
        assert_eq!(
            debug_capability(),
            DebugCapability::deny_all()
                .allow(DebugPermission::Info)
                .allow(DebugPermission::StackInspection)
                .allow(DebugPermission::LocalInspection)
                .allow(DebugPermission::LocalMutation)
                .allow(DebugPermission::Upvalues)
                .allow(DebugPermission::UpvalueMutation)
                .allow(DebugPermission::UpvalueIdentity)
                .allow(DebugPermission::RegistryRead)
                .allow(DebugPermission::UserValueRead)
                .allow(DebugPermission::UserValueWrite)
                .allow(DebugPermission::Traceback)
                .allow(DebugPermission::CountHook)
                .allow(DebugPermission::EventHook)
                .allow(DebugPermission::MetatableRead)
                .allow(DebugPermission::TableMetatableWrite)
        );
    }

    #[test]
    fn cli_atomic_output_failure_preserves_destination_and_cleans_temporary_file() {
        let root = std::env::temp_dir().join(format!(
            "rivetlua-cli-atomic-unit-{}-{}",
            std::process::id(),
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        let destination = root.join("destination");
        let sentinel = destination.join("sentinel");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(&sentinel, b"preserve").unwrap();

        assert!(atomic_write(&destination, b"complete artifact").is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve");
        let leftovers = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".rivetluac-"))
            .count();
        assert_eq!(leftovers, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cli_entropy_reader_consumes_exactly_one_native_endian_seed() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut source = Cursor::new(bytes);
        assert_eq!(
            read_entropy_seed(&mut source),
            Ok(u64::from_ne_bytes(bytes[..8].try_into().unwrap()))
        );
        assert_eq!(source.position(), 8);
    }

    struct InterruptedOnceReader {
        source: Cursor<[u8; 8]>,
        interrupted: bool,
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.source.read(buffer)
        }
    }

    #[test]
    fn cli_entropy_reader_retries_interrupted_reads() {
        let bytes = [8, 7, 6, 5, 4, 3, 2, 1];
        let mut source = InterruptedOnceReader {
            source: Cursor::new(bytes),
            interrupted: false,
        };
        assert_eq!(
            read_entropy_seed(&mut source),
            Ok(u64::from_ne_bytes(bytes))
        );
        assert!(source.interrupted);
        assert_eq!(source.source.position(), 8);
    }

    #[test]
    fn cli_entropy_reader_maps_short_reads_and_read_errors_to_read_failed() {
        let mut short = Cursor::new([0_u8; 7]);
        assert_eq!(
            read_entropy_seed(&mut short),
            Err(HostEntropyError::ReadFailed)
        );
        assert_eq!(short.position(), 7);

        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }

        assert_eq!(
            read_entropy_seed(&mut FailingReader),
            Err(HostEntropyError::ReadFailed)
        );
    }

    #[test]
    fn cli_unix_epoch_seconds_floor_negative_fractions() {
        assert_eq!(unix_epoch_seconds(UNIX_EPOCH), Ok(0));
        assert_eq!(
            unix_epoch_seconds(
                UNIX_EPOCH
                    .checked_add(Duration::new(2, 999_999_999))
                    .unwrap()
            ),
            Ok(2)
        );
        assert_eq!(
            unix_epoch_seconds(UNIX_EPOCH.checked_sub(Duration::from_nanos(1)).unwrap()),
            Ok(-1)
        );
        assert_eq!(
            unix_epoch_seconds(UNIX_EPOCH.checked_sub(Duration::new(1, 1)).unwrap()),
            Ok(-2)
        );
    }

    #[test]
    fn cli_unix_epoch_seconds_checks_i64_bounds_when_system_time_can_represent_them() {
        let max_seconds = i64::MAX as u64;
        if let Some(maximum) = UNIX_EPOCH.checked_add(Duration::from_secs(max_seconds)) {
            assert_eq!(unix_epoch_seconds(maximum), Ok(i64::MAX));
        }
        if let Some(maximum_fraction) = UNIX_EPOCH
            .checked_add(Duration::from_secs(max_seconds))
            .and_then(|time| time.checked_add(Duration::from_nanos(999_999_999)))
        {
            assert_eq!(unix_epoch_seconds(maximum_fraction), Ok(i64::MAX));
        }
        if let Some(overflow) = UNIX_EPOCH.checked_add(Duration::from_secs(max_seconds + 1)) {
            assert_eq!(
                unix_epoch_seconds(overflow).unwrap_err().kind,
                HostResourceErrorKind::PlatformDifference
            );
        }

        let min_magnitude = 1_u64 << 63;
        if let Some(minimum) = UNIX_EPOCH.checked_sub(Duration::from_secs(min_magnitude)) {
            assert_eq!(unix_epoch_seconds(minimum), Ok(i64::MIN));
        }
        if let Some(underflow) = UNIX_EPOCH
            .checked_sub(Duration::from_secs(min_magnitude))
            .and_then(|time| time.checked_sub(Duration::from_nanos(1)))
        {
            assert_eq!(
                unix_epoch_seconds(underflow).unwrap_err().kind,
                HostResourceErrorKind::PlatformDifference
            );
        }
    }

    fn run_resource_script(source: &[u8], resource: ResourceCapability) -> RunOutcome {
        let engine = Engine::new(LuaProfile::Lua55);
        let module = engine.compile(source).unwrap();
        let mut vm = engine
            .new_vm_with_services(HostServices::deny_all().and_resource(resource))
            .unwrap();
        vm.load_module(&module).unwrap().run().unwrap()
    }

    #[test]
    fn cli_resource_deadline_expires_and_unrepresentable_deadline_fails_closed() {
        for deadline in [
            CliResourceDeadline {
                expires_at: Some(Instant::now()),
            },
            CliResourceDeadline { expires_at: None },
        ] {
            let outcome =
                run_resource_script(b"return os.clock()", cli_resource_capability(deadline));
            let RunOutcome::LuaError(error) = outcome else {
                panic!("expired resource deadline 應拒絕 host operation: {outcome:?}");
            };
            assert_eq!(error.kind, RuntimeErrorKind::HostDeadline);
        }
    }

    #[test]
    fn cli_resource_budget_is_charged_before_authorize_deadline_and_perform() {
        for work_units in [0, 1, 2] {
            let limits = ResourceLimits {
                max_work_units: work_units,
                ..ResourceLimits::default()
            };
            let deadline = CliResourceDeadline::from_now();
            assert!(deadline.expires_at.is_some());
            let resource = cli_resource_capability(deadline).with_limits(limits);
            let outcome = run_resource_script(b"return os.time()", resource);
            let RunOutcome::LuaError(error) = outcome else {
                panic!("work_units={work_units} 應在 host effect 前耗盡: {outcome:?}");
            };
            assert_eq!(error.kind, RuntimeErrorKind::HostResourceBudget);
        }
    }

    #[test]
    fn cli_locale_response_is_precharged_and_respects_the_temporary_limit() {
        let limited = ResourceLimits {
            max_temporary_bytes: 0,
            ..ResourceLimits::default()
        };
        let outcome = run_resource_script(
            b"return os.setlocale() == 'C'",
            cli_resource_capability(CliResourceDeadline::from_now()).with_limits(limited),
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("zero temporary bytes 應在建立 C locale 回應前耗盡: {outcome:?}");
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostResourceBudget);

        let admitted = ResourceLimits {
            max_temporary_bytes: 1,
            ..ResourceLimits::default()
        };
        let outcome = run_resource_script(
            b"return os.setlocale() == 'C'",
            cli_resource_capability(CliResourceDeadline::from_now()).with_limits(admitted),
        );
        assert!(matches!(
            outcome,
            RunOutcome::Returned(values) if values == [Value::Boolean(true)]
        ));
    }

    #[cfg(not(unix))]
    #[test]
    fn cli_entropy_provider_fails_closed_on_unsupported_platforms() {
        use rivetlua::HostEntropy;

        assert_eq!(
            HostEntropy::seed(&mut OsEntropy),
            Err(HostEntropyError::ReadFailed)
        );
    }
}

#[derive(Debug)]
struct CompilerOptions {
    profile: LuaProfile,
    list: bool,
    syntax_only: bool,
    show_version: bool,
    output: Option<OsString>,
    input: Option<OsString>,
}

fn parse_compiler_options(args: &[OsString]) -> CliResult<CompilerOptions> {
    let mut profile = default_profile();
    let mut list = false;
    let mut syntax_only = false;
    let mut show_version = false;
    let mut output = None;
    let mut i = 1;
    let mut input_start = args.len();
    while i < args.len() {
        let bytes = os_bytes(&args[i]);
        if bytes == b"--" {
            input_start = i + 1;
            break;
        }
        if bytes == b"-" || !bytes.starts_with(b"-") {
            input_start = i;
            break;
        }
        if bytes == b"-l" {
            list = true;
        } else if bytes == b"-p" {
            syntax_only = true;
        } else if bytes == b"-v" {
            show_version = true;
        } else if bytes == b"--profile" {
            i += 1;
            let Some(value) = args.get(i).map(|arg| os_bytes(arg)) else {
                return Err(CliFailure::usage("--profile 需要 lua54 或 lua55"));
            };
            profile = parse_profile(&value)?;
        } else if bytes.starts_with(b"--profile=") {
            profile = parse_profile(&bytes[b"--profile=".len()..])?;
        } else if bytes == b"-o" || bytes.starts_with(b"-o") {
            let attached = &bytes[2..];
            let value = if attached.is_empty() {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err(CliFailure::usage("-o 需要輸出路徑"));
                };
                os_bytes(value)
            } else {
                attached.to_vec()
            };
            if value.is_empty() || (value.starts_with(b"-") && value != b"-") {
                return Err(CliFailure::usage("-o 需要輸出路徑"));
            }
            output = Some(os_from_bytes(&value));
        } else {
            return Err(CliFailure::usage(format!(
                "不支援的選項：{}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        i += 1;
    }
    let remaining = args.get(input_start..).unwrap_or_default();
    if remaining.len() > 1 {
        return Err(CliFailure::usage("rivetluac 一次只接受一個輸入檔案"));
    }
    let input = remaining.first().cloned();
    if output.is_some() && (list || syntax_only) {
        return Err(CliFailure::usage("-o 不可與 -l 或 -p 同時使用"));
    }
    Ok(CompilerOptions {
        profile,
        list,
        syntax_only,
        show_version,
        output,
        input,
    })
}

fn compiler_version(profile: LuaProfile) -> &'static [u8] {
    match profile {
        LuaProfile::Lua54 => b"RivetLua luac (Lua 5.4.9)\n",
        LuaProfile::Lua55 => b"RivetLua luac (Lua 5.5.1)\n",
    }
}

fn run_compiler(args: &[OsString], stdin: &mut dyn Read, stdout: &mut dyn Write) -> CliResult<u8> {
    let options = parse_compiler_options(args)?;
    if options.show_version {
        write_bytes(stdout, compiler_version(options.profile))?;
        if options.input.is_none()
            && options.output.is_none()
            && !options.list
            && !options.syntax_only
        {
            return Ok(0);
        }
    }
    let engine = Engine::new(options.profile);
    let (input, chunk_name, file_mode) = match options.input.as_ref() {
        Some(path) if os_bytes(path) != b"-" => {
            let bytes = read_file(Path::new(path), MAX_INPUT_BYTES)?;
            let name = os_bytes(path);
            (bytes, name, true)
        }
        Some(_) | None => (read_input(stdin, MAX_INPUT_BYTES)?, b"=stdin".to_vec(), false),
    };
    let module = input_module(&engine, input, &chunk_name, file_mode)?;
    if options.list {
        let source_name = module
            .source_name()
            .map(|name| name.escape_ascii().to_string())
            .unwrap_or_else(|| "<none>".to_string());
        let summary = format!(
            "profile={:?} format={:?} origin={:?} source_name={} main_line={:?}\n",
            module.profile(),
            module.format_version(),
            module.origin(),
            source_name,
            module.main_line_range()
        );
        write_bytes(stdout, summary.as_bytes())?;
    }
    if options.list || options.syntax_only {
        return Ok(0);
    }
    let budget = TransportBudget::new(ContainerLimits::default());
    let encoded = engine
        .save_module(&module, &budget)
        .map_err(|error| CliFailure::failed(format!("RVCT 儲存失敗：{error}")))?;
    let Some(destination) = options.output else {
        return atomic_write(Path::new("rivetluac.out"), &encoded)
            .map(|_| 0)
            .map_err(|error| CliFailure::failed(format!("輸出檔案寫入失敗：{error}")));
    };
    if os_bytes(&destination) == b"-" {
        write_bytes(stdout, &encoded)?;
        return Ok(0);
    }
    let destination = PathBuf::from(destination);
    atomic_write(&destination, &encoded)
        .map(|_| 0)
        .map_err(|error| CliFailure::failed(format!("輸出檔案寫入失敗：{error}")))
}

static NEXT_OUTPUT_TEMP: AtomicU64 = AtomicU64::new(0);

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "輸出路徑缺少檔名",
        ));
    }
    for _ in 0..32 {
        let sequence = NEXT_OUTPUT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".rivetluac-{}-{sequence}.tmp", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let write_result = file.write_all(bytes).and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "無法建立唯一暫存輸出檔",
    ))
}

fn run_interpreter(
    args: &[OsString],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> CliResult<u8> {
    run_interpreter_inner(
        args,
        stdin,
        stdout,
        stderr,
        #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
        None,
        false,
    )
}

fn run_interpreter_inner(
    args: &[OsString],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))] attestor: Option<
        &mut dyn FnMut(VerifiedNative) -> AttestedNative,
    >,
    standalone_signal: bool,
) -> CliResult<u8> {
    let options = parse_options(args)?;
    let _signal_session = if standalone_signal
        && (!options.show_version
            || options.interactive
            || options.script.is_some()
            || !options.actions.is_empty())
    {
        Some(StandaloneSignalSession::install()?)
    } else {
        None
    };
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let mut bridge = NativeBridge::from_env(options.profile, attestor)?;
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let mut bridge = {
        if std::env::var_os("RIVETLUA_NATIVE_MANIFEST").is_some() {
            return Err(CliFailure::failed(
                "native-grant: feature 此 CLI 未編入原生載入能力",
            ));
        }
        NativeBridge(std::marker::PhantomData)
    };
    if options.show_version {
        write_bytes(stdout, version_line(options.profile))?;
    }
    let engine = Engine::new(options.profile);
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let native_cpath = bridge.grant_cpath();
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let native_cpath: Option<Vec<u8>> = None;
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let capability_cpath = Some(native_cpath.clone().unwrap_or_default());
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let capability_cpath = None;
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let trusted = bridge.grant.is_some();
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let trusted = false;
    let services = host_services(&engine, capability_cpath, trusted);
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let mut vm = if native_cpath.is_some() {
        engine.new_vm_with_native_services(services)
    } else {
        engine.new_vm_with_services(services)
    }
    .map_err(sdk_failure)?;
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let mut vm = engine.new_vm_with_services(services).map_err(sdk_failure)?;
    let invocation = (|| -> CliResult<u8> {
        // 原始 builtin 必須先持根，LUA_INIT 即使改寫全域 warn，-W 仍控制同一 VM。
        let warning_value = vm.get_global(b"warn").map_err(sdk_failure)?;
        let original_warning = vm.root(warning_value).map_err(sdk_failure)?;
        let tostring_value = vm.get_global(b"tostring").map_err(sdk_failure)?;
        let original_tostring = vm.root(tostring_value).map_err(sdk_failure)?;
        let program_name = args.first().map(|name| os_bytes(name)).unwrap_or_else(|| b"rivetlua".to_vec());
        let error_handler = cli_error_handler(&mut vm, &program_name, &original_tostring)?;
        call_original_warning(&mut vm, &original_warning, b"@off", stderr, &mut bridge)?;
        set_arg_table(&mut vm, args, options.script_index)?;
        configure_package_paths(&mut vm, &options, native_cpath.as_deref())?;
        let arg_length = if options.script.is_some() {
            Some(capture_script_arg_length(
                &engine,
                &mut vm,
                stderr,
                &mut bridge,
            )?)
        } else {
            None
        };
        if !options.ignore_environment {
            run_init(&engine, &mut vm, options.profile, stderr, &mut bridge, &error_handler)?;
        }
        for action in &options.actions {
            match action {
                Action::Execute(source) => {
                    run_exec_action(&engine, &mut vm, source, stdout, stderr, &mut bridge, &error_handler)?
                }
                Action::Require(name) => run_require_action(&mut vm, name, stderr, &mut bridge)?,
                Action::WarningOn => {
                    call_original_warning(&mut vm, &original_warning, b"@on", stderr, &mut bridge)?
                }
            }
        }
        if let Some(script) = &options.script {
            let length_function = arg_length
                .as_ref()
                .ok_or_else(|| CliFailure::failed("script args 長度函式遺失"))?;
            if os_bytes(script) == b"-" && !options.stdin_as_file_after_double_dash {
                run_stdin_script(
                    &engine,
                    &mut vm,
                    stdin,
                    Some(length_function),
                    stdout,
                    stderr,
                    &mut bridge,
                    &error_handler,
                )?;
            } else {
                run_path(
                    &engine,
                    &mut vm,
                    script,
                    length_function,
                    stdout,
                    stderr,
                    &mut bridge,
                    &error_handler,
                )?;
            }
        } else if !options.interactive && options.actions.is_empty() && !options.show_version {
            if io::stdin().is_terminal() {
                repl(&engine, &mut vm, stdin, stdout, stderr, &mut bridge, &original_tostring, false)?;
                return Ok(0);
            }
            run_stdin_script(&engine, &mut vm, stdin, None, stdout, stderr, &mut bridge, &error_handler)?;
        }
        if options.interactive {
            repl(&engine, &mut vm, stdin, stdout, stderr, &mut bridge, &original_tostring, true)?;
            return Ok(0);
        }
        Ok(0)
    })();
    match invocation {
        Err(CliFailure {
            requested_exit: Some(request),
            ..
        }) => {
            let final_request = vm.finish_exit(request).map_err(sdk_failure)?;
            Ok(final_request.status as u8)
        }
        Ok(status) => match vm.finish_shutdown().map_err(sdk_failure)? {
            Some(request) => Ok(request.status as u8),
            None => Ok(status),
        },
        Err(error) => Err(error),
    }
}
