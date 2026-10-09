#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rivetlua::{
    AbortReason, CompileBudget, ContainerLimits, DebugCapability, DebugPermission, DumpCapability,
    DumpLimits, Engine, HostDeadline, HostEntropy, HostEntropyError, HostLoadError,
    HostLoadErrorKind, HostModuleBytes, HostModuleRepository, HostOs, HostOsOperation, HostOsValue,
    HostOutput, HostOutputError, HostResourceError, HostResourceErrorKind, HostServices,
    HostSourceReader, InputFormat, LoadBudget, LoadCapability, LoadFormat, LoadLimits, LuaProfile,
    Module, ResourceBudget, ResourceCapability, RunOutcome, SdkError, TransportBudget, Value, Vm,
};

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_READER_BYTES: usize = 4 * 1024 * 1024;
const MAX_HOST_LOAD_TEMPORARY_BYTES: usize = 256 * 1024 * 1024;
const MAX_HOST_LOAD_WORK_UNITS: usize = 2 * 1024 * 1024 * 1024;
const CLI_EXECUTION_FUEL: u64 = 8_000_000_000;
const READ_CHUNK_BYTES: usize = 1024;
const DEFAULT_LUA_PATH: &[u8] = b"./?.lua;./?/init.lua";
const DEFAULT_LUA_CPATH: &[u8] = b"";

#[derive(Debug)]
struct CliFailure {
    status: u8,
    message: Vec<u8>,
}

type CliResult<T> = Result<T, CliFailure>;

impl CliFailure {
    fn usage(message: impl ToString) -> Self {
        Self {
            status: 2,
            message: message.to_string().into_bytes(),
        }
    }

    fn failed(message: impl ToString) -> Self {
        Self {
            status: 1,
            message: message.to_string().into_bytes(),
        }
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
    script_args: Vec<OsString>,
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
            let attached = &bytes[2..];
            let value = if attached.is_empty() {
                i += 1;
                let Some(next) = args.get(i) else {
                    return Err(CliFailure::usage(if is_execute {
                        "-e 需要程式文字".to_string()
                    } else {
                        "-l 需要模組名稱".to_string()
                    }));
                };
                let next = os_bytes(next);
                if next.starts_with(b"-") {
                    return Err(CliFailure::usage(if is_execute {
                        "-e 需要程式文字".to_string()
                    } else {
                        "-l 需要模組名稱".to_string()
                    }));
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
            return Err(CliFailure::usage(format!(
                "不支援的選項：{}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        i += 1;
    }

    if script.is_none() {
        script_index = 0;
    }
    let script_args = if let Some(index) = script.as_ref().and_then(|_| Some(script_index)) {
        args.get(index + 1..).unwrap_or_default().to_vec()
    } else {
        Vec::new()
    };
    Ok(Options {
        profile,
        ignore_environment,
        show_version,
        interactive,
        actions,
        script_index,
        script,
        script_args,
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
        .and_deadline(deadline)
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
        if rivetlua::classify_input(&bytes) == InputFormat::Source {
            preprocess_source_budgeted(&mut bytes, budget)?;
        }
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
    if rivetlua::classify_input(&bytes) == InputFormat::Source {
        preprocess_source_budgeted(&mut bytes, budget)?;
    }
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

fn host_services(engine: &Engine) -> HostServices {
    let load = LoadCapability::deny_all()
        .and_compiler(engine.clone())
        .and_reader(FsSourceReader)
        .and_repository(FsRepository)
        .with_bytecode(true)
        .with_official_bytecode(true)
        .with_limits(load_limits());
    let dump = DumpCapability::deny_all()
        .with_official_bytecode(true)
        .with_limits(dump_limits());
    HostServices::with_output(StdoutOutput)
        .and_load(load)
        .and_entropy(OsEntropy)
        .and_resource(cli_resource_capability(CliResourceDeadline::from_now()))
        .and_dump(dump)
        .and_debug(debug_capability())
}

fn version_line(profile: LuaProfile) -> &'static [u8] {
    match profile {
        LuaProfile::Lua54 => b"RivetLua 0.0.0 (Lua 5.4.9)\n",
        LuaProfile::Lua55 => b"RivetLua 0.0.0 (Lua 5.5.1)\n",
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

fn configure_package_paths(vm: &mut Vm, options: &Options) -> CliResult<()> {
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
    let cpath = if options.ignore_environment {
        DEFAULT_LUA_CPATH.to_vec()
    } else {
        expand_default_path(
            configured_env(options.profile, "CPATH")
                .as_deref()
                .unwrap_or(b";;"),
            DEFAULT_LUA_CPATH,
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

fn script_values(vm: &mut Vm, options: &Options) -> CliResult<(Vec<Value>, Vec<rivetlua::Root>)> {
    let mut values = Vec::new();
    let mut roots = Vec::new();
    values
        .try_reserve_exact(options.script_args.len())
        .map_err(|_| CliFailure::failed("script args 配置失敗"))?;
    roots
        .try_reserve_exact(options.script_args.len())
        .map_err(|_| CliFailure::failed("script args root 配置失敗"))?;
    for arg in &options.script_args {
        let root = vm.new_string(&os_bytes(arg)).map_err(sdk_failure)?;
        values.push(root.value(vm).map_err(sdk_failure)?);
        roots.push(root);
    }
    Ok((values, roots))
}

fn preprocess_source(bytes: &mut Vec<u8>) {
    if bytes.starts_with(b"\xef\xbb\xbf") {
        bytes.drain(..3);
    }
    if bytes.starts_with(b"#!") {
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(bytes.len());
        for byte in &mut bytes[..end] {
            *byte = b' ';
        }
    }
}

fn preprocess_source_budgeted(
    bytes: &mut Vec<u8>,
    budget: &mut LoadBudget<'_>,
) -> Result<(), HostLoadError> {
    let work = bytes
        .len()
        .checked_mul(4)
        .and_then(|units| units.checked_add(8))
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    budget.spend_work(work)?;
    preprocess_source(bytes);
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
        .map_err(|error| CliFailure::failed(format!("讀取檔案資訊失敗：{error}")))?;
    let size = usize::try_from(metadata.len()).map_err(|_| CliFailure::failed("檔案長度溢位"))?;
    if size > limit {
        return Err(CliFailure::failed("檔案超出 CLI 限額"));
    }
    let mut file =
        File::open(path).map_err(|error| CliFailure::failed(format!("開啟檔案失敗：{error}")))?;
    read_input(&mut file, limit)
}

fn compile_source(engine: &Engine, source: &[u8], chunk_name: &[u8]) -> CliResult<Module> {
    compile_source_raw(engine, source, chunk_name)
        .map_err(|error| CliFailure::failed(format!("編譯失敗：{error}")))
}

fn compile_source_raw(
    engine: &Engine,
    source: &[u8],
    chunk_name: &[u8],
) -> Result<Module, rivetlua::CompileError> {
    let budget = CompileBudget::default();
    engine.compile_named_with_budget(source, chunk_name, &budget)
}

fn input_module(engine: &Engine, mut bytes: Vec<u8>, chunk_name: &[u8]) -> CliResult<Module> {
    let format = if is_container_marker(&bytes) {
        None
    } else {
        Some(rivetlua::classify_input(&bytes))
    };
    if format.is_none() || format.is_some_and(|value| value != InputFormat::Source) {
        let budget = TransportBudget::new(ContainerLimits::default());
        return engine
            .load_binary_module(&bytes, &budget)
            .map_err(|error| CliFailure::failed(format!("binary 載入失敗：{error}")));
    }
    preprocess_source(&mut bytes);
    compile_source(engine, &bytes, chunk_name)
}

fn set_cli_execution_fuel(execution: &mut rivetlua::Execution<'_>) -> CliResult<()> {
    execution.set_fuel(CLI_EXECUTION_FUEL).map_err(|error| {
        CliFailure::failed(format!(
            "Execution fuel 設定失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })
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

fn run_module(
    vm: &mut Vm,
    module: &Module,
    args: &[Value],
    interactive: bool,
    _output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<Vec<Value>> {
    let outcome = {
        let mut execution = vm
            .load_module_with_args(module, args)
            .map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "VM 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    match outcome {
        RunOutcome::Returned(values) => {
            if interactive && !values.is_empty() {
                print_interactive_values(vm, &values, errors)?;
            }
            Ok(values)
        }
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors)?;
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
    values: &[Value],
    errors: &mut dyn Write,
) -> CliResult<()> {
    let mut value_roots = Vec::new();
    value_roots
        .try_reserve_exact(values.len())
        .map_err(|_| CliFailure::failed("REPL 結果 root 配置失敗"))?;
    for value in values {
        if matches!(value, Value::Object(_)) {
            value_roots.push(vm.root(*value).map_err(sdk_failure)?);
        }
    }

    let print = vm.get_global(b"print").map_err(sdk_failure)?;
    let print = vm.root(print).map_err(sdk_failure)?;
    let outcome = {
        let mut execution = vm.call(&print, values).map_err(sdk_failure)?;
        set_cli_execution_fuel(&mut execution)?;
        execution.run()
    };
    let outcome = outcome.map_err(|error| {
        CliFailure::failed(format!(
            "REPL print 執行失敗 {}：{:?}",
            error.diagnostic_id, error.kind
        ))
    })?;
    match outcome {
        RunOutcome::Returned(_) => Ok(()),
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors)?;
            Err(CliFailure::failed("REPL print 執行失敗"))
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
) -> CliResult<()> {
    write_bytes(writer, b"rivetlua: ")?;
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
    write_bytes(writer, b"\n")
}

fn run_source(
    engine: &Engine,
    vm: &mut Vm,
    source: &[u8],
    name: &[u8],
    args: &[Value],
    interactive: bool,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<()> {
    let module = compile_source(engine, source, name)?;
    run_module(vm, &module, args, interactive, output, errors).map(|_| ())
}

fn run_path(
    engine: &Engine,
    vm: &mut Vm,
    path: &OsStr,
    args: &[Value],
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<()> {
    let pathbuf = PathBuf::from(path);
    let bytes = read_file(&pathbuf, MAX_INPUT_BYTES)?;
    let module = input_module(engine, bytes, &os_bytes(path))?;
    run_module(vm, &module, args, false, output, errors).map(|_| ())
}

fn run_stdin_script(
    engine: &Engine,
    vm: &mut Vm,
    stdin: &mut dyn Read,
    args: &[Value],
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<()> {
    let bytes = read_input(stdin, MAX_INPUT_BYTES)?;
    let module = input_module(engine, bytes, b"=stdin")?;
    run_module(vm, &module, args, false, output, errors).map(|_| ())
}

fn run_exec_action(
    engine: &Engine,
    vm: &mut Vm,
    source: &[u8],
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<()> {
    run_source(
        engine,
        vm,
        source,
        b"=(command line)",
        &[],
        false,
        output,
        errors,
    )
}

fn run_require_action(vm: &mut Vm, argument: &[u8], errors: &mut dyn Write) -> CliResult<()> {
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
    match outcome {
        RunOutcome::Returned(values) => {
            let value = values.first().copied().unwrap_or(Value::Nil);
            vm.set_global(global, value).map_err(sdk_failure)
        }
        RunOutcome::LuaError(error) => {
            write_lua_error(vm, &error, errors)?;
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
) -> CliResult<()> {
    let Some(init) = configured_env(profile, "INIT") else {
        return Ok(());
    };
    if init.first() == Some(&b'@') {
        let path = os_from_bytes(&init[1..]);
        let bytes = read_file(Path::new(&path), MAX_INPUT_BYTES)?;
        let module = input_module(engine, bytes, &init[1..])?;
        run_module(vm, &module, &[], false, &mut io::stdout(), errors).map(|_| ())
    } else {
        run_source(
            engine,
            vm,
            &init,
            b"=LUA_INIT",
            &[],
            false,
            &mut io::stdout(),
            errors,
        )
    }
}

fn repl(
    engine: &Engine,
    vm: &mut Vm,
    input: &mut dyn Read,
    output: &mut dyn Write,
    errors: &mut dyn Write,
) -> CliResult<bool> {
    let interactive_input = io::stdin().is_terminal();
    let mut had_error = false;
    loop {
        if interactive_input {
            write_bytes(output, b"> ")?;
            output
                .flush()
                .map_err(|error| CliFailure::failed(format!("REPL 輸出失敗：{error}")))?;
        }
        let (line, eof) = read_repl_line(input)?;
        if eof && line.is_empty() {
            break;
        }
        if line.is_empty() {
            continue;
        }
        let mut source = line;
        loop {
            let expression = repl_expression_source(engine.profile(), &source)?;
            let compiled = match compile_source_raw(engine, &expression, b"=stdin") {
                Ok(module) => Ok((module, true)),
                Err(_) => {
                    compile_source_raw(engine, &source, b"=stdin").map(|module| (module, false))
                }
            };
            match compiled {
                Ok((module, expression)) => {
                    if run_module(vm, &module, &[], expression, output, errors).is_err() {
                        had_error = true;
                    }
                    break;
                }
                Err(error) if is_incomplete(&error, source.len()) => {
                    if interactive_input {
                        write_bytes(output, b">> ")?;
                        output.flush().map_err(|error| {
                            CliFailure::failed(format!("REPL 輸出失敗：{error}"))
                        })?;
                    }
                    let (continuation, eof) = read_repl_line(input)?;
                    if eof && continuation.is_empty() {
                        had_error = true;
                        write_bytes(errors, "rivetlua: 未完成的 REPL 輸入\n".as_bytes())?;
                        break;
                    }
                    let next_len = source
                        .len()
                        .checked_add(1)
                        .and_then(|len| len.checked_add(continuation.len()))
                        .ok_or_else(|| CliFailure::failed("REPL 輸入長度溢位"))?;
                    if next_len > MAX_INPUT_BYTES {
                        had_error = true;
                        write_bytes(errors, "rivetlua: REPL 輸入超出上限\n".as_bytes())?;
                        break;
                    }
                    source
                        .try_reserve_exact(next_len - source.len())
                        .map_err(|_| CliFailure::failed("REPL 多行輸入配置失敗"))?;
                    if source.capacity() > MAX_INPUT_BYTES {
                        had_error = true;
                        write_bytes(errors, "rivetlua: REPL 實際配置超出上限\n".as_bytes())?;
                        break;
                    }
                    source.push(b'\n');
                    source.extend_from_slice(&continuation);
                    continue;
                }
                Err(error) => {
                    had_error = true;
                    write_bytes(errors, format!("rivetlua: 編譯失敗：{error}\n").as_bytes())?;
                    break;
                }
            }
        }
    }
    Ok(had_error)
}

fn read_repl_line(input: &mut dyn Read) -> CliResult<(Vec<u8>, bool)> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let count = input
            .read(&mut byte)
            .map_err(|error| CliFailure::failed(format!("REPL 讀取失敗：{error}")))?;
        if count == 0 {
            return Ok((line, true));
        }
        if byte[0] == b'\n' {
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
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let result = run_interpreter(&args, &mut stdin, &mut stdout, &mut stderr);
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
        DebugCapability, DebugPermission, Engine, HostEntropyError, HostResourceErrorKind,
        HostServices, LuaProfile, ResourceCapability, ResourceLimits, RunOutcome, RuntimeErrorKind,
        Value,
    };
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, UNIX_EPOCH};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

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
    let (input, chunk_name) = match options.input.as_ref() {
        Some(path) if os_bytes(path) != b"-" => {
            let bytes = read_file(Path::new(path), MAX_INPUT_BYTES)?;
            let name = os_bytes(path);
            (bytes, name)
        }
        Some(_) | None => (read_input(stdin, MAX_INPUT_BYTES)?, b"=stdin".to_vec()),
    };
    let module = input_module(&engine, input, &chunk_name)?;
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
    let options = parse_options(args)?;
    if options.show_version {
        write_bytes(stdout, version_line(options.profile))?;
    }
    let engine = Engine::new(options.profile);
    let mut vm = engine
        .new_vm_with_services(host_services(&engine))
        .map_err(sdk_failure)?;
    let _arg_table = set_arg_table(&mut vm, args, options.script_index)?;
    configure_package_paths(&mut vm, &options)?;
    if !options.ignore_environment {
        run_init(&engine, &mut vm, options.profile, stderr)?;
    }
    for action in &options.actions {
        match action {
            Action::Execute(source) => run_exec_action(&engine, &mut vm, source, stdout, stderr)?,
            Action::Require(name) => run_require_action(&mut vm, name, stderr)?,
        }
    }
    if let Some(script) = &options.script {
        if os_bytes(script) == b"-" && !options.stdin_as_file_after_double_dash {
            let (values, _roots) = script_values(&mut vm, &options)?;
            run_stdin_script(&engine, &mut vm, stdin, &values, stdout, stderr)?;
        } else {
            let (values, _roots) = script_values(&mut vm, &options)?;
            run_path(&engine, &mut vm, script, &values, stdout, stderr)?;
        }
    } else if !options.interactive && options.actions.is_empty() && !options.show_version {
        if io::stdin().is_terminal() {
            return Ok(if repl(&engine, &mut vm, stdin, stdout, stderr)? {
                1
            } else {
                0
            });
        }
        run_stdin_script(&engine, &mut vm, stdin, &[], stdout, stderr)?;
    }
    if options.interactive {
        return Ok(if repl(&engine, &mut vm, stdin, stdout, stderr)? {
            1
        } else {
            0
        });
    }
    Ok(0)
}
