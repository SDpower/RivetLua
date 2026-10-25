use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(unix, windows))]
use cpu_time::ProcessTime;

use rivetlua::{
    CompileBudget, CompileBudgetLimits, Engine, FileOperation, FileReadFormat, FileSeekOrigin,
    HostCloseResult, HostFileLease, HostIo, HostLoadError, HostLoadErrorKind, HostModuleBytes,
    HostModuleRepository, HostOs, HostOsOperation, HostOsValue, HostOutput, HostOutputError,
    HostResourceError, HostResourceErrorKind, HostServices, HostSourceReader, LoadBudget,
    LoadCapability, LoadFormat, LoadLimits, LuaProfile, ResourceBudget, ResourceCapability,
    ResourceLimits, RunOutcome, Value, Vm,
};

#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
use crate::NativeDriver;

const MAX_SCRIPT_BYTES: u64 = 4 * 1024 * 1024;

fn denied() -> HostResourceError {
    HostResourceError::new(HostResourceErrorKind::PolicyDenied, Vec::new())
}

fn load_denied() -> HostLoadError {
    HostLoadError::new(HostLoadErrorKind::PolicyDenied, Vec::new())
}

#[derive(Clone)]
struct Allowed {
    tree_lua: PathBuf,
    script_dir: PathBuf,
}

impl Allowed {
    fn checked(&self, raw: &[u8], module_only: bool) -> Result<Option<PathBuf>, HostLoadError> {
        if raw.is_empty() || raw.len() > 4096 {
            return Err(load_denied());
        }
        let text = std::str::from_utf8(raw).map_err(|_| load_denied())?;
        let input = Path::new(text);
        let mut path = if input.is_absolute() {
            PathBuf::new()
        } else {
            self.script_dir.clone()
        };
        for part in input.components() {
            match part {
                Component::RootDir => path.push(part),
                Component::Normal(_) => {
                    path.push(part);
                    match fs::symlink_metadata(&path) {
                        Ok(meta) if meta.file_type().is_symlink() => return Err(load_denied()),
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                        Err(_) => return Err(load_denied()),
                    }
                }
                Component::CurDir => {}
                _ => return Err(load_denied()),
            }
        }
        let canonical = fs::canonicalize(path).map_err(|_| load_denied())?;
        if !canonical.starts_with(&self.tree_lua)
            && (module_only || !canonical.starts_with(&self.script_dir))
        {
            return Err(load_denied());
        }
        let meta = fs::symlink_metadata(&canonical).map_err(|_| load_denied())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_SCRIPT_BYTES {
            return Err(load_denied());
        }
        Ok(Some(canonical))
    }
}

fn read_limited(path: &Path, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
    let len = usize::try_from(fs::metadata(path).map_err(|_| load_denied())?.len())
        .map_err(|_| load_denied())?;
    if len > MAX_SCRIPT_BYTES as usize {
        return Err(load_denied());
    }
    budget.spend_work(len.saturating_add(1))?;
    budget.claim_temporary(len)?;
    let mut bytes = vec![0; len];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| load_denied())?;
    Ok(bytes)
}

struct RestrictedReader(Allowed);

impl HostSourceReader for RestrictedReader {
    fn read_path(
        &mut self,
        raw: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        let path = self.0.checked(raw, false)?.ok_or_else(load_denied)?;
        read_limited(&path, budget)
    }
    fn read_stdin(&mut self, _budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        Err(load_denied())
    }
}

struct RestrictedRepository(Allowed);

impl HostModuleRepository for RestrictedRepository {
    fn readable(
        &mut self,
        _modname: &[u8],
        raw: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<bool, HostLoadError> {
        budget.spend_work(raw.len().saturating_add(1))?;
        let Some(path) = self.0.checked(raw, true)? else {
            return Ok(false);
        };
        Ok(File::open(path).is_ok())
    }

    fn search(
        &mut self,
        _modname: &[u8],
        raw: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        let Some(path) = self.0.checked(raw, true)? else {
            return Ok(None);
        };
        let data = read_limited(&path, budget)?;
        if !matches!(
            rivetlua::classify_input(&data),
            rivetlua::InputFormat::Source
        ) {
            return Err(load_denied());
        }
        budget.claim_temporary(raw.len())?;
        budget.spend_work(raw.len())?;
        Ok(Some(HostModuleBytes {
            data,
            loader_data: raw.to_vec(),
            format: LoadFormat::Source,
        }))
    }
}

struct StandardOutput {
    written: usize,
}

impl HostOutput for StandardOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        let next = self
            .written
            .checked_add(bytes.len())
            .filter(|total| *total <= 8 * 1024 * 1024)
            .ok_or(HostOutputError::WriteFailed)?;
        io::stdout()
            .lock()
            .write_all(bytes)
            .map_err(|_| HostOutputError::WriteFailed)?;
        self.written = next;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum StandardStream {
    Stdin,
    Stdout,
    Stderr,
}

struct FileLease {
    stream: Option<StandardStream>,
    bytes: Vec<u8>,
    offset: usize,
}

impl FileLease {
    fn standard(
        stream: StandardStream,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        budget.claim_retained(std::mem::size_of::<Self>())?;
        Ok(Box::new(Self {
            stream: Some(stream),
            bytes: Vec::new(),
            offset: 0,
        }))
    }
}

impl HostFileLease for FileLease {
    fn authorize(
        &mut self,
        operation: FileOperation,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        match (self.stream, operation) {
            (_, FileOperation::Close) => Ok(()),
            (
                Some(StandardStream::Stdout | StandardStream::Stderr),
                FileOperation::Write | FileOperation::Flush,
            ) => Ok(()),
            (Some(StandardStream::Stdin) | None, FileOperation::Read | FileOperation::Seek) => {
                Ok(())
            }
            _ => Err(denied()),
        }
    }

    fn read(
        &mut self,
        format: FileReadFormat,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError> {
        if matches!(
            self.stream,
            Some(StandardStream::Stdout | StandardStream::Stderr)
        ) {
            return Err(denied());
        }
        budget.spend_work(1)?;
        if self.offset >= self.bytes.len() {
            return Ok(match format {
                FileReadFormat::All | FileReadFormat::Bytes(0) => Some(Vec::new()),
                _ => None,
            });
        }
        let end = match format {
            FileReadFormat::Bytes(count) => self.offset.saturating_add(count).min(self.bytes.len()),
            FileReadFormat::All => self.bytes.len(),
            FileReadFormat::Line { keep_newline } => {
                let rest = &self.bytes[self.offset..];
                let newline = rest
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map(|index| self.offset + index);
                let end = newline.map(|index| index + 1).unwrap_or(self.bytes.len());
                let copied = if keep_newline {
                    end
                } else {
                    newline.unwrap_or(end)
                };
                budget.spend_work(end - self.offset)?;
                budget.claim_temporary(copied - self.offset)?;
                let data = self.bytes[self.offset..copied].to_vec();
                self.offset = end;
                return Ok(Some(data));
            }
            FileReadFormat::Number => return Err(denied()),
        };
        budget.spend_work(end - self.offset)?;
        budget.claim_temporary(end - self.offset)?;
        let data = self.bytes[self.offset..end].to_vec();
        self.offset = end;
        Ok(Some(data))
    }

    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError> {
        budget.spend_work(bytes.len().saturating_add(1))?;
        let result = match self.stream {
            Some(StandardStream::Stdout) => io::stdout().lock().write_all(bytes),
            Some(StandardStream::Stderr) => io::stderr().lock().write_all(bytes),
            _ => return Err(denied()),
        };
        result.map_err(|_| HostResourceError::new(HostResourceErrorKind::IoFailure, Vec::new()))?;
        Ok(bytes.len())
    }

    fn seek(
        &mut self,
        origin: FileSeekOrigin,
        offset: i64,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError> {
        budget.spend_work(1)?;
        if self.stream.is_some() {
            return Err(denied());
        }
        let base = match origin {
            FileSeekOrigin::Set => 0,
            FileSeekOrigin::Current => self.offset as i64,
            FileSeekOrigin::End => self.bytes.len() as i64,
        };
        let next = base.checked_add(offset).ok_or_else(denied)?;
        if next < 0 {
            return Err(denied());
        }
        self.offset = usize::try_from(next).map_err(|_| denied())?;
        Ok(self.offset as u64)
    }

    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        match self.stream {
            Some(StandardStream::Stdout) => io::stdout().flush(),
            Some(StandardStream::Stderr) => io::stderr().flush(),
            _ => return Err(denied()),
        }
        .map_err(|_| HostResourceError::new(HostResourceErrorKind::IoFailure, Vec::new()))
    }

    fn close(
        self: Box<Self>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError> {
        budget.spend_work(1)?;
        Ok(HostCloseResult::File)
    }
}

struct RestrictedIo(Allowed);

impl HostIo for RestrictedIo {
    fn authorize_path(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(path.len().saturating_add(mode.len()).saturating_add(1))?;
        if mode != b"r" && mode != b"rb" {
            return Err(denied());
        }
        self.0
            .checked(path, false)
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        Ok(())
    }

    fn open(
        &mut self,
        path: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        self.authorize_path(path, mode, budget)?;
        let file = self
            .0
            .checked(path, false)
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        let len = usize::try_from(fs::metadata(&file).map_err(|_| denied())?.len())
            .map_err(|_| denied())?;
        if len > MAX_SCRIPT_BYTES as usize {
            return Err(denied());
        }
        budget.claim_retained(len.saturating_add(std::mem::size_of::<FileLease>()))?;
        budget.spend_work(len)?;
        let mut bytes = vec![0; len];
        File::open(file)
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| denied())?;
        Ok(Box::new(FileLease {
            stream: None,
            bytes,
            offset: 0,
        }))
    }

    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        FileLease::standard(StandardStream::Stdin, budget)
    }
    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        FileLease::standard(StandardStream::Stdout, budget)
    }
    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        FileLease::standard(StandardStream::Stderr, budget)
    }
}

struct RestrictedOs;

impl HostOs for RestrictedOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        match operation {
            HostOsOperation::Exit(_)
            | HostOsOperation::Clock
            | HostOsOperation::Time(None)
            | HostOsOperation::GetEnv(_)
            | HostOsOperation::Locale(_, _) => Ok(()),
            _ => Err(denied()),
        }
    }
    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        self.authorize(operation, budget)?;
        match operation {
            HostOsOperation::Exit(request) => Ok(HostOsValue::ExitRequest(request)),
            HostOsOperation::Clock => {
                #[cfg(any(unix, windows))]
                {
                    let seconds = ProcessTime::try_now()
                        .map_err(|_| denied())?
                        .as_duration()
                        .as_secs_f64();
                    if !seconds.is_finite() || seconds < 0.0 {
                        return Err(denied());
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
                epoch: i64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| denied())?
                        .as_secs(),
                )
                .map_err(|_| denied())?,
                normalized: None,
            }),
            HostOsOperation::GetEnv(_) => Ok(HostOsValue::Nil),
            HostOsOperation::Locale(None, _) | HostOsOperation::Locale(Some(b"C"), _) => {
                budget.claim_temporary(1)?;
                Ok(HostOsValue::Bytes(b"C".to_vec()))
            }
            HostOsOperation::Locale(Some(_), _) => Ok(HostOsValue::Nil),
            _ => Err(denied()),
        }
    }
}

fn set_package_field(vm: &mut Vm, name: &[u8], value: &[u8]) -> Result<(), String> {
    let package = vm
        .get_global(b"package")
        .map_err(|_| "runner package 讀取失敗")?;
    let package = vm.root(package).map_err(|_| "runner package 保根失敗")?;
    let key = vm
        .new_string(name)
        .map_err(|_| "runner package key 建立失敗")?;
    let value = vm
        .new_string(value)
        .map_err(|_| "runner package value 建立失敗")?;
    vm.table_raw_set(
        &package,
        key.value(vm).map_err(|_| "runner key 讀取失敗")?,
        value.value(vm).map_err(|_| "runner value 讀取失敗")?,
    )
    .map_err(|_| "runner package 設定失敗".into())
}

fn set_args(vm: &mut Vm, values: &[String]) -> Result<(), String> {
    let table = vm.new_table().map_err(|_| "runner arg table 建立失敗")?;
    for (index, value) in values.iter().enumerate() {
        let string = vm
            .new_string(value.as_bytes())
            .map_err(|_| "runner arg 建立失敗")?;
        vm.table_raw_set(
            &table,
            Value::Integer(index as i64),
            string.value(vm).map_err(|_| "runner arg 讀取失敗")?,
        )
        .map_err(|_| "runner arg 設定失敗")?;
    }
    vm.set_global(b"arg", table.value(vm).map_err(|_| "runner arg 讀取失敗")?)
        .map_err(|_| "runner arg 設定失敗".into())
}

/// 執行已驗證 tree 的 Lua package；宿主須先核對 tree identity 與 framework 安裝狀態。
pub fn run(
    profile: LuaProfile,
    tree: &Path,
    framework: &str,
    script: &Path,
    args: &[String],
) -> Result<(), String> {
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    {
        run_inner(profile, tree, framework, script, args, None)
    }
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    {
        run_inner(profile, tree, framework, script, args)
    }
}

/// 消耗 driver，讓 VM 關閉後釋放載入快取；宿主須核對 tree identity、安裝狀態及 grant 的 profile／target／ABI，並承擔 C 模組的程序權限與 attestor 契約。
#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
pub fn run_with_native_driver(
    profile: LuaProfile,
    tree: &Path,
    framework: &str,
    script: &Path,
    args: &[String],
    mut driver: NativeDriver<'_>,
) -> Result<(), String> {
    run_inner(profile, tree, framework, script, args, Some(&mut driver))
}

fn lua_version(profile: LuaProfile) -> &'static str {
    match profile {
        LuaProfile::Lua54 => "5.4",
        LuaProfile::Lua55 => "5.5",
    }
}

fn checked_tree(tree: &Path, profile: LuaProfile) -> Result<PathBuf, String> {
    if !tree.is_absolute()
        || tree
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("runner tree 路徑不安全".into());
    }
    let canonical = fs::canonicalize(tree).map_err(|_| "runner tree 不可讀")?;
    let meta = fs::symlink_metadata(tree).map_err(|_| "runner tree 不可讀")?;
    if canonical != tree || !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("runner tree 必須是不含 symlink 的絕對目錄".into());
    }
    let tree_lua = canonical.join("share/lua").join(lua_version(profile));
    let lua_meta = fs::symlink_metadata(&tree_lua).map_err(|_| "runner Lua 目錄缺失")?;
    if !lua_meta.is_dir()
        || lua_meta.file_type().is_symlink()
        || fs::canonicalize(&tree_lua).map_err(|_| "runner Lua 目錄不可讀")? != tree_lua
    {
        return Err("runner Lua 目錄不安全".into());
    }
    Ok(canonical)
}

fn run_inner(
    profile: LuaProfile,
    tree: &Path,
    framework: &str,
    script: &Path,
    args: &[String],
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))] native: Option<
        &mut NativeDriver<'_>,
    >,
) -> Result<(), String> {
    if !["lua", "luaunit", "busted"].contains(&framework) {
        return Err("framework 不支援".into());
    }
    let tree = checked_tree(tree, profile)?;
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    if let Some(driver) = native.as_ref() {
        driver.check_tree(profile, &tree)?;
    }
    let script = if script.is_absolute() {
        script.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "runner 目前目錄不可讀")?
            .join(script)
    };
    let mut checked = PathBuf::new();
    for part in script.components() {
        if matches!(part, Component::ParentDir) {
            return Err("runner script 含上層目錄".into());
        }
        checked.push(part);
        let meta = fs::symlink_metadata(&checked).map_err(|_| "runner script 不可讀")?;
        if meta.file_type().is_symlink() {
            return Err("runner script 含 symlink".into());
        }
    }
    let script = fs::canonicalize(&script).map_err(|_| "runner script 不可讀")?;
    let script_dir = script
        .parent()
        .ok_or("runner script 無父目錄")?
        .to_path_buf();
    let tree_lua = tree.join("share/lua").join(lua_version(profile));
    let allowed = Allowed {
        tree_lua,
        script_dir,
    };
    let script_bytes = {
        let path = allowed
            .checked(script.to_string_lossy().as_bytes(), false)
            .map_err(|_| "runner script 路徑不安全")?
            .ok_or("runner script 缺失")?;
        let file = File::open(path).map_err(|_| "runner script 不可讀")?;
        let mut bytes = Vec::new();
        file.take(MAX_SCRIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "runner script 不可讀")?;
        bytes
    };
    if script_bytes.len() as u64 > MAX_SCRIPT_BYTES {
        return Err("runner script 超過限制".into());
    }
    let engine = Engine::new(profile);
    let load = LoadCapability::deny_all()
        .and_compiler(engine.clone())
        .and_reader(RestrictedReader(allowed.clone()))
        .and_repository(RestrictedRepository(allowed.clone()))
        .with_limits(LoadLimits {
            max_source_bytes: MAX_SCRIPT_BYTES as usize,
            max_encoded_bytes: 32 * 1024 * 1024,
            max_module_allocation_bytes: 32 * 1024 * 1024,
            max_temporary_bytes: 64 * 1024 * 1024,
            max_work_units: 64 * 1024 * 1024,
            max_reader_chunks: 512,
            max_path_candidates: 512,
        });
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let native_cpath = native.as_ref().map(|driver| driver.initial_cpath());
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let load = if let Some(cpath) = &native_cpath {
        load.with_foreign_native_cpath(cpath.clone())
    } else {
        load
    };
    let resource = ResourceCapability::deny_all()
        .and_io(RestrictedIo(allowed))
        .and_os(RestrictedOs)
        .with_limits(ResourceLimits {
            max_work_units: 64 * 1024 * 1024,
            max_temporary_bytes: 8 * 1024 * 1024,
            max_retained_bytes: 8 * 1024 * 1024,
            max_read_bytes: MAX_SCRIPT_BYTES as usize,
            max_write_bytes: 8 * 1024 * 1024,
        });
    let services = HostServices::deny_all()
        .and_output(StandardOutput { written: 0 })
        .and_load(load)
        .and_resource(resource);
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let mut vm = if native.is_some() {
        engine.new_vm_with_native_services(services)
    } else {
        engine.new_vm_with_services(services)
    }
    .map_err(|_| "runner VM 建立失敗")?;
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let mut vm = engine
        .new_vm_with_services(services)
        .map_err(|_| "runner VM 建立失敗")?;
    vm.set_allocation_limit(128 * 1024 * 1024);
    let path = format!(
        "{}/?.lua;{}/?/init.lua",
        tree.join("share/lua").join(lua_version(profile)).display(),
        tree.join("share/lua").join(lua_version(profile)).display()
    );
    set_package_field(&mut vm, b"path", path.as_bytes())?;
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let cpath = native_cpath.as_deref().unwrap_or(b"");
    #[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
    let cpath: &[u8] = b"";
    set_package_field(&mut vm, b"cpath", cpath)?;
    let argv = if framework == "busted" {
        std::iter::once("busted".to_owned())
            .chain(std::iter::once(script.display().to_string()))
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
    } else {
        std::iter::once(script.display().to_string())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
    };
    set_args(&mut vm, &argv)?;
    let bootstrap = b"return require('busted.runner')({ standalone = false })";
    let compile_budget = CompileBudget::new(CompileBudgetLimits {
        max_work: 16_000_000,
        max_allocation_bytes: 32 * 1024 * 1024,
    });
    let module = if framework == "busted" {
        engine
            .compile_named_with_budget(bootstrap, b"=busted.runner", &compile_budget)
            .map_err(|_| "busted bootstrap 編譯失敗")?
    } else {
        engine
            .compile_named_with_budget(
                &script_bytes,
                script.to_string_lossy().as_bytes(),
                &compile_budget,
            )
            .map_err(|_| "runner script 編譯失敗")?
    };
    let chunk_roots = if framework == "busted" {
        Vec::new()
    } else {
        let mut roots = Vec::new();
        for arg in args {
            let string = vm
                .new_string(arg.as_bytes())
                .map_err(|_| "runner script 參數建立失敗")?;
            roots.push(string);
        }
        roots
    };
    let chunk_args = chunk_roots
        .iter()
        .map(|root| root.value(&vm).map_err(|_| "runner script 參數讀取失敗"))
        .collect::<Result<Vec<_>, _>>()?;
    let outcome = {
        let mut execution = vm
            .load_module_with_args(&module, &chunk_args)
            .map_err(|_| "runner script 載入失敗")?;
        execution
            .set_fuel(100_000_000)
            .map_err(|_| "runner fuel 設定失敗")?;
        execution.run().map_err(|_| "runner VM 執行失敗")?
    };
    #[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
    let outcome = if let Some(driver) = native {
        driver.drive(&mut vm, outcome)?
    } else {
        outcome
    };
    let status = match outcome {
        RunOutcome::Returned(values) => {
            if framework == "busted"
                && (matches!(values.first(), Some(Value::Boolean(false)))
                    || matches!(values.first(), Some(Value::Integer(count)) if *count != 0))
            {
                1
            } else {
                0
            }
        }
        RunOutcome::Exited(request) => {
            vm.finish_exit(request)
                .map_err(|_| "runner close/finalizer 失敗")?
                .status
        }
        RunOutcome::LuaError(error) => {
            let detail = vm
                .root(error.value)
                .ok()
                .and_then(|root| vm.read_byte_string(&root).ok());
            if let Some(detail) = detail {
                eprintln!("runner Lua error: {}", String::from_utf8_lossy(&detail));
            } else {
                eprintln!("runner Lua error: {}", error.diagnostic_id);
            }
            1
        }
        RunOutcome::Aborted(_) => return Err("runner VM 執行額度耗盡".into()),
        _ => return Err("runner 不支援的 VM 停放狀態".into()),
    };
    if let Some(request) = vm
        .finish_shutdown()
        .map_err(|_| "runner shutdown/finalizer 失敗")?
    {
        if request.status != 0 {
            return Err(format!("framework exit {}", request.status));
        }
    }
    if status != 0 {
        return Err(format!("framework exit {status}"));
    }
    Ok(())
}


