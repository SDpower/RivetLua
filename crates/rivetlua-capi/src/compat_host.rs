//! 官方 C state 的 Compatibility 預設宿主服務。

use std::ffi::{CStr, CString, OsStr, c_char};
use std::cell::Cell;
use std::marker::PhantomData;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rivetlua_alloc::{Block, BorrowedBytes, StateAllocator};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileJob, CompileLimits, CompileProgress,
    CompileSource, compile_with_budget,
};
use rivetlua_core::{InputFormat, IrLimits, LuaProfile, VerifiedModule, VerifyLimits, classify_input};
use rivetlua_runtime::{
    DebugCapability, DebugPermission, DumpCapability, FileOperation, FileReadFormat,
    FileSeekOrigin, HostCalendar, HostCloseResult, HostDeadline, HostEntropy, HostEntropyError,
    HostExitStatus, HostFileLease, HostIo, HostLoadAdvance, HostLoadCompiler,
    HostLoadError, HostLoadErrorKind, HostLoadJob, HostLoadJobContext, HostLoadJobDriver,
    HostLoadProgress,
    HostModuleBytes, HostModuleRepository, HostOs, HostOsOperation, HostOsValue, HostOutput,
    HostOutputError, HostResourceError, HostResourceErrorKind, HostServices, HostSourceReader,
    HostLoadSource, LoadBudget, LoadCapability, LoadFormat, LoadLimits, PathEncoding, ResourceBudget,
    ResourceCapability, ResourceLimits,
    NativeFileView, VmError,
};

fn load_error(kind: HostLoadErrorKind) -> HostLoadError {
    HostLoadError::new(kind, Vec::new())
}

fn source_file_error(
    action: &[u8], path: &[u8], error: Option<io::Error>, budget: &mut LoadBudget<'_>,
) -> HostLoadError {
    let detail = error.map(|error| error.to_string().into_bytes());
    if let Some(detail) = &detail {
        if let Err(error) = budget.claim_temporary(detail.capacity()) {
            return error;
        }
    }
    let detail_bytes = detail.as_deref().unwrap_or_default();
    let suffix = if detail_bytes.is_empty() { Some(0) } else { detail_bytes.len().checked_add(2) };
    let Some(needed) = b"cannot ".len().checked_add(action.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(path.len()))
        .and_then(|len| suffix.and_then(|suffix| len.checked_add(suffix)))
    else {
        return budget.record_allocator_failure(VmError::AllocationFailed);
    };
    if let Err(error) = budget.claim_temporary(needed) {
        return error;
    }
    let mut diagnostic = Vec::new();
    if diagnostic.try_reserve_exact(needed).is_err() {
        return budget.record_allocator_failure(VmError::AllocationFailed);
    }
    if let Err(error) = budget.claim_temporary(diagnostic.capacity() - needed) {
        return error;
    }
    diagnostic.extend_from_slice(b"cannot ");
    diagnostic.extend_from_slice(action);
    diagnostic.push(b' ');
    diagnostic.extend_from_slice(path);
    if !detail_bytes.is_empty() {
        diagnostic.extend_from_slice(b": ");
        diagnostic.extend_from_slice(detail_bytes);
    }
    HostLoadError::new(HostLoadErrorKind::Failed, diagnostic)
}

fn resource_error(kind: HostResourceErrorKind) -> HostResourceError {
    HostResourceError::new(kind, Vec::new())
}

fn io_diagnostic_len(name: Option<&[u8]>, detail_len: usize) -> Option<usize> {
    let prefix_len = match name {
        Some(name) => name.len().checked_add(2)?,
        None => 0,
    };
    prefix_len.checked_add(detail_len)
}

fn append_io_diagnostic(output: &mut Vec<u8>, name: Option<&[u8]>, detail: &[u8]) {
    if let Some(name) = name {
        output.extend_from_slice(name);
        output.extend_from_slice(b": ");
    }
    output.extend_from_slice(detail);
}

fn io_error_with_name(
    error: io::Error,
    name: Option<&[u8]>,
    written: Option<usize>,
    budget: &mut ResourceBudget<'_>,
) -> HostResourceError {
    let errno = error.raw_os_error().unwrap_or(0);
    let detail = if errno == 0 {
        b"(no extra info)".as_slice()
    } else {
        // SAFETY：strerror 的 NUL 結尾診斷只在本次同步呼叫中借用，隨後複製到計費緩衝。
        let pointer = unsafe { strerror(errno) };
        if pointer.is_null() {
            b"(no extra info)".as_slice()
        } else {
            // SAFETY：已確認 strerror 指標非 null，且其文字在複製前仍有效。
            unsafe { CStr::from_ptr(pointer) }.to_bytes()
        }
    };
    let Some(needed) = io_diagnostic_len(name, detail.len()) else {
        return budget.record_allocator_failure(VmError::AllocationFailed);
    };
    if let Err(error) = budget.claim_temporary(needed) {
        return error;
    }
    let mut message = Vec::new();
    if message.try_reserve_exact(needed).is_err() {
        return budget.record_allocator_failure(VmError::AllocationFailed);
    }
    if let Err(error) = budget.claim_temporary(message.capacity() - needed) {
        return error;
    }
    append_io_diagnostic(&mut message, name, detail);
    match written {
        Some(written) => HostResourceError::write_failure(message, i64::from(errno), written),
        None => HostResourceError::io_failure(message, i64::from(errno)),
    }
}

fn io_error(error: io::Error, budget: &mut ResourceBudget<'_>) -> HostResourceError {
    io_error_with_name(error, None, None, budget)
}

fn io_error_named(
    error: io::Error,
    name: &[u8],
    budget: &mut ResourceBudget<'_>,
) -> HostResourceError {
    io_error_with_name(error, Some(name), None, budget)
}

fn write_error(error: io::Error, written: usize, budget: &mut ResourceBudget<'_>) -> HostResourceError {
    io_error_with_name(error, None, Some(written), budget)
}

fn os_path(bytes: &[u8]) -> Result<&Path, HostResourceError> {
    if bytes.contains(&0) {
        return Err(resource_error(HostResourceErrorKind::PathDenied));
    }
    Ok(Path::new(OsStr::from_bytes(bytes)))
}

fn default_path() -> Vec<u8> {
    let version = if cfg!(feature = "lua55") { "5.5" } else { "5.4" };
    format!(
        "/usr/local/share/lua/{version}/?.lua;/usr/local/share/lua/{version}/?/init.lua;/usr/local/lib/lua/{version}/?.lua;/usr/local/lib/lua/{version}/?/init.lua;./?.lua;./?/init.lua"
    )
    .into_bytes()
}

fn default_cpath() -> Vec<u8> {
    let version = if cfg!(feature = "lua55") { "5.5" } else { "5.4" };
    format!("/usr/local/lib/lua/{version}/?.so;/usr/local/lib/lua/{version}/loadall.so;./?.so")
        .into_bytes()
}

pub(crate) fn services() -> HostServices {
    let load = LoadCapability::deny_all()
        .and_compiler(CompatCompiler)
        .and_reader(CompatReader)
        .and_repository(CompatRepository)
        .with_foreign_native_cpath(default_cpath())
        .with_bytecode(true)
        .with_official_bytecode(true)
        .with_capi_compatibility_limits(LoadLimits {
            max_source_bytes: usize::MAX,
            max_encoded_bytes: usize::MAX,
            max_module_allocation_bytes: usize::MAX,
            max_temporary_bytes: usize::MAX,
            max_work_units: usize::MAX,
            max_reader_chunks: usize::MAX,
            max_path_candidates: usize::MAX,
        });
    let mut debug = DebugCapability::deny_all();
    for permission in [
        DebugPermission::Info, DebugPermission::StackInspection, DebugPermission::LocalInspection,
        DebugPermission::LocalMutation, DebugPermission::Upvalues,
        DebugPermission::UpvalueMutation, DebugPermission::UpvalueIdentity,
        DebugPermission::RegistryRead, DebugPermission::UserValueRead,
        DebugPermission::UserValueWrite, DebugPermission::Traceback,
        DebugPermission::CountHook, DebugPermission::EventHook,
        DebugPermission::MetatableRead, DebugPermission::TableMetatableWrite,
        DebugPermission::TypeMetatableRead, DebugPermission::TypeMetatableWrite,
        DebugPermission::Console,
    ] {
        debug = debug.allow(permission);
    }
    HostServices::with_output(CompatOutput)
        .and_entropy(CompatEntropy)
        .and_load(load)
        .with_package_path(default_path())
        .and_resource(
            ResourceCapability::deny_all()
                .and_io(CompatIo { allocator: StateAllocator::Global })
                .and_os(CompatOs)
                .and_deadline(CompatDeadline)
                .with_path_encoding(PathEncoding::RawBytes)
                .with_limits(ResourceLimits {
                    max_work_units: usize::MAX,
                    max_temporary_bytes: usize::MAX,
                    max_retained_bytes: usize::MAX,
                    max_read_bytes: usize::MAX,
                    max_write_bytes: usize::MAX,
                }),
        )
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true))
        .and_debug(debug)
}

struct CompatOutput;

impl HostOutput for CompatOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        // SAFETY：標準串流由 C 程式庫持有；bytes 僅在同步 fwrite 期間借用。
        let stdout = unsafe { rivetlua_capi_native_standard_file(1) };
        let written = unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stdout) };
        if written == bytes.len() {
            Ok(())
        } else {
            Err(HostOutputError::WriteFailed)
        }
    }

    fn flush(&mut self) -> Result<(), HostOutputError> {
        // SAFETY：標準串流由 C 程式庫持有，與 io.stdout 共用同一個 FILE*。
        let stdout = unsafe { rivetlua_capi_native_standard_file(1) };
        if unsafe { libc::fflush(stdout) } == 0 {
            Ok(())
        } else {
            Err(HostOutputError::WriteFailed)
        }
    }
}

struct CompatEntropy;

impl HostEntropy for CompatEntropy {
    fn seed(&mut self) -> Result<u64, HostEntropyError> {
        let mut bytes = [0; 8];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| HostEntropyError::ReadFailed)?;
        Ok(u64::from_ne_bytes(bytes))
    }
}

struct CompatCompiler;

struct CompilerSink<'a, 'b, 'c> {
    budget: &'a mut LoadBudget<'b>,
    allocator: StateAllocator,
    recover: &'c mut dyn FnMut(u64) -> Result<bool, VmError>,
}

impl CompileBudgetSink for CompilerSink<'_, '_, '_> {
    type Error = HostLoadError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.budget.spend_work(units)
    }
    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_temporary(bytes)
    }
    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_module_allocation(bytes)
    }
    fn state_allocator(&self) -> StateAllocator {
        self.allocator.clone()
    }
    fn recover_allocator_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        (self.recover)(before)
            .map_err(|error| self.budget.record_allocator_failure(error))
    }
}

impl CompatCompiler {
    fn limits() -> (CompileLimits, IrLimits, VerifyLimits) {
        let mut compile_limits = CompileLimits::default();
        compile_limits.max_source_bytes = usize::MAX;
        compile_limits.max_token_bytes = usize::MAX;
        compile_limits.max_tokens = usize::MAX;
        compile_limits.max_lines = usize::MAX;
        compile_limits.max_ast_nodes = usize::MAX;
        compile_limits.max_parse_depth = 200;
        compile_limits.max_statements = usize::MAX;
        compile_limits.max_list_entries = usize::MAX;
        compile_limits.max_bindings_per_function = usize::MAX;
        compile_limits.max_scope_depth = 200;
        compile_limits.max_labels = usize::MAX;
        compile_limits.max_gotos = usize::MAX;
        let mut ir_limits = IrLimits::default();
        ir_limits.max_prototypes = usize::MAX;
        ir_limits.max_instructions = usize::MAX;
        let mut verify_limits = VerifyLimits::default();
        verify_limits.max_module_bytes = usize::MAX;
        verify_limits.max_artifact_bytes = usize::MAX;
        verify_limits.max_prototypes = usize::MAX;
        verify_limits.max_instructions = usize::MAX;
        verify_limits.max_constants = usize::MAX;
        (compile_limits, ir_limits, verify_limits)
    }

    fn compile_inner(
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
        allocator: StateAllocator,
        recover: &mut dyn FnMut(u64) -> Result<bool, VmError>,
    ) -> Result<VerifiedModule, HostLoadError> {
        let (compile_limits, ir_limits, verify_limits) = Self::limits();
        compile_with_budget(
            source,
            chunkname,
            profile,
            &compile_limits,
            &ir_limits,
            &verify_limits,
            &mut CompilerSink { budget, allocator, recover },
        )
        .map_err(|error| Self::compile_error(error, budget, chunkname))
    }

    fn compile_error(
        error: BudgetedCompileError<HostLoadError>, budget: &mut LoadBudget<'_>, chunkname: &[u8],
    ) -> HostLoadError {
        match error {
            BudgetedCompileError::Budget(error) => error,
            BudgetedCompileError::Frontend(error) => match budget.compile_diagnostic(
                chunkname, error.start.line, error.message.as_bytes(),
            ) { Ok(error) | Err(error) => error },
            BudgetedCompileError::Ir(_) | BudgetedCompileError::Bytecode(_) => {
                load_error(HostLoadErrorKind::Compile)
            }
            BudgetedCompileError::AllocationFailed =>
                budget.record_allocator_failure(VmError::AllocationFailed),
            BudgetedCompileError::AdmissionOverflow
            | BudgetedCompileError::AdmissionUnderestimated => load_error(HostLoadErrorKind::Budget),
        }
    }
}

struct CompatReaderSource<'a> {
    source: &'a mut HostLoadSource,
    allocator: StateAllocator,
    max_source_bytes: usize,
    source_limit_failed: &'a mut bool,
}

impl CompileSource for CompatReaderSource<'_> {
    type Source = HostLoadSource;

    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, sink: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        let next = self.source.as_ref().len().checked_add(1);
        if next.map_or(true, |next| next > self.max_source_bytes) {
            *self.source_limit_failed = true;
            return Err(BudgetedCompileError::AdmissionOverflow);
        }
        let work = self.source.copy_work(1).map_err(|_| {
            *self.source_limit_failed = true;
            BudgetedCompileError::AdmissionOverflow
        })?;
        sink.spend_work(work).map_err(BudgetedCompileError::Budget)?;
        if self.source.planned_growth(1)
            .map_err(|_| {
                *self.source_limit_failed = true;
                BudgetedCompileError::AdmissionOverflow
            })?.is_some() {
            let before = self.allocator.refusal_count();
            if self.source.reserve_for_append(1).is_err() {
                if !self.allocator.is_lua() || self.allocator.refusal_count() == before
                    || !sink.recover_allocator_refusal(before).map_err(BudgetedCompileError::Budget)?
                    || self.source.reserve_for_append(1).is_err() {
                    return Err(BudgetedCompileError::AllocationFailed);
                }
            }
        }
        self.source.append(&[byte], self.max_source_bytes).map_err(|error| {
            if matches!(error.kind, rivetlua_runtime::RuntimeErrorKind::HostLoadBudget
                | rivetlua_runtime::RuntimeErrorKind::Heap(VmError::ArithmeticOverflow)) {
                *self.source_limit_failed = true;
                BudgetedCompileError::AdmissionOverflow
            } else {
                BudgetedCompileError::AllocationFailed
            }
        })
    }

    fn take_source(&mut self) -> Self::Source { self.source.take_compile_source() }
}

struct CompatReaderJob { compiler: CompileJob }

impl HostLoadJobDriver for CompatReaderJob {
    fn advance(
        &mut self, available: &[u8], eof: bool, chunkname: &[u8],
        context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<HostLoadAdvance, HostLoadError> {
        if !context.source.uses_allocator(&context.allocator) {
            return Err(context.budget.record_allocator_failure(VmError::AllocationFailed));
        }
        let mut source_limit_failed = false;
        let result = {
            let mut source = CompatReaderSource {
                source: &mut *context.source, allocator: context.allocator.clone(),
                max_source_bytes: context.max_source_bytes,
                source_limit_failed: &mut source_limit_failed,
            };
            let mut sink = CompilerSink {
                budget: &mut *context.budget, allocator: context.allocator.clone(),
                recover: &mut *context.recover,
            };
            self.compiler.advance(available, eof, &mut source, chunkname, &mut sink)
        };
        if source_limit_failed {
            return Err(context.budget.record_source_limit_failure());
        }
        match result {
            Ok(result) => Ok(HostLoadAdvance {
                consumed: result.consumed,
                progress: match result.progress {
                    CompileProgress::NeedInput { minimum_total } => HostLoadProgress::NeedInput { minimum_total },
                    CompileProgress::Complete(module) => HostLoadProgress::Complete(module),
                },
            }),
            Err(BudgetedCompileError::AllocationFailed) => Err(context.budget.record_allocator_failure(
                context.source.last_failure().unwrap_or(VmError::AllocationFailed))),
            Err(error) => Err(CompatCompiler::compile_error(error, context.budget, chunkname)),
        }
    }

    fn consumed_total(&self) -> usize { self.compiler.consumed_total() }
}

impl HostLoadCompiler for CompatCompiler {
    fn begin_reader(
        &mut self, context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<Option<HostLoadJob>, HostLoadError> {
        let (compile_limits, ir_limits, verify_limits) = Self::limits();
        let compiler = CompileJob::new(context.profile, compile_limits, ir_limits, verify_limits);
        HostLoadJob::new(CompatReaderJob { compiler }, context).map(Some)
    }

    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError> {
        let mut no_recovery = |_| Ok(false);
        Self::compile_inner(
            source, chunkname, profile, budget, StateAllocator::Global, &mut no_recovery,
        )
    }

    fn compile_with_recovery(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
        allocator: StateAllocator,
        recover: &mut dyn FnMut(u64) -> Result<bool, VmError>,
    ) -> Result<VerifiedModule, HostLoadError> {
        Self::compile_inner(source, chunkname, profile, budget, allocator, recover)
    }
}

fn read_budgeted(
    reader: &mut impl Read,
    budget: &mut LoadBudget<'_>,
    path: &[u8],
) -> Result<Vec<u8>, HostLoadError> {
    let mut result = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        budget.spend_work(chunk.len() + 1)?;
        let size = reader.read(&mut chunk)
            .map_err(|error| source_file_error(b"read", path, Some(error), budget))?;
        if size == 0 {
            break;
        }
        let needed = result.len().checked_add(size).ok_or_else(|| load_error(HostLoadErrorKind::Budget))?;
        if needed > result.capacity() {
            let admitted = needed.checked_next_power_of_two().ok_or_else(|| load_error(HostLoadErrorKind::Budget))?;
            budget.claim_temporary(admitted)?;
            result.try_reserve_exact(admitted - result.len())
                .map_err(|_| budget.record_allocator_failure(VmError::AllocationFailed))?;
            budget.claim_temporary(result.capacity() - admitted)?;
        }
        result.extend_from_slice(&chunk[..size]);
    }
    Ok(result)
}

fn preprocess(bytes: &mut Vec<u8>) {
    let bom = if bytes.starts_with(b"\xef\xbb\xbf") { 3 } else { 0 };
    let skip = if bytes.get(bom) == Some(&b'#') {
        bytes[bom..].iter().position(|byte| *byte == b'\n').map_or(bytes.len(), |end| bom + end + 1)
    } else {
        bom
    };
    if skip < bytes.len() && classify_input(&bytes[skip..]) != InputFormat::Source {
        bytes.drain(..skip);
    } else {
        if bom != 0 {
            bytes.drain(..bom);
        }
        if bytes.starts_with(b"#") {
            let end = bytes.iter().position(|byte| *byte == b'\n').unwrap_or(bytes.len());
            bytes[..end].fill(b' ');
        }
    }
}

struct CompatReader;

struct CStdin(*mut libc::FILE);

impl Read for CStdin {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // SAFETY：指標由既有 C 標準串流 bridge 取得；bytes 在同步 fread 期間有效。
        let size = unsafe { libc::fread(bytes.as_mut_ptr().cast(), 1, bytes.len(), self.0) };
        // SAFETY：同一個有效 FILE*，僅查詢 fread 留下的錯誤旗標。
        if size == 0 && unsafe { libc::ferror(self.0) } != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size)
        }
    }
}

impl HostSourceReader for CompatReader {
    fn read_path(&mut self, path: &[u8], budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        budget.spend_work(path.len().saturating_add(1))?;
        let file_path = os_path(path).map_err(|_| source_file_error(b"open", path, None, budget))?;
        let mut file = File::open(file_path)
            .map_err(|error| source_file_error(b"open", path, Some(error), budget))?;
        let mut bytes = read_budgeted(&mut file, budget, path)?;
        preprocess(&mut bytes);
        Ok(bytes)
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        // SAFETY：標準輸入 FILE* 由 C 程式庫持有，與 io.stdin 共用緩衝。
        let mut input = CStdin(unsafe { rivetlua_capi_native_standard_file(0) });
        let mut bytes = read_budgeted(&mut input, budget, b"stdin")?;
        preprocess(&mut bytes);
        Ok(bytes)
    }
}

struct CompatRepository;

impl HostModuleRepository for CompatRepository {
    fn readable(
        &mut self,
        _modname: &[u8],
        candidate_path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<bool, HostLoadError> {
        budget.spend_work(candidate_path.len().saturating_add(1))?;
        let path = os_path(candidate_path).map_err(|_| load_error(HostLoadErrorKind::Failed))?;
        Ok(File::open(path).is_ok())
    }

    fn search(
        &mut self,
        _modname: &[u8],
        candidate_path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        budget.spend_work(candidate_path.len().saturating_add(1))?;
        let path = os_path(candidate_path).map_err(|_| load_error(HostLoadErrorKind::Failed))?;
        let Ok(mut file) = File::open(path) else {
            return Ok(None);
        };
        let mut data = read_budgeted(&mut file, budget, candidate_path)?;
        preprocess(&mut data);
        budget.claim_temporary(candidate_path.len())?;
        let loader_data = candidate_path.to_vec();
        budget.claim_temporary(loader_data.capacity() - candidate_path.len())?;
        let format = match classify_input(&data) {
            InputFormat::Source => LoadFormat::Source,
            InputFormat::RawRvlu => LoadFormat::RivetBytecode,
            InputFormat::Official => LoadFormat::OfficialBytecode,
            InputFormat::UnsupportedBinary => return Err(load_error(HostLoadErrorKind::Failed)),
        };
        Ok(Some(HostModuleBytes { data, loader_data, format }))
    }
}

struct CompatDeadline;

impl HostDeadline for CompatDeadline {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }
}

fn c_path(bytes: &[u8]) -> Result<CString, HostResourceError> {
    CString::new(bytes).map_err(|_| resource_error(HostResourceErrorKind::PathDenied))
}

fn stream_error(budget: &mut ResourceBudget<'_>) -> HostResourceError {
    io_error(io::Error::last_os_error(), budget)
}

fn named_stream_error(name: &[u8], budget: &mut ResourceBudget<'_>) -> HostResourceError {
    io_error_named(io::Error::last_os_error(), name, budget)
}

struct CompatIo {
    allocator: StateAllocator,
}

type FileCloseFunction = unsafe extern "C" fn(*mut crate::stack::lua_State) -> i32;

#[repr(C)]
struct CompatStream {
    file: Cell<*mut libc::FILE>,
    closef: Cell<Option<FileCloseFunction>>,
}

pub(crate) const fn native_stream_prefix_len() -> usize {
    std::mem::size_of::<CompatStream>()
}

enum CompatStreamStorage {
    Owned(Block<CompatStream>),
    Borrowed(std::ptr::NonNull<CompatStream>),
}

unsafe extern "C" {
    fn strerror(errno: i32) -> *mut c_char;
    fn rivetlua_capi_native_file_fclose(state: *mut crate::stack::lua_State) -> i32;
    fn rivetlua_capi_native_file_pclose(state: *mut crate::stack::lua_State) -> i32;
    fn rivetlua_capi_native_file_noclose(state: *mut crate::stack::lua_State) -> i32;
    fn rivetlua_capi_native_standard_file(which: i32) -> *mut libc::FILE;
}

struct CompatFile<'a> {
    stream: CompatStreamStorage,
    process: bool,
    standard: bool,
    _borrow: PhantomData<&'a CompatStream>,
}

impl CompatFile<'static> {
    fn new(
        open: impl FnOnce() -> *mut libc::FILE,
        process: bool,
        standard: bool,
        name: Option<&[u8]>,
        allocator: StateAllocator,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        if let Err(error) = budget.claim_retained(
            std::mem::size_of::<Self>() + std::mem::size_of::<CompatStream>(),
        ) {
            return Err(error);
        }
        let closef = if standard {
            rivetlua_capi_native_file_noclose
        } else if process {
            rivetlua_capi_native_file_pclose
        } else {
            rivetlua_capi_native_file_fclose
        };
        let block = allocator.uninit::<CompatStream>(7)
            .map_err(|_| budget.record_allocator_failure(VmError::AllocationFailed))?;
        let stream = block.write(CompatStream {
            file: Cell::new(std::ptr::null_mut()),
            closef: Cell::new(None),
        });
        let lease = Box::new(Self {
            stream: CompatStreamStorage::Owned(stream),
            process,
            standard,
            _borrow: PhantomData,
        });
        // 前綴已成功配置，才允許 fopen/popen/tmpfile 的外部副作用。
        let handle = open();
        if handle.is_null() {
            return Err(match name {
                Some(name) => named_stream_error(name, budget),
                None => stream_error(budget),
            });
        }
        lease.prefix().file.set(handle);
        lease.prefix().closef.set(Some(closef));
        Ok(lease)
    }
}

impl CompatFile<'_> {
    fn prefix(&self) -> &CompatStream {
        match &self.stream {
            CompatStreamStorage::Owned(stream) => stream,
            // SAFETY：此短命借用僅在 VM 已驗證的 full userdata 活躍操作期間存在。
            CompatStreamStorage::Borrowed(pointer) => unsafe { pointer.as_ref() },
        }
    }

    fn handle(&self) -> *mut libc::FILE {
        self.prefix().file.get()
    }

    fn next(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Option<u8>, HostResourceError> {
        budget.spend_work(1)?;
        // SAFETY：lease 持有有效 FILE*；本 VM 同步序列化使用它。
        let value = unsafe { libc::fgetc(self.handle()) };
        if value != libc::EOF {
            return Ok(Some(value as u8));
        }
        // SAFETY：同一有效 FILE* 的錯誤旗標查詢。
        if unsafe { libc::ferror(self.handle()) } != 0 {
            Err(stream_error(budget))
        } else {
            Ok(None)
        }
    }

    fn put_back(&mut self, byte: u8, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        // SAFETY：byte 由此 FILE* 的前次讀取所得；ungetc 保證一個 byte 容量。
        if unsafe { libc::ungetc(i32::from(byte), self.handle()) } == libc::EOF {
            Err(stream_error(budget))
        } else {
            Ok(())
        }
    }

    fn push(
        bytes: &mut Vec<u8>,
        byte: u8,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        if bytes.len() == bytes.capacity() {
            let admitted = bytes.len().max(128).checked_mul(2)
                .ok_or_else(|| resource_error(HostResourceErrorKind::Budget))?;
            budget.claim_temporary(admitted)?;
            bytes.try_reserve_exact(admitted - bytes.len())
                .map_err(|_| resource_error(HostResourceErrorKind::Budget))?;
            budget.claim_temporary(bytes.capacity() - admitted)?;
        }
        bytes.push(byte);
        Ok(())
    }

    fn read_number(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Option<Vec<u8>>, HostResourceError> {
        let mut result = Vec::new();
        // SAFETY：localeconv 回傳程序持有的 locale 資料；本次同步讀取只取 decimal_point 首 byte。
        let decimal = unsafe {
            let locale = libc::localeconv();
            if locale.is_null() || (*locale).decimal_point.is_null() {
                b'.'
            } else {
                *(*locale).decimal_point.cast::<u8>()
            }
        };
        let first = loop {
            match self.next(budget)? {
                Some(byte) if byte.is_ascii_whitespace() => continue,
                other => break other,
            }
        };
        let Some(mut first) = first else { return Ok(None) };
        if matches!(first, b'+' | b'-') {
            Self::push(&mut result, first, budget)?;
            let Some(next) = self.next(budget)? else { return Ok(None) };
            first = next;
        }
        let mut hex = false;
        if first == b'0' {
            Self::push(&mut result, first, budget)?;
            if let Some(next) = self.next(budget)? {
                if matches!(next, b'x' | b'X') {
                    hex = true;
                    Self::push(&mut result, next, budget)?;
                } else {
                    self.put_back(next, budget)?;
                }
            }
        } else {
            self.put_back(first, budget)?;
        }
        let mut digits = usize::from(first == b'0' && !hex);
        let mut dot = false;
        let mut invalid = false;
        let mut exponent = false;
        while result.len() < 200 {
            let Some(byte) = self.next(budget)? else { break };
            if (hex && byte.is_ascii_hexdigit()) || (!hex && byte.is_ascii_digit()) {
                digits += 1;
                Self::push(&mut result, byte, budget)?;
            } else if (byte == b'.' || byte == decimal) && !dot {
                dot = true;
                Self::push(&mut result, b'.', budget)?;
            } else if digits > 0 && ((hex && matches!(byte, b'p' | b'P'))
                || (!hex && matches!(byte, b'e' | b'E'))) {
                exponent = true;
                Self::push(&mut result, byte, budget)?;
                let next = self.next(budget)?;
                let next = if let Some(sign @ (b'+' | b'-')) = next {
                    if result.len() == 200 {
                        self.put_back(sign, budget)?;
                        return Ok(None);
                    }
                    Self::push(&mut result, sign, budget)?;
                    self.next(budget)?
                } else { next };
                if let Some(digit) = next.filter(|byte| byte.is_ascii_digit()) {
                    if result.len() == 200 {
                        self.put_back(digit, budget)?;
                        return Ok(None);
                    }
                    Self::push(&mut result, digit, budget)?;
                    while let Some(byte) = self.next(budget)? {
                        if byte.is_ascii_digit() {
                            if result.len() == 200 {
                                self.put_back(byte, budget)?;
                                return Ok(None);
                            }
                            Self::push(&mut result, byte, budget)?;
                        } else {
                            self.put_back(byte, budget)?;
                            break;
                        }
                    }
                } else {
                    if let Some(byte) = next { self.put_back(byte, budget)?; }
                    invalid = true;
                }
                break;
            } else {
                self.put_back(byte, budget)?;
                break;
            }
        }
        if digits == 0 || invalid || result.len() > 200 { return Ok(None); }
        if result.len() == 200 {
            if let Some(byte) = self.next(budget)? {
                self.put_back(byte, budget)?;
                if exponent {
                    if byte.is_ascii_digit() {
                        return Ok(None);
                    }
                } else if (hex && byte.is_ascii_hexdigit()) || (!hex && byte.is_ascii_digit())
                    || ((byte == b'.' || byte == decimal) && !dot)
                    || (digits > 0 && ((hex && matches!(byte, b'p' | b'P'))
                        || (!hex && matches!(byte, b'e' | b'E'))))
                {
                    return Ok(None);
                }
            }
        }
        Ok(Some(result))
    }
}

impl Drop for CompatFile<'_> {
    fn drop(&mut self) {
        if self.standard || !matches!(&self.stream, CompatStreamStorage::Owned(_)) {
            return;
        }
        let closef = self.prefix().closef.get();
        let fallback = closef.is_some_and(|callback| if self.process {
            std::ptr::fn_addr_eq(callback, rivetlua_capi_native_file_pclose as FileCloseFunction)
        } else {
            std::ptr::fn_addr_eq(callback, rivetlua_capi_native_file_fclose as FileCloseFunction)
        });
        if fallback {
            let handle = self.prefix().file.replace(std::ptr::null_mut());
            self.prefix().closef.set(None);
            if !handle.is_null() {
                // SAFETY：僅已知預設 closef 的 managed stream 可由 Rust Drop 作備援關閉。
                unsafe {
                    if self.process { libc::pclose(handle) } else { libc::fclose(handle) };
                }
            }
        }
    }
}

impl HostIo for CompatIo {
    fn bind_state_allocator(&mut self, allocator: StateAllocator) {
        self.allocator = allocator;
    }

    fn with_native_file(
        &mut self,
        view: NativeFileView<'_>,
        callback: &mut dyn FnMut(&mut dyn HostFileLease),
    ) -> Result<(), HostResourceError> {
        if view.len() < std::mem::size_of::<CompatStream>()
            || (view.pointer() as usize) % std::mem::align_of::<CompatStream>() != 0
        {
            return Err(resource_error(HostResourceErrorKind::PolicyDenied));
        }
        let pointer = std::ptr::NonNull::new(view.pointer().cast::<CompatStream>())
            .ok_or_else(|| resource_error(HostResourceErrorKind::PolicyDenied))?;
        // SAFETY：VM 已驗完整 userdata 與當前 registry metatable；長度、對齊由上方驗證。
        let stream = unsafe { pointer.as_ref() };
        if stream.closef.get().is_none() {
            return Err(resource_error(HostResourceErrorKind::IoFailure));
        }
        let mut lease = CompatFile {
            stream: CompatStreamStorage::Borrowed(pointer),
            process: false,
            standard: false,
            _borrow: PhantomData,
        };
        callback(&mut lease);
        Ok(())
    }
    fn authorize_path(
        &mut self, path: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(path.len().saturating_add(mode.len()).saturating_add(1))?;
        c_path(path).map(|_| ())
    }

    fn open(
        &mut self, path: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        let path = c_path(path)?;
        let mode = c_path(mode)?;
        CompatFile::new(
            || unsafe { libc::fopen(path.as_ptr(), mode.as_ptr()) },
            false,
            false,
            Some(path.as_bytes()),
            self.allocator.clone(),
            budget,
        )
    }

    fn stdin(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        standard_stream(0, self.allocator.clone(), budget)
    }
    fn stdout(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        standard_stream(1, self.allocator.clone(), budget)
    }
    fn stderr(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        standard_stream(2, self.allocator.clone(), budget)
    }
    fn tmpfile(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        CompatFile::new(
            || unsafe { libc::tmpfile() },
            false,
            false,
            None,
            self.allocator.clone(),
            budget,
        )
    }
    fn authorize_process(&mut self, command: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(command.len().saturating_add(1))?;
        c_path(command)?;
        if !matches!(mode, b"r" | b"w") { return Err(resource_error(HostResourceErrorKind::PolicyDenied)); }
        Ok(())
    }
    fn popen(&mut self, command: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        let command = c_path(command)?;
        let mode = c_path(mode)?;
        CompatFile::new(
            || unsafe { libc::popen(command.as_ptr(), mode.as_ptr()) },
            true,
            false,
            Some(command.as_bytes()),
            self.allocator.clone(),
            budget,
        )
    }
}

fn standard_stream(
    which: i32, allocator: StateAllocator,
    budget: &mut ResourceBudget<'_>,
) -> Result<Box<dyn HostFileLease>, HostResourceError> {
    budget.spend_work(1)?;
    CompatFile::new(
        || unsafe { rivetlua_capi_native_standard_file(which) },
        false,
        true,
        None,
        allocator,
        budget,
    )
}

impl HostFileLease for CompatFile<'_> {
    fn native_userdata(&self) -> Option<BorrowedBytes<'_>> {
        match &self.stream {
            CompatStreamStorage::Owned(stream) => {
                // SAFETY：state-backed Block 由此 owned lease 保活且不搬移；repr(C)
                // 前綴由本實作初始化，FILE* 與 closef 僅依 C stream 契約同步修改。
                Some(unsafe { BorrowedBytes::from_raw_parts(
                    (&**stream as *const CompatStream).cast_mut().cast::<u8>(),
                    std::mem::size_of::<CompatStream>(),
                ) })
            }
            CompatStreamStorage::Borrowed(_) => None,
        }
    }
    fn native_handle_open(&self) -> bool {
        !self.handle().is_null()
    }
    fn native_handle_token(&self) -> Option<usize> {
        Some(self.handle() as usize)
    }

    fn authorize(&mut self, _operation: FileOperation, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if !self.native_handle_open() {
            return Err(resource_error(HostResourceErrorKind::IoFailure));
        }
        Ok(())
    }
    fn read(&mut self, format: FileReadFormat, budget: &mut ResourceBudget<'_>) -> Result<Option<Vec<u8>>, HostResourceError> {
        // SAFETY：lease 保持 FILE* 有效；每次 Lua read 開始時清除先前 EOF／錯誤旗標。
        unsafe { libc::clearerr(self.handle()) };
        if matches!(format, FileReadFormat::Number) { return self.read_number(budget); }
        let mut bytes = Vec::new();
        let mut saw = false;
        match format {
            FileReadFormat::Bytes(0) => {
                if let Some(byte) = self.next(budget)? {
                    self.put_back(byte, budget)?;
                    saw = true;
                }
            }
            FileReadFormat::Bytes(count) => {
                for _ in 0..count {
                    let Some(byte) = self.next(budget)? else { break };
                    Self::push(&mut bytes, byte, budget)?;
                    saw = true;
                }
            }
            FileReadFormat::Line { keep_newline } => {
                while let Some(byte) = self.next(budget)? {
                    saw = true;
                    if byte == b'\n' {
                        if keep_newline { Self::push(&mut bytes, byte, budget)?; }
                        break;
                    }
                    Self::push(&mut bytes, byte, budget)?;
                }
            }
            FileReadFormat::All => {
                while let Some(byte) = self.next(budget)? {
                    Self::push(&mut bytes, byte, budget)?;
                }
                saw = true;
            }
            FileReadFormat::Number => unreachable!(),
        }
        if saw { Ok(Some(bytes)) } else { Ok(None) }
    }
    fn write(&mut self, bytes: &[u8], budget: &mut ResourceBudget<'_>) -> Result<usize, HostResourceError> {
        budget.spend_work(bytes.len().saturating_add(1))?;
        // SAFETY：bytes slice 在同步 fwrite 期間有效；目前 FILE* 由保活的 stream 前綴持有。
        let written = unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), self.handle()) };
        if written == bytes.len() { return Ok(written); }
        let error = io::Error::last_os_error();
        Err(write_error(error, written, budget))
    }
    fn seek(&mut self, origin: FileSeekOrigin, offset: i64, budget: &mut ResourceBudget<'_>) -> Result<u64, HostResourceError> {
        budget.spend_work(1)?;
        let whence = match origin {
            FileSeekOrigin::Set => libc::SEEK_SET,
            FileSeekOrigin::Current => libc::SEEK_CUR,
            FileSeekOrigin::End => libc::SEEK_END,
        };
        // SAFETY：有效 FILE*；fseeko/ftello 僅在此 lease 同步使用。
        if unsafe { libc::fseeko(self.handle(), offset, whence) } != 0 { return Err(stream_error(budget)); }
        // SAFETY：同一有效 FILE* 查詢目前位置。
        let position = unsafe { libc::ftello(self.handle()) };
        if position < 0 { Err(stream_error(budget)) } else { Ok(position as u64) }
    }
    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        // SAFETY：有效 FILE*；fflush 返回後沒有保留 Rust pointer。
        if unsafe { libc::fflush(self.handle()) } == 0 { Ok(()) } else { Err(stream_error(budget)) }
    }
    fn close(self: Box<Self>, budget: &mut ResourceBudget<'_>) -> Result<HostCloseResult, HostResourceError> {
        if self.standard || matches!(&self.stream, CompatStreamStorage::Borrowed(_)) {
            return Err(resource_error(HostResourceErrorKind::Unsupported));
        }
        budget.spend_work(1)?;
        let handle = self.prefix().file.replace(std::ptr::null_mut());
        self.prefix().closef.set(None);
        // SAFETY：唯一 FILE* 已從 lease 移出，此處只關閉一次。
        let status = unsafe { if self.process { libc::pclose(handle) } else { libc::fclose(handle) } };
        if status < 0 { return Err(stream_error(budget)); }
        if self.process {
            Ok(HostCloseResult::Process { success: status == 0, signaled: status & 0x7f != 0,
                code: i64::from(if status & 0x7f != 0 { status & 0x7f } else { (status >> 8) & 0xff }) })
        } else {
            Ok(HostCloseResult::File)
        }
    }
    fn setvbuf(&mut self, mode: &[u8], size: usize, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        let mode = match mode {
            b"no" => libc::_IONBF,
            b"full" => libc::_IOFBF,
            b"line" => libc::_IOLBF,
            _ => return Err(resource_error(HostResourceErrorKind::PolicyDenied)),
        };
        budget.claim_retained(size.max(1))?;
        // SAFETY：buffer=NULL 讓 libc 自行管理；handle 在此 lease 有效。
        if unsafe { libc::setvbuf(self.handle(), std::ptr::null_mut(), mode, size) } == 0 {
            Ok(())
        } else {
            Err(stream_error(budget))
        }
    }
}

struct CompatOs;

unsafe extern "C" {
    fn clock() -> libc::clock_t;
}

fn host_bytes(bytes: &[u8], budget: &mut ResourceBudget<'_>) -> Result<Vec<u8>, HostResourceError> {
    budget.spend_work(bytes.len().saturating_add(1))?;
    budget.claim_temporary(bytes.len())?;
    let output = bytes.to_vec();
    budget.claim_temporary(output.capacity() - bytes.len())?;
    Ok(output)
}

fn calendar(tm: &libc::tm) -> HostCalendar {
    HostCalendar {
        year: i64::from(tm.tm_year) + 1900,
        month: i64::from(tm.tm_mon) + 1,
        day: i64::from(tm.tm_mday),
        hour: i64::from(tm.tm_hour),
        minute: i64::from(tm.tm_min),
        second: i64::from(tm.tm_sec),
        weekday: Some(i64::from(tm.tm_wday) + 1),
        year_day: Some(i64::from(tm.tm_yday) + 1),
        daylight_saving: (tm.tm_isdst >= 0).then_some(tm.tm_isdst != 0),
    }
}

fn tm_from_calendar(value: HostCalendar) -> Result<libc::tm, HostResourceError> {
    let checked = |value: i64| i32::try_from(value).map_err(|_| resource_error(HostResourceErrorKind::PlatformDifference));
    // SAFETY：libc tm 全欄位為數值或原始指標；零值是有效初始化，mktime 會填入派生欄位。
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = checked(value.year.checked_sub(1900)
        .ok_or_else(|| resource_error(HostResourceErrorKind::PlatformDifference))?)?;
    tm.tm_mon = checked(value.month.checked_sub(1)
        .ok_or_else(|| resource_error(HostResourceErrorKind::PlatformDifference))?)?;
    tm.tm_mday = checked(value.day)?;
    tm.tm_hour = checked(value.hour)?;
    tm.tm_min = checked(value.minute)?;
    tm.tm_sec = checked(value.second)?;
    tm.tm_isdst = value.daylight_saving.map_or(-1, i32::from);
    Ok(tm)
}

fn platform_error(message: &[u8], budget: &mut ResourceBudget<'_>) -> HostResourceError {
    if budget.claim_temporary(message.len()).is_err() {
        return resource_error(HostResourceErrorKind::Budget);
    }
    let mut diagnostic = Vec::new();
    if diagnostic.try_reserve_exact(message.len()).is_err() {
        return resource_error(HostResourceErrorKind::Budget);
    }
    if budget.claim_temporary(diagnostic.capacity() - message.len()).is_err() {
        return resource_error(HostResourceErrorKind::Budget);
    }
    diagnostic.extend_from_slice(message);
    HostResourceError::new(HostResourceErrorKind::PlatformDifference, diagnostic)
}

fn append_date_part(
    output: &mut Vec<u8>, part: &[u8], budget: &mut ResourceBudget<'_>,
) -> Result<(), HostResourceError> {
    let needed = output.len().checked_add(part.len())
        .ok_or_else(|| resource_error(HostResourceErrorKind::Budget))?;
    if needed > output.capacity() {
        budget.claim_temporary(needed - output.capacity())?;
        output.try_reserve(needed - output.len())
            .map_err(|_| resource_error(HostResourceErrorKind::Budget))?;
        budget.claim_temporary(output.capacity() - needed)?;
    }
    output.extend_from_slice(part);
    Ok(())
}

fn date_value(
    format: &[u8], epoch: Option<i64>, budget: &mut ResourceBudget<'_>,
) -> Result<HostOsValue, HostResourceError> {
    let epoch = epoch.unwrap_or_else(|| {
        // SAFETY：time(NULL) 只讀取系統時間。
        unsafe { libc::time(std::ptr::null_mut()) as i64 }
    });
    let epoch: libc::time_t = epoch.try_into().map_err(|_| resource_error(HostResourceErrorKind::PlatformDifference))?;
    // SAFETY：libc tm 為 POD；成功的 localtime_r/gmtime_r 會完整填入。
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let (utc, format) = if let Some(format) = format.strip_prefix(b"!") { (true, format) } else { (false, format) };
    // SAFETY：epoch 與 tm 是有效記憶體，C 只在呼叫期間使用。
    let converted = unsafe {
        if utc { libc::gmtime_r(&epoch, &mut tm) } else { libc::localtime_r(&epoch, &mut tm) }
    };
    if converted.is_null() { return Err(resource_error(HostResourceErrorKind::PlatformDifference)); }
    if format == b"*t" {
        return Ok(HostOsValue::Calendar(calendar(&tm)));
    }
    budget.spend_work(format.len().saturating_add(1))?;
    let mut output = Vec::new();
    let mut offset = 0;
    const SINGLE: &[u8] = b"aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%";
    const DOUBLE: &[u8] = b"EcECExEXEyEYOdOeOHOIOmOMOSOuOUOVOwOWOy";
    while offset < format.len() {
        if format[offset] != b'%' {
            let end = format[offset..].iter().position(|byte| *byte == b'%')
                .map_or(format.len(), |next| offset + next);
            append_date_part(&mut output, &format[offset..end], budget)?;
            offset = end;
            continue;
        }
        let option = &format[offset + 1..];
        let option_len = if option.first().is_some_and(|byte| SINGLE.contains(byte)) {
            1
        } else if option.len() >= 2
            && DOUBLE.chunks_exact(2).any(|part| part == &option[..2])
        {
            2
        } else {
            return Err(platform_error(b"invalid conversion specifier", budget));
        };
        let mut conversion = [0_u8; 4];
        conversion[0] = b'%';
        conversion[1..1 + option_len].copy_from_slice(&option[..option_len]);
        let mut item = [0_u8; 250];
        // SAFETY：conversion NUL 結尾，item 固定 250 bytes；strftime 不保留指標。
        let length = unsafe { libc::strftime(item.as_mut_ptr().cast(), item.len(),
            conversion.as_ptr().cast(), &tm) };
        append_date_part(&mut output, &item[..length], budget)?;
        offset += 1 + option_len;
    }
    Ok(HostOsValue::Bytes(output))
}

fn exit_status(status: i32) -> HostExitStatus {
    let signaled = status & 0x7f != 0;
    let code = if signaled { status & 0x7f } else { (status >> 8) & 0xff };
    HostExitStatus { success: status == 0, signaled, code: i64::from(code) }
}

impl HostOs for CompatOs {
    fn authorize(
        &mut self, _operation: HostOsOperation<'_>, budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }

    fn authorize_path(&mut self, path: &[u8], budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(path.len().saturating_add(1))?;
        os_path(path).map(|_| ())
    }

    fn perform(
        &mut self, operation: HostOsOperation<'_>, budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        budget.spend_work(1)?;
        match operation {
            HostOsOperation::Exit(request) => Ok(HostOsValue::ExitRequest(request)),
            HostOsOperation::GetEnv(name) => {
                if name.contains(&b'=') { return Ok(HostOsValue::Nil); }
                let name = c_path(name)?;
                // SAFETY：name 是有效 C 字串；返回的程序環境指標在同步複製時有效。
                let value = unsafe { libc::getenv(name.as_ptr()) };
                if value.is_null() { return Ok(HostOsValue::Nil); }
                // SAFETY：非 NULL getenv 結果為 NUL 結尾字串，在此立即複製。
                let value = unsafe { CStr::from_ptr(value) }.to_bytes();
                Ok(HostOsValue::Bytes(host_bytes(value, budget)?))
            }
            HostOsOperation::Clock => {
                // SAFETY：clock 不接收指標，回傳 process CPU time。
                let ticks = unsafe { clock() };
                if ticks == !0 { return Err(stream_error(budget)); }
                Ok(HostOsValue::Number(ticks as f64 / 1_000_000.0))
            }
            HostOsOperation::Date(format, epoch) => date_value(format, epoch, budget),
            HostOsOperation::Time(None) => {
                // SAFETY：time(NULL) 只讀取系統時間。
                let epoch = unsafe { libc::time(std::ptr::null_mut()) };
                if epoch == -1 {
                    return Err(platform_error(b"time result cannot be represented in this installation", budget));
                }
                Ok(HostOsValue::Time { epoch: epoch as i64, normalized: None })
            }
            HostOsOperation::Time(Some(value)) => {
                let mut tm = tm_from_calendar(value)?;
                // SAFETY：mktime 可更新此唯一可寫 tm，且不保存指標。
                let epoch = unsafe { libc::mktime(&mut tm) };
                if epoch == -1 {
                    return Err(platform_error(b"time result cannot be represented in this installation", budget));
                }
                Ok(HostOsValue::Time { epoch: epoch as i64, normalized: Some(calendar(&tm)) })
            }
            HostOsOperation::Locale(locale, category) => {
                let category = match category.unwrap_or(b"all") {
                    b"all" => libc::LC_ALL,
                    b"collate" => libc::LC_COLLATE,
                    b"ctype" => libc::LC_CTYPE,
                    b"monetary" => libc::LC_MONETARY,
                    b"numeric" => libc::LC_NUMERIC,
                    b"time" => libc::LC_TIME,
                    _ => return Err(resource_error(HostResourceErrorKind::PlatformDifference)),
                };
                let locale = locale.map(c_path).transpose()?;
                // SAFETY：locale CString 在同步 setlocale 期間有效；返回的程序全域指標立即複製。
                let result = unsafe { libc::setlocale(category, locale.as_ref().map_or(std::ptr::null(), |value| value.as_ptr())) };
                if result.is_null() { return Ok(HostOsValue::Nil); }
                // SAFETY：成功 setlocale 回傳 NUL 結尾的程序全域字串，立即複製。
                let bytes = unsafe { CStr::from_ptr(result) }.to_bytes();
                Ok(HostOsValue::Bytes(host_bytes(bytes, budget)?))
            }
            HostOsOperation::Remove(path) => {
                let path_bytes = path;
                let path = os_path(path_bytes)?;
                let result = if fs::symlink_metadata(path)
                    .map_err(|error| io_error_named(error, path_bytes, budget))?
                    .file_type()
                    .is_dir()
                {
                    fs::remove_dir(path)
                } else {
                    fs::remove_file(path)
                };
                result.map_err(|error| io_error_named(error, path_bytes, budget))?;
                Ok(HostOsValue::Boolean(true))
            }
            HostOsOperation::Rename(from, to) => {
                fs::rename(os_path(from)?, os_path(to)?).map_err(|error| io_error(error, budget))?;
                Ok(HostOsValue::Boolean(true))
            }
            HostOsOperation::Execute(command) => {
                let command = command.map(c_path).transpose()?;
                // SAFETY：command CString 在同步 system 期間有效；NULL 僅探測 shell。
                let status = unsafe { libc::system(command.as_ref().map_or(std::ptr::null(), |value| value.as_ptr())) };
                if command.is_none() { return Ok(HostOsValue::Boolean(status != 0)); }
                if status < 0 { return Err(stream_error(budget)); }
                Ok(HostOsValue::Exit(exit_status(status)))
            }
            HostOsOperation::TmpName => {
                let mut template = b"/tmp/lua_XXXXXX\0".to_vec();
                budget.claim_temporary(template.capacity())?;
                // SAFETY：template 可寫且 NUL 結尾；mkstemp 原地替換 X，成功 fd 唯一持有。
                let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
                if fd < 0 { return Err(stream_error(budget)); }
                // SAFETY：成功 fd 由此呼叫取得，只關閉不刪檔，對齊 Lua POSIX tmpname。
                unsafe { libc::close(fd) };
                template.pop();
                Ok(HostOsValue::Bytes(template))
            }
        }
    }
}


