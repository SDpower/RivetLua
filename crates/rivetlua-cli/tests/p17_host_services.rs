#![cfg(all(unix, any(feature = "native-lua55", feature = "native-lua54")))]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("P17 host services 每個測試 binary 只能選一個 Lua ABI profile");

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "native-lua55")]
const PROFILE: &str = "lua55-i64f64";
#[cfg(feature = "native-lua54")]
const PROFILE: &str = "lua54-i64f64";

#[cfg(feature = "native-lua55")]
const FIXTURE_SUFFIX: &str = "lua-5.5.1-tests";
#[cfg(feature = "native-lua54")]
const FIXTURE_SUFFIX: &str = "lua-5.4.9-tests";

#[cfg(feature = "native-lua55")]
const B01_GRANT_SHA256: &str = "67d81268e3daafc7e172ee73e607448309d452f5067d07f9ced8f769129726ac";
#[cfg(feature = "native-lua54")]
const B01_GRANT_SHA256: &str = "23895bb7d1e26f817f3ff4cd451258055124c0227e6ec521e25cbf8b708ec3de";

const CLI_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    root: PathBuf,
    work: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let evidence = env::var_os("RIVETLUA_P17_EVIDENCE_DIR")
            .map(PathBuf::from)
            .expect("P17 runner 必須指定外部 evidence 目錄");
        assert!(evidence.is_absolute(), "P17 evidence 目錄必須是絕對路徑");
        fs::create_dir_all(&evidence).expect("建立 P17 evidence 目錄");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let root = evidence.join(format!(
            "host-services-{PROFILE}-{label}-{}-{sequence}-{stamp}",
            std::process::id()
        ));
        let work = root.join("work");
        fs::create_dir_all(&work).expect("建立隔離 host services scratch");
        Self { root, work }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct B01Fixture {
    grant: PathBuf,
    modules: PathBuf,
}

struct CliResult {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    timed_out: bool,
    log_path: PathBuf,
}

struct CallerOwnedTempnames(Vec<(String, PathBuf)>);

impl CallerOwnedTempnames {
    fn from_stdout(stdout: &str) -> Self {
        let mut paths = Vec::new();
        for line in stdout.lines() {
            for marker in ["P17_TMPNAME_PROG=", "P17_TMPNAME_OTHER="] {
                if let Some(path) = line.strip_prefix(marker) {
                    paths.push((marker.to_owned(), PathBuf::from(path)));
                    break;
                }
            }
        }
        Self(paths)
    }

    fn get(&self, marker: &str) -> &Path {
        let mut matches = self
            .0
            .iter()
            .filter(|(candidate, _)| candidate == marker)
            .map(|(_, path)| path.as_path());
        let path = matches
            .next()
            .unwrap_or_else(|| panic!("CLI 未回報 {marker} os.tmpname 路徑"));
        assert!(matches.next().is_none(), "CLI 重複回報 {marker} 路徑");
        path
    }

    fn remove_all(&mut self) {
        for (_, path) in &self.0 {
            fs::remove_file(path).unwrap_or_else(|error| {
                panic!("移除呼叫端擁有的 {} 失敗：{error}", path.display())
            });
        }
        self.0.clear();
    }
}

impl Drop for CallerOwnedTempnames {
    fn drop(&mut self) {
        for (_, path) in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn evidence_root() -> PathBuf {
    let root = env::var_os("RIVETLUA_P17_EVIDENCE_DIR")
        .map(PathBuf::from)
        .expect("P17 runner 必須指定 external evidence 目錄");
    assert!(root.is_absolute(), "P17 evidence 目錄必須是絕對路徑");
    root
}

fn b01_fixture() -> B01Fixture {
    let prefix = format!("b01-{}-", PROFILE.trim_end_matches("-i64f64"));
    let mut candidates = fs::read_dir(evidence_root())
        .expect("讀取既有 B01 evidence 目錄")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
                && path.join("p17-native-grant.json").is_file()
                && path.join("rivetlua").is_file()
                && path
                    .join("fixture")
                    .join(FIXTURE_SUFFIX)
                    .join("libs/lib1.so")
                    .is_file()
                && path
                    .join("fixture")
                    .join(FIXTURE_SUFFIX)
                    .join("libs/lib2.so")
                    .is_file()
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| {
                name.to_string_lossy()
                    .rsplit('-')
                    .next()?
                    .parse::<u128>()
                    .ok()
            })
            .unwrap_or_default()
    });
    let run = candidates
        .pop()
        .expect("找不到既有 P17-B01 同 profile grant 與 lib1/lib2 artifacts");
    let grant = run.join("p17-native-grant.json");
    assert_eq!(
        file_sha256(&grant),
        B01_GRANT_SHA256,
        "重用的官方 B01 grant 必須與封存來源 bytes 完全相同"
    );
    B01Fixture {
        grant,
        modules: run.join("fixture").join(FIXTURE_SUFFIX).join("libs"),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = rivetlua_capi::native::binary_sha256(bytes).expect("計算 SHA-256");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn file_sha256(path: &Path) -> String {
    sha256(&fs::read(path).unwrap_or_else(|error| panic!("讀取 {} 失敗：{error}", path.display())))
}

fn test_source_sha256() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("p17_host_services.rs");
    file_sha256(&path)
}

fn lua_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value.is_control() => out.push_str(&format!("\\{:03}", value as u32)),
            value => out.push(value),
        }
    }
    out.push('"');
    out
}

fn replace_json_string_field(input: &str, key: &str, replacement: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = input
        .find(&needle)
        .unwrap_or_else(|| panic!("B01 grant 缺少 JSON 欄位 {key}"))
        + needle.len();
    let end = start
        + input[start..]
            .find('"')
            .unwrap_or_else(|| panic!("B01 grant 欄位 {key} 未結束"));
    let mut output = String::with_capacity(input.len() + replacement.len());
    output.push_str(&input[..start]);
    output.push_str(replacement);
    output.push_str(&input[end..]);
    output
}

fn cli_binary() -> PathBuf {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_rivetlua"))
        .canonicalize()
        .expect("Cargo 提供的編譯後 rivetlua binary 存在");
    let metadata = fs::metadata(&binary).expect("讀取 rivetlua binary metadata");
    assert!(
        metadata.is_file(),
        "CLI 必須是實際可執行檔，不可使用 wrapper"
    );
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "Cargo CLI artifact 必須具有 executable 權限"
    );
    binary
}

fn run_lua(label: &str, source: &str, grant: Option<&Path>, stdin: &[u8]) -> CliResult {
    run_cli_input(label, Some(source.as_bytes()), grant, stdin)
}

fn run_lua_with_options(
    label: &str,
    source: &str,
    grant: Option<&Path>,
    arguments: &[&str],
    extra_env: &[(&str, &str)],
) -> CliResult {
    run_cli_input_with_options(
        label,
        Some(source.as_bytes()),
        grant,
        &[],
        arguments,
        extra_env,
    )
}

fn run_lua_file_bytes(label: &str, source: &[u8], grant: Option<&Path>) -> CliResult {
    run_cli_input(label, Some(source), grant, &[])
}

fn run_lua_stdin(label: &str, source: &[u8], grant: Option<&Path>) -> CliResult {
    run_cli_input(label, None, grant, source)
}

fn run_cli_input(
    label: &str,
    file_source: Option<&[u8]>,
    grant: Option<&Path>,
    stdin: &[u8],
) -> CliResult {
    run_cli_input_with_options(label, file_source, grant, stdin, &[], &[])
}

fn run_cli_input_with_options(
    label: &str,
    file_source: Option<&[u8]>,
    grant: Option<&Path>,
    stdin: &[u8],
    arguments: &[&str],
    extra_env: &[(&str, &str)],
) -> CliResult {
    let scratch = Scratch::new(label);
    let script = file_source.map(|source| {
        let script = scratch.path("case.lua");
        fs::write(&script, source).expect("寫入隔離 Lua case bytes");
        script
    });
    let cli = cli_binary();
    let cli_hash = file_sha256(&cli);
    let source_hash = test_source_sha256();
    let grant_hash = grant.map(file_sha256);
    let stdout_path = scratch.path("stdout.log");
    let stderr_path = scratch.path("stderr.log");
    let stdin_path = scratch.path("stdin.data");
    if !stdin.is_empty() {
        fs::write(&stdin_path, stdin).expect("寫入隔離 CLI stdin");
    }

    // 執行路徑是 Cargo 編譯出的 CLI binary，直接傳入 guest script，沒有 shell wrapper。
    let mut command = Command::new(&cli);
    command
        .current_dir(&scratch.work)
        .env_clear()
        .env_remove("_U")
        .env("TMPDIR", &scratch.work)
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::from(
            File::create(&stdout_path).expect("建立 CLI stdout log"),
        ))
        .stderr(Stdio::from(
            File::create(&stderr_path).expect("建立 CLI stderr log"),
        ));
    command.args(arguments.iter().copied());
    if let Some(script) = &script {
        command.arg(script);
    }
    for (key, value) in extra_env {
        command.env(*key, *value);
    }
    if let Some(grant) = grant {
        command.env("RIVETLUA_NATIVE_MANIFEST", grant);
    } else {
        command.env_remove("RIVETLUA_NATIVE_MANIFEST");
    }
    command.stdin(if stdin.is_empty() {
        Stdio::null()
    } else {
        Stdio::from(File::open(&stdin_path).expect("開啟隔離 CLI stdin"))
    });

    let mut argv_items = Vec::with_capacity(2 + arguments.len());
    argv_items.push(cli.as_os_str().to_owned());
    argv_items.extend(arguments.iter().map(|argument| OsString::from(*argument)));
    if let Some(script) = &script {
        argv_items.push(script.as_os_str().to_owned());
    }
    let argv = format!("{argv_items:?}");
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("直接啟動編譯後 CLI 失敗：{error}"));
    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().expect("檢查 CLI process 狀態") {
            break (status, false);
        }
        if started.elapsed() >= CLI_TIMEOUT {
            let _ = child.kill();
            break (child.wait().expect("逾時後等待已終止 CLI"), true);
        }
        thread::sleep(Duration::from_millis(10));
    };

    let mut stdout = Vec::new();
    File::open(&stdout_path)
        .expect("讀取 CLI stdout log")
        .read_to_end(&mut stdout)
        .expect("讀取 CLI stdout");
    let mut stderr = Vec::new();
    File::open(&stderr_path)
        .expect("讀取 CLI stderr log")
        .read_to_end(&mut stderr)
        .expect("讀取 CLI stderr");
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    let evidence_dir = evidence_root();
    let log_dir = if label.starts_with("p17_debug_console_") {
        let dir = evidence_dir.join("p17-debug-console-regressions");
        fs::create_dir_all(&dir).expect("建立 debug console P17 regression evidence 目錄");
        dir
    } else {
        evidence_dir
    };
    let log_path = log_dir.join(format!(
        "p17-host-{PROFILE}-{}-{}-{}.log",
        label,
        std::process::id(),
        NEXT_RUN.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &log_path,
        format!(
            "profile={PROFILE}\nselector={label}\nprocess_count=1\nmatched=1\nargv={argv}\nextra_env={extra_env:?}\ncwd={}\ncli_sha256={cli_hash}\ntest_source_sha256={source_hash}\ngrant={}\ngrant_sha256={}\nexit_code={:?}\ntimed_out={timed_out}\nstdout={stdout:?}\nstderr={stderr:?}\n",
            scratch.work.display(),
            grant.map_or_else(|| "<unset>".to_owned(), |path| path.display().to_string()),
            grant_hash.as_deref().unwrap_or("<none>"),
            status.code()
        ),
    )
    .expect("保存不可變 P17 host test process log");
    CliResult {
        status,
        stdout,
        stderr,
        timed_out,
        log_path,
    }
}

fn assert_cli_success(result: &CliResult, label: &str) {
    assert!(
        !result.timed_out,
        "{label} CLI 超過 {:?}; log={}",
        CLI_TIMEOUT,
        result.log_path.display()
    );
    assert!(
        result.status.success(),
        "{label} CLI 失敗，exit={:?}\nstdout={}\nstderr={}\nlog={}",
        result.status.code(),
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

fn assert_cli_rejected(result: &CliResult, label: &str) {
    assert!(
        !result.timed_out,
        "{label} CLI 超過 {:?}; log={}",
        CLI_TIMEOUT,
        result.log_path.display()
    );
    assert!(
        !result.status.success(),
        "{label} CLI 應拒絕來源，實際成功\nstdout={}\nstderr={}\nlog={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

fn assert_cli_diagnostic_contains(result: &CliResult, expected: &str, label: &str) {
    let output = format!("{}\n{}", result.stdout, result.stderr);
    assert!(
        output.contains(expected),
        "{label} CLI 診斷缺少 {expected:?}\nstdout={}\nstderr={}\nlog={}",
        result.stdout,
        result.stderr,
        result.log_path.display()
    );
}

fn assert_malformed_bom_rejected(label: &str, source: &[u8]) {
    for (route, result) in [
        (
            "file",
            run_lua_file_bytes(&format!("{label}-file"), source, None),
        ),
        (
            "stdin",
            run_lua_stdin(&format!("{label}-stdin"), source, None),
        ),
    ] {
        let case = format!("{label} {route}");
        assert_cli_rejected(&result, &case);
        assert_cli_diagnostic_contains(&result, "未知詞法元素", &case);
        assert_cli_diagnostic_contains(&result, "unexpected symbol", &case);
    }
}

#[test]
fn p17_host_no_grant_policy_and_legacy_os() {
    let fixture = b01_fixture();
    let module = fixture.modules.join("lib1.so");
    let scratch = Scratch::new("no-grant-io-sentinel");
    let denied_path = scratch.path("must-not-be-created.bin");
    assert!(!denied_path.exists());
    let script = format!(
        r#"
assert(_U == nil)
assert(type(os.clock()) == "number" and os.clock() >= 0)
assert(type(os.time()) == "number")
assert(os.setlocale(nil, "all") == "C")

local ok, err = pcall(os.execute, "printf P17_NO_GRANT_MUST_NOT_EXECUTE")
assert(not ok and type(err) == "string" and string.find(err, "E_HOST_POLICY_OS", 1, true))
ok, err = pcall(os.tmpname)
assert(not ok and type(err) == "string" and string.find(err, "E_HOST_POLICY_OS", 1, true))
ok, err = pcall(io.open, {denied_path}, "wb")
assert(not ok and type(err) == "string" and string.find(err, "E_HOST_POLICY_IO", 1, true))
ok, err = pcall(io.tmpfile)
assert(not ok and type(err) == "string" and string.find(err, "E_HOST_POLICY_IO", 1, true))
ok, err = pcall(io.popen, "printf P17_NO_GRANT_MUST_NOT_EXECUTE", "r")
assert(not ok and type(err) == "string" and string.find(err, "E_HOST_POLICY_IO", 1, true))

local opener, message, when = package.loadlib({module}, "luaopen_lib1_sub")
assert(opener == nil and type(message) == "string" and when == "open")
assert(string.find(message, "native-grant:", 1, true))
assert(_G.x == nil and _G.y == nil)
print("P17_HOST_NO_GRANT {PROFILE} PASS")
"#,
        PROFILE = PROFILE,
        module = lua_quote(&module.to_string_lossy()),
        denied_path = lua_quote(&denied_path.to_string_lossy()),
    );
    let result = run_lua("p17_host_no_grant_policy_and_legacy_os", &script, None, &[]);
    assert!(
        !denied_path.exists(),
        "no-grant io.open 不得建立 sentinel 檔案"
    );
    assert_cli_success(&result, "no-grant");
    assert!(result.stdout.contains("P17_HOST_NO_GRANT"));
    assert!(!result.stdout.contains("P17_NO_GRANT_MUST_NOT_EXECUTE"));

    let no_grant_debug = run_cli_input_with_options(
        "p17_debug_console_no_grant_rejected_without_prompt",
        None,
        None,
        b"print(\"P17_DEBUG_NO_GRANT_STDIN_MUST_NOT_RUN\")\n",
        &["-e", "require('debug').debug()", "-i"],
        &[],
    );
    assert_cli_rejected(&no_grant_debug, "no-grant debug console");
    assert_cli_diagnostic_contains(
        &no_grant_debug,
        "E_HOST_POLICY_DEBUG",
        "no-grant debug console",
    );
    assert!(!no_grant_debug.stderr.contains("lua_debug> "));
    assert!(
        !no_grant_debug
            .stdout
            .contains("P17_DEBUG_NO_GRANT_STDIN_MUST_NOT_RUN")
    );
    assert!(
        !no_grant_debug
            .stderr
            .contains("P17_DEBUG_NO_GRANT_STDIN_MUST_NOT_RUN")
    );

    // 這些子案例都直接啟動 Cargo 編出的 CLI；檔案 script 路徑與其後參數由本地 helper 原樣傳入。
    let script_inputs = Scratch::new("script-args-inputs");
    let run_file_script = |label: &str,
                           source: &str,
                           grant: Option<&Path>,
                           prefix_args: &[&str],
                           script_args: &[&str],
                           extra_env: &[(&str, &str)]| {
        let script_path = script_inputs.path(&format!("{label}.lua"));
        fs::write(&script_path, source.as_bytes()).expect("寫入隔離 script-args fixture");
        let script_path = script_path
            .to_str()
            .expect("script-args fixture path 是 UTF-8")
            .to_owned();
        let mut arguments = Vec::with_capacity(prefix_args.len() + 1 + script_args.len());
        arguments.extend_from_slice(prefix_args);
        arguments.push(&script_path);
        arguments.extend_from_slice(script_args);
        run_cli_input_with_options(label, None, grant, &[], &arguments, extra_env)
    };

    let action_updates_arg = run_cli_input_with_options(
        "p17_script_args_action_updates_arg_stdin",
        None,
        None,
        b"print(...)\n",
        &["-e", "arg[1] = 100", "-"],
        &[],
    );
    assert_cli_success(&action_updates_arg, "-e arg[1] stdin");
    assert_eq!(action_updates_arg.stdout, "100\n");

    let typed_setup = r#"
_P17_ARG_WEAK = setmetatable({arg}, {__mode = "v"})
local table_value = { marker = "table" }
local function_value = function() return "function" end
_P17_ARG_TABLE = table_value
_P17_ARG_FUNCTION = function_value
arg = { true, "string", table_value, function_value }
type = false
error = false
math = false
"#;
    let typed_script = r##"
collectgarbage("collect")
assert(_P17_ARG_WEAK[1] == nil)
local boolean_value, string_value, table_value, function_value = ...
assert(select("#", ...) == 4)
assert(rawequal(boolean_value, true))
assert(rawequal(string_value, "string"))
assert(rawequal(table_value, _P17_ARG_TABLE))
assert(rawequal(function_value, _P17_ARG_FUNCTION))
assert(rawequal(rawget(arg, 3), _P17_ARG_TABLE))
assert(rawequal(rawget(arg, 4), _P17_ARG_FUNCTION))
print("P17_SCRIPT_ARGS_TYPED PASS")
"##;
    let typed_values = run_file_script(
        "p17_script_args_replacement_values_and_builtin_overrides",
        typed_script,
        None,
        &["-e", typed_setup],
        &[],
        &[],
    );
    assert_cli_success(&typed_values, "replacement arg values");
    assert_eq!(typed_values.stdout, "P17_SCRIPT_ARGS_TYPED PASS\n");

    let sparse_setup = r#"
_P17_ARG_INDEX_HIT = false
local sparse = { [1] = "first", [3] = "third" }
setmetatable(sparse, {
  __len = function() return 3 end,
  __index = function()
    _P17_ARG_INDEX_HIT = true
    error("P17_ARG_INDEX_MUST_NOT_RUN")
  end
})
arg = sparse
"#;
    let sparse_script = r##"
local first, hole, third = ...
assert(select("#", ...) == 3)
assert(first == "first" and hole == nil and third == "third")
assert(rawget(arg, 2) == nil)
assert(_P17_ARG_INDEX_HIT == false)
print("P17_SCRIPT_ARGS_SPARSE PASS")
"##;
    let sparse_values = run_file_script(
        "p17_script_args_len_rawget_and_nil_hole",
        sparse_script,
        None,
        &["-e", sparse_setup],
        &[],
        &[],
    );
    assert_cli_success(&sparse_values, "sparse arg raw lookup");
    assert_eq!(sparse_values.stdout, "P17_SCRIPT_ARGS_SPARSE PASS\n");

    let replaced_global_setup = r#"
local original = { [1] = "retained" }
setmetatable(original, {
  __len = function()
    arg = { replacement = true }
    collectgarbage("collect")
    return 1
  end
})
arg = original
"#;
    let replaced_global_script = r##"
local retained = ...
assert(select("#", ...) == 1 and retained == "retained")
assert(arg.replacement == true)
print("P17_SCRIPT_ARGS_LEN_REPLACED_GLOBAL PASS")
"##;
    let replaced_global = run_file_script(
        "p17_script_args_len_replaces_global_and_collects",
        replaced_global_script,
        None,
        &["-e", replaced_global_setup],
        &[],
        &[],
    );
    assert_cli_success(&replaced_global, "__len replaces global arg");
    assert_eq!(
        replaced_global.stdout,
        "P17_SCRIPT_ARGS_LEN_REPLACED_GLOBAL PASS\n"
    );

    let len_error = run_cli_input_with_options(
        "p17_script_args_len_error_stops_stdin_script",
        None,
        None,
        b"print(\"P17_ARG_SCRIPT_MUST_NOT_RUN\")\n",
        &[
            "-e",
            "arg = setmetatable({}, {__len = function() error('P17_ARG_LEN_FAILURE') end})",
            "-",
        ],
        &[],
    );
    assert_cli_rejected(&len_error, "arg __len error");
    assert_cli_diagnostic_contains(&len_error, "P17_ARG_LEN_FAILURE", "arg __len error");
    assert!(!len_error.stdout.contains("P17_ARG_SCRIPT_MUST_NOT_RUN"));
    assert!(!len_error.stderr.contains("(rivetlua script args)"));

    let noninteger_len = run_cli_input_with_options(
        "p17_script_args_noninteger_len_stops_stdin_script",
        None,
        None,
        b"print(\"P17_NONINTEGER_LEN_SCRIPT_MUST_NOT_RUN\")\n",
        &[
            "-e",
            "arg = setmetatable({}, {__len = function() return 1.5 end})",
            "-",
        ],
        &[],
    );
    assert_cli_rejected(&noninteger_len, "noninteger arg __len");
    assert_cli_diagnostic_contains(
        &noninteger_len,
        "object length is not an integer",
        "noninteger arg __len",
    );
    assert!(
        !noninteger_len
            .stdout
            .contains("P17_NONINTEGER_LEN_SCRIPT_MUST_NOT_RUN")
    );
    assert!(!noninteger_len.stderr.contains("(rivetlua script args)"));

    for (label, replacement) in [
        ("number", "arg = 17"),
        ("string", "arg = 'not a table'"),
        ("nil", "arg = nil"),
    ] {
        let invalid_arg = run_cli_input_with_options(
            &format!("p17_script_args_invalid_{label}_stops_stdin_script"),
            None,
            None,
            b"print(\"P17_INVALID_ARG_SCRIPT_MUST_NOT_RUN\")\n",
            &["-e", replacement, "-"],
            &[],
        );
        assert_cli_rejected(&invalid_arg, &format!("invalid arg {label}"));
        assert_cli_diagnostic_contains(
            &invalid_arg,
            "'arg' is not a table",
            &format!("invalid arg {label}"),
        );
        assert!(
            !invalid_arg
                .stdout
                .contains("P17_INVALID_ARG_SCRIPT_MUST_NOT_RUN")
        );
        assert!(!invalid_arg.stderr.contains("(rivetlua script args)"));
    }

    let lua_init_script = r##"
local value = ...
assert(select("#", ...) == 1 and value == 77)
assert(rawget(arg, 1) == 77)
print("P17_LUA_INIT_ARG PASS")
"##;
    let lua_init = "arg = { [1] = 77 }";
    let lua_init_env = [("LUA_INIT", lua_init)];
    let lua_init_arg = run_file_script(
        "p17_script_args_lua_init_updates_arg",
        lua_init_script,
        None,
        &[],
        &[],
        &lua_init_env,
    );
    assert_cli_success(&lua_init_arg, "LUA_INIT arg update");
    assert_eq!(lua_init_arg.stdout, "P17_LUA_INIT_ARG PASS\n");

    let syntax_priority = run_cli_input_with_options(
        "p17_script_args_syntax_error_precedes_invalid_arg",
        None,
        None,
        b"return @\n",
        &["-e", "arg = 17", "-"],
        &[],
    );
    assert_cli_rejected(&syntax_priority, "script syntax error priority");
    assert_cli_diagnostic_contains(&syntax_priority, "unexpected symbol", "script syntax error");
    assert!(!syntax_priority.stderr.contains("'arg' is not a table"));
    assert!(syntax_priority.stdout.is_empty());

    let missing_script = script_inputs.path("script-args-missing.lua");
    assert!(!missing_script.exists());
    let missing_script = missing_script
        .to_str()
        .expect("missing script path 是 UTF-8")
        .to_owned();
    let load_priority = run_cli_input_with_options(
        "p17_script_args_load_error_precedes_invalid_arg",
        None,
        None,
        &[],
        &["-e", "arg = 17", missing_script.as_str()],
        &[],
    );
    assert_cli_rejected(&load_priority, "script load error priority");
    assert_cli_diagnostic_contains(
        &load_priority,
        "讀取檔案資訊失敗",
        "script load error priority",
    );
    assert!(!load_priority.stderr.contains("'arg' is not a table"));
    assert!(load_priority.stdout.is_empty());

    let grant = fs::canonicalize(&fixture.grant).expect("解析唯讀 B01 grant 路徑");
    let module = fs::canonicalize(&module).expect("解析唯讀 B01 lib1.so 路徑");
    let native_len_setup = format!(
        r#"
local opener = assert(package.loadlib({}, "luaopen_lib1_sub"))
local native_module = assert(opener("lib1.sub", {}))
_P17_ARG_NATIVE_LEN_RAN = false
local original = {{ [1] = "native-len" }}
setmetatable(original, {{
  __len = function()
    assert(rawequal(native_module.id("P17_NATIVE_LEN"), "P17_NATIVE_LEN"))
    _P17_ARG_NATIVE_LEN_RAN = true
    return 1
  end
}})
arg = original
"#,
        lua_quote(&module.to_string_lossy()),
        lua_quote(&module.to_string_lossy())
    );
    let native_len_script = r##"
local value = ...
assert(select("#", ...) == 1 and value == "native-len")
assert(_P17_ARG_NATIVE_LEN_RAN == true)
print("P17_NATIVE_ARG_LEN PASS")
"##;
    let native_len = run_file_script(
        "p17_script_args_native_callback_from_len",
        native_len_script,
        Some(&grant),
        &["-e", native_len_setup.as_str()],
        &[],
        &[],
    );
    assert_cli_success(&native_len, "native callback from __len");
    assert_eq!(native_len.stdout, "P17_NATIVE_ARG_LEN PASS\n");

    // 互動 REPL 的單行錯誤只回報，不中止後續輸入；前置 action 錯誤則不得進入 REPL。
    let repl_nil_print = run_cli_input_with_options(
        "p17_repl_nil_print_reports_and_exits_successfully",
        None,
        None,
        b"10\n",
        &["-e", "print = nil", "-i"],
        &[],
    );
    assert_cli_success(&repl_nil_print, "REPL nil print");
    assert!(
        repl_nil_print.stderr.contains("error calling 'print'"),
        "REPL nil print 錯誤未寫入 stderr；log={}",
        repl_nil_print.log_path.display()
    );

    let repl_nil_print_recovery = run_cli_input_with_options(
        "p17_repl_nil_print_recovers_for_next_line",
        None,
        None,
        b"10\nprint = _P17_REPL_SAVED_PRINT\nprint(\"P17_REPL_NIL_PRINT_RECOVERED\")\n",
        &["-e", "_P17_REPL_SAVED_PRINT = print; print = nil", "-i"],
        &[],
    );
    assert_cli_success(&repl_nil_print_recovery, "REPL nil print recovery");
    assert!(
        repl_nil_print_recovery
            .stderr
            .contains("error calling 'print'"),
        "REPL nil print recovery 錯誤未寫入 stderr；log={}",
        repl_nil_print_recovery.log_path.display()
    );
    assert!(
        repl_nil_print_recovery
            .stdout
            .contains("P17_REPL_NIL_PRINT_RECOVERED")
    );

    let repl_throwing_print_recovery = run_cli_input_with_options(
        "p17_repl_throwing_print_recovers_for_next_line",
        None,
        None,
        b"10\nprint = _P17_REPL_SAVED_PRINT\nprint(\"P17_REPL_ERROR_PRINT_RECOVERED\")\n",
        &[
            "-e",
            "_P17_REPL_SAVED_PRINT = print; print = function() error('P17_REPL_PRINT_FAILURE') end",
            "-i",
        ],
        &[],
    );
    assert_cli_success(
        &repl_throwing_print_recovery,
        "REPL throwing print recovery",
    );
    assert!(
        repl_throwing_print_recovery
            .stderr
            .contains("error calling 'print'"),
        "REPL throwing print failure 未寫入 stderr；log={}",
        repl_throwing_print_recovery.log_path.display()
    );
    assert!(
        repl_throwing_print_recovery
            .stderr
            .contains("P17_REPL_PRINT_FAILURE"),
        "REPL throwing print 原始錯誤未寫入 stderr；log={}",
        repl_throwing_print_recovery.log_path.display()
    );
    assert!(
        repl_throwing_print_recovery
            .stdout
            .contains("P17_REPL_ERROR_PRINT_RECOVERED")
    );

    let repl_syntax_recovery = run_cli_input_with_options(
        "p17_repl_syntax_error_recovers_for_next_line",
        None,
        None,
        b"local =\nprint(\"P17_REPL_AFTER_SYNTAX_ERROR\")\n",
        &["-i"],
        &[],
    );
    assert_cli_success(&repl_syntax_recovery, "REPL syntax error recovery");
    assert!(
        repl_syntax_recovery.stderr.contains("編譯診斷"),
        "REPL syntax error 未寫入 stderr；log={}",
        repl_syntax_recovery.log_path.display()
    );
    assert!(
        repl_syntax_recovery
            .stdout
            .contains("P17_REPL_AFTER_SYNTAX_ERROR")
    );

    let repl_runtime_recovery = run_cli_input_with_options(
        "p17_repl_runtime_error_recovers_for_next_line",
        None,
        None,
        b"error(\"P17_REPL_RUNTIME_FAILURE\")\nprint(\"P17_REPL_AFTER_RUNTIME_ERROR\")\n",
        &["-i"],
        &[],
    );
    assert_cli_success(&repl_runtime_recovery, "REPL runtime error recovery");
    assert!(
        repl_runtime_recovery
            .stderr
            .contains("P17_REPL_RUNTIME_FAILURE"),
        "REPL runtime error 未寫入 stderr；log={}",
        repl_runtime_recovery.log_path.display()
    );
    assert!(
        repl_runtime_recovery
            .stdout
            .contains("P17_REPL_AFTER_RUNTIME_ERROR")
    );

    let repl_incomplete_eof = run_cli_input_with_options(
        "p17_repl_incomplete_input_reports_at_eof",
        None,
        None,
        b"function p17_incomplete()\n",
        &["-i"],
        &[],
    );
    assert_cli_success(&repl_incomplete_eof, "REPL incomplete EOF");
    assert!(
        repl_incomplete_eof.stderr.contains("未完成的 REPL 輸入"),
        "REPL incomplete input at EOF 未寫入 stderr；log={}",
        repl_incomplete_eof.log_path.display()
    );

    let repl_preact_action_error = run_cli_input_with_options(
        "p17_repl_preaction_error_does_not_enter_repl",
        None,
        None,
        b"print(\"P17_REPL_PREACTION_MUST_NOT_RUN\")\n",
        &["-e", "error('P17_REPL_PREACTION_FAILURE')", "-i"],
        &[],
    );
    assert_cli_rejected(&repl_preact_action_error, "REPL pre-action error");
    assert!(
        repl_preact_action_error
            .stderr
            .contains("P17_REPL_PREACTION_FAILURE"),
        "前置 action 錯誤未寫入 stderr；log={}",
        repl_preact_action_error.log_path.display()
    );
    assert!(
        !repl_preact_action_error
            .stdout
            .contains("P17_REPL_PREACTION_MUST_NOT_RUN")
    );

    let bom_comment = b"\xEF\xBB\xBF# comment!!\nassert(debug.getinfo(1, \"l\").currentline == 2)\nprint(\"P17_BOM_COMMENT PASS\")";
    for (route, result) in [
        (
            "file",
            run_lua_file_bytes("p17-bom-comment-file", bom_comment, None),
        ),
        (
            "stdin",
            run_lua_stdin("p17-bom-comment-stdin", bom_comment, None),
        ),
    ] {
        let label = format!("BOM comment {route}");
        assert_cli_success(&result, &label);
        assert!(
            result.stdout.contains("P17_BOM_COMMENT PASS"),
            "{label} 未執行第二行；log={}",
            result.log_path.display()
        );
    }

    let bom_shebang = b"\xEF\xBB\xBF#!/usr/bin/env rivetlua\nassert(debug.getinfo(1, \"l\").currentline == 2)\nprint(\"P17_BOM_SHEBANG PASS\")";
    for (route, result) in [
        (
            "file",
            run_lua_file_bytes("p17-bom-shebang-file", bom_shebang, None),
        ),
        (
            "stdin",
            run_lua_stdin("p17-bom-shebang-stdin", bom_shebang, None),
        ),
    ] {
        let label = format!("BOM shebang {route}");
        assert_cli_success(&result, &label);
        assert!(
            result.stdout.contains("P17_BOM_SHEBANG PASS"),
            "{label} 未執行第二行；log={}",
            result.log_path.display()
        );
    }

    let plain_hash = b"# ordinary first line\nassert(debug.getinfo(1, \"l\").currentline == 2)\nlocal chunk, err = load(\"# ordinary string prefix\\nreturn 1\")\nassert(chunk == nil and type(err) == \"string\")\nprint(\"P17_PLAIN_HASH PASS\")";
    for (route, result) in [
        (
            "file",
            run_lua_file_bytes("p17-plain-hash-file", plain_hash, None),
        ),
        (
            "stdin",
            run_lua_stdin("p17-plain-hash-stdin", plain_hash, None),
        ),
    ] {
        let label = format!("no-BOM hash prefix {route}");
        assert_cli_success(&result, &label);
        assert!(
            result.stdout.contains("P17_PLAIN_HASH PASS"),
            "{label} 未執行第二行；log={}",
            result.log_path.display()
        );
    }

    for (label, source) in [
        ("p17-bom-only", &b"\xEF\xBB\xBF"[..]),
        ("p17-bom-hash-only", &b"\xEF\xBB\xBF#"[..]),
    ] {
        let result = run_lua_file_bytes(label, source, None);
        assert_cli_success(&result, label);
        assert!(
            result.stdout.is_empty(),
            "{label} 空來源不應輸出內容；log={}",
            result.log_path.display()
        );
    }

    for (label, source) in [
        ("p17-second-line-hash", &b"return 1\n# second line\n"[..]),
        (
            "p17-leading-space-hash",
            &b" # leading whitespace\nreturn 1\n"[..],
        ),
    ] {
        let result = run_lua_file_bytes(label, source, None);
        assert_cli_rejected(&result, label);
    }

    for (label, source) in [
        ("p17-bad-bom-ef", &b"\xEF"[..]),
        ("p17-bad-bom-ef-bb", &b"\xEF\xBB"[..]),
        ("p17-bad-bom-ef-code", &b"\xEFprint(3)"[..]),
        ("p17-bad-bom-ef-bb-code", &b"\xEF\xBBprint(3)"[..]),
    ] {
        assert_malformed_bom_rejected(label, source);
    }
}

#[test]
fn p17_host_invalid_grants_reject_before_guest_side_effects() {
    let fixture = b01_fixture();
    let grant_text = fs::read_to_string(&fixture.grant).expect("讀取唯讀 B01 grant");
    let fixture_sha = file_sha256(&fixture.grant);
    let wrong_profile = if PROFILE.starts_with("lua55") {
        "lua54-i64f64"
    } else {
        "lua55-i64f64"
    };
    let zero_digest = "0".repeat(64);
    let mutations = [
        (
            "wrong-profile",
            "profile",
            wrong_profile,
            "native-grant: profile",
        ),
        (
            "wrong-target",
            "target",
            "x86_64-unknown-linux-gnu",
            "native-grant: target",
        ),
        (
            "wrong-abi",
            "abi_manifest_sha256",
            zero_digest.as_str(),
            "native-grant: abi",
        ),
        (
            "wrong-module-digest",
            "sha256",
            zero_digest.as_str(),
            "native-grant: digest",
        ),
    ];
    let scratch = Scratch::new("invalid-grants");
    let sentinel = scratch.path("guest-started.sentinel");
    let script_path = lua_quote(&sentinel.to_string_lossy());
    let script = format!(
        "local f=assert(io.open({script_path}, \"wb\")); f:write(\"guest started\"); assert(f:close()); os.execute(\"printf P17_GUEST_STARTED\")"
    );
    let lua_path = scratch.path("case.lua");
    fs::write(&lua_path, &script).expect("寫入 preflight side-effect fixture");

    for (label, key, replacement, category) in mutations {
        let mutated = replace_json_string_field(&grant_text, key, replacement);
        let manifest = scratch.path(&format!("{label}.json"));
        fs::write(&manifest, mutated).expect("寫入隔離 mutated grant copy");
        let cli = cli_binary();
        let cli_hash = file_sha256(&cli);
        let source_hash = test_source_sha256();
        let grant_hash = file_sha256(&manifest);
        let stdout_path = scratch.path(&format!("{label}.stdout"));
        let stderr_path = scratch.path(&format!("{label}.stderr"));
        let mut command = Command::new(&cli);
        command
            .arg(&lua_path)
            .current_dir(&scratch.work)
            .env_clear()
            .env_remove("_U")
            .env("TMPDIR", &scratch.work)
            .env("PATH", "/usr/bin:/bin")
            .env("RIVETLUA_NATIVE_MANIFEST", &manifest)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                File::create(&stdout_path).expect("建立 stdout log"),
            ))
            .stderr(Stdio::from(
                File::create(&stderr_path).expect("建立 stderr log"),
            ));
        let argv = format!("{:?}", [cli.as_os_str(), lua_path.as_os_str()]);
        let mut child = command
            .spawn()
            .expect("直接啟動編譯後 rivetlua binary，不經 wrapper");
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait().expect("檢查無效 grant CLI 狀態") {
                break (status, false);
            }
            if started.elapsed() >= CLI_TIMEOUT {
                let _ = child.kill();
                break (child.wait().expect("逾時後等待已終止 CLI"), true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = fs::read_to_string(&stdout_path).expect("讀取 invalid grant stdout");
        let stderr = fs::read_to_string(&stderr_path).expect("讀取 invalid grant stderr");
        let log = evidence_root().join(format!(
            "p17-host-{PROFILE}-{label}-{}-{}.log",
            std::process::id(),
            NEXT_RUN.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(
            &log,
            format!(
                "profile={PROFILE}\nselector=p17_host_invalid_grants_reject_before_guest_side_effects\nprocess_count=1\nmatched=1\nmutation={label}\nargv={argv}\ncwd={}\ncli_sha256={cli_hash}\ntest_source_sha256={source_hash}\nb01_grant={}\nb01_grant_sha256={fixture_sha}\nmutated_grant={}\nmutated_grant_sha256={grant_hash}\nexit_code={:?}\ntimed_out={timed_out}\nstdout={stdout:?}\nstderr={stderr:?}\nexpected_category={category}\nsentinel={}\n",
                scratch.work.display(),
                fixture.grant.display(),
                manifest.display(),
                status.code(),
                sentinel.display()
            ),
        )
        .expect("保存 invalid grant CLI evidence");
        assert!(!timed_out, "{label} preflight 超時，log={}", log.display());
        assert!(!status.success(), "{label} grant 應在 guest 前拒絕");
        assert!(stderr.contains(category), "{label} category 不符：{stderr}");
        assert!(!stdout.contains("P17_GUEST_STARTED"));
        assert!(!sentinel.exists(), "{label} guest side effect 不得發生");
    }
}

#[test]
fn p17_host_os_execute_and_filesystem_lifecycle() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析 B01 grant 路徑");
    let scratch = Scratch::new("os-io");
    let dotted_tmpdir = scratch.path(".dot.tmp");
    fs::create_dir(&dotted_tmpdir).expect("建立含點號且由本測試擁有的 TMPDIR");
    let dotted_tmpdir_env = dotted_tmpdir
        .to_str()
        .expect("測試 TMPDIR 是 UTF-8 路徑")
        .to_owned();
    let data = lua_quote(&scratch.path("data.bin").to_string_lossy());
    let renamed = lua_quote(&scratch.path("renamed.bin").to_string_lossy());
    let missing = lua_quote(&scratch.path("missing.bin").to_string_lossy());
    let gc_path = lua_quote(&scratch.path("gc.bin").to_string_lossy());
    let gc_renamed = lua_quote(&scratch.path("gc-renamed.bin").to_string_lossy());

    let allocate_tmpnames = r#"
local prog = assert(os.tmpname())
print("P17_TMPNAME_PROG=" .. prog)
local other = assert(os.tmpname())
print("P17_TMPNAME_OTHER=" .. other)
"#;
    let allocated = run_lua_with_options(
        "p17_host_tmpname_allocate_paths",
        allocate_tmpnames,
        Some(&grant),
        &[],
        &[("TMPDIR", &dotted_tmpdir_env)],
    );
    let mut caller_tempnames = CallerOwnedTempnames::from_stdout(&allocated.stdout);
    assert_cli_success(&allocated, "tmpname-allocate");
    assert_eq!(caller_tempnames.0.len(), 2, "應只回報兩個 tmpname 路徑");

    let prog_path = caller_tempnames.get("P17_TMPNAME_PROG=").to_path_buf();
    let other_path = caller_tempnames.get("P17_TMPNAME_OTHER=").to_path_buf();
    assert_ne!(prog_path, other_path, "os.tmpname 必須回傳唯一路徑");
    for path in [&prog_path, &other_path] {
        assert_eq!(
            path.parent(),
            Some(Path::new("/tmp")),
            "os.tmpname 必須固定使用 /tmp，即使 TMPDIR 含點號：{}",
            path.display()
        );
        assert!(
            !path.starts_with(&dotted_tmpdir),
            "os.tmpname 不得使用外接且含點號的 TMPDIR：{}",
            path.display()
        );
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("tmpname 回傳 UTF-8 filename");
        assert!(
            !file_name.contains(['.', '-']),
            "os.tmpname filename 不得含點號或連字號：{file_name}"
        );
        let suffix = file_name
            .strip_prefix("rivetlua_")
            .expect("tmpname filename 使用 rivetlua 前綴");
        let (pid, counter) = suffix
            .split_once('_')
            .expect("tmpname filename 含 PID 與 counter");
        assert!(!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()));
        assert!(!counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit()));
        let metadata = fs::metadata(path).expect("tmpname 應先建立可讀 reservation file");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(fs::read(path).expect("讀取 reservation file").is_empty());
    }

    let prog_text = prog_path.to_str().expect("prog path 是 UTF-8");
    let other_text = other_path.to_str().expect("other path 是 UTF-8");
    let prog_source = "print(1); a=2; return {x=15}";
    let other_source = format!("print(a); print(_G[{}].x)", lua_quote(prog_text));
    let write_modules = format!(
        "local prog=assert(io.open({}, \"wb\"))\nassert(prog:write({}))\nassert(prog:close())\nlocal other=assert(io.open({}, \"wb\"))\nassert(other:write({}))\nassert(other:close())\n",
        lua_quote(prog_text),
        lua_quote(prog_source),
        lua_quote(other_text),
        lua_quote(&other_source),
    );
    let prepared = run_lua_with_options(
        "p17_host_tmpname_prepare_modules",
        &write_modules,
        Some(&grant),
        &[],
        &[("TMPDIR", &dotted_tmpdir_env)],
    );
    assert_cli_success(&prepared, "tmpname-prepare");

    let prog_payload = fs::read(&prog_path).expect("讀取 prog payload");
    let other_payload = fs::read(&other_path).expect("讀取 other payload");
    assert_eq!(prog_payload, prog_source.as_bytes());
    assert_eq!(other_payload, other_source.as_bytes());
    let prog_payload_sha_before = sha256(&prog_payload);
    let other_payload_sha_before = sha256(&other_payload);

    let attached_other = format!("-l{other_text}");
    let arguments = [
        "-l",
        prog_text,
        attached_other.as_str(),
        "-lstring",
        "-l",
        "io",
        other_text,
    ];
    let load_environment = [("TMPDIR", dotted_tmpdir_env.as_str()), ("LUA_PATH", "?;;")];
    let loaded = run_cli_input_with_options(
        "p17_host_tmpname_module_paths",
        None,
        Some(&grant),
        &[],
        &arguments,
        &load_environment,
    );
    assert_cli_success(&loaded, "tmpname-module-paths");
    assert_eq!(
        loaded.stdout,
        "1\n2\n15\n2\n15\n",
        "-l 須保留完整 tmpname pathname 作為 global key\nlog={}\nstderr={}",
        loaded.log_path.display(),
        loaded.stderr
    );
    assert!(
        loaded.stderr.is_empty(),
        "unexpected stderr: {}",
        loaded.stderr
    );

    let prog_payload_after = fs::read(&prog_path).expect("讀取 prog payload after CLI");
    let other_payload_after = fs::read(&other_path).expect("讀取 other payload after CLI");
    assert_eq!(sha256(&prog_payload_after), prog_payload_sha_before);
    assert_eq!(sha256(&other_payload_after), other_payload_sha_before);
    assert_eq!(
        fs::metadata(&prog_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&other_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let tmpname_proof = evidence_root().join(format!(
        "p17-host-{PROFILE}-tmpname-module-proof-{}-{}.log",
        std::process::id(),
        NEXT_RUN.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(
        &tmpname_proof,
        format!(
            "profile={PROFILE}\nselector=p17_host_os_execute_and_filesystem_lifecycle\nsubcase_process_count=3\nmatched=1\ntmpdir={dotted_tmpdir_env}\nlua_path=?;;\nprog_path={}\nother_path={}\nprog_payload_sha256_before={prog_payload_sha_before}\nprog_payload_sha256_after={}\nother_payload_sha256_before={other_payload_sha_before}\nother_payload_sha256_after={}\nargv={:?}\nallocate_log={}\nprepare_log={}\nload_log={}\nstdout={:?}\nexit_code={:?}\ncli_sha256={}\ntest_source_sha256={}\ngrant_sha256={}\n",
            prog_path.display(),
            other_path.display(),
            sha256(&prog_payload_after),
            sha256(&other_payload_after),
            arguments,
            allocated.log_path.display(),
            prepared.log_path.display(),
            loaded.log_path.display(),
            loaded.stdout,
            loaded.status.code(),
            file_sha256(&cli_binary()),
            test_source_sha256(),
            file_sha256(&grant),
        ),
    )
    .expect("保存 tmpname 模組載入證據 log");

    caller_tempnames.remove_all();

    let script = format!(
        r#"
assert(_U == nil)
assert(os.execute() == true)
local ok, why, code = os.execute("printf P17_OS_EXEC")
assert(ok == true and why == "exit" and code == 0)
ok, why, code = os.execute("exit 7")
assert(ok == nil and why == "exit" and code == 7)

local temp = os.tmpname()
assert(type(temp) == "string" and string.sub(temp, 1, 14) == "/tmp/rivetlua_")
local temp_file = assert(io.open(temp, "w+b"))
assert(temp_file:write("tmpname"))
assert(temp_file:flush())
assert(temp_file:seek("set", 0) == 0)
assert(temp_file:read("*a") == "tmpname")
assert(temp_file:close() == true)
assert(os.remove(temp) == true)

local anonymous = assert(io.tmpfile())
assert(anonymous:write("anonymous"))
assert(anonymous:seek("set", 0) == 0)
assert(anonymous:read("*a") == "anonymous")
assert(anonymous:close() == true)

local f = assert(io.open({data}, "w+b"))
assert(f:write("A\0B\n123\nend"))
assert(f:flush())
assert(f:seek("set", 0) == 0)
assert(f:read(3) == "A\0B")
assert(f:read("*L") == "\n")
assert(f:read("*n") == 123)
assert(f:read(1) == "\n")
assert(f:read("*l") == "end")
assert(f:read("*l") == nil)
assert(f:seek("end", -3) == 8)
assert(f:read("*a") == "end")
assert(f:read("*a") == "")
assert(f:close() == true)
local closed_ok, closed_error = pcall(f.close, f)
assert(not closed_ok and type(closed_error) == "string" and string.find(closed_error, "E_IO_CLOSED", 1, true))
local read_closed_ok, read_closed_error = pcall(f.read, f, "*a")
assert(not read_closed_ok and type(read_closed_error) == "string" and string.find(read_closed_error, "E_IO_CLOSED", 1, true))

local mode_ok, mode_error = pcall(io.open, {data}, "q")
assert(not mode_ok and type(mode_error) == "string")
local absent, absent_error, absent_errno = io.open({missing}, "rb")
assert(absent == nil and type(absent_error) == "string" and type(absent_errno) == "number" and absent_errno ~= 0)

assert(os.rename({data}, {renamed}) == true)
local moved = assert(io.open({renamed}, "rb"))
assert(moved:read("*a") == "A\0B\n123\nend")
assert(moved:close() == true)
assert(os.remove({renamed}) == true)
local remove_ok, remove_error, remove_errno = os.remove({missing})
assert(remove_ok == nil and type(remove_error) == "string" and type(remove_errno) == "number" and remove_errno ~= 0)
local rename_ok, rename_error, rename_errno = os.rename({missing}, {renamed})
assert(rename_ok == nil and type(rename_error) == "string" and type(rename_errno) == "number" and rename_errno ~= 0)

do
  local gc_file = assert(io.open({gc_path}, "wb"))
  assert(gc_file:write("GC lifecycle"))
end
collectgarbage("collect")
assert(os.rename({gc_path}, {gc_renamed}) == true)
assert(os.remove({gc_renamed}) == true)
print("P17_HOST_OS_IO PASS")
"#,
        data = data,
        renamed = renamed,
        missing = missing,
        gc_path = gc_path,
        gc_renamed = gc_renamed,
    );
    let result = run_lua(
        "p17_host_os_execute_and_filesystem_lifecycle",
        &script,
        Some(&grant),
        &[],
    );
    assert_cli_success(&result, "os-io");
    assert!(result.stdout.contains("P17_OS_EXEC"));
    assert!(result.stdout.contains("P17_HOST_OS_IO"));
}

#[test]
fn p17_host_stdio_and_popen_status_cleanup() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析 B01 grant 路徑");
    let script = r#"
assert(_U == nil)
local input = io.stdin:read("*a")
assert(input == "P17_STDIN\n")
assert(io.stdin:read("*a") == "")
assert(io.stdout:write("P17_STDOUT\n"))
assert(io.stdout:flush())
assert(io.stderr:write("P17_STDERR\n"))
assert(io.stderr:flush())

local read_pipe = assert(io.popen("printf P17_POPEN_READ", "r"))
assert(read_pipe:read("*a") == "P17_POPEN_READ")
local ok, why, code = read_pipe:close()
assert(ok == true and why == "exit" and code == 0)

local write_pipe = assert(io.popen("cat", "w"))
assert(write_pipe:write("P17_POPEN_WRITE\n"))
assert(write_pipe:flush())
ok, why, code = write_pipe:close()
assert(ok == true and why == "exit" and code == 0)

local failed_pipe = assert(io.popen("exit 7", "r"))
assert(failed_pipe:read("*a") == "")
ok, why, code = failed_pipe:close()
assert(ok == nil and why == "exit" and code == 7)

local signaled_pipe = assert(io.popen("kill -TERM $$", "r"))
assert(signaled_pipe:read("*a") == "")
ok, why, code = signaled_pipe:close()
assert(ok == nil and why == "signal" and code > 0)
print("P17_HOST_STDIO_POPEN PASS")
"#;
    let result = run_lua(
        "p17_host_stdio_and_popen_status_cleanup",
        script,
        Some(&grant),
        b"P17_STDIN\n",
    );
    assert_cli_success(&result, "stdio-popen");
    assert!(result.stdout.contains("P17_STDOUT\n"));
    assert!(result.stdout.contains("P17_POPEN_WRITE\n"));
    assert!(result.stderr.contains("P17_STDERR\n"));
    assert!(result.stdout.contains("P17_HOST_STDIO_POPEN"));

    let debug_write_and_cont = run_cli_input_with_options(
        "p17_debug_console_stderr_write_and_cont",
        None,
        Some(&grant),
        b"io.stderr:write(1000)\ncont\n",
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(&debug_write_and_cont, "debug console stderr write and cont");
    assert!(debug_write_and_cont.stdout.is_empty());
    assert_eq!(debug_write_and_cont.stderr, "lua_debug> 1000lua_debug> ");

    let debug_error_recovery = run_cli_input_with_options(
        "p17_debug_console_error_recovery",
        None,
        Some(&grant),
        b"local =\nerror('P17_DEBUG_RUNTIME_FAILURE')\n_G.P17_DEBUG_RECOVERED = true\ncont\n",
        &[
            "-e",
            "require('debug').debug()",
            "-e",
            "assert(_G.P17_DEBUG_RECOVERED == true)",
        ],
        &[],
    );
    assert_cli_success(&debug_error_recovery, "debug console error recovery");
    assert!(debug_error_recovery.stdout.is_empty());
    let recovery_segments = debug_error_recovery
        .stderr
        .split("lua_debug> ")
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(recovery_segments.len(), 4);
    assert!(!recovery_segments[0].trim().is_empty());
    assert!(recovery_segments[0].ends_with('\n'));
    assert!(recovery_segments[1].contains("(debug command):1:"));
    assert!(recovery_segments[1].contains("P17_DEBUG_RUNTIME_FAILURE"));
    assert!(recovery_segments[2].is_empty() && recovery_segments[3].is_empty());

    let debug_empty_eof = run_cli_input_with_options(
        "p17_debug_console_empty_eof",
        None,
        Some(&grant),
        b"",
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(&debug_empty_eof, "debug console empty EOF");
    assert!(debug_empty_eof.stdout.is_empty());
    assert_eq!(debug_empty_eof.stderr, "lua_debug> ");

    let debug_partial_eof = run_cli_input_with_options(
        "p17_debug_console_partial_eof_executes",
        None,
        Some(&grant),
        b"io.stderr:write('P17_DEBUG_PARTIAL_EOF')",
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(&debug_partial_eof, "debug console partial EOF");
    assert!(debug_partial_eof.stdout.is_empty());
    assert_eq!(
        debug_partial_eof.stderr,
        "lua_debug> P17_DEBUG_PARTIAL_EOFlua_debug> "
    );

    let debug_cont_without_newline = run_cli_input_with_options(
        "p17_debug_console_cont_without_newline_is_command",
        None,
        Some(&grant),
        b"cont",
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(
        &debug_cont_without_newline,
        "debug console bare cont command",
    );
    assert!(debug_cont_without_newline.stdout.is_empty());
    let bare_cont_segments = debug_cont_without_newline
        .stderr
        .split("lua_debug> ")
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(bare_cont_segments.len(), 2);
    assert!(!bare_cont_segments[0].trim().is_empty());
    assert!(bare_cont_segments[0].ends_with('\n'));
    assert!(bare_cont_segments[1].is_empty());

    let mut debug_line_boundary = b"io.stderr:write('P17_DEBUG_249')".to_vec();
    debug_line_boundary.resize(249, b' ');
    debug_line_boundary.extend_from_slice(b"\nio.stderr:write('P17_DEBUG_AFTER_SPLIT')\ncont\n");
    let debug_line_chunking = run_cli_input_with_options(
        "p17_debug_console_249_byte_fgets_boundary",
        None,
        Some(&grant),
        &debug_line_boundary,
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(&debug_line_chunking, "debug console 249-byte boundary");
    assert!(debug_line_chunking.stdout.is_empty());
    assert_eq!(
        debug_line_chunking.stderr,
        "lua_debug> P17_DEBUG_249lua_debug> lua_debug> P17_DEBUG_AFTER_SPLITlua_debug> "
    );

    let debug_nul_prefix = run_cli_input_with_options(
        "p17_debug_console_nul_terminates_command",
        None,
        Some(&grant),
        b"io.stderr:write('P17_DEBUG_NUL_PREFIX')\0;io.stderr:write('P17_DEBUG_NUL_SUFFIX')\ncont\n",
        &["-e", "require('debug').debug()"],
        &[],
    );
    assert_cli_success(&debug_nul_prefix, "debug console NUL truncation");
    assert!(debug_nul_prefix.stdout.is_empty());
    assert_eq!(
        debug_nul_prefix.stderr,
        "lua_debug> P17_DEBUG_NUL_PREFIXlua_debug> "
    );

    let debug_shared_scope = run_cli_input_with_options(
        "p17_debug_console_shared_globals_c_scope_and_discarded_returns",
        None,
        Some(&grant),
        b"_G.P17_DEBUG_SHARED = 'updated'; assert(caller_local == nil and probe == nil and debugfn == nil); return 1,nil,3\ncont\n",
        &[
            "-e",
            "local caller_local = 'private'; local fn = require('debug').debug; local info = debug.getinfo(fn, 'Su'); assert(info.what == 'C' and info.nups == 0); local isolated = { debugfn = fn, probe = 5 }; local caller = assert(load('debugfn()', '=console-isolated-caller', 't', isolated)); assert(select('#', caller()) == 0); assert(caller_local == 'private' and _G.P17_DEBUG_SHARED == 'updated'); assert(isolated.probe == 5 and isolated.debugfn == fn)",
        ],
        &[],
    );
    assert_cli_success(
        &debug_shared_scope,
        "debug console shared globals and C identity",
    );
    assert!(debug_shared_scope.stdout.is_empty());
    assert_eq!(debug_shared_scope.stderr, "lua_debug> lua_debug> ");

    let debug_init =
        "local fn = require('debug').debug; io = nil; pcall = nil; load = nil; _P17_DEBUG_FN = fn";
    let debug_survives_guest_globals = run_cli_input_with_options(
        "p17_debug_console_survives_mutated_guest_globals",
        None,
        Some(&grant),
        b"_G.P17_DEBUG_CORE_ALIVE = true\ncont\n",
        &[
            "-e",
            "_P17_DEBUG_FN()",
            "-e",
            "assert(_G.P17_DEBUG_CORE_ALIVE == true)",
        ],
        &[("LUA_INIT", debug_init)],
    );
    assert_cli_success(
        &debug_survives_guest_globals,
        "debug console with mutated guest globals",
    );
    assert!(debug_survives_guest_globals.stdout.is_empty());
    assert_eq!(
        debug_survives_guest_globals.stderr,
        "lua_debug> lua_debug> "
    );

    let module =
        fs::canonicalize(fixture.modules.join("lib1.so")).expect("解析唯讀 B01 lib1.so 路徑");
    let native_debug_setup = format!(
        "local opener = assert(package.loadlib({}, 'luaopen_lib1_sub')); local native_module = assert(opener('lib1.sub', {})); _P17_DEBUG_NATIVE_ID = native_module.id; require('debug').debug()",
        lua_quote(&module.to_string_lossy()),
        lua_quote(&module.to_string_lossy())
    );
    let debug_native_callback = run_cli_input_with_options(
        "p17_debug_console_native_callback",
        None,
        Some(&grant),
        b"_G.P17_DEBUG_NATIVE_RESULT = _P17_DEBUG_NATIVE_ID('P17_NATIVE_DEBUG_ID')\ncont\n",
        &[
            "-e",
            native_debug_setup.as_str(),
            "-e",
            "assert(rawequal(_G.P17_DEBUG_NATIVE_RESULT, 'P17_NATIVE_DEBUG_ID'))",
        ],
        &[],
    );
    assert_cli_success(&debug_native_callback, "debug console native callback");
    assert!(debug_native_callback.stdout.is_empty());
    assert_eq!(debug_native_callback.stderr, "lua_debug> lua_debug> ");
}

#[test]
fn p17_host_official_native_module_effects_remain_available() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析唯讀 B01 grant");
    let modules = lua_quote(&fixture.modules.to_string_lossy());

    let default_cpath = format!("{}/?.so", fixture.modules.display());
    let default_cpath_script = format!(
        "assert(package.cpath == {})\nprint(package.cpath)\n",
        lua_quote(&default_cpath)
    );
    let generic_cpath = run_lua_with_options(
        "p17_host_cpath_generic_env",
        "assert(package.cpath == \"xuxu\")\nprint(package.cpath)\n",
        Some(&grant),
        &[],
        &[("LUA_CPATH", "xuxu")],
    );
    assert_cli_success(&generic_cpath, "generic LUA_CPATH");
    assert_eq!(generic_cpath.stdout, "xuxu\n");

    let versioned_cpath_env = if PROFILE.starts_with("lua55") {
        "LUA_CPATH_5_5"
    } else {
        "LUA_CPATH_5_4"
    };
    let versioned_cpath = run_lua_with_options(
        "p17_host_cpath_versioned_precedence",
        "assert(package.cpath == \"yacc\")\nprint(package.cpath)\n",
        Some(&grant),
        &[],
        &[(versioned_cpath_env, "yacc"), ("LUA_CPATH", "genericx")],
    );
    assert_cli_success(&versioned_cpath, "versioned LUA_CPATH precedence");
    assert_eq!(versioned_cpath.stdout, "yacc\n");

    let ignored_environment = run_lua_with_options(
        "p17_host_cpath_ignore_environment",
        &default_cpath_script,
        Some(&grant),
        &["-E"],
        &[(versioned_cpath_env, "yacc"), ("LUA_CPATH", "genericx")],
    );
    assert_cli_success(&ignored_environment, "-E CPath default");
    assert_eq!(ignored_environment.stdout, format!("{default_cpath}\n"));

    let expanded_cpath = format!("X;{default_cpath};Y");
    let separator_expansion_script = format!(
        "assert(package.cpath == {})\nprint(package.cpath)\n",
        lua_quote(&expanded_cpath)
    );
    let separator_expansion = run_lua_with_options(
        "p17_host_cpath_default_separator_expansion",
        &separator_expansion_script,
        Some(&grant),
        &[],
        &[("LUA_CPATH", "X;;Y")],
    );
    assert_cli_success(&separator_expansion, "LUA_CPATH ;; expansion");
    assert_eq!(separator_expansion.stdout, format!("{expanded_cpath}\n"));

    let unlisted = Scratch::new("cpath-unlisted-module");
    let unlisted_directory = unlisted.path("modules");
    fs::create_dir_all(&unlisted_directory).expect("建立隔離的未授權 module 目錄");
    let listed_module = fixture.modules.join("lib1.so");
    let unlisted_module = unlisted_directory.join("lib1.so");
    fs::copy(&listed_module, &unlisted_module).expect("複製同 bytes module 到新路徑");
    assert_eq!(
        file_sha256(&listed_module),
        file_sha256(&unlisted_module),
        "未授權路徑 fixture 必須保留原 module bytes"
    );
    let listed_module = fs::canonicalize(listed_module).expect("解析已授權 module 路徑");
    let unlisted_module = fs::canonicalize(unlisted_module).expect("解析未授權 module 路徑");
    assert_ne!(listed_module, unlisted_module);
    let unlisted_cpath = format!("{}/?.so", unlisted_directory.display());
    let unlisted_script = format!(
        r#"
local opener, message, when = package.loadlib({}, "luaopen_lib1_sub")
assert(
  opener == nil and type(message) == "string" and when == "open",
  "未授權 package.loadlib 必須回傳 nil、診斷字串與 open stage"
)
assert(
  message == "native 候選路徑不在 grant 白名單",
  "未授權 package.loadlib 診斷不符：" .. tostring(message)
)
local ok, err = pcall(require, "lib1")
assert(not ok and type(err) == "string", "require 不得載入未授權 module")
assert(
  string.find(err, "native 候選路徑不在 grant 白名單", 1, true),
  "require 未保留未授權路徑診斷：" .. tostring(err)
)
print("P17_HOST_CPATH_UNLISTED_BLOCKED {PROFILE} PASS")
"#,
        lua_quote(&unlisted_module.to_string_lossy()),
        PROFILE = PROFILE,
    );
    let unlisted_result = run_lua_with_options(
        "p17_host_cpath_unlisted_module_rejected",
        &unlisted_script,
        Some(&grant),
        &[],
        &[("LUA_CPATH", &unlisted_cpath)],
    );
    assert_cli_success(&unlisted_result, "unlisted CPath module");
    assert!(
        unlisted_result
            .stdout
            .contains("P17_HOST_CPATH_UNLISTED_BLOCKED")
    );

    let script = format!(
        r#"
assert(_U == nil)
package.cpath = {modules} .. "/?.so"
local one = assert(package.loadlib({modules} .. "/lib1.so", "onefunction"))
local first, second = one(15, 25)
assert(first == 25 and second == 15)
local another = assert(package.loadlib({modules} .. "/lib1.so", "anotherfunc"))
assert(another(10, 20) == "10%20\n")

local lib2 = assert(require("lib2"))
assert(package.loaded.lib2 == lib2)
assert(_G.x == "lib2" and _G.y == {modules} .. "/lib2.so")
local left, right = lib2.id("left", "right")
assert(left == "left" and right == "right")
local lib1, filename = assert(require("lib1.sub"))
assert(package.loaded["lib1.sub"] == lib1)
assert(filename == {modules} .. "/lib1.so")
assert(_G.x == "lib1.sub" and _G.y == filename)
assert(lib1.id(45) == 45)
print("P17_HOST_NATIVE_MODULES {PROFILE} PASS")
"#,
        modules = modules,
        PROFILE = PROFILE,
    );
    let result = run_lua(
        "p17_host_official_native_module_effects_remain_available",
        &script,
        Some(&grant),
        &[],
    );
    assert_cli_success(&result, "native-modules");
    assert!(result.stdout.contains("P17_HOST_NATIVE_MODULES"));
}
