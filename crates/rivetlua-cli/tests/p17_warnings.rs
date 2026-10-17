#![cfg(all(unix, any(feature = "native-lua55", feature = "native-lua54")))]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("P17 warning 每個測試 binary 只能選一個 Lua ABI profile");

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rivetlua_capi::abi::{self, AbiIdentity};

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
        let root = evidence_root();
        fs::create_dir_all(&root).expect("建立 P17 warning evidence 根目錄");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let dir = root.join(format!(
            "p17-warning-{PROFILE}-{label}-{}-{sequence}-{stamp}",
            std::process::id()
        ));
        let work = dir.join("work");
        fs::create_dir_all(&work).expect("建立隔離 warning CLI 工作目錄");
        Self { root: dir, work }
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
}

struct CliResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    log_path: PathBuf,
}

struct WarningProbeFixture {
    grant: PathBuf,
    cpath: String,
}

fn evidence_root() -> PathBuf {
    let root = env::var_os("RIVETLUA_P17_EVIDENCE_DIR")
        .map(PathBuf::from)
        .expect("P17 runner 必須指定外部 evidence 目錄");
    assert!(root.is_absolute(), "P17 evidence 目錄必須是絕對路徑");
    root
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
        .join("p17_warnings.rs");
    file_sha256(&path)
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
    B01Fixture { grant }
}

fn cli_binary() -> PathBuf {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_rivetlua"))
        .canonicalize()
        .expect("Cargo 提供的編譯後 rivetlua binary 存在");
    let metadata = fs::metadata(&binary).expect("讀取 rivetlua binary metadata");
    assert!(metadata.is_file(), "CLI 必須是可執行檔，不可使用 wrapper");
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "Cargo CLI artifact 必須具有 executable 權限"
    );
    binary
}

fn immutable_log_path(label: &str) -> (PathBuf, File) {
    let directory = evidence_root().join("p17-warning-regressions");
    fs::create_dir_all(&directory).expect("建立 P17 warning regression evidence 目錄");
    loop {
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let path = directory.join(format!(
            "p17-warning-{PROFILE}-{label}-{}-{sequence}-{stamp}.log",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return (path, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("建立不可覆寫 warning evidence log 失敗：{error}"),
        }
    }
}

fn run_cli(
    label: &str,
    source: &str,
    grant: Option<&Path>,
    arguments: &[&str],
    extra_env: &[(&str, &str)],
) -> CliResult {
    let scratch = Scratch::new(label);
    let script = scratch.path("case.lua");
    fs::write(&script, source.as_bytes()).expect("寫入隔離 warning Lua case");

    let cli = cli_binary();
    let cli_hash = file_sha256(&cli);
    let source_hash = test_source_sha256();
    let grant_hash = grant.map(file_sha256);
    let stdout_path = scratch.path("stdout.log");
    let stderr_path = scratch.path("stderr.log");

    // 直接啟動 Cargo 編譯出的 RivetLua CLI；沒有 shell、測試 oracle 或除錯器 helper。
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
        ))
        .stdin(Stdio::null());
    command.args(arguments.iter().copied()).arg(&script);
    for (key, value) in extra_env {
        command.env(*key, *value);
    }
    if let Some(grant) = grant {
        command.env("RIVETLUA_NATIVE_MANIFEST", grant);
    } else {
        command.env_remove("RIVETLUA_NATIVE_MANIFEST");
    }

    let mut argv_items = Vec::with_capacity(2 + arguments.len());
    argv_items.push(cli.as_os_str().to_owned());
    argv_items.extend(arguments.iter().map(|argument| OsString::from(*argument)));
    argv_items.push(script.as_os_str().to_owned());
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

    let (log_path, mut log) = immutable_log_path(label);
    let stdout_text = String::from_utf8_lossy(&stdout);
    let stderr_text = String::from_utf8_lossy(&stderr);
    writeln!(
        log,
        "schema=rivetlua-p17-warning-child-v1\nprofile={PROFILE}\nselector={label}\nprocess_count=1\nmatched=1\nargv={argv}\ncwd={}\nenv_clear=true\nPATH=/usr/bin:/bin\nTMPDIR={}\nextra_env={extra_env:?}\ncli={}\ncli_sha256={cli_hash}\ntest_source_sha256={source_hash}\ngrant={}\ngrant_sha256={}\ntimeout_seconds={}\ntimed_out={timed_out}\nexit_code={:?}\nstdout={stdout_text:?}\nstderr={stderr_text:?}\nsource_sha256={}\nsource={source:?}",
        scratch.work.display(),
        scratch.work.display(),
        cli.display(),
        grant.map_or_else(|| "<unset>".to_owned(), |path| path.display().to_string()),
        grant_hash.as_deref().unwrap_or("<none>"),
        CLI_TIMEOUT.as_secs(),
        status.code(),
        sha256(source.as_bytes()),
    )
    .expect("寫入 warning child evidence");

    CliResult {
        status,
        stdout,
        stderr,
        timed_out,
        log_path,
    }
}

fn assert_success_exact(
    result: &CliResult,
    expected_stdout: &[u8],
    expected_stderr: &[u8],
    label: &str,
) {
    assert!(
        !result.timed_out,
        "{label} CLI 超過 {:?}; log={}",
        CLI_TIMEOUT,
        result.log_path.display()
    );
    assert!(
        result.status.success(),
        "{label} CLI 失敗，exit={:?}\nstdout={:?}\nstderr={:?}\nlog={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
        result.log_path.display()
    );
    assert_eq!(
        result.stdout.as_slice(),
        expected_stdout,
        "{label} stdout 不符；stderr={:?}; log={}",
        String::from_utf8_lossy(&result.stderr),
        result.log_path.display()
    );
    assert_eq!(
        result.stderr.as_slice(),
        expected_stderr,
        "{label} stderr 不符；stdout={:?}; log={}",
        String::from_utf8_lossy(&result.stdout),
        result.log_path.display()
    );
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn target_string(target: &[u8]) -> String {
    let end = target
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(target.len());
    String::from_utf8(target[..end].to_vec()).expect("ABI target 是 UTF-8")
}

fn abi_identity_json(identity: AbiIdentity) -> String {
    let layout = identity
        .layout
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"revision\":{},\"profile_id\":{},\"numeric_config\":{},\"pointer_width_bits\":{},\"endianness\":{},\"reserved_zero\":{},\"target\":{},\"header_set_sha256\":{},\"lua_h_sha256\":{},\"lauxlib_h_sha256\":{},\"luaconf_h_sha256\":{},\"layout\":[{}]}}",
        identity.revision,
        identity.profile,
        identity.numeric_config,
        identity.pointer_width_bits,
        identity.endianness,
        identity.reserved_zero,
        json_string(&target_string(&identity.target)),
        json_string(&hex_bytes(&identity.header_set_sha256)),
        json_string(&hex_bytes(&identity.lua_h_sha256)),
        json_string(&hex_bytes(&identity.lauxlib_h_sha256)),
        json_string(&hex_bytes(&identity.luaconf_h_sha256)),
        layout,
    )
}

fn create_external_run_dir(label: &str) -> PathBuf {
    let evidence = evidence_root();
    fs::create_dir_all(&evidence).expect("建立 P17 warning evidence 根目錄");
    loop {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let path = evidence.join(format!(
            "p17-warning-native-{PROFILE}-{label}-{}-{sequence}-{stamp}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("建立不可重用的 native warning fixture 目錄失敗：{error}"),
        }
    }
}

fn warning_probe_grant_json(repo: &Path, binary: &Path, source: &Path, cpath: &Path) -> String {
    let identity = abi::current_identity();
    let target = target_string(&identity.target);
    let header_binding = hex_bytes(&identity.header_set_sha256);
    let abi_manifest_sha256 = file_sha256(&repo.join("tests/p16/abi-manifest.toml"));
    let binary_sha256 = file_sha256(binary);
    let source_sha256 = file_sha256(source);
    format!(
        "{{\"schema\":\"rivetlua-native-grant-v1\",\"profile\":{},\"target\":{},\"abi_manifest_sha256\":{},\"capability\":\"trusted-host-process-permissions-v1\",\"cpath\":[{}],\"modules\":[{{\"canonical_path\":{},\"sha256\":{},\"source_sha256\":{},\"header_binding\":{},\"abi_identity\":{},\"unwind\":\"CNoUnwind\",\"exports\":[\"luaopen_p17_warning_probe\"],\"visibility\":\"local\",\"dependencies\":[]}}]}}\n",
        json_string(PROFILE),
        json_string(&target),
        json_string(&abi_manifest_sha256),
        json_string(&cpath.display().to_string()),
        json_string(
            &binary
                .canonicalize()
                .expect("module binary canonicalize")
                .display()
                .to_string()
        ),
        json_string(&binary_sha256),
        json_string(&source_sha256),
        json_string(&header_binding),
        abi_identity_json(identity),
    )
}

fn warning_probe_fixture() -> WarningProbeFixture {
    const MACOS_CLANG: &str = "/Library/Developer/CommandLineTools/usr/bin/clang";
    const MACOS_CLANG_SHA256: &str =
        "1590ac950a3d627817d09ade5cb60b2115f17a72182a3141e010b4bcc482a0c9";
    const MACOS_LD: &str = "/Library/Developer/CommandLineTools/usr/bin/ld";
    const MACOS_LD_SHA256: &str =
        "374d9f0713bce2c8a9e1e82bde51615d5433516a10d99b63107eb6ee70542e4c";
    const MACOS_SDKROOT: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk";

    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root 存在");
    let root = create_external_run_dir("callback");
    let libs = root.join("libs");
    fs::create_dir(&libs).expect("建立專屬 warning module 目錄");
    let source = repo.join("tests/p17/native-fixtures/warning_probe.c");
    let binary = libs.join("p17_warning_probe.so");
    assert!(source.is_file(), "C warning fixture 存在");
    assert!(!binary.exists(), "module output 必須是尚不存在的新路徑");

    let include_profile = repo.join(match PROFILE {
        "lua55-i64f64" => "include/rivetlua/lua55",
        _ => "include/rivetlua/lua54",
    });
    let common_include = repo.join("include/rivetlua");
    let compile_tmp = root.join("tmp");
    fs::create_dir(&compile_tmp).expect("建立專屬 C build 暫存目錄");

    let program = if cfg!(target_os = "macos") {
        let clang = PathBuf::from(MACOS_CLANG);
        let linker = PathBuf::from(MACOS_LD);
        let sdkroot = PathBuf::from(MACOS_SDKROOT);
        assert!(
            clang.is_file(),
            "固定 macOS clang 不存在：{}",
            clang.display()
        );
        assert!(
            linker.is_file(),
            "固定 macOS linker 不存在：{}",
            linker.display()
        );
        assert!(
            sdkroot.is_dir(),
            "固定 macOS SDK 不存在：{}",
            sdkroot.display()
        );
        assert_eq!(
            sdkroot.canonicalize().expect("解析固定 macOS SDK 路徑"),
            sdkroot,
            "macOS SDK 必須是指定的實體路徑"
        );
        assert_eq!(
            file_sha256(&clang),
            MACOS_CLANG_SHA256,
            "固定 macOS clang SHA-256 不符"
        );
        assert_eq!(
            file_sha256(&linker),
            MACOS_LD_SHA256,
            "固定 macOS linker SHA-256 不符"
        );
        clang
    } else {
        PathBuf::from("/usr/bin/cc")
    };

    let mut args = vec![
        "-std=c11".to_owned(),
        "-Wall".to_owned(),
        "-Wextra".to_owned(),
        "-Werror".to_owned(),
        "-fPIC".to_owned(),
    ];
    if cfg!(target_os = "macos") {
        args.extend([
            format!("--ld-path={MACOS_LD}"),
            "-dynamiclib".to_owned(),
            "-undefined".to_owned(),
            "dynamic_lookup".to_owned(),
        ]);
    } else {
        args.push("-shared".to_owned());
    }
    args.extend([
        "-I".to_owned(),
        include_profile.display().to_string(),
        "-I".to_owned(),
        common_include.display().to_string(),
        source.display().to_string(),
        "-o".to_owned(),
        binary.display().to_string(),
    ]);

    // 僅傳明列的編譯環境；所有值都寫入同一筆不可覆寫 build evidence。
    let mut explicit_env = vec![
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("TMPDIR".to_owned(), compile_tmp.display().to_string()),
        ("LLVM_DISABLE_SYMBOLIZATION".to_owned(), "1".to_owned()),
        ("RUST_BACKTRACE".to_owned(), "0".to_owned()),
    ];
    if cfg!(target_os = "macos") {
        explicit_env.push(("SDKROOT".to_owned(), MACOS_SDKROOT.to_owned()));
        explicit_env.push(("MACOSX_DEPLOYMENT_TARGET".to_owned(), "11.0".to_owned()));
    } else {
        for key in ["SDKROOT", "DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET"] {
            if let Some(value) = env::var_os(key) {
                explicit_env.push((key.to_owned(), value.to_string_lossy().into_owned()));
            }
        }
    }
    let mut command = Command::new(&program);
    command.current_dir(&repo).env_clear().args(&args);
    for (key, value) in &explicit_env {
        command.env(key, value);
    }
    let result = command.output();
    let (exit_code, compile_success, stdout, stderr, spawn_error) = match result {
        Ok(output) => (
            output.status.code(),
            Some(output.status.success()),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            None,
        ),
        Err(error) => (
            None,
            None,
            String::new(),
            String::new(),
            Some(error.to_string()),
        ),
    };
    let source_sha256 = file_sha256(&source);
    let binary_sha256 = binary.is_file().then(|| file_sha256(&binary));
    let cpath = libs.join("?.so");
    let grant = root.join("warning-native-grant.json");
    let mut grant_error = None;
    let grant_sha256 = if compile_success == Some(true) && binary_sha256.is_some() {
        let result = (|| {
            let grant_bytes = warning_probe_grant_json(&repo, &binary, &source, &cpath);
            let mut grant_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&grant)
                .map_err(|error| error.to_string())?;
            grant_file
                .write_all(grant_bytes.as_bytes())
                .map_err(|error| error.to_string())?;
            grant_file.flush().map_err(|error| error.to_string())?;
            Ok::<String, String>(file_sha256(&grant))
        })();
        match result {
            Ok(digest) => Some(digest),
            Err(error) => {
                grant_error = Some(error);
                None
            }
        }
    } else {
        None
    };
    let binary_path = if binary.exists() {
        binary.canonicalize().expect("module binary canonicalize")
    } else {
        binary.clone()
    };
    let grant_path = if grant.exists() {
        grant.canonicalize().expect("grant canonicalize")
    } else {
        grant.clone()
    };
    let args_json = args
        .iter()
        .map(|argument| json_string(argument))
        .collect::<Vec<_>>()
        .join(",");
    let env_json = explicit_env
        .iter()
        .map(|(key, value)| format!("{}:{}", json_string(key), json_string(value)))
        .collect::<Vec<_>>()
        .join(",");
    let identity = abi::current_identity();
    let identity_json = abi_identity_json(identity);
    let exit_code_json = exit_code.map_or_else(|| "null".to_owned(), |code| code.to_string());
    let compile_success_json =
        compile_success.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let spawn_error_json = spawn_error
        .as_deref()
        .map_or_else(|| "null".to_owned(), json_string);
    let program_name = program.display().to_string();
    let grant_error_json = grant_error
        .as_deref()
        .map_or_else(|| "null".to_owned(), json_string);
    let binary_sha_json = binary_sha256
        .as_deref()
        .map_or_else(|| "null".to_owned(), json_string);
    let grant_sha_json = grant_sha256
        .as_deref()
        .map_or_else(|| "null".to_owned(), json_string);
    let record = format!(
        "{{\"schema\":\"rivetlua-p17-warning-native-build-v1\",\"profile\":{},\"header_identity\":{},\"program\":{},\"args\":[{}],\"cwd\":{},\"stdin\":\"null\",\"env_clear\":true,\"explicit_env\":{{{}}},\"exit_code\":{},\"compile_success\":{},\"spawn_error\":{},\"stdout\":{},\"stderr\":{},\"source_path\":{},\"source_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"grant_path\":{},\"grant_sha256\":{},\"grant_error\":{}}}\n",
        json_string(PROFILE),
        identity_json,
        json_string(&program_name),
        args_json,
        json_string(&repo.display().to_string()),
        env_json,
        exit_code_json,
        compile_success_json,
        spawn_error_json,
        json_string(&stdout),
        json_string(&stderr),
        json_string(&source.display().to_string()),
        json_string(&source_sha256),
        json_string(&binary_path.display().to_string()),
        binary_sha_json,
        json_string(&grant_path.display().to_string()),
        grant_sha_json,
        grant_error_json,
    );
    let build_log = root.join("warning-probe-build.json");
    let mut build_log_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&build_log)
        .expect("以 create_new 建立不可覆寫 C build evidence");
    build_log_file
        .write_all(record.as_bytes())
        .expect("寫入 C build evidence");
    build_log_file.flush().expect("flush C build evidence");
    println!(
        "P17_WARNING_NATIVE_BUILD profile={PROFILE} log={} sha256={}",
        build_log.display(),
        file_sha256(&build_log)
    );
    assert!(
        compile_success == Some(true) && binary_sha256.is_some() && grant_sha256.is_some(),
        "warning_probe.c 編譯或 grant 建立失敗：exit={exit_code:?} spawn_error={spawn_error:?} grant_error={grant_error:?}\nstdout={stdout}\nstderr={stderr}\nlog={}",
        build_log.display(),
    );
    let binary = binary.canonicalize().expect("module binary canonicalize");

    WarningProbeFixture {
        grant: grant.canonicalize().expect("grant canonicalize"),
        cpath: cpath.display().to_string(),
    }
}

#[test]
fn p17_warning_cli_basic() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析唯讀 B01 grant");

    let default_off = run_cli(
        "p17_warning_cli_basic_default_off",
        "assert(type(warn) == 'function'); assert(select('#', warn('suppressed')) == 0); io.stdout:write('default-off\\n')",
        Some(&grant),
        &[],
        &[],
    );
    assert_success_exact(&default_off, b"default-off\n", b"", "warning 預設關閉");

    let control_and_formatting = run_cli(
        "p17_warning_cli_basic_control_and_formatting",
        r#"assert(type(warn) == 'function')
assert(select('#', warn("number=", 42, 3.5)) == 0)
assert(select('#', warn("nul\0hidden")) == 0)
warn("@unknown")
warn("@off", "XXX", "@off")
warn("@off")
warn("@on", "YYY", "@on")
warn("@off")
warn("@on")
warn("", "@on")
warn("@on")
warn("@off")
warn("hidden")
warn("@on")
warn("@on", "multi")
warn("Z", "Z", "Z")
io.stdout:write("control-format-ok\n")"#,
        Some(&grant),
        &["-W"],
        &[],
    );
    assert_success_exact(
        &control_and_formatting,
        b"control-format-ok\n",
        b"Lua warning: number=423.5\nLua warning: nul\nLua warning: @offXXX@off\nLua warning: @on\nLua warning: @onmulti\nLua warning: ZZZ\n",
        "warning 參數、NUL 與控制字串",
    );

    let invalid_arguments = run_cli(
        "p17_warning_cli_basic_invalid_arguments",
        r#"local tostring_calls = 0
local bad = setmetatable({}, {
  __tostring = function()
    tostring_calls = tostring_calls + 1
    return "must-not-be-stringified"
  end,
})
local invalid = {
  function() return pcall(warn) end,
  function() return pcall(warn, nil) end,
  function() return pcall(warn, false) end,
  function() return pcall(warn, "partial", bad) end,
  function() return pcall(warn, function() end) end,
}
for _, call in ipairs(invalid) do
  local ok = call()
  assert(not ok)
end
assert(tostring_calls == 0)
io.stdout:write("invalid-arguments-ok\n")"#,
        Some(&grant),
        &["-W"],
        &[],
    );
    assert_success_exact(
        &invalid_arguments,
        b"invalid-arguments-ok\n",
        b"",
        "無效 warning 參數不得部分輸出或呼叫 __tostring",
    );

    let no_grant = run_cli(
        "p17_warning_cli_basic_no_grant",
        "assert(select('#', warn('without-grant')) == 0); io.stdout:write('no-grant-ok\\n')",
        None,
        &["-W"],
        &[],
    );
    assert_success_exact(
        &no_grant,
        b"no-grant-ok\n",
        b"Lua warning: without-grant\n",
        "無 grant 的 warning",
    );
}

#[test]
fn p17_warning_cli_option_order() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析唯讀 B01 grant");

    let init_and_order = run_cli(
        "p17_warning_cli_option_order_init_and_W",
        "assert(warn('guest-replacement') == 'replacement'); io.stdout:write('ordered-w-ok\\n')",
        Some(&grant),
        &[
            "-e",
            "assert(select('#', P17_SAVED_WARN('before-W')) == 0)",
            "-W",
            "-e",
            "assert(select('#', P17_SAVED_WARN('enabled')) == 0)",
            "-W",
            "-e",
            "P17_SAVED_WARN('@off'); P17_SAVED_WARN('disabled')",
            "-W",
            "-e",
            "assert(select('#', P17_SAVED_WARN('reopened')) == 0)",
        ],
        &[(
            "LUA_INIT",
            "P17_SAVED_WARN=warn; warn('init-hidden'); warn=function(...) return 'replacement' end",
        )],
    );
    assert_success_exact(
        &init_and_order,
        b"ordered-w-ok\n",
        b"Lua warning: enabled\nLua warning: reopened\n",
        "LUA_INIT、原 warning service 與 argv 順序",
    );

    let execute_require_order = run_cli(
        "p17_warning_cli_option_order_execute_require",
        "assert(P17_MODULE_LOADED == true); io.stdout:write('load-order-ok\\n')",
        Some(&grant),
        &[
            "-e",
            "P17_ORDER='ready'",
            "-l",
            "p17_warning_order",
            "-W",
            "-e",
            "assert(P17_MODULE_LOADED == true); warn('load-order')",
        ],
        &[(
            "LUA_INIT",
            "package.preload.p17_warning_order=function() assert(P17_ORDER == 'ready'); P17_MODULE_LOADED=true; return {} end",
        )],
    );
    assert_success_exact(
        &execute_require_order,
        b"load-order-ok\n",
        b"Lua warning: load-order\n",
        "-e 與 -l argv 次序",
    );

    let ignore_init_but_keep_warning_option = run_cli(
        "p17_warning_cli_option_order_ignore_init",
        "assert(select('#', warn('visible')) == 0); io.stdout:write('ignore-init-ok\\n')",
        None,
        &["-E", "-W", "-e", "warn('action-visible')"],
        &[(
            "LUA_INIT",
            "io.stdout:write('init-ran\\n'); warn('init-warning')",
        )],
    );
    assert_success_exact(
        &ignore_init_but_keep_warning_option,
        b"ignore-init-ok\n",
        b"Lua warning: action-visible\nLua warning: visible\n",
        "-E 略過 LUA_INIT 並保留 -W",
    );

    let invalid_suffix = run_cli(
        "p17_warning_cli_option_order_invalid_suffix",
        "io.stdout:write('script-must-not-run\\n')",
        None,
        &["-Wfoo"],
        &[],
    );
    assert!(
        !invalid_suffix.timed_out,
        "-Wfoo CLI 超過 {:?}; log={}",
        CLI_TIMEOUT,
        invalid_suffix.log_path.display()
    );
    assert!(
        !invalid_suffix.status.success(),
        "-Wfoo 應以 usage 錯誤拒絕；stdout={:?}; stderr={:?}; log={}",
        String::from_utf8_lossy(&invalid_suffix.stdout),
        String::from_utf8_lossy(&invalid_suffix.stderr),
        invalid_suffix.log_path.display()
    );
    assert!(
        invalid_suffix.stdout.is_empty(),
        "-Wfoo 不應執行 guest script；log={}",
        invalid_suffix.log_path.display()
    );
    assert!(
        !invalid_suffix.stderr.is_empty(),
        "-Wfoo 應輸出 usage 診斷；log={}",
        invalid_suffix.log_path.display()
    );
}

#[test]
fn p17_warning_cli_gc_shutdown() {
    let fixture = b01_fixture();
    let grant = fs::canonicalize(&fixture.grant).expect("解析唯讀 B01 grant");

    let explicit_gc_string_error = run_cli(
        "p17_warning_cli_gc_shutdown_explicit_string_error",
        r#"warn("@on")
do
  local victim = setmetatable({}, {
    __gc = function()
      error("explicit-gc", 0)
    end,
  })
end
collectgarbage("collect")
io.stdout:write("explicit-gc-ok\n")"#,
        Some(&grant),
        &["-W"],
        &[],
    );
    assert_success_exact(
        &explicit_gc_string_error,
        b"explicit-gc-ok\n",
        b"Lua warning: error in __gc (explicit-gc)\n",
        "顯式 GC 的字串 finalizer 錯誤",
    );

    let explicit_gc_non_string_error = run_cli(
        "p17_warning_cli_gc_shutdown_explicit_non_string_error",
        r#"warn("@on")
local tostring_calls = 0
local failure = setmetatable({}, {
  __tostring = function()
    tostring_calls = tostring_calls + 1
    return "must-not-be-stringified"
  end,
})
do
  local victim = setmetatable({}, {
    __gc = function()
      error(failure, 0)
    end,
  })
end
collectgarbage("collect")
assert(tostring_calls == 0)
io.stdout:write("non-string-gc-ok\n")"#,
        Some(&grant),
        &["-W"],
        &[],
    );
    assert_success_exact(
        &explicit_gc_non_string_error,
        b"non-string-gc-ok\n",
        b"Lua warning: error in __gc (error object is not a string)\n",
        "非字串 finalizer error 不呼叫 __tostring",
    );

    let explicit_gc_warning_off = run_cli(
        "p17_warning_cli_gc_shutdown_explicit_off",
        r#"warn("@off")
do
  local victim = setmetatable({}, {
    __gc = function()
      error("suppressed-gc", 0)
    end,
  })
end
collectgarbage("collect")
io.stdout:write("gc-warning-off-ok\n")"#,
        Some(&grant),
        &[],
        &[],
    );
    assert_success_exact(
        &explicit_gc_warning_off,
        b"gc-warning-off-ok\n",
        b"",
        "GC finalizer warning 與 warn('@off') 共用開關",
    );

    let shutdown_only_finalizer = run_cli(
        "p17_warning_cli_gc_shutdown_only",
        r#"warn("@on")
P17_WARNING_FINALIZER = setmetatable({}, {
  __gc = function()
    error("shutdown-only", 0)
  end,
})
io.stdout:write("shutdown-main-ok\n")"#,
        Some(&grant),
        &["-W"],
        &[],
    );
    assert_success_exact(
        &shutdown_only_finalizer,
        b"shutdown-main-ok\n",
        b"Lua warning: error in __gc (shutdown-only)\n",
        "只在 CLI 關閉時執行的 finalizer 錯誤",
    );

    let no_grant_shutdown_finalizer = run_cli(
        "p17_warning_cli_gc_shutdown_no_grant",
        r#"P17_WARNING_FINALIZER = setmetatable({}, {
  __gc = function()
    error("no-grant-shutdown", 0)
  end,
})
io.stdout:write("no-grant-shutdown-main-ok\n")"#,
        None,
        &["-W"],
        &[],
    );
    assert_success_exact(
        &no_grant_shutdown_finalizer,
        b"no-grant-shutdown-main-ok\n",
        b"Lua warning: error in __gc (no-grant-shutdown)\n",
        "無 grant CLI 關閉時仍安全回報 __gc warning",
    );
}

#[test]
fn p17_warning_cli_callback_reentry() {
    let fixture = warning_probe_fixture();

    let cpath = fixture.cpath.as_str();
    let reentry = run_cli(
        "p17_warning_cli_callback_reentry",
        r##"local probe = require("p17_warning_probe")
probe.setup("reenter")
P17_CALLBACK_VALUE = 41
warn("guest-first", "guest-second")
assert(P17_CALLBACK_PUSHED == 42)
local protected, protected_error = pcall(function()
  error("protected-callback-error", 0)
end)
assert(not protected and protected_error == "protected-callback-error")
assert(select("#", warn("after-callback-disable")) == 0)
io.stdout:write(probe.events())
io.stdout:write("callback-reentry-ok\n")"##,
        Some(&fixture.grant),
        &["-W"],
        &[("LUA_CPATH", cpath)],
    );
    assert_success_exact(
        &reentry,
        b"primary|1|1|41|guest-first\nnested|0|-1|-1|nested-callback\nreplacement|0|-1|-1|guest-second\ncallback-reentry-ok\n",
        b"",
        "warning callback 重入、替換、停用與 buffer lifetime",
    );

    let cpath = fixture.cpath.as_str();
    let finalizer_fragments = run_cli(
        "p17_warning_cli_callback_reentry_finalizer_fragments",
        r#"local probe = require("p17_warning_probe")
probe.setup("record")
do
  local victim = setmetatable({}, {
    __gc = function()
      error("gc-callback-sentinel", 0)
    end,
  })
end
collectgarbage("collect")
local string_error = probe.events()

probe.setup("record")
do
  local victim = setmetatable({}, {
    __gc = function()
      error(73, 0)
    end,
  })
end
collectgarbage("collect")
local number_error = probe.events()

P17_CALLBACK_TOSTRING_CALLS = 0
probe.setup("record")
do
  local failure = setmetatable({}, {
    __tostring = function()
      P17_CALLBACK_TOSTRING_CALLS = P17_CALLBACK_TOSTRING_CALLS + 1
      return "must-not-be-called"
    end,
  })
  local victim = setmetatable({}, {
    __gc = function()
      error(failure, 0)
    end,
  })
end
collectgarbage("collect")
assert(P17_CALLBACK_TOSTRING_CALLS == 0)
io.stdout:write(string_error, number_error, probe.events())
io.stdout:write("callback-finalizer-ok\n")"#,
        Some(&fixture.grant),
        &["-W"],
        &[("LUA_CPATH", cpath)],
    );
    assert_success_exact(
        &finalizer_fragments,
        b"record|1|-1|-1|error in \nrecord|1|-1|-1|__gc\nrecord|1|-1|-1| (\nrecord|1|-1|-1|gc-callback-sentinel\nrecord|0|-1|-1|)\nrecord|1|-1|-1|error in \nrecord|1|-1|-1|__gc\nrecord|1|-1|-1| (\nrecord|1|-1|-1|error object is not a string\nrecord|0|-1|-1|)\nrecord|1|-1|-1|error in \nrecord|1|-1|-1|__gc\nrecord|1|-1|-1| (\nrecord|1|-1|-1|error object is not a string\nrecord|0|-1|-1|)\ncallback-finalizer-ok\n",
        b"",
        "C callback 接收完整五段 GC finalizer 警告與非字串 fallback",
    );
}
