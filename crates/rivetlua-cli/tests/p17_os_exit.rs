#![forbid(unsafe_code)]
#![cfg(all(unix, any(feature = "native-lua55", feature = "native-lua54")))]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("P17 os.exit 每個測試 binary 只能選一個 Lua ABI profile");

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rivetlua_capi::abi::{self, AbiIdentity};

#[cfg(feature = "native-lua55")]
const PROFILE: &str = "lua55";
#[cfg(feature = "native-lua54")]
const PROFILE: &str = "lua54";

#[cfg(feature = "native-lua55")]
const PROFILE_ID: &str = "lua55-i64f64";
#[cfg(feature = "native-lua54")]
const PROFILE_ID: &str = "lua54-i64f64";

#[cfg(feature = "native-lua55")]
const FIXTURE_SUFFIX: &str = "lua-5.5.1-tests";
#[cfg(feature = "native-lua54")]
const FIXTURE_SUFFIX: &str = "lua-5.4.9-tests";

#[cfg(feature = "native-lua55")]
const B01_GRANT_SHA256: &str = "67d81268e3daafc7e172ee73e607448309d452f5067d07f9ced8f769129726ac";
#[cfg(feature = "native-lua54")]
const B01_GRANT_SHA256: &str = "23895bb7d1e26f817f3ff4cd451258055124c0227e6ec521e25cbf8b708ec3de";

#[cfg(feature = "native-lua55")]
const VERSION_LINE: &[u8] = b"RivetLua 0.0.0 (Lua 5.5.1)\n";
#[cfg(feature = "native-lua54")]
const VERSION_LINE: &[u8] = b"RivetLua 0.0.0 (Lua 5.4.9)\n";

const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let parent = evidence_root().join("p17-os-exit-work");
        fs::create_dir_all(&parent).expect("建立外部 os.exit 測試工作目錄");
        loop {
            let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("系統時間晚於 Unix epoch")
                .as_nanos();
            let path = parent.join(format!(
                "p17-os-exit-{PROFILE_ID}-{label}-{}-{sequence}-{stamp}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("建立隔離 os.exit 工作目錄失敗：{error}"),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct CliResult {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    log_path: PathBuf,
}

struct ExitProbeFixture {
    grant: PathBuf,
    cpath: String,
    source: PathBuf,
    source_sha256: String,
    binary: PathBuf,
    binary_sha256: String,
    build_log: PathBuf,
    build_log_sha256: String,
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
        .join("p17_os_exit.rs");
    file_sha256(&path)
}

fn b01_grant() -> PathBuf {
    let prefix = format!("b01-{}-", PROFILE);
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
    grant
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('\"');
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
        concat!(
            "{{\"revision\":{},\"profile_id\":{},\"numeric_config\":{},\"pointer_width_bits\":{},",
            "\"endianness\":{},\"reserved_zero\":{},\"target\":{},\"header_set_sha256\":{},",
            "\"lua_h_sha256\":{},\"lauxlib_h_sha256\":{},\"luaconf_h_sha256\":{},\"layout\":[{}]}}",
        ),
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

fn unique_external_run_dir(label: &str) -> PathBuf {
    let parent = evidence_root().join("p17-exit-native-fixtures");
    fs::create_dir_all(&parent).expect("建立 P17 os.exit C fixture evidence 目錄");
    loop {
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let path = parent.join(format!(
            "p17-exit-native-{PROFILE_ID}-{label}-{}-{sequence}-{stamp}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("建立不可重用的 os.exit native fixture 目錄失敗：{error}"),
        }
    }
}

fn exit_probe_grant_json(
    repo: &Path,
    binary: &Path,
    source: &Path,
    cpath: &Path,
    identity: AbiIdentity,
) -> String {
    let target = target_string(&identity.target);
    let header_binding = hex_bytes(&identity.header_set_sha256);
    let abi_manifest_sha256 = file_sha256(&repo.join("tests/p16/abi-manifest.toml"));
    format!(
        concat!(
            "{{\"schema\":\"rivetlua-native-grant-v1\",",
            "\"profile\":{},\"target\":{},",
            "\"abi_manifest_sha256\":{},",
            "\"capability\":\"trusted-host-process-permissions-v1\",",
            "\"cpath\":[{}],\"modules\":[",
            "{{\"canonical_path\":{},",
            "\"sha256\":{},\"source_sha256\":{},\"header_binding\":{},\"abi_identity\":{},",
            "\"unwind\":\"CNoUnwind\",\"exports\":[\"luaopen_p17_exit_probe\"],\"visibility\":\"local\",",
            "\"dependencies\":[]}}]}}\n",
        ),
        json_string(PROFILE_ID),
        json_string(&target),
        json_string(&abi_manifest_sha256),
        json_string(&cpath.display().to_string()),
        json_string(
            &binary
                .canonicalize()
                .expect("exit_probe module binary canonicalize")
                .display()
                .to_string()
        ),
        json_string(&file_sha256(binary)),
        json_string(&file_sha256(source)),
        json_string(&header_binding),
        abi_identity_json(identity),
    )
}

fn exit_probe_fixture() -> ExitProbeFixture {
    const MACOS_CLANG: &str = "/Library/Developer/CommandLineTools/usr/bin/clang";
    const MACOS_CLANG_SHA256: &str =
        "1590ac950a3d627817d09ade5cb60b2115f17a72182a3141e010b4bcc482a0c9";
    const MACOS_AR: &str = "/Library/Developer/CommandLineTools/usr/bin/ar";
    const MACOS_AR_SHA256: &str =
        "85d15bd3999895f659e8a483b17ea9ab44b924c8e0b3026abfe359f2de02cbd7";
    const MACOS_LD: &str = "/Library/Developer/CommandLineTools/usr/bin/ld";
    const MACOS_LD_SHA256: &str =
        "374d9f0713bce2c8a9e1e82bde51615d5433516a10d99b63107eb6ee70542e4c";
    const MACOS_SDKROOT: &str = "/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk";

    assert!(
        cfg!(target_os = "macos"),
        "exit_probe 僅允許已驗證的 macOS C toolchain"
    );
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root 存在");
    let run = unique_external_run_dir("callback");
    let libs = run.join("libs");
    fs::create_dir(&libs).expect("建立專屬 exit_probe module 目錄");
    let source = repo.join("tests/p17/native-fixtures/exit_probe.c");
    let binary = libs.join("p17_exit_probe.so");
    assert!(source.is_file(), "C os.exit fixture 存在");
    assert!(!binary.exists(), "module output 必須是尚不存在的新路徑");

    let clang = PathBuf::from(MACOS_CLANG);
    let archiver = PathBuf::from(MACOS_AR);
    let linker = PathBuf::from(MACOS_LD);
    let sdkroot = PathBuf::from(MACOS_SDKROOT);
    assert!(clang.is_file(), "固定 macOS clang 不存在");
    assert!(archiver.is_file(), "固定 macOS archiver 不存在");
    assert!(linker.is_file(), "固定 macOS linker 不存在");
    assert!(sdkroot.is_dir(), "固定 macOS SDK 不存在");
    assert_eq!(
        clang.canonicalize().expect("解析固定 macOS clang"),
        clang,
        "clang 必須是固定的實體路徑"
    );
    assert_eq!(
        archiver.canonicalize().expect("解析固定 macOS archiver"),
        archiver,
        "archiver 必須是固定的實體路徑"
    );
    assert_eq!(
        linker.canonicalize().expect("解析固定 macOS linker"),
        linker,
        "linker 必須是固定的實體路徑"
    );
    assert_eq!(
        sdkroot.canonicalize().expect("解析固定 macOS SDK"),
        sdkroot,
        "SDK 必須是指定的實體路徑"
    );
    assert_eq!(
        file_sha256(&clang),
        MACOS_CLANG_SHA256,
        "clang SHA-256 不符"
    );
    assert_eq!(
        file_sha256(&archiver),
        MACOS_AR_SHA256,
        "archiver SHA-256 不符"
    );
    assert_eq!(file_sha256(&linker), MACOS_LD_SHA256, "linker SHA-256 不符");

    let profile_include = repo.join(match PROFILE_ID {
        "lua55-i64f64" => "include/rivetlua/lua55",
        _ => "include/rivetlua/lua54",
    });
    let common_include = repo.join("include/rivetlua");
    let compile_tmp = run.join("tmp");
    fs::create_dir(&compile_tmp).expect("建立專屬 C build 暫存目錄");
    let args = vec![
        "-std=c11".to_owned(),
        "-Wall".to_owned(),
        "-Wextra".to_owned(),
        "-Werror".to_owned(),
        "-fPIC".to_owned(),
        format!("--ld-path={MACOS_LD}"),
        "-dynamiclib".to_owned(),
        "-undefined".to_owned(),
        "dynamic_lookup".to_owned(),
        "-isysroot".to_owned(),
        MACOS_SDKROOT.to_owned(),
        "-mmacosx-version-min=11.0".to_owned(),
        "-I".to_owned(),
        profile_include.display().to_string(),
        "-I".to_owned(),
        common_include.display().to_string(),
        source.display().to_string(),
        "-o".to_owned(),
        binary.display().to_string(),
    ];
    let explicit_env = [
        (
            "PATH",
            "/Library/Developer/CommandLineTools/usr/bin:/usr/bin:/bin",
        ),
        ("TMPDIR", compile_tmp.to_str().expect("TMPDIR 是 UTF-8")),
        ("SDKROOT", MACOS_SDKROOT),
        ("MACOSX_DEPLOYMENT_TARGET", "11.0"),
        ("LLVM_DISABLE_SYMBOLIZATION", "1"),
        ("RUST_BACKTRACE", "0"),
    ];
    let mut command = Command::new(&clang);
    command.current_dir(&repo).env_clear().args(&args);
    for (key, value) in explicit_env {
        command.env(key, value);
    }
    let output = command.output();
    let (exit_code, compile_success, stdout, stderr, spawn_error) = match output {
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
    let identity = abi::current_identity();
    let source_sha256 = file_sha256(&source);
    let binary_sha256 = binary.is_file().then(|| file_sha256(&binary));
    let cpath = libs.join("?.so");
    let grant = run.join("exit-native-grant.json");
    let mut grant_error = None;
    let grant_sha256 = if compile_success == Some(true) && binary_sha256.is_some() {
        let result = (|| {
            let bytes = exit_probe_grant_json(&repo, &binary, &source, &cpath, identity);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&grant)
                .map_err(|error| error.to_string())?;
            file.write_all(bytes.as_bytes())
                .map_err(|error| error.to_string())?;
            file.flush().map_err(|error| error.to_string())?;
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
    let record = format!(
        concat!(
            "{{\"schema\":\"rivetlua-p17-exit-native-build-v1\",\"profile\":{},\"header_identity\":{},",
            "\"process_count\":1,\"program\":{},\"program_sha256\":{},\"archiver\":{},",
            "\"archiver_sha256\":{},\"archiver_invoked\":false,\"linker\":{},\"linker_sha256\":{},",
            "\"sdkroot\":{},\"args\":[{}],\"cwd\":{},\"stdin\":\"null\",\"env_clear\":true,",
            "\"explicit_env\":{{{}}},\"exit_code\":{},\"compile_success\":{},\"spawn_error\":{},",
            "\"stdout\":{},\"stderr\":{},\"source_path\":{},\"source_sha256\":{},\"binary_path\":{},",
            "\"binary_sha256\":{},\"cpath\":{},\"grant_path\":{},\"grant_sha256\":{},",
            "\"grant_error\":{}}}\n",
        ),
        json_string(PROFILE_ID),
        abi_identity_json(identity),
        json_string(&clang.display().to_string()),
        json_string(&file_sha256(&clang)),
        json_string(&archiver.display().to_string()),
        json_string(&file_sha256(&archiver)),
        json_string(&linker.display().to_string()),
        json_string(&file_sha256(&linker)),
        json_string(&sdkroot.display().to_string()),
        args_json,
        json_string(&repo.display().to_string()),
        env_json,
        exit_code.map_or_else(|| "null".to_owned(), |code| code.to_string()),
        compile_success.map_or_else(|| "null".to_owned(), |success| success.to_string()),
        spawn_error
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string),
        json_string(&stdout),
        json_string(&stderr),
        json_string(&source.display().to_string()),
        json_string(&source_sha256),
        json_string(&binary.display().to_string()),
        binary_sha256
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string),
        json_string(&cpath.display().to_string()),
        json_string(&grant.display().to_string()),
        grant_sha256
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string),
        grant_error
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string),
    );
    let build_log = run.join("exit-probe-build.json");
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&build_log)
        .expect("以 create_new 建立不可覆寫 C build evidence");
    log.write_all(record.as_bytes())
        .expect("寫入 os.exit C build evidence");
    log.flush().expect("flush os.exit C build evidence");
    println!(
        "P17_EXIT_NATIVE_BUILD profile={PROFILE_ID} log={} sha256={}",
        build_log.display(),
        file_sha256(&build_log)
    );
    assert!(
        compile_success == Some(true) && binary_sha256.is_some() && grant_sha256.is_some(),
        concat!(
            "exit_probe.c 編譯或 grant 建立失敗：exit={exit_code:?} spawn_error={spawn_error:?} ",
            "grant_error={grant_error:?}\n",
            "stdout={stdout}\n",
            "stderr={stderr}\n",
            "log={}",
        ),
        build_log.display(),
        exit_code = exit_code,
        spawn_error = spawn_error,
        grant_error = grant_error,
        stdout = stdout,
        stderr = stderr,
    );

    let binary = binary
        .canonicalize()
        .expect("exit_probe module canonicalize");
    let source_sha256 = file_sha256(&source);
    let binary_sha256 = file_sha256(&binary);
    let build_log = build_log.canonicalize().expect("build log canonicalize");
    ExitProbeFixture {
        grant: grant.canonicalize().expect("exit_probe grant canonicalize"),
        cpath: cpath.display().to_string(),
        source,
        source_sha256,
        binary,
        binary_sha256,
        build_log_sha256: file_sha256(&build_log),
        build_log,
    }
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
    let directory = evidence_root().join("p17-os-exit-regressions");
    fs::create_dir_all(&directory).expect("建立 P17 os.exit regression evidence 目錄");
    loop {
        let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let path = directory.join(format!(
            "p17-os-exit-{PROFILE_ID}-{label}-{}-{sequence}-{stamp}.log",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return (path, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("建立不可覆寫 os.exit evidence log 失敗：{error}"),
        }
    }
}

fn run_cli(
    label: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
    grant: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> CliResult {
    run_cli_inner(label, arguments, stdin, grant, extra_env, None)
}

fn run_cli_with_exit_probe(label: &str, source: &str, fixture: &ExitProbeFixture) -> CliResult {
    run_cli_inner(
        label,
        &["-e", source],
        None,
        Some(&fixture.grant),
        &[("LUA_CPATH", fixture.cpath.as_str())],
        Some(fixture),
    )
}

fn run_cli_inner(
    label: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
    grant: Option<&Path>,
    extra_env: &[(&str, &str)],
    native_fixture: Option<&ExitProbeFixture>,
) -> CliResult {
    let scratch = Scratch::new(label);
    let empty_path = scratch.path.join("empty-path");
    fs::create_dir(&empty_path).expect("建立空 PATH 目錄");
    let stdout_path = scratch.path.join("stdout.log");
    let stderr_path = scratch.path.join("stderr.log");
    let stdout_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .expect("建立 CLI stdout log");
    let stderr_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .expect("建立 CLI stderr log");

    let cli = cli_binary();
    let cli_hash = file_sha256(&cli);
    let source_hash = test_source_sha256();
    let grant_hash = grant.map(file_sha256);
    let native_module_path = native_fixture
        .map(|fixture| fixture.binary.display().to_string())
        .unwrap_or_else(|| "<none>".to_owned());
    let native_module_sha256 = native_fixture
        .map(|fixture| fixture.binary_sha256.as_str())
        .unwrap_or("<none>");
    let native_source_path = native_fixture
        .map(|fixture| fixture.source.display().to_string())
        .unwrap_or_else(|| "<none>".to_owned());
    let native_source_sha256 = native_fixture
        .map(|fixture| fixture.source_sha256.as_str())
        .unwrap_or("<none>");
    let native_build_log = native_fixture
        .map(|fixture| fixture.build_log.display().to_string())
        .unwrap_or_else(|| "<none>".to_owned());
    let native_build_log_sha256 = native_fixture
        .map(|fixture| fixture.build_log_sha256.as_str())
        .unwrap_or("<none>");
    let mut command = Command::new(&cli);
    command
        .current_dir(&scratch.path)
        .env_clear()
        .env("PATH", &empty_path)
        .env("TMPDIR", &scratch.path)
        .env("LLVM_DISABLE_SYMBOLIZATION", "1")
        .env("RUST_BACKTRACE", "0")
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .args(["--profile", PROFILE])
        .args(arguments);
    if let Some(grant) = grant {
        command.env("RIVETLUA_NATIVE_MANIFEST", grant);
    }
    for (key, value) in extra_env {
        command.env(*key, *value);
    }

    let mut argv = Vec::with_capacity(3 + arguments.len());
    argv.push(cli.as_os_str().to_owned());
    argv.push(OsString::from("--profile"));
    argv.push(OsString::from(PROFILE));
    argv.extend(arguments.iter().map(|argument| OsString::from(*argument)));
    let argv = format!("{argv:?}");
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("直接啟動編譯後 CLI 失敗：{error}"));
    if let Some(stdin) = stdin {
        child
            .stdin
            .take()
            .expect("CLI stdin pipe 存在")
            .write_all(stdin)
            .expect("寫入 CLI stdin");
    }

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().expect("檢查 CLI process 狀態") {
            break (status, false);
        }
        if started.elapsed() >= CHILD_TIMEOUT {
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
    writeln!(
        log,
        concat!(
            "schema=rivetlua-p17-os-exit-child-v1\n",
            "profile={PROFILE_ID}\n",
            "selector={label}\n",
            "process_count=1\n",
            "argv={argv}\n",
            "cwd={}\n",
            "env_clear=true\n",
            "PATH={}\n",
            "TMPDIR={}\n",
            "LLVM_DISABLE_SYMBOLIZATION=1\n",
            "RUST_BACKTRACE=0\n",
            "extra_env={extra_env:?}\n",
            "cli={}\n",
            "cli_sha256={cli_hash}\n",
            "test_source_sha256={source_hash}\n",
            "grant={}\n",
            "grant_sha256={}\n",
            "native_module={}\n",
            "native_module_sha256={}\n",
            "native_module_source={}\n",
            "native_module_source_sha256={}\n",
            "native_build_log={}\n",
            "native_build_log_sha256={}\n",
            "timeout_seconds={}\n",
            "timed_out={timed_out}\n",
            "exit_code={:?}\n",
            "stdin={:?}\n",
            "stdout={:?}\n",
            "stderr={:?}",
        ),
        scratch.path.display(),
        empty_path.display(),
        scratch.path.display(),
        cli.display(),
        grant.map_or_else(|| "<unset>".to_owned(), |path| path.display().to_string()),
        grant_hash.as_deref().unwrap_or("<none>"),
        native_module_path,
        native_module_sha256,
        native_source_path,
        native_source_sha256,
        native_build_log,
        native_build_log_sha256,
        CHILD_TIMEOUT.as_secs(),
        status.code(),
        stdin
            .map(String::from_utf8_lossy)
            .map(|value| value.into_owned())
            .unwrap_or_else(|| "<null>".to_owned()),
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
        PROFILE_ID = PROFILE_ID,
        label = label,
        argv = argv,
        extra_env = extra_env,
        cli_hash = cli_hash,
        source_hash = source_hash,
        timed_out = timed_out,
    )
    .expect("寫入 os.exit child evidence");

    CliResult {
        exit_code: status.code(),
        stdout,
        stderr,
        timed_out,
        log_path,
    }
}

fn assert_cli_result(
    result: &CliResult,
    expected_exit: i32,
    expected_stdout: &[u8],
    expected_stderr: &[u8],
    label: &str,
) {
    assert!(
        !result.timed_out,
        "{label} CLI 超過 {:?}; log={}",
        CHILD_TIMEOUT,
        result.log_path.display()
    );
    assert_eq!(
        result.exit_code,
        Some(expected_exit),
        "{label} exit code 不符；stdout={:?}; stderr={:?}; log={}",
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

fn run_exit(label: &str, source: &str, expected_exit: i32, grant: Option<&Path>) {
    let result = run_cli(label, &["-e", source], None, grant, &[]);
    assert_cli_result(&result, expected_exit, b"", b"", label);
}

#[test]
fn p17_exit_status_and_arguments() {
    for (label, source, expected_exit) in [
        ("default_status", "os.exit()", 0),
        ("nil_status", "os.exit(nil, false)", 0),
        ("true_status", "os.exit(true, false)", 0),
        ("false_status", "os.exit(false, false)", 1),
        ("integer_status", "os.exit(23, false)", 23),
        ("numeric_string_status", "os.exit('17', false)", 17),
        ("negative_i32_cast", "os.exit(-1, false)", 255),
        ("i32_cast_low_byte_zero", "os.exit(256, false)", 0),
        (
            "i32_cast_after_wide_integer",
            "os.exit(4294967297, false)",
            1,
        ),
    ] {
        run_exit(label, source, expected_exit, None);
    }

    let grant = b01_grant();
    run_exit("valid_native_grant", "os.exit(19, false)", 19, Some(&grant));

    let source = concat!(
        "local fractional = pcall(os.exit, 1.5, false)\n",
        "local text = pcall(os.exit, 'not-an-integer', false)\n",
        "local table = pcall(os.exit, {}, false)\n",
        "assert(not fractional and not text and not table)\n",
        "print('caught-invalid')",
    );
    let result = run_cli(
        "invalid_arguments_are_catchable",
        &["-e", source],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        0,
        b"caught-invalid\n",
        b"",
        "invalid_arguments_are_catchable",
    );
}

#[test]
fn p17_exit_uncatchable_boundaries() {
    let cases = [
        (
            "pcall_cannot_catch_exit",
            "pcall(function() os.exit(31, false) end)\nprint('after-pcall')",
            31,
            false,
        ),
        (
            "xpcall_cannot_catch_exit",
            concat!(
                "xpcall(function() os.exit(32, false) end, function() print('caught-handler') end)\n",
                "print('after-xpcall')",
            ),
            32,
            true,
        ),
        (
            "coroutine_resume_cannot_catch_exit",
            concat!(
                "local co = coroutine.create(function() os.exit(33, false) end)\n",
                "coroutine.resume(co)\n",
                "print('after-resume')",
            ),
            33,
            false,
        ),
    ];
    let grant = b01_grant();
    for (label, source, expected_exit, use_grant) in cases {
        let result = run_cli(
            label,
            &["-e", source],
            None,
            use_grant.then_some(grant.as_path()),
            &[],
        );
        assert_cli_result(&result, expected_exit, b"", b"", label);
    }

    let fixture = exit_probe_fixture();
    for (label, source, expected_exit) in [
        (
            "native_call_exit_is_terminal",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "probe.call(function() os.exit(61, false) end)\n",
                "print('after-native-call')",
            ),
            61,
        ),
        (
            "native_pcall_exit_is_terminal",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "probe.pcall(function() os.exit(62, false) end)\n",
                "print('after-native-pcall')",
            ),
            62,
        ),
        (
            "nested_native_call_pcall_exit_is_terminal",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "probe.pcall(function() probe.call(function() os.exit(63, false) end) end)\n",
                "print('after-native-nested')",
            ),
            63,
        ),
        (
            "coroutine_native_call_exit_is_terminal",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "local co = coroutine.create(function() probe.call(function() os.exit(64,",
                " false) end) end)\n",
                "coroutine.resume(co)\n",
                "print('after-native-coroutine')",
            ),
            64,
        ),
        (
            "native_pcall_close_true_runs_main_tbc",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "local value <close> = setmetatable({}, {__close = function() print('native-main-tbc') ",
                "end})\n",
                "probe.pcall(function() os.exit(65, true) end)\n",
                "print('after-native-close')",
            ),
            65,
        ),
        (
            "native_pcall_close_true_runs_main_gc",
            concat!(
                "local probe = require('p17_exit_probe')\n",
                "collectgarbage('stop')\n",
                "setmetatable({}, {__gc = function() print('native-main-gc') end})\n",
                "probe.pcall(function() os.exit(66, true) end)\n",
                "print('after-native-close')",
            ),
            66,
        ),
    ] {
        let result = run_cli_with_exit_probe(label, source, &fixture);
        let expected_stdout: &[u8] = match label {
            "native_pcall_close_true_runs_main_tbc" => b"native-main-tbc\n",
            "native_pcall_close_true_runs_main_gc" => b"native-main-gc\n",
            _ => b"",
        };
        assert_cli_result(&result, expected_exit, expected_stdout, b"", label);
    }

    let result = run_cli_with_exit_probe(
        "native_call_normal_return_control",
        concat!(
            "local probe = require('p17_exit_probe')\n",
            "local first, second = probe.call(function() return 'native-return', 71 end)\n",
            "assert(first == 'native-return' and second == 71)\n",
            "print('native-call-return-ok')",
        ),
        &fixture,
    );
    assert_cli_result(
        &result,
        0,
        b"native-call-return-ok\n",
        b"native-after-call\n",
        "native_call_normal_return_control",
    );

    let result = run_cli_with_exit_probe(
        "native_pcall_lua_error_control",
        concat!(
            "local probe = require('p17_exit_probe')\n",
            "local ok, message = probe.pcall(function() error('native-pcall-error', 0) ",
            "end)\n",
            "assert(not ok and message == 'native-pcall-error')\n",
            "print('native-pcall-error-caught')",
        ),
        &fixture,
    );
    assert_cli_result(
        &result,
        0,
        b"native-pcall-error-caught\n",
        b"native-after-pcall\n",
        "native_pcall_lua_error_control",
    );

    let result = run_cli_with_exit_probe(
        "native_global_env_return_control",
        concat!(
            "local probe = require('p17_exit_probe')\n",
            "local get_os = function() return os end\n",
            "local direct_os = get_os()\n",
            "local native_os = probe.call(get_os)\n",
            "local get_exit = function() return os.exit end\n",
            "local direct_exit = get_exit()\n",
            "local native_exit = probe.call(get_exit)\n",
            "assert(type(direct_os) == 'table' and direct_os == os)\n",
            "assert(type(native_os) == 'table' and native_os == os)\n",
            "assert(type(direct_exit) == 'function' and direct_exit == os.exit)\n",
            "assert(type(native_exit) == 'function' and native_exit == os.exit)\n",
            "print(type(direct_os))\n",
            "print(type(native_os))\n",
            "print(type(direct_exit))\n",
            "print(type(native_exit))",
        ),
        &fixture,
    );
    assert_cli_result(
        &result,
        0,
        b"table\ntable\nfunction\nfunction\n",
        b"native-after-call\nnative-after-call\n",
        "native_global_env_return_control",
    );

    let result = run_cli_with_exit_probe(
        "native_nested_shared_upvalue_return_control",
        concat!(
            "local probe = require('p17_exit_probe')\n",
            "local counter = 10\n",
            "local function nested_bump()\n",
            "  return probe.pcall(function()\n",
            "    return probe.call(function()\n",
            "      counter = counter + 1\n",
            "      return counter\n",
            "    end)\n",
            "  end)\n",
            "end\n",
            "local ok1, value1 = nested_bump()\n",
            "assert(ok1 and value1 == 11 and counter == 11)\n",
            "print(tostring(ok1) .. ':' .. tostring(value1) .. ':' .. tostring(counter))\n",
            "local ok2, value2 = nested_bump()\n",
            "assert(ok2 and value2 == 12 and counter == 12)\n",
            "print(tostring(ok2) .. ':' .. tostring(value2) .. ':' .. tostring(counter))",
        ),
        &fixture,
    );
    assert_cli_result(
        &result,
        0,
        b"true:11:11\ntrue:12:12\n",
        b"native-after-call\nnative-after-pcall\nnative-after-call\nnative-after-pcall\n",
        "native_nested_shared_upvalue_return_control",
    );
}

#[test]
fn p17_exit_close_lifecycle() {
    let close_false = concat!(
        "collectgarbage('stop')\n",
        "local value <close> = setmetatable({}, {__close = function() print('close-false-tbc') ",
        "end})\n",
        "setmetatable({}, {__gc = function() print('close-false-gc') end})\n",
        "os.exit(12, false)",
    );
    let result = run_cli(
        "close_false_skips_tbc_and_gc",
        &["-e", close_false],
        None,
        None,
        &[],
    );
    assert_cli_result(&result, 12, b"", b"", "close_false_skips_tbc_and_gc");

    let close_true = concat!(
        "local first <close> = setmetatable({}, {__close = function() print('close-first') ",
        "end})\n",
        "local second <close> = setmetatable({}, {__close = function() print('close-second') ",
        "end})\n",
        "os.exit(13, true)",
    );
    let result = run_cli(
        "close_true_runs_tbc_once",
        &["-e", close_true],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        13,
        b"close-second\nclose-first\n",
        b"",
        "close_true_runs_tbc_once",
    );

    let finalizers = concat!(
        "collectgarbage('stop')\n",
        "print('creating 1')\n",
        "setmetatable({}, {__gc = function() print(1) end})\n",
        "print('creating 2')\n",
        "setmetatable({}, {__gc = function()\n",
        "  print(2)\n",
        "  print('creating 3')\n",
        "  setmetatable({}, {__gc = function() print(3) end})\n",
        "  print(collectgarbage())\n",
        "  os.exit(0, true)\n",
        "end})\n",
        "os.exit(0, true)",
    );
    let result = run_cli(
        "close_true_finalizer_reentry_continues_once",
        &["-e", finalizers],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        0,
        b"creating 1\ncreating 2\n2\ncreating 3\nnil\n1\n",
        b"",
        "close_true_finalizer_reentry_continues_once",
    );

    let gc_interrupt = concat!(
        "collectgarbage('stop')\n",
        "setmetatable({}, {__gc = function() print('gc-interrupt')\n",
        "os.exit(41, false)\n",
        "print('after-gc-exit')\n",
        "end})\n",
        "setmetatable({}, {__gc = function() print('gc-interrupt')\n",
        "os.exit(41, false)\n",
        "print('after-gc-exit')\n",
        "end})\n",
        "os.exit(0, true)",
    );
    let result = run_cli(
        "close_false_from_gc_stops_remaining_callbacks",
        &["-e", gc_interrupt],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        41,
        b"gc-interrupt\n",
        b"",
        "close_false_from_gc_stops_remaining_callbacks",
    );

    let shutdown_exit_true = concat!(
        "collectgarbage('stop')\n",
        "P17_SHUTDOWN_EXIT_TRUE = setmetatable({}, {__gc = function()\n",
        "  print('shutdown-exit-true')\n",
        "  os.exit(43, true)\n",
        "  print('after-shutdown-exit-true')\n",
        "end})\n",
        "print('main-finished')",
    );
    let result = run_cli(
        "normal_shutdown_gc_exit_true_status",
        &["-e", shutdown_exit_true],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        43,
        b"main-finished\nshutdown-exit-true\n",
        b"",
        "normal_shutdown_gc_exit_true_status",
    );

    let shutdown_exit_false = concat!(
        "collectgarbage('stop')\n",
        "local function exit_false()\n",
        "  print('shutdown-exit-false')\n",
        "  os.exit(44, false)\n",
        "  print('after-shutdown-exit-false')\n",
        "end\n",
        "P17_SHUTDOWN_EXIT_FALSE_A = setmetatable({}, {__gc = exit_false})\n",
        "P17_SHUTDOWN_EXIT_FALSE_B = setmetatable({}, {__gc = exit_false})\n",
        "print('main-finished')",
    );
    let result = run_cli(
        "normal_shutdown_gc_exit_false_stops_pending",
        &["-e", shutdown_exit_false],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        44,
        b"main-finished\nshutdown-exit-false\n",
        b"",
        "normal_shutdown_gc_exit_false_stops_pending",
    );

    let tbc_interrupt = concat!(
        "local first <close> = setmetatable({}, {__close = function() print('remaining-close') ",
        "end})\n",
        "local second <close> = setmetatable({}, {__close = function() print('close-interrupt')\n",
        "os.exit(42, false)\n",
        "print('after-close-exit')\n",
        "end})\n",
        "os.exit(0, true)",
    );
    let result = run_cli(
        "close_false_from_tbc_stops_remaining_callbacks",
        &["-e", tbc_interrupt],
        None,
        None,
        &[],
    );
    assert_cli_result(
        &result,
        42,
        b"close-interrupt\n",
        b"",
        "close_false_from_tbc_stops_remaining_callbacks",
    );
}

#[test]
fn p17_exit_cli_control_flow() {
    let actions = [
        "-e",
        "print('before-exit')",
        "-e",
        "os.exit(51, false)",
        "-e",
        "print('after-exit')",
    ];
    let result = run_cli("exit_stops_later_e_actions", &actions, None, None, &[]);
    assert_cli_result(
        &result,
        51,
        b"before-exit\n",
        b"",
        "exit_stops_later_e_actions",
    );

    #[cfg(feature = "native-lua55")]
    let init_key = "LUA_INIT_5_5";
    #[cfg(feature = "native-lua54")]
    let init_key = "LUA_INIT_5_4";
    let grant = b01_grant();
    let result = run_cli(
        "exit_stops_init_following_actions",
        &["-e", "print('after-init')"],
        None,
        Some(&grant),
        &[(init_key, "print('init-exit')\nos.exit(52, false)")],
    );
    assert_cli_result(
        &result,
        52,
        b"init-exit\n",
        b"",
        "exit_stops_init_following_actions",
    );

    let repl_input = b"print('repl-before-exit')\nos.exit(53, false)\nprint('after-repl-exit')\n";
    let result = run_cli(
        "exit_stops_repl_input",
        &["-i"],
        Some(repl_input),
        None,
        &[],
    );
    let mut expected_stdout = VERSION_LINE.to_vec();
    expected_stdout.extend_from_slice(
        b"> print('repl-before-exit')\nrepl-before-exit\n> os.exit(53, false)\n",
    );
    assert_cli_result(&result, 53, &expected_stdout, b"", "exit_stops_repl_input");
}
