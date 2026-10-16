#![cfg(all(unix, any(feature = "native-lua55", feature = "native-lua54")))]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("P17 native integration 每個測試 binary 只能選一個 Lua ABI profile");

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rivetlua_capi::abi::{self, AbiIdentity};

#[cfg(feature = "native-lua55")]
const PROFILE: &str = "lua55-i64f64";
#[cfg(feature = "native-lua54")]
const PROFILE: &str = "lua54-i64f64";

#[cfg(feature = "native-lua55")]
const PROFILE_DIR: &str = "lua55";
#[cfg(feature = "native-lua54")]
const PROFILE_DIR: &str = "lua54";

const CLI_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

struct NativeModule {
    name: &'static str,
    source: PathBuf,
    binary: PathBuf,
    exports: &'static [&'static str],
    visibility: &'static str,
    dependencies: Vec<PathBuf>,
}

struct Fixture {
    repo: PathBuf,
    root: PathBuf,
    cli_binary: PathBuf,
    cli_sha256: String,
    modules: Vec<NativeModule>,
    token: String,
}

struct CliResult {
    status: ExitStatus,
    stdout: String,
    stderr: String,
    constructor_marker: PathBuf,
    events: PathBuf,
}

#[derive(Clone, Copy)]
enum GrantMutation {
    None,
    WrongProfile,
    WrongTarget,
    WrongAbi,
    WrongProbeHash,
}

fn profile_name() -> &'static str {
    if PROFILE_DIR == "lua54" {
        "lua54"
    } else {
        "lua55"
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("CLI crate 的 repo root 存在")
}

fn scratch_root() -> PathBuf {
    let evidence = env::var_os("RIVETLUA_P17_EVIDENCE_DIR")
        .map(PathBuf::from)
        .expect("需由 P17 runner 指定外部 evidence 目錄");
    assert!(evidence.is_absolute(), "P17 evidence 目錄必須是絕對路徑");
    fs::create_dir_all(&evidence).expect("建立 P17 evidence 目錄");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系統時間晚於 Unix epoch")
        .as_nanos();
    let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
    let path = evidence.join(format!(
        "native-cli-{}-{}-{}-{}",
        profile_name(),
        std::process::id(),
        sequence,
        stamp
    ));
    fs::create_dir_all(&path).expect("建立隔離 native CLI scratch root");
    path
}

fn command_output(command: &mut Command, description: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("啟動 {description} 失敗：{error}"));
    assert!(
        output.status.success(),
        "{description} 失敗，exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{description} 輸出不是 UTF-8：{error}"))
}

fn build_shared(source: &Path, binary: &Path, include_profile: &Path, common_include: &Path) {
    let mut command = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()));
    command
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-fPIC");
    if PROFILE_DIR == "lua55"
        && source
            .file_name()
            .is_some_and(|name| name == OsStr::new("lib22.c"))
    {
        // 官方 Lua 5.5 lib22.c 的 t_freestr 保留一個未使用的 ABI 參數。
        command.arg("-Wno-unused-parameter");
    }
    if cfg!(target_os = "macos") {
        command
            .arg("-dynamiclib")
            .arg("-undefined")
            .arg("dynamic_lookup");
    } else {
        command.arg("-shared");
    }
    command
        .arg("-I")
        .arg(include_profile)
        .arg("-I")
        .arg(common_include)
        .arg(source)
        .arg("-o")
        .arg(binary);
    let description = format!("編譯 {}", source.display());
    let _ = command_output(&mut command, &description);
}

fn prepare_fixture() -> Fixture {
    let repo = repo_root();
    let root = scratch_root();
    let cli_source = PathBuf::from(env!("CARGO_BIN_EXE_rivetlua"))
        .canonicalize()
        .expect("Cargo 提供的 CLI artifact 存在");
    let cli_sha256 = sha256(&cli_source);
    let cli_binary = root.join(format!(
        "rivetlua-{}-{}.bin",
        profile_name(),
        &cli_sha256[..16]
    ));
    fs::copy(&cli_source, &cli_binary).expect("複製 CLI 到隔離 external artifact");
    let mode = fs::metadata(&cli_source)
        .expect("讀取 CLI artifact permissions")
        .permissions()
        .mode();
    fs::set_permissions(&cli_binary, fs::Permissions::from_mode(mode & !0o222))
        .expect("保留 executable permissions 並凍結 CLI snapshot");
    let snapshot_mode = fs::metadata(&cli_binary)
        .expect("讀取 CLI snapshot permissions")
        .permissions()
        .mode();
    assert_ne!(
        snapshot_mode & 0o111,
        0,
        "CLI snapshot 必須保留 executable bit"
    );
    assert_eq!(snapshot_mode & 0o222, 0, "CLI snapshot 必須唯讀");
    assert_eq!(
        sha256(&cli_binary),
        cli_sha256,
        "CLI snapshot SHA 必須與 Cargo 原 artifact 相同"
    );
    let identity = abi::current_identity();
    fs::write(
        root.join("cli-snapshot.txt"),
        format!(
            "profile={}\nartifact_original={}\nartifact_snapshot={}\nartifact_sha256={}\nexpected_native_abi={}\n",
            PROFILE,
            cli_source.display(),
            cli_binary.display(),
            cli_sha256,
            identity_json(identity, GrantMutation::None)
        ),
    )
    .expect("記錄 CLI artifact、SHA 與預期 typed ABI");
    let lib_dir = root.join("libs");
    fs::create_dir_all(&lib_dir).expect("建立 native module 目錄");
    let source_dir = repo.join(format!(
        "vendor/{}/{}-tests/libs",
        PROFILE_DIR,
        match PROFILE_DIR {
            "lua54" => "lua-5.4.9",
            _ => "lua-5.5.1",
        }
    ));
    let include_profile = repo.join(format!("include/rivetlua/{PROFILE_DIR}"));
    let common_include = repo.join("include/rivetlua");
    let module_inputs = [
        (
            "lib1.so",
            "lib1.c",
            &[
                "luaopen_lib1_sub",
                "lib1_export",
                "onefunction",
                "anotherfunc",
            ][..],
            "global",
        ),
        ("lib11.so", "lib11.c", &["luaopen_lib11"][..], "local"),
        ("lib2.so", "lib2.c", &["luaopen_lib2"][..], "global"),
        ("lib21.so", "lib21.c", &["luaopen_lib21"][..], "local"),
        ("lib2-v2.so", "lib22.c", &["luaopen_lib2"][..], "local"),
    ];
    let mut modules = Vec::new();
    for (name, source_name, exports, visibility) in module_inputs {
        let source = source_dir.join(source_name);
        let binary = lib_dir.join(name);
        assert!(
            source.is_file(),
            "官方 C module source 不存在：{}",
            source.display()
        );
        build_shared(&source, &binary, &include_profile, &common_include);
        modules.push(NativeModule {
            name,
            source,
            binary: binary.canonicalize().expect("module binary canonicalize"),
            exports,
            visibility,
            dependencies: Vec::new(),
        });
    }
    let host_source = repo.join("tests/p17/native-fixtures/host_probe.c");
    let host_binary = lib_dir.join("p17probe.so");
    build_shared(
        &host_source,
        &host_binary,
        &include_profile,
        &common_include,
    );
    modules.push(NativeModule {
        name: "p17probe.so",
        source: host_source,
        binary: host_binary.canonicalize().expect("host probe canonicalize"),
        exports: &["luaopen_p17probe"],
        visibility: "local",
        dependencies: Vec::new(),
    });
    let lib1 = modules[0].binary.clone();
    let lib2 = modules[2].binary.clone();
    modules[1].dependencies.push(lib1);
    modules[3].dependencies.push(lib2);

    let sequence = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
    let token = format!("P17_{}_{}_{}", profile_name(), std::process::id(), sequence);
    Fixture {
        repo,
        root,
        cli_binary,
        cli_sha256,
        modules,
        token,
    }
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

fn lua_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\{:03}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn sha256(path: &Path) -> String {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("shasum");
        command.args(["-a", "256"]);
        command
    } else {
        Command::new("sha256sum")
    };
    command.arg(path);
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("計算 {} SHA-256 失敗：{error}", path.display()));
    assert!(
        output.status.success(),
        "SHA-256 指令失敗：{}",
        path.display()
    );
    let body = String::from_utf8(output.stdout).expect("SHA-256 輸出 UTF-8");
    let digest = body.split_whitespace().next().expect("SHA-256 digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    digest.to_ascii_lowercase()
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

fn target_string(target: &[u8]) -> String {
    let end = target
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(target.len());
    String::from_utf8(target[..end].to_vec()).expect("ABI target 是 UTF-8")
}

fn identity_json(identity: AbiIdentity, mutation: GrantMutation) -> String {
    let mut layout = identity.layout.to_vec();
    if matches!(mutation, GrantMutation::WrongAbi) {
        layout[0] = layout[0].wrapping_add(1);
        if layout[0] == identity.layout[0] {
            layout[0] = layout[0].wrapping_sub(1);
        }
    }
    let layout = layout
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
        json_string(&hex(&identity.header_set_sha256)),
        json_string(&hex(&identity.lua_h_sha256)),
        json_string(&hex(&identity.lauxlib_h_sha256)),
        json_string(&hex(&identity.luaconf_h_sha256)),
        layout
    )
}

fn grant_json(fixture: &Fixture, mutation: GrantMutation) -> String {
    let identity = abi::current_identity();
    let target = target_string(&identity.target);
    let header_binding = hex(&identity.header_set_sha256);
    let abi_manifest_sha256 = sha256(&fixture.repo.join("tests/p16/abi-manifest.toml"));
    let grant_profile = match mutation {
        GrantMutation::WrongProfile if PROFILE_DIR == "lua55" => "lua54-i64f64",
        GrantMutation::WrongProfile => "lua55-i64f64",
        _ => PROFILE,
    };
    let grant_target = if matches!(mutation, GrantMutation::WrongTarget) {
        "rivetlua-invalid-target"
    } else {
        &target
    };
    let modules = fixture
        .modules
        .iter()
        .map(|module| {
            let binary_hash = sha256(&module.binary);
            let binary_hash = if matches!(mutation, GrantMutation::WrongProbeHash)
                && module.name == "p17probe.so"
            {
                let replacement = if binary_hash.as_bytes()[0] == b'0' { '1' } else { '0' };
                format!("{replacement}{}", &binary_hash[1..])
            } else {
                binary_hash
            };
            let dependencies = module
                .dependencies
                .iter()
                .map(|dependency| json_string(&dependency.display().to_string()))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"canonical_path\":{},\"sha256\":{},\"source_sha256\":{},\"header_binding\":{},\"abi_identity\":{},\"unwind\":\"CNoUnwind\",\"exports\":[{}],\"visibility\":{},\"dependencies\":[{}]}}",
                json_string(&module.binary.display().to_string()),
                json_string(&binary_hash),
                json_string(&sha256(&module.source)),
                json_string(&header_binding),
                identity_json(identity, mutation),
                module
                    .exports
                    .iter()
                    .map(|symbol| json_string(symbol))
                    .collect::<Vec<_>>()
                    .join(","),
                json_string(module.visibility),
                dependencies
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let cpath = fixture.root.join("libs/?.so");
    format!(
        "{{\"schema\":\"rivetlua-native-grant-v1\",\"profile\":{},\"target\":{},\"abi_manifest_sha256\":{},\"capability\":\"trusted-host-process-permissions-v1\",\"cpath\":[{}],\"modules\":[{}]}}\n",
        json_string(grant_profile),
        json_string(grant_target),
        json_string(&abi_manifest_sha256),
        json_string(&cpath.display().to_string()),
        modules
    )
}

fn write_grant(fixture: &Fixture, mutation: GrantMutation, name: &str) -> PathBuf {
    let path = fixture.root.join(format!("{name}.grant.json"));
    fs::write(&path, grant_json(fixture, mutation)).expect("寫入 process permission grant");
    path.canonicalize().expect("grant path canonicalize")
}

fn run_cli(
    fixture: &Fixture,
    script: &str,
    grant: Option<&Path>,
    label: &str,
    token: &str,
) -> CliResult {
    let stdout_path = fixture.root.join(format!("{label}.stdout.log"));
    let stderr_path = fixture.root.join(format!("{label}.stderr.log"));
    let constructor_marker = fixture.root.join(format!("{label}.constructor.marker"));
    let events = fixture.root.join(format!("{label}.events.log"));
    for path in [&stdout_path, &stderr_path, &constructor_marker, &events] {
        let _ = fs::remove_file(path);
    }
    assert!(
        !constructor_marker.exists(),
        "測試前移除 stale constructor marker"
    );
    let stdout = File::create(&stdout_path).expect("建立 CLI stdout log");
    let stderr = File::create(&stderr_path).expect("建立 CLI stderr log");
    assert_eq!(
        sha256(&fixture.cli_binary),
        fixture.cli_sha256,
        "執行前 CLI snapshot SHA 必須保持不變"
    );
    let mut command = Command::new(&fixture.cli_binary);
    command
        .arg("--profile")
        .arg(profile_name())
        .arg("-e")
        .arg(script)
        .current_dir(&fixture.root)
        .env_remove("RIVETLUA_NATIVE_MANIFEST")
        .env_remove("LUA_INIT")
        .env_remove("LUA_INIT_5_4")
        .env_remove("LUA_INIT_5_5")
        .env_remove("LUA_PATH")
        .env_remove("LUA_PATH_5_4")
        .env_remove("LUA_PATH_5_5")
        .env_remove("LUA_CPATH")
        .env_remove("LUA_CPATH_5_4")
        .env_remove("LUA_CPATH_5_5")
        .env("RIVETLUA_P17_CONSTRUCTOR_MARKER", &constructor_marker)
        .env("RIVETLUA_P17_PROBE_EVENTS", &events)
        .env("RIVETLUA_P17_PROBE_TOKEN", token)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(grant) = grant {
        command.env("RIVETLUA_NATIVE_MANIFEST", grant);
    }
    let mut child = command.spawn().expect("啟動 CLI integration process");
    let started = Instant::now();
    let status = wait_with_watchdog(&mut child, started, &fixture.root, label);
    assert_eq!(
        sha256(&fixture.cli_binary),
        fixture.cli_sha256,
        "執行後 CLI snapshot SHA 必須保持不變"
    );
    let stdout = read_log(&stdout_path);
    let stderr = read_log(&stderr_path);
    CliResult {
        status,
        stdout,
        stderr,
        constructor_marker,
        events,
    }
}

fn wait_with_watchdog(child: &mut Child, started: Instant, root: &Path, label: &str) -> ExitStatus {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if started.elapsed() < CLI_TIMEOUT => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "CLI watchdog 超時：profile={PROFILE} label={label} root={}",
                    root.display()
                );
            }
            Err(error) => panic!("等待 CLI process 失敗：{error}"),
        }
    }
}

fn read_log(path: &Path) -> String {
    let mut file =
        File::open(path).unwrap_or_else(|error| panic!("讀取 {} 失敗：{error}", path.display()));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("讀取 CLI log");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn positive_script(token: &str) -> String {
    let token = lua_string(token);
    let is_lua55 = if PROFILE_DIR == "lua55" {
        "true"
    } else {
        "false"
    };
    format!(
        r#"
local loaded, load_error = package.loadlib("libs/lib1.so", "*")
assert(loaded == true, load_error)

local one = assert(package.loadlib("libs/lib1.so", "onefunction"))
local first, second = one(15, 25)
assert(first == 25 and second == 15)
local another = assert(package.loadlib("libs/lib1.so", "anotherfunc"))
assert(another(10, 20) == "10%20\n")
local missing_symbol, missing_symbol_error, missing_symbol_when = package.loadlib("libs/lib1.so", "xuxu")
assert(not missing_symbol and type(missing_symbol_error) == "string" and missing_symbol_when == "init")
local missing_file, missing_file_error, missing_file_when = package.loadlib("donotexist", "xuxu")
assert(not missing_file and type(missing_file_error) == "string" and missing_file_when == "open")

local lib11_open = assert(package.loadlib("libs/lib11.so", "luaopen_lib11"))
assert(lib11_open() == "exported")

package.cpath = "libs/?.so"
local lib2_v2, lib2_v2_path = require "lib2-v2"
assert(lib2_v2_path == "libs/lib2-v2.so")
assert(package.loaded["lib2-v2"] == lib2_v2)
assert(_G.x == "lib2-v2" and _G.y == "libs/lib2-v2.so")
local version_two, echoed = lib2_v2.id("x")
assert(version_two == true and echoed == "x")
if {is_lua55} then
  local external = lib2_v2.newstr("P17 external string lifetime")
  assert(external == "P17 external string lifetime")
  external = nil
  collectgarbage("collect")
end

local lib2 = require "lib2"
assert(package.loaded.lib2 == lib2)
assert(_G.x == "lib2" and _G.y == "libs/lib2.so")
local left, right = lib2.id("left", "right")
assert(left == "left" and right == "right")
local lib21 = require "lib21"
assert(package.loaded.lib21 == lib21)
assert(_G.x == "lib21" and _G.y == "libs/lib21.so")
assert(lib21.id("linked") == "linked")

local lib1_sub, lib1_path = require "lib1.sub"
assert(lib1_path == "libs/lib1.so")
assert(package.loaded["lib1.sub"] == lib1_sub)
assert(_G.x == "lib1.sub" and _G.y == "libs/lib1.so")
assert(lib1_sub.id(45) == 45)

local open_probe = assert(package.loadlib("libs/p17probe.so", "luaopen_p17probe"))
local probe = open_probe("p17probe", "libs/p17probe.so")
package.loaded.p17probe = probe
assert(package.loaded.p17probe == probe)
assert(_G.P17_NATIVE_TOKEN == {token})
local echo_first, echo_second = probe.echo("callback-left", "callback-right")
assert(echo_first == "callback-left" and echo_second == "callback-right")
local callback_ok, callback_error = pcall(open_probe, "p17probe-error", "libs/p17probe.so")
assert(not callback_ok and string.find(tostring(callback_error), "P17_HOST_PROBE_EXPECTED_ERROR", 1, true))
local finalizable = probe.finalizable()
finalizable = nil
collectgarbage("collect")
collectgarbage("collect")
print("P17_NATIVE_CLI_PASS")
"#
    )
}

fn rejection_script() -> &'static str {
    r#"
local opener, message, when = package.loadlib("libs/p17probe.so", "luaopen_p17probe")
if opener ~= nil then error("P17_NATIVE_UNEXPECTED_SUCCESS", 0) end
assert(type(message) == "string" and #message > 0, "native loader must return a diagnostic")
assert(when == "open", "preflight rejection must be reported before symbol initialization")
print("P17_NATIVE_REJECTED " .. message)
error(message, 0)
"#
}

fn local_visibility_star_rejection_script() -> &'static str {
    r#"
local opener, message, when = package.loadlib("libs/p17probe.so", "*")
assert(opener == nil, "local-visibility module must not be opened with '*'")
assert(type(message) == "string" and string.find(message, "native-grant: visibility", 1, true),
       "local-visibility rejection must report its native grant category")
assert(string.find(message, "global", 1, true),
       "local-visibility rejection must explain the global symbol requirement")
assert(when == "open", "visibility rejection must happen before dlopen")
print("P17_NATIVE_LOCAL_STAR_REJECTED " .. message)
"#
}

#[test]
fn p17_native_cli_loads_official_modules_and_runs_same_vm_host_callbacks() {
    let fixture = prepare_fixture();
    let grant = write_grant(&fixture, GrantMutation::None, "positive");
    let token = fixture.token.clone();
    let result = run_cli(
        &fixture,
        &positive_script(&token),
        Some(&grant),
        "positive",
        &token,
    );
    assert!(
        result.status.success(),
        "profile={PROFILE} exit={:?}\nstdout={}\nstderr={}",
        result.status.code(),
        result.stdout,
        result.stderr
    );
    assert_eq!(
        result
            .stdout
            .lines()
            .filter(|line| *line == "P17_NATIVE_CLI_PASS")
            .count(),
        1,
        "正向 process 必須完成全部 Lua assertion"
    );
    assert_eq!(
        fs::read_to_string(&result.constructor_marker).expect("host probe constructor marker"),
        format!("constructor|{}\n", token)
    );
    let events = fs::read_to_string(&result.events).expect("host probe callback events");
    for event in [
        format!("open|{}|p17probe|libs/p17probe.so", token),
        format!("open|{}|p17probe-error|libs/p17probe.so", token),
        format!("finalizer|{}", token),
    ] {
        assert_eq!(
            events.lines().filter(|line| *line == event).count(),
            1,
            "缺少或重複 host callback side effect：{event}"
        );
    }
}

#[test]
fn p17_native_cli_rejects_missing_or_mismatched_grants_before_dlopen() {
    let fixture = prepare_fixture();
    let cases = [
        ("no-grant", None, "native-grant: preflight"),
        (
            "wrong-profile",
            Some(GrantMutation::WrongProfile),
            "native-grant: profile",
        ),
        (
            "wrong-target",
            Some(GrantMutation::WrongTarget),
            "native-grant: target",
        ),
        (
            "wrong-abi",
            Some(GrantMutation::WrongAbi),
            "native-grant: abi",
        ),
        (
            "wrong-hash",
            Some(GrantMutation::WrongProbeHash),
            "native-grant: digest",
        ),
    ];
    for (label, mutation, expected_category) in cases {
        let grant = mutation.map(|mutation| write_grant(&fixture, mutation, label));
        let token = format!("{}_{}", fixture.token, label);
        let result = run_cli(
            &fixture,
            rejection_script(),
            grant.as_deref(),
            label,
            &token,
        );
        assert!(
            !result.status.success(),
            "profile={PROFILE} case={label} 必須拒絕 native load"
        );
        let diagnostics = format!("{}\n{}", result.stdout, result.stderr);
        assert!(
            diagnostics.contains(expected_category),
            "profile={PROFILE} case={label} 未回報明確 native grant 類別 {expected_category}：{diagnostics}"
        );
        if mutation.is_none() {
            assert!(
                result
                    .stdout
                    .lines()
                    .any(|line| line.starts_with("P17_NATIVE_REJECTED ")),
                "無 grant 必須透過公開 package.loadlib 回傳診斷並維持 when=open：{}",
                result.stdout
            );
        }
        assert!(
            !result.constructor_marker.exists(),
            "profile={PROFILE} case={label} 在 preflight 拒絕前執行了 native constructor"
        );
        assert!(
            !result.events.exists(),
            "profile={PROFILE} case={label} 在 preflight 拒絕前進入了 opener"
        );
    }
}

#[test]
fn p17_native_cli_rejects_local_visibility_star_before_dlopen() {
    let fixture = prepare_fixture();
    let grant = write_grant(&fixture, GrantMutation::None, "local-star");
    let token = format!("{}_local-star", fixture.token);
    let result = run_cli(
        &fixture,
        local_visibility_star_rejection_script(),
        Some(&grant),
        "local-star",
        &token,
    );
    assert!(
        result.status.success(),
        "profile={PROFILE} exit={:?}\nstdout={}\nstderr={}",
        result.status.code(),
        result.stdout,
        result.stderr
    );
    assert_eq!(
        result
            .stdout
            .lines()
            .filter(|line| line
                .starts_with("P17_NATIVE_LOCAL_STAR_REJECTED native-grant: visibility")
                && line.contains("global"))
            .count(),
        1,
        "成功只代表具名 visibility refusal assertion 完整執行"
    );
    assert!(
        !result.constructor_marker.exists(),
        "local-visibility '*' 拒絕必須發生在 native constructor 前"
    );
    assert!(
        !result.events.exists(),
        "local-visibility '*' 拒絕不得進入 native opener 或 finalizer"
    );
}
