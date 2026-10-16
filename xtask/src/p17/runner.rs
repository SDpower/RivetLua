use super::grant::{self, ValidatedAbi};
use super::manifest::{self, Profile};
use super::report::{Check, Input, NegativeRun, Report};
use crate::{StrictJsonParser, StrictJsonValue};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn collect_rust_sources(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("P17 source 目錄不可讀：{error}"))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        let kind = fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            collect_rust_sources(&path, found)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        } else if kind.is_symlink() {
            return Err(format!(
                "P17 producer source 含 symlink：{}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn collect_fixture_sources(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("P17 fixture 目錄不可讀：{error}"))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        let kind = fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            collect_fixture_sources(&path, found)?;
        } else if kind.is_file() {
            found.push(path);
        } else {
            return Err(format!("P17 fixture 含非一般檔案：{}", path.display()));
        }
    }
    Ok(())
}

pub(super) fn related_sources(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = [
        "Cargo.toml",
        "Cargo.lock",
        "xtask/Cargo.toml",
        "xtask/src/main.rs",
        "xtask/src/p17/mod.rs",
        "xtask/src/p17/grant.rs",
        "xtask/src/p17/manifest.rs",
        "xtask/src/p17/report.rs",
        "xtask/src/p17/runner.rs",
        "xtask/tests/p17_cli.rs",
        "tests/p17/runner-manifest.toml",
        "tests/p17/modules/driver.c",
        "tests/p17/modules/runner_ok.lua",
        "tests/p17/modules/runner_fail.lua",
        "tests/p17/modules/cli_native_load.lua",
        "tests/p17/modules/cli_native_reject.lua",
        "tests/p17/fixtures/counterexample-fake-pass-zero-matches.json",
        "tests/p17/fixtures/counterexample-fake-pass-wrong-profiles.json",
        "tests/p17/fixtures/counterexample-fake-pass-out-of-scope.json",
        "tests/p17/fixtures/counterexample-fake-pass-missing-hash.json",
        "crates/rivetlua-cli/tests/p17_native_modules.rs",
        "tests/p17/native-fixtures/host_probe.c",
        "tests/p16/abi-manifest.toml",
        "include/rivetlua/rivetlua_abi.h",
        "crates/rivetlua-capi/src/trampoline.c",
        "crates/rivetlua-capi/src/native/platform.c",
    ]
    .iter()
    .map(|relative| root.join(relative))
    .collect::<Vec<_>>();
    for crate_name in [
        "rivetlua-core",
        "rivetlua-compiler",
        "rivetlua-runtime",
        "rivetlua",
        "rivetlua-cli",
        "rivetlua-capi",
    ] {
        let crate_dir = root.join("crates").join(crate_name);
        found.push(crate_dir.join("Cargo.toml"));
        let build = crate_dir.join("build.rs");
        if build.is_file() {
            found.push(build);
        }
        collect_rust_sources(&crate_dir.join("src"), &mut found)?;
    }
    for profile in manifest::PROFILES {
        for relative in [profile.tarball, profile.libs_makefile] {
            found.push(root.join(relative));
        }
        collect_fixture_sources(&root.join(profile.suite), &mut found)?;
        for name in ["lua.h", "lauxlib.h", "luaconf.h"] {
            found.push(root.join(profile.header_dir).join(name));
        }
    }
    found.sort();
    found.dedup();
    for path in &found {
        if !path.is_file() {
            return Err(format!("P17 producer source 缺失：{}", path.display()));
        }
    }
    Ok(found)
}

pub(super) struct Environment {
    pub target_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub target: String,
}

pub(super) fn toolchain_identity() -> Result<String, String> {
    let mut values = Vec::new();
    for name in ["rustc", "cargo", "cc"] {
        let output = Command::new(name)
            .arg("--version")
            .output()
            .map_err(|error| format!("P17 {name} version 無法啟動：{error}"))?;
        if !output.status.success() {
            return Err(format!("P17 {name} version 非零退出"));
        }
        let first = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
        if first.is_empty() {
            return Err(format!("P17 {name} version 為空"));
        }
        values.push(format!("{name}={first}"));
    }
    Ok(values.join("\n"))
}

pub(super) fn related_environment(env: &Environment) -> Vec<(String, String)> {
    let mut values = vec![
        (
            "CARGO_TARGET_DIR".into(),
            env.target_dir.display().to_string(),
        ),
        (
            "RIVETLUA_P17_EVIDENCE_DIR".into(),
            env.evidence_dir.display().to_string(),
        ),
        (
            "SDK_HOST_TRUST".into(),
            "explicit-sdk-host-process-permissions-v1".into(),
        ),
    ];
    for key in [
        "TMPDIR",
        "PATH",
        "_U",
        "LUA_INIT",
        "LUA_INIT_5_4",
        "LUA_INIT_5_5",
        "LUA_PATH",
        "LUA_PATH_5_4",
        "LUA_PATH_5_5",
        "LUA_CPATH",
        "LUA_CPATH_5_4",
        "LUA_CPATH_5_5",
        "RIVETLUA_NATIVE_MANIFEST",
        "CARGO_BUILD_TARGET",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC",
        "CC",
        "CFLAGS",
        "AR",
        "ARFLAGS",
        "CC_aarch64-apple-darwin",
        "CC_aarch64_apple_darwin",
        "CFLAGS_aarch64-apple-darwin",
        "CFLAGS_aarch64_apple_darwin",
        "AR_aarch64-apple-darwin",
        "AR_aarch64_apple_darwin",
        "ARFLAGS_aarch64-apple-darwin",
        "ARFLAGS_aarch64_apple_darwin",
        "HOST_CC",
        "HOST_CFLAGS",
        "HOST_AR",
        "HOST_ARFLAGS",
        "TARGET_CC",
        "TARGET_CFLAGS",
        "TARGET_AR",
        "TARGET_ARFLAGS",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
    ] {
        values.push((
            key.into(),
            std::env::var(key)
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unset".into()),
        ));
    }
    values
}

fn external_dir(root: &Path, key: &str) -> Result<PathBuf, String> {
    let raw = env::var_os(key).ok_or_else(|| format!("P17 缺少 {key}"))?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!("P17 {key} 必須是絕對路徑"));
    }
    let path = fs::canonicalize(&path).map_err(|error| format!("P17 {key} 無效：{error}"))?;
    if !path.is_dir()
        || path.starts_with(fs::canonicalize(root).map_err(|error| error.to_string())?)
    {
        return Err(format!("P17 {key} 必須是 workspace 外部既有目錄"));
    }
    Ok(path)
}

pub(super) fn environment(root: &Path) -> Result<Environment, String> {
    let target_dir = external_dir(root, "CARGO_TARGET_DIR")?;
    let evidence_dir = external_dir(root, "RIVETLUA_P17_EVIDENCE_DIR")?;
    for key in ["_U", "LUA_INIT", "LUA_INIT_5_4", "LUA_INIT_5_5"] {
        if env::var_os(key).is_some_and(|value| !value.is_empty()) {
            return Err(format!("P17 不接受非空 {key}"));
        }
    }
    let target = format!("{}-{}-{}", std::env::consts::ARCH, "apple", "darwin");
    if target != "aarch64-apple-darwin" {
        return Err(format!("P17 B01 尚未驗證此 host target：{target}"));
    }
    if env::var("CARGO_BUILD_TARGET")
        .ok()
        .is_some_and(|configured| configured != target)
    {
        return Err("P17 CARGO_BUILD_TARGET 與 host ABI 不符".into());
    }
    Ok(Environment {
        target_dir,
        evidence_dir,
        target,
    })
}

pub(super) fn binding(
    expected: Profile,
    profile: &str,
    release: &str,
    tarball_sha: &str,
    all_lua_sha: &str,
    binary_sha: &str,
    recorded_binary_sha: &str,
    abi_sha: &str,
    recorded_abi_sha: &str,
) -> Result<(), String> {
    if profile != expected.name {
        return Err("P17 profile mismatch".into());
    }
    if release != expected.release {
        return Err("P17 release mismatch".into());
    }
    if tarball_sha != expected.tarball_sha256 || all_lua_sha != expected.all_lua_sha256 {
        return Err("P17 fixture hash mismatch".into());
    }
    if binary_sha.len() != 64 || binary_sha != recorded_binary_sha {
        return Err("P17 binary hash mismatch".into());
    }
    if abi_sha.len() != 64 || abi_sha != recorded_abi_sha {
        return Err("P17 SDK ABI hash mismatch".into());
    }
    Ok(())
}

pub(super) fn negative_controls(profile: Profile, binary_sha: &str, abi_sha: &str) -> bool {
    let accept = |name: &str,
                  release: &str,
                  tar: &str,
                  all: &str,
                  binary: &str,
                  recorded: &str,
                  abi: &str,
                  recorded_abi: &str| {
        binding(
            profile,
            name,
            release,
            tar,
            all,
            binary,
            recorded,
            abi,
            recorded_abi,
        )
        .is_err()
    };
    accept(
        "wrong-profile",
        profile.release,
        profile.tarball_sha256,
        profile.all_lua_sha256,
        binary_sha,
        binary_sha,
        abi_sha,
        abi_sha,
    ) && accept(
        profile.name,
        "wrong-release",
        profile.tarball_sha256,
        profile.all_lua_sha256,
        binary_sha,
        binary_sha,
        abi_sha,
        abi_sha,
    ) && accept(
        profile.name,
        profile.release,
        "wrong-tar",
        profile.all_lua_sha256,
        binary_sha,
        binary_sha,
        abi_sha,
        abi_sha,
    ) && accept(
        profile.name,
        profile.release,
        profile.tarball_sha256,
        "wrong-all",
        binary_sha,
        binary_sha,
        abi_sha,
        abi_sha,
    ) && accept(
        profile.name,
        profile.release,
        profile.tarball_sha256,
        profile.all_lua_sha256,
        "wrong-binary",
        binary_sha,
        abi_sha,
        abi_sha,
    ) && accept(
        profile.name,
        profile.release,
        profile.tarball_sha256,
        profile.all_lua_sha256,
        binary_sha,
        binary_sha,
        "wrong-abi",
        abi_sha,
    )
}

struct Output {
    exit_code: Option<i32>,
    body: String,
}

fn invoke(cwd: &Path, command: &[String], log: &Path, uninit: bool) -> Result<Output, String> {
    invoke_with_native(cwd, command, log, uninit, None)
}

fn lua_clean_keys() -> &'static [&'static str] {
    &[
        "_U",
        "LUA_INIT",
        "LUA_INIT_5_4",
        "LUA_INIT_5_5",
        "LUA_PATH",
        "LUA_PATH_5_4",
        "LUA_PATH_5_5",
        "LUA_CPATH",
        "LUA_CPATH_5_4",
        "LUA_CPATH_5_5",
    ]
}

pub(super) fn effective_native_environment(grant: &Path) -> Vec<(String, String)> {
    let mut values = lua_clean_keys()
        .iter()
        .map(|name| ((*name).to_owned(), "unset".into()))
        .collect::<Vec<_>>();
    values.push((
        "RIVETLUA_NATIVE_MANIFEST".into(),
        grant.display().to_string(),
    ));
    values
}

pub(super) fn effective_no_native_environment() -> Vec<(String, String)> {
    let mut values = lua_clean_keys()
        .iter()
        .map(|name| ((*name).to_owned(), "unset".into()))
        .collect::<Vec<_>>();
    values.push(("RIVETLUA_NATIVE_MANIFEST".into(), "unset".into()));
    values
}

fn invoke_with_native(
    cwd: &Path,
    command: &[String],
    log: &Path,
    uninit: bool,
    native_grant: Option<&Path>,
) -> Result<Output, String> {
    let (program, args) = command.split_first().ok_or("P17 空命令")?;
    let mut process = Command::new(program);
    process.args(args).current_dir(cwd);
    process.env_remove("RIVETLUA_NATIVE_MANIFEST");
    if uninit {
        for name in lua_clean_keys() {
            process.env_remove(name);
        }
    }
    if let Some(grant) = native_grant {
        if !uninit || !grant.is_absolute() {
            return Err("P17 native CLI 必須清除 Lua 環境並注入絕對 grant".into());
        }
        process.env("RIVETLUA_NATIVE_MANIFEST", grant);
    }
    let output = process
        .output()
        .map_err(|error| format!("P17 {} 啟動失敗：{error}", program))?;
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    fs::write(log, &bytes).map_err(|error| format!("P17 log 寫入失敗：{error}"))?;
    Ok(Output {
        exit_code: output.status.code(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

fn observed(
    report: &mut Report,
    facet: &str,
    profile: Profile,
    command: Vec<String>,
    cwd: &Path,
    log: &Path,
    output: &Output,
    pass: bool,
    diagnostic: &str,
) -> Result<(), String> {
    report.checks.push(Check::observed(
        facet,
        profile.name,
        command,
        cwd,
        output.exit_code,
        Some(Input::from_path(log)?),
        pass,
        diagnostic,
    ));
    if pass {
        Ok(())
    } else {
        Err(format!("P17 {} {}：{diagnostic}", profile.name, facet))
    }
}

pub(super) fn cargo_artifact(log: &str, name: &str, kind: &str) -> Result<PathBuf, String> {
    let mut found = None;
    for line in log.lines() {
        let Ok(value) = StrictJsonParser::parse(line) else {
            continue;
        };
        if value.get("reason").and_then(StrictJsonValue::as_str) != Some("compiler-artifact")
            || value
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(StrictJsonValue::as_str)
                != Some(name)
        {
            continue;
        }
        let target = value.get("target").ok_or("P17 Cargo artifact 缺 target")?;
        let types = target
            .get(if kind == "bin" { "kind" } else { "crate_types" })
            .and_then(StrictJsonValue::as_array)
            .ok_or("P17 Cargo artifact 缺 kind")?;
        if !types.iter().any(|entry| entry.as_str() == Some(kind)) {
            continue;
        }
        let candidate = if kind == "bin" {
            value
                .get("executable")
                .and_then(StrictJsonValue::as_str)
                .map(PathBuf::from)
        } else {
            value
                .get("filenames")
                .and_then(StrictJsonValue::as_array)
                .and_then(|files| {
                    files
                        .iter()
                        .filter_map(StrictJsonValue::as_str)
                        .find(|file| {
                            Path::new(file).file_name().and_then(|n| n.to_str())
                                == Some("librivetlua_capi.a")
                        })
                })
                .map(PathBuf::from)
        };
        if let Some(path) = candidate {
            if found.replace(path).is_some() {
                return Err("P17 Cargo artifact 重複".into());
            }
        }
    }
    found.ok_or_else(|| format!("P17 Cargo 缺 {name} {kind} artifact"))
}

pub(super) fn native_libs(log: &str) -> Result<Vec<String>, String> {
    let mut found = None;
    for line in log.lines() {
        let rendered = if let Ok(value) = StrictJsonParser::parse(line) {
            value
                .get("message")
                .and_then(|v| v.get("rendered"))
                .and_then(StrictJsonValue::as_str)
                .unwrap_or("")
                .to_owned()
        } else {
            line.to_owned()
        };
        for line in rendered.lines() {
            if let Some((_, flags)) = line.split_once("native-static-libs:") {
                let flags = flags
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if flags.is_empty() || found.as_ref().is_some_and(|prior| prior != &flags) {
                    return Err("P17 native-static-libs 空白或矛盾".into());
                }
                found = Some(flags);
            }
        }
    }
    let flags: Vec<String> = found.ok_or("P17 缺 native-static-libs")?;
    let mut framework_name = false;
    for flag in &flags {
        if framework_name {
            if flag.starts_with('-')
                || !flag
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err("P17 native framework 名稱無效".into());
            }
            framework_name = false;
        } else if flag == "-framework" {
            framework_name = true;
        } else if !((flag.starts_with("-l") && flag.len() > 2)
            || flag.starts_with("-L")
            || flag == "-pthread"
            || flag.starts_with("-Wl,"))
            || flag.to_ascii_lowercase().contains("lua")
        {
            return Err(format!("P17 native-static-libs 不允許 {flag}"));
        }
    }
    if framework_name {
        return Err("P17 native framework 缺名稱".into());
    }
    Ok(flags)
}

pub(super) fn cli_build_command(profile: Profile) -> Vec<String> {
    let mut command = [
        "cargo",
        "build",
        "--locked",
        "-p",
        "rivetlua-cli",
        "--bin",
        "rivetlua",
        "--message-format=json-render-diagnostics",
    ]
    .map(str::to_owned)
    .to_vec();
    command.extend([
        "--features".into(),
        if profile.name == "lua54-i64f64" {
            "default-lua54,native-lua54".into()
        } else {
            "native-lua55".into()
        },
    ]);
    command
}

pub(super) fn capi_build_command(profile: Profile) -> Vec<String> {
    let mut command = [
        "cargo",
        "rustc",
        "--locked",
        "-p",
        "rivetlua-capi",
        "--lib",
        "--message-format=json-render-diagnostics",
    ]
    .map(str::to_owned)
    .to_vec();
    if profile.name == "lua54-i64f64" {
        command.extend([
            "--no-default-features".into(),
            "--features".into(),
            "lua54".into(),
        ]);
    }
    command.extend(["--".into(), "--print=native-static-libs".into()]);
    command
}

pub(super) fn module_build_command(
    root: &Path,
    profile: Profile,
    index: usize,
    source: &Path,
    destination: &Path,
) -> Vec<String> {
    let mut command = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-fPIC".into(),
    ];
    if profile.name == "lua55-i64f64" && index == 4 {
        command.push("-Wno-unused-parameter".into());
    }
    command.extend([
        "-dynamiclib".into(),
        "-undefined".into(),
        "dynamic_lookup".into(),
        "-I".into(),
        root.join(profile.header_dir).display().to_string(),
        "-I".into(),
        root.join("include/rivetlua").display().to_string(),
        source.display().to_string(),
        "-o".into(),
        destination.display().to_string(),
    ]);
    command
}

pub(super) fn driver_build_command(
    root: &Path,
    profile: Profile,
    source: &Path,
    library: &Path,
    native_flags: &[String],
    driver: &Path,
) -> Vec<String> {
    let mut command = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-I".into(),
        root.join(profile.header_dir).display().to_string(),
        "-I".into(),
        root.join("include/rivetlua").display().to_string(),
        source.display().to_string(),
        format!("-Wl,-force_load,{}", library.display()),
        "-Wl,-export_dynamic".into(),
    ];
    command.extend(native_flags.iter().cloned());
    command.extend(["-o".into(), driver.display().to_string()]);
    command
}

fn snapshot(path: &Path, work: &Path, name: &str, target_dir: &Path) -> Result<PathBuf, String> {
    let source = fs::canonicalize(path).map_err(|error| error.to_string())?;
    if !source.starts_with(target_dir) || !source.is_file() {
        return Err("P17 Cargo artifact 位於共享 target 以外或不是檔案".into());
    }
    let before = manifest::sha256(&source)?;
    let destination = work.join(name);
    fs::copy(&source, &destination).map_err(|error| error.to_string())?;
    if manifest::sha256(&destination)? != before {
        return Err("P17 profile 專屬 snapshot SHA 不符".into());
    }
    Ok(destination)
}

fn build_artifact(
    root: &Path,
    work: &Path,
    env: &Environment,
    profile: Profile,
    report: &mut Report,
    binary: bool,
) -> Result<(PathBuf, Vec<String>), String> {
    let facet = if binary { "binary" } else { "abi" };
    let command = if binary {
        cli_build_command(profile)
    } else {
        capi_build_command(profile)
    };
    let log = work.join(if binary {
        "cli-build.log"
    } else {
        "capi-build.log"
    });
    let output = invoke(root, &command, &log, false)?;
    observed(
        report,
        facet,
        profile,
        command,
        root,
        &log,
        &output,
        output.exit_code == Some(0),
        "Cargo artifact 建置",
    )?;
    let artifact = cargo_artifact(
        &output.body,
        if binary { "rivetlua" } else { "rivetlua_capi" },
        if binary { "bin" } else { "staticlib" },
    )?;
    let copied = snapshot(
        &artifact,
        work,
        if binary {
            "rivetlua"
        } else {
            "librivetlua_capi.a"
        },
        &env.target_dir,
    )?;
    report.input(&copied)?;
    let snapshot_input = Input::from_path(&copied)?;
    let check = report
        .checks
        .last_mut()
        .ok_or("P17 Cargo build check 缺失")?;
    check.diagnostic = format!(
        "Cargo artifact={} immutable_snapshot_sha256={}",
        artifact.display(),
        snapshot_input.sha256
    );
    check.inputs.push(snapshot_input);
    let flags = if binary {
        Vec::new()
    } else {
        native_libs(&output.body)?
    };
    Ok((copied, flags))
}

fn exact_lines(body: &str, expected: &[String]) -> bool {
    expected
        .iter()
        .all(|needle| body.lines().filter(|line| line == needle).count() == 1)
}

fn profile_work(env: &Environment, profile: Profile) -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let work = env
        .evidence_dir
        .join(format!("b01-{}-{}-{now}", profile.name, std::process::id()));
    fs::create_dir_all(&work).map_err(|error| error.to_string())?;
    Ok(work)
}

pub(super) fn run_profile(
    root: &Path,
    env: &Environment,
    profile: Profile,
    report: &mut Report,
) -> Result<(), String> {
    let work = profile_work(env, profile)?;
    let suite = manifest::verify_fixture(root, profile, &work.join("fixture"))?;
    for path in [
        root.join(profile.tarball),
        root.join(profile.suite).join("all.lua"),
        root.join(profile.libs_makefile),
    ] {
        report.input(&path)?;
    }
    let fixture_log = work.join("fixture.log");
    fs::write(
        &fixture_log,
        format!(
            "P17_FIXTURE {} tar={} all={} canonical_tree=exact PASS\n",
            profile.name, profile.tarball_sha256, profile.all_lua_sha256
        ),
    )
    .map_err(|error| error.to_string())?;
    let mut fixture = Check::observed(
        "fixture",
        profile.name,
        vec![
            "tar".into(),
            "-xzf".into(),
            root.join(profile.tarball).display().to_string(),
            "-C".into(),
            work.join("fixture").display().to_string(),
        ],
        root,
        Some(0),
        Some(Input::from_path(&fixture_log)?),
        true,
        "全樹與固定 SHA 一致",
    );
    fixture.inputs = vec![
        Input::from_path(&root.join(profile.tarball))?,
        Input::from_path(&root.join(profile.suite).join("all.lua"))?,
    ];
    report.checks.push(fixture);
    let (binary, _) = build_artifact(root, &work, env, profile, report, true)?;
    let binary_sha = manifest::sha256(&binary)?;
    let version_command = vec![binary.display().to_string(), "-v".into()];
    let version_log = work.join("cli-version.log");
    let version = invoke(root, &version_command, &version_log, true)?;
    let version_ok = version.exit_code == Some(0) && version.body.trim() == profile.version;
    observed(
        report,
        "profile",
        profile,
        version_command,
        root,
        &version_log,
        &version,
        version_ok,
        "CLI release/profile 身分",
    )?;
    report
        .checks
        .last_mut()
        .ok_or("P17 profile check 缺失")?
        .inputs = vec![Input::from_path(&binary)?];
    let (library, native_flags) = build_artifact(root, &work, env, profile, report, false)?;
    let abi_header = root.join("include/rivetlua/rivetlua_abi.h");
    let abi_sha = manifest::sha256(&abi_header)?;
    report.input(&abi_header)?;
    for name in ["lua.h", "lauxlib.h", "luaconf.h"] {
        report.input(&root.join(profile.header_dir).join(name))?;
    }
    binding(
        profile,
        profile.name,
        profile.release,
        profile.tarball_sha256,
        profile.all_lua_sha256,
        &binary_sha,
        &manifest::sha256(&binary)?,
        &abi_sha,
        &manifest::sha256(&abi_header)?,
    )?;
    if !negative_controls(profile, &binary_sha, &abi_sha) {
        return Err("P17 preflight 負向控制未拒絕錯配".into());
    }
    let modules = build_modules(root, &work, env, profile, report, &library, &native_flags)?;
    runner_controls(root, &work, profile, report, &binary, &suite)?;
    let legal_grant = native_cli_load(
        root, &work, profile, report, &binary, &library, &suite, &modules,
    )?;
    run_negative_controls(
        root,
        &work,
        profile,
        report,
        &binary,
        &abi_header,
        &suite,
        &modules.built,
        &legal_grant,
    )?;
    Ok(())
}

struct ModuleArtifacts {
    built: [PathBuf; 5],
    packages: [PathBuf; 2],
    driver: PathBuf,
    abi_log: PathBuf,
    abi: ValidatedAbi,
}

pub(super) fn native_cli_command(
    root: &Path,
    binary: &Path,
    profile: Profile,
    nonce: &str,
) -> Vec<String> {
    vec![
        binary.display().to_string(),
        root.join("tests/p17/modules/cli_native_load.lua")
            .display()
            .to_string(),
        profile.name.into(),
        nonce.into(),
    ]
}

pub(super) const NEGATIVE_CASES: [(&str, &str); 5] = [
    ("no-grant", "native-grant: preflight"),
    ("wrong-profile", "native-grant: profile"),
    ("wrong-target", "native-grant: target"),
    ("wrong-abi", "native-grant: abi"),
    ("wrong-hash", "native-grant: digest"),
];

pub(super) fn native_reject_command(
    root: &Path,
    binary: &Path,
    profile: Profile,
    label: &str,
) -> Vec<String> {
    vec![
        binary.display().to_string(),
        root.join("tests/p17/modules/cli_native_reject.lua")
            .display()
            .to_string(),
        label.into(),
        profile.name.into(),
    ]
}

pub(super) fn negative_grant_path(work: &Path, label: &str) -> PathBuf {
    work.join(format!("p17-native-{label}.json"))
}

pub(super) fn negative_log_pass(body: &str, label: &str, profile: Profile, category: &str) -> bool {
    let marker = format!("P17_NATIVE_REJECT no-grant {} PASS", profile.name);
    body.contains(category)
        && !body.contains("P17_NATIVE_UNEXPECTED_SUCCESS")
        && !body.contains("P17_NATIVE_FIVE")
        && !body.contains("P17_NATIVE_P1")
        && !body.contains("panicked at")
        && !body.contains("P17_SDK_FAIL")
        && if label == "no-grant" {
            body.lines().filter(|line| *line == marker).count() == 1
        } else {
            !body.contains("P17_NATIVE_REJECT")
                && !body.contains("P17 bad grant must fail before script execution")
        }
}

fn run_negative_controls(
    root: &Path,
    work: &Path,
    profile: Profile,
    report: &mut Report,
    binary: &Path,
    abi_header: &Path,
    suite: &Path,
    modules: &[PathBuf; 5],
    legal_grant: &Path,
) -> Result<(), String> {
    let script = root.join("tests/p17/modules/cli_native_reject.lua");
    report.input(&script)?;
    let legal = fs::read_to_string(legal_grant).map_err(|error| error.to_string())?;
    let first_sha = manifest::sha256(&modules[0])?;
    let abi_manifest_sha = manifest::sha256(&root.join("tests/p16/abi-manifest.toml"))?;
    let mut runs = Vec::new();
    let mut inputs = vec![
        Input::from_path(binary)?,
        Input::from_path(abi_header)?,
        Input::from_path(&script)?,
        Input::from_path(legal_grant)?,
    ];
    inputs.extend(
        modules
            .iter()
            .map(|path| Input::from_path(path))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut passed = 1u32;
    let mut summary = format!(
        "P17_NEGATIVE_BINDING {} profile release tar all binary abi PASS\n",
        profile.name
    );
    for (label, category) in NEGATIVE_CASES {
        let grant_path = if label == "no-grant" {
            None
        } else {
            let path = negative_grant_path(work, label);
            let variant = grant::rejected_variant(
                &legal,
                profile,
                label,
                &modules[0],
                &first_sha,
                &abi_manifest_sha,
            )?;
            fs::write(&path, variant).map_err(|error| error.to_string())?;
            report.input(&path)?;
            inputs.push(Input::from_path(&path)?);
            Some(path)
        };
        let command = native_reject_command(root, binary, profile, label);
        let log = work.join(format!("negative-{label}.log"));
        let output = invoke_with_native(suite, &command, &log, true, grant_path.as_deref())?;
        let accepted = output.exit_code.is_some_and(|code| code != 0)
            && negative_log_pass(&output.body, label, profile, category);
        passed += u32::from(accepted);
        let log_input = Input::from_path(&log)?;
        let grant_input = grant_path.as_deref().map(Input::from_path).transpose()?;
        summary.push_str(&format!(
            "P17_NEGATIVE_CLI {} {label} category={category} exit={:?} log_sha256={} {}\n",
            profile.name,
            output.exit_code,
            log_input.sha256,
            if accepted { "PASS" } else { "FAIL" },
        ));
        runs.push(NegativeRun {
            label,
            command,
            cwd: suite.display().to_string(),
            exit_code: output.exit_code,
            log: log_input,
            grant: grant_input,
            environment: grant_path.as_deref().map_or_else(
                effective_no_native_environment,
                effective_native_environment,
            ),
            expected_category: category,
            status: if accepted { "PASS" } else { "FAIL" },
        });
    }
    let log = work.join("negative-controls.log");
    fs::write(&log, summary).map_err(|error| error.to_string())?;
    let mut check = Check::observed(
        "negative-controls",
        profile.name,
        vec!["P17 binding negative controls and CLI native preflight".into()],
        root,
        Some(if passed == 6 { 0 } else { 1 }),
        Some(Input::from_path(&log)?),
        passed == 6,
        "fixture/release/binary binding 與 no-grant/profile/target/ABI/digest CLI 預檢拒絕",
    );
    check.matched = 6;
    check.passed = passed;
    check.failed = 6 - passed;
    check.negative_runs = runs;
    check.inputs = inputs;
    report.checks.push(check);
    if passed == 6 {
        Ok(())
    } else {
        Err(format!(
            "P17 {} native negative control 未全部拒絕",
            profile.name
        ))
    }
}

fn native_cli_load(
    root: &Path,
    work: &Path,
    profile: Profile,
    report: &mut Report,
    binary: &Path,
    library: &Path,
    suite: &Path,
    artifacts: &ModuleArtifacts,
) -> Result<PathBuf, String> {
    let nonce = work
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("P17 native work 名稱無效")?;
    let script = root.join("tests/p17/modules/cli_native_load.lua");
    let grant_path = work.join("p17-native-grant.json");
    grant::write(
        root,
        profile,
        &artifacts.abi,
        suite,
        &artifacts.built,
        &grant_path,
    )?;
    let grant_sha_before = manifest::sha256(&grant_path)?;
    report.input(&script)?;
    report.input(&grant_path)?;
    let command = native_cli_command(root, binary, profile, nonce);
    let log = work.join("cli-native-load.log");
    let output = invoke_with_native(suite, &command, &log, true, Some(&grant_path))?;
    let expected = [
        format!("P17_NATIVE_FIVE {} {nonce} PASS", profile.name),
        format!("P17_NATIVE_P1 {} {nonce} PASS", profile.name),
    ];
    let passed = output.exit_code == Some(0)
        && exact_lines(&output.body, &expected)
        && manifest::sha256(&grant_path)? == grant_sha_before;
    let mut check = Check::observed(
        "module-load",
        profile.name,
        command,
        suite,
        output.exit_code,
        Some(Input::from_path(&log)?),
        passed,
        "CLI 同一 Rust VM 真載入官方五 C module、公開效果與 P1 隔離",
    );
    check.operation = "cli-native-load";
    check.execution_path = "cli-rust-vm";
    check.environment = effective_native_environment(&grant_path);
    let mut inputs = vec![
        Input::from_path(binary)?,
        Input::from_path(&grant_path)?,
        Input::from_path(&script)?,
        Input::from_path(&artifacts.abi_log)?,
        Input::from_path(&artifacts.driver)?,
        Input::from_path(library)?,
    ];
    inputs.extend(
        artifacts
            .built
            .iter()
            .chain(artifacts.packages.iter())
            .map(|path| Input::from_path(path))
            .collect::<Result<Vec<_>, _>>()?,
    );
    report.checks.push(check);
    report
        .checks
        .last_mut()
        .ok_or("P17 CLI native check 缺失")?
        .inputs = inputs;
    if passed {
        Ok(grant_path)
    } else {
        Err(format!(
            "P17 {} CLI 同 VM native module 效果失敗",
            profile.name
        ))
    }
}

fn build_modules(
    root: &Path,
    work: &Path,
    _env: &Environment,
    profile: Profile,
    report: &mut Report,
    library: &Path,
    native_flags: &[String],
) -> Result<ModuleArtifacts, String> {
    let libs = work
        .join("fixture")
        .join(
            Path::new(profile.suite)
                .file_name()
                .ok_or("P17 suite 名稱缺失")?,
        )
        .join("libs");
    let makefile = fs::read_to_string(root.join(profile.libs_makefile))
        .map_err(|error| format!("P17 libs/makefile 不可讀：{error}"))?;
    let all = "all: lib1.so lib11.so lib2.so lib21.so lib2-v2.so";
    if makefile.lines().filter(|line| *line == all).count() != 1 {
        return Err(format!("P17 {} 官方五模組目標變更", profile.name));
    }
    let mut built = Vec::new();
    for (index, &(name, source_name)) in manifest::MODULES.iter().enumerate() {
        let rule = format!(
            "{name}: {} $(LUA_DIR)/luaconf.h $(LUA_DIR)/lua.h",
            if name == "lib2-v2.so" {
                "lib21.c"
            } else {
                source_name
            }
        );
        let command_line = format!("$(CC) $(CFLAGS) -o {name} {source_name}");
        if makefile.lines().filter(|line| *line == rule).count() != 1
            || makefile
                .lines()
                .filter(|line| line.trim() == command_line)
                .count()
                != 1
        {
            return Err(format!(
                "P17 {} 官方 {} makefile 配對變更",
                profile.name, name
            ));
        }
        let source = root.join(profile.suite).join("libs").join(source_name);
        let destination = libs.join(name);
        let command = module_build_command(root, profile, index, &source, &destination);
        let log = work.join(format!("{name}-build.log"));
        let output = invoke(root, &command, &log, false)?;
        let passed = output.exit_code == Some(0) && destination.is_file();
        observed(
            report,
            "module-build",
            profile,
            command,
            root,
            &log,
            &output,
            passed,
            &format!("官方 {source_name} 建立 {name}"),
        )?;
        report
            .checks
            .last_mut()
            .ok_or("P17 module-build check 缺失")?
            .inputs = vec![Input::from_path(&source)?, Input::from_path(&destination)?];
        report.input(&source)?;
        report.input(&destination)?;
        built.push(destination);
    }
    let attrib = root.join(profile.suite).join("attrib.lua");
    let attrib_body = fs::read_to_string(&attrib).map_err(|error| error.to_string())?;
    if !attrib_body.contains("createfiles(files, \"_ENV = {}\\n\", \"\\nreturn _ENV\\n\")") {
        return Err(format!("P17 {} 官方 P1 產生契約變更", profile.name));
    }
    report.input(&attrib)?;
    let p1 = libs.join("P1");
    fs::create_dir_all(&p1).map_err(|error| error.to_string())?;
    let mut packages = Vec::new();
    for (name, value) in [("init.lua", 10), ("xuxu.lua", 20)] {
        let path = p1.join(name);
        fs::write(&path, format!("_ENV = {{}}\nAA = {value}\nreturn _ENV\n"))
            .map_err(|error| error.to_string())?;
        report.input(&path)?;
        packages.push(path);
    }
    let source = root.join("tests/p17/modules/driver.c");
    report.input(&source)?;
    let driver = work.join("sdk-driver");
    let command = driver_build_command(root, profile, &source, library, native_flags, &driver);
    let log = work.join("driver-build.log");
    let output = invoke(root, &command, &log, false)?;
    let linked = output.exit_code == Some(0) && driver.is_file();
    let abi_log = work.join("driver-abi.json");
    let abi = if linked {
        let probe = invoke(
            root,
            &[driver.display().to_string(), "--abi-json".into()],
            &abi_log,
            true,
        )?;
        if probe.exit_code == Some(0) {
            grant::validate_abi_json(root, profile, &probe.body)
        } else {
            Err("P17 C driver ABI metadata probe 非零退出".into())
        }
    } else {
        Err("P17 C API driver 未成功連結".into())
    };
    let abi_diagnostic = abi
        .as_ref()
        .map(|_| "真 Rust C API staticlib 與 SDK driver 連結，typed ABI probe 一致".to_owned())
        .unwrap_or_else(|error| error.clone());
    observed(
        report,
        "abi",
        profile,
        command,
        root,
        &log,
        &output,
        linked && abi.is_ok(),
        &abi_diagnostic,
    )?;
    let abi = abi?;
    report
        .checks
        .last_mut()
        .ok_or("P17 ABI driver check 缺失")?
        .operation = "cc-capi-driver";
    report.input(&driver)?;
    report.input(&abi_log)?;
    report
        .checks
        .last_mut()
        .ok_or("P17 ABI driver check 缺失")?
        .inputs = vec![
        Input::from_path(&source)?,
        Input::from_path(library)?,
        Input::from_path(&driver)?,
        Input::from_path(&abi_log)?,
    ];
    let mut command = vec![driver.display().to_string()];
    command.extend(built.iter().map(|path| path.display().to_string()));
    command.extend(packages.iter().map(|path| path.display().to_string()));
    let log = work.join("driver-run.log");
    let output = invoke(root, &command, &log, true)?;
    let mut expected = vec![
        "P17_SDK_ABI revision=1 layout=37 PASS".to_owned(),
        "P17_SDK_HOST_LIMITS source=65536 encoded=4194304 module=8388608 temporary=1048576 work=2000000 chunks=256 paths=256 PASS".to_owned(),
        "P17_SDK_LIB11 lib11.so GLOBAL_LINK PASS".to_owned(),
        "P17_SDK_LIB1 FUNCTIONS PASS".to_owned(),
        "P17_SDK_CLOSE ALLOCATOR_RELEASE PASS".to_owned(),
        "P17_SDK_DLCLOSE AFTER_LUA_CLOSE PASS".to_owned(),
        "P17_SDK_RESULT PASS".to_owned(),
    ];
    for path in &built {
        expected.push(format!("P17_SDK_DLOPEN {} PASS", path.display()));
    }
    for (name, symbol) in [
        ("lib1.so", "luaopen_lib1_sub"),
        ("lib2.so", "luaopen_lib2"),
        ("lib21.so", "luaopen_lib21"),
        ("lib2-v2.so", "luaopen_lib2"),
    ] {
        expected.push(format!("P17_SDK_MODULE {name} {symbol} TWO_ARG_ID PASS"));
    }
    for (path, aa) in packages.iter().zip([10, 20]) {
        expected.push(format!(
            "P17_SDK_P1 {} AA={aa} GLOBAL=0 PASS",
            path.display()
        ));
    }
    observed(
        report,
        "module-load",
        profile,
        command,
        root,
        &log,
        &output,
        output.exit_code == Some(0) && exact_lines(&output.body, &expected),
        "五個真 C module dlopen/符號/效果、P1 隔離、ABI、close ledger",
    )?;
    let mut inputs = vec![Input::from_path(&driver)?, Input::from_path(library)?];
    for path in built.iter().chain(packages.iter()) {
        inputs.push(Input::from_path(path)?);
    }
    report
        .checks
        .last_mut()
        .ok_or("P17 module-load check 缺失")?
        .inputs = inputs;
    Ok(ModuleArtifacts {
        built: built.try_into().map_err(|_| "P17 固定五模組數目不符")?,
        packages: packages
            .try_into()
            .map_err(|_| "P17 固定 P1 檔案數目不符")?,
        driver,
        abi_log,
        abi,
    })
}

fn runner_controls(
    root: &Path,
    work: &Path,
    profile: Profile,
    report: &mut Report,
    binary: &Path,
    suite: &Path,
) -> Result<(), String> {
    let ok_script = root.join("tests/p17/modules/runner_ok.lua");
    let fail_script = root.join("tests/p17/modules/runner_fail.lua");
    report.input(&ok_script)?;
    report.input(&fail_script)?;
    let command = vec![
        binary.display().to_string(),
        ok_script.display().to_string(),
    ];
    let log = work.join("runner-ok.log");
    let output = invoke(suite, &command, &log, true)?;
    for (facet, marker) in [
        ("runner-argv", "P17_RUNNER_ARGV PASS"),
        ("runner-cwd", "P17_RUNNER_CWD PASS"),
        ("runner-no-u", "P17_RUNNER_NO_U PASS"),
    ] {
        observed(
            report,
            facet,
            profile,
            command.clone(),
            suite,
            &log,
            &output,
            output.exit_code == Some(0)
                && output.body.lines().filter(|line| *line == marker).count() == 1,
            "raw argv、官方 suite root cwd、_U 未設定",
        )?;
        report
            .checks
            .last_mut()
            .ok_or("P17 runner check 缺失")?
            .inputs = vec![Input::from_path(binary)?, Input::from_path(&ok_script)?];
    }
    let command = vec![
        binary.display().to_string(),
        fail_script.display().to_string(),
    ];
    let log = work.join("runner-fail.log");
    let output = invoke(suite, &command, &log, true)?;
    observed(
        report,
        "runner-error",
        profile,
        command,
        suite,
        &log,
        &output,
        output.exit_code.is_some_and(|code| code != 0)
            && output.body.contains("P17_INTENTIONAL_FAILURE"),
        "故意腳本失敗必須非零退出",
    )?;
    report
        .checks
        .last_mut()
        .ok_or("P17 runner-error check 缺失")?
        .inputs = vec![Input::from_path(binary)?, Input::from_path(&fail_script)?];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cargo_artifact, native_libs};

    #[test]
    fn p17_cargo_artifact_and_native_flags_are_exact() {
        let log = "{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"rivetlua_capi\",\"crate_types\":[\"rlib\",\"staticlib\"]},\"filenames\":[\"/tmp/librivetlua_capi.a\"]}\nnote: native-static-libs: -framework Security -lm\n";
        assert_eq!(
            cargo_artifact(log, "rivetlua_capi", "staticlib").unwrap(),
            std::path::Path::new("/tmp/librivetlua_capi.a")
        );
        assert_eq!(native_libs(log).unwrap(), ["-framework", "Security", "-lm"]);
        assert!(native_libs("note: native-static-libs: -llua -lm").is_err());
        assert!(native_libs("note: native-static-libs: -framework -lm").is_err());
        assert!(
            cargo_artifact(
                "note: native-static-libs: -lm",
                "rivetlua_capi",
                "staticlib"
            )
            .is_err()
        );
    }
}
