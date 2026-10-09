use super::manifest::{Manifest, Row};
use super::matrix::{self, Case, ExecutionKind};
use super::report;
use super::rowproof::{self, ProofKey};
use super::selection::{self, Applicability, Snapshot};
use super::{q, sha_file};
use crate::{StrictJsonParser, StrictJsonValue};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn strings(values: &[String]) -> String {
    values
        .iter()
        .map(|value| q(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn environment(values: &[(String, String)]) -> String {
    values
        .iter()
        .map(|(name, value)| format!("{{\"name\":{},\"value\":{}}}", q(name), q(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn opt_string(value: &Option<String>) -> String {
    value.as_deref().map(q).unwrap_or_else(|| "null".into())
}

fn opt_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn artifact(path: &Path) -> Result<(String, String), String> {
    Ok((path.display().to_string(), sha_file(path)?))
}

struct ProcessResult {
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
}

impl ProcessResult {
    fn success(&self) -> bool {
        self.exit_code == Some(0) && self.signal.is_none()
    }

    fn log(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn output(root: &Path, parts: &[String]) -> Result<ProcessResult, String> {
    output_with_env(root, parts, &[])
}

fn output_with_env(
    root: &Path,
    parts: &[String],
    overrides: &[(String, String)],
) -> Result<ProcessResult, String> {
    let command = parts.first().ok_or("P16 command 為空")?;
    let mut process = Command::new(command);
    process.args(&parts[1..]).current_dir(root);
    for (name, _) in env::vars_os() {
        if name.to_string_lossy().starts_with("RIVETLUA_P16_") {
            process.env_remove(name);
        }
    }
    for (name, value) in overrides {
        process.env(name, value);
    }
    let result = process
        .output()
        .map_err(|error| format!("P16 {command} 無法啟動：{error}"))?;
    Ok(ProcessResult {
        exit_code: result.status.code(),
        signal: result.status.signal(),
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
    })
}

fn write_log(path: &Path, body: &str) -> Result<(String, String), String> {
    report::write(path, body)?;
    artifact(path)
}

pub(super) fn cargo_staticlib_artifact(log: &str) -> Result<PathBuf, String> {
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
                != Some("rivetlua_capi")
        {
            continue;
        }
        let crates = value
            .get("target")
            .and_then(|target| target.get("crate_types"))
            .and_then(StrictJsonValue::as_array)
            .ok_or("P16 Cargo artifact 缺 crate_types")?;
        if !crates.iter().any(|kind| kind.as_str() == Some("staticlib")) {
            continue;
        }
        let files = value
            .get("filenames")
            .and_then(StrictJsonValue::as_array)
            .ok_or("P16 Cargo artifact 缺 filenames")?;
        for file in files {
            let Some(path) = file.as_str() else { continue };
            let path = PathBuf::from(path);
            if path.file_name().and_then(|name| name.to_str()) == Some("librivetlua_capi.a") {
                if found.replace(path).is_some() {
                    return Err("P16 Cargo staticlib artifact 重複".into());
                }
            }
        }
    }
    found.ok_or_else(|| "P16 Cargo 未報告 rivetlua_capi staticlib artifact".into())
}

pub(super) fn cargo_worker_artifact(log: &str) -> Result<PathBuf, String> {
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
                != Some("rivetlua-native-worker")
        {
            continue;
        }
        let kinds = value
            .get("target")
            .and_then(|target| target.get("kind"))
            .and_then(StrictJsonValue::as_array)
            .ok_or("P16 worker artifact 缺 kind")?;
        if !kinds.iter().any(|kind| kind.as_str() == Some("bin")) {
            continue;
        }
        let executable = value
            .get("executable")
            .and_then(StrictJsonValue::as_str)
            .ok_or("P16 worker artifact 缺 executable")?;
        let path = PathBuf::from(executable);
        if path.file_name().and_then(|name| name.to_str()) != Some("rivetlua-native-worker")
            || found.replace(path).is_some()
        {
            return Err("P16 worker executable 名稱或重複 artifact 不符".into());
        }
    }
    found.ok_or_else(|| "P16 Cargo 未報告 rivetlua-native-worker bin artifact".into())
}

pub(super) fn native_static_libs(log: &str) -> Result<Vec<String>, String> {
    let mut messages = Vec::new();
    for line in log.lines() {
        if let Ok(value) = StrictJsonParser::parse(line) {
            if let Some(rendered) = value
                .get("message")
                .and_then(|message| message.get("rendered"))
                .and_then(StrictJsonValue::as_str)
            {
                messages.push(rendered.to_owned());
            }
        } else {
            messages.push(line.to_owned());
        }
    }
    let mut found = None;
    for message in messages {
        for line in message.lines() {
            let Some((_, flags)) = line.split_once("native-static-libs:") else {
                continue;
            };
            let flags = flags
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if flags.is_empty() || found.as_ref().is_some_and(|prior| prior != &flags) {
                return Err("P16 native-static-libs 空白或重複".into());
            }
            found = Some(flags);
        }
    }
    let flags = found.ok_or("P16 rustc 未報告 native-static-libs")?;
    let mut framework_name = false;
    for flag in &flags {
        if framework_name {
            if flag.starts_with('-')
                || !flag
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err("P16 native framework 名稱無效".into());
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
            return Err(format!("P16 native-static-libs 不允許 {flag}"));
        }
    }
    if framework_name {
        return Err("P16 native framework 缺名稱".into());
    }
    Ok(flags)
}

struct StaticLibrary {
    path: PathBuf,
    artifact: (String, String),
    build_command: Vec<String>,
    build_log: (String, String),
    native_flags: Vec<String>,
}

#[derive(Clone)]
struct WorkerEvidence {
    status: &'static str,
    source: Option<(String, String)>,
    artifact: Option<(String, String)>,
    binary: Option<(String, String)>,
    build_command: Vec<String>,
    build_exit_code: Option<i32>,
    build_signal: Option<i32>,
    build_log: Option<(String, String)>,
    diagnostic: String,
}

impl WorkerEvidence {
    fn new() -> Self {
        Self {
            status: "FAIL",
            source: None,
            artifact: None,
            binary: None,
            build_command: Vec::new(),
            build_exit_code: None,
            build_signal: None,
            build_log: None,
            diagnostic: "worker build 尚未完成".into(),
        }
    }

    fn json(&self) -> String {
        let pair = |value: &Option<(String, String)>, index: usize| {
            value
                .as_ref()
                .map(|item| q(if index == 0 { &item.0 } else { &item.1 }))
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"status\":{},\"source_path\":{},\"source_sha256\":{},\"artifact_path\":{},\"artifact_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"build_command\":[{}],\"build_exit_code\":{},\"build_signal\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"diagnostic\":{}}}",
            q(self.status),
            pair(&self.source, 0),
            pair(&self.source, 1),
            pair(&self.artifact, 0),
            pair(&self.artifact, 1),
            pair(&self.binary, 0),
            pair(&self.binary, 1),
            strings(&self.build_command),
            opt_i32(self.build_exit_code),
            opt_i32(self.build_signal),
            pair(&self.build_log, 0),
            pair(&self.build_log, 1),
            q(&self.diagnostic)
        )
    }
}

#[derive(Clone)]
struct TestBinary {
    path: PathBuf,
    build_command: Vec<String>,
    build_log_path: String,
    build_log_sha256: String,
}

struct RustFailure {
    stage: &'static str,
    diagnostic: String,
    source: Option<(String, String)>,
    binary: Option<(String, String)>,
    build_command: Vec<String>,
    build_exit_code: Option<i32>,
    build_signal: Option<i32>,
    build_log: Option<(String, String)>,
    command: Vec<String>,
    environment: Vec<(String, String)>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    log: Option<(String, String)>,
    matched: usize,
    passed: usize,
    failed: usize,
}

impl RustFailure {
    fn new(stage: &'static str, diagnostic: String) -> Self {
        Self {
            stage,
            diagnostic,
            source: None,
            binary: None,
            build_command: Vec::new(),
            build_exit_code: None,
            build_signal: None,
            build_log: None,
            command: Vec::new(),
            environment: Vec::new(),
            exit_code: None,
            signal: None,
            log: None,
            matched: 0,
            passed: 0,
            failed: 0,
        }
    }

    fn persist_log(&mut self, path: &Path, body: &str) {
        match write_log(path, body) {
            Ok(log) if self.stage == "build" => self.build_log = Some(log),
            Ok(log) => self.log = Some(log),
            Err(error) => self
                .diagnostic
                .push_str(&format!("；failure log 保存失敗：{error}")),
        }
    }

    fn json(&self) -> String {
        let pair = |value: &Option<(String, String)>, index: usize| {
            value
                .as_ref()
                .map(|item| q(if index == 0 { &item.0 } else { &item.1 }))
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"stage\":{},\"diagnostic\":{},\"source_path\":{},\"source_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"build_command\":[{}],\"build_exit_code\":{},\"build_signal\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"command\":[{}],\"environment\":[{}],\"exit_code\":{},\"signal\":{},\"log_path\":{},\"log_sha256\":{}}}",
            q(self.stage),
            q(&self.diagnostic),
            pair(&self.source, 0),
            pair(&self.source, 1),
            pair(&self.binary, 0),
            pair(&self.binary, 1),
            strings(&self.build_command),
            opt_i32(self.build_exit_code),
            opt_i32(self.build_signal),
            pair(&self.build_log, 0),
            pair(&self.build_log, 1),
            strings(&self.command),
            environment(&self.environment),
            opt_i32(self.exit_code),
            opt_i32(self.signal),
            pair(&self.log, 0),
            pair(&self.log, 1),
        )
    }
}

fn test_binary(
    root: &Path,
    work: &Path,
    profile: &str,
    target: &str,
    cache: &mut HashMap<String, TestBinary>,
) -> Result<TestBinary, RustFailure> {
    if let Some(binary) = cache.get(target) {
        return Ok(binary.clone());
    }
    let mut build = vec![
        "cargo".into(),
        "test".into(),
        "--locked".into(),
        "-p".into(),
        "rivetlua-capi".into(),
        "--test".into(),
        target.into(),
        "--no-run".into(),
        "--message-format=json-render-diagnostics".into(),
    ];
    if profile == "lua54-i64f64" {
        build.extend([
            "--no-default-features".into(),
            "--features".into(),
            "lua54".into(),
        ]);
    }
    let mut failure = RustFailure::new("build", format!("P16 Rust test {target} build 失敗"));
    failure.build_command = build.clone();
    let result = match output(root, &build) {
        Ok(result) => result,
        Err(error) => {
            failure.diagnostic = error;
            let diagnostic = failure.diagnostic.clone();
            failure.persist_log(&work.join(format!("rust-{target}-build.log")), &diagnostic);
            return Err(failure);
        }
    };
    failure.build_exit_code = result.exit_code;
    failure.build_signal = result.signal;
    let mut executable = None;
    for line in result.stdout.lines() {
        let Ok(parsed) = StrictJsonParser::parse(line) else {
            continue;
        };
        if parsed.get("reason").and_then(StrictJsonValue::as_str) == Some("compiler-artifact")
            && parsed
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(StrictJsonValue::as_str)
                == Some(target)
        {
            if let Some(path) = parsed.get("executable").and_then(StrictJsonValue::as_str) {
                executable = Some(PathBuf::from(path));
            }
        }
    }
    let path = work.join(format!("rust-{target}-build.log"));
    let mut log = result.log();
    if !result.success() {
        failure.diagnostic = format!(
            "P16 Rust test {target} build exit={:?} signal={:?}",
            result.exit_code, result.signal
        );
        failure.persist_log(&path, &log);
        return Err(failure);
    }
    let Some(executable) = executable.filter(|path| path.is_file()) else {
        failure.diagnostic = format!("P16 Rust test {target} 未輸出有效 executable");
        failure.persist_log(&path, &log);
        return Err(failure);
    };
    let snapshot = work.join(format!("rust-{target}-testbin"));
    let original_sha = match sha_file(&executable) {
        Ok(sha) => sha,
        Err(error) => {
            failure.diagnostic = error;
            failure.persist_log(&path, &log);
            return Err(failure);
        }
    };
    if let Err(error) = fs::copy(&executable, &snapshot) {
        failure.diagnostic = format!("P16 Rust test {target} snapshot 失敗：{error}");
        failure.persist_log(&path, &log);
        return Err(failure);
    }
    let snapshot_sha = match sha_file(&snapshot) {
        Ok(sha) => sha,
        Err(error) => {
            failure.diagnostic = error;
            failure.persist_log(&path, &log);
            return Err(failure);
        }
    };
    if snapshot_sha != original_sha {
        failure.diagnostic = format!("P16 Rust test {target} snapshot SHA 不符");
        failure.persist_log(&path, &log);
        return Err(failure);
    }
    log.push_str(&format!("P16_BUILD {target} {profile} PASS\n"));
    let (log_path, log_sha) = write_log(&path, &log).map_err(|error| {
        failure.diagnostic = error;
        failure
    })?;
    let binary = TestBinary {
        path: snapshot,
        build_command: build,
        build_log_path: log_path,
        build_log_sha256: log_sha,
    };
    cache.insert(target.into(), binary.clone());
    Ok(binary)
}

#[derive(Clone)]
struct RustTestRun {
    target: String,
    name: String,
    source_path: String,
    source_sha256: String,
    binary_path: String,
    binary_sha256: String,
    build_command: Vec<String>,
    build_log_path: String,
    build_log_sha256: String,
    command: Vec<String>,
    environment: Vec<(String, String)>,
    log_path: String,
    log_sha256: String,
}

impl RustTestRun {
    fn json(&self, root: &Path) -> String {
        format!(
            "{{\"target\":{},\"name\":{},\"source_path\":{},\"source_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"build_command\":[{}],\"build_exit_code\":0,\"build_signal\":null,\"build_log_path\":{},\"build_log_sha256\":{},\"command\":[{}],\"environment\":[{}],\"cwd\":{},\"exit_code\":0,\"signal\":null,\"matched\":1,\"passed\":1,\"failed\":0,\"ignored\":0,\"log_path\":{},\"log_sha256\":{}}}",
            q(&self.target),
            q(&self.name),
            q(&self.source_path),
            q(&self.source_sha256),
            q(&self.binary_path),
            q(&self.binary_sha256),
            strings(&self.build_command),
            q(&self.build_log_path),
            q(&self.build_log_sha256),
            strings(&self.command),
            environment(&self.environment),
            q(&root.display().to_string()),
            q(&self.log_path),
            q(&self.log_sha256)
        )
    }
}

fn rust_test(
    root: &Path,
    work: &Path,
    profile: &str,
    case_id: &str,
    test_target: &str,
    test_name: &str,
    run_env: &[(String, String)],
    cache: &mut HashMap<String, TestBinary>,
    run_cache: &mut HashMap<String, RustTestRun>,
) -> Result<RustTestRun, RustFailure> {
    let cache_key = format!(
        "{profile}:{test_target}:{test_name}:{}",
        environment(run_env)
    );
    if let Some(prior) = run_cache.get(&cache_key) {
        return Ok(prior.clone());
    }
    let binary = test_binary(root, work, profile, test_target, cache)?;
    let source = root.join(format!("crates/rivetlua-capi/tests/{test_target}.rs"));
    let mut failure = RustFailure::new(
        "run",
        format!("P16 Rust test {test_target}:{test_name} 執行失敗"),
    );
    failure.build_command = binary.build_command.clone();
    failure.environment = run_env.to_vec();
    failure.build_exit_code = Some(0);
    failure.build_log = Some((
        binary.build_log_path.clone(),
        binary.build_log_sha256.clone(),
    ));
    failure.source = Some(match artifact(&source) {
        Ok(artifact) => artifact,
        Err(error) => {
            failure.diagnostic = error;
            return Err(failure);
        }
    });
    failure.binary = Some(match artifact(&binary.path) {
        Ok(artifact) => artifact,
        Err(error) => {
            failure.diagnostic = error;
            return Err(failure);
        }
    });
    let (source_path, source_sha256) = failure.source.clone().unwrap();
    let (binary_path, binary_sha256) = failure.binary.clone().unwrap();
    let mut command = vec![
        binary_path.clone(),
        test_name.into(),
        "--exact".into(),
        "--nocapture".into(),
    ];
    if test_target == "sdk_modules" {
        command.push("--ignored".into());
    }
    command.push("--test-threads=1".into());
    failure.command = command.clone();
    let path = work.join(format!("rust-{case_id}-{}-{}.log", test_target, test_name));
    let result = match output_with_env(root, &command, run_env) {
        Ok(result) => result,
        Err(error) => {
            failure.diagnostic = error;
            let diagnostic = failure.diagnostic.clone();
            failure.persist_log(&path, &diagnostic);
            return Err(failure);
        }
    };
    failure.exit_code = result.exit_code;
    failure.signal = result.signal;
    let log = result.log();
    failure.matched = usize::from(log.lines().any(|line| line == "running 1 test"));
    failure.passed = usize::from(
        result.success() && failure.matched == 1 && super::named_libtest_passed(&log, test_name),
    );
    failure.failed = failure.matched - failure.passed;
    failure.persist_log(&path, &log);
    if !result.success() || !super::named_libtest_passed(&log, test_name) {
        failure.diagnostic = format!(
            "P16 Rust test {}:{} exit={:?} signal={:?} count 不符",
            test_target, test_name, result.exit_code, result.signal
        );
        return Err(failure);
    }
    let Some((log_path, log_sha256)) = failure.log else {
        return Err(failure);
    };
    let completed = RustTestRun {
        target: test_target.into(),
        name: test_name.into(),
        source_path,
        source_sha256,
        binary_path,
        binary_sha256,
        build_command: binary.build_command,
        build_log_path: binary.build_log_path,
        build_log_sha256: binary.build_log_sha256,
        command,
        environment: run_env.to_vec(),
        log_path,
        log_sha256,
    };
    run_cache.insert(cache_key, completed.clone());
    Ok(completed)
}

struct CaseEvidence {
    status: &'static str,
    build_command: Vec<String>,
    build_exit_code: Option<i32>,
    build_signal: Option<i32>,
    command: Vec<String>,
    environment: Vec<(String, String)>,
    cwd: Option<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    matched: usize,
    passed: usize,
    failed: usize,
    source: Option<(String, String)>,
    upstream_source: Option<(String, String)>,
    header: Option<(String, String)>,
    header_set: Option<String>,
    library: Option<(String, String)>,
    staticlib_artifact: Option<(String, String)>,
    staticlib_build_command: Vec<String>,
    staticlib_build_exit_code: Option<i32>,
    staticlib_build_signal: Option<i32>,
    staticlib_build_log: Option<(String, String)>,
    native_static_libs: Vec<String>,
    binary: Option<(String, String)>,
    build_log: Option<(String, String)>,
    c_log: Option<(String, String)>,
    log: Option<(String, String)>,
    local_tests: Vec<RustTestRun>,
    rust_failure: Option<RustFailure>,
    worker: Option<WorkerEvidence>,
    artifact_record: Option<(String, String)>,
    diagnostic: String,
}

struct ProofEvidence {
    key: ProofKey,
    status: &'static str,
    source: Option<(String, String)>,
    header: Option<(String, String)>,
    header_set: Option<String>,
    library: Option<(String, String)>,
    binary: Option<(String, String)>,
    build_command: Vec<String>,
    build_exit_code: Option<i32>,
    build_signal: Option<i32>,
    build_log: Option<(String, String)>,
    command: Vec<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    log: Option<(String, String)>,
    matched: usize,
    passed: usize,
    failed: usize,
    diagnostic: String,
}

impl ProofEvidence {
    fn new(key: ProofKey) -> Self {
        Self {
            key,
            status: "NOT_RUN",
            source: None,
            header: None,
            header_set: None,
            library: None,
            binary: None,
            build_command: Vec::new(),
            build_exit_code: None,
            build_signal: None,
            build_log: None,
            command: Vec::new(),
            exit_code: None,
            signal: None,
            log: None,
            matched: 0,
            passed: 0,
            failed: 0,
            diagnostic: "尚未執行固定 proof".into(),
        }
    }

    fn json(&self, target: &str, root: &Path) -> String {
        let pair = |value: &Option<(String, String)>, index: usize| {
            value
                .as_ref()
                .map(|item| q(if index == 0 { &item.0 } else { &item.1 }))
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"id\":{},\"kind\":{},\"profile\":{},\"target\":{},\"status\":{},\"source_path\":{},\"source_sha256\":{},\"header_path\":{},\"header_sha256\":{},\"header_set_sha256\":{},\"library_path\":{},\"library_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"build_command\":[{}],\"build_exit_code\":{},\"build_signal\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"command\":[{}],\"cwd\":{},\"exit_code\":{},\"signal\":{},\"log_path\":{},\"log_sha256\":{},\"matched\":{},\"passed\":{},\"failed\":{},\"ignored\":0,\"diagnostic\":{}}}",
            q(&self.key.id()),
            q(self.key.kind()),
            q(self.key.profile()),
            q(target),
            q(self.status),
            pair(&self.source, 0),
            pair(&self.source, 1),
            pair(&self.header, 0),
            pair(&self.header, 1),
            opt_string(&self.header_set),
            pair(&self.library, 0),
            pair(&self.library, 1),
            pair(&self.binary, 0),
            pair(&self.binary, 1),
            strings(&self.build_command),
            opt_i32(self.build_exit_code),
            opt_i32(self.build_signal),
            pair(&self.build_log, 0),
            pair(&self.build_log, 1),
            strings(&self.command),
            q(&root.display().to_string()),
            opt_i32(self.exit_code),
            opt_i32(self.signal),
            pair(&self.log, 0),
            pair(&self.log, 1),
            self.matched,
            self.passed,
            self.failed,
            q(&self.diagnostic)
        )
    }
}

impl CaseEvidence {
    fn new() -> Self {
        Self {
            status: "NOT_RUN",
            build_command: Vec::new(),
            build_exit_code: None,
            build_signal: None,
            command: Vec::new(),
            environment: Vec::new(),
            cwd: None,
            exit_code: None,
            signal: None,
            matched: 0,
            passed: 0,
            failed: 0,
            source: None,
            upstream_source: None,
            header: None,
            header_set: None,
            library: None,
            staticlib_artifact: None,
            staticlib_build_command: Vec::new(),
            staticlib_build_exit_code: None,
            staticlib_build_signal: None,
            staticlib_build_log: None,
            native_static_libs: Vec::new(),
            binary: None,
            build_log: None,
            c_log: None,
            log: None,
            local_tests: Vec::new(),
            rust_failure: None,
            worker: None,
            artifact_record: None,
            diagnostic: "未完成實際驗收".into(),
        }
    }

    fn json(&self, case: &Case, profile: &str, target: &str, root: &Path) -> String {
        let pair = |value: &Option<(String, String)>, index: usize| {
            value
                .as_ref()
                .map(|item| q(if index == 0 { &item.0 } else { &item.1 }))
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"id\":{},\"profile\":{},\"target\":{},\"execution_kind\":{},\"status\":{},\"fixture\":{},\"assertions\":[{}],\"build_command\":[{}],\"build_exit_code\":{},\"build_signal\":{},\"command\":[{}],\"environment\":[{}],\"cwd\":{},\"exit_code\":{},\"signal\":{},\"matched\":{},\"passed\":{},\"failed\":{},\"ignored\":0,\"source_path\":{},\"source_sha256\":{},\"upstream_source_path\":{},\"upstream_source_sha256\":{},\"header_path\":{},\"header_sha256\":{},\"header_set_sha256\":{},\"library_path\":{},\"library_sha256\":{},\"staticlib_artifact_path\":{},\"staticlib_artifact_sha256\":{},\"staticlib_build_command\":[{}],\"staticlib_build_exit_code\":{},\"staticlib_build_signal\":{},\"staticlib_build_log_path\":{},\"staticlib_build_log_sha256\":{},\"native_static_libs\":[{}],\"binary_path\":{},\"binary_sha256\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"c_log_path\":{},\"c_log_sha256\":{},\"log_path\":{},\"log_sha256\":{},\"local_tests\":[{}],\"local_failure\":{},\"worker\":{},\"artifact_record_path\":{},\"artifact_record_sha256\":{},\"modules\":[],\"package_artifacts\":[],\"diagnostic\":{}}}",
            q(&case.id),
            q(profile),
            q(target),
            q(case.execution_kind.as_str()),
            q(self.status),
            q(&case.fixture),
            strings(&case.assertions),
            strings(&self.build_command),
            opt_i32(self.build_exit_code),
            opt_i32(self.build_signal),
            strings(&self.command),
            environment(&self.environment),
            opt_string(&self.cwd),
            opt_i32(self.exit_code),
            opt_i32(self.signal),
            self.matched,
            self.passed,
            self.failed,
            pair(&self.source, 0),
            pair(&self.source, 1),
            pair(&self.upstream_source, 0),
            pair(&self.upstream_source, 1),
            pair(&self.header, 0),
            pair(&self.header, 1),
            opt_string(&self.header_set),
            pair(&self.library, 0),
            pair(&self.library, 1),
            pair(&self.staticlib_artifact, 0),
            pair(&self.staticlib_artifact, 1),
            strings(&self.staticlib_build_command),
            opt_i32(self.staticlib_build_exit_code),
            opt_i32(self.staticlib_build_signal),
            pair(&self.staticlib_build_log, 0),
            pair(&self.staticlib_build_log, 1),
            strings(&self.native_static_libs),
            pair(&self.binary, 0),
            pair(&self.binary, 1),
            pair(&self.build_log, 0),
            pair(&self.build_log, 1),
            pair(&self.c_log, 0),
            pair(&self.c_log, 1),
            pair(&self.log, 0),
            pair(&self.log, 1),
            self.local_tests
                .iter()
                .map(|run| run.json(root))
                .collect::<Vec<_>>()
                .join(","),
            self.rust_failure
                .as_ref()
                .map(RustFailure::json)
                .unwrap_or_else(|| "null".into()),
            self.worker
                .as_ref()
                .map(WorkerEvidence::json)
                .unwrap_or_else(|| "null".into()),
            pair(&self.artifact_record, 0),
            pair(&self.artifact_record, 1),
            q(&self.diagnostic)
        )
    }
}

fn invalidate_stale_evidence(observed: &mut [Option<CaseEvidence>], diagnostic: &str) {
    for evidence in observed.iter_mut().flatten() {
        if evidence.status == "PASS" {
            evidence.status = "FAIL";
            evidence.passed = 0;
            evidence.failed = evidence.matched;
            evidence.diagnostic = diagnostic.to_owned();
        }
    }
}

fn staticlib(
    root: &Path,
    work: &Path,
    profile: &str,
    target: &str,
    target_dir: &Path,
) -> Result<StaticLibrary, String> {
    if !matrix::TARGETS.contains(&target)
        || env::var("CARGO_BUILD_TARGET")
            .ok()
            .is_some_and(|configured| configured != target)
    {
        return Err("P16 staticlib 僅支援固定 host target，且 CARGO_BUILD_TARGET 必須一致".into());
    }
    let mut command = vec![
        "cargo".into(),
        "rustc".into(),
        "--locked".into(),
        "-p".into(),
        "rivetlua-capi".into(),
        "--lib".into(),
        "--message-format=json-render-diagnostics".into(),
    ];
    if profile == "lua54-i64f64" {
        command.extend([
            "--no-default-features".into(),
            "--features".into(),
            "lua54".into(),
        ]);
    }
    command.extend(["--".into(), "--print=native-static-libs".into()]);
    let path = work.join("staticlib-build.log");
    let result = match output(root, &command) {
        Ok(result) => result,
        Err(error) => {
            write_log(&path, &error)?;
            return Err(error);
        }
    };
    let mut log = result.log();
    write_log(&path, &log)?;
    if !result.success() {
        return Err(format!(
            "P16 staticlib build exit={:?} signal={:?}",
            result.exit_code, result.signal
        ));
    }
    let source = cargo_staticlib_artifact(&log)?;
    let native_flags = native_static_libs(&log)?;
    let source = fs::canonicalize(&source)
        .map_err(|error| format!("P16 Cargo staticlib 不可讀：{error}"))?;
    let target_dir = fs::canonicalize(target_dir).map_err(|error| error.to_string())?;
    if !source.starts_with(&target_dir) || !source.is_file() {
        return Err("P16 Cargo staticlib artifact 超出共用 target 或非檔案".into());
    }
    let artifact = artifact(&source)?;
    let copy = work.join("librivetlua_capi.a");
    fs::copy(&source, &copy).map_err(|error| format!("P16 staticlib snapshot 失敗：{error}"))?;
    if sha_file(&copy)? != artifact.1 {
        return Err("P16 staticlib snapshot SHA 不符".into());
    }
    log.push_str(&format!(
        "P16_STATICLIB {profile} {target} PASS artifact={} native_flags={}\n",
        source.display(),
        native_flags.join(" ")
    ));
    let build_log = write_log(&path, &log)?;
    Ok(StaticLibrary {
        path: copy,
        artifact,
        build_command: command,
        build_log,
        native_flags,
    })
}

fn worker_binary(
    root: &Path,
    work: &Path,
    profile: &str,
    target: &str,
    target_dir: &Path,
) -> WorkerEvidence {
    let mut evidence = WorkerEvidence::new();
    let log_path = work.join("worker-build.log");
    let attempt = (|| -> Result<(), String> {
        if !matrix::TARGETS.contains(&target)
            || env::var("CARGO_BUILD_TARGET")
                .ok()
                .is_some_and(|configured| configured != target)
        {
            return Err("P16 worker build 僅支援固定 host target".into());
        }
        let source = root.join("crates/rivetlua-capi/src/bin/rivetlua-native-worker.rs");
        evidence.source = Some(artifact(&source)?);
        evidence.build_command = vec![
            "cargo".into(),
            "build".into(),
            "--locked".into(),
            "-p".into(),
            "rivetlua-capi".into(),
            "--bin".into(),
            "rivetlua-native-worker".into(),
            "--message-format=json-render-diagnostics".into(),
        ];
        if profile == "lua54-i64f64" {
            evidence.build_command.extend([
                "--no-default-features".into(),
                "--features".into(),
                "lua54".into(),
            ]);
        }
        let built = output(root, &evidence.build_command)?;
        evidence.build_exit_code = built.exit_code;
        evidence.build_signal = built.signal;
        let mut log = built.log();
        evidence.build_log = write_log(&log_path, &log).ok();
        if !built.success() {
            return Err(format!(
                "P16 worker build exit={:?} signal={:?}",
                built.exit_code, built.signal
            ));
        }
        let alias = cargo_worker_artifact(&log)?;
        let alias = fs::canonicalize(&alias)
            .map_err(|error| format!("P16 worker Cargo alias 不可讀：{error}"))?;
        let cache = fs::canonicalize(target_dir).map_err(|error| error.to_string())?;
        if !alias.starts_with(cache) || !alias.is_file() {
            return Err("P16 worker alias 超出共用 target 或非檔案".into());
        }
        let built_artifact = artifact(&alias)?;
        let snapshot = work.join("rivetlua-native-worker");
        fs::copy(&alias, &snapshot)
            .map_err(|error| format!("P16 worker snapshot 失敗：{error}"))?;
        let binary = artifact(&snapshot)?;
        if built_artifact.1 != binary.1 {
            return Err("P16 worker build-time SHA 與 snapshot 不符".into());
        }
        log.push_str(&format!(
            "P16_WORKER_BUILD {profile} {target} PASS artifact={} sha256={}\n",
            alias.display(),
            built_artifact.1
        ));
        evidence.build_log = Some(write_log(&log_path, &log)?);
        evidence.artifact = Some(built_artifact);
        evidence.binary = Some(binary);
        evidence.status = "PASS";
        evidence.diagnostic = "worker binary profile snapshot 已建立".into();
        Ok(())
    })();
    if let Err(error) = attempt {
        evidence.diagnostic = error;
        if evidence.build_log.is_none() {
            evidence.build_log = write_log(&log_path, &evidence.diagnostic).ok();
        }
    }
    evidence
}

fn c_case(
    root: &Path,
    work: &Path,
    case: &Case,
    profile: &str,
    target: &str,
    manifest: &Manifest,
    library: &StaticLibrary,
    cache: &mut HashMap<String, TestBinary>,
    run_cache: &mut HashMap<String, RustTestRun>,
) -> CaseEvidence {
    let mut result = CaseEvidence::new();
    let attempt = (|| -> Result<(), String> {
        let short = profile.strip_suffix("-i64f64").ok_or("P16 profile 無效")?;
        let source = root.join(&case.fixture);
        let header = root.join(format!("include/rivetlua/{short}/lua.h"));
        let include = root.join(format!("include/rivetlua/{short}"));
        let binary = work.join(format!("case-{}", case.id));
        result.source = Some(artifact(&source)?);
        result.header = Some(artifact(&header)?);
        result.header_set = Some(
            manifest
                .header_sets
                .get(short)
                .ok_or("P16 header set 缺失")?
                .clone(),
        );
        result.library = Some(artifact(&library.path)?);
        result.staticlib_artifact = Some(library.artifact.clone());
        result.staticlib_build_command = library.build_command.clone();
        result.staticlib_build_exit_code = Some(0);
        result.staticlib_build_log = Some(library.build_log.clone());
        result.native_static_libs = library.native_flags.clone();
        if let Some(path) = matrix::original_source(&case.id) {
            result.upstream_source = Some(artifact(&root.join(path))?);
        }
        result.build_command = vec![
            "cc".into(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            format!("-I{}", include.display()),
            format!("-I{}", root.join("include/rivetlua").display()),
            source.display().to_string(),
            library.path.display().to_string(),
            "-o".into(),
            binary.display().to_string(),
        ];
        result
            .build_command
            .extend(library.native_flags.iter().cloned());
        result.status = "FAIL";
        let build = match output(root, &result.build_command) {
            Ok(build) => build,
            Err(error) => {
                result.build_log = Some(write_log(
                    &work.join(format!("{}-build.log", case.id)),
                    &error,
                )?);
                return Err(error);
            }
        };
        result.build_exit_code = build.exit_code;
        result.build_signal = build.signal;
        let mut build_log = build.log();
        if build.success() {
            build_log.push_str(&format!("P16_BUILD {} {profile} {target} PASS\n", case.id));
        }
        result.build_log = Some(write_log(
            &work.join(format!("{}-build.log", case.id)),
            &build_log,
        )?);
        if !build.success() {
            return Err(format!(
                "P16 {} C build exit={:?} signal={:?}",
                case.id, build.exit_code, build.signal
            ));
        }
        result.binary = Some(artifact(&binary)?);
        result.command = vec![binary.display().to_string()];
        result.cwd = Some(root.display().to_string());
        let run = match output(root, &result.command) {
            Ok(run) => run,
            Err(error) => {
                result.log = Some(write_log(
                    &work.join(format!("{}-run.log", case.id)),
                    &error,
                )?);
                return Err(error);
            }
        };
        result.exit_code = run.exit_code;
        result.signal = run.signal;
        result.matched = 1;
        let mut log = run.log();
        result.c_log = Some(write_log(
            &work.join(format!("{}-c-body.log", case.id)),
            &log,
        )?);
        result.log = Some(write_log(&work.join(format!("{}-run.log", case.id)), &log)?);
        if !run.success()
            || !log
                .lines()
                .any(|line| line == format!("P16_C_BODY {} PASS", case.id))
        {
            result.failed = 1;
            return Err(format!(
                "P16 {} C body exit={:?} signal={:?} 或 marker 不符",
                case.id, run.exit_code, run.signal
            ));
        }
        for proof in matrix::rust_proofs(&case.id) {
            let run = match rust_test(
                root,
                work,
                profile,
                &case.id,
                proof.target,
                proof.test,
                &[],
                cache,
                run_cache,
            ) {
                Ok(run) => run,
                Err(failure) => {
                    result.failed = 1;
                    let diagnostic = failure.diagnostic.clone();
                    result.rust_failure = Some(failure);
                    return Err(diagnostic);
                }
            };
            result.local_tests.push(run);
            for assertion in proof.assertions {
                log.push_str(&format!("P16_ASSERT {} {assertion}=PASS\n", case.id));
            }
        }
        for assertion in &case.assertions {
            if !log
                .lines()
                .any(|line| line == format!("P16_ASSERT {} {assertion}=PASS", case.id))
            {
                return Err(format!("P16 {} {assertion} 無具名 body/test 證據", case.id));
            }
        }
        result.matched = 1;
        result.passed = 1;
        log.push_str(&format!(
            "P16_CASE {} {profile} {target} PASS matched=1 passed=1 failed=0 ignored=0\n",
            case.id
        ));
        result.log = Some(write_log(&work.join(format!("{}-run.log", case.id)), &log)?);
        result.status = "PASS";
        result.diagnostic = "C fixture body 與固定具名 Rust tests 均通過".into();
        Ok(())
    })();
    if let Err(error) = attempt {
        result.diagnostic = error;
        if result.matched == 1 {
            result.passed = 0;
            result.failed = 1;
        }
    }
    result
}

fn rust_case(
    root: &Path,
    work: &Path,
    case: &Case,
    profile: &str,
    target: &str,
    worker: Option<&WorkerEvidence>,
    library: Option<&StaticLibrary>,
    cache: &mut HashMap<String, TestBinary>,
    run_cache: &mut HashMap<String, RustTestRun>,
) -> CaseEvidence {
    let mut result = CaseEvidence::new();
    let attempt = (|| -> Result<(), String> {
        let proofs = matrix::rust_proofs(&case.id);
        if proofs.len() != 1 {
            return Err(format!("P16 {} 尚無固定 Rust test", case.id));
        }
        result.status = "FAIL";
        let native = matches!(
            case.id.as_str(),
            "ABI-005" | "ABI-006" | "ABI-007" | "ABI-NEG-005"
        );
        let mut run_env = Vec::new();
        if native {
            let base = work.join(format!("child-{}-{}", case.id, std::process::id()));
            let evidence_dir = (0..1000)
                .map(|index| base.with_extension(index.to_string()))
                .find(|path| fs::create_dir(path).is_ok())
                .ok_or("P16 native evidence 目錄無法建立")?;
            fs::set_permissions(&evidence_dir, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("P16 native evidence 私有目錄權限設定失敗：{error}"))?;
            run_env.push((
                "RIVETLUA_P16_EVIDENCE_DIR".into(),
                evidence_dir.display().to_string(),
            ));
            if matches!(case.id.as_str(), "ABI-006" | "ABI-NEG-005") {
                let worker = worker.ok_or("P16 worker build 證據缺失")?;
                result.worker = Some(worker.clone());
                if worker.status != "PASS" {
                    return Err(format!("P16 worker build 失敗：{}", worker.diagnostic));
                }
                let binary = worker.binary.as_ref().ok_or("P16 worker snapshot 缺失")?;
                run_env.push(("RIVETLUA_P16_WORKER_BIN".into(), binary.0.clone()));
            }
        }
        if case.id == "SDK-MODULE" {
            let library = library.ok_or("P16 SDK staticlib snapshot 缺失")?;
            let base = work.join(format!("sdk-{}", std::process::id()));
            let evidence_dir = (0..1000)
                .map(|index| base.with_extension(index.to_string()))
                .find(|path| fs::create_dir(path).is_ok())
                .ok_or("P16 SDK evidence 目錄無法建立")?;
            fs::set_permissions(&evidence_dir, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("P16 SDK evidence 私有目錄權限設定失敗：{error}"))?;
            let short = profile
                .strip_suffix("-i64f64")
                .ok_or("P16 SDK profile 無效")?;
            run_env.extend([
                ("RIVETLUA_P16_SDK_ROOT".into(), root.display().to_string()),
                (
                    "RIVETLUA_P16_SDK_EVIDENCE_DIR".into(),
                    evidence_dir.display().to_string(),
                ),
                ("RIVETLUA_P16_SDK_PROFILE".into(), short.into()),
                ("RIVETLUA_P16_SDK_TARGET".into(), target.into()),
                (
                    "RIVETLUA_P16_SDK_HOST_TRUST".into(),
                    "explicit-sdk-host-process-permissions-v1".into(),
                ),
                (
                    "RIVETLUA_P16_SDK_LIB_PATH".into(),
                    library.path.display().to_string(),
                ),
                (
                    "RIVETLUA_P16_SDK_NATIVE_LIBS".into(),
                    library.native_flags.join("\u{1f}"),
                ),
                (
                    "RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_PATH".into(),
                    library.build_log.0.clone(),
                ),
                (
                    "RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_SHA256".into(),
                    library.build_log.1.clone(),
                ),
            ]);
        }
        result.environment = run_env.clone();
        let run = match rust_test(
            root,
            work,
            profile,
            &case.id,
            proofs[0].target,
            proofs[0].test,
            &run_env,
            cache,
            run_cache,
        ) {
            Ok(run) => run,
            Err(failure) => {
                result.source = failure.source.clone();
                result.binary = failure.binary.clone();
                result.build_command = failure.build_command.clone();
                result.build_exit_code = failure.build_exit_code;
                result.build_signal = failure.build_signal;
                result.build_log = failure.build_log.clone();
                result.command = failure.command.clone();
                result.environment = failure.environment.clone();
                result.cwd = Some(root.display().to_string());
                result.exit_code = failure.exit_code;
                result.signal = failure.signal;
                result.log = failure.log.clone();
                result.matched = failure.matched;
                result.passed = failure.passed;
                result.failed = failure.failed;
                let diagnostic = failure.diagnostic.clone();
                result.rust_failure = Some(failure);
                return Err(diagnostic);
            }
        };
        result.source = Some((run.source_path.clone(), run.source_sha256.clone()));
        result.binary = Some((run.binary_path.clone(), run.binary_sha256.clone()));
        result.build_command = run.build_command.clone();
        result.build_exit_code = Some(0);
        result.build_log = Some((run.build_log_path.clone(), run.build_log_sha256.clone()));
        result.command = run.command.clone();
        result.environment = run.environment.clone();
        result.cwd = Some(root.display().to_string());
        result.exit_code = Some(0);
        result.local_tests.push(run);
        result.matched = 1;
        if case.id == "SDK-MODULE" {
            let library = library.ok_or("P16 SDK staticlib snapshot 缺失")?;
            result.library = Some(artifact(&library.path)?);
            result.staticlib_artifact = Some(library.artifact.clone());
            result.staticlib_build_command = library.build_command.clone();
            result.staticlib_build_exit_code = Some(0);
            result.staticlib_build_log = Some(library.build_log.clone());
            result.native_static_libs = library.native_flags.clone();
        }
        let mut log = fs::read_to_string(&result.local_tests[0].log_path)
            .map_err(|error| format!("P16 Rust log 不可讀：{error}"))?;
        if native {
            result.log = Some(write_log(&work.join(format!("{}-run.log", case.id)), &log)?);
            let receipt = super::native::receipt(&log, &case.id, profile)?;
            result.artifact_record =
                Some(super::native::record_artifact(root, &run_env, &receipt)?);
            let json = result.json(case, profile, target, root);
            let parsed = StrictJsonParser::parse(&json)?;
            super::native::verify_case(root, &parsed, &case.id, profile, target, &log)?;
        }
        if case.id == "SDK-MODULE" {
            let short = profile
                .strip_suffix("-i64f64")
                .ok_or("P16 SDK profile 無效")?;
            let receipt = super::sdk::receipt(&log, short)?;
            let evidence_dir = run_env
                .iter()
                .find(|(name, _)| name == "RIVETLUA_P16_SDK_EVIDENCE_DIR")
                .map(|(_, value)| Path::new(value))
                .ok_or("P16 SDK evidence dir 缺失")?;
            result.artifact_record = Some(super::sdk::record_artifact(evidence_dir, &receipt)?);
        }
        for assertion in proofs[0].assertions {
            log.push_str(&format!("P16_ASSERT {} {assertion}=PASS\n", case.id));
        }
        if case.id == "ABI-NEG-002" {
            log.push_str(
                "P16_EVIDENCE ABI-NEG-002 foreign_unwind=STATIC_AUDIT panic=RUNTIME_GUARD\n",
            );
        }
        result.matched = 1;
        result.passed = 1;
        log.push_str(&format!(
            "P16_CASE {} {profile} {target} PASS matched=1 passed=1 failed=0 ignored=0\n",
            case.id
        ));
        result.log = Some(write_log(&work.join(format!("{}-run.log", case.id)), &log)?);
        if case.id == "SDK-MODULE" {
            let json = result.json(case, profile, target, root);
            let parsed = StrictJsonParser::parse(&json)?;
            super::gate::sdk_modules_evidence(root, &parsed, case, profile, target, &log)?;
        }
        result.status = "PASS";
        result.diagnostic = "固定具名 Rust test 通過".into();
        Ok(())
    })();
    if let Err(error) = attempt {
        result.diagnostic = error;
        if result.matched == 1 {
            result.passed = 0;
            result.failed = 1;
        }
    }
    result
}

fn build_audit_case(
    root: &Path,
    work: &Path,
    case: &Case,
    profile: &str,
    target: &str,
    library: &StaticLibrary,
) -> CaseEvidence {
    let mut result = CaseEvidence::new();
    let attempt = (|| -> Result<(), String> {
        if case.id != "ABI-NEG-006" || case.fixture != "tests/p16/acceptance/abi_neg006.py" {
            return Err("P16 build audit 非固定 fixture".into());
        }
        result.status = "FAIL";
        let source = root.join(&case.fixture);
        result.source = Some(artifact(&source)?);
        result.upstream_source = Some(artifact(&root.join("crates/rivetlua-capi/build.rs"))?);
        result.library = Some(artifact(&library.path)?);
        result.staticlib_artifact = Some(library.artifact.clone());
        result.staticlib_build_command = library.build_command.clone();
        result.staticlib_build_exit_code = Some(0);
        result.staticlib_build_log = Some(library.build_log.clone());
        result.native_static_libs = library.native_flags.clone();
        result.command = vec![
            "python3".into(),
            source.display().to_string(),
            "--root".into(),
            root.display().to_string(),
            "--library".into(),
            library.path.display().to_string(),
            "--build-log".into(),
            library.build_log.0.clone(),
            "--profile".into(),
            profile.into(),
            "--target".into(),
            target.into(),
            "--provenance".into(),
            work.join("neg006-provenance").display().to_string(),
        ];
        result.cwd = Some(root.display().to_string());
        let run = output(root, &result.command)?;
        result.exit_code = run.exit_code;
        result.signal = run.signal;
        let mut log = run.log();
        result.matched = 1;
        if !run.success() {
            result.failed = 1;
            result.log = Some(write_log(&work.join("ABI-NEG-006-run.log"), &log)?);
            return Err("P16 C fallback audit 失敗".into());
        }
        result.artifact_record = Some(artifact(&work.join("neg006-provenance/receipt.json"))?);
        if !log
            .lines()
            .any(|line| line == "P16_ASSERT ABI-NEG-006 reject_c_lua_fallback=PASS")
            || log
                .lines()
                .filter(|line| line.starts_with("P16_NEG006_CONTROL "))
                .count()
                != 7
        {
            return Err("P16 C fallback audit 缺負向控制或 assertion".into());
        }
        result.passed = 1;
        log.push_str(&format!(
            "P16_CASE {} {profile} {target} PASS matched=1 passed=1 failed=0 ignored=0\n",
            case.id
        ));
        result.log = Some(write_log(&work.join("ABI-NEG-006-run.log"), &log)?);
        result.status = "PASS";
        result.diagnostic = "固定 staticlib C fallback 稽核與負向控制通過".into();
        Ok(())
    })();
    if let Err(error) = attempt {
        result.diagnostic = error;
        if result.matched == 1 {
            result.passed = 0;
            result.failed = 1;
        }
    }
    result
}

fn execute_proof(
    root: &Path,
    work: &Path,
    key: ProofKey,
    index: usize,
    manifest: &Manifest,
    library: &StaticLibrary,
    selection: Option<&Snapshot>,
    cache: &mut HashMap<String, TestBinary>,
    run_cache: &mut HashMap<String, RustTestRun>,
) -> ProofEvidence {
    let mut proof = ProofEvidence::new(key.clone());
    let profile = key.profile().to_owned();
    let prefix = work.join(format!("proof-{index}"));
    let attempt = (|| -> Result<(), String> {
        let header = root.join(format!("include/rivetlua/{profile}/lua.h"));
        proof.header = Some(artifact(&header)?);
        proof.header_set = Some(
            manifest
                .header_sets
                .get(&profile)
                .ok_or("P16 proof header set 缺失")?
                .clone(),
        );
        proof.status = "FAIL";
        match &key {
            ProofKey::Pinned(_) => {
                proof.source = Some(artifact(&root.join("tests/p16/generate_manifest.py"))?);
                proof.build_command = vec![
                    "python3".into(),
                    "tests/p16/generate_manifest.py".into(),
                    "check".into(),
                ];
                let result = output(root, &proof.build_command)?;
                proof.build_exit_code = result.exit_code;
                proof.build_signal = result.signal;
                proof.matched = 1;
                let mut body = result.log();
                if !result.success() {
                    proof.failed = 1;
                    proof.build_log = Some(write_log(&prefix.with_extension("build.log"), &body)?);
                    return Err("P16 pinned generator check 失敗".into());
                }
                proof.build_log = Some(write_log(&prefix.with_extension("build.log"), &body)?);
                super::gate::verify_header_set(root, manifest, &profile)?;
                body.push_str(&format!("P16_PROOF {} PASS\n", key.id()));
                proof.build_log = Some(write_log(&prefix.with_extension("build.log"), &body)?);
            }
            ProofKey::Surface(_) => {
                let source = root.join(format!("tests/p16/surface_{profile}.c"));
                proof.source = Some(artifact(&source)?);
                proof.build_command = vec![
                    "cc".into(),
                    "-std=c11".into(),
                    "-Wall".into(),
                    "-Wextra".into(),
                    "-Werror".into(),
                    format!(
                        "-I{}",
                        root.join(format!("include/rivetlua/{profile}")).display()
                    ),
                    format!("-I{}", root.join("include/rivetlua").display()),
                    "-fsyntax-only".into(),
                    source.display().to_string(),
                ];
                let result = output(root, &proof.build_command)?;
                proof.build_exit_code = result.exit_code;
                proof.build_signal = result.signal;
                proof.matched = 1;
                let mut body = result.log();
                if !result.success() {
                    proof.failed = 1;
                    proof.build_log = Some(write_log(&prefix.with_extension("build.log"), &body)?);
                    return Err("P16 fixed surface 編譯失敗".into());
                }
                body.push_str(&format!("P16_PROOF {} PASS\n", key.id()));
                proof.build_log = Some(write_log(&prefix.with_extension("build.log"), &body)?);
            }
            ProofKey::HeaderSelection(_) => {
                let observed = selection.ok_or("P16 HeaderSelection 預處理證據缺失")?;
                proof.source = Some(artifact(&selection::source(root))?);
                proof.build_command = observed.command.clone();
                proof.build_exit_code = Some(0);
                proof.matched = 1;
                proof.build_log = Some(write_log(
                    &prefix.with_extension("build.log"),
                    &observed.output,
                )?);
            }
            ProofKey::HeaderValues(_) | ProofKey::OfficialValues(_) => {
                let observed = selection.ok_or("P16 value probe selection 缺失")?;
                let official = matches!(key, ProofKey::OfficialValues(_));
                super::valueprobe::verify_vendor(root, manifest, &profile)?;
                if official {
                    proof.header = Some(artifact(
                        &super::valueprobe::vendor_dir(root, &profile)?.join("lua.h"),
                    )?);
                }
                proof.source = Some(artifact(&super::valueprobe::source(root))?);
                let binary = prefix.with_extension("bin");
                proof.build_command =
                    super::valueprobe::command(root, &profile, official, &binary)?;
                let build = output(root, &proof.build_command)?;
                proof.build_exit_code = build.exit_code;
                proof.build_signal = build.signal;
                proof.build_log = Some(write_log(
                    &prefix.with_extension("build.log"),
                    &build.log(),
                )?);
                if !build.success() {
                    return Err("P16 value probe C 編譯失敗".into());
                }
                proof.binary = Some(artifact(&binary)?);
                proof.command = vec![binary.display().to_string()];
                let run = output(root, &proof.command)?;
                proof.exit_code = run.exit_code;
                proof.signal = run.signal;
                proof.matched = 1;
                let mut body = run.log();
                proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                if !run.success() {
                    proof.failed = 1;
                    return Err("P16 value probe C 執行失敗".into());
                }
                let expected = super::valueprobe::expected(manifest, &profile, observed)?;
                let values = super::valueprobe::observations(&body)?;
                if values
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected
                {
                    proof.failed = 1;
                    return Err("P16 value probe 逐列 C marker 集合不符".into());
                }
                body.push_str(&format!("P16_PROOF {} PASS\n", key.id()));
                proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
            }
            ProofKey::MacroEffects(_) => {
                let observed = selection.ok_or("P16 MacroEffects selection 缺失")?;
                let source = root.join("tests/p16/acceptance/macro_effects.c");
                proof.source = Some(artifact(&source)?);
                let binary = prefix.with_extension("bin");
                proof.build_command = vec![
                    "cc".into(),
                    "-std=c11".into(),
                    "-Wall".into(),
                    "-Wextra".into(),
                    "-Werror".into(),
                    format!(
                        "-I{}",
                        root.join(format!("include/rivetlua/{profile}")).display()
                    ),
                    format!("-I{}", root.join("include/rivetlua").display()),
                ];
                if profile == "lua54" {
                    proof.build_command.push("-DLUA_COMPAT_5_3".into());
                } else {
                    proof.build_command.push("-DLUA_COMPAT_APIINTCASTS".into());
                }
                proof.build_command.extend([
                    source.display().to_string(),
                    "-lm".into(),
                    "-o".into(),
                    binary.display().to_string(),
                ]);
                let build = output(root, &proof.build_command)?;
                proof.build_exit_code = build.exit_code;
                proof.build_signal = build.signal;
                proof.build_log = Some(write_log(
                    &prefix.with_extension("build.log"),
                    &build.log(),
                )?);
                if !build.success() {
                    return Err("P16 macro effect C probe 編譯失敗".into());
                }
                proof.binary = Some(artifact(&binary)?);
                proof.command = vec![binary.display().to_string()];
                let run = output(root, &proof.command)?;
                proof.exit_code = run.exit_code;
                proof.signal = run.signal;
                proof.matched = 1;
                let mut body = run.log();
                if !run.success() {
                    proof.failed = 1;
                    proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                    return Err("P16 macro effect C probe 執行失敗".into());
                }
                if let Err(error) = selection::verify_macro_output(&profile, &body) {
                    proof.failed = 1;
                    proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                    return Err(error);
                }
                let selected = manifest
                    .rows
                    .iter()
                    .filter(|row| {
                        row.profile == profile
                            && row.status == "HEADER_ONLY"
                            && row.kind == "macro"
                            && row
                                .definition
                                .starts_with(&format!("#define {}(", row.name))
                            && matches!(
                                selection::classify(observed, row),
                                Ok(Applicability::Selected(_))
                            )
                    })
                    .map(|row| row.name.as_str())
                    .collect::<Vec<_>>();
                let actual = body
                    .lines()
                    .filter_map(|line| {
                        line.strip_prefix("P16_MACRO ")
                            .and_then(|rest| rest.strip_suffix(" PASS"))
                    })
                    .collect::<Vec<_>>();
                if selected.len() != actual.len()
                    || selected
                        .iter()
                        .any(|name| actual.iter().filter(|actual| *actual == name).count() != 1)
                {
                    proof.failed = 1;
                    proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                    return Err("P16 selected macro 各名稱專屬 effect marker 不符".into());
                }
                body.push_str(&format!("P16_PROOF {} PASS\n", key.id()));
                proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
            }
            ProofKey::Layout(_)
            | ProofKey::CFixture { .. }
            | ProofKey::CFixtureFailFalse { .. } => {
                let source = match &key {
                    ProofKey::Layout(_) => root.join("tests/p16/acceptance/layout_identity.c"),
                    ProofKey::CFixture { source, .. } => root.join(source),
                    ProofKey::CFixtureFailFalse { .. } => root.join(rowproof::FAILFALSE_SOURCE),
                    _ => unreachable!(),
                };
                proof.source = Some(artifact(&source)?);
                proof.library = Some(artifact(&library.path)?);
                let binary = prefix.with_extension("bin");
                proof.build_command = if matches!(&key, ProofKey::CFixtureFailFalse { .. }) {
                    rowproof::failfalse_command(
                        root,
                        &profile,
                        &library.path,
                        &binary,
                        &library.native_flags,
                    )?
                } else {
                    let mut command = vec![
                        "cc".into(),
                        "-std=c11".into(),
                        "-Wall".into(),
                        "-Wextra".into(),
                        "-Werror".into(),
                        format!(
                            "-I{}",
                            root.join(format!("include/rivetlua/{profile}")).display()
                        ),
                        format!("-I{}", root.join("include/rivetlua").display()),
                    ];
                    if matches!(&key, ProofKey::CFixture { source, .. } if source == "tests/p16/acceptance/api_effects.c")
                    {
                        command.push(
                            if profile == "lua54" {
                                "-DLUA_COMPAT_5_3"
                            } else {
                                "-DLUA_COMPAT_APIINTCASTS"
                            }
                            .into(),
                        );
                    }
                    command.extend([
                        source.display().to_string(),
                        library.path.display().to_string(),
                        "-o".into(),
                        binary.display().to_string(),
                    ]);
                    command.extend(library.native_flags.iter().cloned());
                    command
                };
                let build = output(root, &proof.build_command)?;
                proof.build_exit_code = build.exit_code;
                proof.build_signal = build.signal;
                proof.build_log = Some(write_log(
                    &prefix.with_extension("build.log"),
                    &build.log(),
                )?);
                if !build.success() {
                    return Err("P16 C proof 編譯失敗".into());
                }
                proof.binary = Some(artifact(&binary)?);
                proof.command = vec![binary.display().to_string()];
                if matches!(&key, ProofKey::CFixture { source, .. } if source == "tests/p16/load_b3.c")
                {
                    let file = prefix.with_extension("load-b3.lua");
                    if file.exists() {
                        return Err("P16 load_b3 專屬暫存檔已存在".into());
                    }
                    proof.command.push(file.display().to_string());
                }
                let run = output(root, &proof.command)?;
                proof.exit_code = run.exit_code;
                proof.signal = run.signal;
                proof.matched = 1;
                let mut body = run.log();
                if !run.success() {
                    proof.failed = 1;
                    proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                    return Err("P16 C proof 執行失敗".into());
                }
                if matches!(key, ProofKey::Layout(_))
                    && !body.lines().any(|line| line == "P16_LAYOUT 37 PASS")
                {
                    proof.failed = 1;
                    proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
                    return Err("P16 layout identity 未驗證 37 欄".into());
                }
                body.push_str(&format!("P16_PROOF {} PASS\n", key.id()));
                proof.log = Some(write_log(&prefix.with_extension("run.log"), &body)?);
            }
            ProofKey::RustNamed {
                target: test_target,
                test,
                ..
            }
            | ProofKey::RustCrossContract {
                target: test_target,
                test,
                ..
            } => {
                proof.source = Some(artifact(
                    &root.join(format!("crates/rivetlua-capi/tests/{test_target}.rs")),
                )?);
                match rust_test(
                    root,
                    work,
                    &format!("{profile}-i64f64"),
                    &format!("proof-{index}"),
                    test_target,
                    test,
                    &[],
                    cache,
                    run_cache,
                ) {
                    Ok(run) => {
                        proof.source = Some((run.source_path, run.source_sha256));
                        proof.binary = Some((run.binary_path, run.binary_sha256));
                        proof.build_command = run.build_command;
                        proof.build_exit_code = Some(0);
                        proof.build_log = Some((run.build_log_path, run.build_log_sha256));
                        proof.command = run.command;
                        proof.exit_code = Some(0);
                        proof.log = Some((run.log_path, run.log_sha256));
                        proof.matched = 1;
                    }
                    Err(failure) => {
                        proof.source = failure.source;
                        proof.binary = failure.binary;
                        proof.build_command = failure.build_command;
                        proof.build_exit_code = failure.build_exit_code;
                        proof.build_signal = failure.build_signal;
                        proof.build_log = failure.build_log;
                        proof.command = failure.command;
                        proof.exit_code = failure.exit_code;
                        proof.signal = failure.signal;
                        proof.log = failure.log;
                        proof.matched = failure.matched;
                        proof.passed = failure.passed;
                        proof.failed = failure.failed;
                        return Err(failure.diagnostic);
                    }
                }
            }
        }
        proof.passed = 1;
        proof.status = "PASS";
        proof.diagnostic = "固定 typed proof 完成".into();
        Ok(())
    })();
    if let Err(error) = attempt {
        proof.diagnostic = error;
        if proof.matched == 1 && proof.passed == 0 {
            proof.failed = 1;
        }
        if proof.build_log.is_none() && !proof.build_command.is_empty() {
            proof.build_log =
                write_log(&prefix.with_extension("build.log"), &proof.diagnostic).ok();
        }
        if proof.log.is_none() && !proof.command.is_empty() {
            proof.log = write_log(&prefix.with_extension("run.log"), &proof.diagnostic).ok();
        }
    }
    proof
}

fn row_report(
    row: &Row,
    plan: &Result<Vec<ProofKey>, String>,
    proof_results: &HashMap<String, &'static str>,
    unresolved: &mut BTreeMap<String, Vec<String>>,
    selection: Option<&Snapshot>,
) -> String {
    let applicability = selection.and_then(|observed| selection::classify(observed, row).ok());
    match plan {
        Ok(keys) => {
            let ids = keys.iter().map(ProofKey::id).collect::<Vec<_>>();
            let failed = ids
                .iter()
                .filter(|id| proof_results.get(*id).copied() == Some("FAIL"))
                .cloned()
                .collect::<Vec<_>>();
            let pending = ids
                .iter()
                .filter(|id| !matches!(proof_results.get(*id).copied(), Some("PASS" | "FAIL")))
                .cloned()
                .collect::<Vec<_>>();
            if !failed.is_empty() {
                let mut reason = format!("已執行 proof 失敗：{}", failed.join(","));
                if !pending.is_empty() {
                    reason.push_str(&format!("；尚未執行：{}", pending.join(",")));
                }
                unresolved
                    .entry("已執行 proof 失敗".into())
                    .or_default()
                    .push(row.id.clone());
                report::row_with_observation(row, "FAIL", &ids, &reason, applicability.as_ref())
            } else if !pending.is_empty() {
                let reason = format!("必要 proof 尚未執行：{}", pending.join(","));
                unresolved
                    .entry("必要 proof 尚未執行".into())
                    .or_default()
                    .push(row.id.clone());
                report::row_with_observation(row, "NOT_RUN", &ids, &reason, applicability.as_ref())
            } else {
                report::row_with_observation(row, "PASS", &ids, "", applicability.as_ref())
            }
        }
        Err(reason) => {
            unresolved
                .entry(reason.clone())
                .or_default()
                .push(row.id.clone());
            report::row_with_observation(row, "NOT_RUN", &[], reason, applicability.as_ref())
        }
    }
}

pub(super) fn run(
    root: &Path,
    profile: &str,
    target: &str,
    digest: &str,
    cases: &[Case],
    manifest: &Manifest,
) -> Result<(), String> {
    if !root.join("crates/rivetlua-capi/Cargo.toml").is_file() {
        return Err("P16 CAPI package 缺失；所有案例維持 NOT_RUN".into());
    }
    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .ok_or("P16 runner 需要外接 CARGO_TARGET_DIR")?;
    if !target_dir.is_absolute() || !target_dir.is_dir() {
        return Err("P16 runner CARGO_TARGET_DIR 必須為已存在絕對目錄".into());
    }
    let work = target_dir.join(format!("p16-acceptance/{profile}/{target}"));
    fs::create_dir_all(&work).map_err(|error| format!("P16 runner work 失敗：{error}"))?;
    let library = match staticlib(root, &work, profile, target, &target_dir) {
        Ok(library) => library,
        Err(error) => {
            let log = work.join("staticlib-build.log");
            let diagnostic = if log.is_file() {
                format!(
                    "{error}; build_log={} sha256={}",
                    log.display(),
                    sha_file(&log)?
                )
            } else {
                error
            };
            let case_reports = cases
                .iter()
                .map(|case| report::case_not_run(case, profile, target))
                .collect::<Vec<_>>();
            let short = profile.strip_suffix("-i64f64").ok_or("P16 profile 無效")?;
            let row_reports = manifest
                .rows
                .iter()
                .filter(|row| row.profile == short)
                .map(report::row_not_run)
                .collect::<Vec<_>>();
            report::partial(
                root,
                profile,
                target,
                digest,
                manifest,
                &case_reports,
                &row_reports,
                &diagnostic,
            )?;
            return Err(diagnostic);
        }
    };
    let mut cache = HashMap::new();
    let mut run_cache = HashMap::new();
    let mut worker = None;
    let mut observed = cases
        .iter()
        .map(|case| {
            if matches!(case.id.as_str(), "ABI-006" | "ABI-NEG-005") && worker.is_none() {
                worker = Some(worker_binary(root, &work, profile, target, &target_dir));
            }
            match (case.execution_kind, case.id.as_str()) {
                (
                    ExecutionKind::CDriver,
                    "ABI-001" | "ABI-002" | "ABI-003" | "ABI-004" | "ABI-NEG-001" | "ABI-NEG-004"
                    | "ABI-STRESS",
                ) => Some(c_case(
                    root,
                    &work,
                    case,
                    profile,
                    target,
                    manifest,
                    &library,
                    &mut cache,
                    &mut run_cache,
                )),
                (
                    ExecutionKind::RustTest,
                    "ABI-005" | "ABI-006" | "ABI-007" | "ABI-NEG-002" | "ABI-NEG-003"
                    | "ABI-NEG-005",
                ) => Some(rust_case(
                    root,
                    &work,
                    case,
                    profile,
                    target,
                    worker.as_ref(),
                    None,
                    &mut cache,
                    &mut run_cache,
                )),
                (ExecutionKind::SdkModules, "SDK-MODULE") => Some(rust_case(
                    root,
                    &work,
                    case,
                    profile,
                    target,
                    None,
                    Some(&library),
                    &mut cache,
                    &mut run_cache,
                )),
                (ExecutionKind::BuildAudit, "ABI-NEG-006") => Some(build_audit_case(
                    root, &work, case, profile, target, &library,
                )),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    let short = profile.strip_suffix("-i64f64").ok_or("P16 profile 無效")?;
    let selection = selection::capture(root, short);
    let row_plans = manifest
        .rows
        .iter()
        .filter(|row| row.profile == short)
        .map(|row| {
            (
                row,
                rowproof::required_with(root, row, selection.as_ref().ok()),
            )
        })
        .collect::<Vec<_>>();
    let proof_keys = row_plans
        .iter()
        .filter_map(|(_, plan)| plan.as_ref().ok())
        .flat_map(|keys| keys.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut proofs = proof_keys
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            execute_proof(
                root,
                &work,
                key,
                index,
                manifest,
                &library,
                selection.as_ref().ok(),
                &mut cache,
                &mut run_cache,
            )
        })
        .collect::<Vec<_>>();
    for proof in &mut proofs {
        if !matches!(&proof.key, ProofKey::CFixture { source, .. } if source == "tests/p16/acceptance/api_effects.c")
            || proof.status != "PASS"
        {
            continue;
        }
        let verify = (|| -> Result<(), String> {
            let log = fs::read_to_string(&proof.log.as_ref().ok_or("P16 per-symbol C log 缺失")?.0)
                .map_err(|error| error.to_string())?;
            let reference = format!("tests/p16/acceptance/api_effects.c:C_LINK_RUN:{short}:PASS");
            for row in manifest.rows.iter().filter(|row| {
                row.profile == short && row.evidence.split(';').any(|part| part == reference)
            }) {
                let marker = format!("P16_C_EFFECT {} PASS", row.name);
                if log.lines().filter(|line| *line == marker).count() != 1 {
                    return Err(format!("P16 C ABI {} 缺個別 effect marker", row.name));
                }
            }
            Ok(())
        })();
        if let Err(error) = verify {
            proof.status = "FAIL";
            proof.passed = 0;
            proof.failed = proof.matched;
            proof.diagnostic = error;
        }
    }
    let product_id = ProofKey::HeaderValues(short.to_owned()).id();
    let official_id = ProofKey::OfficialValues(short.to_owned()).id();
    if let (Some(product_index), Some(official_index)) = (
        proofs.iter().position(|proof| proof.key.id() == product_id),
        proofs
            .iter()
            .position(|proof| proof.key.id() == official_id),
    ) {
        if proofs[product_index].status == "PASS" && proofs[official_index].status == "PASS" {
            let compare = (|| -> Result<(), String> {
                let product = fs::read_to_string(
                    &proofs[product_index]
                        .log
                        .as_ref()
                        .ok_or("P16 product values log 缺失")?
                        .0,
                )
                .map_err(|error| error.to_string())?;
                let official = fs::read_to_string(
                    &proofs[official_index]
                        .log
                        .as_ref()
                        .ok_or("P16 official values log 缺失")?
                        .0,
                )
                .map_err(|error| error.to_string())?;
                if super::valueprobe::observations(&product)?
                    != super::valueprobe::observations(&official)?
                {
                    return Err("P16 SDK/official 逐名稱 C 值／型別不符".into());
                }
                Ok(())
            })();
            if let Err(error) = compare {
                let proof = &mut proofs[product_index];
                proof.status = "FAIL";
                proof.passed = 0;
                proof.failed = proof.matched;
                proof.diagnostic = error;
            }
        }
    }
    let drift = match crate::source_digest(root) {
        Ok(current) if current == digest => None,
        Ok(_) => Some("P16 runner 執行期間來源 digest 已變更".to_owned()),
        Err(error) => Some(format!("P16 runner 結束時來源 digest 無法重算：{error}")),
    };
    if let Some(diagnostic) = &drift {
        invalidate_stale_evidence(&mut observed, diagnostic);
        for proof in &mut proofs {
            if proof.status == "PASS" {
                proof.status = "FAIL";
                proof.passed = 0;
                proof.failed = proof.matched;
                proof.diagnostic = diagnostic.clone();
            }
        }
    }
    let proof_results = proofs
        .iter()
        .map(|proof| (proof.key.id(), proof.status))
        .collect::<HashMap<_, _>>();
    let case_reports = cases
        .iter()
        .zip(&observed)
        .map(|(case, evidence)| {
            evidence.as_ref().map_or_else(
                || report::case_not_run(case, profile, target),
                |evidence| evidence.json(case, profile, target, root),
            )
        })
        .collect::<Vec<_>>();
    let mut unmapped = BTreeMap::<String, Vec<String>>::new();
    let row_reports = row_plans
        .iter()
        .map(|(row, plan)| {
            row_report(
                row,
                plan,
                &proof_results,
                &mut unmapped,
                selection.as_ref().ok(),
            )
        })
        .collect::<Vec<_>>();
    let unmapped_json = unmapped
        .iter()
        .map(|(reason, ids)| {
            format!(
                "{{\"reason\":{},\"count\":{},\"sample_ids\":[{}]}}",
                q(reason),
                ids.len(),
                ids.iter()
                    .take(6)
                    .map(|id| q(id))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<Vec<_>>();
    let proof_reports = proofs
        .iter()
        .map(|proof| proof.json(target, root))
        .collect::<Vec<_>>();
    let complete = drift.is_none()
        && unmapped.is_empty()
        && observed
            .iter()
            .all(|item| item.as_ref().is_some_and(|case| case.status == "PASS"));
    report::partial_with_proofs(
        root,
        profile,
        target,
        digest,
        manifest,
        &case_reports,
        &row_reports,
        &proof_reports,
        &unmapped_json,
        drift.as_deref().unwrap_or(if complete {
            "P16 案例與逐列 typed proof 均通過"
        } else {
            "P16 尚有 NOT_RUN 案例、SDK module 或逐列 runtime/ABI 證據"
        }),
        complete,
    )?;
    if complete {
        Ok(())
    } else {
        Err(format!(
            "P16 {profile}/{target} 正式驗收仍有 NOT_RUN rows/cases"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn p16_failed_executed_proof_marks_row_fail_and_unmapped_stays_not_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = super::super::manifest::load(root).unwrap();
        let constant = manifest
            .rows
            .iter()
            .find(|row| {
                row.profile == "lua55" && row.status == "HEADER_ONLY" && row.kind == "constant"
            })
            .unwrap();
        let plan = rowproof::required(root, constant);
        let ids = plan
            .as_ref()
            .unwrap()
            .iter()
            .map(ProofKey::id)
            .collect::<Vec<_>>();
        assert!(ids.contains(&"layout:lua55".to_owned()));
        let mut results = ids
            .iter()
            .map(|id| (id.clone(), "PASS"))
            .collect::<HashMap<_, _>>();
        results.insert("layout:lua55".into(), "FAIL");
        let mut unresolved = BTreeMap::new();
        let failed = StrictJsonParser::parse(&row_report(
            constant,
            &plan,
            &results,
            &mut unresolved,
            None,
        ))
        .unwrap();
        assert_eq!(
            failed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        assert_eq!(
            failed.get("matched"),
            Some(&StrictJsonValue::Number("0".into()))
        );
        assert!(
            failed
                .get("unmapped_reason")
                .and_then(StrictJsonValue::as_str)
                .unwrap()
                .contains("layout:lua55")
        );
        assert_eq!(unresolved.get("已執行 proof 失敗").unwrap().len(), 1);

        results.remove("layout:lua55");
        let pending = StrictJsonParser::parse(&row_report(
            constant,
            &plan,
            &results,
            &mut BTreeMap::new(),
            None,
        ))
        .unwrap();
        assert_eq!(
            pending.get("status").and_then(StrictJsonValue::as_str),
            Some("NOT_RUN")
        );
        let macro_row = manifest
            .rows
            .iter()
            .find(|row| row.profile == "lua55" && row.name == "luaL_intop")
            .unwrap();
        let unmapped_plan = rowproof::required(root, macro_row);
        assert!(unmapped_plan.is_ok());
        let unmapped = StrictJsonParser::parse(&row_report(
            macro_row,
            &unmapped_plan,
            &HashMap::new(),
            &mut BTreeMap::new(),
            None,
        ))
        .unwrap();
        assert_eq!(
            unmapped.get("status").and_then(StrictJsonValue::as_str),
            Some("NOT_RUN")
        );
    }

    #[test]
    fn p16_surface_proof_records_real_compile_and_source_hash() {
        let root = env::temp_dir().join(format!("rivetlua-p16-surface-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let header_dir = root.join("include/rivetlua/lua55");
        let source_dir = root.join("tests/p16");
        let work = root.join("work");
        fs::create_dir_all(&header_dir).unwrap();
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(header_dir.join("lua.h"), "#define P16_TEST 1\n").unwrap();
        fs::write(
            source_dir.join("surface_lua55.c"),
            "#include \"lua.h\"\nint p16_test(void) { return P16_TEST; }\n",
        )
        .unwrap();
        let manifest = Manifest {
            rows: Vec::new(),
            header_sets: HashMap::from([("lua55".into(), "a".repeat(64))]),
            header_files: HashMap::new(),
        };
        let library = StaticLibrary {
            path: work.join("unused.a"),
            artifact: (String::new(), String::new()),
            build_command: Vec::new(),
            build_log: (String::new(), String::new()),
            native_flags: Vec::new(),
        };
        let proof = execute_proof(
            &root,
            &work,
            ProofKey::Surface("lua55".into()),
            0,
            &manifest,
            &library,
            None,
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        assert_eq!(proof.status, "PASS");
        assert_eq!((proof.matched, proof.passed, proof.failed), (1, 1, 0));
        assert_eq!(proof.build_exit_code, Some(0));
        assert_eq!(
            proof.source.as_ref().unwrap().1,
            sha_file(&source_dir.join("surface_lua55.c")).unwrap()
        );
        assert!(
            fs::read_to_string(&proof.build_log.as_ref().unwrap().0)
                .unwrap()
                .contains("P16_PROOF surface:lua55 PASS")
        );
        let report = StrictJsonParser::parse(&proof.json("aarch64-apple-darwin", &root)).unwrap();
        super::super::gate::proof(
            &root,
            &report,
            &ProofKey::Surface("lua55".into()),
            "aarch64-apple-darwin",
            &HashMap::new(),
            &manifest,
            None,
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p16_signal_exit_status_model_preserves_null_exit_and_signal() {
        let status = std::process::ExitStatus::from_raw(15);
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(15));
        assert_eq!(opt_i32(status.code()), "null");
        assert_eq!(opt_i32(status.signal()), "15");
    }

    #[test]
    fn p16_staticlib_provenance_requires_cargo_artifact_and_native_flags() {
        let artifact = "/tmp/p16-target/aarch64-apple-darwin/debug/librivetlua_capi.a";
        let log = format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"rivetlua_capi\",\"crate_types\":[\"rlib\",\"staticlib\"]}},\"filenames\":[{}]}}\nnote: native-static-libs: -lm -lpthread\n",
            q(artifact)
        );
        assert_eq!(cargo_staticlib_artifact(&log).unwrap(), Path::new(artifact));
        assert_eq!(native_static_libs(&log).unwrap(), ["-lm", "-lpthread"]);
        assert!(native_static_libs("note: native-static-libs: -llua -lm").is_err());
        assert!(cargo_staticlib_artifact("note: native-static-libs: -lm").is_err());
    }

    #[test]
    fn p16_worker_artifact_requires_exact_cargo_bin_target() {
        let executable = "/tmp/p16-target/debug/rivetlua-native-worker";
        let artifact = format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"rivetlua-native-worker\",\"kind\":[\"bin\"]}},\"executable\":{}}}\n",
            q(executable)
        );
        assert_eq!(
            cargo_worker_artifact(&artifact).unwrap(),
            Path::new(executable)
        );
        assert!(cargo_worker_artifact(&artifact.repeat(2)).is_err());
        assert!(
            cargo_worker_artifact(
                &artifact.replace("rivetlua-native-worker\",\"kind", "other\",\"kind")
            )
            .is_err()
        );
    }

    #[test]
    fn p16_worker_case_without_built_snapshot_stays_fail_closed() {
        let root = env::temp_dir().join(format!(
            "rivetlua-p16-missing-worker-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        let case = Case {
            id: "ABI-006".into(),
            execution_kind: ExecutionKind::RustTest,
            step: "P16-4".into(),
            fixture: String::new(),
            local_test:
                "worker:abi_006_worker_primitives_bytes_gc_crash_timeout_malformed_and_fresh_reuse"
                    .into(),
            assertions: [
                "crash",
                "timeout",
                "malformed",
                "private_vm",
                "heap_cleanup",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        };
        let evidence = rust_case(
            &root,
            &work,
            &case,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            None,
            None,
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        assert_eq!(evidence.status, "FAIL");
        assert_eq!(
            (evidence.matched, evidence.passed, evidence.failed),
            (0, 0, 0)
        );
        assert!(evidence.diagnostic.contains("worker build 證據缺失"));
        let report = StrictJsonParser::parse(&evidence.json(
            &case,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            &root,
        ))
        .unwrap();
        assert_eq!(report.get("worker"), Some(&StrictJsonValue::Null));
        assert_eq!(
            report.get("artifact_record_path"),
            Some(&StrictJsonValue::Null)
        );
        assert_eq!(
            report.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p16_digest_drift_removes_case_pass_claim() {
        let mut passing = CaseEvidence::new();
        passing.status = "PASS";
        passing.matched = 1;
        passing.passed = 1;
        let mut observed = vec![Some(passing), None];
        invalidate_stale_evidence(&mut observed, "source digest changed");
        let evidence = observed[0].as_ref().unwrap();
        assert_eq!(evidence.status, "FAIL");
        assert_eq!(evidence.diagnostic, "source digest changed");
        assert_eq!(
            (evidence.matched, evidence.passed, evidence.failed),
            (1, 0, 1)
        );
    }

    #[test]
    fn p16_runner_reports_real_c_build_run_signal_and_rust_failure() {
        let root = env::temp_dir().join(format!("rivetlua-p16-failure-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let work = root.join("work");
        let include = root.join("include/rivetlua/lua55");
        let fixtures = root.join("tests/p16/acceptance");
        let rust_sources = root.join("crates/rivetlua-capi/tests");
        for dir in [&work, &include, &fixtures, &rust_sources] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(include.join("lua.h"), "/* synthetic */\n").unwrap();
        let archive = work.join("librivetlua_capi.a");
        fs::write(&archive, b"!<arch>\n").unwrap();
        let build_log = work.join("staticlib-build.log");
        fs::write(&build_log, "synthetic build\n").unwrap();
        let library = StaticLibrary {
            path: archive.clone(),
            artifact: artifact(&archive).unwrap(),
            build_command: vec!["synthetic".into()],
            build_log: artifact(&build_log).unwrap(),
            native_flags: Vec::new(),
        };
        let manifest = Manifest {
            rows: Vec::new(),
            header_sets: HashMap::from([("lua55".into(), "a".repeat(64))]),
            header_files: HashMap::new(),
        };
        let source = fixtures.join("case.c");
        let case = Case {
            id: "ABI-TEST".into(),
            execution_kind: ExecutionKind::CDriver,
            step: "P16-3".into(),
            fixture: "tests/p16/acceptance/case.c".into(),
            local_test: String::new(),
            assertions: vec!["stack".into()],
        };
        let mut cache = HashMap::new();
        let mut run_cache = HashMap::new();
        fs::write(&source, "int main(\n").unwrap();
        let compile = c_case(
            &root,
            &work,
            &case,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            &manifest,
            &library,
            &mut cache,
            &mut run_cache,
        );
        assert_eq!(compile.status, "FAIL");
        assert_eq!(
            compile.build_command.first().map(String::as_str),
            Some("cc")
        );
        assert!(compile.build_exit_code.is_some_and(|code| code != 0));
        assert!(compile.command.is_empty());
        assert_eq!((compile.matched, compile.passed, compile.failed), (0, 0, 0));
        assert_eq!(
            sha_file(Path::new(&compile.build_log.as_ref().unwrap().0)).unwrap(),
            compile.build_log.as_ref().unwrap().1
        );

        fs::write(&source, "int main(void) { return 7; }\n").unwrap();
        let nonzero = c_case(
            &root,
            &work,
            &case,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            &manifest,
            &library,
            &mut cache,
            &mut run_cache,
        );
        assert_eq!(nonzero.status, "FAIL");
        assert_eq!(nonzero.command.len(), 1);
        assert_eq!(nonzero.build_exit_code, Some(0));
        assert_eq!(nonzero.exit_code, Some(7));
        assert_eq!(nonzero.signal, None);
        assert_eq!((nonzero.matched, nonzero.passed, nonzero.failed), (1, 0, 1));
        assert_eq!(
            sha_file(Path::new(&nonzero.c_log.as_ref().unwrap().0)).unwrap(),
            nonzero.c_log.as_ref().unwrap().1
        );
        let parsed = StrictJsonParser::parse(&nonzero.json(
            &case,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            &root,
        ))
        .unwrap();
        assert_eq!(
            parsed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        assert!(
            matches!(parsed.get("exit_code"), Some(StrictJsonValue::Number(value)) if value == "7")
        );
        assert_eq!(parsed.get("signal"), Some(&StrictJsonValue::Null));

        let script = work.join("fake-rust-test");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'running 1 test\\ntest fake ... FAILED\\n'\nexit 7\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            rust_sources.join("abi_acceptance.rs"),
            "fn synthetic() {}\n",
        )
        .unwrap();
        cache.insert(
            "abi_acceptance".into(),
            TestBinary {
                path: script,
                build_command: vec!["cargo".into(), "test".into()],
                build_log_path: build_log.display().to_string(),
                build_log_sha256: sha_file(&build_log).unwrap(),
            },
        );
        let rust_case_spec = Case {
            id: "ABI-NEG-002".into(),
            execution_kind: ExecutionKind::RustTest,
            step: "P16-3".into(),
            fixture: String::new(),
            local_test:
                "abi_acceptance:abi_neg002_panic_is_caught_and_foreign_unwind_boundary_is_static"
                    .into(),
            assertions: vec!["reject_foreign_unwind".into(), "panic_boundary".into()],
        };
        let rust = rust_case(
            &root,
            &work,
            &rust_case_spec,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            None,
            None,
            &mut cache,
            &mut run_cache,
        );
        assert_eq!(rust.status, "FAIL");
        assert_eq!(rust.command.len(), 5);
        assert_eq!(rust.exit_code, Some(7));
        assert_eq!((rust.matched, rust.passed, rust.failed), (1, 0, 1));
        assert_eq!(rust.rust_failure.as_ref().unwrap().stage, "run");
        assert!(
            fs::read_to_string(&rust.log.as_ref().unwrap().0)
                .unwrap()
                .contains("FAILED")
        );
        assert_eq!(
            sha_file(Path::new(&rust.log.as_ref().unwrap().0)).unwrap(),
            rust.log.as_ref().unwrap().1
        );
        fs::write(&cache.get("abi_acceptance").unwrap().path,
            "#!/bin/sh\nprintf 'running 0 tests\\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured\\n'\nexit 0\n").unwrap();
        let zero = rust_case(
            &root,
            &work,
            &rust_case_spec,
            "lua55-i64f64",
            "aarch64-apple-darwin",
            None,
            None,
            &mut cache,
            &mut run_cache,
        );
        assert_eq!(zero.status, "FAIL");
        assert_eq!((zero.matched, zero.passed, zero.failed), (0, 0, 0));
        assert_eq!(zero.exit_code, Some(0));
        assert!(
            fs::read_to_string(&zero.log.as_ref().unwrap().0)
                .unwrap()
                .contains("running 0 tests")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
