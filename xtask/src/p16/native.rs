use super::{is_sha, sha_file};
use crate::{StrictJsonParser, StrictJsonValue};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct Receipt {
    pub fields: BTreeMap<String, String>,
}

impl Receipt {
    pub(super) fn field(&self, name: &str) -> Result<&str, String> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("P16 native receipt 缺 {name}"))
    }
}

fn string<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(StrictJsonValue::as_str)
        .ok_or_else(|| format!("P16 native record 缺 {key}"))
}

fn list<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a [StrictJsonValue], String> {
    value
        .get(key)
        .and_then(StrictJsonValue::as_array)
        .ok_or_else(|| format!("P16 native record {key} 非陣列"))
}

fn flag(value: &StrictJsonValue, key: &str, expected: bool) -> Result<(), String> {
    if value.get(key) != Some(&StrictJsonValue::Bool(expected)) {
        return Err(format!("P16 native record {key} 不符"));
    }
    Ok(())
}

fn number(value: &StrictJsonValue, key: &str) -> Result<usize, String> {
    match value.get(key) {
        Some(StrictJsonValue::Number(raw)) => raw
            .parse::<usize>()
            .map_err(|_| format!("P16 native record {key} 無效")),
        _ => Err(format!("P16 native record {key} 非整數")),
    }
}

fn command<'a>(value: &'a StrictJsonValue, key: &str) -> Result<Vec<&'a str>, String> {
    list(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("P16 native {key} 引數非字串"))
        })
        .collect()
}

fn contained_file(directory: &Path, path: &str, sha: &str) -> Result<(), String> {
    if !is_sha(sha) {
        return Err("P16 native artifact SHA 無效".into());
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("P16 native artifact 路徑非絕對".into());
    }
    let actual =
        fs::canonicalize(path).map_err(|error| format!("P16 native artifact 不可讀：{error}"))?;
    if !actual.starts_with(directory) || !actual.is_file() || sha_file(&actual)? != sha {
        return Err("P16 native artifact 範圍或 SHA 不符".into());
    }
    Ok(())
}

pub(super) fn receipt(log: &str, case: &str, profile: &str) -> Result<Receipt, String> {
    let mut found = log.lines().filter(|line| line.starts_with("RVP16\t"));
    let line = found.next().ok_or("P16 native receipt 缺失")?;
    if found.next().is_some() {
        return Err("P16 native receipt 重複".into());
    }
    let mut fields = BTreeMap::new();
    for item in line.split('\t').skip(1) {
        let (key, value) = item
            .split_once('=')
            .ok_or("P16 native receipt 欄位格式錯誤")?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("P16 native receipt 欄位無效或重複".into());
        }
    }
    let found = Receipt { fields };
    let short = profile
        .strip_suffix("-i64f64")
        .ok_or("P16 native profile 無效")?;
    for (key, expected) in [
        ("v", "1"),
        ("case", case),
        ("profile", short),
        ("result", "PASS"),
    ] {
        if found.field(key)? != expected {
            return Err(format!("P16 native receipt {key} 不符"));
        }
    }
    if !is_sha(found.field("artifact_record_sha256")?) {
        return Err("P16 native receipt artifact_record_sha256 無效".into());
    }
    match case {
        "ABI-005" | "ABI-007" => {
            let count = if case == "ABI-005" { "48" } else { "4" };
            for (key, expected) in [
                ("ctor_calibrated", "1"),
                ("reject_count", count),
                ("ctor_on_reject", "0"),
            ] {
                if found.field(key)? != expected {
                    return Err(format!("P16 native receipt {key} 不符"));
                }
            }
        }
        "ABI-006" => {
            for key in [
                "complete",
                "crash",
                "deadline",
                "malformed",
                "reaped",
                "cleanup",
                "fresh_reuse",
            ] {
                if found.field(key)? != "1" {
                    return Err(format!("P16 native receipt {key} 不符"));
                }
            }
            if !is_sha(found.field("worker_sha256")?) {
                return Err("P16 native receipt worker SHA 無效".into());
            }
        }
        "ABI-NEG-005" => {
            for (key, expected) in [
                ("invalid_tags", "4"),
                ("noncopyable", "1"),
                ("parent_unchanged", "1"),
            ] {
                if found.field(key)? != expected {
                    return Err(format!("P16 native receipt {key} 不符"));
                }
            }
        }
        _ => return Err("P16 native receipt 案例無效".into()),
    }
    Ok(found)
}

pub(super) fn record_artifact(
    _root: &Path,
    run_env: &[(String, String)],
    receipt: &Receipt,
) -> Result<(String, String), String> {
    let directory = run_env
        .iter()
        .find(|(name, _)| name == "RIVETLUA_P16_EVIDENCE_DIR")
        .map(|(_, value)| PathBuf::from(value))
        .ok_or("P16 native evidence env 缺失")?;
    let directory = fs::canonicalize(&directory)
        .map_err(|error| format!("P16 native evidence 目錄無效：{error}"))?;
    let given = Path::new(receipt.field("artifact_record_path")?);
    if !given.is_absolute() {
        return Err("P16 native record 路徑非絕對".into());
    }
    let path =
        fs::canonicalize(given).map_err(|error| format!("P16 native record 不可讀：{error}"))?;
    if !path.starts_with(directory) || !path.is_file() {
        return Err("P16 native record 超出本次 evidence 目錄".into());
    }
    let sha = sha_file(&path)?;
    if sha != receipt.field("artifact_record_sha256")? {
        return Err("P16 native record SHA 不符".into());
    }
    Ok((path.display().to_string(), sha))
}

pub(super) fn verify_case(
    root: &Path,
    value: &StrictJsonValue,
    case: &str,
    profile: &str,
    target: &str,
    log: &str,
) -> Result<(), String> {
    let environment = list(value, "environment")?;
    let needs_worker = matches!(case, "ABI-006" | "ABI-NEG-005");
    if environment.len() != if needs_worker { 2 } else { 1 } {
        return Err("P16 native env 數量不符".into());
    }
    let env = environment
        .iter()
        .map(|item| {
            Ok((
                string(item, "name")?.to_owned(),
                string(item, "value")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if env[0].0 != "RIVETLUA_P16_EVIDENCE_DIR" {
        return Err("P16 native evidence env 名稱不符".into());
    }
    let directory = fs::canonicalize(&env[0].1)
        .map_err(|error| format!("P16 native evidence 目錄不可讀：{error}"))?;
    let cache = std::env::var_os("CARGO_TARGET_DIR").ok_or("P16 native 缺共用 target")?;
    let expected_base = PathBuf::from(cache).join(format!("p16-acceptance/{profile}/{target}"));
    let expected_base = fs::canonicalize(expected_base)
        .map_err(|error| format!("P16 native profile cache 不可讀：{error}"))?;
    if !directory.is_dir()
        || !directory.starts_with(&expected_base)
        || directory.parent() != Some(expected_base.as_path())
        || !directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(&format!("child-{case}-")))
    {
        return Err("P16 native evidence 目錄不屬本次案例".into());
    }
    let receipt = receipt(log, case, profile)?;
    let local = list(value, "local_tests")?;
    if local.len() != 1 {
        return Err("P16 native 具名 Rust test 證據數量不符".into());
    }
    contained_file(
        &expected_base,
        string(&local[0], "log_path")?,
        string(&local[0], "log_sha256")?,
    )?;
    let local_log = fs::read_to_string(string(&local[0], "log_path")?)
        .map_err(|error| format!("P16 native Rust log 不可讀：{error}"))?;
    if !log.starts_with(&local_log)
        || self::receipt(&local_log, case, profile)?.fields != receipt.fields
    {
        return Err("P16 native receipt 未綁定具名 Rust test log".into());
    }
    if string(value, "artifact_record_path")? != receipt.field("artifact_record_path")?
        || string(value, "artifact_record_sha256")? != receipt.field("artifact_record_sha256")?
    {
        return Err("P16 native report 與 receipt record 不符".into());
    }
    let (record_path, _) = record_artifact(root, &env, &receipt)?;
    let record_directory = Path::new(&record_path)
        .parent()
        .ok_or("P16 native record 目錄缺失")?;
    let record = StrictJsonParser::parse(
        &fs::read_to_string(&record_path).map_err(|error| error.to_string())?,
    )?;
    for (key, expected) in [
        ("schema", "rivetlua-p16-child-artifacts-v1"),
        ("case", case),
        (
            "profile",
            profile
                .strip_suffix("-i64f64")
                .ok_or("P16 native profile 無效")?,
        ),
        ("target", target),
    ] {
        if string(&record, key)? != expected {
            return Err(format!("P16 native record {key} 不符"));
        }
    }
    verify_artifacts(root, &record, record_directory, profile, target, case)?;
    if let Some(first) = list(&record, "artifacts")?.first() {
        if matches!(case, "ABI-005" | "ABI-007")
            && Path::new(string(first, "binary_path")?).parent()
                != Some(record_directory.join("positive").as_path())
        {
            return Err("P16 constructor positive artifact 非第一筆".into());
        }
        for (receipt_key, artifact_key) in [
            ("fixture_path", "binary_path"),
            ("fixture_sha256", "binary_sha256"),
            ("compile_log", "build_log_path"),
        ] {
            if receipt.field(receipt_key)? != string(first, artifact_key)? {
                return Err(format!(
                    "P16 native receipt {receipt_key} 與 C artifact 不符"
                ));
            }
        }
    }
    if needs_worker {
        if env[1].0 != "RIVETLUA_P16_WORKER_BIN" {
            return Err("P16 worker env 名稱不符".into());
        }
        let worker = value.get("worker").ok_or("P16 worker build 證據缺失")?;
        if string(worker, "status")? != "PASS"
            || string(worker, "binary_path")? != env[1].1
            || string(worker, "source_path")?
                != root
                    .join("crates/rivetlua-capi/src/bin/rivetlua-native-worker.rs")
                    .display()
                    .to_string()
        {
            return Err("P16 worker source/status/env 不符".into());
        }
        contained_file(
            &expected_base,
            string(worker, "binary_path")?,
            string(worker, "binary_sha256")?,
        )?;
        if string(worker, "binary_path")?
            != expected_base
                .join("rivetlua-native-worker")
                .display()
                .to_string()
        {
            return Err("P16 worker snapshot 路徑不符".into());
        }
        if string(worker, "artifact_sha256")? != string(worker, "binary_sha256")? {
            return Err("P16 worker alias 與 snapshot SHA 不符".into());
        }
        if sha_file(Path::new(string(worker, "source_path")?))? != string(worker, "source_sha256")?
        {
            return Err("P16 worker source SHA 不符".into());
        }
        let mut build = vec![
            "cargo",
            "build",
            "--locked",
            "-p",
            "rivetlua-capi",
            "--bin",
            "rivetlua-native-worker",
            "--message-format=json-render-diagnostics",
        ];
        if profile == "lua54-i64f64" {
            build.extend(["--no-default-features", "--features", "lua54"]);
        }
        if command(worker, "build_command")? != build
            || number(worker, "build_exit_code")? != 0
            || worker.get("build_signal") != Some(&StrictJsonValue::Null)
        {
            return Err("P16 worker build command/status 不符".into());
        }
        let alias = Path::new(string(worker, "artifact_path")?);
        let cache_dir = std::env::var_os("CARGO_TARGET_DIR").ok_or("P16 worker 缺共用 target")?;
        let alias_parent = alias.parent().and_then(|path| fs::canonicalize(path).ok());
        if alias.file_name().and_then(|item| item.to_str()) != Some("rivetlua-native-worker")
            || !alias_parent
                .as_ref()
                .is_some_and(|path| path.starts_with(&cache_dir))
            || !is_sha(string(worker, "artifact_sha256")?)
        {
            return Err("P16 worker Cargo alias 路徑／SHA 無效".into());
        }
        contained_file(
            &expected_base,
            string(worker, "build_log_path")?,
            string(worker, "build_log_sha256")?,
        )?;
        let build_log = fs::read_to_string(string(worker, "build_log_path")?)
            .map_err(|error| format!("P16 worker build log 不可讀：{error}"))?;
        if fs::canonicalize(super::runner::cargo_worker_artifact(&build_log)?)
            .map_err(|error| format!("P16 worker Cargo alias 不可讀：{error}"))?
            != fs::canonicalize(alias)
                .map_err(|error| format!("P16 worker report alias 不可讀：{error}"))?
        {
            return Err("P16 worker Cargo artifact JSON 與 report alias 不符".into());
        }
        let marker = format!(
            "P16_WORKER_BUILD {profile} {target} PASS artifact={} sha256={}",
            alias.display(),
            string(worker, "artifact_sha256")?
        );
        if !build_log.lines().any(|line| line == marker) {
            return Err("P16 worker Cargo build marker 缺失".into());
        }
        if case == "ABI-006" {
            if receipt.field("worker_path")? != env[1].1
                || receipt.field("worker_sha256")? != string(worker, "binary_sha256")?
                || string(&record, "worker_path")? != env[1].1
                || string(&record, "worker_sha256")? != string(worker, "binary_sha256")?
            {
                return Err("P16 worker runtime 與 snapshot 不符".into());
            }
        }
    } else if value.get("worker") != Some(&StrictJsonValue::Null) {
        return Err("P16 native 非 worker 案例夾帶 worker 證據".into());
    }
    match case {
        "ABI-005" | "ABI-007" => verify_constructor(&record, &directory, record_directory, case)?,
        "ABI-006" => verify_worker_events(&record, &directory, record_directory)?,
        "ABI-NEG-005" => verify_packet_rejection(&record)?,
        _ => return Err("P16 native 案例無效".into()),
    }
    Ok(())
}

fn verify_artifacts(
    root: &Path,
    record: &StrictJsonValue,
    directory: &Path,
    profile: &str,
    target: &str,
    case: &str,
) -> Result<(), String> {
    let artifacts = list(record, "artifacts")?;
    let expected = match case {
        "ABI-005" => Some(49),
        "ABI-007" => Some(5),
        "ABI-006" => Some(6),
        "ABI-NEG-005" => Some(0),
        _ => return Err("P16 native artifact 案例無效".into()),
    };
    if expected.is_some_and(|count| artifacts.len() != count) {
        return Err("P16 native C artifact 數量不符".into());
    }
    let source = directory.join("module.c");
    let original = root.join("crates/rivetlua-capi/tests/p16/worker-fixtures/module.c");
    if !artifacts.is_empty() && sha_file(&source)? != sha_file(&original)? {
        return Err("P16 native C fixture source 與固定來源不同".into());
    }
    let short = profile
        .strip_suffix("-i64f64")
        .ok_or("P16 native profile 無效")?;
    let capi_root = root.join("crates/rivetlua-capi");
    let include_profile = capi_root.join(format!("../../include/rivetlua/{short}"));
    let include_root = capi_root.join("../../include/rivetlua");
    let suffix = if target.contains("apple-darwin") {
        "dylib"
    } else {
        "so"
    };
    let mut scenarios = std::collections::BTreeSet::new();
    for item in artifacts {
        let source_path = string(item, "source_path")?;
        if source_path != source.display().to_string() {
            return Err("P16 native C artifact source 路徑不符".into());
        }
        contained_file(directory, source_path, string(item, "source_sha256")?)?;
        let binary_path = string(item, "binary_path")?;
        let binary = Path::new(binary_path);
        let scenario = binary.parent().ok_or("P16 native C binary 目錄缺失")?;
        let scenario_name = scenario
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("P16 native C scenario 名稱無效")?;
        if scenario.parent() != Some(directory)
            || !scenarios.insert(scenario_name.to_owned())
            || binary.file_name().and_then(|name| name.to_str())
                != Some(if suffix == "dylib" {
                    "module.dylib"
                } else {
                    "module.so"
                })
        {
            return Err("P16 native C scenario/binary 路徑不符".into());
        }
        contained_file(directory, binary_path, string(item, "binary_sha256")?)?;
        if string(item, "build_log_path")? != scenario.join("build.log").display().to_string() {
            return Err("P16 native C build log 路徑不符".into());
        }
        contained_file(
            directory,
            string(item, "build_log_path")?,
            string(item, "build_log_sha256")?,
        )?;
        if number(item, "build_exit_code")? != 0
            || item.get("build_signal") != Some(&StrictJsonValue::Null)
        {
            return Err("P16 native C build exit/signal 不符".into());
        }
        let actual = command(item, "build_command")?;
        let marker = if case == "ABI-006" {
            directory.join(format!("{scenario_name}.ctor.marker"))
        } else {
            scenario.join("ctor.marker")
        };
        let kind = actual
            .iter()
            .find_map(|arg| arg.strip_prefix("-DRV_CASE_KIND="))
            .ok_or("P16 native C build 缺 CASE_KIND")?;
        let kind = kind
            .parse::<usize>()
            .map_err(|_| "P16 native C CASE_KIND 無效")?;
        let expected_kind = if case == "ABI-006" {
            match scenario_name {
                "normal" | "fresh_reuse" => 0,
                "crash" => 1,
                "timeout" => 2,
                "malformed" => 3,
                "noncopyable" => 5,
                _ => return Err("P16 worker C fixture scenario 名稱無效".into()),
            }
        } else {
            4
        };
        if kind != expected_kind {
            return Err("P16 native C CASE_KIND 與案例不符".into());
        }
        let mut expected_command = vec![
            "cc".to_owned(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-fPIC".into(),
        ];
        if suffix == "dylib" {
            expected_command.extend([
                "-dynamiclib".into(),
                "-undefined".into(),
                "dynamic_lookup".into(),
            ]);
        } else {
            expected_command.push("-shared".into());
        }
        expected_command.extend([
            "-I".into(),
            include_profile.display().to_string(),
            "-I".into(),
            include_root.display().to_string(),
            format!("-DRV_MARKER_PATH=\"{}\"", marker.display()),
            format!("-DRV_CASE_KIND={kind}"),
            source.display().to_string(),
            "-o".into(),
            binary_path.into(),
        ]);
        if actual
            != expected_command
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return Err("P16 native C build argv 與固定 SDK flags 不符".into());
        }
        let build_log = fs::read_to_string(string(item, "build_log_path")?)
            .map_err(|error| format!("P16 native C build log 不可讀：{error}"))?;
        let expected_prefix = format!("argv={expected_command:?}\nexit=Some(0) signal=None\n");
        if !build_log.starts_with(&expected_prefix) {
            return Err("P16 native C build log argv/exit 記錄不符".into());
        }
        if case == "ABI-006" {
            if fs::read(&marker)
                .map_err(|error| format!("P16 worker constructor marker 缺失：{error}"))?
                != b"constructor\n"
            {
                return Err("P16 worker constructor marker 內容不符".into());
            }
            if matches!(kind, 0 | 5)
                && fs::read(marker.with_extension("marker.dtor"))
                    .map_err(|error| format!("P16 worker destructor marker 缺失：{error}"))?
                    != b"destructor\n"
            {
                return Err("P16 worker destructor marker 內容不符".into());
            }
        }
    }
    if matches!(case, "ABI-005" | "ABI-007") {
        let rejects = if case == "ABI-005" { 48 } else { 4 };
        if !scenarios.contains("positive")
            || (0..rejects).any(|index| !scenarios.contains(&format!("reject_{index:02}")))
        {
            return Err("P16 native constructor scenario artifact 缺失".into());
        }
    } else if case == "ABI-006"
        && [
            "normal",
            "crash",
            "timeout",
            "malformed",
            "fresh_reuse",
            "noncopyable",
        ]
        .iter()
        .any(|scenario| !scenarios.contains(*scenario))
    {
        return Err("P16 worker C artifact scenario 缺失".into());
    }
    Ok(())
}

fn verify_constructor(
    record: &StrictJsonValue,
    directory: &Path,
    record_directory: &Path,
    case: &str,
) -> Result<(), String> {
    let constructor = record
        .get("constructor")
        .ok_or("P16 constructor 記錄缺失")?;
    flag(constructor, "calibrated", true)?;
    if string(constructor, "positive_marker_path")?
        != record_directory
            .join("positive/ctor.marker")
            .display()
            .to_string()
        || string(constructor, "positive_log_path")?
            != record_directory
                .join("positive/load.log")
                .display()
                .to_string()
    {
        return Err("P16 constructor positive 校準產物路徑不符".into());
    }
    contained_file(
        directory,
        string(constructor, "positive_marker_path")?,
        string(constructor, "positive_marker_sha256")?,
    )?;
    contained_file(
        directory,
        string(constructor, "positive_log_path")?,
        string(constructor, "positive_log_sha256")?,
    )?;
    if fs::read(string(constructor, "positive_marker_path")?).map_err(|error| error.to_string())?
        != b"constructor\n"
        || !fs::read_to_string(string(constructor, "positive_log_path")?)
            .map_err(|error| error.to_string())?
            .contains("load_trusted status=0; marker=constructor")
    {
        return Err("P16 constructor positive 校準內容不符".into());
    }
    let rejections = list(constructor, "rejections")?;
    let expected = if case == "ABI-005" { 48 } else { 4 };
    if rejections.len() != expected {
        return Err("P16 constructor reject_count 不符".into());
    }
    let mut indexes = std::collections::BTreeSet::new();
    let mut marker_paths = std::collections::BTreeSet::new();
    let identity_reasons = [
        "Revision",
        "Profile",
        "NumericConfig",
        "PointerWidth",
        "Endianness",
        "Reserved",
        "Target",
        "HeaderSetSha256",
        "LuaHSha256",
        "LauxlibHSha256",
        "LuaconfHSha256",
    ];
    let policy_reasons = ["Denied", "Digest", "UnknownUnwind", "ForeignUnwind"];
    for item in rejections {
        let index = number(item, "index")?;
        let reason = if case == "ABI-005" {
            if index < identity_reasons.len() {
                identity_reasons[index].to_owned()
            } else {
                format!("Layout({})", index - identity_reasons.len())
            }
        } else {
            policy_reasons.get(index).copied().unwrap_or("").to_owned()
        };
        if index >= expected || !indexes.insert(index) || string(item, "reason")? != reason {
            return Err("P16 constructor rejection index/reason 無效".into());
        }
        flag(item, "preloader_rejected", true)?;
        flag(item, "ctor_marker_seen", false)?;
        let marker = Path::new(string(item, "marker_path")?);
        if marker != record_directory.join(format!("reject_{index:02}/ctor.marker")) {
            return Err("P16 constructor rejection marker index 路徑不符".into());
        }
        let parent = marker.parent().and_then(|path| fs::canonicalize(path).ok());
        if !marker.is_absolute()
            || !parent
                .as_ref()
                .is_some_and(|path| path.starts_with(directory))
            || !marker_paths.insert(marker)
            || marker.exists()
        {
            return Err("P16 constructor rejection marker 存在或超出 cache".into());
        }
    }
    Ok(())
}

fn optional_status(value: &StrictJsonValue, key: &str) -> Result<String, String> {
    match value.get(key) {
        Some(StrictJsonValue::Null) => Ok("None".into()),
        Some(StrictJsonValue::Number(raw)) if raw.parse::<i32>().is_ok() => {
            Ok(format!("Some({raw})"))
        }
        _ => Err(format!("P16 child event {key} 無效")),
    }
}

fn verify_child_event(
    event: &StrictJsonValue,
    directory: &Path,
    record_directory: &Path,
    worker: &str,
    worker_sha: &str,
    scenario: &str,
) -> Result<String, String> {
    if string(event, "scenario")? != scenario
        || string(event, "log_path")?
            != record_directory
                .join(format!("{scenario}.child.log"))
                .display()
                .to_string()
    {
        return Err("P16 child event scenario/log 路徑不符".into());
    }
    flag(event, "reaped", true)?;
    flag(event, "cache_clean", true)?;
    flag(event, "timed_out", scenario == "timeout")?;
    contained_file(
        directory,
        string(event, "log_path")?,
        string(event, "log_sha256")?,
    )?;
    let exit = optional_status(event, "exit_code")?;
    let signal = optional_status(event, "signal")?;
    if exit == "None" && signal == "None" {
        return Err("P16 child event exit/signal 皆缺失".into());
    }
    if matches!(scenario, "normal" | "fresh_reuse" | "noncopyable")
        && (exit != "Some(0)" || signal != "None")
    {
        return Err("P16 child 正常案例狀態不符".into());
    }
    if matches!(scenario, "crash" | "timeout") && exit == "Some(0)" && signal == "None" {
        return Err("P16 child 異常案例卻成功退出".into());
    }
    let body = fs::read_to_string(string(event, "log_path")?)
        .map_err(|error| format!("P16 child event log 不可讀：{error}"))?;
    let lines = body.lines().collect::<Vec<_>>();
    if lines.len() != 10
        || lines[0] != format!("scenario={scenario}")
        || lines[1] != format!("worker_path={worker}")
        || lines[2] != format!("worker_sha256={worker_sha}")
        || !lines[3].starts_with("pid=Some(")
        || !lines[3].ends_with(')')
        || lines[3][9..lines[3].len() - 1]
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 0)
            .is_none()
        || lines[5] != format!("exit_code={exit}")
        || lines[6] != format!("signal={signal}")
        || lines[7] != format!("timed_out={}", scenario == "timeout")
        || lines[8] != "reaped=true"
        || lines[9] != "cache_clean=true"
    {
        return Err("P16 child event log 與 sidecar status 不符".into());
    }
    let outcome = lines[4]
        .strip_prefix("outcome=")
        .ok_or("P16 child outcome 缺失")?;
    let matches_outcome = match scenario {
        "normal" | "fresh_reuse" => {
            outcome
                == "Complete([Nil, Boolean(false), Integer(123), NumberBits(4608308318706860032), Bytes([0, 255, 65])])"
        }
        "crash" => outcome == "Crash",
        "timeout" => outcome == "Deadline",
        "malformed" => outcome == "Malformed",
        "noncopyable" => outcome == "NonCopyable { index: 1, lua_type: 5 }",
        _ => false,
    };
    if !matches_outcome {
        return Err("P16 child outcome 與 scenario 不符".into());
    }
    Ok(outcome.to_owned())
}

fn verify_worker_events(
    record: &StrictJsonValue,
    directory: &Path,
    record_directory: &Path,
) -> Result<(), String> {
    let events = list(record, "child_events")?;
    let expected = ["normal", "crash", "timeout", "malformed", "fresh_reuse"];
    if events.len() != expected.len() {
        return Err("P16 child events 數量不符".into());
    }
    let worker = string(record, "worker_path")?;
    let worker_sha = string(record, "worker_sha256")?;
    let mut outcomes = std::collections::BTreeMap::new();
    for (event, scenario) in events.iter().zip(expected) {
        outcomes.insert(
            scenario,
            verify_child_event(
                event,
                directory,
                record_directory,
                worker,
                worker_sha,
                scenario,
            )?,
        );
    }
    if outcomes["normal"] != outcomes["fresh_reuse"] {
        return Err("P16 fresh worker 結果與正常執行不同".into());
    }
    let noncopyable = record
        .get("noncopyable_event")
        .ok_or("P16 noncopyable child event 缺失")?;
    verify_child_event(
        noncopyable,
        directory,
        record_directory,
        worker,
        worker_sha,
        "noncopyable",
    )?;
    Ok(())
}

fn verify_packet_rejection(record: &StrictJsonValue) -> Result<(), String> {
    if number(record, "packet_only")? != 1 {
        return Err("P16 packet_only 不符".into());
    }
    flag(record, "noncopyable_rejected", true)?;
    let tags = list(record, "invalid_tags")?;
    let expected = [6, 7, 8, 255];
    if tags.len() != expected.len()
        || tags
            .iter()
            .zip(expected)
            .any(|(value, expected)| value != &StrictJsonValue::Number(expected.to_string()))
    {
        return Err("P16 invalid tags 不符".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::q;
    use super::*;

    #[test]
    fn p16_native_receipt_rejects_wrong_profile_and_missing_child_record() {
        let sha = "0".repeat(64);
        let text = format!(
            "RVP16\tv=1\tcase=ABI-005\tprofile=lua54\tresult=PASS\tartifact_record_path=/tmp/no-such-record\tartifact_record_sha256={sha}\tctor_calibrated=1\treject_count=48\tctor_on_reject=0\n"
        );
        assert!(receipt(&text, "ABI-005", "lua55-i64f64").is_err());
        let parsed = receipt(&text, "ABI-005", "lua54-i64f64").unwrap();
        let env = [("RIVETLUA_P16_EVIDENCE_DIR".into(), "/tmp".into())];
        assert!(record_artifact(Path::new("/tmp"), &env, &parsed).is_err());
    }

    #[test]
    fn p16_native_artifact_rechecks_fixed_compiler_argv_and_hashes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let directory =
            std::env::temp_dir().join(format!("rivetlua-p16-native-proof-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let source = directory.join("module.c");
        fs::copy(
            root.join("crates/rivetlua-capi/tests/p16/worker-fixtures/module.c"),
            &source,
        )
        .unwrap();
        let capi = root.join("crates/rivetlua-capi");
        let source_sha = sha_file(&source).unwrap();
        let mut artifacts = Vec::new();
        for (scenario, kind) in [
            ("normal", 0),
            ("crash", 1),
            ("timeout", 2),
            ("malformed", 3),
            ("fresh_reuse", 0),
            ("noncopyable", 5),
        ] {
            let folder = directory.join(scenario);
            fs::create_dir_all(&folder).unwrap();
            let marker = directory.join(format!("{scenario}.ctor.marker"));
            fs::write(&marker, b"constructor\n").unwrap();
            if matches!(kind, 0 | 5) {
                fs::write(marker.with_extension("marker.dtor"), b"destructor\n").unwrap();
            }
            let binary = folder.join("module.dylib");
            fs::write(&binary, b"synthetic binary").unwrap();
            let log = folder.join("build.log");
            let argv = vec![
                "cc".to_owned(),
                "-std=c11".into(),
                "-Wall".into(),
                "-Wextra".into(),
                "-Werror".into(),
                "-fPIC".into(),
                "-dynamiclib".into(),
                "-undefined".into(),
                "dynamic_lookup".into(),
                "-I".into(),
                capi.join("../../include/rivetlua/lua55")
                    .display()
                    .to_string(),
                "-I".into(),
                capi.join("../../include/rivetlua").display().to_string(),
                format!("-DRV_MARKER_PATH=\"{}\"", marker.display()),
                format!("-DRV_CASE_KIND={kind}"),
                source.display().to_string(),
                "-o".into(),
                binary.display().to_string(),
            ];
            fs::write(&log, format!("argv={argv:?}\nexit=Some(0) signal=None\n")).unwrap();
            artifacts.push(format!(
                "{{\"source_path\":{},\"source_sha256\":{},\"build_command\":[{}],\"build_exit_code\":0,\"build_signal\":null,\"build_log_path\":{},\"build_log_sha256\":{},\"binary_path\":{},\"binary_sha256\":{}}}",
                q(&source.display().to_string()), q(&source_sha),
                argv.iter().map(|part| q(part)).collect::<Vec<_>>().join(","),
                q(&log.display().to_string()), q(&sha_file(&log).unwrap()),
                q(&binary.display().to_string()), q(&sha_file(&binary).unwrap()),
            ));
        }
        let valid = format!("{{\"artifacts\":[{}]}}", artifacts.join(","));
        let record = StrictJsonParser::parse(&valid).unwrap();
        assert!(
            verify_artifacts(
                root,
                &record,
                &directory,
                "lua55-i64f64",
                "aarch64-apple-darwin",
                "ABI-006"
            )
            .is_ok()
        );
        let bad =
            StrictJsonParser::parse(&valid.replacen(&source_sha, &"0".repeat(64), 1)).unwrap();
        assert!(
            verify_artifacts(
                root,
                &bad,
                &directory,
                "lua55-i64f64",
                "aarch64-apple-darwin",
                "ABI-006"
            )
            .is_err()
        );
        let bad = StrictJsonParser::parse(&valid.replacen("-dynamiclib", "-shared", 1)).unwrap();
        assert!(
            verify_artifacts(
                root,
                &bad,
                &directory,
                "lua55-i64f64",
                "aarch64-apple-darwin",
                "ABI-006"
            )
            .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn p16_child_event_requires_log_status_and_hash_agreement() {
        let directory =
            std::env::temp_dir().join(format!("rivetlua-p16-child-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let log = directory.join("normal.child.log");
        let worker = "/tmp/p16-worker-snapshot";
        let worker_sha = "a".repeat(64);
        let outcome = "Complete([Nil, Boolean(false), Integer(123), NumberBits(4608308318706860032), Bytes([0, 255, 65])])";
        fs::write(&log, format!("scenario=normal\nworker_path={worker}\nworker_sha256={worker_sha}\npid=Some(123)\noutcome={outcome}\nexit_code=Some(0)\nsignal=None\ntimed_out=false\nreaped=true\ncache_clean=true\n")).unwrap();
        let valid = format!(
            "{{\"scenario\":\"normal\",\"exit_code\":0,\"signal\":null,\"timed_out\":false,\"reaped\":true,\"cache_clean\":true,\"log_path\":{},\"log_sha256\":{}}}",
            q(&log.display().to_string()),
            q(&sha_file(&log).unwrap()),
        );
        let event = StrictJsonParser::parse(&valid).unwrap();
        assert_eq!(
            verify_child_event(
                &event,
                &directory,
                &directory,
                worker,
                &worker_sha,
                "normal"
            )
            .unwrap(),
            outcome
        );
        let changed =
            StrictJsonParser::parse(&valid.replace("\"exit_code\":0", "\"exit_code\":1")).unwrap();
        assert!(
            verify_child_event(
                &changed,
                &directory,
                &directory,
                worker,
                &worker_sha,
                "normal"
            )
            .is_err()
        );
        fs::write(&log, b"tampered\n").unwrap();
        assert!(
            verify_child_event(
                &event,
                &directory,
                &directory,
                worker,
                &worker_sha,
                "normal"
            )
            .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
