use super::manifest::{self, Manifest, Row};
use super::matrix::{self, Case, ExecutionKind};
use super::report;
use super::rowproof::{self, ProofKey};
use super::selection::{self, Applicability, Snapshot};
use super::{host_target, q, sha_bytes, sha_file};
use crate::{StrictJsonParser, StrictJsonValue, root, source_digest};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn field<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(StrictJsonValue::as_str)
        .ok_or_else(|| format!("P16 report 缺字串欄位 {key}"))
}

fn exact(value: &StrictJsonValue, key: &str, expected: &str) -> Result<(), String> {
    if field(value, key)? != expected {
        return Err(format!("P16 report {key} 不符"));
    }
    Ok(())
}

fn number(value: &StrictJsonValue, key: &str) -> Result<usize, String> {
    let raw = value
        .get(key)
        .ok_or_else(|| format!("P16 report 缺 {key}"))?;
    let StrictJsonValue::Number(raw) = raw else {
        return Err(format!("P16 report {key} 不是整數"));
    };
    raw.parse::<usize>()
        .map_err(|_| format!("P16 report {key} 無效"))
}

fn array<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a [StrictJsonValue], String> {
    value
        .get(key)
        .and_then(StrictJsonValue::as_array)
        .ok_or_else(|| format!("P16 report {key} 不是陣列"))
}

fn command<'a>(value: &'a StrictJsonValue, key: &str) -> Result<Vec<&'a str>, String> {
    let command = array(value, key)?;
    if command.is_empty() || command.len() > 32 {
        return Err(format!("P16 report {key} 空白或過長"));
    }
    command
        .iter()
        .map(|part| {
            part.as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("P16 report {key} 有空白／非字串引數"))
        })
        .collect()
}

fn counts(value: &StrictJsonValue) -> Result<(), String> {
    let matched = number(value, "matched")?;
    let passed = number(value, "passed")?;
    let failed = number(value, "failed")?;
    let ignored = number(value, "ignored")?;
    if matched == 0
        || passed == 0
        || failed != 0
        || ignored != 0
        || matched
            != passed
                .checked_add(failed)
                .and_then(|sum| sum.checked_add(ignored))
                .ok_or("P16 test count 溢位")?
    {
        return Err("P16 zero tests、失敗、忽略或計數不一致".into());
    }
    Ok(())
}

fn unique_ids(values: &[StrictJsonValue], label: &str) -> Result<(), String> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(field(value, "id")?) {
            return Err(format!("P16 {label} 重複 ID"));
        }
    }
    Ok(())
}

fn allowed_artifact(root: &Path, path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("P16 artifact 路徑非絕對路徑".into());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("P16 artifact 不可讀 {}：{error}", path.display()))?;
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let cache = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok());
    if !canonical.starts_with(&root)
        && !cache
            .as_ref()
            .is_some_and(|cache| canonical.starts_with(cache))
    {
        return Err(format!(
            "P16 artifact 路徑超出 workspace/cache：{}",
            path.display()
        ));
    }
    if !canonical.is_file() {
        return Err("P16 artifact 非檔案".into());
    }
    Ok(canonical)
}

fn allowed_directory(root: &Path, path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("P16 cwd 路徑非絕對路徑".into());
    }
    let canonical = fs::canonicalize(path).map_err(|error| format!("P16 cwd 不可讀：{error}"))?;
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let cache = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok());
    if !canonical.is_dir()
        || (!canonical.starts_with(&root)
            && !cache
                .as_ref()
                .is_some_and(|cache| canonical.starts_with(cache)))
    {
        return Err("P16 cwd 超出 workspace/cache 或不是目錄".into());
    }
    Ok(canonical)
}

fn artifact(root: &Path, value: &StrictJsonValue, key: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(field(value, &format!("{key}_path"))?);
    let path = allowed_artifact(root, path)?;
    let expected = field(value, &format!("{key}_sha256"))?;
    if !super::is_sha(expected) || sha_file(&path)? != expected {
        return Err(format!("P16 {key} SHA-256 不符"));
    }
    fs::read(path).map_err(|error| error.to_string())
}

pub(super) fn verify_header_set(
    root: &Path,
    manifest: &Manifest,
    short: &str,
) -> Result<(), String> {
    let known = manifest
        .header_files
        .get(short)
        .ok_or("P16 header profile 缺失")?;
    let mut bytes = b"RivetLua-SDK-headers-v1\0".to_vec();
    for name in ["lua.h", "lauxlib.h", "luaconf.h"] {
        let content = fs::read(root.join(format!("include/rivetlua/{short}/{name}")))
            .map_err(|error| format!("P16 fixed header {short}/{name} 不可讀：{error}"))?;
        let expected = known.get(name).ok_or("P16 header SHA 欄位缺失")?;
        if sha_bytes(&content)? != *expected {
            return Err(format!("P16 fixed header {short}/{name} SHA 不符"));
        }
        bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(content.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&content);
    }
    let actual = sha_bytes(&bytes)?;
    if manifest.header_sets.get(short) != Some(&actual) {
        return Err(format!("P16 {short} header set SHA 不符"));
    }
    Ok(())
}

fn p14_report(root: &Path, digest: &str) -> Result<(), String> {
    let prior = crate::p14_validate_prior_reports(root, digest)?;
    let path = root.join("target/rivetlua-reports/gate-P14.json");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("P16 前置 P14 gate report 缺失：{error}"))?;
    let report = StrictJsonParser::parse(&source)
        .map_err(|error| format!("P16 前置 P14 JSON 無效：{error}"))?;
    exact(&report, "status", "PASS")?;
    exact(&report, "source_digest", digest)?;
    let checks = array(&report, "checks")?;
    let fixture = fs::read_to_string(root.join("tests/p14/sdk-cases.fixture"))
        .map_err(|error| format!("P14 fixture 不可讀：{error}"))?;
    let cases = crate::parse_p14_fixture(&fixture)?;
    let references = array(&report, "case_reports")?;
    if cases.len() != 28 || references.len() != 28 {
        return Err("P14 case / reference 必須各 28 項".into());
    }
    let mut expected = HashMap::new();
    for item in prior {
        expected.insert(item.name, (item.command, item.report_path));
    }
    for (name, command) in [
        (
            "p14-dependencies",
            "validate spec/phase-dependencies.csv DA-19/20/21/32/33",
        ),
        ("p14-csv", "validate spec/compatibility.csv P14 rows"),
        ("p14-fixture", "validate tests/p14/sdk-cases.fixture"),
        (
            "p00-p13-after",
            "validate P00-P13 reports after P14 children",
        ),
        ("p14-case-reports", "validate 28 P14 case reports"),
        ("p14-source-digest", "verify source digest after children"),
    ] {
        expected.insert(
            name.to_owned(),
            (
                command.to_owned(),
                "target/rivetlua-reports/gate-P14.json".into(),
            ),
        );
    }
    for profile in ["lua55", "lua54"] {
        let name = format!("p14-example-{profile}");
        expected.insert(
            name,
            (
                format!("cargo run --locked -p rivetlua --example embed -- {profile}"),
                "target/rivetlua-reports/gate-P14.json".into(),
            ),
        );
    }
    let mut by_name = HashMap::new();
    for check in checks {
        let name = crate::p13_validate_prior_check("P14", check)?;
        if by_name.insert(name.clone(), check).is_some() {
            return Err(format!("P14 重複 check：{name}"));
        }
        if let Some((command, report_path)) = expected.get(&name) {
            exact(check, "command", command)?;
            exact(check, "report_path", report_path)?;
        }
    }
    for name in expected.keys() {
        if !by_name.contains_key(name) {
            return Err(format!("P14 缺少 check：{name}"));
        }
    }
    for (name, count, prefix) in [
        (
            "p14-sdk-filter",
            52,
            "cargo test --locked -p rivetlua --test p14_contracts --test sdk --test sdk_inputs --test state_separation --test wrapper -- sdk",
        ),
        (
            "p14-wrapper-filter",
            13,
            "cargo test --locked -p rivetlua --lib --test wrapper -- wrapper",
        ),
        (
            "p14-cli-filter",
            38,
            "cargo test --locked -p rivetlua-cli --lib --test cli --test p14_contracts -- cli",
        ),
    ] {
        let check = by_name
            .get(name)
            .ok_or_else(|| format!("P14 缺少 {name}"))?;
        let command = field(check, "command")?;
        if (name == "p14-cli-filter" && !command.starts_with(prefix))
            || (name != "p14-cli-filter" && command != prefix)
        {
            return Err(format!("P14 {name} command 不符"));
        }
        exact(
            check,
            "diagnostic",
            &format!("精確通過 {count} 個測試；0 failed/ignored"),
        )?;
        exact(
            check,
            "report_path",
            "target/rivetlua-reports/gate-P14.json",
        )?;
    }
    let mut reference_ids = HashSet::new();
    for case in &cases {
        let spec = crate::p14_spec(&case.id).ok_or("P14 fixture 未知案例")?;
        let lua_profile = case
            .profile
            .strip_suffix("-i64f64")
            .ok_or("P14 profile 無效")?;
        let name = format!("{}-{lua_profile}", case.id);
        let relative = format!("target/rivetlua-reports/P14-{}-{lua_profile}.json", case.id);
        let check = by_name
            .get(&name)
            .ok_or_else(|| format!("P14 缺少 case check：{name}"))?;
        exact(check, "report_path", &relative)?;
        let command = field(check, "command")?;
        let suffix = format!(
            "RIVETLUA_P14_PROFILE={} cargo test --locked -p {} --test p14_contracts {} -- --exact --nocapture --test-threads=1",
            case.profile, spec.package, spec.input
        );
        let prefix = command
            .strip_suffix(&suffix)
            .ok_or_else(|| format!("P14 {name} command 不符"))?;
        if !prefix.is_empty()
            && !(prefix.starts_with("CARGO_TARGET_DIR=")
                && prefix.ends_with(' ')
                && !prefix.trim_end().contains(' '))
        {
            return Err(format!("P14 {name} target command 不符"));
        }
        crate::p14_validate_case_report(&root.join(&relative), case, digest, command, root)?;
        if !references.iter().any(|reference| {
            reference.get("case_id").and_then(StrictJsonValue::as_str) == Some(case.id.as_str())
                && reference
                    .get("lua_profile")
                    .and_then(StrictJsonValue::as_str)
                    == Some(lua_profile)
                && reference
                    .get("report_path")
                    .and_then(StrictJsonValue::as_str)
                    == Some(relative.as_str())
        }) || !reference_ids.insert(name)
        {
            return Err("P14 case reference 缺失或重複".into());
        }
    }
    if by_name.len() != expected.len() + 3 + cases.len() {
        return Err("P14 checks 總數或身分不符".into());
    }
    Ok(())
}

fn generator_output(text: &str, manifest: &Manifest) -> Result<(), String> {
    if !text
        .lines()
        .any(|line| line.starts_with("P16-1 清單 PASS: 951 rows "))
    {
        return Err("P16 pinned generator 缺 951-row PASS marker".into());
    }
    for short in ["lua55", "lua54"] {
        let expected = format!(
            "{short} header_set_sha256 {}",
            manifest
                .header_sets
                .get(short)
                .ok_or("P16 manifest 缺 header set")?
        );
        if text.lines().filter(|line| *line == expected).count() != 1 {
            return Err(format!("P16 pinned generator {short} header set 不符"));
        }
    }
    Ok(())
}

fn generator_check(root: &Path, manifest: &Manifest) -> Result<(String, String), String> {
    let output = Command::new("python3")
        .arg("tests/p16/generate_manifest.py")
        .arg("check")
        .current_dir(root)
        .output()
        .map_err(|error| format!("P16 pinned generator 無法啟動：{error}"))?;
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!(
            "P16 pinned generator check exit={:?}：{log}",
            output.status.code()
        ));
    }
    generator_output(&String::from_utf8_lossy(&output.stdout), manifest)?;
    let path = root.join("target/rivetlua-reports/P16-manifest-check.log");
    report::write(&path, &log)?;
    let digest = sha_file(&path)?;
    Ok((path.display().to_string(), digest))
}

fn prior_reports(root: &Path, digest: &str) -> Result<(), String> {
    p14_report(root, digest)?;
    let observed = crate::p15::validate_existing(root, digest)?;
    let path = root.join("target/rivetlua-reports/gate-P15.json");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("P16 前置 P15 gate report 缺失：{error}"))?;
    let report = StrictJsonParser::parse(&source)
        .map_err(|error| format!("P16 前置 P15 JSON 無效：{error}"))?;
    for (key, expected) in [
        ("schema", "rivetlua-p15-gate-v2"),
        ("status", "PASS"),
        ("scope", "oracle-infrastructure"),
        ("source_digest", digest),
        ("report_path", path.to_str().ok_or("P15 path 非 UTF-8")?),
    ] {
        exact(&report, key, expected)?;
    }
    let statuses = report
        .get("basic_compatibility_status")
        .ok_or("P16 P15 gate 缺 Basic compatibility 並列狀態")?;
    let checks = array(&report, "checks")?;
    if checks.len() != 2 {
        return Err("P16 P15 gate checks 必須精確兩項".into());
    }
    for (index, profile) in matrix::PROFILES.iter().enumerate() {
        let status = observed[index].as_str();
        exact(statuses, profile, status)?;
        let check = &checks[index];
        let observation = root.join(format!("target/rivetlua-reports/P15-basic-{profile}.json"));
        for (key, expected) in [
            ("name", format!("p15-observation-{profile}")),
            ("status", "PASS".to_owned()),
            ("command", format!("validate {}", observation.display())),
            ("report_path", observation.display().to_string()),
            ("basic_compatibility_status", status.to_owned()),
        ] {
            exact(check, key, &expected)?;
        }
    }
    Ok(())
}

fn verified_case_log(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Case,
    profile: &str,
    target: &str,
) -> Result<String, String> {
    let log =
        String::from_utf8(artifact(root, value, "log")?).map_err(|_| "P16 runtime log 非 UTF-8")?;
    let marker = format!(
        "P16_CASE {} {profile} {target} PASS matched={} passed={} failed=0 ignored=0",
        expected.id,
        number(value, "matched")?,
        number(value, "passed")?
    );
    if !log.lines().any(|line| line == marker) {
        return Err(format!("P16 {} runtime/count marker 缺失", expected.id));
    }
    for assertion in &expected.assertions {
        let marker = format!("P16_ASSERT {} {assertion}=PASS", expected.id);
        if !log.lines().any(|line| line == marker) {
            return Err(format!(
                "P16 {} {assertion} body evidence 缺失",
                expected.id
            ));
        }
    }
    Ok(log)
}

fn absent_artifact(value: &StrictJsonValue, key: &str) -> Result<(), String> {
    for name in [format!("{key}_path"), format!("{key}_sha256")] {
        if value.get(&name) != Some(&StrictJsonValue::Null) {
            return Err(format!("P16 不適用的 {name} 須為 null"));
        }
    }
    Ok(())
}

fn staticlib_evidence(
    root: &Path,
    value: &StrictJsonValue,
    profile: &str,
    target: &str,
) -> Result<Vec<String>, String> {
    let mut expected = vec![
        "cargo",
        "rustc",
        "--locked",
        "-p",
        "rivetlua-capi",
        "--lib",
        "--message-format=json-render-diagnostics",
    ];
    if profile == "lua54-i64f64" {
        expected.extend(["--no-default-features", "--features", "lua54"]);
    }
    expected.extend(["--", "--print=native-static-libs"]);
    if command(value, "staticlib_build_command")? != expected
        || number(value, "staticlib_build_exit_code")? != 0
        || value.get("staticlib_build_signal") != Some(&StrictJsonValue::Null)
    {
        return Err("P16 staticlib Cargo build command/status 不符".into());
    }
    let log = String::from_utf8(artifact(root, value, "staticlib_build_log")?)
        .map_err(|_| "P16 staticlib build log 非 UTF-8")?;
    let reported = super::runner::cargo_staticlib_artifact(&log)?;
    if fs::canonicalize(reported).ok()
        != fs::canonicalize(field(value, "staticlib_artifact_path")?).ok()
    {
        return Err("P16 Cargo staticlib artifact 路徑不符".into());
    }
    immutable_staticlib_snapshot(root, value)?;
    let flags = super::runner::native_static_libs(&log)?;
    let actual = array(value, "native_static_libs")?
        .iter()
        .map(|part| {
            part.as_str()
                .map(str::to_owned)
                .ok_or("P16 native flag 非字串")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != flags {
        return Err("P16 native-static-libs 與 rustc 證據不符".into());
    }
    let marker = format!(
        "P16_STATICLIB {profile} {target} PASS artifact={} native_flags={}",
        field(value, "staticlib_artifact_path")?,
        flags.join(" ")
    );
    if !log.lines().any(|line| line == marker) {
        return Err("P16 staticlib build marker 缺失".into());
    }
    Ok(flags)
}

fn stress_evidence(log: &str) -> Result<(), String> {
    let lines = log
        .lines()
        .filter(|line| line.starts_with("P16_STRESS "))
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err("P16 STRESS 摘要缺失或重複".into());
    }
    let fields = lines[0]
        .split_whitespace()
        .skip(1)
        .map(|field| field.split_once('=').ok_or("P16 STRESS 欄位格式錯誤"))
        .collect::<Result<Vec<_>, _>>()?;
    let get = |name: &str| -> Result<usize, String> {
        let matches = fields
            .iter()
            .filter(|(key, _)| *key == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!("P16 STRESS {name} 欄位缺失或重複"));
        }
        matches[0]
            .1
            .parse::<usize>()
            .map_err(|_| format!("P16 STRESS {name} 非整數"))
    };
    if fields.len() != 17
        || get("seed")? != 0x16c0ffee
        || get("iterations")? != 1024
        || get("callback")? != 1024
        || get("gc")? != 1024
        || get("coroutine")? != 1024
        || get("debug_ref")? != 1024
        || get("warmup")? != 128
        || get("stable_samples")? != 896
        || get("warm_active")? == 0
        || get("warm_bytes")? == 0
        || get("peak_bytes")? < get("warm_bytes")?
        || get("active_tokens")? != 0
        || get("live_bytes")? != 0
        || get("issued")? == 0
        || get("issued")? != get("refunded")?
        || get("invalid_pairs")? != 0
        || get("duplicate_refunds")? != 0
    {
        return Err("P16 STRESS 固定迭代與 allocator 帳本不符".into());
    }
    Ok(())
}

fn immutable_staticlib_snapshot(root: &Path, value: &StrictJsonValue) -> Result<(), String> {
    let original = Path::new(field(value, "staticlib_artifact_path")?);
    allowed_artifact(root, original)?;
    if original.file_name().and_then(|name| name.to_str()) != Some("librivetlua_capi.a") {
        return Err("P16 Cargo original staticlib 檔名不符".into());
    }
    let historical_sha = field(value, "staticlib_artifact_sha256")?;
    if !super::is_sha(historical_sha) || historical_sha != field(value, "library_sha256")? {
        return Err("P16 staticlib build-time SHA 與私有 snapshot 不符".into());
    }
    artifact(root, value, "library")?;
    Ok(())
}

fn verified_rust_proof(
    root: &Path,
    value: &StrictJsonValue,
    proof: matrix::RustProof,
    profile: &str,
    target: &str,
) -> Result<(), String> {
    exact(value, "target", proof.target)?;
    exact(value, "name", proof.test)?;
    let source = root.join(format!("crates/rivetlua-capi/tests/{}.rs", proof.target));
    if fs::canonicalize(field(value, "source_path")?).ok() != fs::canonicalize(source).ok() {
        return Err(format!("P16 Rust proof {} source 不符", proof.test));
    }
    artifact(root, value, "source")?;
    artifact(root, value, "binary")?;
    immutable_rust_test_snapshot(value, proof.target, profile, target)?;
    let binary = field(value, "binary_path")?;
    let mut expected_run = vec![binary, proof.test, "--exact", "--nocapture"];
    if proof.target == "sdk_modules" {
        expected_run.push("--ignored");
    }
    expected_run.push("--test-threads=1");
    if command(value, "command")? != expected_run || number(value, "exit_code")? != 0 {
        return Err(format!(
            "P16 Rust proof {} run command/exit 不符",
            proof.test
        ));
    }
    let mut build = vec![
        "cargo",
        "test",
        "--locked",
        "-p",
        "rivetlua-capi",
        "--test",
        proof.target,
        "--no-run",
        "--message-format=json-render-diagnostics",
    ];
    if profile == "lua54-i64f64" {
        build.extend(["--no-default-features", "--features", "lua54"]);
    }
    if command(value, "build_command")? != build || number(value, "build_exit_code")? != 0 {
        return Err(format!(
            "P16 Rust proof {} build command/exit 不符",
            proof.test
        ));
    }
    if value.get("build_signal") != Some(&StrictJsonValue::Null)
        || value.get("signal") != Some(&StrictJsonValue::Null)
    {
        return Err(format!("P16 Rust proof {} PASS 夾帶 signal", proof.test));
    }
    let build_log = String::from_utf8(artifact(root, value, "build_log")?)
        .map_err(|_| "P16 Rust proof build log 非 UTF-8")?;
    if !build_log
        .lines()
        .any(|line| line == format!("P16_BUILD {} {profile} PASS", proof.target))
    {
        return Err(format!("P16 Rust proof {} build marker 缺失", proof.test));
    }
    allowed_directory(root, Path::new(field(value, "cwd")?))?;
    counts(value)?;
    if number(value, "matched")? != 1 || number(value, "passed")? != 1 {
        return Err(format!("P16 Rust proof {} count 不符", proof.test));
    }
    let log = String::from_utf8(artifact(root, value, "log")?)
        .map_err(|_| "P16 Rust proof log 非 UTF-8")?;
    if !super::named_libtest_passed(&log, proof.test) {
        return Err(format!("P16 Rust proof {} 執行摘要不符", proof.test));
    }
    Ok(())
}

fn immutable_rust_test_snapshot(
    value: &StrictJsonValue,
    test_target: &str,
    profile: &str,
    target: &str,
) -> Result<(), String> {
    let cache = env::var_os("CARGO_TARGET_DIR").ok_or("P16 Rust proof 缺共用 target")?;
    let expected = PathBuf::from(cache).join(format!(
        "p16-acceptance/{profile}/{target}/rust-{test_target}-testbin"
    ));
    if field(value, "binary_path")? != expected.display().to_string() {
        return Err("P16 Rust proof 非 immutable profile snapshot".into());
    }
    Ok(())
}

fn rust_test_evidence(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Case,
    profile: &str,
    target: &str,
    log: &str,
) -> Result<(), String> {
    let proofs = matrix::rust_proofs(&expected.id);
    if proofs.len() != 1
        || expected.local_test != format!("{}:{}", proofs[0].target, proofs[0].test)
    {
        return Err(format!("P16 {} 缺固定具名 Rust test", expected.id));
    }
    let local_tests = array(value, "local_tests")?;
    if local_tests.len() != 1 {
        return Err(format!("P16 {} local_tests 數量不符", expected.id));
    }
    verified_rust_proof(root, &local_tests[0], proofs[0], profile, target)?;
    for key in [
        "source_path",
        "source_sha256",
        "binary_path",
        "binary_sha256",
        "build_command",
        "build_exit_code",
        "build_log_path",
        "build_log_sha256",
        "command",
        "environment",
        "cwd",
        "exit_code",
        "matched",
        "passed",
        "failed",
        "ignored",
    ] {
        if value.get(key) != local_tests[0].get(key) {
            return Err(format!("P16 {} {key} 與具名測試證據不符", expected.id));
        }
    }
    for assertion in &expected.assertions {
        if !proofs[0].assertions.contains(&assertion.as_str())
            || !log
                .lines()
                .any(|line| line == format!("P16_ASSERT {} {assertion}=PASS", expected.id))
        {
            return Err(format!("P16 {} {assertion} 未對應具名證據", expected.id));
        }
    }
    if !log.lines().any(|line| line == "running 1 test") {
        return Err(format!("P16 {} Rust summary 缺失", expected.id));
    }
    if expected.id == "ABI-NEG-002"
        && !log.lines().any(|line| {
            line == "P16_EVIDENCE ABI-NEG-002 foreign_unwind=STATIC_AUDIT panic=RUNTIME_GUARD"
        })
    {
        return Err("P16 ABI-NEG-002 證據種類未分辨靜態稽核與執行 guard".into());
    }
    absent_artifact(value, "header")?;
    if expected.id != "SDK-MODULE" {
        absent_artifact(value, "library")?;
    }
    Ok(())
}

fn fixed_module_sources(root: &Path, profile: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let (short, release) = if profile == "lua55-i64f64" {
        ("lua55", "5.5.1")
    } else {
        ("lua54", "5.4.9")
    };
    let directory = root.join(format!("vendor/{short}/lua-{release}-tests/libs"));
    let source = fs::read_to_string(directory.join("makefile"))
        .map_err(|error| format!("P16 fixed official libs/makefile 不可讀：{error}"))?;
    let lines = source.lines().collect::<Vec<_>>();
    let names = ["lib1.so", "lib11.so", "lib2.so", "lib21.so", "lib2-v2.so"];
    let all = lines
        .iter()
        .find_map(|line| line.strip_prefix("all:"))
        .ok_or("P16 official libs/makefile 缺 all target")?;
    if all.split_whitespace().collect::<Vec<_>>() != names {
        return Err("P16 official libs/makefile module 集合不符".into());
    }
    let mut modules = Vec::new();
    for name in names {
        let position = lines
            .iter()
            .position(|line| line.starts_with(&format!("{name}:")))
            .ok_or_else(|| format!("P16 libs/makefile 缺 {name} rule"))?;
        let command = lines
            .get(position + 1)
            .ok_or("P16 libs/makefile rule 缺 command")?;
        let words = command.split_whitespace().collect::<Vec<_>>();
        let output = words
            .windows(3)
            .find(|window| window[0] == "-o" && window[1] == name)
            .ok_or_else(|| format!("P16 libs/makefile {name} command 不符"))?;
        let source = output[2];
        if !source.ends_with(".c") || source.contains('/') || !directory.join(source).is_file() {
            return Err(format!("P16 libs/makefile {name} source 不符"));
        }
        modules.push((name.to_owned(), directory.join(source)));
    }
    Ok(modules)
}

pub(super) fn sdk_modules_evidence(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Case,
    profile: &str,
    target: &str,
    log: &str,
) -> Result<(), String> {
    rust_test_evidence(root, value, expected, profile, target, log)?;
    let native_flags = staticlib_evidence(root, value, profile, target)?;
    let short = profile.strip_suffix("-i64f64").ok_or("P16 profile 無效")?;
    if !array(value, "modules")?.is_empty() || !array(value, "package_artifacts")?.is_empty() {
        return Err("P16 SDK 舊式未驗證 module/package marker 不可用".into());
    }
    let local = &array(value, "local_tests")?[0];
    let local_log = String::from_utf8(artifact(root, local, "log")?)
        .map_err(|_| "P16 SDK Rust log 非 UTF-8")?;
    let receipt = super::sdk::receipt(&local_log, short)?;
    if field(value, "artifact_record_path")? != receipt.0
        || field(value, "artifact_record_sha256")? != receipt.1
    {
        return Err("P16 SDK receipt 與 case record 不符".into());
    }
    let environment = array(value, "environment")?;
    let names = [
        "RIVETLUA_P16_SDK_ROOT",
        "RIVETLUA_P16_SDK_EVIDENCE_DIR",
        "RIVETLUA_P16_SDK_PROFILE",
        "RIVETLUA_P16_SDK_TARGET",
        "RIVETLUA_P16_SDK_HOST_TRUST",
        "RIVETLUA_P16_SDK_LIB_PATH",
        "RIVETLUA_P16_SDK_NATIVE_LIBS",
        "RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_PATH",
        "RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_SHA256",
    ];
    if environment.len() != names.len()
        || environment
            .iter()
            .zip(names)
            .any(|(item, name)| field(item, "name") != Ok(name))
    {
        return Err("P16 SDK per-command env 集合不符".into());
    }
    let env_value = |index: usize| field(&environment[index], "value");
    if env_value(0)? != root.display().to_string()
        || env_value(2)? != short
        || env_value(3)? != target
        || env_value(4)? != "explicit-sdk-host-process-permissions-v1"
        || env_value(5)? != field(value, "library_path")?
        || env_value(6)? != native_flags.join("\u{1f}")
        || env_value(7)? != field(value, "staticlib_build_log_path")?
        || env_value(8)? != field(value, "staticlib_build_log_sha256")?
    {
        return Err("P16 SDK env profile/target/library/native flags 不符".into());
    }
    let evidence_dir = allowed_directory(root, Path::new(env_value(1)?))?;
    let record_path = allowed_artifact(root, Path::new(&receipt.0))?;
    if !record_path.starts_with(&evidence_dir) {
        return Err("P16 SDK record 不在私有 evidence 目錄".into());
    }
    let record_bytes = artifact(root, value, "artifact_record")?;
    let record_text = String::from_utf8(record_bytes).map_err(|_| "P16 SDK record 非 UTF-8")?;
    let record = StrictJsonParser::parse(&record_text)?;
    exact(&record, "schema", "rivetlua-p16-sdk-evidence-v1")?;
    exact(&record, "profile", short)?;
    exact(&record, "target", target)?;
    sdk_pair(root, &record, "library", Path::new(env_value(5)?))?;
    exact(
        &record,
        "host_trust",
        "explicit-sdk-host-process-permissions-v1",
    )?;
    let limits = record
        .get("host_load_limits")
        .ok_or("P16 SDK host load limits 缺失")?;
    for (key, expected) in [
        ("source", 65536),
        ("encoded", 4194304),
        ("module", 8388608),
        ("temporary", 1048576),
        ("work", 2000000),
        ("chunks", 256),
        ("paths", 256),
    ] {
        if number(limits, key)? != expected {
            return Err(format!("P16 SDK host load limit {key} 不符"));
        }
    }
    if limits.get("configured") != Some(&StrictJsonValue::Bool(true)) {
        return Err("P16 SDK host load limits 未由 C bridge 確認".into());
    }
    sdk_pair(
        root,
        &record,
        "staticlib_build_log",
        Path::new(env_value(7)?),
    )?;
    let recorded_flags = array(&record, "native_static_libs")?;
    if recorded_flags.len() != native_flags.len()
        || recorded_flags
            .iter()
            .zip(&native_flags)
            .any(|(actual, expected)| actual.as_str() != Some(expected.as_str()))
    {
        return Err("P16 SDK rustc native-system flags 與 immutable log 不符".into());
    }
    let release = if short == "lua54" { "5.4.9" } else { "5.5.1" };
    let attrib = root.join(format!("vendor/{short}/lua-{release}-tests/attrib.lua"));
    sdk_pair(root, &record, "attrib_source", &attrib)?;
    let attrib_body = fs::read_to_string(attrib).map_err(|error| error.to_string())?;
    if !attrib_body.contains("createfiles(files, \"_ENV = {}\\n\", \"\\nreturn _ENV\\n\")") {
        return Err("P16 P1 attrib.lua fixed source 不符".into());
    }
    let expected_modules = fixed_module_sources(root, profile)?;
    let modules = array(&record, "modules")?;
    if modules.len() != expected_modules.len() {
        return Err("P16 SDK-MODULE 未涵蓋完整官方 Makefile module 集合".into());
    }
    let include = root.join(format!("include/rivetlua/{short}"));
    let common = root.join("include/rivetlua");
    let mut module_paths = Vec::new();
    for (index, (module, (name, source))) in modules.iter().zip(expected_modules).enumerate() {
        exact(module, "name", &name)?;
        sdk_pair(root, module, "source", &source)?;
        let output = evidence_dir.join(&name);
        sdk_private_pair(root, module, "module", &output, &evidence_dir)?;
        let mut build = vec![
            "cc".to_owned(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-fPIC".into(),
        ];
        if short == "lua55" && index == 4 {
            build.push("-Wno-unused-parameter".into());
        }
        if target.ends_with("apple-darwin") {
            build.extend([
                "-dynamiclib".into(),
                "-undefined".into(),
                "dynamic_lookup".into(),
            ]);
        } else {
            build.push("-shared".into());
        }
        build.extend([
            "-I".into(),
            include.display().to_string(),
            "-I".into(),
            common.display().to_string(),
            source.display().to_string(),
            "-o".into(),
            output.display().to_string(),
        ]);
        sdk_exact_command(module, "build_command", &build)?;
        if number(module, "build_exit_code")? != 0 {
            return Err(format!("P16 SDK {name} build exit 非零"));
        }
        sdk_private_pair(
            root,
            module,
            "build_log",
            &evidence_dir.join(format!("{name}-build.log")),
            &evidence_dir,
        )?;
        let symbols: &[&str] = match index {
            0 => &[
                "luaopen_lib1_sub",
                "lib1_export",
                "onefunction",
                "anotherfunc",
            ],
            1 => &["luaopen_lib11"],
            2 | 4 => &["luaopen_lib2"],
            3 => &["luaopen_lib21"],
            _ => unreachable!(),
        };
        let actual_symbols = array(module, "symbols")?;
        if actual_symbols.len() != symbols.len()
            || actual_symbols
                .iter()
                .zip(symbols)
                .any(|(actual, wanted)| actual.as_str() != Some(*wanted))
        {
            return Err(format!("P16 SDK {name} export 符號集合不符"));
        }
        sdk_check_nm(
            root,
            module,
            &output,
            &evidence_dir.join(format!("{name}-nm.log")),
            symbols,
            &evidence_dir,
        )?;
        module_paths.push(output);
    }
    let packages = array(&record, "packages")?;
    if packages.len() != 2 {
        return Err("P16 P1 檔案數量不符".into());
    }
    let mut package_paths = Vec::new();
    for (package, (name, aa)) in packages.iter().zip([("init.lua", 10), ("xuxu.lua", 20)]) {
        exact(package, "name", name)?;
        let path = evidence_dir.join("libs/P1").join(name);
        sdk_private_pair(root, package, "package", &path, &evidence_dir)?;
        if fs::read(&path).map_err(|error| error.to_string())?
            != format!("_ENV = {{}}\nAA = {aa}\nreturn _ENV\n").as_bytes()
            || number(package, "aa")? != aa
            || number(package, "global_aa")? != 0
            || package.get("loaded") != Some(&StrictJsonValue::Bool(true))
            || package.get("executed") != Some(&StrictJsonValue::Bool(true))
        {
            return Err(format!("P16 P1 {name} content/執行資料不符"));
        }
        package_paths.push(path);
    }
    let driver = record.get("driver").ok_or("P16 SDK driver 缺失")?;
    let driver_source = root.join("tests/p16/acceptance/sdk/driver.c");
    let driver_bin = evidence_dir.join("sdk-driver");
    sdk_pair(root, driver, "source", &driver_source)?;
    sdk_private_pair(root, driver, "binary", &driver_bin, &evidence_dir)?;
    let mut build = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-I".into(),
        include.display().to_string(),
        "-I".into(),
        common.display().to_string(),
        driver_source.display().to_string(),
    ];
    if target.ends_with("apple-darwin") {
        build.extend([
            format!("-Wl,-force_load,{}", env_value(5)?),
            "-Wl,-export_dynamic".into(),
        ]);
    } else {
        build.extend([
            "-Wl,--whole-archive".into(),
            env_value(5)?.into(),
            "-Wl,--no-whole-archive".into(),
            "-rdynamic".into(),
            "-ldl".into(),
        ]);
    }
    build.extend(native_flags);
    build.extend(["-o".into(), driver_bin.display().to_string()]);
    sdk_exact_command(driver, "build_command", &build)?;
    if number(driver, "build_exit_code")? != 0 {
        return Err("P16 SDK driver build exit 非零".into());
    }
    sdk_private_pair(
        root,
        driver,
        "build_log",
        &evidence_dir.join("driver-build.log"),
        &evidence_dir,
    )?;
    sdk_check_nm(
        root,
        driver,
        &driver_bin,
        &evidence_dir.join("driver-nm.log"),
        &[
            "lua_newstate",
            "lua_pcallk",
            "lua_close",
            "luaL_loadstring",
            "rivetlua_capi_configure_load_limits_b3",
        ],
        &evidence_dir,
    )?;
    let mut run = vec![driver_bin.display().to_string()];
    run.extend(module_paths.iter().map(|path| path.display().to_string()));
    run.extend(package_paths.iter().map(|path| path.display().to_string()));
    sdk_exact_command(driver, "run_command", &run)?;
    if number(driver, "run_exit_code")? != 0
        || driver.get("close_before_dlclose") != Some(&StrictJsonValue::Bool(true))
        || driver.get("allocator_released") != Some(&StrictJsonValue::Bool(true))
    {
        return Err("P16 SDK driver 執行／close 順序不符".into());
    }
    sdk_private_pair(
        root,
        driver,
        "run_log",
        &evidence_dir.join("driver-run.log"),
        &evidence_dir,
    )?;
    let body = String::from_utf8(artifact(root, driver, "run_log")?)
        .map_err(|_| "P16 SDK driver log 非 UTF-8")?;
    let required = [
        "P16_SDK_HOST_LIMITS source=65536 encoded=4194304 module=8388608 temporary=1048576 work=2000000 chunks=256 paths=256 PASS",
        "P16_SDK_MODULE lib1.so luaopen_lib1_sub TWO_ARG_ID PASS",
        "P16_SDK_MODULE lib2.so luaopen_lib2 TWO_ARG_ID PASS",
        "P16_SDK_MODULE lib21.so luaopen_lib21 TWO_ARG_ID PASS",
        "P16_SDK_MODULE lib2-v2.so luaopen_lib2 TWO_ARG_ID PASS",
        "P16_SDK_LIB11 lib11.so GLOBAL_LINK PASS",
        "P16_SDK_LIB1 FUNCTIONS PASS",
        "P16_SDK_CLOSE ALLOCATOR_RELEASE PASS",
        "P16_SDK_DLCLOSE AFTER_LUA_CLOSE PASS",
        "P16_SDK_RESULT PASS",
    ];
    if required
        .iter()
        .any(|wanted| body.lines().filter(|line| line == wanted).count() != 1)
    {
        return Err("P16 SDK C driver 實際效果證據缺失".into());
    }
    for module in &module_paths {
        let wanted = format!("P16_SDK_DLOPEN {} PASS", module.display());
        if body.lines().filter(|line| line == &wanted).count() != 1 {
            return Err("P16 SDK dlopen 未逐 module 證明".into());
        }
    }
    for (name, aa) in [("init.lua", 10), ("xuxu.lua", 20)] {
        let wanted = format!(
            "P16_SDK_P1 {} AA={aa} GLOBAL=0 PASS",
            evidence_dir.join("libs/P1").join(name).display()
        );
        if body.lines().filter(|line| line == &wanted).count() != 1 {
            return Err(format!("P16 P1 {name} load/execute 證據缺失"));
        }
    }
    let close = body
        .find("P16_SDK_CLOSE ALLOCATOR_RELEASE PASS")
        .ok_or("P16 SDK close 缺失")?;
    let unload = body
        .find("P16_SDK_DLCLOSE AFTER_LUA_CLOSE PASS")
        .ok_or("P16 SDK unload 缺失")?;
    if close >= unload {
        return Err("P16 SDK lua_close 必須先於 dlclose".into());
    }
    Ok(())
}

fn sdk_pair(
    root: &Path,
    value: &StrictJsonValue,
    key: &str,
    expected: &Path,
) -> Result<(), String> {
    if field(value, &format!("{key}_path"))? != expected.display().to_string() {
        return Err(format!("P16 SDK {key} 路徑不符"));
    }
    artifact(root, value, key)?;
    Ok(())
}

fn sdk_private_pair(
    root: &Path,
    value: &StrictJsonValue,
    key: &str,
    expected: &Path,
    evidence_dir: &Path,
) -> Result<(), String> {
    sdk_pair(root, value, key, expected)?;
    if !allowed_artifact(root, expected)?.starts_with(evidence_dir) {
        return Err(format!("P16 SDK {key} 非私有 evidence artifact"));
    }
    Ok(())
}

fn sdk_exact_command(
    value: &StrictJsonValue,
    key: &str,
    expected: &[String],
) -> Result<(), String> {
    let actual = array(value, key)?;
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(format!("P16 SDK {key} argv 不符"));
    }
    Ok(())
}

fn sdk_check_nm(
    root: &Path,
    value: &StrictJsonValue,
    binary: &Path,
    log_path: &Path,
    symbols: &[&str],
    evidence_dir: &Path,
) -> Result<(), String> {
    sdk_exact_command(
        value,
        "nm_command",
        &["nm".into(), "-g".into(), binary.display().to_string()],
    )?;
    if number(value, "nm_exit_code")? != 0 {
        return Err("P16 SDK nm exit 非零".into());
    }
    sdk_private_pair(root, value, "nm_log", log_path, evidence_dir)?;
    let recorded = artifact(root, value, "nm_log")?;
    let output = Command::new("nm")
        .arg("-g")
        .arg(binary)
        .current_dir(root)
        .output()
        .map_err(|error| format!("P16 SDK nm 重驗無法啟動：{error}"))?;
    let mut actual = output.stdout;
    actual.extend_from_slice(&output.stderr);
    if !output.status.success() || actual != recorded {
        return Err("P16 SDK nm 輸出與真 binary 不符".into());
    }
    let text = String::from_utf8(recorded).map_err(|_| "P16 SDK nm 非 UTF-8")?;
    if symbols
        .iter()
        .any(|symbol| !sdk_defined_global_function(&text, symbol, cfg!(target_os = "macos")))
    {
        return Err("P16 SDK exported symbol 缺失".into());
    }
    Ok(())
}

fn sdk_defined_global_function(log: &str, symbol: &str, darwin: bool) -> bool {
    let expected = if darwin {
        format!("_{symbol}")
    } else {
        symbol.to_owned()
    };
    log.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 3 && fields[fields.len() - 2] == "T" && fields[fields.len() - 1] == expected
    })
}

fn typed_case(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Case,
    profile: &str,
    target: &str,
    _manifest: &Manifest,
) -> Result<(), String> {
    let assertions = array(value, "assertions")?;
    if assertions.len() != expected.assertions.len()
        || assertions
            .iter()
            .zip(&expected.assertions)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(format!("P16 {} assertions 矩陣不符", expected.id));
    }
    counts(value)?;
    if number(value, "exit_code")? != 0 {
        return Err(format!("P16 {} 執行非零退出", expected.id));
    }
    if value.get("signal") != Some(&StrictJsonValue::Null)
        || value.get("local_failure") != Some(&StrictJsonValue::Null)
    {
        return Err(format!(
            "P16 {} PASS 夾帶 signal/local failure",
            expected.id
        ));
    }
    command(value, "command")?;
    allowed_directory(root, Path::new(field(value, "cwd")?))?;
    let log = verified_case_log(root, value, expected, profile, target)?;
    match expected.execution_kind {
        ExecutionKind::RustTest => {
            rust_test_evidence(root, value, expected, profile, target, &log)?;
            if matches!(
                expected.id.as_str(),
                "ABI-005" | "ABI-006" | "ABI-007" | "ABI-NEG-005"
            ) {
                super::native::verify_case(root, value, &expected.id, profile, target, &log)?;
            } else if !array(value, "environment")?.is_empty()
                || value.get("worker") != Some(&StrictJsonValue::Null)
                || value.get("artifact_record_path") != Some(&StrictJsonValue::Null)
                || value.get("artifact_record_sha256") != Some(&StrictJsonValue::Null)
            {
                return Err(format!("P16 {} 意外 native 子程序證據", expected.id));
            }
            if !array(value, "modules")?.is_empty()
                || !array(value, "package_artifacts")?.is_empty()
            {
                return Err(format!(
                    "P16 {} RustTest 夾帶 module artifacts",
                    expected.id
                ));
            }
        }
        ExecutionKind::SdkModules => {
            sdk_modules_evidence(root, value, expected, profile, target, &log)?
        }
        ExecutionKind::BuildAudit => {
            if expected.id != "ABI-NEG-006"
                || expected.fixture != "tests/p16/acceptance/abi_neg006.py"
            {
                return Err("P16 build audit 非固定 NEG006 fixture".into());
            }
            let source = root.join(&expected.fixture);
            if fs::canonicalize(field(value, "source_path")?).ok() != fs::canonicalize(source).ok()
            {
                return Err(format!("P16 {} build audit source 不符", expected.id));
            }
            artifact(root, value, "source")?;
            let build_source = root.join("crates/rivetlua-capi/build.rs");
            if fs::canonicalize(field(value, "upstream_source_path")?).ok()
                != fs::canonicalize(build_source).ok()
            {
                return Err("P16 NEG006 build.rs 來源不符".into());
            }
            artifact(root, value, "upstream_source")?;
            staticlib_evidence(root, value, profile, target)?;
            let library = field(value, "library_path")?;
            let expected_run = [
                "python3",
                field(value, "source_path")?,
                "--root",
                root.to_str().ok_or("P16 root 非 UTF-8")?,
                "--library",
                library,
                "--build-log",
                field(value, "staticlib_build_log_path")?,
                "--profile",
                profile,
                "--target",
                target,
                "--provenance",
                Path::new(field(value, "artifact_record_path")?)
                    .parent()
                    .and_then(Path::to_str)
                    .ok_or("P16 NEG006 provenance dir 無效")?,
            ];
            if command(value, "command")? != expected_run {
                return Err("P16 NEG006 audit command 不符".into());
            }
            let record = Path::new(field(value, "artifact_record_path")?);
            if record.file_name().and_then(|name| name.to_str()) != Some("receipt.json") {
                return Err("P16 NEG006 provenance receipt 名稱不符".into());
            }
            artifact(root, value, "artifact_record")?;
            if !array(value, "build_command")?.is_empty()
                || value.get("build_exit_code") != Some(&StrictJsonValue::Null)
                || value.get("build_signal") != Some(&StrictJsonValue::Null)
            {
                return Err(format!("P16 {} build audit 意外編譯", expected.id));
            }
            absent_artifact(value, "header")?;
            absent_artifact(value, "binary")?;
            absent_artifact(value, "build_log")?;
            absent_artifact(value, "c_log")?;
            if !array(value, "environment")?.is_empty()
                || !array(value, "local_tests")?.is_empty()
                || value.get("worker") != Some(&StrictJsonValue::Null)
            {
                return Err("P16 NEG006 夾帶非 audit 證據".into());
            }
            if !array(value, "modules")?.is_empty()
                || !array(value, "package_artifacts")?.is_empty()
            {
                return Err(format!(
                    "P16 {} build audit 夾帶 module artifacts",
                    expected.id
                ));
            }
            let rerun = Command::new("python3")
                .args(&expected_run[1..])
                .current_dir(root)
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .output()
                .map_err(|error| format!("P16 NEG006 audit 無法重驗：{error}"))?;
            if !rerun.status.success() || !rerun.stderr.is_empty() {
                return Err("P16 NEG006 audit 重驗失敗".into());
            }
            artifact(root, value, "artifact_record")?;
            let raw =
                String::from_utf8(rerun.stdout).map_err(|_| "P16 NEG006 audit output 非 UTF-8")?;
            if !log.starts_with(&raw) || !log[raw.len()..].starts_with("P16_CASE ") {
                return Err("P16 NEG006 audit log 與當輪實證不符".into());
            }
            for control in [
                "source",
                "link",
                "object",
                "symbol",
                "shim_private",
                "shim_extra",
                "second_shim",
            ] {
                let prefix = format!("P16_NEG006_CONTROL {control}=REJECTED reason=");
                if raw.lines().filter(|line| line.starts_with(&prefix)).count() != 1 {
                    return Err(format!("P16 NEG006 {control} 負向控制缺失"));
                }
            }
            if !raw
                .lines()
                .any(|line| line == "P16_ASSERT ABI-NEG-006 reject_c_lua_fallback=PASS")
                || !raw.lines().any(|line| {
                    line.starts_with(&format!("P16_NEG006 profile={profile} target={target} "))
                        && line.ends_with(" negative_controls=7 PASS")
                })
            {
                return Err("P16 NEG006 稽核摘要或 assertion 缺失".into());
            }
        }
        _ => return Err("P16 typed case 分類無效".into()),
    }
    Ok(())
}

fn case(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Case,
    profile: &str,
    target: &str,
    manifest: &Manifest,
) -> Result<(), String> {
    for (key, expected) in [
        ("id", expected.id.as_str()),
        ("profile", profile),
        ("target", target),
        ("execution_kind", expected.execution_kind.as_str()),
        ("fixture", expected.fixture.as_str()),
        ("status", "PASS"),
    ] {
        exact(value, key, expected)?;
    }
    if expected.execution_kind != ExecutionKind::CDriver {
        return typed_case(root, value, expected, profile, target, manifest);
    }
    if expected.fixture.is_empty() {
        return Err(format!("P16 {} 尚無正式 C fixture", expected.id));
    }
    let assertions = array(value, "assertions")?;
    if assertions.len() != expected.assertions.len()
        || assertions
            .iter()
            .zip(&expected.assertions)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(format!("P16 {} assertions 矩陣不符", expected.id));
    }
    counts(value)?;
    if number(value, "build_exit_code")? != 0 || number(value, "exit_code")? != 0 {
        return Err(format!("P16 {} build/run exit 非零", expected.id));
    }
    if value.get("build_signal") != Some(&StrictJsonValue::Null)
        || value.get("signal") != Some(&StrictJsonValue::Null)
        || value.get("local_failure") != Some(&StrictJsonValue::Null)
    {
        return Err(format!(
            "P16 {} PASS 夾帶 signal/local failure",
            expected.id
        ));
    }
    let build_command = command(value, "build_command")?;
    let run_command = command(value, "command")?;
    if run_command != [field(value, "binary_path")?] {
        return Err(format!("P16 {} actual command 不符", expected.id));
    }
    allowed_directory(root, Path::new(field(value, "cwd")?))?;
    let source = field(value, "source_path")?;
    let expected_source = root.join(&expected.fixture);
    if fs::canonicalize(source).ok() != fs::canonicalize(expected_source).ok() {
        return Err(format!("P16 {} C source path 不符", expected.id));
    }
    artifact(root, value, "source")?;
    if let Some(upstream) = matrix::original_source(&expected.id) {
        let fixed = root.join(upstream);
        if fs::canonicalize(field(value, "upstream_source_path")?).ok()
            != fs::canonicalize(fixed).ok()
        {
            return Err(format!("P16 {} upstream C body 不符", expected.id));
        }
        artifact(root, value, "upstream_source")?;
    } else {
        absent_artifact(value, "upstream_source")?;
    }
    let short = profile.strip_suffix("-i64f64").ok_or("P16 profile 無效")?;
    let expected_header = root.join(format!("include/rivetlua/{short}/lua.h"));
    if fs::canonicalize(field(value, "header_path")?).ok() != fs::canonicalize(expected_header).ok()
    {
        return Err(format!("P16 {} header path 不符", expected.id));
    }
    artifact(root, value, "header")?;
    exact(
        value,
        "header_set_sha256",
        manifest
            .header_sets
            .get(short)
            .ok_or("P16 header set 缺失")?,
    )?;
    let library = field(value, "library_path")?;
    let native_flags = staticlib_evidence(root, value, profile, target)?;
    if Path::new(library)
        .file_name()
        .and_then(|name| name.to_str())
        != Some("librivetlua_capi.a")
        || build_command
            .iter()
            .any(|part| part.starts_with("-llua") || part.ends_with("/liblua.a"))
    {
        return Err(format!(
            "P16 {} library 非 RivetLua staticlib 或使用 C Lua fallback",
            expected.id
        ));
    }
    let include = root.join(format!("include/rivetlua/{short}"));
    let mut expected_build = vec![
        "cc".to_owned(),
        "-std=c11".to_owned(),
        "-Wall".to_owned(),
        "-Wextra".to_owned(),
        "-Werror".to_owned(),
        format!("-I{}", include.display()),
        format!("-I{}", root.join("include/rivetlua").display()),
        source.to_owned(),
        library.to_owned(),
        "-o".to_owned(),
        field(value, "binary_path")?.to_owned(),
    ];
    expected_build.extend(native_flags);
    if build_command
        != expected_build
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(format!(
            "P16 {} C build command 未連接固定 header、source、staticlib 與 binary",
            expected.id
        ));
    }
    artifact(root, value, "library")?;
    artifact(root, value, "binary")?;
    let build_log = artifact(root, value, "build_log")?;
    let build_log = String::from_utf8(build_log).map_err(|_| "P16 build log 非 UTF-8")?;
    if !build_log
        .lines()
        .any(|line| line == format!("P16_BUILD {} {profile} {target} PASS", expected.id))
    {
        return Err(format!("P16 {} build log marker 缺失", expected.id));
    }
    let c_log = String::from_utf8(artifact(root, value, "c_log")?)
        .map_err(|_| "P16 C body log 非 UTF-8")?;
    if !c_log
        .lines()
        .any(|line| line == format!("P16_C_BODY {} PASS", expected.id))
    {
        return Err(format!("P16 {} C body marker 缺失", expected.id));
    }
    if expected.id == "ABI-STRESS" {
        stress_evidence(&c_log)?;
    }
    let proofs = matrix::rust_proofs(&expected.id);
    let local_tests = array(value, "local_tests")?;
    if local_tests.len() != proofs.len() {
        return Err(format!("P16 {} 具名 Rust proof 數量不符", expected.id));
    }
    for (item, proof) in local_tests.iter().zip(proofs) {
        verified_rust_proof(root, item, *proof, profile, target)?;
    }
    let log = artifact(root, value, "log")?;
    let log = String::from_utf8(log).map_err(|_| "P16 run log 非 UTF-8")?;
    let marker = format!(
        "P16_CASE {} {profile} {target} PASS matched={} passed={} failed=0 ignored=0",
        expected.id,
        number(value, "matched")?,
        number(value, "passed")?
    );
    if !log.lines().any(|line| line == marker) {
        return Err(format!("P16 {} runtime/count marker 缺失", expected.id));
    }
    for assertion in &expected.assertions {
        let marker = format!("P16_ASSERT {} {assertion}=PASS", expected.id);
        let backed_by_c = c_log.lines().any(|line| line == marker);
        let backed_by_rust = proofs
            .iter()
            .any(|proof| proof.assertions.contains(&assertion.as_str()));
        if !log.lines().any(|line| line == marker) || (!backed_by_c && !backed_by_rust) {
            return Err(format!(
                "P16 {} {assertion} 固定 C/Rust body evidence 缺失",
                expected.id
            ));
        }
    }
    if !array(value, "modules")?.is_empty() || !array(value, "package_artifacts")?.is_empty() {
        return Err(format!(
            "P16 {} CDriver 含非預期 module/package artifacts",
            expected.id
        ));
    }
    Ok(())
}

fn row(
    root: &Path,
    value: &StrictJsonValue,
    expected: &Row,
    proofs: &HashMap<&str, &StrictJsonValue>,
    selection: Option<&Snapshot>,
) -> Result<(), String> {
    exact(value, "id", &expected.id)?;
    exact(value, "status", "PASS")?;
    let applicability = selection.and_then(|observed| selection::classify(observed, expected).ok());
    exact(value, "manifest_evidence", &expected.evidence)?;
    exact(value, "manifest_mapping", &expected.mapping)?;
    exact(value, "manifest_p17_use", &expected.p17_use)?;
    let required = rowproof::required_with(root, expected, selection)
        .map_err(|reason| format!("P16 row {} 無固定 proof：{reason}", expected.id))?;
    let ids = required.iter().map(ProofKey::id).collect::<Vec<_>>();
    let expected_metadata = StrictJsonParser::parse(&report::row_with_observation(
        expected,
        "PASS",
        &ids,
        "",
        applicability.as_ref(),
    ))?;
    for key in [
        "evidence_mode",
        "applicability",
        "active_header",
        "active_line",
        "active_definition",
        "manifest_guard",
        "effect_matched",
        "effect_passed",
    ] {
        if value.get(key) != expected_metadata.get(key) {
            return Err(format!(
                "P16 row {} {key} selection/effect 不符",
                expected.id
            ));
        }
    }
    let actual = array(value, "required_proofs")?
        .iter()
        .map(|item| item.as_str().ok_or("P16 row proof ID 非字串"))
        .collect::<Result<Vec<_>, _>>()?;
    if actual != ids.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(format!(
            "P16 row {} exact required proof set 不符",
            expected.id
        ));
    }
    if value.get("case_id") != Some(&StrictJsonValue::Null)
        || value.get("command") != Some(&StrictJsonValue::Array(Vec::new()))
        || value.get("cwd") != Some(&StrictJsonValue::Null)
        || value.get("exit_code") != Some(&StrictJsonValue::Null)
        || value
            .get("unmapped_reason")
            .and_then(StrictJsonValue::as_str)
            != Some("")
    {
        return Err(format!("P16 row {} 含非 typed proof 證據", expected.id));
    }
    if number(value, "matched")? != ids.len()
        || number(value, "passed")? != ids.len()
        || number(value, "failed")? != 0
        || number(value, "ignored")? != 0
        || ids.is_empty()
    {
        return Err(format!("P16 row {} proof counts 不符", expected.id));
    }
    absent_artifact(value, "log")?;
    for id in ids {
        if proofs.get(id.as_str()).is_none() {
            return Err(format!("P16 row {} 缺 proof {id}", expected.id));
        }
    }
    if rowproof::needs_value(expected)
        && (expected.kind == "layout_field"
            || matches!(applicability, Some(Applicability::Selected(_))))
    {
        let product_id = ProofKey::HeaderValues(expected.profile.clone()).id();
        let official_id = ProofKey::OfficialValues(expected.profile.clone()).id();
        let product = proofs
            .get(product_id.as_str())
            .ok_or("P16 product value proof 缺失")?;
        let official = proofs
            .get(official_id.as_str())
            .ok_or("P16 official value proof 缺失")?;
        let product_log = String::from_utf8(artifact(root, product, "log")?)
            .map_err(|_| "P16 product value log 非 UTF-8")?;
        let official_log = String::from_utf8(artifact(root, official, "log")?)
            .map_err(|_| "P16 official value log 非 UTF-8")?;
        if super::valueprobe::row_value(expected, &product_log)?
            != super::valueprobe::row_value(expected, &official_log)?
        {
            return Err(format!(
                "P16 row {} SDK/official C 值或型別不符",
                expected.id
            ));
        }
    }
    for key in &required {
        if matches!(key, ProofKey::CFixture { source, .. } if source == "tests/p16/acceptance/api_effects.c")
        {
            let proof = proofs
                .get(key.id().as_str())
                .ok_or("P16 per-symbol C proof 缺失")?;
            let log = String::from_utf8(artifact(root, proof, "log")?)
                .map_err(|_| "P16 per-symbol C log 非 UTF-8")?;
            let marker = format!("P16_C_EFFECT {} PASS", expected.name);
            if log.lines().filter(|line| *line == marker).count() != 1 {
                return Err(format!(
                    "P16 row {} 缺個別 C ABI effect marker",
                    expected.id
                ));
            }
        }
    }
    Ok(())
}

fn verify_proof_build_command(
    value: &StrictJsonValue,
    key: &ProofKey,
    expected: &[String],
) -> Result<(), String> {
    if command(value, "build_command")? != expected.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(format!("P16 proof {} build command 不符", key.id()));
    }
    Ok(())
}

pub(super) fn proof(
    root: &Path,
    value: &StrictJsonValue,
    key: &ProofKey,
    target: &str,
    cases: &HashMap<&str, &StrictJsonValue>,
    manifest: &Manifest,
    selection: Option<&Snapshot>,
) -> Result<(), String> {
    exact(value, "id", &key.id())?;
    exact(value, "kind", key.kind())?;
    exact(value, "profile", key.profile())?;
    exact(value, "target", target)?;
    exact(value, "status", "PASS")?;
    exact(
        value,
        "cwd",
        root.to_str().ok_or("P16 workspace path 非 UTF-8")?,
    )?;
    let profile = key.profile();
    let full_profile = format!("{profile}-i64f64");
    exact(
        value,
        "header_set_sha256",
        manifest
            .header_sets
            .get(profile)
            .ok_or("P16 proof header set 缺失")?,
    )?;
    let header = if matches!(key, ProofKey::OfficialValues(_)) {
        super::valueprobe::vendor_dir(root, profile)?.join("lua.h")
    } else {
        root.join(format!("include/rivetlua/{profile}/lua.h"))
    };
    if field(value, "header_path")? != header.display().to_string() {
        return Err(format!("P16 proof {} header path 不符", key.id()));
    }
    artifact(root, value, "header")?;
    let source = match key {
        ProofKey::Pinned(_) => root.join("tests/p16/generate_manifest.py"),
        ProofKey::Surface(_) => root.join(format!("tests/p16/surface_{profile}.c")),
        ProofKey::Layout(_) => root.join("tests/p16/acceptance/layout_identity.c"),
        ProofKey::HeaderSelection(_) => selection::source(root),
        ProofKey::MacroEffects(_) => root.join("tests/p16/acceptance/macro_effects.c"),
        ProofKey::HeaderValues(_) | ProofKey::OfficialValues(_) => super::valueprobe::source(root),
        ProofKey::CFixture { source, .. } => root.join(source),
        ProofKey::CFixtureFailFalse { .. } => root.join(rowproof::FAILFALSE_SOURCE),
        ProofKey::RustNamed { target, .. } | ProofKey::RustCrossContract { target, .. } => {
            root.join(format!("crates/rivetlua-capi/tests/{target}.rs"))
        }
    };
    if field(value, "source_path")? != source.display().to_string() {
        return Err(format!("P16 proof {} source path 不符", key.id()));
    }
    artifact(root, value, "source")?;
    counts(value)?;
    if number(value, "matched")? != 1
        || number(value, "passed")? != 1
        || number(value, "build_exit_code")? != 0
        || value.get("build_signal") != Some(&StrictJsonValue::Null)
        || value.get("signal") != Some(&StrictJsonValue::Null)
    {
        return Err(format!("P16 proof {} zero matching/status 不符", key.id()));
    }
    let mut expected_build: Vec<String>;
    let mut expected_run = Vec::<String>::new();
    let mut run_expected = false;
    match key {
        ProofKey::Pinned(_) => {
            expected_build = vec![
                "python3".into(),
                "tests/p16/generate_manifest.py".into(),
                "check".into(),
            ];
            absent_artifact(value, "library")?;
            absent_artifact(value, "binary")?;
        }
        ProofKey::Surface(_) => {
            expected_build = vec![
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
            absent_artifact(value, "library")?;
            absent_artifact(value, "binary")?;
        }
        ProofKey::HeaderSelection(_) => {
            expected_build = selection
                .ok_or("P16 HeaderSelection gate 未重跑預處理")?
                .command
                .clone();
            absent_artifact(value, "library")?;
            absent_artifact(value, "binary")?;
        }
        ProofKey::HeaderValues(_) | ProofKey::OfficialValues(_) => {
            super::valueprobe::verify_vendor(root, manifest, profile)?;
            absent_artifact(value, "library")?;
            artifact(root, value, "binary")?;
            let binary = field(value, "binary_path")?.to_owned();
            expected_build = super::valueprobe::command(
                root,
                profile,
                matches!(key, ProofKey::OfficialValues(_)),
                Path::new(&binary),
            )?;
            expected_run = vec![binary];
            run_expected = true;
        }
        ProofKey::MacroEffects(_) => {
            absent_artifact(value, "library")?;
            artifact(root, value, "binary")?;
            let binary = field(value, "binary_path")?.to_owned();
            expected_build = vec![
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
                expected_build.push("-DLUA_COMPAT_5_3".into());
            } else {
                expected_build.push("-DLUA_COMPAT_APIINTCASTS".into());
            }
            expected_build.extend([
                source.display().to_string(),
                "-lm".into(),
                "-o".into(),
                binary.clone(),
            ]);
            expected_run = vec![binary];
            run_expected = true;
        }
        ProofKey::Layout(_) | ProofKey::CFixture { .. } | ProofKey::CFixtureFailFalse { .. } => {
            let linked = cases
                .get("ABI-001")
                .ok_or("P16 C proof 缺 ABI-001 staticlib 來源")?;
            for name in ["library_path", "library_sha256"] {
                if value.get(name) != linked.get(name) {
                    return Err(format!(
                        "P16 C proof {} private staticlib snapshot 不符",
                        key.id()
                    ));
                }
            }
            artifact(root, value, "library")?;
            artifact(root, value, "binary")?;
            let binary = field(value, "binary_path")?.to_owned();
            let native_flags = array(linked, "native_static_libs")?
                .iter()
                .map(|flag| {
                    flag.as_str()
                        .map(str::to_owned)
                        .ok_or("P16 native flag 非字串")
                })
                .collect::<Result<Vec<_>, _>>()?;
            expected_build = if matches!(key, ProofKey::CFixtureFailFalse { .. }) {
                rowproof::failfalse_command(
                    root,
                    profile,
                    Path::new(field(value, "library_path")?),
                    Path::new(&binary),
                    &native_flags,
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
                if matches!(key, ProofKey::CFixture { source, .. } if source == "tests/p16/acceptance/api_effects.c")
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
                    field(value, "library_path")?.into(),
                    "-o".into(),
                    binary.clone(),
                ]);
                command.extend(native_flags);
                command
            };
            expected_run = vec![binary.clone()];
            if matches!(key, ProofKey::CFixture { source, .. } if source == "tests/p16/load_b3.c") {
                let file = Path::new(&binary).with_extension("load-b3.lua");
                expected_run.push(file.display().to_string());
            }
            run_expected = true;
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
            absent_artifact(value, "library")?;
            artifact(root, value, "binary")?;
            immutable_rust_test_snapshot(value, test_target, &full_profile, target)?;
            let binary = field(value, "binary_path")?.to_owned();
            expected_build = vec![
                "cargo".into(),
                "test".into(),
                "--locked".into(),
                "-p".into(),
                "rivetlua-capi".into(),
                "--test".into(),
                test_target.clone(),
                "--no-run".into(),
                "--message-format=json-render-diagnostics".into(),
            ];
            if profile == "lua54" {
                expected_build.extend([
                    "--no-default-features".into(),
                    "--features".into(),
                    "lua54".into(),
                ]);
            }
            expected_run = vec![
                binary,
                test.clone(),
                "--exact".into(),
                "--nocapture".into(),
                "--test-threads=1".into(),
            ];
            run_expected = true;
        }
    }
    verify_proof_build_command(value, key, &expected_build)?;
    let build_log = String::from_utf8(artifact(root, value, "build_log")?)
        .map_err(|_| "P16 proof build log 非 UTF-8")?;
    if run_expected {
        if command(value, "command")? != expected_run.iter().map(String::as_str).collect::<Vec<_>>()
            || number(value, "exit_code")? != 0
        {
            return Err(format!("P16 proof {} run command/status 不符", key.id()));
        }
        let log = String::from_utf8(artifact(root, value, "log")?)
            .map_err(|_| "P16 proof run log 非 UTF-8")?;
        match key {
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
                if !build_log
                    .lines()
                    .any(|line| line == format!("P16_BUILD {test_target} {full_profile} PASS"))
                    || !super::named_libtest_passed(&log, test)
                {
                    return Err(format!(
                        "P16 Rust proof {} libtest 0/失敗/marker 不符",
                        key.id()
                    ));
                }
            }
            ProofKey::Layout(_) => {
                if !log.lines().any(|line| line == "P16_LAYOUT 37 PASS")
                    || (0..37).any(|index| {
                        !log.lines()
                            .any(|line| line.starts_with(&format!("P16_LAYOUT {index} ")))
                    })
                    || !log
                        .lines()
                        .any(|line| line == format!("P16_PROOF {} PASS", key.id()))
                {
                    return Err("P16 layout 37 欄 runtime proof 不完整".into());
                }
            }
            ProofKey::CFixture { .. } | ProofKey::CFixtureFailFalse { .. } => {
                if !log
                    .lines()
                    .any(|line| line == format!("P16_PROOF {} PASS", key.id()))
                {
                    return Err(format!("P16 C proof {} runtime marker 缺失", key.id()));
                }
            }
            ProofKey::MacroEffects(_) => {
                let observed = selection.ok_or("P16 MacroEffects selection 缺失")?;
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
                let actual = log
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
                    || selection::verify_macro_output(profile, &log).is_err()
                    || !log
                        .lines()
                        .any(|line| line == format!("P16_PROOF {} PASS", key.id()))
                {
                    return Err("P16 selected macro 各名稱專屬 effect 證據不符".into());
                }
            }
            ProofKey::HeaderValues(_) | ProofKey::OfficialValues(_) => {
                let observed = selection.ok_or("P16 value probe selection 缺失")?;
                let expected = super::valueprobe::expected(manifest, profile, observed)?;
                let values = super::valueprobe::observations(&log)?;
                if values
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected
                    || !log
                        .lines()
                        .any(|line| line == format!("P16_PROOF {} PASS", key.id()))
                {
                    return Err("P16 value probe 逐列 C 值／型別 marker 不符".into());
                }
            }
            _ => unreachable!(),
        }
    } else if matches!(key, ProofKey::HeaderSelection(_)) {
        let observed = selection.ok_or("P16 HeaderSelection 重驗缺失")?;
        if value.get("command") != Some(&StrictJsonValue::Array(Vec::new()))
            || value.get("exit_code") != Some(&StrictJsonValue::Null)
            || build_log != observed.output
        {
            return Err("P16 HeaderSelection 完整預處理輸出或 argv 不符".into());
        }
        absent_artifact(value, "log")?;
    } else if value.get("command") != Some(&StrictJsonValue::Array(Vec::new()))
        || value.get("exit_code") != Some(&StrictJsonValue::Null)
        || !build_log
            .lines()
            .any(|line| line == format!("P16_PROOF {} PASS", key.id()))
    {
        return Err(format!(
            "P16 compile/header proof {} marker/status 不符",
            key.id()
        ));
    } else {
        absent_artifact(value, "log")?;
    }
    Ok(())
}

fn acceptance(
    root: &Path,
    digest: &str,
    profile: &str,
    target: &str,
    cases: &[Case],
    manifest: &Manifest,
) -> Result<(), String> {
    let path = report::path(root, profile, target);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("P16 {profile}/{target} acceptance report 缺失：{error}"))?;
    let value = StrictJsonParser::parse(&source)
        .map_err(|error| format!("P16 acceptance JSON 無效：{error}"))?;
    for (key, expected) in [
        ("schema", report::SCHEMA),
        ("status", "PASS"),
        ("profile", profile),
        ("target", target),
        ("source_digest", digest),
        ("report_path", path.to_str().ok_or("P16 path 非 UTF-8")?),
    ] {
        exact(&value, key, expected)?;
    }
    exact(
        &value,
        "matrix_sha256",
        &sha_file(&root.join("tests/p16/acceptance-cases.toml"))?,
    )?;
    exact(
        &value,
        "manifest_sha256",
        &sha_file(&root.join("tests/p16/abi-manifest.toml"))?,
    )?;
    let short = profile
        .strip_suffix("-i64f64")
        .ok_or("P16 profile numeric 無效")?;
    exact(
        &value,
        "header_set_sha256",
        manifest
            .header_sets
            .get(short)
            .ok_or("P16 header set 缺失")?,
    )?;
    let actual = array(&value, "cases")?;
    if actual.len() != cases.len() {
        return Err("P16 acceptance case 總數不符".into());
    }
    unique_ids(actual, "case")?;
    let mut ids = HashSet::new();
    let mut case_map = HashMap::new();
    for (actual, expected) in actual.iter().zip(cases) {
        let id = field(actual, "id")?;
        if !ids.insert(id) {
            return Err("P16 acceptance 重複 case ID".into());
        }
        case_map.insert(id, actual);
        case(root, actual, expected, profile, target, manifest)?;
    }
    let expected_rows: Vec<_> = manifest
        .rows
        .iter()
        .filter(|row| row.profile == short)
        .collect();
    let selection = selection::capture(root, short)?;
    let mut expected_proofs = BTreeSet::new();
    for row in &expected_rows {
        for key in rowproof::required_with(root, row, Some(&selection))
            .map_err(|reason| format!("P16 acceptance row {} 無固定 proof：{reason}", row.id))?
        {
            expected_proofs.insert(key);
        }
    }
    let actual_proofs = array(&value, "proofs")?;
    if actual_proofs.len() != expected_proofs.len() {
        return Err("P16 acceptance proof 總數不符".into());
    }
    unique_ids(actual_proofs, "typed proof")?;
    let mut proof_map = HashMap::new();
    for (actual, expected) in actual_proofs.iter().zip(expected_proofs.iter()) {
        proof(
            root,
            actual,
            expected,
            target,
            &case_map,
            manifest,
            Some(&selection),
        )?;
        proof_map.insert(field(actual, "id")?, actual);
    }
    if !array(&value, "unmapped")?.is_empty() {
        return Err("P16 acceptance 仍有未映射列".into());
    }
    let actual_rows = array(&value, "rows")?;
    if actual_rows.len() != expected_rows.len() {
        return Err("P16 acceptance manifest row 總數不符".into());
    }
    unique_ids(actual_rows, "manifest row")?;
    let mut row_ids = HashSet::new();
    for (actual, expected) in actual_rows.iter().zip(expected_rows) {
        if !row_ids.insert(field(actual, "id")?) {
            return Err("P16 acceptance 重複 manifest row ID".into());
        }
        row(root, actual, expected, &proof_map, Some(&selection))?;
    }
    Ok(())
}

fn evaluate(root: &Path, digest: &str) -> Result<String, String> {
    let target = host_target()?;
    if !matrix::TARGETS.contains(&target) {
        return Err("P16 target 不在矩陣".into());
    }
    let cases = matrix::load(root)?;
    let manifest = manifest::load(root)?;
    for short in ["lua55", "lua54"] {
        verify_header_set(root, &manifest, short)?;
    }
    prior_reports(root, digest)?;
    let (generator_log, generator_sha) = generator_check(root, &manifest)?;
    for profile in matrix::PROFILES {
        acceptance(root, digest, profile, target, &cases, &manifest)?;
    }
    if source_digest(root)? != digest {
        return Err("P16 gate 執行期間來源已變更".into());
    }
    let mut checks = vec![format!(
        "{{\"name\":\"p16-pinned-generator\",\"status\":\"PASS\",\"command\":[\"python3\",\"tests/p16/generate_manifest.py\",\"check\"],\"exit_code\":0,\"log_path\":{},\"log_sha256\":{}}}",
        q(&generator_log),
        q(&generator_sha)
    )];
    checks.extend(matrix::PROFILES.iter().map(|profile| {
        format!(
            "{{\"name\":{},\"status\":\"PASS\",\"report_path\":{},\"target\":{}}}",
            q(&format!("p16-acceptance-{profile}")),
            q(&report::path(root, profile, target).display().to_string()),
            q(target)
        )
    }));
    Ok(checks.join(","))
}

pub(super) fn run() -> Result<(), String> {
    let root = root()?;
    let digest = source_digest(&root).ok();
    match digest
        .as_deref()
        .ok_or_else(|| "P16 source digest 不可取得".to_owned())
        .and_then(|digest| evaluate(&root, digest))
    {
        Ok(checks) => {
            report::gate_result(
                &root,
                digest.as_deref(),
                "PASS",
                "P16 兩 profile 於本 target 驗收通過",
                &checks,
            )?;
            println!(
                "P16 PASS target={} report={}",
                host_target()?,
                report::gate_path(&root).display()
            );
            Ok(())
        }
        Err(error) => {
            report::gate_result(&root, digest.as_deref(), "FAIL", &error, "")?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_stress_rejects_zero_iterations_and_leaked_tokens() {
        let good = "P16_STRESS seed=381747182 iterations=1024 callback=1024 gc=1024 coroutine=1024 debug_ref=1024 warmup=128 stable_samples=896 warm_active=23 warm_bytes=128 peak_bytes=256 active_tokens=0 live_bytes=0 issued=23 refunded=23 invalid_pairs=0 duplicate_refunds=0\n";
        assert!(stress_evidence(good).is_ok());
        assert!(stress_evidence(&good.replace("callback=1024", "callback=0")).is_err());
        assert!(stress_evidence(&good.replace("active_tokens=0", "active_tokens=1")).is_err());
        assert!(stress_evidence(&good.replace("live_bytes=0", "live_bytes=1")).is_err());
        assert!(stress_evidence(&good.replace("warm_bytes=128", "warm_bytes=0")).is_err());
        assert!(stress_evidence(&good.replace("refunded=23", "refunded=22")).is_err());
        assert!(stress_evidence(&(good.to_owned() + good)).is_err());
    }

    #[test]
    fn p16_sdk_rejects_linux_flags_on_macos_and_stale_artifact() {
        let expected = vec!["cc".to_owned(), "-dynamiclib".to_owned()];
        let valid = StrictJsonParser::parse(r#"{"argv":["cc","-dynamiclib"]}"#).unwrap();
        sdk_exact_command(&valid, "argv", &expected).unwrap();
        let wrong = StrictJsonParser::parse(r#"{"argv":["cc","-shared"]}"#).unwrap();
        assert!(sdk_exact_command(&wrong, "argv", &expected).is_err());

        let root = std::env::temp_dir().join(format!("rivetlua-sdk-gate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("module.so");
        fs::write(&path, b"module-v1").unwrap();
        let value = StrictJsonParser::parse(&format!(
            "{{\"module_path\":{},\"module_sha256\":{}}}",
            super::super::q(&path.display().to_string()),
            super::super::q(&sha_file(&path).unwrap())
        ))
        .unwrap();
        sdk_pair(&root, &value, "module", &path).unwrap();
        fs::write(&path, b"module-v2").unwrap();
        assert!(sdk_pair(&root, &value, "module", &path).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn p16_sdk_undefined_nm_symbol_cannot_satisfy_export() {
        assert!(sdk_defined_global_function(
            "0000 T _luaopen_lib2\n",
            "luaopen_lib2",
            true
        ));
        assert!(sdk_defined_global_function(
            "0000 T luaopen_lib2\n",
            "luaopen_lib2",
            false
        ));
        assert!(!sdk_defined_global_function(
            "U _luaopen_lib2\n",
            "luaopen_lib2",
            true
        ));
        assert!(!sdk_defined_global_function(
            "0000 W luaopen_lib2\n",
            "luaopen_lib2",
            false
        ));
    }

    #[test]
    fn p16_row_requires_exact_typed_set_and_real_proof() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let row_spec = manifest
            .rows
            .iter()
            .find(|row| {
                row.profile == "lua55" && row.status == "HEADER_ONLY" && row.kind == "constant"
            })
            .unwrap();
        let keys = rowproof::required(root, row_spec)
            .unwrap()
            .iter()
            .map(ProofKey::id)
            .collect::<Vec<_>>();
        let observed = selection::capture(root, "lua55").unwrap();
        let applicability = selection::classify(&observed, row_spec).unwrap();
        let valid = StrictJsonParser::parse(&report::row_with_observation(
            row_spec,
            "PASS",
            &keys,
            "",
            Some(&applicability),
        ))
        .unwrap();
        assert!(
            row(root, &valid, row_spec, &HashMap::new(), Some(&observed))
                .unwrap_err()
                .contains("缺 proof")
        );
        let forged = StrictJsonParser::parse(&report::row_with_observation(
            row_spec,
            "PASS",
            &["generic:ABI-004".into()],
            "",
            Some(&applicability),
        ))
        .unwrap();
        assert!(
            row(root, &forged, row_spec, &HashMap::new(), Some(&observed))
                .unwrap_err()
                .contains("exact required proof set")
        );
    }

    #[test]
    fn p16_failfalse_proof_requires_fixed_c11_define_command() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let key = ProofKey::CFixtureFailFalse {
            profile: "lua55".into(),
        };
        let expected = rowproof::failfalse_command(
            root,
            "lua55",
            Path::new("/fixed/lib.a"),
            Path::new("/fixed/proof.bin"),
            &["-lm".into()],
        )
        .unwrap();
        assert_eq!(
            expected
                .iter()
                .filter(|arg| *arg == "-DLUA_FAILISFALSE")
                .count(),
            1
        );
        assert_eq!(expected[1], "-std=c11");
        let as_value = |args: &[String]| {
            StrictJsonParser::parse(&format!(
                "{{\"build_command\":[{}]}}",
                args.iter().map(|arg| q(arg)).collect::<Vec<_>>().join(",")
            ))
            .unwrap()
        };
        assert!(verify_proof_build_command(&as_value(&expected), &key, &expected).is_ok());
        let missing = expected
            .iter()
            .filter(|arg| *arg != "-DLUA_FAILISFALSE")
            .cloned()
            .collect::<Vec<_>>();
        assert!(verify_proof_build_command(&as_value(&missing), &key, &expected).is_err());
        let wrong = expected
            .iter()
            .map(|arg| {
                if arg == "-DLUA_FAILISFALSE" {
                    "-DLUA_FAILISFALSE=0".into()
                } else {
                    arg.clone()
                }
            })
            .collect::<Vec<_>>();
        assert!(verify_proof_build_command(&as_value(&wrong), &key, &expected).is_err());
        assert!(
            rowproof::failfalse_command(
                root,
                "lua54",
                Path::new("/fixed/lib.a"),
                Path::new("/fixed/proof.bin"),
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn p16_typed_proof_rejects_zero_matching_before_pass() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let key = ProofKey::Pinned("lua55".into());
        let source = root.join("tests/p16/generate_manifest.py");
        let header = root.join("include/rivetlua/lua55/lua.h");
        let value = StrictJsonParser::parse(&format!(
            "{{\"id\":{},\"kind\":\"PinnedHeaders\",\"profile\":\"lua55\",\"target\":\"aarch64-apple-darwin\",\"status\":\"PASS\",\"cwd\":{},\"source_path\":{},\"source_sha256\":{},\"header_path\":{},\"header_sha256\":{},\"header_set_sha256\":{},\"matched\":0,\"passed\":0,\"failed\":0,\"ignored\":0,\"build_exit_code\":0,\"build_signal\":null,\"signal\":null}}",
            q(&key.id()), q(&root.display().to_string()), q(&source.display().to_string()),
            q(&sha_file(&source).unwrap()), q(&header.display().to_string()),
            q(&sha_file(&header).unwrap()), q(manifest.header_sets.get("lua55").unwrap())
        )).unwrap();
        assert!(
            proof(
                root,
                &value,
                &key,
                "aarch64-apple-darwin",
                &HashMap::new(),
                &manifest,
                None,
            )
            .unwrap_err()
            .contains("zero tests")
        );
    }

    #[test]
    fn p16_two_profiles_keep_immutable_snapshots_after_cargo_alias_changes() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p16-two-snapshots-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let shared = root.join("shared/debug");
        let profiles = root.join("profiles");
        fs::create_dir_all(&shared).unwrap();
        fs::create_dir_all(&profiles).unwrap();
        let alias = shared.join("librivetlua_capi.a");
        let first = profiles.join("lua55-librivetlua_capi.a");
        let second = profiles.join("lua54-librivetlua_capi.a");
        fs::write(&alias, b"lua55 archive").unwrap();
        fs::copy(&alias, &first).unwrap();
        let first_hash = sha_file(&alias).unwrap();
        fs::write(&alias, b"lua54 archive").unwrap();
        fs::copy(&alias, &second).unwrap();
        let second_hash = sha_file(&alias).unwrap();
        assert_ne!(first_hash, second_hash);
        for (snapshot, hash) in [(&first, first_hash), (&second, second_hash)] {
            let value = StrictJsonParser::parse(&format!(
                "{{\"staticlib_artifact_path\":{},\"staticlib_artifact_sha256\":{},\"library_path\":{},\"library_sha256\":{}}}",
                q(&alias.display().to_string()), q(&hash),
                q(&snapshot.display().to_string()), q(&hash)
            )).unwrap();
            assert!(immutable_staticlib_snapshot(&root, &value).is_ok());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p16_pinned_generator_rejects_forged_manifest_or_header() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let good = format!(
            "P16-1 清單 PASS: 951 rows []\nlua55 header_set_sha256 {}\nlua54 header_set_sha256 {}\n",
            manifest.header_sets["lua55"], manifest.header_sets["lua54"]
        );
        assert!(generator_output(&good, &manifest).is_ok());
        assert!(generator_output(&good.replace("951 rows", "951 items"), &manifest).is_err());
        assert!(
            generator_output(
                &good.replace(&manifest.header_sets["lua55"], &"0".repeat(64)),
                &manifest
            )
            .is_err()
        );
    }

    #[test]
    fn p16_gate_rejects_zero_tests_and_duplicate_ids() {
        let zero =
            StrictJsonParser::parse("{\"matched\":0,\"passed\":0,\"failed\":0,\"ignored\":0}")
                .unwrap();
        assert!(counts(&zero).is_err());
        let ignored =
            StrictJsonParser::parse("{\"matched\":2,\"passed\":1,\"failed\":0,\"ignored\":1}")
                .unwrap();
        assert!(counts(&ignored).is_err());
        let valid =
            StrictJsonParser::parse("{\"matched\":2,\"passed\":2,\"failed\":0,\"ignored\":0}")
                .unwrap();
        assert!(counts(&valid).is_ok());
        let duplicate =
            StrictJsonParser::parse("[{\"id\":\"ABI-001\"},{\"id\":\"ABI-001\"}]").unwrap();
        assert!(unique_ids(duplicate.as_array().unwrap(), "case").is_err());
    }

    #[test]
    fn p16_case_evidence_rechecks_hash_exit_and_body_markers() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p16-case-protocol-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let include = root.join("include/rivetlua/lua55");
        let fixture_dir = root.join("tests/p16/acceptance");
        fs::create_dir_all(&include).unwrap();
        fs::create_dir_all(&fixture_dir).unwrap();
        let source = fixture_dir.join("abi001.c");
        let header = include.join("lua.h");
        let library = root.join("librivetlua_capi.a");
        let binary = root.join("driver");
        let build_log = root.join("build.log");
        let staticlib_log = root.join("staticlib-build.log");
        let c_log = root.join("c.log");
        let log = root.join("run.log");
        for (path, content) in [
            (&source, b"int main(void){return 0;}".as_slice()),
            (&header, b"fixed header"),
            (&library, b"archive"),
            (&binary, b"driver"),
        ] {
            fs::write(path, content).unwrap();
        }
        let target = host_target().unwrap();
        fs::write(&staticlib_log, format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"rivetlua_capi\",\"crate_types\":[\"staticlib\"]}},\"filenames\":[{}]}}\nnote: native-static-libs: -lm\nP16_STATICLIB lua55-i64f64 {target} PASS artifact={} native_flags=-lm\n",
            q(&library.display().to_string()), library.display()
        )).unwrap();
        fs::write(
            &build_log,
            format!("P16_BUILD ABI-TEST lua55-i64f64 {target} PASS\n"),
        )
        .unwrap();
        fs::write(
            &c_log,
            "P16_C_BODY ABI-TEST PASS\nP16_ASSERT ABI-TEST stack=PASS\n",
        )
        .unwrap();
        fs::write(&log, format!("P16_CASE ABI-TEST lua55-i64f64 {target} PASS matched=1 passed=1 failed=0 ignored=0\nP16_ASSERT ABI-TEST stack=PASS\n")).unwrap();
        let case_spec = Case {
            id: "ABI-TEST".into(),
            execution_kind: ExecutionKind::CDriver,
            step: "P16-3".into(),
            fixture: "tests/p16/acceptance/abi001.c".into(),
            local_test: String::new(),
            assertions: vec!["stack".into()],
        };
        let manifest = Manifest {
            rows: Vec::new(),
            header_sets: HashMap::from([("lua55".into(), "a".repeat(64))]),
            header_files: HashMap::new(),
        };
        let make_json = |log_hash: String, exit: usize| {
            format!(
                "{{\"id\":\"ABI-TEST\",\"profile\":\"lua55-i64f64\",\"target\":{},\"execution_kind\":\"CDriver\",\"status\":\"PASS\",\"fixture\":\"tests/p16/acceptance/abi001.c\",\"assertions\":[\"stack\"],\"build_command\":[\"cc\",\"-std=c11\",\"-Wall\",\"-Wextra\",\"-Werror\",{}, {}, {}, {},\"-o\",{},\"-lm\"],\"build_exit_code\":0,\"build_signal\":null,\"command\":[{}],\"cwd\":{},\"exit_code\":{exit},\"signal\":null,\"matched\":1,\"passed\":1,\"failed\":0,\"ignored\":0,\"source_path\":{},\"source_sha256\":{},\"upstream_source_path\":null,\"upstream_source_sha256\":null,\"header_path\":{},\"header_sha256\":{},\"header_set_sha256\":{},\"library_path\":{},\"library_sha256\":{},\"staticlib_artifact_path\":{},\"staticlib_artifact_sha256\":{},\"staticlib_build_command\":[\"cargo\",\"rustc\",\"--locked\",\"-p\",\"rivetlua-capi\",\"--lib\",\"--message-format=json-render-diagnostics\",\"--\",\"--print=native-static-libs\"],\"staticlib_build_exit_code\":0,\"staticlib_build_signal\":null,\"staticlib_build_log_path\":{},\"staticlib_build_log_sha256\":{},\"native_static_libs\":[\"-lm\"],\"binary_path\":{},\"binary_sha256\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"c_log_path\":{},\"c_log_sha256\":{},\"log_path\":{},\"log_sha256\":{},\"local_tests\":[],\"local_failure\":null,\"modules\":[],\"package_artifacts\":[]}}",
                q(target),
                q(&format!("-I{}", include.display())),
                q(&format!("-I{}", root.join("include/rivetlua").display())),
                q(&source.display().to_string()),
                q(&library.display().to_string()),
                q(&binary.display().to_string()),
                q(&binary.display().to_string()),
                q(&root.display().to_string()),
                q(&source.display().to_string()),
                q(&sha_file(&source).unwrap()),
                q(&header.display().to_string()),
                q(&sha_file(&header).unwrap()),
                q(&"a".repeat(64)),
                q(&library.display().to_string()),
                q(&sha_file(&library).unwrap()),
                q(&library.display().to_string()),
                q(&sha_file(&library).unwrap()),
                q(&staticlib_log.display().to_string()),
                q(&sha_file(&staticlib_log).unwrap()),
                q(&binary.display().to_string()),
                q(&sha_file(&binary).unwrap()),
                q(&build_log.display().to_string()),
                q(&sha_file(&build_log).unwrap()),
                q(&c_log.display().to_string()),
                q(&sha_file(&c_log).unwrap()),
                q(&log.display().to_string()),
                q(&log_hash)
            )
        };
        let good = StrictJsonParser::parse(&make_json(sha_file(&log).unwrap(), 0)).unwrap();
        assert!(case(&root, &good, &case_spec, "lua55-i64f64", target, &manifest).is_ok());
        let exit = StrictJsonParser::parse(&make_json(sha_file(&log).unwrap(), 2)).unwrap();
        assert!(case(&root, &exit, &case_spec, "lua55-i64f64", target, &manifest).is_err());
        fs::write(&log, format!("P16_CASE ABI-TEST lua55-i64f64 {target} PASS matched=1 passed=1 failed=0 ignored=0\n")).unwrap();
        let no_body = StrictJsonParser::parse(&make_json(sha_file(&log).unwrap(), 0)).unwrap();
        assert!(
            case(
                &root,
                &no_body,
                &case_spec,
                "lua55-i64f64",
                target,
                &manifest
            )
            .is_err()
        );
        fs::write(&header, b"tampered header").unwrap();
        assert!(case(&root, &good, &case_spec, "lua55-i64f64", target, &manifest).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
