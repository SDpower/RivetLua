use super::{manifest, parser, result};
use crate::{StrictJsonParser, StrictJsonValue, root, source_digest};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PROFILES: [&str; 2] = ["lua55-i64f64", "lua54-i64f64"];
const SCHEMA: &str = "rivetlua-p15-basic-v2";
const SCOPE: &str = "oracle-infrastructure";

fn q(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(StrictJsonValue::as_str)
        .ok_or_else(|| format!("P15 report 缺少字串欄位 {name}"))
}

fn exact(value: &StrictJsonValue, name: &str, expected: &str) -> Result<(), String> {
    let actual = field(value, name)?;
    if actual != expected {
        return Err(format!("P15 report {name} 不符：{actual:?}"));
    }
    Ok(())
}

fn digest(value: &str, name: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("P15 report {name} 不是 SHA-256"));
    }
    Ok(())
}

fn command(value: &StrictJsonValue, binary: &str) -> Result<(), String> {
    let values = value.as_array().ok_or("P15 report command 不是陣列")?;
    if values.len() != 3
        || values[0].as_str() != Some(binary)
        || values[1].as_str() != Some("-e_U=true")
        || values[2].as_str() != Some("all.lua")
    {
        return Err("P15 report command 不符".into());
    }
    Ok(())
}

fn nonnegative_integer(value: &StrictJsonValue, name: &str) -> Result<(), String> {
    let Some(StrictJsonValue::Number(number)) = value.get(name) else {
        return Err(format!("P15 report {name} 缺少整數"));
    };
    if number.parse::<u128>().is_err() {
        return Err(format!("P15 report {name} 不是非負整數"));
    }
    Ok(())
}

fn observed(root: &Path, profile: &str, current_digest: &str) -> Result<String, String> {
    let path = result::report_path(root, profile);
    let text = fs::read_to_string(&path).map_err(|error| {
        format!(
            "P15 {profile} report 缺失或不可讀 {}：{error}",
            path.display()
        )
    })?;
    let report = StrictJsonParser::parse(&text)
        .map_err(|error| format!("P15 {profile} report JSON 無效：{error}"))?;
    let source = manifest::source(root, profile)?;
    manifest::verify_archive(root, &source)?;
    for (name, expected) in [
        ("schema", SCHEMA),
        ("status", "PASS"),
        ("scope", SCOPE),
        ("runner_status", "PASS"),
        ("profile", profile),
        ("mode", "basic"),
        ("source_digest", current_digest),
    ] {
        exact(&report, name, expected)?;
    }
    exact(&report, "report_path", &path.display().to_string())?;
    let compatibility = field(&report, "basic_compatibility_status")?;
    if !matches!(compatibility, "FAIL" | "INCOMPLETE") {
        return Err(format!("P15 {profile} Basic 狀態無效：{compatibility}"));
    }

    let manifest = report.get("manifest").ok_or("P15 report 缺 manifest")?;
    let expected_binary = root
        .join("target/rivetlua-p15")
        .join(format!("build-{profile}/debug/rivetlua"));
    let binary = fs::canonicalize(&expected_binary)
        .map_err(|error| format!("P15 {profile} binary 不可讀：{error}"))?;
    let binary_text = binary.display().to_string();
    let version_output = Command::new(&binary)
        .arg("-v")
        .output()
        .map_err(|error| format!("P15 {profile} binary -v 啟動失敗：{error}"))?;
    let actual_version = format!(
        "{}{}",
        String::from_utf8_lossy(&version_output.stdout),
        String::from_utf8_lossy(&version_output.stderr)
    );
    if !version_output.status.success() || actual_version.trim() != source.version {
        return Err(format!("P15 {profile} binary -v 身分不符"));
    }
    let expected_suite = Path::new(source.suite)
        .file_name()
        .ok_or("P15 suite 名稱缺失")?;
    let cwd_text = field(&report, "cwd")?;
    let cwd = PathBuf::from(cwd_text);
    let work = cwd.parent().ok_or("P15 report cwd 沒有 work 目錄")?;
    let work_name = work
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !cwd.is_absolute()
        || cwd.file_name() != Some(expected_suite)
        || !work_name.starts_with(&format!("work-{profile}-"))
        || work.parent() != Some(root.join("target/rivetlua-p15").as_path())
    {
        return Err("P15 report cwd 不符".into());
    }
    let map = manifest::file_map(&cwd)?;
    let tree = manifest::tree_sha(&map)?;
    let canonical = manifest::file_map(&root.join(source.suite))?;
    if map != canonical {
        return Err(format!("P15 {profile} report suite tree 與官方來源不符"));
    }

    for (name, expected) in [
        ("profile", profile),
        ("mode", "basic"),
        ("release", source.release),
        ("source_url", source.url),
        ("tarball", &root.join(source.tarball).display().to_string()),
        ("tarball_sha256", source.tarball_sha256),
        ("all_lua_sha256", source.all_lua_sha256),
        ("suite_tree_sha256", &tree),
        ("binary_path", &binary_text),
        ("binary_version", source.version),
        ("features", source.feature),
        ("runner_version", "p15-basic-v2"),
        ("cwd", cwd_text),
    ] {
        exact(manifest, name, expected)?;
    }
    let binary_sha = field(manifest, "binary_sha256")?;
    digest(binary_sha, "binary_sha256")?;
    if manifest::sha256(&binary)? != binary_sha {
        return Err(format!("P15 {profile} binary SHA-256 已變更"));
    }
    let command_value = report.get("command").ok_or("P15 report 缺 command")?;
    command(command_value, &binary_text)?;
    command(
        manifest.get("command").ok_or("P15 manifest 缺 command")?,
        &binary_text,
    )?;
    nonnegative_integer(manifest, "verified_at_unix_seconds")?;
    nonnegative_integer(&report, "elapsed_ms")?;

    let stdout_path = work.join("stdout.raw");
    let stderr_path = work.join("stderr.raw");
    exact(&report, "stdout_path", &stdout_path.display().to_string())?;
    exact(&report, "stderr_path", &stderr_path.display().to_string())?;
    let stdout =
        fs::read(&stdout_path).map_err(|error| format!("P15 stdout log 不可讀：{error}"))?;
    let stderr =
        fs::read(&stderr_path).map_err(|error| format!("P15 stderr log 不可讀：{error}"))?;
    exact(&report, "stdout", &String::from_utf8_lossy(&stdout))?;
    exact(&report, "stderr", &String::from_utf8_lossy(&stderr))?;
    let exit_code = match report.get("exit_code") {
        Some(StrictJsonValue::Null) => None,
        Some(value) => Some(value.as_i32().ok_or("P15 report exit_code 無效")?),
        None => return Err("P15 report 缺 exit_code".into()),
    };
    let parsed = parser::parse(&stdout, &stderr, exit_code);
    let expected_compatibility = if parsed.provisional_pass {
        "INCOMPLETE"
    } else {
        "FAIL"
    };
    exact(
        &report,
        "runner_observation",
        if parsed.provisional_pass {
            "PROVISIONAL_PASS"
        } else {
            "FAIL"
        },
    )?;
    if field(&report, "diagnostic")?.is_empty() {
        return Err("P15 report diagnostic 為空".into());
    }
    if compatibility != expected_compatibility {
        return Err(format!("P15 {profile} Basic 狀態與 logs 不符"));
    }
    for (name, expected) in [
        ("assertion_count", parsed.assertion_count),
        ("panic_count", parsed.panic_count),
        ("crash_count", parsed.crash_count),
        ("error_count", parsed.error_count),
    ] {
        let actual = report.get(name).and_then(StrictJsonValue::as_i32);
        if actual != i32::try_from(expected).ok() {
            return Err(format!("P15 report {name} 與 logs 不符"));
        }
    }
    for (name, expected) in [
        ("final_ok", parsed.final_ok),
        ("starting_tests", parsed.starting_tests),
    ] {
        if report.get(name) != Some(&StrictJsonValue::Bool(expected)) {
            return Err(format!("P15 report {name} 與 logs 不符"));
        }
    }
    let skips = report
        .get("skip_messages")
        .and_then(StrictJsonValue::as_array)
        .ok_or("P15 report skip_messages 無效")?;
    if skips.len() != parsed.skip_messages.len()
        || skips
            .iter()
            .zip(&parsed.skip_messages)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err("P15 report skip_messages 與 logs 不符".into());
    }
    let deferred = report
        .get("deferred_checks")
        .and_then(StrictJsonValue::as_array)
        .ok_or("P15 report 缺 deferred_checks")?;
    if deferred.len() != 2
        || deferred[0].as_str() != Some("_U skip trace/coverage")
        || deferred[1].as_str() != Some("production arithmetic injection")
    {
        return Err("P15 report deferred_checks 不符".into());
    }
    Ok(compatibility.to_owned())
}

fn report_path(root: &Path) -> PathBuf {
    root.join("target/rivetlua-reports/gate-P15.json")
}

fn write(root: &Path, value: &str) -> Result<(), String> {
    let path = report_path(root);
    fs::create_dir_all(path.parent().ok_or("P15 gate report 無父目錄")?)
        .map_err(|error| format!("建立 P15 gate report 目錄失敗：{error}"))?;
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&temporary, value).map_err(|error| format!("寫入 P15 gate report 失敗：{error}"))?;
    fs::rename(&temporary, &path).map_err(|error| format!("提交 P15 gate report 失敗：{error}"))
}

fn run(root: &Path) -> Result<(), String> {
    let digest = source_digest(root)?;
    let mut statuses = Vec::new();
    for profile in PROFILES {
        statuses.push((profile, observed(root, profile, &digest)?));
    }
    if source_digest(root)? != digest {
        return Err("P15 gate 執行期間 repository 來源已變更".into());
    }
    let checks = statuses
        .iter()
        .map(|(profile, status)| {
            let path = result::report_path(root, profile);
            format!(
                "{{\"name\":{},\"status\":\"PASS\",\"command\":{},\"report_path\":{},\"basic_compatibility_status\":{}}}",
                q(&format!("p15-observation-{profile}")),
                q(&format!("validate {}", path.display())),
                q(&path.display().to_string()),
                q(status)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let value = format!(
        "{{\"schema\":\"rivetlua-p15-gate-v2\",\"status\":\"PASS\",\"scope\":\"oracle-infrastructure\",\"source_digest\":{},\"basic_compatibility_status\":{{{}:{},{}:{}}},\"checks\":[{}],\"report_path\":{}}}\n",
        q(&digest),
        q(statuses[0].0),
        q(&statuses[0].1),
        q(statuses[1].0),
        q(&statuses[1].1),
        checks,
        q(&report_path(root).display().to_string())
    );
    write(root, &value)?;
    println!(
        "oracle infrastructure PASS；Basic {}={}、{}={}；report={}",
        statuses[0].0,
        statuses[0].1,
        statuses[1].0,
        statuses[1].1,
        report_path(root).display()
    );
    Ok(())
}

pub(super) fn gate() -> Result<(), String> {
    let root = root()?;
    let path = report_path(&root);
    if path.exists() {
        fs::remove_file(&path).map_err(|error| format!("清除舊 P15 gate report 失敗：{error}"))?;
    }
    match run(&root) {
        Ok(()) => Ok(()),
        Err(error) => {
            let digest = source_digest(&root).ok();
            let value = format!(
                "{{\"schema\":\"rivetlua-p15-gate-v2\",\"status\":\"FAIL\",\"scope\":\"oracle-infrastructure\",\"source_digest\":{},\"diagnostic\":{},\"checks\":[],\"report_path\":{}}}\n",
                digest.as_deref().map(q).unwrap_or_else(|| "null".into()),
                q(&error),
                q(&path.display().to_string())
            );
            write(&root, &value)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p15::result::RunReport;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn p15_gate_accepts_two_observations_and_rejects_changed_evidence() {
        let real = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let scratch =
            std::env::temp_dir().join(format!("rivetlua-p15-gate-valid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("tests/p15")).unwrap();
        fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
        fs::write(scratch.join(".gitignore"), b"target/\n").unwrap();
        fs::copy(
            real.join("tests/p15/runner-manifest.toml"),
            scratch.join("tests/p15/runner-manifest.toml"),
        )
        .unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(&scratch)
                .status()
                .unwrap()
                .success()
        );
        for profile in PROFILES {
            let source = manifest::source(real, profile).unwrap();
            let vendor = scratch.join(source.tarball).parent().unwrap().to_path_buf();
            fs::create_dir_all(&vendor).unwrap();
            fs::copy(real.join(source.tarball), scratch.join(source.tarball)).unwrap();
            assert!(
                Command::new("tar")
                    .arg("-xzf")
                    .arg(scratch.join(source.tarball))
                    .arg("-C")
                    .arg(&vendor)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let digest = source_digest(&scratch).unwrap();
        for profile in PROFILES {
            let source = manifest::source(&scratch, profile).unwrap();
            let work = scratch.join(format!("target/rivetlua-p15/work-{profile}-test"));
            let (suite, _, tree) = manifest::prepare(&scratch, &source, &work).unwrap();
            let binary = scratch.join(format!(
                "target/rivetlua-p15/build-{profile}/debug/rivetlua"
            ));
            fs::create_dir_all(binary.parent().unwrap()).unwrap();
            fs::write(
                &binary,
                format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", source.version),
            )
            .unwrap();
            let mut permissions = fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&binary, permissions).unwrap();
            let binary = fs::canonicalize(binary).unwrap();
            let stdout = if profile == "lua55-i64f64" {
                b"Starting Tests\nerror: suite failure\n".as_slice()
            } else {
                b"Starting Tests\nfinal OK !!!\n".as_slice()
            };
            let exit = if profile == "lua55-i64f64" {
                Some(1)
            } else {
                Some(0)
            };
            let stdout_path = work.join("stdout.raw");
            let stderr_path = work.join("stderr.raw");
            fs::write(&stdout_path, stdout).unwrap();
            fs::write(&stderr_path, b"").unwrap();
            let parsed = parser::parse(stdout, b"", exit);
            result::run(&RunReport {
                root: &scratch,
                source: &source,
                binary: &binary,
                binary_sha256: &manifest::sha256(&binary).unwrap(),
                version: source.version,
                suite: &suite,
                tree_sha256: &tree,
                stdout_path: &stdout_path,
                stderr_path: &stderr_path,
                stdout,
                stderr: b"",
                exit_code: exit,
                elapsed_ms: 1,
                parsed: &parsed,
                diagnostic: "isolated observation",
                source_digest: &digest,
                infrastructure_ok: true,
            })
            .unwrap();
        }
        run(&scratch).unwrap();
        let gate = fs::read_to_string(report_path(&scratch)).unwrap();
        assert!(gate.contains("\"status\":\"PASS\""));
        assert!(gate.contains("\"lua55-i64f64\":\"FAIL\""));
        assert!(gate.contains("\"lua54-i64f64\":\"INCOMPLETE\""));

        let path = result::report_path(&scratch, "lua55-i64f64");
        let original = fs::read_to_string(&path).unwrap();
        for (from, to) in [
            ("\"source_digest\":\"", "\"source_digest\":\"bad"),
            ("\"status\":\"PASS\"", "\"status\":\"FAIL\""),
            ("\"scope\":\"oracle-infrastructure\"", "\"scope\":\"Basic\""),
            (
                "\"profile\":\"lua55-i64f64\"",
                "\"profile\":\"lua54-i64f64\"",
            ),
            ("\"-e_U=true\"", "\"-e_U=false\""),
        ] {
            fs::write(&path, original.replacen(from, to, 1)).unwrap();
            assert!(run(&scratch).is_err(), "P15 gate 接受了篡改：{from}");
        }
        fs::write(&path, b"{malformed").unwrap();
        assert!(run(&scratch).is_err());
        fs::remove_file(&path).unwrap();
        assert!(run(&scratch).is_err());
        let _ = fs::remove_dir_all(&scratch);
    }
}
