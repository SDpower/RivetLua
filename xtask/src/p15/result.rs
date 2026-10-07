use super::manifest::Source;
use super::parser::Parsed;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn q(value: &str) -> String {
    format!("\"{}\"", super::super::json_escape(value))
}

pub(super) fn report_path(root: &Path, profile: &str) -> PathBuf {
    let profile = match profile {
        "lua55-i64f64" => "lua55-i64f64",
        "lua54-i64f64" => "lua54-i64f64",
        _ => "invalid",
    };
    root.join("target/rivetlua-reports")
        .join(format!("P15-basic-{profile}.json"))
}

fn write(path: &Path, value: &str) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("P15 report 沒有父目錄")?)
        .map_err(|error| format!("建立 P15 report 目錄失敗：{error}"))?;
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&temporary, value).map_err(|error| format!("寫入 P15 report 失敗：{error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("提交 P15 report 失敗：{error}"))
}

pub(super) fn early_failure(
    root: &Path,
    profile: &str,
    diagnostic: &str,
) -> Result<PathBuf, String> {
    let path = report_path(root, profile);
    let value = format!(
        "{{\"schema\":\"rivetlua-p15-basic-v2\",\"status\":\"FAIL\",\"scope\":\"oracle-infrastructure\",\"runner_status\":\"FAIL\",\"basic_compatibility_status\":\"INCOMPLETE\",\"profile\":{},\"mode\":\"basic\",\"diagnostic\":{},\"manifest\":null,\"command\":null,\"cwd\":null,\"exit_code\":null,\"stdout_path\":null,\"stderr_path\":null,\"stdout\":null,\"stderr\":null,\"assertion_count\":null,\"panic_count\":null,\"crash_count\":null,\"error_count\":null,\"skip_messages\":null,\"final_ok\":false,\"starting_tests\":false,\"source_digest\":null,\"report_path\":{},\"deferred_checks\":[\"_U skip trace/coverage\",\"production arithmetic injection\"]}}\n",
        q(profile),
        q(diagnostic),
        q(&path.display().to_string())
    );
    write(&path, &value)?;
    Ok(path)
}

pub(super) struct RunReport<'a> {
    pub root: &'a Path,
    pub source: &'a Source,
    pub binary: &'a Path,
    pub binary_sha256: &'a str,
    pub version: &'a str,
    pub suite: &'a Path,
    pub tree_sha256: &'a str,
    pub stdout_path: &'a Path,
    pub stderr_path: &'a Path,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub exit_code: Option<i32>,
    pub elapsed_ms: u128,
    pub parsed: &'a Parsed,
    pub diagnostic: &'a str,
    pub source_digest: &'a str,
    pub infrastructure_ok: bool,
}

fn environment_json_from(mut values: Vec<(String, String)>) -> String {
    values.sort();
    let mut public = Vec::new();
    let mut other_names = Vec::new();
    for (key, value) in &values {
        if key == "PATH" || key == "LANG" || key.starts_with("LC_") || key.starts_with("LUA_") {
            public.push(format!(
                "{}:{{\"value\":{},\"source\":\"inherited\"}}",
                q(key),
                q(value)
            ));
        } else {
            other_names.push(q(key));
        }
    }
    format!(
        "{{\"public_values\":{{{}}},\"other_names\":[{}]}}",
        public.join(","),
        other_names.join(",")
    )
}

fn environment_json() -> String {
    let values = env::vars_os()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    environment_json_from(values)
}

#[cfg(test)]
mod tests {
    #[test]
    fn p15_environment_records_public_settings_without_secret_values() {
        let json = super::environment_json_from(vec![
            ("PATH".into(), "/usr/bin".into()),
            ("LUA_PATH".into(), "./?.lua".into()),
            ("SECRET_TOKEN".into(), "redact-me".into()),
        ]);
        assert!(json.contains("/usr/bin"));
        assert!(json.contains("./?.lua"));
        assert!(json.contains("SECRET_TOKEN"));
        assert!(!json.contains("redact-me"));
    }

    #[test]
    fn p15_observation_keeps_child_failure_separate_from_runner_success() {
        use super::{RunReport, run};
        use crate::p15::{manifest, parser};
        use std::fs;
        use std::path::Path;
        use std::process::Command;

        let real = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let source = manifest::source(real, "lua55-i64f64").unwrap();
        let scratch =
            std::env::temp_dir().join(format!("rivetlua-p15-observation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
        assert!(
            Command::new("git")
                .arg("init")
                .arg("-q")
                .current_dir(&scratch)
                .status()
                .unwrap()
                .success()
        );
        for (stdout, exit, expected) in [
            (
                b"Starting Tests\nerror: suite failure\n".as_slice(),
                Some(1),
                "FAIL",
            ),
            (
                b"Starting Tests\nfinal OK !!!\n".as_slice(),
                Some(0),
                "INCOMPLETE",
            ),
        ] {
            let parsed = parser::parse(stdout, b"", exit);
            let path = run(&RunReport {
                root: &scratch,
                source: &source,
                binary: Path::new("/tmp/rivetlua-test-binary"),
                binary_sha256: &"a".repeat(64),
                version: source.version,
                suite: Path::new("/tmp/rivetlua-test-suite"),
                tree_sha256: &"b".repeat(64),
                stdout_path: Path::new("/tmp/rivetlua-test-stdout"),
                stderr_path: Path::new("/tmp/rivetlua-test-stderr"),
                stdout,
                stderr: b"",
                exit_code: exit,
                elapsed_ms: 1,
                parsed: &parsed,
                diagnostic: "test observation",
                source_digest: &crate::source_digest(&scratch).unwrap(),
                infrastructure_ok: true,
            })
            .unwrap();
            let value = fs::read_to_string(path).unwrap();
            assert!(value.contains("\"schema\":\"rivetlua-p15-basic-v2\""));
            assert!(value.contains("\"scope\":\"oracle-infrastructure\""));
            assert!(value.contains("\"runner_status\":\"PASS\""));
            assert!(value.contains("\"status\":\"PASS\""));
            assert!(value.contains(&format!("\"basic_compatibility_status\":\"{expected}\"")));
        }
        let _ = fs::remove_dir_all(&scratch);
    }
}

pub(super) fn run(report: &RunReport<'_>) -> Result<PathBuf, String> {
    let path = report_path(report.root, report.source.profile);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let manifest = format!(
        "{{\"release\":{},\"profile\":{},\"mode\":\"basic\",\"source_url\":{},\"source_recorded_date\":\"2026-09-21\",\"tarball\":{},\"tarball_sha256\":{},\"all_lua_sha256\":{},\"suite_tree_sha256\":{},\"binary_path\":{},\"binary_sha256\":{},\"binary_version\":{},\"features\":{},\"runner_version\":\"p15-basic-v2\",\"verified_at_unix_seconds\":{},\"command\":[{},\"-e_U=true\",\"all.lua\"],\"cwd\":{},\"environment_inherited\":{}}}",
        q(report.source.release),
        q(report.source.profile),
        q(report.source.url),
        q(&report
            .root
            .join(report.source.tarball)
            .display()
            .to_string()),
        q(report.source.tarball_sha256),
        q(report.source.all_lua_sha256),
        q(report.tree_sha256),
        q(&report.binary.display().to_string()),
        q(report.binary_sha256),
        q(report.version),
        q(report.source.feature),
        now,
        q(&report.binary.display().to_string()),
        q(&report.suite.display().to_string()),
        environment_json(),
    );
    let skip_json = report
        .parsed
        .skip_messages
        .iter()
        .map(|item| q(item))
        .collect::<Vec<_>>()
        .join(",");
    let exit = report
        .exit_code
        .map_or("null".into(), |value| value.to_string());
    let runner_status = if report.infrastructure_ok {
        "PASS"
    } else {
        "FAIL"
    };
    let compatibility = if report.parsed.provisional_pass {
        "INCOMPLETE"
    } else {
        "FAIL"
    };
    let value = format!(
        "{{\"schema\":\"rivetlua-p15-basic-v2\",\"status\":{},\"scope\":\"oracle-infrastructure\",\"runner_status\":{},\"basic_compatibility_status\":{},\"runner_observation\":{},\"profile\":{},\"mode\":\"basic\",\"diagnostic\":{},\"manifest\":{},\"command\":[{},\"-e_U=true\",\"all.lua\"],\"cwd\":{},\"exit_code\":{},\"stdout_path\":{},\"stderr_path\":{},\"stdout\":{},\"stderr\":{},\"assertion_count\":{},\"panic_count\":{},\"crash_count\":{},\"error_count\":{},\"skip_messages\":[{}],\"final_ok\":{},\"starting_tests\":{},\"elapsed_ms\":{},\"executed_count\":null,\"skipped_count\":null,\"trace_reference\":null,\"local_regressions\":null,\"negative_control\":null,\"deferred_checks\":[\"_U skip trace/coverage\",\"production arithmetic injection\"],\"source_digest\":{},\"report_path\":{}}}\n",
        q(runner_status),
        q(runner_status),
        q(compatibility),
        q(if report.parsed.provisional_pass {
            "PROVISIONAL_PASS"
        } else {
            "FAIL"
        }),
        q(report.source.profile),
        q(report.diagnostic),
        manifest,
        q(&report.binary.display().to_string()),
        q(&report.suite.display().to_string()),
        exit,
        q(&report.stdout_path.display().to_string()),
        q(&report.stderr_path.display().to_string()),
        q(&String::from_utf8_lossy(report.stdout)),
        q(&String::from_utf8_lossy(report.stderr)),
        report.parsed.assertion_count,
        report.parsed.panic_count,
        report.parsed.crash_count,
        report.parsed.error_count,
        skip_json,
        report.parsed.final_ok,
        report.parsed.starting_tests,
        report.elapsed_ms,
        q(report.source_digest),
        q(&path.display().to_string()),
    );
    write(&path, &value)?;
    Ok(path)
}
