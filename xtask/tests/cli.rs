use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_rivetlua-xtask");
static CLI_TEST_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

struct RestoreFixture {
    path: PathBuf,
    contents: String,
}

impl Drop for RestoreFixture {
    fn drop(&mut self) {
        fs::write(&self.path, &self.contents).unwrap();
    }
}

fn assert_report_is_json(path: &Path, expected_case: &str, expected_status: &str) {
    let output = Command::new("python3")
        .args([
            "-c",
            r#"import json, sys
with open(sys.argv[1], encoding='utf-8') as report_file:
    report = json.load(report_file)
required = {'case_id', 'lua_profile', 'mode', 'status', 'command', 'exit_code', 'reference_version', 'source_sha256', 'report_path', 'diagnostic'}
missing = required.difference(report)
if missing:
    raise SystemExit('missing fields: ' + ', '.join(sorted(missing)))
if report['case_id'] != sys.argv[2]:
    raise SystemExit('unexpected case: ' + report['case_id'])
if report['status'] != sys.argv[3]:
    raise SystemExit('unexpected status: ' + report['status'])
if not isinstance(report['diagnostic'], str):
    raise SystemExit('diagnostic is not a string')"#,
        ])
        .arg(path)
        .arg(expected_case)
        .arg(expected_status)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "JSON report validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_gate_report_is_json(path: &Path) {
    let output = Command::new("python3")
        .args([
            "-c",
            r#"import json, sys
with open(sys.argv[1], encoding='utf-8') as report_file:
    report = json.load(report_file)
if report.get('status') != 'FAIL':
    raise SystemExit('gate status is not FAIL')
checks = report.get('checks')
if not isinstance(checks, list) or not checks:
    raise SystemExit('missing checks')
if not any(check.get('status') == 'FAIL' and isinstance(check.get('diagnostic'), str) for check in checks):
    raise SystemExit('missing FAIL diagnostic')"#,
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gate JSON report validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn toolchain_command_succeeds() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .arg("toolchain")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("msrv=1.94.1"));
    assert!(stdout.contains("actual=rustc "));
}

#[test]
fn normal_and_version_failure_reports_parse_as_json() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let normal = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["runner", "--profile", "lua55", "--case", "P00-RUN-001"])
        .output()
        .unwrap();
    assert!(normal.status.success());
    assert_report_is_json(
        &workspace_root().join("target/rivetlua-reports/P00-RUN-001-lua55.json"),
        "P00-RUN-001",
        "PASS",
    );

    let version_failure = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["runner", "--profile", "lua55", "--case", "P00-REF-003"])
        .output()
        .unwrap();
    assert!(!version_failure.status.success());
    assert_report_is_json(
        &workspace_root().join("target/rivetlua-reports/P00-REF-003-lua55.json"),
        "P00-REF-003",
        "FAIL",
    );
}

#[test]
fn parallel_normal_and_wrong_version_do_not_share_verify_directory() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let normal = std::thread::spawn(|| {
        Command::new(BIN)
            .current_dir(workspace_root())
            .args(["runner", "--profile", "lua55", "--case", "P00-RUN-001"])
            .output()
            .unwrap()
    });
    let wrong = std::thread::spawn(|| {
        Command::new(BIN)
            .current_dir(workspace_root())
            .args(["runner", "--profile", "lua55", "--case", "P00-REF-003"])
            .output()
            .unwrap()
    });
    let normal = normal.join().unwrap();
    assert!(
        normal.status.success(),
        "{}",
        String::from_utf8_lossy(&normal.stderr)
    );
    let wrong = wrong.join().unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("參考程式版本不符"));
}

#[test]
fn failing_gate_keeps_parseable_accumulated_report() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let fixture = workspace_root().join("tests/p00/fixtures/normal.fixture");
    let original = fs::read_to_string(&fixture).unwrap();
    let _restore = RestoreFixture {
        path: fixture.clone(),
        contents: original.clone(),
    };
    fs::write(
        &fixture,
        original.replace(
            "expected_output=reference-ok",
            "expected_output=deliberate-failure",
        ),
    )
    .unwrap();

    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P00"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_gate_report_is_json(&workspace_root().join("target/rivetlua-reports/gate-P00.json"));
}

#[test]
fn wrong_num_fixture_makes_p01_gate_fail_and_restores_it() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let fixture = workspace_root().join("tests/p01/fixtures/wrong-num-001.fixture");
    let original = fs::read_to_string(&fixture).unwrap();
    let _restore = RestoreFixture {
        path: fixture.clone(),
        contents: original.clone(),
    };
    fs::write(&fixture, original.replace("expected=-2", "expected=-1")).unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P01"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report =
        fs::read_to_string(workspace_root().join("target/rivetlua-reports/gate-P01.json")).unwrap();
    assert!(report.contains("P01-NUM-NEG-001"));
    Command::new("python3")
        .args(["-c", "import json,sys; json.load(open(sys.argv[1]))"])
        .arg(workspace_root().join("target/rivetlua-reports/gate-P01.json"))
        .status()
        .unwrap();
}

#[test]
fn p02_gate_succeeds_and_writes_json_report() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P02"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = workspace_root().join("target/rivetlua-reports/gate-P02.json");
    let parsed = Command::new("python3")
        .args([
            "-c",
            "import json,sys; report=json.load(open(sys.argv[1])); assert report['status'] == 'PASS'; assert any(check['name'] == 'p02-strict-reference' for check in report['checks'])",
        ])
        .arg(report)
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
}

#[test]
fn wrong_long_delimiter_fixture_makes_p02_gate_fail_and_restores_it() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let fixture = workspace_root().join("tests/p02/fixtures/wrong-long-delimiter.fixture");
    let original = fs::read_to_string(&fixture).unwrap();
    let _restore = RestoreFixture {
        path: fixture.clone(),
        contents: original.clone(),
    };
    fs::write(
        &fixture,
        original.replace("expected=E_LEX", "expected=String"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P02"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report =
        fs::read_to_string(workspace_root().join("target/rivetlua-reports/gate-P02.json")).unwrap();
    assert!(report.contains("P02-LONG-NEG-001"));
    assert_gate_report_is_json(&workspace_root().join("target/rivetlua-reports/gate-P02.json"));
}

#[test]
fn p02_missing_case_and_wrong_profile_make_gate_fail_with_json() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let csv = workspace_root().join("spec/compatibility.csv");
    let original = fs::read_to_string(&csv).unwrap();
    let _restore = RestoreFixture {
        path: csv.clone(),
        contents: original.clone(),
    };
    fs::write(&csv, original.replacen("LEX-ERR-004", "LEX-MISSING-004", 1)).unwrap();
    let missing_case = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P02"])
        .output()
        .unwrap();
    assert!(!missing_case.status.success());
    let report_path = workspace_root().join("target/rivetlua-reports/gate-P02.json");
    assert_gate_report_is_json(&report_path);
    assert!(
        fs::read_to_string(&report_path)
            .unwrap()
            .contains("p02-csv")
    );

    fs::write(
        &csv,
        original.replacen("p02.lexer,lua55,", "p02.lexer,common,", 1),
    )
    .unwrap();
    let wrong_profile = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P02"])
        .output()
        .unwrap();
    assert!(!wrong_profile.status.success());
    assert_gate_report_is_json(&report_path);
    assert!(
        fs::read_to_string(&report_path)
            .unwrap()
            .contains("p02-csv")
    );
}

#[test]
fn oversized_token_fixture_makes_p02_gate_fail_and_restores_it() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let fixture = workspace_root().join("tests/p02/fixtures/oversized-token.fixture");
    let original = fs::read_to_string(&fixture).unwrap();
    let _restore = RestoreFixture {
        path: fixture.clone(),
        contents: original.clone(),
    };
    fs::write(
        &fixture,
        original.replace("expected=E_COMPILE_LIMIT", "expected=PASS"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P02"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report_path = workspace_root().join("target/rivetlua-reports/gate-P02.json");
    assert_gate_report_is_json(&report_path);
    assert!(
        fs::read_to_string(&report_path)
            .unwrap()
            .contains("P02-LIMIT-NEG-001")
    );
}
