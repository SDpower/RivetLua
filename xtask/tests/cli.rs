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
