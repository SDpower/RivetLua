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

fn assert_fixture_restored_with_cmp(path: &Path, original: &str) {
    assert_eq!(fs::read_to_string(path).unwrap(), original);
    let name = path.file_name().unwrap().to_string_lossy();
    let backup = std::env::temp_dir().join(format!(
        "rivetlua-fixture-backup-{}-{name}",
        std::process::id()
    ));
    fs::write(&backup, original).unwrap();
    let compared = Command::new("cmp")
        .arg("-s")
        .arg(&backup)
        .arg(path)
        .status()
        .unwrap();
    fs::remove_file(backup).unwrap();
    assert!(compared.success(), "cmp -s 未確認 fixture 完整還原");
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

#[test]
fn p06_gate_reports_sixteen_profile_cases_and_passes() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let output = Command::new(BIN)
        .current_dir(workspace_root())
        .args(["gate", "P06"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = workspace_root().join("target/rivetlua-reports/gate-P06.json");
    let parsed = Command::new("python3")
        .args([
            "-c",
            "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='PASS'; cases=[c for c in r['checks'] if c['name'].startswith('HEAP-')]; assert len(cases)==16; assert len({c['name'] for c in cases})==16; reports=[json.load(open(c['report_path'])) for c in cases]; assert all(x['status']=='PASS' and x['input'] and x['actual'] and x['command'] and x['diagnostic'] for x in reports); assert sum(x['profile']=='lua55-i64f64' and x['lua_profile']=='lua55' for x in reports)==8; assert sum(x['profile']=='lua54-i64f64' and x['lua_profile']=='lua54' for x in reports)==8; h=next(x for x in reports if x['case_id']=='HEAP-008'); assert '--doc with_value -- --show-output --test-threads=1' in h['command'] and h['actual'].endswith('with_value doctest 各一個正常與 compile_fail 範例通過'); docs=[c for c in r['checks'] if c['name'].startswith('p06-doctest-')]; assert len(docs)==2 and all(c['status']=='PASS' and '--doc with_value -- --show-output --test-threads=1' in c['command'] and 'compile=1; compile_fail=1' in c['diagnostic'] for c in docs); unit=[c for c in r['checks'] if c['name']=='p06-runtime-unit']; assert len(unit)==1 and 'minimum 17' in unit[0]['diagnostic']",
        ])
        .arg(report)
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "P06 PASS JSON 驗證失敗：{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
}

#[test]
fn p06_missing_duplicate_wrong_profile_and_damaged_fixture_fail_and_restore() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let report_path = root.join("target/rivetlua-reports/gate-P06.json");
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read_to_string(&csv_path).unwrap();
    for mutated in [
        csv_original.replacen("HEAP-001", "HEAP-MISSING", 1),
        csv_original.replacen("HEAP-008", "HEAP-001", 1),
        csv_original.replacen("p06.heap,lua54,", "p06.heap,common,", 1),
    ] {
        let restore = RestoreFixture {
            path: csv_path.clone(),
            contents: csv_original.clone(),
        };
        fs::write(&csv_path, mutated).unwrap();
        let output = Command::new(BIN)
            .current_dir(root)
            .args(["gate", "P06"])
            .output()
            .unwrap();
        drop(restore);
        assert_fixture_restored_with_cmp(&csv_path, &csv_original);
        assert!(!output.status.success());
        assert_gate_report_is_json(&report_path);
    }

    let fixture_path = root.join("tests/p06/heap-cases.fixture");
    let fixture_original = fs::read_to_string(&fixture_path).unwrap();
    let restore = RestoreFixture {
        path: fixture_path.clone(),
        contents: fixture_original.clone(),
    };
    fs::write(
        &fixture_path,
        fixture_original.replace("HEAP-008", "HEAP-BROKEN"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P06"])
        .output()
        .unwrap();
    drop(restore);
    assert_fixture_restored_with_cmp(&fixture_path, &fixture_original);
    assert!(!output.status.success());
    assert_gate_report_is_json(&report_path);
}

#[test]
fn p06_failed_p01_prerequisite_writes_fail_json_and_restores_fixture() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let fixture_path = root.join("tests/p01/fixtures/wrong-num-001.fixture");
    let original = fs::read_to_string(&fixture_path).unwrap();
    let restore = RestoreFixture {
        path: fixture_path.clone(),
        contents: original.clone(),
    };
    fs::write(
        &fixture_path,
        original.replace("expected=-2", "expected=-1"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P06"])
        .output()
        .unwrap();
    drop(restore);
    assert_fixture_restored_with_cmp(&fixture_path, &original);
    assert!(!output.status.success());
    let report_path = root.join("target/rivetlua-reports/gate-P06.json");
    assert_gate_report_is_json(&report_path);
    let report = fs::read_to_string(report_path).unwrap();
    assert!(report.contains("p01-before"));
    assert!(report.contains("FAIL"));
}

fn git_status_snapshot(root: &Path) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "-uall"])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn p07_gate_reports_twenty_profile_cases_and_passes() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let status_before = git_status_snapshot(root);
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P07"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = root.join("target/rivetlua-reports/gate-P07.json");
    let parsed = Command::new("python3")
        .args([
            "-c",
            r#"import json,sys
r=json.load(open(sys.argv[1])); assert r['status']=='PASS'
cases=[c for c in r['checks'] if c['name'].startswith('VM-')]
assert len(cases)==20 and len({c['name'] for c in cases})==20
reports=[json.load(open(c['report_path'])) for c in cases]
assert all(x['status']=='PASS' and x['case_id'] and x['profile'] and x['lua_profile'] and x['mode'] and x['input'] and x['expected'] and x['actual'] and x['command'] and x['exit_code']==0 and x['diagnostic'] for x in reports)
assert sum(x['profile']=='lua55-i64f64' and x['lua_profile']=='lua55' for x in reports)==10
assert sum(x['profile']=='lua54-i64f64' and x['lua_profile']=='lua54' for x in reports)==10
assert {x['case_id'] for x in reports if x['profile']=='lua55-i64f64'}=={f'VM-{i:03}' for i in range(1,11)}
assert all('--test p07_contracts -- --nocapture --test-threads=1' in x['command'] for x in reports)
assert all('fuel_remaining=' in x['actual'] and 'pc=' in x['actual'] for x in reports)
for x in reports:
    if x['case_id'] in ('VM-005','VM-007'):
        assert x['input']=='while true do end' and 'compiler-produced' in x['diagnostic'] and 'implicit terminal Return(Fixed(0))' in x['diagnostic']
        assert 'p05_compiler_used=true' in x['actual'] and 'implicit_return=Fixed(0)' in x['actual']
assert any(c['name']=='p07-runtime-unit' and 'minimum 48' in c['diagnostic'] for c in r['checks'])
assert all(any(c['name']==name and c['status']=='PASS' for c in r['checks']) for name in ('p01-before','p05-before','p06-before','p00-p06-before'))"#,
        ])
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "P07 PASS JSON 驗證失敗：{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    assert_eq!(
        git_status_snapshot(root),
        status_before,
        "P07 gate 造成工作區狀態漂移"
    );
}

#[test]
fn p07_missing_duplicate_wrong_profile_and_corrupt_fixture_fail_json_and_restore() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let report_path = root.join("target/rivetlua-reports/gate-P07.json");
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read_to_string(&csv_path).unwrap();
    let status_original = git_status_snapshot(root);
    for mutated in [
        csv_original.replacen("VM-001", "VM-MISSING", 1),
        csv_original.replacen("VM-010", "VM-001", 1),
        csv_original.replacen("p07.vm,lua54,", "p07.vm,common,", 1),
    ] {
        let restore = RestoreFixture {
            path: csv_path.clone(),
            contents: csv_original.clone(),
        };
        fs::write(&csv_path, mutated).unwrap();
        let output = Command::new(BIN)
            .current_dir(root)
            .args(["gate", "P07"])
            .output()
            .unwrap();
        drop(restore);
        assert_fixture_restored_with_cmp(&csv_path, &csv_original);
        assert_eq!(
            git_status_snapshot(root),
            status_original,
            "P07 CSV 負向注入未恢復工作區狀態"
        );
        assert!(!output.status.success());
        assert_gate_report_is_json(&report_path);
    }

    let fixture_path = root.join("tests/p07/vm-cases.fixture");
    let fixture_original = fs::read_to_string(&fixture_path).unwrap();
    let restore = RestoreFixture {
        path: fixture_path.clone(),
        contents: fixture_original.clone(),
    };
    fs::write(
        &fixture_path,
        fixture_original.replace("VM-010", "VM-BROKEN"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P07"])
        .output()
        .unwrap();
    drop(restore);
    assert_fixture_restored_with_cmp(&fixture_path, &fixture_original);
    assert_eq!(
        git_status_snapshot(root),
        status_original,
        "P07 fixture 損壞注入未恢復工作區狀態"
    );
    assert!(!output.status.success());
    assert_gate_report_is_json(&report_path);
}

#[test]
fn p07_failed_p01_prerequisite_writes_fail_json_and_restores_fixture() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let status_original = git_status_snapshot(root);
    let fixture_path = root.join("tests/p01/fixtures/wrong-num-001.fixture");
    let original = fs::read_to_string(&fixture_path).unwrap();
    let restore = RestoreFixture {
        path: fixture_path.clone(),
        contents: original.clone(),
    };
    fs::write(
        &fixture_path,
        original.replace("expected=-2", "expected=-1"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P07"])
        .output()
        .unwrap();
    drop(restore);
    assert_fixture_restored_with_cmp(&fixture_path, &original);
    assert_eq!(
        git_status_snapshot(root),
        status_original,
        "P01 prerequisite 注入未恢復工作區狀態"
    );
    assert!(!output.status.success());
    let report_path = root.join("target/rivetlua-reports/gate-P07.json");
    assert_gate_report_is_json(&report_path);
    let report = fs::read_to_string(report_path).unwrap();
    assert!(report.contains("p01-before"));
    assert!(report.contains("FAIL"));
}
