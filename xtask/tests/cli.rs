use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_rivetlua-xtask");
static CLI_TEST_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn current_source_digest(root: &Path) -> String {
    let script = r#"import hashlib,os,subprocess,sys
root=sys.argv[1]; cwd=os.fsencode(root)
paths=sorted(set(filter(None,subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).split(b'\0'))))
h=hashlib.sha256(); h.update(b'RivetLua-source-digest-v1\0')
for name in paths:
    path=os.path.join(cwd,name)
    h.update(len(name).to_bytes(8,'big')); h.update(name)
    if not os.path.lexists(path): h.update(b'M')
    elif os.path.islink(path):
        data=os.readlink(path); data=os.fsencode(data); h.update(b'L'); h.update(len(data).to_bytes(8,'big')); h.update(data)
    elif os.path.isfile(path):
        data=open(path,'rb').read(); h.update(b'F'); h.update(len(data).to_bytes(8,'big')); h.update(data)
    elif os.path.isdir(path): h.update(b'D')
    else: h.update(b'O')
print(h.hexdigest())
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "測試來源 digest 計算失敗：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn ensure_prerequisite_reports(root: &Path, through: &str) {
    let report_dir = root.join("target/rivetlua-reports");
    fs::create_dir_all(&report_dir).unwrap();
    let digest = current_source_digest(root);
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); last=int(sys.argv[2][1:]); digest=sys.argv[3]
for phase in range(last+1):
    path=root/'target/rivetlua-reports'/f'gate-P{phase:02}.json'
    try: report=json.loads(path.read_bytes())
    except (OSError,ValueError,UnicodeError): report=None
    checks=report.get('checks') if isinstance(report,dict) else None
    valid=(isinstance(report,dict) and report.get('status')=='PASS'
           and report.get('source_digest')==digest
           and isinstance(checks,list) and bool(checks))
    if valid:
        valid=all(isinstance(check,dict)
                  and isinstance(check.get('name'),str) and check['name'].strip()
                  and isinstance(check.get('command'),str) and check['command'].strip()
                  and type(check.get('exit_code')) is int and check['exit_code']==0
                  and check.get('status')=='PASS'
                  and isinstance(check.get('diagnostic'),str) and check['diagnostic'].strip()
                  and isinstance(check.get('report_path'),str) and check['report_path'].strip()
                  for check in checks)
    if valid and phase==7:
        valid=all(sum(check['name']==name for check in checks)==1 for name in
                  ('p01-before','p05-before','p06-before','p00-p06-before'))
    if not valid: print(f'P{phase:02}')
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(through)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "前置 gate 報告檢查失敗：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for phase in String::from_utf8(output.stdout).unwrap().lines() {
        let gate = Command::new(BIN)
            .current_dir(root)
            .args(["gate", phase])
            .output()
            .unwrap();
        assert!(
            gate.status.success(),
            "重建 {phase} 前置 gate 失敗：stdout={} stderr={}",
            String::from_utf8_lossy(&gate.stdout),
            String::from_utf8_lossy(&gate.stderr)
        );
    }
}

fn ensure_p12_prerequisite_reports(root: &Path) {
    let report_dir = root.join("target/rivetlua-reports");
    fs::create_dir_all(&report_dir).unwrap();
    let digest = current_source_digest(root);
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); last=11; digest=sys.argv[2]
for phase in range(last+1):
    path=root/'target/rivetlua-reports'/f'gate-P{phase:02}.json'
    try: report=json.loads(path.read_bytes())
    except (OSError,ValueError,UnicodeError): report=None
    checks=report.get('checks') if isinstance(report,dict) else None
    valid=(isinstance(report,dict) and report.get('status')=='PASS'
           and report.get('source_digest')==digest
           and isinstance(checks,list) and bool(checks))
    if valid:
        valid=all(isinstance(check,dict)
                  and isinstance(check.get('name'),str) and check['name'].strip()
                  and isinstance(check.get('command'),str) and check['command'].strip()
                  and type(check.get('exit_code')) is int
                  and check.get('status')=='PASS'
                  and isinstance(check.get('diagnostic'),str) and check['diagnostic'].strip()
                  and isinstance(check.get('report_path'),str) and check['report_path'].strip()
                  for check in checks)
    if valid and phase==7:
        valid=all(sum(check['name']==name for check in checks)==1 for name in
                  ('p01-before','p05-before','p06-before','p00-p06-before'))
    if not valid: print(f'P{phase:02}')
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P12 prerequisite report scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stale: std::collections::HashSet<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    for phase in 0..=11 {
        let name = format!("P{phase:02}");
        let log_path = report_dir.join(format!("p12-prerequisite-{name}.log"));
        if !stale.contains(&name) {
            fs::write(
                log_path,
                format!("reused fresh PASS report; source_digest={digest}\n"),
            )
            .unwrap();
            continue;
        }
        let command = format!("{} gate {name}", BIN);
        let output = Command::new(BIN)
            .current_dir(root)
            .args(["gate", &name])
            .output()
            .unwrap();
        let exit_code = output.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        fs::write(
            &log_path,
            format!(
                "command={command}\nexit_code={exit_code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n"
            ),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "重建 {name} 前置 gate 失敗，log={}：stdout={} stderr={}",
            log_path.display(),
            stdout,
            stderr
        );
    }
}

fn stamp_prerequisite_reports_for_negative_test(root: &Path, through: &str) {
    let digest = current_source_digest(root);
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); last=int(sys.argv[2][1:]); digest=sys.argv[3]
for phase in range(last+1):
    path=root/'target/rivetlua-reports'/f'gate-P{phase:02}.json'
    if not path.exists(): continue
    try: report=json.loads(path.read_bytes())
    except (ValueError,UnicodeError): continue
    if not isinstance(report,dict) or report.get('status')!='PASS': continue
    report['source_digest']=digest
    path.write_text(json.dumps(report,ensure_ascii=False,separators=(',',':'))+'\n',encoding='utf-8')
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(through)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "測試前置報告 digest 準備失敗：{}",
        String::from_utf8_lossy(&output.stderr)
    );
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

struct RestoreBytes {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl RestoreBytes {
    fn new(path: PathBuf) -> Self {
        let contents = fs::read(&path).ok();
        Self { path, contents }
    }
}

impl Drop for RestoreBytes {
    fn drop(&mut self) {
        if let Some(contents) = &self.contents {
            fs::write(&self.path, contents).unwrap();
        } else {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn assert_bytes_restored_with_cmp(path: &Path, original: &[u8]) {
    assert_eq!(fs::read(path).unwrap(), original);
    let backup = std::env::temp_dir().join(format!(
        "rivetlua-byte-backup-{}-{}",
        std::process::id(),
        path.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&backup, original).unwrap();
    let compared = Command::new("cmp")
        .args(["-s"])
        .arg(&backup)
        .arg(path)
        .status()
        .unwrap();
    fs::remove_file(backup).unwrap();
    assert!(compared.success(), "cmp -s 未確認檔案位元組完整還原");
}

fn assert_no_p09_case_reports(report_dir: &Path) {
    for entry in fs::read_dir(report_dir).unwrap().flatten() {
        assert!(
            !entry.file_name().to_string_lossy().starts_with("P09-CALL-"),
            "P09 failure retained a stale case report: {}",
            entry.path().display()
        );
    }
}

fn run_p09_gate(root: &Path) -> std::process::Output {
    stamp_prerequisite_reports_for_negative_test(root, "P08");
    Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P09"])
        .output()
        .unwrap()
}

fn assert_p09_gate_failure(root: &Path, report_dir: &Path, report_path: &Path) -> String {
    let stale = report_dir.join("P09-CALL-001-lua55.json");
    fs::write(&stale, b"{\"status\":\"PASS\"}\n").unwrap();
    let output = run_p09_gate(root);
    assert!(!output.status.success());
    assert_gate_report_is_json(report_path);
    assert_no_p09_case_reports(report_dir);
    let report = fs::read_to_string(report_path).unwrap();
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL'; assert r['checks']; assert any(c['status']=='FAIL' and c['exit_code']!=0 and c['command'] and c['diagnostic'] and c['report_path'] for c in r['checks'])",
        ])
        .arg(report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P09 FAIL JSON 欄位無效：{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    report
}

fn assert_no_p10_case_reports(report_dir: &Path) {
    for entry in fs::read_dir(report_dir).unwrap().flatten() {
        assert!(
            !entry.file_name().to_string_lossy().starts_with("P10-META-"),
            "P10 failure retained a stale case report: {}",
            entry.path().display()
        );
    }
}

fn assert_no_p11_case_reports(report_dir: &Path) {
    for entry in fs::read_dir(report_dir).unwrap().flatten() {
        assert!(
            !entry.file_name().to_string_lossy().starts_with("P11-"),
            "P11 failure retained a stale case report: {}",
            entry.path().display()
        );
    }
}

struct RestoreP11Cases {
    report_dir: PathBuf,
    reports: Vec<(PathBuf, Vec<u8>)>,
}

impl RestoreP11Cases {
    fn new(report_dir: &Path) -> Self {
        let reports = fs::read_dir(report_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("P11-"))
            .map(|entry| (entry.path(), fs::read(entry.path()).unwrap()))
            .collect();
        Self {
            report_dir: report_dir.to_path_buf(),
            reports,
        }
    }
}

impl Drop for RestoreP11Cases {
    fn drop(&mut self) {
        let preserved: std::collections::HashSet<_> =
            self.reports.iter().map(|(path, _)| path.clone()).collect();
        for entry in fs::read_dir(&self.report_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            if entry.file_name().to_string_lossy().starts_with("P11-")
                && !preserved.contains(&entry.path())
            {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        for (path, contents) in &self.reports {
            fs::write(path, contents).unwrap();
        }
    }
}

fn p11_sha256(path: &Path) -> String {
    let output = Command::new("python3")
        .args([
            "-c",
            "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn make_p11_fake_cargo(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let fake = directory.join("cargo");
    fs::write(
        &fake,
        r##"#!/usr/bin/env python3
import os, pathlib, sys
scenario = os.environ.get('RIVETLUA_P11_FAKE', 'valid')
log = os.environ.get('RIVETLUA_P11_CHILD_LOG')
is_unit = '--lib' in sys.argv
profile = os.environ.get('RIVETLUA_P11_PROFILE', '')
if log:
    with open(log, 'a', encoding='utf-8') as stream:
        stream.write(('unit' if is_unit else profile + ':' + sys.argv[sys.argv.index('--test') + 2]) + '\n')
if is_unit:
    counts = {'unit-zero': 0, 'unit-short': 22, 'unit-extra': 24}
    count = counts.get(scenario, 23)
    print(f'test result: ok. {count} passed; 0 failed; {max(0, 223-count)} filtered out; finished in 0.00s')
    if scenario == 'unit-fail':
        raise SystemExit(1)
    raise SystemExit(0)
if scenario in ('child-assertion', 'child-nonzero'):
    print('thread panicked at assertion failed' if scenario == 'child-assertion' else 'cargo test child failed')
    print('test result: FAILED. 0 passed; 1 failed')
    raise SystemExit(1 if scenario == 'child-assertion' else 101)
counts = {'case-zero': 0, 'case-extra': 2}
count = counts.get(scenario, 1)
print(f'test result: ok. {count} passed; 0 failed; {max(0, 48-count)} filtered out; finished in 0.00s')
test_name = sys.argv[sys.argv.index('--test') + 2]
profile = os.environ.get('RIVETLUA_P11_PROFILE', '')
rows = pathlib.Path('tests/p11/error-coroutine-close-cases.fixture').read_text(encoding='utf-8').splitlines()
fields = next(line.split('|') for line in rows if line.startswith('case|') and line.split('|')[1] == profile and line.split('|')[4] == test_name)
case_id, marker, actual = fields[2], fields[5], fields[6]
if scenario == 'missing-marker':
    raise SystemExit(0)
if scenario == 'unknown-marker':
    marker = 'P11_STAGE:unknown'
if scenario == 'cross-profile':
    profile = 'lua54-i64f64'
if marker.startswith('P11_CASE:'):
    marker_id = marker.split(':', 1)[1]
    line = f'P11_CASE\t{marker_id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=observed-formal-assertions'
else:
    line = f'P11_STAGE\t{marker.split(":", 1)[1]}\t{profile}\tstatus=PASS;{actual}'
if scenario == 'unknown-marker' and marker.startswith('P11_CASE:'):
    line = line.replace(marker_id, 'UNKNOWN-001')
print(line)
if scenario == 'duplicate-marker':
    print(line)
"##,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fake
}

fn assert_p11_gate_failure(
    root: &Path,
    report_dir: &Path,
    report_path: &Path,
    fake_cargo_dir: &Path,
    scenario: &str,
    child_log: &Path,
    expected_check: &str,
    expected_diagnostic: &str,
    expected_children: Option<&[&str]>,
) -> String {
    stamp_prerequisite_reports_for_negative_test(root, "P10");
    fs::write(
        report_dir.join("P11-ERR-001-lua55.json"),
        b"{\"status\":\"PASS\"}\n",
    )
    .unwrap();
    let path = std::env::join_paths(
        std::iter::once(fake_cargo_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .env("RIVETLUA_P11_FAKE", scenario)
        .env("RIVETLUA_P11_CHILD_LOG", child_log)
        .args(["gate", "P11"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "P11 negative scenario {scenario} unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_gate_report_is_json(report_path);
    assert_no_p11_case_reports(report_dir);
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL'; assert isinstance(r.get('checks'),list) and r['checks']; required={'name','command','exit_code','status','diagnostic','report_path'}; assert all(required <= c.keys() for c in r['checks']); assert any(c['status']=='FAIL' and isinstance(c['exit_code'],int) and c['exit_code'] != 0 and isinstance(c['diagnostic'],str) and c['diagnostic'] for c in r['checks'])",
        ])
        .arg(report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P11 FAIL JSON schema 無效：{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let report = fs::read_to_string(report_path).unwrap();
    assert!(
        report.contains(expected_check),
        "{scenario}: missing check {expected_check}"
    );
    assert!(
        report.contains(expected_diagnostic),
        "{scenario}: missing diagnostic {expected_diagnostic}"
    );
    match expected_children {
        Some(expected) => {
            let children = fs::read_to_string(child_log).unwrap();
            assert_eq!(children.lines().collect::<Vec<_>>(), expected, "{scenario}");
        }
        None => assert!(
            !child_log.exists(),
            "{scenario} must fail before runtime child"
        ),
    }
    report
}

struct RestoreP10Cases {
    reports: Vec<(PathBuf, Vec<u8>)>,
}

impl RestoreP10Cases {
    fn new(report_dir: &Path) -> Self {
        let reports = fs::read_dir(report_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("P10-META-"))
            .map(|entry| (entry.path(), fs::read(entry.path()).unwrap()))
            .collect();
        Self { reports }
    }
}

impl Drop for RestoreP10Cases {
    fn drop(&mut self) {
        for (path, contents) in &self.reports {
            fs::write(path, contents).unwrap();
        }
    }
}

fn make_p10_fake_cargo(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let fake = directory.join("cargo");
    fs::write(
        &fake,
        r##"#!/usr/bin/env python3
import os, pathlib, sys
profile = os.environ.get('RIVETLUA_P10_PROFILE', '')
scenario = os.environ.get('RIVETLUA_P10_FAKE', 'valid')
log = os.environ.get('RIVETLUA_P10_CHILD_LOG')
if log:
    with open(log, 'a', encoding='utf-8') as stream:
        stream.write((profile or 'P10_UNIT') + '\n')
if scenario == 'child-fail':
    if '--lib' not in sys.argv:
        print('test result: FAILED. 0 passed; 1 failed')
        raise SystemExit(1)
if '--lib' in sys.argv:
    print('test result: ok. 7 passed; 0 failed; 100 filtered out; finished in 0.00s')
    raise SystemExit(0)
counts = {'zero': 0, 'short': 9, 'long': 11}
count = counts.get(scenario, 10)
print(f'test result: ok. {count} passed; 0 failed; {max(0, 16-count)} filtered out; finished in 0.00s')
if count != 10:
    raise SystemExit(0)
rows = []
fixture = pathlib.Path('tests/p10/metamethod-cases.fixture').read_text(encoding='utf-8')
for line in fixture.splitlines():
    fields = line.split('|')
    if len(fields) == 7 and fields[0] == 'case' and fields[1] == profile:
        rows.append(fields)
diagnostic = 'event=__index;operands=target=t;pending=not-exposed;frame_pc=not-exposed;resume=result=ok;fuel=default;roots=2;error=none;aborted=false;protected_boundary=run;internal_unit=vm::tests::p10_3_pending_op_resume'
markers = []
for fields in rows:
    markers.append([fields[2], profile, fields[5], diagnostic])
if scenario == 'duplicate' and markers:
    markers[-1][0] = markers[0][0]
elif scenario == 'unknown' and markers:
    markers[0][0] = 'META-011'
elif scenario == 'wrong-profile' and markers:
    markers[0][1] = 'lua54-i64f64' if profile == 'lua55-i64f64' else 'lua55-i64f64'
elif scenario == 'incomplete-diagnostic' and markers:
    markers[0][3] = 'event=__index;operands=t'
elif scenario == 'missing-marker' and markers:
    markers.pop()
for case_id, case_profile, actual, details in markers:
    print(f'P10_CASE\t{case_id}\t{case_profile}\tactual={actual}\tdiagnostic={details}')
"##,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fake
}

fn assert_p10_gate_failure(
    root: &Path,
    report_dir: &Path,
    report_path: &Path,
    fake_cargo_dir: &Path,
    scenario: &str,
    child_log: &Path,
) -> String {
    stamp_prerequisite_reports_for_negative_test(root, "P09");
    fs::write(
        report_dir.join("P10-META-001-lua55.json"),
        b"{\"status\":\"PASS\"}\n",
    )
    .unwrap();
    let path = std::env::join_paths(
        std::iter::once(fake_cargo_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .env("RIVETLUA_P10_FAKE", scenario)
        .env("RIVETLUA_P10_CHILD_LOG", child_log)
        .args(["gate", "P10"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "scenario {scenario} unexpectedly passed"
    );
    assert_gate_report_is_json(report_path);
    assert_no_p10_case_reports(report_dir);
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL'; assert isinstance(r.get('checks'),list) and r['checks']; required={'name','command','exit_code','status','diagnostic','report_path'}; assert all(required <= c.keys() for c in r['checks']); assert any(c['status']=='FAIL' and isinstance(c['diagnostic'],str) and c['diagnostic'] for c in r['checks'])",
        ])
        .arg(report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P10 FAIL aggregate 欄位無效：{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    fs::read_to_string(report_path).unwrap()
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

#[test]
fn p08_invalid_fixture_csv_and_prerequisites_fail_then_full_gate_passes() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P06");
    let p07_rebuild = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P07"])
        .output()
        .unwrap();
    assert!(
        p07_rebuild.status.success(),
        "P07 前置 gate 重建失敗：{}{}",
        String::from_utf8_lossy(&p07_rebuild.stdout),
        String::from_utf8_lossy(&p07_rebuild.stderr)
    );
    let p07_report = root.join("target/rivetlua-reports/gate-P07.json");
    let p07_validation = Command::new("python3")
        .args([
            "-c",
            r#"import json,sys
r=json.load(open(sys.argv[1])); assert r['status']=='PASS'
checks=r['checks']; assert checks and all(c['status']=='PASS' for c in checks)
for name in ('p01-before','p05-before','p06-before','p00-p06-before'):
    found=[c for c in checks if c['name']==name]
    assert len(found)==1 and found[0]['exit_code']==0"#,
        ])
        .arg(&p07_report)
        .output()
        .unwrap();
    assert!(
        p07_validation.status.success(),
        "重建後的 P07 PASS 報告驗證失敗：{}",
        String::from_utf8_lossy(&p07_validation.stderr)
    );
    let report_path = root.join("target/rivetlua-reports/gate-P08.json");
    let case_report_dir = root.join("target/rivetlua-reports");
    let fixture_path = root.join("tests/p08/table-cases.fixture");
    let fixture_original = fs::read_to_string(&fixture_path).unwrap();
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read_to_string(&csv_path).unwrap();
    let status_original = git_status_snapshot(root);

    let run_gate = || {
        stamp_prerequisite_reports_for_negative_test(root, "P07");
        Command::new(BIN)
            .current_dir(root)
            .args(["gate", "P08"])
            .output()
            .unwrap()
    };
    let assert_fail_and_no_case_reports = || {
        let output = run_gate();
        assert!(!output.status.success());
        assert_gate_report_is_json(&report_path);
        for entry in fs::read_dir(&case_report_dir).unwrap().flatten() {
            assert!(!entry.file_name().to_string_lossy().starts_with("P08-"));
        }
    };
    let fixture_mutations = [
        fixture_original.replacen("case|TAB-012|", "case|TAB-MISSING|", 1),
        fixture_original.replacen("case|TAB-012|", "case|TAB-011|", 1),
        fixture_original.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|common"),
        fixture_original.replacen("|raw_get(Nil)|Nil|", "|raw_get(Nil)|Wrong|", 1),
        fixture_original.replacen("case|TAB-012|", "broken|TAB-012|", 1),
    ];
    for mutated in fixture_mutations {
        let restore = RestoreFixture {
            path: fixture_path.clone(),
            contents: fixture_original.clone(),
        };
        fs::write(&fixture_path, mutated).unwrap();
        assert_fail_and_no_case_reports();
        drop(restore);
        assert_fixture_restored_with_cmp(&fixture_path, &fixture_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let p08_lua55_row = csv_original
        .lines()
        .find(|line| line.starts_with("p08.string-table,lua55,"))
        .unwrap()
        .to_owned();
    let missing_csv_column =
        csv_original.replacen(&p08_lua55_row, p08_lua55_row.trim_end_matches(','), 1);
    for mutated in [
        csv_original.replacen("TAB-012", "TAB-MISSING", 1),
        csv_original.replacen("p08.string-table,lua54,", "p08.string-table,common,", 1),
        missing_csv_column,
    ] {
        let restore = RestoreFixture {
            path: csv_path.clone(),
            contents: csv_original.clone(),
        };
        fs::write(&csv_path, mutated).unwrap();
        assert_fail_and_no_case_reports();
        drop(restore);
        assert_fixture_restored_with_cmp(&csv_path, &csv_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let p07_original = fs::read_to_string(&p07_report).unwrap();
    let valid_p07_checks = r#"{"name":"p01-before","exit_code":0,"status":"PASS"},{"name":"p05-before","exit_code":0,"status":"PASS"},{"name":"p06-before","exit_code":0,"status":"PASS"},{"name":"p00-p06-before","exit_code":0,"status":"PASS"}"#;
    let mut nonzero_checks = valid_p07_checks.to_owned();
    nonzero_checks = nonzero_checks.replacen("\"exit_code\":0", "\"exit_code\":7", 1);
    let invalid_prior_reports = [
        format!("garbage{{\"status\":\"PASS\",\"checks\":[{valid_p07_checks}]}}"),
        format!(
            "{{\"status\":\"PASS\",\"checks\":[{{\"name\":\"smoke\",\"exit_code\":0,\"status\":\"PASS\"}}],\"metadata\":[{valid_p07_checks}]}}"
        ),
        format!("{{\"status\":\"PASS\",\"checks\":[{nonzero_checks}]}}"),
    ];
    for invalid_report in invalid_prior_reports {
        let restore = RestoreFixture {
            path: p07_report.clone(),
            contents: p07_original.clone(),
        };
        fs::write(&p07_report, invalid_report).unwrap();
        assert_fail_and_no_case_reports();
        drop(restore);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let restore = RestoreFixture {
        path: p07_report.clone(),
        contents: p07_original.clone(),
    };
    fs::write(&p07_report, "{\"status\":\"FAIL\",\"checks\":[] }\n").unwrap();
    assert_fail_and_no_case_reports();
    drop(restore);
    assert_eq!(git_status_snapshot(root), status_original);

    let p07_original = fs::read_to_string(&p07_report).unwrap();
    let restore = RestoreFixture {
        path: p07_report.clone(),
        contents: p07_original,
    };
    fs::remove_file(&p07_report).unwrap();
    assert_fail_and_no_case_reports();
    drop(restore);
    assert_eq!(git_status_snapshot(root), status_original);

    let failing_cargo_dir =
        std::env::temp_dir().join(format!("rivetlua-p08-failing-cargo-{}", std::process::id()));
    fs::create_dir_all(&failing_cargo_dir).unwrap();
    let failing_cargo = failing_cargo_dir.join("cargo");
    fs::write(
        &failing_cargo,
        "#!/bin/sh\nprintf '%s\\n' 'test result: FAILED. 0 passed; 1 failed' >&2\nexit 1\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&failing_cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(failing_cargo_dir.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    stamp_prerequisite_reports_for_negative_test(root, "P07");
    let output = Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .args(["gate", "P08"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_gate_report_is_json(&report_path);
    let failed_gate = fs::read_to_string(&report_path).unwrap();
    assert!(failed_gate.contains("p08-runtime-unit"));
    assert_eq!(git_status_snapshot(root), status_original);
    fs::remove_dir_all(&failing_cargo_dir).unwrap();

    let output = run_gate();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = Command::new("python3")
        .args([
            "-c",
            r#"import glob,json,os,sys
r=json.load(open(sys.argv[1])); assert r['status']=='PASS'
cases=[c for c in r['checks'] if c['name'].startswith('TAB-')]
assert len(cases)==24 and len({c['name'] for c in cases})==24
reports=[json.load(open(c['report_path'])) for c in cases]
required={'case_id','profile','lua_profile','mode','input','expected','actual','status','command','exit_code','report_path','diagnostic'}
assert all(required <= x.keys() and x['status']=='PASS' and x['exit_code']==0 for x in reports)
assert sum(x['profile']=='lua55-i64f64' and x['lua_profile']=='lua55' for x in reports)==12
assert sum(x['profile']=='lua54-i64f64' and x['lua_profile']=='lua54' for x in reports)==12
assert {x['case_id'] for x in reports}=={f'TAB-{i:03}' for i in range(1,13)}
assert all(any(c['name']==name and c['status']=='PASS' for c in r['checks']) for name in ('p08-csv','p08-fixture','p00-p07-before','p08-runtime-unit'))
assert all(sum('input_order=' in x['actual'] for x in reports if x['case_id']=='TAB-010' and x['profile']==profile)==1 for profile in ('lua55-i64f64','lua54-i64f64'))
assert len(glob.glob(os.path.join(os.path.dirname(sys.argv[1]),'P08-TAB-*.json')))==24"#,
        ])
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "P08 PASS JSON 驗證失敗：{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    assert_eq!(git_status_snapshot(root), status_original);
}

#[test]
fn p09_gate_failure_writes_parseable_fail_aggregate() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P08");
    let status_original = git_status_snapshot(root);
    let report_path = root.join("target/rivetlua-reports/gate-P09.json");
    let previous_report = RestoreBytes::new(report_path.clone());
    let _ = fs::remove_file(&report_path);
    let prerequisite = root.join("target/rivetlua-reports/gate-P08.json");
    let prerequisite_bytes = fs::read(&prerequisite).unwrap();
    let restore_prerequisite = RestoreBytes::new(prerequisite.clone());
    fs::remove_file(&prerequisite).unwrap();
    let stale_case = root.join("target/rivetlua-reports/P09-CALL-001-lua55.json");
    let previous_stale_case = RestoreBytes::new(stale_case.clone());
    fs::write(&stale_case, b"{\"status\":\"PASS\"}\n").unwrap();

    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P09"])
        .output()
        .unwrap();
    let generated = fs::read(&report_path).ok();
    let aggregate = generated
        .clone()
        .map(|bytes| std::str::from_utf8(&bytes).unwrap().to_owned());
    let stale_removed = !stale_case.exists();
    drop(previous_stale_case);
    drop(restore_prerequisite);
    drop(previous_report);
    assert_bytes_restored_with_cmp(&prerequisite, &prerequisite_bytes);
    assert_eq!(
        git_status_snapshot(root),
        status_original,
        "P09 前置注入未恢復工作樹狀態"
    );

    assert!(!output.status.success());
    assert!(stale_removed, "P09 fail-fast 必須清除舊 PASS case 報告");
    let Some(generated) = generated else {
        panic!("P09 失敗時必須寫出 aggregate JSON");
    };
    let backup =
        std::env::temp_dir().join(format!("rivetlua-p09-fail-{}.json", std::process::id()));
    fs::write(&backup, generated).unwrap();
    assert_gate_report_is_json(&backup);
    fs::remove_file(backup).unwrap();
    let aggregate = aggregate.unwrap();
    assert!(aggregate.contains("p00-p08-before"));
    assert!(aggregate.contains("缺少 P08 前置 gate 報告"));
}

#[test]
fn p09_invalid_inputs_prerequisites_and_child_fail_then_full_gate_passes() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P08");
    let status_original = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P09.json");
    let fixture_path = root.join("tests/p09/call-cases.fixture");
    let fixture_original = fs::read(&fixture_path).unwrap();
    let fixture_text = String::from_utf8(fixture_original.clone()).unwrap();
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read(&csv_path).unwrap();
    let csv_text = String::from_utf8(csv_original.clone()).unwrap();

    let fixture_mutations = [
        fixture_text.replacen(
            "case|lua55-i64f64|CALL-013|",
            "case|lua55-i64f64|CALL-MISSING|",
            1,
        ),
        fixture_text.replacen(
            "case|lua55-i64f64|CALL-013|",
            "case|lua55-i64f64|CALL-001|",
            1,
        ),
        fixture_text.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|common"),
        fixture_text.replace("case|lua55-i64f64|CALL-011|", "case|lua54-i64f64|CALL-011|"),
        fixture_text.replace("case|lua54-i64f64|CALL-012|", "case|lua55-i64f64|CALL-012|"),
        fixture_text.replacen("|Returned([7])|", "|Returned([8])|", 1),
        fixture_text.replacen(
            "case|lua55-i64f64|CALL-013|",
            "broken|lua55-i64f64|CALL-013|",
            1,
        ),
    ];
    for mutated in fixture_mutations {
        let restore = RestoreBytes::new(fixture_path.clone());
        fs::write(&fixture_path, mutated.as_bytes()).unwrap();
        let report = assert_p09_gate_failure(root, &report_dir, &report_path);
        assert!(report.contains("p09-fixture"));
        drop(restore);
        assert_bytes_restored_with_cmp(&fixture_path, &fixture_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let p09_lua55_row = csv_text
        .lines()
        .find(|line| line.starts_with("p09.function-closure,lua55,"))
        .unwrap()
        .to_owned();
    let missing_column = csv_text.replacen(&p09_lua55_row, p09_lua55_row.trim_end_matches(','), 1);
    let csv_mutations = [
        csv_text.replacen("CALL-013", "CALL-MISSING", 1),
        csv_text.replacen("CALL-013", "CALL-001", 1),
        csv_text.replacen(
            "p09.function-closure,lua54,",
            "p09.function-closure,common,",
            1,
        ),
        missing_column,
        format!("{csv_text}\n{p09_lua55_row}"),
        format!("{csv_text}\np09.extra,lua55,docs/plane/P09.md,rivetlua-runtime,CALL-001,PASS,"),
    ];
    for mutated in csv_mutations {
        let restore = RestoreBytes::new(csv_path.clone());
        fs::write(&csv_path, mutated.as_bytes()).unwrap();
        let report = assert_p09_gate_failure(root, &report_dir, &report_path);
        assert!(report.contains("p09-csv"));
        drop(restore);
        assert_bytes_restored_with_cmp(&csv_path, &csv_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let p08_report = report_dir.join("gate-P08.json");
    let p08_original = fs::read(&p08_report).unwrap();
    for mutated in [
        Some(b"{\"status\":\"FAIL\",\"checks\":[]}\n".to_vec()),
        Some(b"not-json\n".to_vec()),
        None,
    ] {
        let restore = RestoreBytes::new(p08_report.clone());
        if let Some(mutated) = mutated {
            fs::write(&p08_report, mutated).unwrap();
        } else {
            fs::remove_file(&p08_report).unwrap();
        }
        let report = assert_p09_gate_failure(root, &report_dir, &report_path);
        assert!(report.contains("p00-p08-before"));
        drop(restore);
        assert_bytes_restored_with_cmp(&p08_report, &p08_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let failing_cargo_dir =
        std::env::temp_dir().join(format!("rivetlua-p09-failing-cargo-{}", std::process::id()));
    fs::create_dir_all(&failing_cargo_dir).unwrap();
    let failing_cargo = failing_cargo_dir.join("cargo");
    fs::write(
        &failing_cargo,
        "#!/bin/sh\nprintf '%s\\n' 'test result: FAILED. 0 passed; 1 failed' >&2\nexit 1\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&failing_cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(failing_cargo_dir.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let stale_case = report_dir.join("P09-CALL-001-lua55.json");
    fs::write(&stale_case, b"{\"status\":\"PASS\"}\n").unwrap();
    stamp_prerequisite_reports_for_negative_test(root, "P08");
    let child_failure = Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .args(["gate", "P09"])
        .output()
        .unwrap();
    assert!(!child_failure.status.success());
    assert_gate_report_is_json(&report_path);
    assert_no_p09_case_reports(&report_dir);
    let child_report = fs::read_to_string(&report_path).unwrap();
    assert!(child_report.contains("p09-contracts-lua55"));
    assert!(child_report.contains("實際 exit=1"));
    assert_eq!(git_status_snapshot(root), status_original);
    fs::remove_dir_all(&failing_cargo_dir).unwrap();

    let output = run_p09_gate(root);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let validated = Command::new("python3")
        .args([
            "-c",
            r#"import glob,json,os,sys
root=sys.argv[1]; report=json.load(open(sys.argv[2])); assert report['status']=='PASS'
cases=[check for check in report['checks'] if check['name'].startswith('CALL-')]
assert len(cases)==24 and len({case['name'] for case in cases})==24
items=[json.load(open(case['report_path'])) for case in cases]
required={'case_id','profile','lua_profile','mode','input','expected','actual','status','command','exit_code','report_path','diagnostic'}
assert all(required <= item.keys() and item['status']=='PASS' and item['exit_code']==0 for item in items)
want55={f'CALL-{n:03}' for n in range(1,12)}|{'CALL-013'}
want54={f'CALL-{n:03}' for n in range(1,11)}|{'CALL-012','CALL-013'}
for profile,lua_profile,wanted in [('lua55-i64f64','lua55',want55),('lua54-i64f64','lua54',want54)]:
    selected=[item for item in items if item['profile']==profile]
    assert len(selected)==12 and all(item['lua_profile']==lua_profile for item in selected)
    assert {item['case_id'] for item in selected}==wanted
close=next(item for item in items if item['case_id']=='CALL-013')
assert close['mode']=='runtime-close'
assert close['expected']=='Returned([nil,1,nil]);peak_frames=2;path_pc=numeric;tail_reuse=false;result_count=3;close_order=LIFO'
assert close['actual'].startswith('Returned([nil,1,nil]);peak_frames=2;path_pc=')
actual_fields=dict(field.split('=',1) for field in close['actual'].split(';')[1:])
assert close['actual'].split(';')[0]=='Returned([nil,1,nil])'
assert actual_fields['peak_frames']=='2' and actual_fields['path_pc'].isdigit()
assert actual_fields['tail_reuse']=='false' and actual_fields['result_count']=='3'
assert actual_fields['close_order']=='LIFO'
assert '宿主環境' in close['diagnostic'] and '__close' in close['diagnostic']
assert len(glob.glob(os.path.join(root,'target/rivetlua-reports','P09-CALL-*.json')))==24
assert all(any(check['name']==name and check['status']=='PASS' for check in report['checks']) for name in ('p00-p08-before','p09-csv','p09-fixture','p09-contracts-lua55','p09-contracts-lua54'))"#,
        ])
        .arg(root)
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        validated.status.success(),
        "P09 PASS JSON 驗證失敗：{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    assert_bytes_restored_with_cmp(&fixture_path, &fixture_original);
    assert_bytes_restored_with_cmp(&csv_path, &csv_original);
    assert_eq!(git_status_snapshot(root), status_original);
}

#[test]
fn p10_gate_fail_fast_writes_json_and_clears_stale_cases() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P09");
    let status_original = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P10.json");
    let _previous_cases = RestoreP10Cases::new(&report_dir);
    let previous_report = RestoreBytes::new(report_path.clone());
    let _ = fs::remove_file(&report_path);
    let prerequisite = report_dir.join("gate-P09.json");
    let prerequisite_bytes = fs::read(&prerequisite).unwrap();
    let restore_prerequisite = RestoreBytes::new(prerequisite.clone());
    fs::remove_file(&prerequisite).unwrap();
    let stale_case = report_dir.join("P10-META-001-lua55.json");
    let previous_stale_case = RestoreBytes::new(stale_case.clone());
    fs::write(&stale_case, b"{\"status\":\"PASS\"}\n").unwrap();

    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P10"])
        .output()
        .unwrap();
    let generated = fs::read(&report_path).ok();
    let generated_text = generated
        .as_ref()
        .map(|bytes| String::from_utf8(bytes.clone()).unwrap());
    let stale_removed = !stale_case.exists();
    drop(previous_stale_case);
    drop(restore_prerequisite);
    drop(previous_report);

    assert_bytes_restored_with_cmp(&prerequisite, &prerequisite_bytes);
    assert_eq!(git_status_snapshot(root), status_original);
    assert!(!output.status.success());
    assert!(stale_removed, "P10 fail-fast 必須清除舊 PASS case 報告");
    let Some(generated) = generated else {
        panic!("P10 失敗時必須寫出合法 aggregate JSON");
    };
    let backup =
        std::env::temp_dir().join(format!("rivetlua-p10-fail-{}.json", std::process::id()));
    fs::write(&backup, generated).unwrap();
    assert_gate_report_is_json(&backup);
    fs::remove_file(&backup).unwrap();
    let report = generated_text.unwrap();
    assert!(report.contains("p00-p09-before"));
    assert!(report.contains("缺少 P09 前置 gate 報告"));
}

#[test]
fn p10_prerequisites_fixture_and_csv_fail_fast_restore_bytes() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P09");
    let status_original = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P10.json");
    let _previous_cases = RestoreP10Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());
    let p09_path = report_dir.join("gate-P09.json");
    let p09_original = fs::read(&p09_path).unwrap();
    let fixture_path = root.join("tests/p10/metamethod-cases.fixture");
    let fixture_original = fs::read(&fixture_path).unwrap();
    let fixture_text = String::from_utf8(fixture_original.clone()).unwrap();
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read(&csv_path).unwrap();
    let csv_text = String::from_utf8(csv_original.clone()).unwrap();
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p10-fake-{}", std::process::id()));
    let fake_cargo = make_p10_fake_cargo(&fake_dir);
    let fake_cargo_dir = fake_cargo.parent().unwrap();
    let child_log = fake_dir.join("child.log");

    let prerequisite_mutations = [
        Some(b"{\"status\":\"FAIL\",\"checks\":[]}\n".to_vec()),
        Some(b"not-json\n".to_vec()),
        Some(
            b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"status\":\"PASS\"}]}\n"
                .to_vec(),
        ),
        Some(b"{\"status\":\"PASS\",\"checks\":{}}\n".to_vec()),
        None,
    ];
    for mutation in prerequisite_mutations {
        let restore = RestoreBytes::new(p09_path.clone());
        if let Some(mutation) = mutation {
            fs::write(&p09_path, mutation).unwrap();
        } else {
            fs::remove_file(&p09_path).unwrap();
        }
        let _ = fs::remove_file(&child_log);
        let report = assert_p10_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
        );
        assert!(report.contains("p00-p09-before"));
        assert!(!child_log.exists(), "前置失敗不可啟動 runtime child");
        drop(restore);
        assert_bytes_restored_with_cmp(&p09_path, &p09_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let fixture_010 = fixture_text
        .lines()
        .find(|line| line.starts_with("case|lua55-i64f64|META-010|"))
        .unwrap()
        .to_owned();
    let fixture_mutations = [
        fixture_text.replacen(&format!("{fixture_010}\n"), "", 1),
        fixture_text.replacen(
            "case|lua55-i64f64|META-010|",
            "case|lua55-i64f64|META-009|",
            1,
        ),
        fixture_text.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|lua55"),
        fixture_text.replace("case|lua55-i64f64|META-009|", "case|lua54-i64f64|META-009|"),
        fixture_text.replacen("|Returned([Integer(7)])|", "|Returned([Integer(9)])|", 1),
        fixture_text.replacen(
            "case|lua55-i64f64|META-010|",
            "broken|lua55-i64f64|META-010|",
            1,
        ),
        fixture_text.replacen("META-010", "META-011", 1),
        format!("{fixture_text}broken-row\n"),
    ];
    for mutation in fixture_mutations {
        let restore = RestoreBytes::new(fixture_path.clone());
        fs::write(&fixture_path, mutation.as_bytes()).unwrap();
        let _ = fs::remove_file(&child_log);
        let report = assert_p10_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
        );
        assert!(report.contains("p10-fixture"));
        assert!(!child_log.exists(), "fixture 失敗不可啟動 runtime child");
        drop(restore);
        assert_bytes_restored_with_cmp(&fixture_path, &fixture_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }

    let row_55 = csv_text
        .lines()
        .find(|line| line.starts_with("p10.metatable,lua55,"))
        .unwrap()
        .to_owned();
    let row_54 = csv_text
        .lines()
        .find(|line| line.starts_with("p10.metatable,lua54,"))
        .unwrap()
        .to_owned();
    let csv_mutations = [
        csv_text.replacen("META-010", "META-MISSING", 1),
        csv_text.replacen("META-010", "META-001", 1),
        csv_text.replace("p10.metatable,lua54,", "p10.metatable,common,"),
        csv_text.replacen(&row_55, row_55.trim_end_matches(','), 1),
        csv_text.replacen(&format!("{row_54}\n"), "", 1),
        format!("{csv_text}{row_55}\n"),
        format!("{csv_text}p10.extra,lua55,docs/plane/P10.md,rivetlua-runtime,META-001,PASS,\n"),
        csv_text.replacen("p10.metatable,lua55,", "p10.metatable,lua55,bad-ref,", 1),
    ];
    for mutation in csv_mutations {
        let restore = RestoreBytes::new(csv_path.clone());
        fs::write(&csv_path, mutation.as_bytes()).unwrap();
        let _ = fs::remove_file(&child_log);
        let report = assert_p10_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
        );
        assert!(report.contains("p10-csv"));
        assert!(!child_log.exists(), "CSV 失敗不可啟動 runtime child");
        drop(restore);
        assert_bytes_restored_with_cmp(&csv_path, &csv_original);
        assert_eq!(git_status_snapshot(root), status_original);
    }
    fs::remove_dir_all(fake_dir).unwrap();
}

#[test]
fn p10_runtime_child_and_marker_failures_write_fail_aggregates() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P09");
    let status_original = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P10.json");
    let _previous_cases = RestoreP10Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p10-child-{}", std::process::id()));
    let fake_cargo = make_p10_fake_cargo(&fake_dir);
    let fake_cargo_dir = fake_cargo.parent().unwrap();
    let child_log = fake_dir.join("child.log");
    let scenarios = [
        ("child-fail", "p10-contracts-lua55", "實際 exit=1"),
        ("zero", "p10-contracts-lua55", "0 passed"),
        ("short", "p10-contracts-lua55", "9 passed"),
        ("long", "p10-contracts-lua55", "11 passed"),
        ("missing-marker", "p10-contracts-lua55", "marker 數錯誤"),
        ("duplicate", "p10-contracts-lua55", "marker 數錯誤"),
        ("unknown", "p10-contracts-lua55", "未知正式 META marker"),
        ("wrong-profile", "p10-contracts-lua55", "profile 錯誤"),
        (
            "incomplete-diagnostic",
            "p10-contracts-lua55",
            "diagnostic 缺",
        ),
    ];
    for (scenario, check_name, diagnostic) in scenarios {
        let _ = fs::remove_file(&child_log);
        let report = assert_p10_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            scenario,
            &child_log,
        );
        assert!(report.contains(check_name), "{scenario}: {report}");
        assert!(report.contains(diagnostic), "{scenario}: {report}");
        let child_runs = fs::read_to_string(&child_log).unwrap();
        assert_eq!(
            child_runs.lines().collect::<Vec<_>>(),
            ["P10_UNIT", "lua55-i64f64"],
            "每個 profile failure 都須記錄已執行的 unit 與首個 profile child"
        );
        assert_eq!(git_status_snapshot(root), status_original);
    }
    fs::remove_dir_all(fake_dir).unwrap();
}

#[test]
fn p10_and_p11_reject_stale_or_invalid_source_digest_before_child() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    let original_status = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    fs::create_dir_all(&report_dir).unwrap();
    let _restore_reports = (0..=11)
        .map(|phase| RestoreBytes::new(report_dir.join(format!("gate-P{phase:02}.json"))))
        .collect::<Vec<_>>();
    let _restore_p10_cases = RestoreP10Cases::new(&report_dir);
    let _restore_p11_cases = RestoreP11Cases::new(&report_dir);
    for phase in 0..=10 {
        let names: &[&str] = if phase == 7 {
            &["p01-before", "p05-before", "p06-before", "p00-p06-before"]
        } else {
            &["smoke"]
        };
        let checks = names.iter().map(|name| format!("{{\"name\":\"{name}\",\"command\":\"run\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}}")).collect::<Vec<_>>().join(",");
        fs::write(
            report_dir.join(format!("gate-P{phase:02}.json")),
            format!("{{\"status\":\"PASS\",\"checks\":[{checks}]}}\n"),
        )
        .unwrap();
    }
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-stale-gate-{}", std::process::id()));
    fs::create_dir_all(&fake_dir).unwrap();
    let fake_cargo = fake_dir.join("cargo");
    let child_log = fake_dir.join("child.log");
    fs::write(
        &fake_cargo,
        format!(
            "#!/bin/sh\necho child >> '{}'\nexit 99\n",
            child_log.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(fake_dir.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let assert_stale = |phase: &str, expected: &str| {
        let _ = fs::remove_file(&child_log);
        let output = Command::new(BIN)
            .current_dir(root)
            .env("PATH", &path)
            .args(["gate", phase])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{phase} 沿用舊來源 PASS");
        assert!(!child_log.exists(), "{phase} 前置失敗仍啟動 runtime child");
        let report_path = report_dir.join(format!("gate-{phase}.json"));
        assert_gate_report_is_json(&report_path);
        let report = fs::read_to_string(report_path).unwrap();
        assert!(
            report.contains("source_digest") && report.contains(expected),
            "{phase}: {report}"
        );
    };

    stamp_prerequisite_reports_for_negative_test(root, "P09");
    for source in [
        "crates/rivetlua-compiler/tests/p05_contracts.rs",
        "crates/rivetlua-runtime/tests/p09_contracts.rs",
    ] {
        let source_path = root.join(source);
        let original = fs::read(&source_path).unwrap();
        let _restore = RestoreBytes::new(source_path.clone());
        let mut changed = original.clone();
        changed.extend_from_slice("\n// 測試來源狀態變更\n".as_bytes());
        fs::write(&source_path, changed).unwrap();
        assert_stale("P10", "已過期");
        fs::write(&source_path, &original).unwrap();
        assert_bytes_restored_with_cmp(&source_path, &original);
    }
    for phase in ["P05", "P09"] {
        let report_path = report_dir.join(format!("gate-{phase}.json"));
        let original = fs::read_to_string(&report_path).unwrap();
        fs::write(
            &report_path,
            original.replacen("\"source_digest\"", "\"missing_digest\"", 1),
        )
        .unwrap();
        assert_stale("P10", "缺少合法 source_digest");
        fs::write(
            &report_path,
            original.replacen("\"source_digest\":\"", "\"source_digest\":\"bad", 1),
        )
        .unwrap();
        assert_stale("P10", "缺少合法 source_digest");
        fs::write(&report_path, original).unwrap();
    }
    let p10_path = report_dir.join("gate-P10.json");
    fs::write(&p10_path, b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"run\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n").unwrap();
    stamp_prerequisite_reports_for_negative_test(root, "P10");
    let p10_original = fs::read_to_string(&p10_path).unwrap();
    fs::write(
        &p10_path,
        p10_original.replacen("\"source_digest\"", "\"missing_digest\"", 1),
    )
    .unwrap();
    assert_stale("P11", "P10 前置 gate 報告缺少合法 source_digest");
    fs::write(&p10_path, p10_original).unwrap();
    fs::remove_dir_all(fake_dir).unwrap();
    assert_eq!(git_status_snapshot(root), original_status);
}

#[test]
fn p11_gate_rejects_invalid_prerequisites_inputs_and_child_evidence() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P10");
    let status_original = git_status_snapshot(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P11.json");
    let _previous_cases = RestoreP11Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());

    let fixture_path = root.join("tests/p11/error-coroutine-close-cases.fixture");
    let csv_path = root.join("spec/compatibility.csv");
    let fixture_original = fs::read(&fixture_path).unwrap();
    let csv_original = fs::read(&csv_path).unwrap();
    let _restore_fixture = RestoreBytes::new(fixture_path.clone());
    let _restore_csv = RestoreBytes::new(csv_path.clone());
    let fixture_text = String::from_utf8(fixture_original.clone()).unwrap();
    let csv_text = String::from_utf8(csv_original.clone()).unwrap();

    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p11-cli-{}", std::process::id()));
    let fake_cargo = make_p11_fake_cargo(&fake_dir);
    let fake_cargo_dir = fake_cargo.parent().unwrap();
    let child_log = fake_dir.join("child.log");

    let p00_path = report_dir.join("gate-P00.json");
    let p00_original = fs::read(&p00_path).unwrap();
    let p00_original_hash = p11_sha256(&p00_path);
    let fixture_hash = p11_sha256(&fixture_path);
    let csv_hash = p11_sha256(&csv_path);
    for (scenario, mutation, expected_diagnostic) in [
        ("missing", None, "缺少 P00 前置 gate 報告"),
        ("fail", Some(b"{\"status\":\"FAIL\",\"checks\":[]}\n".as_slice()), "不是 PASS JSON"),
        ("invalid-json", Some(b"not-json\n".as_slice()), "不是合法 JSON"),
        ("schema", Some(b"{\"status\":\"PASS\"}\n".as_slice()), "缺少非空 checks"),
        (
            "check-name",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "缺少名稱",
        ),
        (
            "check-field",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "缺少 command",
        ),
        (
            "check-exit-code",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":\"0\",\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "缺少整數 exit_code",
        ),
        (
            "check-status",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"FAIL\",\"diagnostic\":\"bad\",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "不是 PASS 狀態",
        ),
        (
            "check-diagnostic",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "缺少 diagnostic",
        ),
        (
            "check-empty-diagnostic",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"  \",\"report_path\":\"report.json\"}]}\n".as_slice()),
            "缺少 diagnostic",
        ),
        (
            "check-report-path",
            Some(b"{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\"}]}\n".as_slice()),
            "缺少 report_path",
        ),
    ] {
        let _ = fs::remove_file(&child_log);
        if let Some(mutation) = mutation {
            fs::write(&p00_path, mutation).unwrap();
        } else {
            fs::remove_file(&p00_path).unwrap();
        }
        let report = assert_p11_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
            "p00-p10-before",
            expected_diagnostic,
            None,
        );
        assert!(report.contains("gate-P00.json"));
        fs::write(&p00_path, &p00_original).unwrap();
        assert_eq!(p11_sha256(&p00_path), p00_original_hash, "{scenario} P00 restore");
        assert_eq!(p11_sha256(&fixture_path), fixture_hash, "{scenario} fixture unchanged");
        assert_eq!(p11_sha256(&csv_path), csv_hash, "{scenario} CSV unchanged");
        assert_eq!(git_status_snapshot(root), status_original, "{scenario} status drift");
    }

    let inject_file =
        |path: &Path, mutation: &[u8], original: &[u8], check: &str, diagnostic: &str| {
            let before_fixture = p11_sha256(&fixture_path);
            let before_csv = p11_sha256(&csv_path);
            let before_status = git_status_snapshot(root);
            fs::write(path, mutation).unwrap();
            let _ = fs::remove_file(&child_log);
            let report = assert_p11_gate_failure(
                root,
                &report_dir,
                &report_path,
                fake_cargo_dir,
                "valid",
                &child_log,
                check,
                diagnostic,
                None,
            );
            fs::write(path, original).unwrap();
            assert_eq!(
                p11_sha256(&fixture_path),
                before_fixture,
                "fixture restore hash"
            );
            assert_eq!(p11_sha256(&csv_path), before_csv, "CSV restore hash");
            assert_eq!(
                git_status_snapshot(root),
                before_status,
                "injection status drift"
            );
            report
        };

    let err005 = fixture_text
        .lines()
        .find(|line| line.starts_with("case|lua55-i64f64|ERR-005|"))
        .unwrap()
        .to_owned();
    let missing_fixture_case = fixture_text
        .lines()
        .filter(|line| !line.starts_with("case|lua55-i64f64|ERR-005|"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let fixture_mutations = [
        missing_fixture_case,
        fixture_text.replacen(
            "case|lua55-i64f64|ERR-005|",
            "case|lua55-i64f64|ERR-MISSING|",
            1,
        ),
        format!("{fixture_text}{err005}\n"),
        fixture_text.replace("profile|lua54-i64f64|lua54\n", ""),
        fixture_text.replacen(
            "case|lua55-i64f64|ERR-001|",
            "case|lua54-i64f64|ERR-001|",
            1,
        ),
        fixture_text.replacen(
            "case|lua55-i64f64|ERR-001|",
            "case|lua55-i64f64|UNKNOWN-001|",
            1,
        ),
        fixture_text.replacen(
            "identity=preserved;nested=nearest;host_root=owned",
            "identity=stringified;nested=nearest;host_root=owned",
            1,
        ),
        fixture_text.replacen(
            "case|lua55-i64f64|ERR-001|",
            "broken|lua55-i64f64|ERR-001|",
            1,
        ),
    ];
    for mutation in fixture_mutations {
        let report = inject_file(
            &fixture_path,
            mutation.as_bytes(),
            &fixture_original,
            "p11-fixture",
            "fixture",
        );
        assert!(report.contains("p11-fixture"));
    }

    let row55 = csv_text
        .lines()
        .find(|line| line.starts_with("p11.errors-coroutines-close,lua55,"))
        .unwrap()
        .to_owned();
    let no_p11_rows = csv_text
        .lines()
        .filter(|line| !line.starts_with("p11."))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let csv_mutations = [
        csv_text.replacen(&row55, row55.trim_end_matches(','), 1),
        no_p11_rows,
        csv_text.replace("p11.errors-coroutines-close,lua55,", "p11.other,lua55,"),
        csv_text.replace(
            "p11.errors-coroutines-close,lua54,",
            "p11.errors-coroutines-close,common,",
        ),
        format!("{csv_text}{row55}\n"),
        csv_text.replace(
            "p11.errors-coroutines-close,lua54,",
            "p11.errors-coroutines-close,lua56,",
        ),
        format!("{csv_text}p11.unknown,lua55,docs/plane/P11.md,rivetlua-runtime,ERR-001,PASS,\n"),
    ];
    for mutation in csv_mutations {
        let report = inject_file(
            &csv_path,
            mutation.as_bytes(),
            &csv_original,
            "p11-csv",
            "CSV",
        );
        assert!(report.contains("p11-csv"));
    }

    let child_scenarios = [
        (
            "unit-fail",
            "p11-runtime-unit",
            "實際 exit=1",
            &["unit"][..],
        ),
        ("unit-zero", "p11-runtime-unit", "23 個 p11_", &["unit"][..]),
        (
            "unit-short",
            "p11-runtime-unit",
            "23 個 p11_",
            &["unit"][..],
        ),
        (
            "unit-extra",
            "p11-runtime-unit",
            "23 個 p11_",
            &["unit"][..],
        ),
        (
            "child-assertion",
            "ERR-001-lua55",
            "實際 exit=1",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "child-nonzero",
            "ERR-001-lua55",
            "實際 exit=101",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "case-zero",
            "ERR-001-lua55",
            "精確通過 1 個測試",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "case-extra",
            "ERR-001-lua55",
            "精確通過 1 個測試",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "missing-marker",
            "ERR-001-lua55",
            "marker 數錯誤",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "duplicate-marker",
            "ERR-001-lua55",
            "marker 數錯誤",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "unknown-marker",
            "ERR-001-lua55",
            "未知 formal marker",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
        (
            "cross-profile",
            "ERR-001-lua55",
            "profile 錯誤",
            &[
                "unit",
                "lua55-i64f64:err_case_001_original_table_and_nested_boundary",
            ][..],
        ),
    ];
    for (scenario, check, diagnostic, expected_children) in child_scenarios {
        let _ = fs::remove_file(&child_log);
        let report = assert_p11_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            scenario,
            &child_log,
            check,
            diagnostic,
            Some(expected_children),
        );
        assert_eq!(
            p11_sha256(&fixture_path),
            p11_sha256_from_bytes(&fixture_original)
        );
        assert_eq!(p11_sha256(&csv_path), p11_sha256_from_bytes(&csv_original));
        assert_eq!(
            git_status_snapshot(root),
            status_original,
            "{scenario} status drift"
        );
        assert!(report.contains("\"status\":\"FAIL\""));
        if scenario == "child-assertion" {
            assert!(report.contains("\"exit_code\":1"));
        } else if scenario == "child-nonzero" {
            assert!(report.contains("\"exit_code\":101"));
        }
    }
    fs::remove_dir_all(fake_dir).unwrap();
}

fn p11_sha256_from_bytes(bytes: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!("rivetlua-p11-sha-input-{}", std::process::id()));
    fs::write(&path, bytes).unwrap();
    let hash = p11_sha256(&path);
    fs::remove_file(path).unwrap();
    hash
}

#[test]
fn p11_gate_produces_all_formal_case_reports() {
    let _guard = CLI_TEST_LOCK.lock().unwrap();
    let root = workspace_root();
    ensure_prerequisite_reports(root, "P10");
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P11.json");
    let _previous_cases = RestoreP11Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());
    stamp_prerequisite_reports_for_negative_test(root, "P10");
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P11"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P11 gate 應產生 32 份 formal case：stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let cases = fs::read_dir(&report_dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("P11-"))
        .count();
    assert_eq!(cases, 32, "P11 gate 必須產生恰好 32 份 case JSON");
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='PASS'; assert isinstance(r.get('checks'),list) and all(c.get('status')=='PASS' and isinstance(c.get('exit_code'),int) for c in r['checks']); assert sum(c['name'].startswith(('ERR-','COR-','CLOSE-')) for c in r['checks'])==32",
        ])
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P11 PASS aggregate 欄位無效：{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

fn assert_no_p12_case_reports(report_dir: &Path) {
    for entry in fs::read_dir(report_dir).unwrap().flatten() {
        assert!(
            !entry.file_name().to_string_lossy().starts_with("P12-"),
            "P12 failure retained a stale case report: {}",
            entry.path().display()
        );
    }
}

struct RestoreP12Cases {
    report_dir: PathBuf,
    reports: Vec<(PathBuf, Vec<u8>)>,
}

impl RestoreP12Cases {
    fn new(report_dir: &Path) -> Self {
        let reports = fs::read_dir(report_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("P12-"))
            .filter(|entry| entry.path().is_file())
            .map(|entry| (entry.path(), fs::read(entry.path()).unwrap()))
            .collect();
        Self {
            report_dir: report_dir.to_path_buf(),
            reports,
        }
    }
}

impl Drop for RestoreP12Cases {
    fn drop(&mut self) {
        let preserved: std::collections::HashSet<_> =
            self.reports.iter().map(|(path, _)| path.clone()).collect();
        for entry in fs::read_dir(&self.report_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            if entry.file_name().to_string_lossy().starts_with("P12-")
                && !preserved.contains(&entry.path())
            {
                if entry.path().is_dir() {
                    fs::remove_dir_all(entry.path()).unwrap();
                } else {
                    fs::remove_file(entry.path()).unwrap();
                }
            }
        }
        for (path, contents) in &self.reports {
            fs::write(path, contents).unwrap();
        }
    }
}

struct RestoreP12Prerequisites {
    reports: Vec<(PathBuf, Vec<u8>)>,
}

impl RestoreP12Prerequisites {
    fn new(report_dir: &Path) -> Self {
        let reports = (0..=11)
            .map(|phase| report_dir.join(format!("gate-P{phase:02}.json")))
            .filter(|path| path.exists())
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();
        Self { reports }
    }
}

impl Drop for RestoreP12Prerequisites {
    fn drop(&mut self) {
        for (path, contents) in &self.reports {
            fs::write(path, contents).unwrap();
        }
    }
}

fn make_p12_fake_cargo(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let fake = directory.join("cargo");
    fs::write(
        &fake,
        r##"#!/usr/bin/env python3
import os, pathlib, sys
scenario = os.environ.get('RIVETLUA_P12_FAKE', 'valid')
log = os.environ.get('RIVETLUA_P12_CHILD_LOG')
args = sys.argv[1:]
is_lib = '--lib' in args
is_reentry = any('p12_5_reentrant_gc_is_rejected_without_losing_queue' in arg for arg in args)
profile = os.environ.get('RIVETLUA_P12_PROFILE', '')
if log:
    if is_lib:
        label = 'reentry' if is_reentry else 'unit'
    elif '--test' in args:
        label = profile + ':' + args[args.index('--test') + 2]
    else:
        label = 'filter:' + args[args.index('rivetlua-runtime') + 1]
    with open(log, 'a', encoding='utf-8') as stream:
        stream.write(label + '\n')
if is_lib and is_reentry:
    if scenario == 'reentry-fail':
        print('test result: FAILED. 0 passed; 1 failed')
        raise SystemExit(101)
    print('test vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue ... ok')
    print('test result: ok. 1 passed; 0 failed; 176 filtered out; finished in 0.00s')
    raise SystemExit(0)
if is_lib:
    count = 0 if scenario == 'unit-zero' else 46
    print(f'test result: ok. {count} passed; 0 failed; {177-count} filtered out; finished in 0.00s')
    raise SystemExit(1 if scenario == 'unit-fail' else 0)
if '--test' not in args:
    if scenario == 'filter-fail' and args[args.index('rivetlua-runtime') + 1] == 'gc':
        print('filter child failed')
        raise SystemExit(2)
    count = 0 if scenario == 'filter-zero' else 2
    print(f'test result: ok. {count} passed; 0 failed; 100 filtered out; finished in 0.00s')
    raise SystemExit(0)
if scenario == 'case-fail':
    print('formal child failed')
    print('test result: FAILED. 0 passed; 1 failed')
    raise SystemExit(101)
test_name = args[args.index('--test') + 2]
fixture = pathlib.Path('tests/p12/gc-cases.fixture').read_text(encoding='utf-8').splitlines()
fields = next(line.split('|') for line in fixture if line.startswith('case|') and line.split('|')[1] == profile and line.split('|')[4] == test_name)
case_id, marker, actual = fields[2], fields[5], fields[6]
count = 0 if scenario == 'case-zero' else (2 if scenario == 'case-extra' else 1)
print(f'test result: ok. {count} passed; 0 failed; {100-count} filtered out; finished in 0.00s')
if scenario == 'missing-marker':
    raise SystemExit(0)
if scenario == 'unknown-marker':
    case_id = 'GC-UNKNOWN'
if scenario == 'wrong-actual':
    actual = 'wrong=actual'
if scenario == 'cross-profile':
    profile = 'lua54-i64f64' if profile == 'lua55-i64f64' else 'lua55-i64f64'
line = f'P12_CASE\t{case_id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted-by-fake-formal-case'
if scenario == 'report-write-fail':
    pathlib.Path('target/rivetlua-reports/P12-GC-001-lua55.json').mkdir(parents=True, exist_ok=True)
print(line)
if scenario == 'duplicate-marker':
    print(line)
"##,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fake
}

fn assert_p12_gate_failure(
    root: &Path,
    report_dir: &Path,
    report_path: &Path,
    fake_cargo_dir: &Path,
    scenario: &str,
    child_log: &Path,
    expected_check: &str,
    expected_diagnostic: &str,
    expect_child: bool,
) -> String {
    stamp_prerequisite_reports_for_negative_test(root, "P11");
    fs::write(
        report_dir.join("P12-GC-001-lua55.json"),
        b"{\"status\":\"PASS\"}\n",
    )
    .unwrap();
    let fake_path = std::env::join_paths(
        std::iter::once(fake_cargo_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .env("PATH", fake_path)
        .env("RIVETLUA_P12_FAKE", scenario)
        .env("RIVETLUA_P12_CHILD_LOG", child_log)
        .args(["gate", "P12"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "P12 negative scenario {scenario} unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_gate_report_is_json(report_path);
    assert_no_p12_case_reports(report_dir);
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,re,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL'; assert re.fullmatch('[0-9a-f]{64}',r.get('source_digest','')); assert isinstance(r.get('checks'),list) and r['checks']; required={'name','command','exit_code','status','diagnostic','report_path'}; assert all(required <= c.keys() for c in r['checks']); assert any(c['status']=='FAIL' and isinstance(c['exit_code'],int) and c['exit_code'] != 0 and c['command'] and c['diagnostic'] and c['report_path'] for c in r['checks'])",
        ])
        .arg(report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P12 FAIL JSON schema invalid: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let report = fs::read_to_string(report_path).unwrap();
    assert!(
        report.contains(expected_check),
        "{scenario}: missing check {expected_check}"
    );
    assert!(
        report.contains(expected_diagnostic),
        "{scenario}: missing diagnostic {expected_diagnostic}"
    );
    if expect_child {
        assert!(
            child_log.exists(),
            "{scenario} did not invoke fake child commands"
        );
        let children = fs::read_to_string(child_log).unwrap();
        assert!(
            children.contains("unit"),
            "{scenario}: missing runtime unit command: {children}"
        );
        for filter in [
            "gc",
            "weak",
            "ephemeron",
            "finalizer",
            "allocation_failure",
            "vm_lifecycle",
        ] {
            assert!(
                children.contains(&format!("filter:{filter}")),
                "{scenario}: missing filter {filter}: {children}"
            );
        }
        assert!(
            children.contains("reentry"),
            "{scenario}: missing GC-009 reentry unit: {children}"
        );
    } else if scenario == "valid" {
        assert!(
            !child_log.exists(),
            "{scenario} unexpectedly started a child command"
        );
    }
    report
}

#[test]
fn p12_fake_reentry_failure_matches_exact_module_filter() {
    let fake_dir =
        std::env::temp_dir().join(format!("rivetlua-p12-fake-reentry-{}", std::process::id()));
    let fake_cargo = make_p12_fake_cargo(&fake_dir);
    let child_log = fake_dir.join("child.log");
    let output = Command::new(fake_cargo)
        .env("RIVETLUA_P12_FAKE", "reentry-fail")
        .env("RIVETLUA_P12_CHILD_LOG", &child_log)
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue",
            "--",
            "--exact",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(101));
    assert!(String::from_utf8_lossy(&output.stdout).contains("test result: FAILED"));
    assert_eq!(fs::read_to_string(child_log).unwrap(), "reentry\n");
    fs::remove_dir_all(fake_dir).unwrap();
}

#[test]
fn p12_gate_produces_twenty_unique_formal_case_reports() {
    let _guard = CLI_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = workspace_root();
    ensure_p12_prerequisite_reports(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P12.json");
    let _previous_cases = RestoreP12Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());
    let _previous_prerequisites = RestoreP12Prerequisites::new(&report_dir);
    stamp_prerequisite_reports_for_negative_test(root, "P11");
    let output = Command::new(BIN)
        .current_dir(root)
        .args(["gate", "P12"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P12 gate 應產生 20 份 formal case：stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let names: std::collections::HashSet<_> = fs::read_dir(&report_dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("P12-GC-"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 20, "P12 必須有恰好 20 份 unique case JSON");
    let checked = Command::new("python3")
        .args([
            "-c",
            "import json,re,pathlib,sys; p=pathlib.Path(sys.argv[1]); r=json.loads(p.read_text()); assert r['status']=='PASS'; assert re.fullmatch('[0-9a-f]{64}',r['source_digest']); assert isinstance(r.get('checks'),list) and all(c.get('status')=='PASS' and c.get('exit_code')==0 for c in r['checks']); cases=[c for c in r['checks'] if c['name'].startswith('GC-')]; assert len(cases)==20 and len({c['name'] for c in cases})==20; assert sum(c['name']=='p12-reentry-unit' and 'exact runtime unit vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue' in c['diagnostic'] for c in r['checks'])==1; reports=list(p.parent.glob('P12-GC-*.json')); assert len(reports)==20; assert all(json.loads(x.read_text())['status']=='PASS' and json.loads(x.read_text())['source_digest']==r['source_digest'] for x in reports)",
        ])
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "P12 PASS aggregate invalid: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    for profile in ["lua55", "lua54"] {
        let report =
            fs::read_to_string(report_dir.join(format!("P12-GC-009-{profile}.json"))).unwrap();
        assert!(report.contains("composite evidence: gc_case_009 yield/error assertions plus exact runtime unit vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue PASS"));
        assert!(report.contains("the formal case itself does not execute GC reentry"));
    }
}

#[test]
fn p12_gate_rejects_invalid_fixture_csv_and_child_evidence() {
    let _guard = CLI_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = workspace_root();
    ensure_p12_prerequisite_reports(root);
    let report_dir = root.join("target/rivetlua-reports");
    let report_path = report_dir.join("gate-P12.json");
    let _previous_cases = RestoreP12Cases::new(&report_dir);
    let _previous_aggregate = RestoreBytes::new(report_path.clone());
    let _previous_prerequisites = RestoreP12Prerequisites::new(&report_dir);
    let fixture_path = root.join("tests/p12/gc-cases.fixture");
    let csv_path = root.join("spec/compatibility.csv");
    let fixture_original = fs::read(&fixture_path).unwrap();
    let csv_original = fs::read(&csv_path).unwrap();
    let _restore_fixture = RestoreBytes::new(fixture_path.clone());
    let _restore_csv = RestoreBytes::new(csv_path.clone());
    let fixture_text = String::from_utf8(fixture_original.clone()).unwrap();
    let csv_text = String::from_utf8(csv_original.clone()).unwrap();
    let status_original = git_status_snapshot(root);
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p12-cli-{}", std::process::id()));
    let fake_cargo = make_p12_fake_cargo(&fake_dir);
    let fake_cargo_dir = fake_cargo.parent().unwrap();
    let child_log = fake_dir.join("child.log");

    let p11_path = report_dir.join("gate-P11.json");
    let p11_original = fs::read(&p11_path).unwrap();
    let digest = current_source_digest(root);
    let stale_p11 = String::from_utf8(p11_original.clone())
        .unwrap()
        .replace(&digest, &format!("{}", "0".repeat(64)));
    assert_ne!(stale_p11.as_bytes(), p11_original.as_slice());
    fs::write(&p11_path, stale_p11).unwrap();
    fs::write(
        report_dir.join("P12-GC-001-lua55.json"),
        b"{\"status\":\"PASS\"}\n",
    )
    .unwrap();
    let no_child_path = std::env::join_paths(
        std::iter::once(fake_cargo_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let stale_output = Command::new(BIN)
        .current_dir(root)
        .env("PATH", no_child_path)
        .env("RIVETLUA_P12_FAKE", "valid")
        .env("RIVETLUA_P12_CHILD_LOG", &child_log)
        .args(["gate", "P12"])
        .output()
        .unwrap();
    assert!(
        !stale_output.status.success(),
        "P12 accepted stale P11 digest"
    );
    assert_gate_report_is_json(&report_path);
    assert_no_p12_case_reports(&report_dir);
    assert!(
        !child_log.exists(),
        "stale prerequisite started a runtime child"
    );
    assert!(
        fs::read_to_string(&report_path)
            .unwrap()
            .contains("source_digest 已過期")
    );
    fs::write(&p11_path, &p11_original).unwrap();

    let p11_saved = fs::read(&p11_path).unwrap();
    fs::remove_file(&p11_path).unwrap();
    let missing_p11_output = Command::new(BIN)
        .current_dir(root)
        .env(
            "PATH",
            std::env::join_paths(
                std::iter::once(fake_cargo_dir.to_path_buf())
                    .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
            )
            .unwrap(),
        )
        .env("RIVETLUA_P12_FAKE", "valid")
        .env("RIVETLUA_P12_CHILD_LOG", &child_log)
        .args(["gate", "P12"])
        .output()
        .unwrap();
    assert!(
        !missing_p11_output.status.success(),
        "P12 accepted missing P11 report"
    );
    assert_gate_report_is_json(&report_path);
    assert_no_p12_case_reports(&report_dir);
    assert!(
        !child_log.exists(),
        "missing prerequisite started a runtime child"
    );
    assert!(
        fs::read_to_string(&report_path)
            .unwrap()
            .contains("缺少 P11 前置 gate 報告")
    );
    fs::write(&p11_path, p11_saved).unwrap();

    let gc001 = fixture_text
        .lines()
        .find(|line| line.starts_with("case|lua55-i64f64|GC-001|"))
        .unwrap()
        .to_owned();
    let missing_gc001 = fixture_text
        .lines()
        .filter(|line| !line.starts_with("case|lua55-i64f64|GC-001|"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let fixture_mutations = [
        missing_gc001,
        format!("{fixture_text}{gc001}\n"),
        fixture_text.replace("profile|lua54-i64f64|lua54\n", ""),
        fixture_text.replacen("case|lua55-i64f64|GC-001|", "case|lua54-i64f64|GC-001|", 1),
        fixture_text.replacen(
            "case|lua55-i64f64|GC-001|",
            "case|lua55-i64f64|GC-UNKNOWN|",
            1,
        ),
        fixture_text.replacen(
            "case|lua55-i64f64|GC-001|",
            "broken|lua55-i64f64|GC-001|",
            1,
        ),
    ];
    for mutation in fixture_mutations {
        let before_csv = p11_sha256(&csv_path);
        let before_status = git_status_snapshot(root);
        fs::write(&fixture_path, mutation.as_bytes()).unwrap();
        let _ = fs::remove_file(&child_log);
        let report = assert_p12_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
            "p12-fixture",
            "fixture",
            false,
        );
        assert!(report.contains("p12-fixture"));
        fs::write(&fixture_path, &fixture_original).unwrap();
        assert_eq!(
            p11_sha256(&fixture_path),
            p11_sha256_from_bytes(&fixture_original)
        );
        assert_eq!(p11_sha256(&csv_path), before_csv);
        assert_eq!(git_status_snapshot(root), before_status);
    }
    fs::remove_file(&fixture_path).unwrap();
    let _ = fs::remove_file(&child_log);
    let missing_fixture = assert_p12_gate_failure(
        root,
        &report_dir,
        &report_path,
        fake_cargo_dir,
        "valid",
        &child_log,
        "p12-fixture",
        "No such file",
        false,
    );
    assert!(missing_fixture.contains("p12-fixture"));
    fs::write(&fixture_path, &fixture_original).unwrap();

    let row55 = csv_text
        .lines()
        .find(|line| line.starts_with("p12.gc-complete,lua55,"))
        .unwrap()
        .to_owned();
    let no_p12_rows = csv_text
        .lines()
        .filter(|line| !line.starts_with("p12."))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let csv_mutations = [
        csv_text.replacen(&row55, row55.trim_end_matches(','), 1),
        no_p12_rows,
        csv_text.replace("p12.gc-complete,lua55,", "p12.other,lua55,"),
        csv_text.replace("p12.gc-complete,lua54,", "p12.gc-complete,common,"),
        format!("{csv_text}{row55}\n"),
    ];
    for mutation in csv_mutations {
        let before_fixture = p11_sha256(&fixture_path);
        let before_status = git_status_snapshot(root);
        fs::write(&csv_path, mutation.as_bytes()).unwrap();
        let _ = fs::remove_file(&child_log);
        let report = assert_p12_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            "valid",
            &child_log,
            "p12-csv",
            "CSV",
            false,
        );
        assert!(report.contains("p12-csv"));
        fs::write(&csv_path, &csv_original).unwrap();
        assert_eq!(p11_sha256(&fixture_path), before_fixture);
        assert_eq!(p11_sha256(&csv_path), p11_sha256_from_bytes(&csv_original));
        assert_eq!(git_status_snapshot(root), before_status);
    }
    fs::remove_file(&csv_path).unwrap();
    let _ = fs::remove_file(&child_log);
    let missing_csv = assert_p12_gate_failure(
        root,
        &report_dir,
        &report_path,
        fake_cargo_dir,
        "valid",
        &child_log,
        "p12-csv",
        "No such file",
        false,
    );
    assert!(missing_csv.contains("p12-csv"));
    fs::write(&csv_path, &csv_original).unwrap();

    for (scenario, expected_check, expected_diagnostic, child) in [
        ("unit-fail", "p12-runtime-unit", "實際 exit=1", false),
        ("unit-zero", "p12-runtime-unit", "匹配非零", false),
        ("filter-fail", "p12-filter-gc", "實際 exit=2", false),
        (
            "filter-zero",
            "p12-filter-gc",
            "必須至少匹配一個測試",
            false,
        ),
        ("reentry-fail", "p12-reentry-unit", "實際 exit=101", false),
        ("case-fail", "GC-001-lua55", "實際 exit=101", true),
        ("case-zero", "GC-001-lua55", "精確通過 1 個測試", true),
        ("case-extra", "GC-001-lua55", "精確通過 1 個測試", true),
        ("missing-marker", "GC-001-lua55", "marker 數錯誤", true),
        ("duplicate-marker", "GC-001-lua55", "marker 數錯誤", true),
        ("unknown-marker", "GC-001-lua55", "未知 formal marker", true),
        ("cross-profile", "GC-001-lua55", "profile 錯誤", true),
        ("wrong-actual", "GC-001-lua55", "實際結果不符", true),
        (
            "report-write-fail",
            "GC-001-lua55",
            "寫入 P12 case report 失敗",
            true,
        ),
    ] {
        let _ = fs::remove_file(&child_log);
        let before_fixture = p11_sha256(&fixture_path);
        let before_csv = p11_sha256(&csv_path);
        let report = assert_p12_gate_failure(
            root,
            &report_dir,
            &report_path,
            fake_cargo_dir,
            scenario,
            &child_log,
            expected_check,
            expected_diagnostic,
            child,
        );
        assert!(report.contains("\"status\":\"FAIL\""));
        assert_eq!(
            p11_sha256(&fixture_path),
            before_fixture,
            "{scenario} fixture byte drift"
        );
        assert_eq!(
            p11_sha256(&csv_path),
            before_csv,
            "{scenario} CSV byte drift"
        );
        assert_eq!(
            git_status_snapshot(root),
            status_original,
            "{scenario} Git status drift"
        );
    }
    fs::remove_dir_all(fake_dir).unwrap();
}

struct RestoreP13State {
    report_dir: PathBuf,
    preserved_p13: std::collections::HashSet<PathBuf>,
    paths: Vec<RestoreBytes>,
}

impl RestoreP13State {
    fn new(root: &Path) -> Self {
        let report_dir = root.join("target/rivetlua-reports");
        fs::create_dir_all(&report_dir).unwrap();
        let preserved_p13: std::collections::HashSet<_> = fs::read_dir(&report_dir)
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("P13-"))
            })
            .collect();
        let mut paths = Vec::new();
        for number in 0..=13 {
            paths.push(RestoreBytes::new(
                report_dir.join(format!("gate-P{number:02}.json")),
            ));
        }
        for number in 1..=10 {
            for profile in ["lua55", "lua54"] {
                paths.push(RestoreBytes::new(
                    report_dir.join(format!("P12-GC-{number:03}-{profile}.json")),
                ));
            }
        }
        for path in &preserved_p13 {
            if path.is_file() {
                paths.push(RestoreBytes::new(path.clone()));
            }
        }
        paths.push(RestoreBytes::new(root.join("target/gate-P13-fail.json")));
        paths.push(RestoreBytes::new(root.join("tests/p13/lib-cases.fixture")));
        paths.push(RestoreBytes::new(root.join("spec/compatibility.csv")));
        Self {
            report_dir,
            preserved_p13,
            paths,
        }
    }
}

impl Drop for RestoreP13State {
    fn drop(&mut self) {
        for entry in fs::read_dir(&self.report_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            if entry.file_name().to_string_lossy().starts_with("P13-")
                && !self.preserved_p13.contains(&path)
            {
                if path.is_dir() {
                    fs::remove_dir_all(path).unwrap();
                } else {
                    fs::remove_file(path).unwrap();
                }
            }
        }
    }
}

fn stamp_p13_prerequisites(root: &Path) {
    let digest = current_source_digest(root);
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); digest=sys.argv[2]
reports=root/'target/rivetlua-reports'; reports.mkdir(parents=True,exist_ok=True)
def check(name):
    return dict(name=name,command='synthetic P13 CLI protocol prerequisite',exit_code=0,status='PASS',diagnostic='isolated CLI fixture',report_path='target/rivetlua-reports/fixture.json')
expected_failures={
    'P00-SUP-001': ('rivetlua-xtask runner --profile lua55 --case P00-SUP-001','target/rivetlua-reports/P00-SUP-001-lua55.json'),
    'P00-REF-003': ('rivetlua-xtask runner --profile lua55 --case P00-REF-003','target/rivetlua-reports/P00-REF-003-lua55.json'),
    'P00-RUN-003': ('rivetlua-xtask runner --profile lua55 --case P00-RUN-003','target/rivetlua-reports/P00-RUN-003-lua55.json'),
    'P00-RUN-004': ('rivetlua-xtask runner --profile lua55 --case P00-RUN-004','target/rivetlua-reports/P00-RUN-004-lua55.json'),
    'P00-ABI-004': ('abi_evidence_check tests/abi/fixtures/incomplete-evidence.json','tests/abi/fixtures/incomplete-evidence.json'),
    'P00-ABI-005': ('abi_evidence_check tests/abi/fixtures/unsafe-accepted.md','tests/abi/fixtures/unsafe-accepted.md'),
}
for number in range(13):
    checks=[check('smoke')]
    if number in (0,11):
        for name,(command,path) in expected_failures.items():
            item=check(('P00-' if number==11 else '')+name)
            item.update(command=command,report_path=path,exit_code=1)
            checks.append(item)
    if number in (3,11):
        for case_id in ('PARSE-001','PARSE-002','PARSE-003','PARSE-004','PARSE-005','PARSE-006',
                        'PARSE-ERR-001','PARSE-ERR-002','PARSE-ERR-003','PARSE-ERR-004'):
            for profile in ('lua55','lua54'):
                item=check(('P03-' if number==11 else '')+case_id)
                item.update(command='cargo test p03_contracts',
                            report_path=str(reports/f'P03-{case_id}-{profile}.json'))
                checks.append(item)
    if number==5:
        checks += [check(x) for x in ('p05-dependency-graph','p05-core-bytecode','p05-bytecode-contracts')]
        checks += [check(f'BC-{case:03}-{profile}') for case in range(1,11) for profile in ('lua55','lua54')]
    if number==7:
        checks += [check(x) for x in ('p01-before','p05-before','p06-before','p00-p06-before')]
    if number==12:
        checks += [check(x) for x in ('p12-runtime-unit','p12-reentry-unit')]
        checks += [check(f'p12-filter-{name}') for name in ('gc','weak','ephemeron','finalizer','allocation_failure','vm_lifecycle')]
        checks += [check(f'GC-{case:03}-{profile}') for case in range(1,11) for profile in ('lua55','lua54')]
    (reports/f'gate-P{number:02}.json').write_text(json.dumps(dict(status='PASS',source_digest=digest,checks=checks))+'\n')
fixture=(root/'tests/p12/gc-cases.fixture').read_text().splitlines()
for line in fixture:
    fields=line.split('|')
    if fields[0]!='case': continue
    _,fullprofile,case_id,mode,input_name,marker,expected,note=fields
    lua_profile=fullprofile.split('-')[0]
    report=dict(case_id=case_id,profile=fullprofile,lua_profile=lua_profile,mode=mode,input=input_name,
                expected=expected,actual=expected,status='PASS',exit_code=0,source_digest=digest,
                diagnostic=note,command='synthetic P13 CLI protocol prerequisite')
    (reports/f'P12-{case_id}-{lua_profile}.json').write_text(json.dumps(report)+'\n')
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P13 CLI prerequisite setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn make_p13_fake_cargo(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let fake = directory.join("cargo");
    fs::write(&fake, r##"#!/usr/bin/env python3
import os,pathlib,sys
args=sys.argv[1:]
scenario=os.environ.get('RIVETLUA_P13_FAKE','valid')
log=os.environ.get('RIVETLUA_P13_CHILD_LOG')
profile=os.environ.get('RIVETLUA_P13_PROFILE','')
name=args[args.index('--test')+2] if '--test' in args else 'unit'
if log:
    with open(log,'a') as stream: stream.write(f'{profile}:{name}\n')
if '--lib' in args:
    if scenario=='unit-fail':
        print('test result: FAILED. 0 passed; 1 failed; 0 ignored')
        raise SystemExit(101)
    count=0 if scenario=='unit-zero' else 3
    print(f'test result: ok. {count} passed; 0 failed; 0 ignored; 10 filtered out')
    raise SystemExit(0)
fixture=pathlib.Path('tests/p13/lib-cases.fixture').read_text().splitlines()
fields=next(line.split('|') for line in fixture if line.startswith('case|') and line.split('|')[1]==profile and line.split('|')[4]==name)
case_id,actual=fields[2],fields[6]
first=profile=='lua55-i64f64' and case_id=='LIB-001'
last=profile=='lua54-i64f64' and case_id=='LIB-014'
if scenario=='case-child-fail' and first:
    print('test result: FAILED. 0 passed; 1 failed; 0 ignored')
    raise SystemExit(101)
count=0 if scenario=='case-zero' and first else 2 if scenario=='case-two' and first else 1
ignored=1 if scenario=='case-ignored' and first else 0
if scenario=='marker-unknown' and first: case_id='LIB-999'
if scenario=='marker-profile' and first: profile='lua54-i64f64'
if scenario=='marker-wrong-actual' and first: actual='int:7,int:2'
marker=f'P13_CASE\t{case_id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted-by-fake\tcapability=host=deny\tfuel=initial=20,remaining=1\tallocation=reserved=0\tresource=roots=5'
if scenario=='marker-malformed' and first: marker=marker.replace('\tfuel=initial=20,remaining=1','')
if not (scenario=='marker-missing' and first): print(marker)
if scenario=='marker-duplicate' and first: print(marker)
print(f'test result: ok. {count} passed; 0 failed; {ignored} ignored; 13 filtered out')
reports=pathlib.Path('target/rivetlua-reports')
if scenario=='report-write-fail' and first:
    target=reports/'P13-LIB-001-lua55.json'; target.mkdir(exist_ok=True)
    (target/'block').write_text('preserve until test cleanup')
if scenario=='aggregate-write-fail' and last:
    target=reports/'gate-P13.json'; target.mkdir(exist_ok=True)
    (target/'block').write_text('preserve until test cleanup')
"##).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fake
}

fn run_p13_fake(
    root: &Path,
    fake_dir: &Path,
    scenario: &str,
    child_log: &Path,
) -> std::process::Output {
    let path = std::env::join_paths(
        std::iter::once(fake_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .env("RIVETLUA_P13_FAKE", scenario)
        .env("RIVETLUA_P13_CHILD_LOG", child_log)
        .args(["gate", "P13"])
        .output()
        .unwrap()
}

fn assert_p13_json(path: &Path, status: &str, digest: &str) {
    let script = r#"import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; digest=sys.argv[3]
r=json.loads(p.read_text())
assert r['status']==expected
assert r['source_digest']==digest and re.fullmatch(r'[0-9a-f]{64}',digest)
assert isinstance(r['checks'],list) and r['checks']
assert all({'name','command','exit_code','status','diagnostic','report_path'}<=c.keys() for c in r['checks'])
assert all(isinstance(c['exit_code'],int) and c['command'] and c['report_path'] for c in r['checks'])
assert any(c['status']=='FAIL' and c['exit_code']!=0 and c['diagnostic'] for c in r['checks']) if expected=='FAIL' else all(c['status']=='PASS' and c['exit_code']==0 for c in r['checks'])
cases=r['case_reports']
assert isinstance(cases,list)
if expected=='PASS':
    assert len(cases)==28 and len({(c['case_id'],c['lua_profile']) for c in cases})==28
else: assert not cases
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(path)
        .arg(status)
        .arg(digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P13 {status} JSON invalid {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_p13_case_files(report_dir: &Path) {
    for entry in fs::read_dir(report_dir).unwrap().map(Result::unwrap) {
        if entry.file_name().to_string_lossy().starts_with("P13-") {
            assert!(
                !entry.path().is_file(),
                "P13 FAIL retained case file {}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn p13_gate_fake_protocol_and_fail_closed_matrix() {
    let _guard = CLI_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = workspace_root();
    let initial_status = git_status_snapshot(root);
    let restore = RestoreP13State::new(root);
    let original_paths = restore
        .paths
        .iter()
        .map(|item| (item.path.clone(), item.contents.clone()))
        .collect::<Vec<_>>();
    let report_dir = root.join("target/rivetlua-reports");
    let fixture_path = root.join("tests/p13/lib-cases.fixture");
    let csv_path = root.join("spec/compatibility.csv");
    let fixture = fs::read(&fixture_path).unwrap();
    let csv = fs::read(&csv_path).unwrap();
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p13-cli-{}", std::process::id()));
    let _fake = make_p13_fake_cargo(&fake_dir);
    let child_log = fake_dir.join("child.log");

    stamp_p13_prerequisites(root);
    let digest = current_source_digest(root);
    let positive = run_p13_fake(root, &fake_dir, "valid", &child_log);
    assert!(
        positive.status.success(),
        "P13 fake protocol PASS failed: {}",
        String::from_utf8_lossy(&positive.stderr)
    );
    assert_p13_json(&report_dir.join("gate-P13.json"), "PASS", &digest);
    let case_files = fs::read_dir(&report_dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("P13-"))
        .count();
    assert_eq!(case_files, 28);
    let check = Command::new("python3").args(["-c", "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text()); assert c['status']=='PASS' and c['case_id']=='LIB-006' and c['lua_profile']=='lua54' and c['expected']=='size:StringArgument,budget:Heap(AllocationFailed)' and c['actual']==c['expected'] and all(c[k] for k in ('capability_policy','fuel_trace','allocation_trace','resource_trace','source_digest'))"]).arg(report_dir.join("P13-LIB-006-lua54.json")).output().unwrap();
    assert!(
        check.status.success(),
        "P13 case schema invalid: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(fs::read_to_string(&child_log).unwrap().lines().count() == 29);

    for number in 0..=12 {
        let phase = format!("P{number:02}");
        for mutation in ["missing", "fail", "invalid", "stale"] {
            stamp_p13_prerequisites(root);
            let path = report_dir.join(format!("gate-{phase}.json"));
            match mutation {
                "missing" => fs::remove_file(&path).unwrap(),
                "fail" => fs::write(&path, b"{\"status\":\"FAIL\"}\n").unwrap(),
                "invalid" => fs::write(&path, b"{").unwrap(),
                "stale" => {
                    let body = fs::read_to_string(&path).unwrap();
                    fs::write(&path, body.replace(&digest, &"0".repeat(64))).unwrap();
                }
                _ => unreachable!(),
            }
            let _ = fs::remove_file(&child_log);
            let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
            assert!(
                !output.status.success(),
                "{phase}/{mutation} prerequisite passed"
            );
            assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &digest);
            assert_no_p13_case_files(&report_dir);
            assert!(!child_log.exists(), "{phase}/{mutation} started child");
        }
    }
    for (phase, field, value) in [
        ("P00", "name", "P00-SUP-999"),
        ("P00", "exit_code", "0"),
        ("P00", "exit_code", "2"),
        ("P00", "command", "wrong command"),
        ("P00", "report_path", "wrong/report.json"),
        ("P11", "name", "P00-P00-SUP-999"),
        ("P02", "wrong_phase", "P00-SUP-001"),
    ] {
        stamp_p13_prerequisites(root);
        let path = report_dir.join(format!("gate-{phase}.json"));
        let script = r#"import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); field=sys.argv[2]; value=sys.argv[3]
r=json.loads(p.read_text())
if field=='wrong_phase':
    c=r['checks'][0]; c['name']=value; c['exit_code']=1
else:
    c=next(c for c in r['checks'] if c['exit_code']==1)
    c[field]=int(value) if field=='exit_code' else value
p.write_text(json.dumps(r)+'\n')
"#;
        let mutation = Command::new("python3")
            .args(["-c", script])
            .arg(&path)
            .args([field, value])
            .output()
            .unwrap();
        assert!(
            mutation.status.success(),
            "failed to mutate {phase}/{field}: {}",
            String::from_utf8_lossy(&mutation.stderr)
        );
        let _ = fs::remove_file(&child_log);
        let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
        assert!(
            !output.status.success(),
            "{phase}/{field} exception mutation passed"
        );
        assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &digest);
        assert_no_p13_case_files(&report_dir);
        assert!(!child_log.exists(), "{phase}/{field} started child");
    }
    for phase in ["P03", "P11"] {
        for mutation in [
            "duplicate_profile",
            "missing_profile",
            "wrong_profile",
            "wrong_path",
            "wrong_root",
            "wrong_command",
            "unknown_id",
        ] {
            stamp_p13_prerequisites(root);
            let path = report_dir.join(format!("gate-{phase}.json"));
            let script = r#"import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); phase=sys.argv[2]; mutation=sys.argv[3]
r=json.loads(p.read_text()); name=('P03-' if phase=='P11' else '')+'PARSE-001'
cases=[c for c in r['checks'] if c['name']==name]
assert len(cases)==2
left=next(c for c in cases if c['report_path'].endswith('-lua55.json'))
right=next(c for c in cases if c['report_path'].endswith('-lua54.json'))
if mutation=='duplicate_profile': right['report_path']=left['report_path']
elif mutation=='missing_profile': r['checks'].remove(right)
elif mutation=='wrong_profile': right['report_path']=right['report_path'].replace('-lua54.json','-lua53.json')
elif mutation=='wrong_path': right['report_path']=right['report_path'].replace('PARSE-001','PARSE-002')
elif mutation=='wrong_root': right['report_path']='/tmp/rivetlua-p13-wrong-root/P03-PARSE-001-lua54.json'
elif mutation=='wrong_command': right['command']='cargo test wrong'
elif mutation=='unknown_id': right['name']=('P03-' if phase=='P11' else '')+'PARSE-UNKNOWN'
else: raise AssertionError(mutation)
p.write_text(json.dumps(r)+'\n')
"#;
            let injected = Command::new("python3")
                .args(["-c", script])
                .arg(&path)
                .args([phase, mutation])
                .output()
                .unwrap();
            assert!(
                injected.status.success(),
                "{phase}/{mutation} 注入失敗：{}",
                String::from_utf8_lossy(&injected.stderr)
            );
            let _ = fs::remove_file(&child_log);
            let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
            assert!(
                !output.status.success(),
                "{phase}/{mutation} 前置異常意外通過"
            );
            assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &digest);
            assert_no_p13_case_files(&report_dir);
            assert!(!child_log.exists(), "{phase}/{mutation} 啟動了 child");
            assert_eq!(fs::read(&fixture_path).unwrap(), fixture);
            assert_eq!(fs::read(&csv_path).unwrap(), csv);
            assert_eq!(git_status_snapshot(root), initial_status);
        }
    }
    stamp_p13_prerequisites(root);
    let generic = report_dir.join("gate-P02.json");
    let body = fs::read_to_string(&generic).unwrap();
    let duplicated = body.replacen("\"checks\": [", "\"checks\": [{\"name\": \"smoke\", \"command\": \"synthetic\", \"exit_code\": 0, \"status\": \"PASS\", \"diagnostic\": \"duplicate\", \"report_path\": \"report\"}, ", 1);
    assert_ne!(duplicated, body);
    fs::write(&generic, duplicated).unwrap();
    let _ = fs::remove_file(&child_log);
    let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
    assert!(!output.status.success(), "P02 generic check 重複意外通過");
    assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &digest);
    assert_no_p13_case_files(&report_dir);
    assert!(!child_log.exists(), "P02 generic check 重複啟動了 child");
    for mutation in ["missing", "fail", "invalid", "stale"] {
        stamp_p13_prerequisites(root);
        let path = report_dir.join("P12-GC-001-lua55.json");
        match mutation {
            "missing" => fs::remove_file(&path).unwrap(),
            "fail" => {
                let body = fs::read_to_string(&path).unwrap();
                fs::write(
                    &path,
                    body.replace("\"status\": \"PASS\"", "\"status\": \"FAIL\""),
                )
                .unwrap();
            }
            "invalid" => fs::write(&path, b"{").unwrap(),
            "stale" => {
                let body = fs::read_to_string(&path).unwrap();
                fs::write(&path, body.replace(&digest, &"0".repeat(64))).unwrap();
            }
            _ => unreachable!(),
        }
        let _ = fs::remove_file(&child_log);
        let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
        assert!(
            !output.status.success(),
            "P12 case prerequisite {mutation} passed"
        );
        assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &digest);
        assert_no_p13_case_files(&report_dir);
        assert!(!child_log.exists(), "P12 case {mutation} started child");
    }

    let fixture_text = String::from_utf8(fixture.clone()).unwrap();
    let first = fixture_text
        .lines()
        .find(|line| line.starts_with("case|lua55-i64f64|LIB-001|"))
        .unwrap();
    let fixture_mutations = [
        fixture_text.replacen(&format!("{first}\n"), "", 1),
        format!("{fixture_text}{first}\n"),
        fixture_text.replacen(
            "case|lua55-i64f64|LIB-001|",
            "case|lua55-i64f64|LIB-999|",
            1,
        ),
        fixture_text.replacen(
            "profile|lua54-i64f64|lua54",
            "profile|lua54-i64f64|lua55",
            1,
        ),
        fixture_text.replacen("int:6,int:2", "int:7,int:2", 1),
        fixture_text.replacen(
            "case|lua55-i64f64|LIB-001|",
            "broken|lua55-i64f64|LIB-001|",
            1,
        ),
    ];
    for mutation in fixture_mutations {
        fs::write(&fixture_path, mutation).unwrap();
        stamp_p13_prerequisites(root);
        let current = current_source_digest(root);
        let _ = fs::remove_file(&child_log);
        let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
        assert!(!output.status.success(), "malformed fixture passed");
        assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &current);
        assert_no_p13_case_files(&report_dir);
        assert!(!child_log.exists(), "malformed fixture started child");
        fs::write(&fixture_path, &fixture).unwrap();
        assert_eq!(fs::read(&fixture_path).unwrap(), fixture);
        assert_eq!(git_status_snapshot(root), initial_status);
    }
    let csv_text = String::from_utf8(csv.clone()).unwrap();
    let row = csv_text
        .lines()
        .find(|line| line.starts_with("p13.stdlib-modules,lua55,"))
        .unwrap();
    let csv_mutations = [
        csv_text.replacen(&format!("{row}\n"), "", 1),
        format!("{csv_text}{row}\n"),
        csv_text.replacen("p13.stdlib-modules,lua55,", "p13.other,lua55,", 1),
        csv_text.replacen("p13.stdlib-modules,lua54,", "p13.stdlib-modules,common,", 1),
        csv_text.replacen(row, row.trim_end_matches(','), 1),
    ];
    for mutation in csv_mutations {
        fs::write(&csv_path, mutation).unwrap();
        stamp_p13_prerequisites(root);
        let current = current_source_digest(root);
        let _ = fs::remove_file(&child_log);
        let output = run_p13_fake(root, &fake_dir, "valid", &child_log);
        assert!(!output.status.success(), "malformed CSV passed");
        assert_p13_json(&report_dir.join("gate-P13.json"), "FAIL", &current);
        assert_no_p13_case_files(&report_dir);
        assert!(!child_log.exists(), "malformed CSV started child");
        fs::write(&csv_path, &csv).unwrap();
        assert_eq!(fs::read(&csv_path).unwrap(), csv);
        assert_eq!(git_status_snapshot(root), initial_status);
    }

    for scenario in [
        "unit-fail",
        "unit-zero",
        "case-child-fail",
        "case-zero",
        "case-two",
        "case-ignored",
        "marker-missing",
        "marker-duplicate",
        "marker-unknown",
        "marker-profile",
        "marker-wrong-actual",
        "marker-malformed",
        "report-write-fail",
        "aggregate-write-fail",
    ] {
        stamp_p13_prerequisites(root);
        let _ = fs::remove_file(&child_log);
        let output = run_p13_fake(root, &fake_dir, scenario, &child_log);
        assert!(!output.status.success(), "{scenario} unexpectedly passed");
        let gate = report_dir.join("gate-P13.json");
        let fallback = root.join("target/gate-P13-fail.json");
        assert_p13_json(
            if scenario == "aggregate-write-fail" {
                &fallback
            } else {
                &gate
            },
            "FAIL",
            &digest,
        );
        assert_no_p13_case_files(&report_dir);
        assert!(child_log.exists(), "{scenario} did not start child");
        if scenario == "report-write-fail" {
            fs::remove_dir_all(report_dir.join("P13-LIB-001-lua55.json")).unwrap();
        }
        if scenario == "aggregate-write-fail" {
            fs::remove_dir_all(&gate).unwrap();
        }
        assert_eq!(fs::read(&fixture_path).unwrap(), fixture);
        assert_eq!(fs::read(&csv_path).unwrap(), csv);
        assert_eq!(git_status_snapshot(root), initial_status);
    }
    fs::remove_dir_all(fake_dir).unwrap();
    drop(restore);
    for (path, contents) in original_paths {
        assert_eq!(
            fs::read(&path).ok(),
            contents,
            "P13 CLI input/report was not restored: {}",
            path.display()
        );
    }
    assert_eq!(git_status_snapshot(root), initial_status);
}

struct RestoreP14State {
    _p13: RestoreP13State,
    report_dir: PathBuf,
    preserved_p14: std::collections::HashSet<PathBuf>,
    aggregate_paths: [(PathBuf, bool); 2],
    paths: Vec<RestoreBytes>,
}

impl RestoreP14State {
    fn new(root: &Path) -> Self {
        let p13 = RestoreP13State::new(root);
        let report_dir = root.join("target/rivetlua-reports");
        let preserved_p14: std::collections::HashSet<_> = fs::read_dir(&report_dir)
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("P14-"))
            })
            .collect();
        let aggregate_paths = [
            report_dir.join("gate-P14.json"),
            root.join("target/gate-P14-fail.json"),
        ]
        .map(|path| {
            let was_dir = path.is_dir();
            (path, was_dir)
        });
        let mut paths = vec![
            RestoreBytes::new(aggregate_paths[0].0.clone()),
            RestoreBytes::new(aggregate_paths[1].0.clone()),
            RestoreBytes::new(root.join("tests/p14/sdk-cases.fixture")),
        ];
        for path in &preserved_p14 {
            if path.is_file() {
                paths.push(RestoreBytes::new(path.clone()));
            }
        }
        Self {
            _p13: p13,
            report_dir,
            preserved_p14,
            aggregate_paths,
            paths,
        }
    }
}

impl Drop for RestoreP14State {
    fn drop(&mut self) {
        for (path, was_dir) in &self.aggregate_paths {
            if !was_dir && path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            }
        }
        for entry in fs::read_dir(&self.report_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            if entry.file_name().to_string_lossy().starts_with("P14-")
                && !self.preserved_p14.contains(&path)
            {
                if path.is_dir() {
                    fs::remove_dir_all(path).unwrap();
                } else {
                    fs::remove_file(path).unwrap();
                }
            }
        }
    }
}

#[test]
fn p14_restore_after_panic_removes_aggregate_blockers_and_restores_bytes() {
    let root = std::env::temp_dir().join(format!("rivetlua-p14-restore-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let reports = root.join("target/rivetlua-reports");
    fs::create_dir_all(&reports).unwrap();
    fs::create_dir_all(root.join("tests/p13")).unwrap();
    fs::create_dir_all(root.join("tests/p14")).unwrap();
    fs::create_dir_all(root.join("spec")).unwrap();
    let originals = [
        (
            root.join("spec/compatibility.csv"),
            b"original csv\n".as_slice(),
        ),
        (
            root.join("tests/p13/lib-cases.fixture"),
            b"original p13 fixture\n".as_slice(),
        ),
        (
            root.join("tests/p14/sdk-cases.fixture"),
            b"original p14 fixture\n".as_slice(),
        ),
        (
            reports.join("gate-P13.json"),
            b"original p13 report\n".as_slice(),
        ),
        (
            reports.join("gate-P14.json"),
            b"original p14 aggregate\n".as_slice(),
        ),
        (
            root.join("target/gate-P14-fail.json"),
            b"original p14 fallback\n".as_slice(),
        ),
    ];
    for (path, bytes) in &originals {
        fs::write(path, bytes).unwrap();
    }
    let panicked = std::panic::catch_unwind(|| {
        let _restore = RestoreP14State::new(&root);
        for (path, _) in &originals {
            fs::write(path, b"mutated").unwrap();
        }
        for path in [
            reports.join("gate-P14.json"),
            root.join("target/gate-P14-fail.json"),
        ] {
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            fs::write(path.join("block"), b"block").unwrap();
        }
        fs::create_dir(reports.join("P14-SDK-001-lua55.json")).unwrap();
        panic!("模擬 P14 負向驗證中途失敗");
    });
    assert!(panicked.is_err());
    for (path, bytes) in &originals {
        assert_eq!(fs::read(path).unwrap(), *bytes);
    }
    assert!(!reports.join("P14-SDK-001-lua55.json").exists());
    fs::remove_dir_all(root).unwrap();
}

fn stamp_p14_prerequisites(root: &Path) {
    stamp_p13_prerequisites(root);
    let digest = current_source_digest(root);
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); digest=sys.argv[2]
reports=root/'target/rivetlua-reports'
def check(name,command='synthetic P14 protocol prior',path='target/rivetlua-reports/fixture.json'):
    return dict(name=name,command=command,exit_code=0,status='PASS',diagnostic='isolated protocol fixture',report_path=path)
gate_path='target/rivetlua-reports/gate-P13.json'
checks=[check(f'P{number:02}-aggregate',f'validate {reports / f"gate-P{number:02}.json"}',gate_path) for number in range(13)]
fixed={
    'p13-dependencies':'validate spec/phase-dependencies.csv DA-09/14/18/19/20',
    'p13-csv':'validate spec/compatibility.csv',
    'p13-fixture':'validate tests/p13/lib-cases.fixture',
    'p13-runtime-unit':'cargo test --locked -p rivetlua-runtime --lib p13_ -- --test-threads=1',
    'p13-case-reports':'validate 28 unique P13 case JSON',
    'p13-source-digest':'verify source digest after children',
}
checks += [check(name,command,gate_path) for name,command in fixed.items()]
refs=[]
for line in (root/'tests/p13/lib-cases.fixture').read_text().splitlines():
    fields=line.split('|')
    if fields[0]!='case': continue
    _,profile,case_id,mode,input_name,marker,expected,note=fields
    lua_profile=profile.split('-')[0]
    path=f'target/rivetlua-reports/P13-{case_id}-{lua_profile}.json'
    command=f'RIVETLUA_P13_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p13_contracts {input_name} -- --nocapture --exact --test-threads=1'
    report=dict(case_id=case_id,lua_profile=lua_profile,profile=profile,fullprofile=profile,
                mode=mode,input=input_name,expected=expected,actual=expected,status='PASS',
                exit_code=0,command=command,report_path=path,diagnostic=note,
                capability_policy='host=deny',fuel_trace='fuel=observed',
                allocation_trace='reserved=0',resource_trace='roots=checked',source_digest=digest)
    (root/path).write_text(json.dumps(report)+'\n')
    checks.append(check(f'{case_id}-{lua_profile}',command,path))
    refs.append(dict(case_id=case_id,lua_profile=lua_profile,report_path=path))
(reports/'gate-P13.json').write_text(json.dumps(dict(status='PASS',source_digest=digest,checks=checks,case_reports=refs))+'\n')
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P14 synthetic prior 失敗：{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn make_p14_fake_cargo(directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let fake = directory.join("cargo");
    fs::write(&fake, r##"#!/usr/bin/env python3
import os,pathlib,sys
args=sys.argv[1:]
scenario=os.environ.get('RIVETLUA_P14_FAKE','valid')
profile=os.environ.get('RIVETLUA_P14_PROFILE','')
log=os.environ.get('RIVETLUA_P14_CHILD_LOG')
def record(name):
    if log:
        with open(log,'a') as stream: stream.write(f'{profile}:{name}\n')
if args[0]=='run':
    selected=args[-1]; record('example-'+selected)
    print(f'P14_EXAMPLE:{selected}:PASS')
    raise SystemExit(0)
if '--exact' not in args:
    selector=args[args.index('--')+1]
    record('filter-'+selector)
    if scenario=='filter-zero': count=0
    else: count={'sdk':52,'wrapper':13,'cli':38}[selector]
    print(f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured')
    raise SystemExit(0)
name=args[args.index('--test')+2]
record(name)
fixture=pathlib.Path('tests/p14/sdk-cases.fixture').read_text().splitlines()
fields=next(line.split('|') for line in fixture if line.startswith('case|') and line.split('|')[1]==profile and line.split('|')[4]==name)
case_id,actual=fields[2],fields[6]
first=profile=='lua55-i64f64' and case_id=='SDK-001'
last=profile=='lua54-i64f64' and case_id=='SDK-NEG-006'
if scenario=='child-fail' and first:
    print('test result: FAILED. 0 passed; 1 failed; 0 ignored')
    raise SystemExit(101)
if scenario=='source-change' and first:
    pathlib.Path('tests/p14/sdk-cases.fixture').write_text(pathlib.Path('tests/p14/sdk-cases.fixture').read_text()+'\n')
if scenario=='wrong-profile' and first: profile='lua54-i64f64'
if scenario=='wrong-id' and first: case_id='SDK-999'
if scenario=='wrong-actual' and first: actual='int:41'
marker=f'P14_CASE\t{case_id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted-by-fake\tallocation=reserved=0\tresource=roots=checked\tvm=isolated\tcli=checked'
if scenario=='malformed-marker' and first: marker=marker.replace('\tresource=roots=checked','')
if not (scenario=='missing-marker' and first): print(marker)
if scenario=='duplicate-marker' and first: print(marker)
count=0 if scenario=='zero-test' and first else 2 if scenario=='two-tests' and first else 1
ignored=1 if scenario=='ignored-test' and first else 0
if not (scenario=='missing-summary' and first):
    measured=1 if scenario=='measured-test' and first else 0
    print(f'test result: ok. {count} passed; 0 failed; {ignored} ignored; {measured} measured; 13 filtered out')
reports=pathlib.Path('target/rivetlua-reports')
if last and scenario in ('p13-check-after','p13-case-after'):
    if scenario=='p13-check-after':
        path=reports/'gate-P13.json'; document=__import__('json').loads(path.read_text())
        document['checks'][0]['command']='tampered by later child'
    else:
        path=reports/'P13-LIB-001-lua55.json'; document=__import__('json').loads(path.read_text())
        document['fuel_trace']='tampered by later child'
    path.write_text(__import__('json').dumps(document)+'\n')
if last and scenario in ('case-trace-after','case-metadata-after'):
    path=reports/'P14-SDK-001-lua55.json'; document=__import__('json').loads(path.read_text())
    if scenario=='case-trace-after': document['allocation_trace']='reserved=9'
    else: document['diagnostic']='tampered by later child'
    path.write_text(__import__('json').dumps(document)+'\n')
if scenario=='report-write-fail' and first:
    path=reports/'P14-SDK-001-lua55.json'; path.mkdir(exist_ok=True)
    (path/'block').write_text('keep')
if scenario=='extra-report' and last:
    (reports/'P14-SDK-999-lua54.json').write_text('{"status":"PASS"}')
if scenario=='aggregate-write-fail' and last:
    path=reports/'gate-P14.json'; path.mkdir(exist_ok=True)
    (path/'block').write_text('keep')
"##).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    fake
}

fn run_p14_fake(
    root: &Path,
    fake_dir: &Path,
    scenario: &str,
    child_log: &Path,
) -> std::process::Output {
    let path = std::env::join_paths(
        std::iter::once(fake_dir.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    Command::new(BIN)
        .current_dir(root)
        .env("PATH", path)
        .env("RIVETLUA_P14_FAKE", scenario)
        .env("RIVETLUA_P14_CHILD_LOG", child_log)
        .args(["gate", "P14"])
        .output()
        .unwrap()
}

fn assert_p14_fail_json(root: &Path, digest: &str, expected_name: &str) {
    let canonical = root.join("target/rivetlua-reports/gate-P14.json");
    let fallback = root.join("target/gate-P14-fail.json");
    let path = if canonical.is_file() {
        canonical
    } else {
        fallback
    };
    let script = r#"import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); digest=sys.argv[2]; name=sys.argv[3]
r=json.loads(p.read_text())
assert r['status']=='FAIL' and r['source_digest']==digest
assert r['case_reports']==[]
checks=r['checks']; assert checks and checks[-1]['name']==name
assert checks[-1]['status']=='FAIL' and checks[-1]['exit_code']!=0
assert checks[-1]['command'] and checks[-1]['diagnostic'] and checks[-1]['report_path']
"#;
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(&path)
        .arg(digest)
        .arg(expected_name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "P14 FAIL JSON {} 無效：{}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    for entry in fs::read_dir(root.join("target/rivetlua-reports")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("P14-") {
            assert!(
                !entry.path().is_file(),
                "FAIL 留下舊 P14 PASS 檔案：{}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn p14_gate_fake_protocol_and_fail_closed_matrix() {
    let _guard = CLI_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = workspace_root();
    let initial_status = git_status_snapshot(root);
    let restore = RestoreP14State::new(root);
    let original_paths = restore
        .paths
        .iter()
        .map(|item| (item.path.clone(), item.contents.clone()))
        .collect::<Vec<_>>();
    let report_dir = root.join("target/rivetlua-reports");
    let csv_path = root.join("spec/compatibility.csv");
    let csv_original = fs::read(&csv_path).unwrap();
    let fixture_path = root.join("tests/p14/sdk-cases.fixture");
    let fixture_original = fs::read(&fixture_path).unwrap();
    let mut csv_active = String::from_utf8(csv_original.clone()).unwrap();
    if !csv_active
        .lines()
        .any(|line| line.starts_with("p14.sdk-cli,lua55,"))
    {
        let ids = String::from_utf8(fixture_original.clone())
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("case|lua55-i64f64|"))
            .map(|line| line.split('|').nth(2).unwrap().to_owned())
            .collect::<Vec<_>>()
            .join(";");
        for profile in ["lua55", "lua54"] {
            csv_active.push_str(&format!("p14.sdk-cli,{profile},docs/plane/P14.md#6-正常與錯誤案例,rivetlua;rivetlua-cli,{ids},PASS,\n"));
        }
        fs::write(&csv_path, &csv_active).unwrap();
    }
    let fake_dir = std::env::temp_dir().join(format!("rivetlua-p14-cli-{}", std::process::id()));
    let _fake = make_p14_fake_cargo(&fake_dir);
    let child_log = fake_dir.join("child.log");

    stamp_p14_prerequisites(root);
    let digest = current_source_digest(root);
    let positive = run_p14_fake(root, &fake_dir, "valid", &child_log);
    assert!(
        positive.status.success(),
        "P14 fake protocol PASS 失敗：{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    let script = r#"import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); digest=sys.argv[2]; reports=root/'target/rivetlua-reports'
r=json.loads((reports/'gate-P14.json').read_text()); assert r['status']=='PASS' and r['source_digest']==digest
assert len(r['case_reports'])==28
cases=list(reports.glob('P14-*.json')); assert len(cases)==28
for p in cases:
    c=json.loads(p.read_text()); assert c['status']=='PASS' and c['source_digest']==digest
    assert c['expected']==c['actual'] and c['exit_code']==0 and c['cwd']==str(root)
    assert all(c[k] for k in ('command','report_path','diagnostic','allocation_trace','resource_trace','vm_trace','cli_trace'))
"#;
    let check = Command::new("python3")
        .args(["-c", script])
        .arg(root)
        .arg(&digest)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "P14 fake protocol case schema 無效：{}",
        String::from_utf8_lossy(&check.stderr)
    );

    for (scenario, expected) in [
        ("filter-zero", "p14-sdk-filter"),
        ("child-fail", "SDK-001-lua55"),
        ("zero-test", "SDK-001-lua55"),
        ("two-tests", "SDK-001-lua55"),
        ("ignored-test", "SDK-001-lua55"),
        ("missing-summary", "SDK-001-lua55"),
        ("measured-test", "SDK-001-lua55"),
        ("missing-marker", "SDK-001-lua55"),
        ("duplicate-marker", "SDK-001-lua55"),
        ("wrong-profile", "SDK-001-lua55"),
        ("wrong-id", "SDK-001-lua55"),
        ("wrong-actual", "SDK-001-lua55"),
        ("malformed-marker", "SDK-001-lua55"),
        ("report-write-fail", "SDK-001-lua55"),
        ("extra-report", "p14-case-reports"),
        ("aggregate-write-fail", "p14-aggregate-write"),
        ("source-change", "p14-source-digest"),
        ("p13-check-after", "p00-p13-after"),
        ("p13-case-after", "p00-p13-after"),
        ("case-trace-after", "p14-case-reports"),
        ("case-metadata-after", "p14-case-reports"),
    ] {
        fs::write(&fixture_path, &fixture_original).unwrap();
        stamp_p14_prerequisites(root);
        let digest = current_source_digest(root);
        let _ = fs::remove_file(&child_log);
        let output = run_p14_fake(root, &fake_dir, scenario, &child_log);
        assert!(!output.status.success(), "{scenario} 意外 PASS");
        assert_p14_fail_json(root, &digest, expected);
        if scenario == "report-write-fail" {
            fs::remove_dir_all(report_dir.join("P14-SDK-001-lua55.json")).unwrap();
        }
        if scenario == "aggregate-write-fail" {
            fs::remove_dir_all(report_dir.join("gate-P14.json")).unwrap();
        }
    }
    fs::write(&fixture_path, &fixture_original).unwrap();
    for (mutation, expected) in [
        (
            String::from_utf8(fixture_original.clone())
                .unwrap()
                .replacen("SDK-001", "SDK-999", 1),
            "p14-fixture",
        ),
        (
            String::from_utf8(fixture_original.clone())
                .unwrap()
                .replacen("int:42", "int:41", 1),
            "p14-fixture",
        ),
    ] {
        fs::write(&fixture_path, mutation).unwrap();
        stamp_p14_prerequisites(root);
        let digest = current_source_digest(root);
        let output = run_p14_fake(root, &fake_dir, "valid", &child_log);
        assert!(!output.status.success());
        assert_p14_fail_json(root, &digest, expected);
        fs::write(&fixture_path, &fixture_original).unwrap();
    }
    let csv = csv_active.clone();
    for bad in [
        csv.replacen("p14.sdk-cli,lua55,", "p14.bad,lua55,", 1),
        csv.replacen("SDK-NEG-006", "SDK-NEG-999", 1),
        csv.replacen("p14.sdk-cli,lua54,", "p14.sdk-cli,lua55,", 1),
    ] {
        fs::write(&csv_path, bad).unwrap();
        stamp_p14_prerequisites(root);
        let digest = current_source_digest(root);
        let output = run_p14_fake(root, &fake_dir, "valid", &child_log);
        assert!(!output.status.success());
        assert_p14_fail_json(root, &digest, "p14-csv");
        fs::write(&csv_path, &csv_active).unwrap();
    }
    for scenario in [
        "p13-missing",
        "p13-json",
        "p13-digest",
        "p13-check",
        "p13-case-trace",
    ] {
        stamp_p14_prerequisites(root);
        let digest = current_source_digest(root);
        let p13_path = report_dir.join("gate-P13.json");
        let original = fs::read(&p13_path).unwrap();
        let case_path = report_dir.join("P13-LIB-001-lua55.json");
        let case_original = fs::read(&case_path).unwrap();
        match scenario {
            "p13-missing" => {
                fs::remove_file(&p13_path).unwrap();
            }
            "p13-json" => {
                fs::write(&p13_path, "{bad-json").unwrap();
            }
            "p13-digest" => {
                fs::write(
                    &p13_path,
                    String::from_utf8(original.clone()).unwrap().replacen(
                        &digest,
                        &"0".repeat(64),
                        1,
                    ),
                )
                .unwrap();
            }
            "p13-check" => {
                fs::write(
                    &p13_path,
                    String::from_utf8(original.clone()).unwrap().replacen(
                        "p13-runtime-unit",
                        "removed-runtime-unit",
                        1,
                    ),
                )
                .unwrap();
            }
            "p13-case-trace" => {
                fs::write(
                    &case_path,
                    String::from_utf8(case_original.clone()).unwrap().replacen(
                        "fuel_trace",
                        "missing_trace",
                        1,
                    ),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let output = run_p14_fake(root, &fake_dir, "valid", &child_log);
        assert!(!output.status.success(), "{scenario} 意外 PASS");
        assert_p14_fail_json(root, &digest, "p00-p13-before");
        fs::write(&p13_path, original).unwrap();
        fs::write(&case_path, case_original).unwrap();
    }
    fs::remove_dir_all(&fake_dir).unwrap();
    fs::write(&csv_path, &csv_original).unwrap();
    drop(restore);
    for (path, contents) in original_paths {
        assert_eq!(
            fs::read(&path).ok(),
            contents,
            "P14 protocol test 未逐位元組還原：{}",
            path.display()
        );
    }
    assert_eq!(fs::read(&csv_path).unwrap(), csv_original);
    assert_eq!(fs::read(&fixture_path).unwrap(), fixture_original);
    assert_eq!(git_status_snapshot(root), initial_status);
}
