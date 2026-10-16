use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_rivetlua-xtask");
static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rivetlua-p17-cli-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("Cargo.toml"), "[workspace]\n").unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(&path)
                .status()
                .unwrap()
                .success()
        );
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_without_p17_environment(root: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(root)
        .args(args)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RIVETLUA_P17_EVIDENCE_DIR")
        .output()
        .unwrap()
}

fn seed_old_reports(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let reports = root.join("target/rivetlua-reports");
    fs::create_dir_all(&reports).unwrap();
    let mut seeded = Vec::new();
    for phase in 0..=16 {
        let path = reports.join(format!("gate-P{phase:02}.json"));
        let contents = format!("old P{phase:02} report\n").into_bytes();
        fs::write(&path, &contents).unwrap();
        seeded.push((path, contents));
    }
    for name in ["gate-P17.json", "gate-P17-B01.json"] {
        let path = reports.join(name);
        let contents = format!("old {name}\n").into_bytes();
        fs::write(&path, &contents).unwrap();
        seeded.push((path, contents));
    }
    seeded
}

fn assert_invalid_batch_report(path: &Path) {
    let check = Command::new("python3")
        .args([
            "-c",
            r#"import json,sys
r=json.load(open(sys.argv[1], encoding='utf-8'))
assert r['schema']=='rivetlua-phase-gate-v1'
assert r['phase']=='P17' and r['batch'] is None and r['status']=='FAIL'
assert isinstance(r['diagnostic'],str) and r['diagnostic']
checks=r['checks']
assert isinstance(checks,list) and checks
assert any(c.get('case_id')=='COMPLETE-002'
           and c.get('facet')=='batch-selector'
           and c.get('status')=='FAIL'
           and c.get('exit_code') is None
           and c.get('matched')==0 for c in checks)
"#,
        ])
        .arg(path)
        .status()
        .unwrap();
    assert!(check.success(), "非法 batch 應寫入合法且明確失敗的報告");
}

#[test]
fn p17_cli_invalid_batch_tokens_use_one_safe_report_and_preserve_old_reports() {
    let scratch = Scratch::new("invalid-batch");
    let sentinels = seed_old_reports(scratch.path());
    let outside_sentinel = scratch.path().join("target/sentinel.json");
    fs::write(&outside_sentinel, b"untouched\n").unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("unknown batch", &["gate", "P17", "--batch", "P17-B04"]),
        ("foreign batch", &["gate", "P17", "--batch", "P18-B01"]),
        (
            "path traversal",
            &["gate", "P17", "--batch", "../../target/sentinel.json"],
        ),
        (
            "duplicate option",
            &["gate", "P17", "--batch", "P17-B01", "--batch", "P17-B02"],
        ),
        ("missing option value", &["gate", "P17", "--batch"]),
    ];

    let safe_report = scratch
        .path()
        .join("target/rivetlua-reports/gate-P17-invalid.json");
    let safe_receipt = scratch
        .path()
        .join("target/rivetlua-reports/gate-P17-invalid.sha256");
    for (label, args) in cases {
        let output = run_without_p17_environment(scratch.path(), args);
        assert!(
            !output.status.success(),
            "{label} must be rejected: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            safe_report.is_file(),
            "{label} must use the fixed safe report path"
        );
        assert_invalid_batch_report(&safe_report);
        assert!(
            safe_receipt.is_file(),
            "{label} must write the fixed report SHA-256 receipt"
        );
        let expected_receipt = format!("{}  gate-P17-invalid.json\n", sha256(&safe_report));
        assert_eq!(
            fs::read_to_string(&safe_receipt).unwrap(),
            expected_receipt,
            "{label} report receipt must hash the canonical JSON bytes"
        );
        for (path, contents) in &sentinels {
            assert_eq!(
                fs::read(path).unwrap(),
                *contents,
                "{label} modified an old report"
            );
        }
        assert_eq!(fs::read(&outside_sentinel).unwrap(), b"untouched\n");
    }

    let report_dir = safe_report.parent().unwrap();
    let mut names = fs::read_dir(report_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    let mut expected = (0..=16)
        .map(|phase| format!("gate-P{phase:02}.json"))
        .collect::<Vec<_>>();
    expected.extend([
        "gate-P17-B01.json".to_owned(),
        "gate-P17-invalid.json".to_owned(),
        "gate-P17-invalid.sha256".to_owned(),
        "gate-P17.json".to_owned(),
    ]);
    expected.sort();
    assert_eq!(
        names, expected,
        "raw batch token must never become a report path"
    );
}

#[test]
fn p17_cli_missing_external_build_or_evidence_root_fails_before_running_suite() {
    let scratch = Scratch::new("missing-env");
    let b01_report = scratch
        .path()
        .join("target/rivetlua-reports/gate-P17-B01.json");
    let sentinel_reports = seed_old_reports(scratch.path())
        .into_iter()
        .filter(|(path, _)| path != &b01_report)
        .collect::<Vec<_>>();
    fs::remove_file(&b01_report).unwrap();
    let source_manifest = repository_root().join("tests/p17/runner-manifest.toml");
    assert!(
        source_manifest.is_file(),
        "B01 implementation must provide its owned runner manifest"
    );
    let manifest_dir = scratch.path().join("tests/p17");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::copy(&source_manifest, manifest_dir.join("runner-manifest.toml")).unwrap();

    let output =
        run_without_p17_environment(scratch.path(), &["gate", "P17", "--batch", "P17-B01"]);
    assert!(
        !output.status.success(),
        "missing external roots must fail before Cargo or suite execution: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let check = Command::new("python3")
        .args([
            "-c",
            r#"import json,sys
r=json.load(open(sys.argv[1], encoding='utf-8'))
assert r['schema']=='rivetlua-phase-gate-v1'
assert r['phase']=='P17' and r['batch']=='P17-B01' and r['status']=='FAIL'
assert isinstance(r.get('diagnostic'),str) and r['diagnostic']
scope=r['scope']
assert scope['phase']=='P17' and scope['batch']=='P17-B01'
assert scope['declared_cases']==['COMPLETE-002']
facets=scope.get('facets',scope.get('declared_facets'))
assert set(facets)=={'fixture','binary','profile','abi','module-build','module-load',
 'runner-argv','runner-cwd','runner-no-u','runner-error','negative-controls'}
assert set(r['configuration']['profiles'])=={'lua55-i64f64','lua54-i64f64'}
selectors=json.dumps(scope['selectors'], sort_keys=True)
assert all(profile in selectors for profile in ('lua55-i64f64','lua54-i64f64'))
checks=r['checks']
required={'case_id','facet','command','cwd','exit_code','matched','passed','failed',
 'ignored','status','log_path','log_sha256'}
assert isinstance(checks,list) and checks
assert all(required.issubset(c) for c in checks)
assert all(c['case_id']=='COMPLETE-002' for c in checks)
assert all(c['matched']==0 and c['passed']==0 and c['status'] in ('FAIL','NOT_RUN')
           for c in checks)
assert not any('all.lua' in c['command'] for c in checks)
"#,
        ])
        .arg(&b01_report)
        .status()
        .unwrap();
    assert!(check.success(), "缺外接環境需產生完整 P17-B01 FAIL JSON");

    for (path, contents) in sentinel_reports {
        assert_eq!(
            fs::read(path).unwrap(),
            contents,
            "B01 altered a pre-existing report"
        );
    }
    assert!(
        !scratch
            .path()
            .join("target/rivetlua-reports/gate-P17-invalid.json")
            .exists(),
        "valid B01 selector must not use the invalid-selector report"
    );
}

#[test]
fn p17_fake_pass_fixtures_each_encode_the_declared_fail_closed_case() {
    let fixtures = repository_root().join("tests/p17/fixtures");
    let paths = [
        fixtures.join("counterexample-fake-pass-zero-matches.json"),
        fixtures.join("counterexample-fake-pass-missing-hash.json"),
        fixtures.join("counterexample-fake-pass-wrong-profiles.json"),
        fixtures.join("counterexample-fake-pass-out-of-scope.json"),
    ];
    let output = Command::new("python3")
        .args([
            "-c",
            r#"import json,pathlib,sys
expected_profiles={'lua55-i64f64','lua54-i64f64'}
required={'case_id','facet','command','cwd','exit_code','matched','passed','failed',
          'ignored','status','log_path','log_sha256'}
for raw in sys.argv[1:]:
    path=pathlib.Path(raw)
    report=json.loads(path.read_text(encoding='utf-8'))
    assert report['schema']=='rivetlua-phase-gate-v1'
    assert report['phase']=='P17' and report['batch']=='P17-B01'
    assert report['status']=='PASS' and report['checks']
    assert all(required.issubset(check) and check['status']=='PASS'
               for check in report['checks'])
    case=report['checks'][0]
    name=path.name
    if name.endswith('zero-matches.json'):
        assert case['case_id']=='COMPLETE-002' and case['matched']==0
    elif name.endswith('missing-hash.json'):
        assert any(not isinstance(item.get('sha256'),str) or len(item['sha256'])!=64
                   for item in report['source_inputs'])
    elif name.endswith('wrong-profiles.json'):
        assert set(report['scope']['selectors'])==expected_profiles
        assert set(report['configuration']['profiles'])!=expected_profiles
    elif name.endswith('out-of-scope.json'):
        assert case['case_id']=='COMPLETE-001'
        assert case['case_id'] not in {'COMPLETE-002'}
    else:
        raise AssertionError('unexpected fake PASS fixture: '+name)
"#,
        ])
        .args(paths)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fake PASS fixtures must truthfully encode their named flaw: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn toml_block(source: &str, section: Option<&str>) -> Option<String> {
    match section {
        None => Some(
            source
                .lines()
                .take_while(|line| !line.trim_start().starts_with('['))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Some(name) => {
            let header = format!("[{name}]");
            let mut lines = source.lines();
            lines.find(|line| line.trim() == header)?;
            Some(
                lines
                    .take_while(|line| !line.trim_start().starts_with('['))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        }
    }
}

fn toml_raw(source: &str, section: Option<&str>, key: &str) -> Option<String> {
    let block = toml_block(source, section)?;
    let mut lines = block.lines();
    let index = lines.position(|line| {
        line.split_once('=')
            .is_some_and(|(candidate, _)| candidate.trim() == key)
    })?;
    let mut raw = block
        .lines()
        .nth(index)?
        .split_once('=')
        .unwrap()
        .1
        .trim()
        .to_owned();
    for line in block.lines().skip(index + 1) {
        if !raw.starts_with('[') || raw.contains(']') {
            break;
        }
        raw.push_str(line);
    }
    Some(raw)
}

fn toml_string(source: &str, section: Option<&str>, key: &str) -> String {
    toml_raw(source, section, key)
        .unwrap_or_else(|| panic!("missing TOML key {section:?}.{key}"))
        .trim()
        .trim_matches('"')
        .to_owned()
}

fn toml_array(source: &str, section: Option<&str>, key: &str) -> Vec<String> {
    let raw = toml_raw(source, section, key)
        .unwrap_or_else(|| panic!("missing TOML array {section:?}.{key}"));
    let start = raw.find('[').expect("TOML array opening bracket") + 1;
    let end = raw.find(']').expect("TOML array closing bracket");
    raw[start..end]
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_matches('"').to_owned())
        .collect()
}

fn sha256(path: &Path) -> String {
    let (program, args): (&str, &[&str]) = match std::env::consts::OS {
        "macos" => ("shasum", &["-a", "256"]),
        "linux" => ("sha256sum", &[]),
        os => panic!("unsupported SHA-256 test host: {os}"),
    };
    let output = Command::new(program).args(args).arg(path).output().unwrap();
    assert!(
        output.status.success(),
        "SHA-256 failed for {}",
        path.display()
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn p17_runner_manifest_hashes_and_module_metadata_match_official_inputs() {
    let root = repository_root();
    let manifest_path = root.join("tests/p17/runner-manifest.toml");
    let source = fs::read_to_string(&manifest_path).expect("P17 runner manifest");
    assert_eq!(
        toml_string(&source, None, "schema"),
        "rivetlua-p17-runner-v1"
    );
    assert_eq!(toml_string(&source, None, "batch"), "P17-B01");
    assert_eq!(
        toml_array(&source, None, "profiles"),
        vec!["lua55-i64f64".to_owned(), "lua54-i64f64".to_owned()]
    );

    let profiles = [
        (
            "lua55-i64f64",
            "5.5.1",
            "vendor/lua55/tests.tar.gz",
            "da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31",
            "vendor/lua55/lua-5.5.1-tests",
            "f1b8b8075a71e7abc40260f6b9112e8d2a1057772f26374df4bc800d10296309",
            "lua-5.5.1-tests",
        ),
        (
            "lua54-i64f64",
            "5.4.9",
            "vendor/lua54/tests.tar.gz",
            "7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca",
            "vendor/lua54/lua-5.4.9-tests",
            "3e296dd2b26ac6891ccba1ebaa62d40f1816ac93c7efdeaddc05aaa064e7311c",
            "lua-5.4.9-tests",
        ),
    ];
    let modules = [
        "lib1.so:lib1.c",
        "lib11.so:lib11.c",
        "lib2.so:lib2.c",
        "lib21.so:lib21.c",
        "lib2-v2.so:lib22.c",
    ];

    for (profile, release, tarball, tarball_sha, suite, all_lua_sha, archive_root) in profiles {
        let fields = [
            ("release", release),
            ("tarball", tarball),
            ("tarball_sha256", tarball_sha),
            ("suite", suite),
            ("all_lua_sha256", all_lua_sha),
            ("p1_init", "libs/P1/init.lua"),
            ("p1_xuxu", "libs/P1/xuxu.lua"),
        ];
        for (key, expected) in fields {
            assert_eq!(
                toml_string(&source, Some(profile), key),
                expected,
                "unexpected {profile}.{key}"
            );
        }
        let expected_modules = modules
            .iter()
            .map(|module| (*module).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            toml_array(&source, Some(profile), "modules"),
            expected_modules
        );

        let archive = root.join(tarball);
        let all_lua = root.join(suite).join("all.lua");
        assert_eq!(
            sha256(&archive),
            tarball_sha,
            "official tests tarball changed"
        );
        assert_eq!(sha256(&all_lua), all_lua_sha, "official all.lua changed");
        let listing = Command::new("tar")
            .args(["-tzf"])
            .arg(&archive)
            .output()
            .unwrap();
        assert!(
            listing.status.success(),
            "cannot inspect {}",
            archive.display()
        );
        let listing = String::from_utf8(listing.stdout).unwrap();
        for official_path in [
            format!("{archive_root}/libs/makefile"),
            format!("{archive_root}/libs/lib1.c"),
            format!("{archive_root}/libs/lib11.c"),
            format!("{archive_root}/libs/lib2.c"),
            format!("{archive_root}/libs/lib21.c"),
            format!("{archive_root}/libs/lib22.c"),
        ] {
            assert!(
                listing.lines().any(|entry| entry == official_path),
                "missing {official_path}"
            );
        }
        let makefile = toml_string(&source, Some(profile), "libs_makefile");
        assert!(
            makefile.ends_with("libs/makefile"),
            "official archive spells the libs build file as lowercase `makefile`"
        );
    }
}
