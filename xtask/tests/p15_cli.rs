use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rivetlua-xtask");

#[test]
fn p15_cli_rejects_non_basic_mode_before_child() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output = Command::new(BIN)
        .current_dir(root)
        .args([
            "official-tests",
            "--profile",
            "lua55-i64f64",
            "--mode",
            "complete",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("basic"));
}

#[test]
fn p15_cli_missing_canonical_tree_yields_v2_fail_json_before_build() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let scratch = std::env::temp_dir().join(format!("rivetlua-p15-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("tests/p15")).unwrap();
    std::fs::create_dir_all(scratch.join("vendor/lua55/lua-5.5.1-tests")).unwrap();
    std::fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
    std::fs::copy(
        root.join("tests/p15/runner-manifest.toml"),
        scratch.join("tests/p15/runner-manifest.toml"),
    )
    .unwrap();
    std::fs::copy(
        root.join("vendor/lua55/tests.tar.gz"),
        scratch.join("vendor/lua55/tests.tar.gz"),
    )
    .unwrap();
    std::fs::copy(
        root.join("vendor/lua55/lua-5.5.1-tests/all.lua"),
        scratch.join("vendor/lua55/lua-5.5.1-tests/all.lua"),
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
    assert!(
        Command::new("git")
            .args(["add", "Cargo.toml", "tests", "vendor"])
            .current_dir(&scratch)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(BIN)
        .current_dir(&scratch)
        .args([
            "official-tests",
            "--profile",
            "lua55-i64f64",
            "--mode",
            "basic",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report = std::fs::read_to_string(
        scratch.join("target/rivetlua-reports/P15-basic-lua55-i64f64.json"),
    )
    .unwrap();
    assert!(report.contains("\"schema\":\"rivetlua-p15-basic-v2\""));
    assert!(report.contains("\"status\":\"FAIL\""));
    assert!(report.contains("\"runner_status\":\"FAIL\""));
    assert!(report.contains("\"exit_code\":null"));
    assert!(!report.contains("P00"));
    let parsed = Command::new("python3")
        .args(["-c", "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL' and r['exit_code'] is None"])
        .arg(scratch.join("target/rivetlua-reports/P15-basic-lua55-i64f64.json"))
        .status().unwrap();
    assert!(parsed.success());
    assert!(
        !scratch
            .join("target/rivetlua-p15/build-lua55-i64f64.log")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn p15_gate_rejects_missing_observations_with_named_diagnostic() {
    let scratch = std::env::temp_dir().join(format!("rivetlua-p15-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&scratch)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(BIN)
        .current_dir(&scratch)
        .args(["gate", "P15"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("P15"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("report"));
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn p15_cli_rejects_manifest_tamper_before_child() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let scratch = std::env::temp_dir().join(format!("rivetlua-p15-tamper-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("tests/p15")).unwrap();
    std::fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
    let original = std::fs::read_to_string(root.join("tests/p15/runner-manifest.toml")).unwrap();
    std::fs::write(
        scratch.join("tests/p15/runner-manifest.toml"),
        original.replace("5.5.1", "5.5.2"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(&scratch)
        .args([
            "official-tests",
            "--profile",
            "lua55-i64f64",
            "--mode",
            "basic",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let path = scratch.join("target/rivetlua-reports/P15-basic-lua55-i64f64.json");
    let parsed = Command::new("python3")
        .args(["-c", "import json,sys; r=json.load(open(sys.argv[1])); assert r['status']=='FAIL' and 'manifest' in r['diagnostic'] and r['exit_code'] is None"])
        .arg(path).status().unwrap();
    assert!(parsed.success());
    assert!(!scratch.join("target/rivetlua-p15").exists());
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn p15_cli_malicious_profile_cannot_escape_report_directory() {
    let scratch = std::env::temp_dir().join(format!("rivetlua-p15-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("target/rivetlua-reports/P15-basic-..")).unwrap();
    std::fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
    let sentinel = scratch.join("target/sentinel.json");
    std::fs::write(&sentinel, b"untouched").unwrap();
    let output = Command::new(BIN)
        .current_dir(&scratch)
        .args([
            "official-tests",
            "--profile",
            "../../../sentinel",
            "--mode",
            "basic",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
    assert!(
        scratch
            .join("target/rivetlua-reports/P15-basic-invalid.json")
            .is_file()
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn p15_cli_rejects_lua_init_before_child() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let scratch = std::env::temp_dir().join(format!("rivetlua-p15-init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("tests/p15")).unwrap();
    std::fs::write(scratch.join("Cargo.toml"), b"[workspace]\n").unwrap();
    std::fs::copy(
        root.join("tests/p15/runner-manifest.toml"),
        scratch.join("tests/p15/runner-manifest.toml"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .current_dir(&scratch)
        .env("LUA_INIT_5_5", "print('altered')")
        .args([
            "official-tests",
            "--profile",
            "lua55-i64f64",
            "--mode",
            "basic",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report = std::fs::read_to_string(
        scratch.join("target/rivetlua-reports/P15-basic-lua55-i64f64.json"),
    )
    .unwrap();
    assert!(report.contains("LUA_INIT_5_5"));
    assert!(!scratch.join("target/rivetlua-p15").exists());
    let _ = std::fs::remove_dir_all(&scratch);
}
