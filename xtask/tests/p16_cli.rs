use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rivetlua-xtask");

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rivetlua-p16-cli-{name}-{}", std::process::id()));
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
    path
}

fn json_assert(path: &Path, script: &str) {
    assert!(
        Command::new("python3")
            .args(["-c", script])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn p16_cli_invalid_profile_cannot_escape_report_path() {
    let root = scratch("path");
    fs::create_dir_all(root.join("target")).unwrap();
    let sentinel = root.join("target/sentinel.json");
    fs::write(&sentinel, "unchanged").unwrap();
    let output = Command::new(BIN)
        .current_dir(&root)
        .args(["p16-acceptance", "--profile", "../../sentinel"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unchanged");
    let reports = fs::read_dir(root.join("target/rivetlua-reports"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1);
    json_assert(
        &reports[0],
        "import json,sys; r=json.load(open(sys.argv[1])); assert r['schema']=='rivetlua-p16-acceptance-v1' and r['status']=='FAIL' and r['profile']=='invalid' and r['cases']==[]",
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn p16_cli_existing_matrix_stays_not_run_and_gate_fails_closed() {
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let root = scratch("notrun");
    fs::create_dir_all(root.join("tests/p16")).unwrap();
    fs::create_dir_all(root.join("tests/p16/acceptance")).unwrap();
    fs::create_dir_all(root.join("crates/rivetlua-capi/tests")).unwrap();
    for name in [
        "acceptance-cases.toml",
        "abi-manifest.toml",
        "callback_execution_b4.c",
        "public_callback_error_a2.c",
        "allocator_state_a50.c",
        "trampoline_a1.c",
    ] {
        fs::copy(
            real.join("tests/p16").join(name),
            root.join("tests/p16").join(name),
        )
        .unwrap();
    }
    for name in [
        "abi001.c",
        "abi002.c",
        "abi003.c",
        "abi004.c",
        "abi_neg001.c",
        "abi_neg004.c",
        "abi_neg006.py",
        "abi_stress.c",
    ] {
        fs::copy(
            real.join("tests/p16/acceptance").join(name),
            root.join("tests/p16/acceptance").join(name),
        )
        .unwrap();
    }
    for name in [
        "callback_execution",
        "public_callback_error",
        "allocator_state",
        "abi_acceptance",
        "abi_negative_handles",
        "native_modes",
        "worker",
        "sdk_modules",
    ] {
        fs::copy(
            real.join(format!("crates/rivetlua-capi/tests/{name}.rs")),
            root.join(format!("crates/rivetlua-capi/tests/{name}.rs")),
        )
        .unwrap();
    }
    for profile in ["lua55", "lua54"] {
        let include = root.join(format!("include/rivetlua/{profile}"));
        fs::create_dir_all(&include).unwrap();
        for name in ["lua.h", "lauxlib.h", "luaconf.h"] {
            fs::copy(
                real.join(format!("include/rivetlua/{profile}/{name}")),
                include.join(name),
            )
            .unwrap();
        }
    }
    let output = Command::new(BIN)
        .current_dir(&root)
        .args(["p16-acceptance", "--profile", "lua55-i64f64"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let reports = fs::read_dir(root.join("target/rivetlua-reports"))
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1);
    json_assert(
        &reports[0],
        "import json,sys; r=json.load(open(sys.argv[1])); assert r['schema']=='rivetlua-p16-acceptance-v1' and r['status']=='FAIL' and len(r['cases'])==15 and len(r['rows'])>400 and all(c['status']=='NOT_RUN' and c['exit_code'] is None and c['matched']==0 for c in r['cases'])",
    );
    let gate = Command::new(BIN)
        .current_dir(&root)
        .args(["gate", "P16"])
        .output()
        .unwrap();
    assert!(!gate.status.success());
    json_assert(
        &root.join("target/rivetlua-reports/gate-P16.json"),
        "import json,sys; r=json.load(open(sys.argv[1])); assert r['schema']=='rivetlua-p16-gate-v1' and r['status']=='FAIL' and r['checks']==[] and 'P00' in r['diagnostic']",
    );
    fs::remove_dir_all(root).unwrap();
}
