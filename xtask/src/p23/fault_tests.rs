use super::{ExperimentManifest, fault, manifest::FaultPlan};

const FAULT_CASES: [(&str, &str, u64, u64); 6] = [
    ("FP-ALLOC", "fail", 0, 0),
    ("FP-READ", "io-error", 0, 0),
    ("FP-WRITE", "partial-write", 2, 0),
    ("FP-CALLBACK", "throw", 1, 1),
    ("FP-CANCEL", "cancel", 1, 1),
    ("FP-ABORT", "fuel", 0, 0),
];

fn fault_manifest(profile: &str, point_id: &str, action: &str) -> ExperimentManifest {
    let plan = FaultPlan {
        point_id: point_id.into(),
        occurrence: 1,
        action: action.into(),
    };
    let (input_sha256, scenario_sha256) = fault::input_digests(&plan, profile)
        .expect("fault test digests are available");
    let mut json = super::manifest_tests::manifest_for(profile, 23001)
        .replace("\"batch\":\"P23-B01\"", "\"batch\":\"P23-B03\"")
        .replace("\"max_input_bytes\":1024", "\"max_input_bytes\":16777216")
        .replace("\"max_depth\":32", "\"max_depth\":128")
        .replace("\"fuel\":100000", "\"fuel\":100000000")
        .replace("\"heap_bytes\":16777216", "\"heap_bytes\":1073741824")
        .replace("\"seconds\":60", "\"seconds\":3600")
        .replace(
            "\"fault_plan\":null",
            &format!(
                "\"fault_plan\":{{\"point_id\":\"{}\",\"occurrence\":{},\"action\":\"{}\"}}",
                plan.point_id, plan.occurrence, plan.action,
            ),
        );

    if let Some(target) = super::host_triple() {
        let (os, cpu) = match target {
            "aarch64-apple-darwin" => ("macos", "arm64"),
            "x86_64-apple-darwin" => ("macos", "x86_64"),
            "aarch64-unknown-linux-gnu" => ("linux", "aarch64"),
            "x86_64-unknown-linux-gnu" => ("linux", "x86_64"),
            "x86_64-pc-windows-msvc" => ("windows", "x86_64"),
            _ => panic!("host_triple must return a registered host"),
        };
        json = json
            .replace(
                "\"target\":\"aarch64-apple-darwin\"",
                &format!("\"target\":\"{target}\""),
            )
            .replace("\"cpu\":\"arm64\"", &format!("\"cpu\":\"{cpu}\""))
            .replace("\"os\":\"macos\"", &format!("\"os\":\"{os}\""));
    }

    let mut manifest = ExperimentManifest::parse(&json).expect("fault test manifest is valid");
    manifest.input_sha256 = input_sha256;
    manifest.scenario_sha256 = scenario_sha256;
    manifest.validate().expect("fault test digests are valid");
    manifest
}

#[test]
fn fault_plan_uses_only_registered_point_actions() {
    let mut points: Vec<_> = fault::fault_points()
        .iter()
        .map(|point| (point.id, point.action))
        .collect();
    points.sort_unstable();
    assert_eq!(
        points,
        [
            ("FP-ABORT", "fuel"),
            ("FP-ALLOC", "fail"),
            ("FP-CALLBACK", "throw"),
            ("FP-CANCEL", "cancel"),
            ("FP-READ", "io-error"),
            ("FP-WRITE", "partial-write"),
        ],
    );

    let valid = FaultPlan {
        point_id: "FP-ALLOC".into(),
        occurrence: 1,
        action: "fail".into(),
    };
    assert_eq!(fault::validate_plan(&valid), Ok(()));

    for invalid in [
        FaultPlan { point_id: "FP-UNKNOWN".into(), ..valid.clone() },
        FaultPlan { action: "wrong-action".into(), ..valid.clone() },
        FaultPlan { occurrence: 0, ..valid },
    ] {
        assert!(fault::validate_plan(&invalid).is_err());
    }
}

#[test]
fn fixed_faults_reach_injection_and_cleanup_for_each_profile() {
    if super::host_triple().is_none() {
        let manifest = fault_manifest("lua55-i64f64", "FP-ALLOC", "fail");
        assert_eq!(
            fault::run_fault(&manifest).unwrap_err(),
            "E_FAULT_HOST_UNSUPPORTED",
        );
        return;
    }

    let valid = fault_manifest("lua55-i64f64", "FP-ALLOC", "fail");
    let mut mismatched_input = valid.clone();
    mismatched_input.input_sha256 = if valid.input_sha256 == "0".repeat(64) {
        "1".repeat(64)
    } else {
        "0".repeat(64)
    };
    assert!(mismatched_input.validate().is_ok());
    assert!(fault::run_fault(&mismatched_input).is_err());

    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        for (point_id, action, side_effects, callbacks) in FAULT_CASES {
            let manifest = fault_manifest(profile, point_id, action);
            let coverage = fault::run_fault(&manifest)
                .unwrap_or_else(|error| panic!("{profile} {point_id}: {error}"));
            assert_eq!(coverage.point_id, point_id);
            assert_eq!(coverage.reached, 1);
            assert!(coverage.injected);
            assert_eq!(coverage.status, "PASS");
            assert_eq!(coverage.code, "OK");
            assert!(coverage.cleanup_ok);
            assert!(coverage.accounting_ok);
            assert_eq!(coverage.side_effects, side_effects);
            assert_eq!(coverage.callbacks, callbacks);
        }
    }
}
