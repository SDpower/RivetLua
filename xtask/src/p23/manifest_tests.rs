use super::{ExperimentManifest, select_target, target_registry};

const VALID_MANIFEST: &str = r#"{"version":1,"phase":"P23","batch":"P23-B01","experiment_id":"P23-B01-SCHEMA-001","commit":"0123456789abcdef0123456789abcdef01234567","dirty":false,"crate":"rivetlua-core","features":[],"profile":"lua55-i64f64","numeric":"i64f64","target":"aarch64-apple-darwin","cpu":"arm64","os":"macos","toolchain":"rustc 1.98.1","tools":[{"name":"miri","version":"0.1","scope":"pure-rust","status":"NOT_RUN","alternative":null}],"target_id":"FZ-001","seed":23001,"corpus_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scenario_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","input_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","budget":{"max_input_bytes":1024,"max_depth":32,"fuel":100000,"heap_bytes":16777216,"cases":1,"seconds":60},"fault_plan":null,"worker_policy":"Compatibility","started_at":"2026-10-17T00:00:00Z"}"#;

pub(super) fn manifest_for(profile: &str, seed: u64) -> String {
    VALID_MANIFEST
        .replace(
            "\"profile\":\"lua55-i64f64\"",
            &format!("\"profile\":\"{profile}\""),
        )
        .replace("\"seed\":23001", &format!("\"seed\":{seed}"))
}

fn is_valid_manifest(json: &str) -> bool {
    let Ok(manifest) = ExperimentManifest::parse(json) else {
        return false;
    };
    manifest.validate().is_ok()
}

#[test]
fn manifest_schema_is_strict_and_profile_seed_bound() {
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let json = manifest_for(profile, 23001);
        let manifest = ExperimentManifest::parse(&json).unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.profile, profile);
        assert_eq!(manifest.target_id, "FZ-001");
        assert_eq!(manifest.seed, 23001);
    }

    let missing_key = VALID_MANIFEST.replace("\"dirty\":false,", "");
    let unknown_key = VALID_MANIFEST.replace("\"version\":1,", "\"version\":1,\"unexpected\":0,");
    let duplicate_key = VALID_MANIFEST.replace("\"version\":1,", "\"version\":1,\"version\":1,");
    let wrong_profile = manifest_for("lua56-i64f64", 23001);
    let wrong_seed = manifest_for("lua55-i64f64", 23002);
    for invalid in [
        missing_key,
        unknown_key,
        duplicate_key,
        wrong_profile,
        wrong_seed,
    ] {
        assert!(!is_valid_manifest(&invalid));
    }
}

#[test]
fn target_registry_and_comparability_bind_inputs() {
    let expected_targets = [
        ("FZ-001", 23001),
        ("FZ-002", 23002),
        ("FZ-003", 23003),
        ("FZ-004", 23004),
        ("FZ-005", 23005),
        ("FZ-006", 23006),
        ("FZ-CHUNK-001", 23007),
    ];
    assert_eq!(target_registry().len(), expected_targets.len());
    for (id, seed) in expected_targets {
        let target = select_target(id).expect("registry selector exists");
        assert_eq!(target.id, id);
        assert_eq!(target.seed, seed);
    }

    let baseline_json = manifest_for("lua55-i64f64", 23001);
    let baseline = ExperimentManifest::parse(&baseline_json).unwrap();
    baseline.validate().unwrap();

    let hash_changed_json = baseline_json.replace(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let hash_changed = ExperimentManifest::parse(&hash_changed_json).unwrap();
    hash_changed.validate().unwrap();
    assert!(!baseline.comparable_to(&hash_changed));

    let budget_changed_json = baseline_json.replace("\"fuel\":100000", "\"fuel\":100001");
    let budget_changed = ExperimentManifest::parse(&budget_changed_json).unwrap();
    budget_changed.validate().unwrap();
    assert!(!baseline.comparable_to(&budget_changed));
}
