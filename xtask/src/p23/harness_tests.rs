use super::harness::{CaseOutcome, HarnessLimits, run_case};
use rivetlua_core::LuaProfile;

fn limits() -> HarnessLimits {
    HarnessLimits {
        max_input_bytes: 1024,
        max_depth: 32,
        fuel: 100_000,
        heap_bytes: 16 * 1024 * 1024,
    }
}

#[test]
fn public_source_is_accepted() {
    let limits = limits();
    assert_eq!(
        run_case("FZ-001", LuaProfile::Lua55, b"return 1", &limits),
        CaseOutcome::Accepted,
    );
}

#[test]
fn malformed_rvlu_and_official_chunk_inputs_are_rejected() {
    let limits = limits();
    for target in ["FZ-003", "FZ-004"] {
        assert_eq!(
            run_case(target, LuaProfile::Lua55, b"not-rvlu", &limits),
            CaseOutcome::Rejected,
        );
    }
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        assert_eq!(
            run_case("FZ-CHUNK-001", profile, b"not-lua-chunk", &limits),
            CaseOutcome::Rejected,
        );
    }
}

#[test]
fn input_and_target_limits_fail_closed() {
    let limits = limits();
    let oversized = vec![b'a'; limits.max_input_bytes + 1];
    assert_eq!(
        run_case("FZ-001", LuaProfile::Lua55, &oversized, &limits),
        CaseOutcome::Limit,
    );

    assert_eq!(
        run_case("FZ-UNKNOWN", LuaProfile::Lua55, b"", &limits),
        CaseOutcome::Blocked("E_FUZZ_UNKNOWN_TARGET"),
    );
    assert_eq!(
        run_case("FZ-006", LuaProfile::Lua55, b"[]", &limits),
        CaseOutcome::Blocked("E_FZ006_JOB_REQUIRED"),
    );
}
