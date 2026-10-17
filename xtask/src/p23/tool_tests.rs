use super::{manifest::ToolStatus, tools};

fn is_deferred(status: ToolStatus) -> bool {
    matches!(
        status,
        ToolStatus::NotRun | ToolStatus::Blocked | ToolStatus::NotApplicable
    )
}

#[test]
fn tool_scopes_do_not_claim_unrun_or_unsupported_checks_as_passed() {
    for job in tools::job_registry() {
        assert!(is_deferred(tools::assess_scope(job.tool, job.scope).status));
    }

    assert!(is_deferred(tools::assess_scope("miri", "pure-rust").status));
    for scope in ["ffi", "jit"] {
        assert_ne!(tools::assess_scope("miri", scope).status, ToolStatus::Pass,);
    }
    assert_eq!(
        tools::assess_scope("unknown-tool", "unknown-scope").status,
        ToolStatus::Blocked,
    );
}
