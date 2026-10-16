//! P23-B03 工具適用範圍與手動工作定義；此模組不執行工具。

use super::manifest::ToolStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ToolJob {
    pub id: &'static str,
    pub tool: &'static str,
    pub scope: &'static str,
    pub negative_control: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScopeDecision {
    pub status: ToolStatus,
    pub alternative: Option<&'static str>,
    pub reason: &'static str,
}

const JOBS: &[ToolJob] = &[
    ToolJob {
        id: "P23-MIRI-PURE",
        tool: "miri",
        scope: "pure-rust",
        negative_control: "xtask/fixtures/p23/miri_negative.rs",
    },
    ToolJob {
        id: "P23-ASAN-FFI",
        tool: "asan",
        scope: "ffi",
        negative_control: "xtask/fixtures/p23/sanitizer_negative.c",
    },
    ToolJob {
        id: "P23-UBSAN-FFI",
        tool: "ubsan",
        scope: "ffi",
        negative_control: "xtask/fixtures/p23/sanitizer_negative.c",
    },
    ToolJob {
        id: "P23-ASAN-NATIVE",
        tool: "asan",
        scope: "native",
        negative_control: "xtask/fixtures/p23/sanitizer_negative.c",
    },
    ToolJob {
        id: "P23-UBSAN-NATIVE",
        tool: "ubsan",
        scope: "native",
        negative_control: "xtask/fixtures/p23/sanitizer_negative.c",
    },
    ToolJob {
        id: "P23-TSAN-SHARED",
        tool: "tsan",
        scope: "native",
        negative_control: "xtask/fixtures/p23/race_negative.c",
    },
    ToolJob {
        id: "P23-JIT-INSTRUMENTED",
        tool: "native-jit",
        scope: "jit",
        negative_control: "P23-JIT-GUARD-NEGATIVE-PENDING",
    },
    ToolJob {
        id: "P23-WORKER-POLICY-DENY",
        tool: "worker-os",
        scope: "os-worker",
        negative_control: "P23-SANDBOX-POLICY-DENY-PENDING",
    },
    ToolJob {
        id: "P23-FZ006-CAPI",
        tool: "cargo-fuzz",
        scope: "c-api",
        negative_control: "xtask/fixtures/p23/capi_sequence.c",
    },
];

pub(super) fn job_registry() -> &'static [ToolJob] {
    JOBS
}

pub(super) fn assess_scope(tool: &str, scope: &str) -> ScopeDecision {
    if tool == "miri" && scope != "pure-rust" {
        return ScopeDecision {
            status: ToolStatus::Blocked,
            alternative: None,
            reason: "E_MIRI_SCOPE_UNSUPPORTED_NO_APPROVED_ALTERNATIVE",
        };
    }

    let Some(job) = job_registry()
        .iter()
        .find(|job| job.tool == tool && job.scope == scope)
    else {
        return ScopeDecision {
            status: ToolStatus::Blocked,
            alternative: None,
            reason: "E_TOOL_SCOPE_UNDEFINED",
        };
    };

    let (status, reason) = match job.id {
        "P23-JIT-INSTRUMENTED" => (ToolStatus::Blocked, "E_JIT_INSTRUMENTATION_UNVERIFIED"),
        "P23-WORKER-POLICY-DENY" => (ToolStatus::Blocked, "E_OS_JOB_UNAPPROVED"),
        "P23-FZ006-CAPI" => (ToolStatus::Blocked, "E_FZ006_EXTERNAL_JOB_UNVERIFIED"),
        _ => (ToolStatus::NotRun, "E_TOOL_JOB_NOT_RUN"),
    };
    ScopeDecision {
        status,
        alternative: None,
        reason,
    }
}
