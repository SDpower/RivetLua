//! FZ-006 的 Rust selector；真正的 C ABI 序列只交給 B03 外部工具 job。

use rivetlua_core::LuaProfile;

use super::harness::{CaseOutcome, HarnessLimits};

pub(super) fn capi_sequence(
    _profile: LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    if input.len() > limits.max_input_bytes
        || input.len() > 64
        || limits.max_input_bytes == 0
        || limits.max_depth == 0
        || limits.fuel == 0
        || limits.heap_bytes == 0
    {
        return CaseOutcome::Limit;
    }
    CaseOutcome::Blocked("E_FZ006_JOB_REQUIRED")
}
