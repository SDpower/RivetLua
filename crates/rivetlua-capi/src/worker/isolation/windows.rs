//! 現行 C API 無 Windows worker；所有受限啟動與證據查詢均拒絕。

use std::path::Path;
use std::process::{Child, Command};
use rivetlua_runtime::VmPolicy;
use super::PolicyDenied;

pub(super) struct PlatformLaunch;
pub(super) struct PlatformEvidence;

pub(super) fn configure(_: &mut Command, _: &Path, _: &Path, _: VmPolicy)
    -> Result<PlatformLaunch, PolicyDenied> {
    Err(PolicyDenied::Unsupported)
}

pub(super) fn parent_probe(_: &Child, _: &PlatformLaunch, _: VmPolicy)
    -> Result<PlatformEvidence, PolicyDenied> {
    Err(PolicyDenied::Unsupported)
}

pub(super) fn child_probe(_: VmPolicy, _: &Path)
    -> Result<PlatformEvidence, PolicyDenied> {
    Err(PolicyDenied::Unsupported)
}
