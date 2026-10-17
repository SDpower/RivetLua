//! 受限 worker 的作業系統證據；成功型別只由平台實際探測路徑建立。

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use rivetlua_runtime::VmPolicy;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use windows as platform;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyDenied {
    Unsupported,
    InvalidWorker,
    MissingEvidence,
    Resource,
}

impl PolicyDenied {
    pub(crate) const fn public_code(self) -> &'static [u8] {
        b"E_POLICY_DENIED"
    }
}

pub(crate) struct LaunchPlan {
    policy: VmPolicy,
    binary: PathBuf,
    run_dir: PathBuf,
    platform: platform::PlatformLaunch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProofPhase {
    Parent,
    Child,
}

pub(crate) struct IsolationProof {
    policy: VmPolicy,
    pid: u32,
    phase: ProofPhase,
    _evidence: platform::PlatformEvidence,
}

impl IsolationProof {
    pub(crate) fn matches(&self, policy: VmPolicy, pid: u32, parent: bool) -> bool {
        self.policy == policy && self.pid == pid && (self.phase == ProofPhase::Parent) == parent
    }
}

pub(crate) fn configure(
    command: &mut Command,
    binary: &Path,
    run_dir: &Path,
    policy: VmPolicy,
    artifacts: &[PathBuf],
) -> Result<LaunchPlan, PolicyDenied> {
    if policy == VmPolicy::Compatibility || !binary.is_absolute() || !run_dir.is_absolute() {
        return Err(PolicyDenied::InvalidWorker);
    }
    command
        .env_clear()
        .env("RIVETLUA_P16_WORKER_CACHE", run_dir)
        .current_dir(run_dir)
        .arg(match policy {
            VmPolicy::Sandbox => "--rivetlua-policy-sandbox",
            VmPolicy::PrivateService => "--rivetlua-policy-private",
            VmPolicy::Compatibility => unreachable!(),
        });
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(target_os = "linux")]
    let platform = platform::configure(command, binary, run_dir, policy, artifacts)?;
    #[cfg(not(target_os = "linux"))]
    let platform = {
        if !artifacts.is_empty() {
            return Err(PolicyDenied::Unsupported);
        }
        platform::configure(command, binary, run_dir, policy)?
    };
    Ok(LaunchPlan {
        policy,
        binary: binary.to_path_buf(),
        run_dir: run_dir.to_path_buf(),
        platform,
    })
}

pub(crate) fn parent_probe(
    child: &Child,
    plan: &LaunchPlan,
) -> Result<IsolationProof, PolicyDenied> {
    if !plan.binary.is_absolute() || !plan.run_dir.is_absolute() {
        return Err(PolicyDenied::InvalidWorker);
    }
    let evidence = platform::parent_probe(child, &plan.platform, plan.policy)?;
    Ok(IsolationProof {
        policy: plan.policy,
        pid: child.id(),
        phase: ProofPhase::Parent,
        _evidence: evidence,
    })
}

pub(crate) fn child_probe(
    policy: VmPolicy,
    run_dir: &Path,
) -> Result<IsolationProof, PolicyDenied> {
    if policy == VmPolicy::Compatibility || !run_dir.is_absolute() {
        return Err(PolicyDenied::InvalidWorker);
    }
    let evidence = platform::child_probe(policy, run_dir)?;
    Ok(IsolationProof {
        policy,
        pid: std::process::id(),
        phase: ProofPhase::Child,
        _evidence: evidence,
    })
}

pub(crate) fn terminate_group(child: &mut Child) -> bool {
    #[cfg(unix)]
    let group_stopped = i32::try_from(child.id())
        .ok()
        .filter(|group| *group > 0)
        .is_some_and(|group| {
            // SAFETY：受限 worker 在獨立 process group；負號只指定該 group。
            let result = unsafe { libc::kill(-group, libc::SIGKILL) };
            result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        });
    #[cfg(not(unix))]
    let group_stopped = false;
    let _ = child.kill();
    group_stopped
}
