use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rivetlua_capi::worker::{Limits, Request, WorkerOutcome, run_worker_with_policy};
use rivetlua_runtime::VmPolicy;

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        loop {
            let path = std::env::temp_dir().join(format!(
                "rivetlua-p22-worker-policy-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("無法建立測試暫存目錄：{error}"),
            }
        }
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn restricted_policies_deny_worker_without_isolation_evidence_before_spawn() {
    let temp = TestTempDir::new();
    let worker_binary = temp.0.join("worker-must-not-exist");
    assert!(!worker_binary.exists());
    let cache_root = temp.0.join("cache");
    fs::create_dir(&cache_root).unwrap();

    for policy in [VmPolicy::Sandbox, VmPolicy::PrivateService] {
        let request = Request {
            rvlu: Vec::new(),
            sidecar: Vec::new(),
            native: Vec::new(),
            args: Vec::new(),
        };
        // SAFETY：request.native 為空，沒有 native artifact 或 constructor 可進入 worker。
        let report = unsafe {
            run_worker_with_policy(
                &worker_binary,
                &cache_root,
                1,
                request,
                policy,
                Duration::from_secs(1),
                Limits::default(),
            )
        };

        assert_eq!(
            report.outcome,
            WorkerOutcome::Rejected(b"E_POLICY_DENIED".to_vec())
        );
        assert_eq!(report.child_pid, None);
        assert!(report.cache_clean);
    }
}
