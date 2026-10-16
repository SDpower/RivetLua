//! P23 實驗入口；工具目錄只列資訊，不自動執行外部工具。

mod manifest;
mod harness;
mod codec;
mod language;
mod sdk;
mod capi_sequence;
mod fault;
mod tools;
mod schedule;
mod performance;
#[cfg(test)]
mod manifest_tests;
#[cfg(test)]
mod harness_tests;
#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod tool_tests;
#[cfg(test)]
mod schedule_tests;
#[cfg(test)]
mod performance_tests;

#[cfg(test)]
pub(super) use manifest::{ExperimentManifest, select_target, target_registry};

use std::fs::{self, File};
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

const MAX_MANIFEST_FILE: u64 = 64 * 1024;
const MAX_PERF_REPORT_FILE: u64 = 1024 * 1024;
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

struct QuietPanicHook(Option<Box<dyn Fn(&panic::PanicHookInfo<'_>) + Send + Sync + 'static>>);

impl QuietPanicHook {
    fn new() -> Self {
        let old = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        Self(Some(old))
    }
}

impl Drop for QuietPanicHook {
    fn drop(&mut self) {
        if let Some(old) = self.0.take() {
            panic::set_hook(old);
        }
    }
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command] if command == "registry" => {
            let entries = manifest::target_registry()
                .iter()
                .map(|target| format!(
                    "{{\"id\":\"{}\",\"seed\":{},\"input_kind\":\"{}\",\"oracle\":\"{}\"}}",
                    target.id, target.seed, target.input_kind, target.oracle
                ))
                .collect::<Vec<_>>()
                .join(",");
            println!("{{\"version\":1,\"targets\":[{entries}]}}");
            Ok(())
        }
        [command, flag, path] if command == "manifest" && flag == "--input" => {
            let bytes = read_bounded(path, MAX_MANIFEST_FILE, "E_MANIFEST_INPUT")?;
            let input = std::str::from_utf8(&bytes).map_err(|_| "E_MANIFEST_JSON".to_owned())?;
            let manifest = manifest::ExperimentManifest::parse(input)?;
            println!(
                "{{\"version\":1,\"schema_valid\":true,\"experiment_id\":\"{}\",\"target_id\":\"{}\"}}",
                manifest.experiment_id, manifest.target_id
            );
            Ok(())
        }
        [command] if command == "tools" => {
            let entries = tools::job_registry()
                .iter()
                .map(|job| {
                    let scope = tools::assess_scope(job.tool, job.scope);
                    let status = match scope.status {
                        manifest::ToolStatus::NotRun => "NOT_RUN",
                        manifest::ToolStatus::Blocked => "BLOCKED",
                        manifest::ToolStatus::NotApplicable => "NOT_APPLICABLE",
                        manifest::ToolStatus::Pass => "PASS",
                        manifest::ToolStatus::Fail => "FAIL",
                    };
                    let alternative = scope.alternative.map_or("null".to_owned(), |value| {
                        format!("\"{}\"", crate::json_escape(value))
                    });
                    format!(
                        "{{\"id\":\"{}\",\"tool\":\"{}\",\"scope\":\"{}\",\"negative_control\":\"{}\",\"status\":\"{status}\",\"alternative\":{alternative},\"reason\":\"{}\"}}",
                        crate::json_escape(job.id), crate::json_escape(job.tool),
                        crate::json_escape(job.scope), crate::json_escape(job.negative_control),
                        crate::json_escape(scope.reason),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            println!("{{\"version\":1,\"jobs\":[{entries}]}}");
            Ok(())
        }
        [command, tier] if command == "schedule" => print_schedule(tier, 3),
        [command, tier, flag, seeds] if command == "schedule" && flag == "--seeds" && tier == "release" => {
            let count = seeds.parse::<usize>().map_err(|_| "E_P23B04_RELEASE_SEEDS")?;
            print_schedule(tier, count)
        }
        [command, flag, path] if command == "performance" && flag == "--manifest" => {
            let bytes = read_bounded(path, MAX_MANIFEST_FILE, "E_MANIFEST_INPUT")?;
            let input = std::str::from_utf8(&bytes).map_err(|_| "E_MANIFEST_JSON")?;
            let manifest = manifest::ExperimentManifest::parse(input)?;
            let _lock = PANIC_HOOK_LOCK.lock().map_err(|_| "E_PERF_HOOK")?;
            let _hook = QuietPanicHook::new();
            let collected = panic::catch_unwind(AssertUnwindSafe(|| performance::collect(&manifest)))
                .map_err(|_| "E_PERF_PANIC")??;
            println!("{}", collected.json);
            if collected.all_jit_fallback { Err("E_PERF_JIT_FALLBACK".into()) } else { Ok(()) }
        }
        [command, rest @ ..] if command == "perf-compare" => compare_perf(rest),
        [command, flag, path] if command == "fault" && flag == "--manifest" => {
            let bytes = read_bounded(path, MAX_MANIFEST_FILE, "E_MANIFEST_INPUT")?;
            let input = std::str::from_utf8(&bytes).map_err(|_| "E_MANIFEST_JSON".to_owned())?;
            let manifest = manifest::ExperimentManifest::parse(input)?;
            if host_triple() != Some(manifest.target.as_str()) {
                return Err("E_FAULT_HOST_UNSUPPORTED".into());
            }
            let _lock = PANIC_HOOK_LOCK.lock().map_err(|_| "E_FAULT_HOOK".to_owned())?;
            let _hook = QuietPanicHook::new();
            let coverage = match panic::catch_unwind(AssertUnwindSafe(|| fault::run_fault(&manifest))) {
                Ok(result) => result?,
                Err(_) => return Err("E_FAULT_PANIC".into()),
            };
            println!(
                "{{\"version\":1,\"point_id\":\"{}\",\"status\":\"{}\",\"code\":\"{}\",\"reached\":{},\"injected\":{},\"cleanup_ok\":{},\"accounting_ok\":{},\"side_effects\":{},\"callbacks\":{}}}",
                coverage.point_id, coverage.status, coverage.code, coverage.reached,
                coverage.injected, coverage.cleanup_ok, coverage.accounting_ok,
                coverage.side_effects, coverage.callbacks,
            );
            if coverage.status == "PASS" { Ok(()) } else { Err(coverage.code.into()) }
        }
        [command, manifest_flag, manifest_path, input_flag, input_path]
            if command == "fuzz" && manifest_flag == "--manifest" && input_flag == "--input" =>
        {
            let manifest_bytes = read_bounded(manifest_path, MAX_MANIFEST_FILE, "E_MANIFEST_INPUT")?;
            let manifest_text = std::str::from_utf8(&manifest_bytes)
                .map_err(|_| "E_MANIFEST_JSON".to_owned())?;
            let manifest = manifest::ExperimentManifest::parse(manifest_text)?;
            if manifest.batch != "P23-B02" {
                return Err("E_FUZZ_BATCH".into());
            }
            let input_bytes = read_bounded(input_path, manifest.budget.max_input_bytes, "E_FUZZ_INPUT")?;
            let digest = crate::p17::package_sha256_bytes(&input_bytes)
                .map_err(|_| "E_FUZZ_DIGEST".to_owned())?;
            if !digest.eq_ignore_ascii_case(&manifest.input_sha256) {
                return Err("E_FUZZ_INPUT_DIGEST".into());
            }
            let summary = if host_triple() != Some(manifest.target.as_str()) {
                harness::FuzzSummary::blocked("E_FUZZ_HOST_UNSUPPORTED")
            } else {
                let _lock = PANIC_HOOK_LOCK.lock().map_err(|_| "E_FUZZ_HOOK".to_owned())?;
                let _hook = QuietPanicHook::new();
                match panic::catch_unwind(AssertUnwindSafe(|| harness::fuzz(&manifest, &input_bytes))) {
                    Ok(result) => result?,
                    Err(_) => harness::FuzzSummary::panic(0),
                }
            };
            print_summary(&manifest, &digest, input_bytes.len(), &summary);
            match summary.status {
                "FINDING" => Err(summary.code.unwrap_or("E_FUZZ_FINDING").into()),
                "BLOCKED" => Err(summary.code.unwrap_or("E_FUZZ_BLOCKED").into()),
                "LIMIT" => Err("E_FUZZ_LIMIT".into()),
                _ => Ok(()),
            }
        }
        _ => Err("E_EXPERIMENT_USAGE".into()),
    }
}

fn print_schedule(tier: &str, seeds: usize) -> Result<(), String> {
    let tier = match tier {
        "pr" => schedule::Tier::PullRequest,
        "nightly" => schedule::Tier::Nightly,
        "release" => schedule::Tier::Release,
        _ => return Err("E_P23B04_TIER".into()),
    };
    let jobs = schedule::schedule(tier, seeds).map_err(str::to_owned)?;
    let entries = jobs.iter().map(|job| format!(
        "{{\"target_id\":\"{}\",\"profile\":\"{}\",\"seed\":{},\"seconds\":{}}}",
        job.target_id, job.profile, job.seed, job.seconds,
    )).collect::<Vec<_>>().join(",");
    println!("{{\"version\":1,\"jobs\":[{entries}]}}");
    Ok(())
}

fn compare_perf(args: &[String]) -> Result<(), String> {
    let [baseline_flag, baseline_path, candidate_flag, candidate_path, rest @ ..] = args else {
        return Err("E_PERF_USAGE".into());
    };
    if baseline_flag != "--baseline" || candidate_flag != "--candidate" || rest.len() > 9 || rest.len() % 3 != 0 {
        return Err("E_PERF_USAGE".into());
    }
    let read = |path: &str| -> Result<String, String> {
        let bytes = read_bounded(path, MAX_PERF_REPORT_FILE, "E_PERF_INPUT")?;
        String::from_utf8(bytes).map_err(|_| "E_PERF_INPUT".into())
    };
    let baseline = read(baseline_path)?;
    let candidate = read(candidate_path)?;
    let mut pairs = Vec::new();
    for group in rest.chunks_exact(3) {
        if group[0] != "--pair" { return Err("E_PERF_USAGE".into()); }
        pairs.push((read(&group[1])?, read(&group[2])?));
    }
    let references = pairs.iter().map(|(left, right)| (left.as_str(), right.as_str())).collect::<Vec<_>>();
    let summary = performance::compare(&baseline, &candidate, &references)?;
    println!("{summary}");
    Ok(())
}

fn read_bounded(path: &str, limit: u64, code: &'static str) -> Result<Vec<u8>, String> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| code.to_owned())?;
    if !path_metadata.is_file() || path_metadata.len() > limit {
        return Err(code.into());
    }
    let file = File::open(path).map_err(|_| code.to_owned())?;
    let metadata = file.metadata().map_err(|_| code.to_owned())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(code.into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| code.to_owned())?;
    if bytes.len() as u64 > limit {
        return Err(code.into());
    }
    Ok(bytes)
}

fn host_triple() -> Option<&'static str> {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu")) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    }
}

fn print_summary(
    manifest: &manifest::ExperimentManifest,
    input_sha256: &str,
    input_len: usize,
    summary: &harness::FuzzSummary,
) {
    let code = summary.code.map_or("null".to_owned(), |value| format!("\"{}\"", crate::json_escape(value)));
    let minimized_hash = summary.minimized_sha256.as_ref()
        .map_or("null".to_owned(), |value| format!("\"{value}\""));
    let minimized_len = summary.minimized_len.map_or("null".to_owned(), |value| value.to_string());
    println!(
        "{{\"version\":1,\"target_id\":\"{}\",\"profile\":\"{}\",\"status\":\"{}\",\"code\":{},\"input_sha256\":\"{}\",\"input_bytes\":{},\"cases\":{},\"accepted\":{},\"rejected\":{},\"limited\":{},\"minimized_sha256\":{},\"minimized_bytes\":{}}}",
        manifest.target_id, manifest.profile, summary.status, code, input_sha256, input_len,
        summary.cases, summary.accepted, summary.rejected, summary.limited,
        minimized_hash, minimized_len,
    );
}
