use std::time::Instant;

use rivetlua::{
    ContainerLimits, Engine, GcTrace, JitPolicy, JitStats, LedgerSnapshot, LuaProfile, RunOutcome,
    TransportBudget, Value,
};

const WARMUP: usize = 2;
const ITERATIONS: usize = 5;
const FUEL: u64 = 100_000;
const HEAP_LIMIT: usize = 16 * 1024 * 1024;
pub(super) const P23_FUEL: u64 = FUEL;
pub(super) const P23_HEAP_LIMIT: usize = HEAP_LIMIT;
pub(super) const P23_RUNS_PER_WORKLOAD: usize = 1 + WARMUP + ITERATIONS;
const USAGE: &str = "用法：perf baseline --target <target-triple> --toolchain <toolchain-label> [--jit] [lua54|lua55]";

#[derive(Clone, Copy)]
enum Expected {
    Integer(i64),
    Float(f64),
}

struct Workload {
    id: &'static str,
    source: &'static str,
    expected: Expected,
}

const WORKLOADS: [Workload; 3] = [
    Workload {
        id: "integer-loop",
        source: "local sum = 0\nlocal i = 1\nwhile i <= 1000 do\n  sum = sum + i\n  i = i + 1\nend\nreturn sum",
        expected: Expected::Integer(500_500),
    },
    Workload {
        id: "float-loop",
        source: "local sum = 0.0\nfor i = 1, 1000 do\n  sum = sum + i * 0.5\nend\nreturn sum",
        expected: Expected::Float(250_250.0),
    },
    Workload {
        id: "table-lookup",
        source: "local values = {11, 13, 17, 19}\nlocal sum = 0\nfor i = 1, 1000 do\n  sum = sum + values[(i % 4) + 1]\nend\nreturn sum",
        expected: Expected::Integer(15_000),
    },
];

struct Options<'a> {
    target: &'a str,
    toolchain: &'a str,
    profile: Option<&'a str>,
    jit: bool,
}

#[derive(Clone, Copy)]
enum SampleKind {
    First,
    Hot,
    Warmup,
}

impl SampleKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Hot => "hot",
            Self::Warmup => "warmup",
        }
    }
}

struct Sample {
    kind: SampleKind,
    iteration: usize,
    compile_ns: Option<u128>,
    load_ns: u128,
    first_ns: Option<u128>,
    hot_ns: Option<u128>,
    gc_ns: u128,
    cache_bytes: usize,
    jit_stats: JitStats,
    jit: bool,
    ledger_before_load: LedgerSnapshot,
    ledger_after_run: LedgerSnapshot,
    ledger_after_collect: LedgerSnapshot,
    trace_before_load: GcTrace,
    trace_after_run: GcTrace,
    trace_after_collect: GcTrace,
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    let options = parse_arguments(arguments)?;
    validate_target(options.target, current_host_target())?;

    let profiles = [
        ("lua54", "lua54-i64f64", LuaProfile::Lua54),
        ("lua55", "lua55-i64f64", LuaProfile::Lua55),
    ];
    let mut scenarios = Vec::with_capacity(6);
    for (profile_argument, profile_name, profile) in profiles {
        if options
            .profile
            .is_some_and(|selected| selected != profile_argument)
        {
            continue;
        }
        for workload in &WORKLOADS {
            scenarios.push(run_scenario(
                workload,
                profile_name,
                profile,
                options.target,
                options.toolchain,
                options.jit,
            )?);
        }
    }

    println!("{{\"version\":1,\"scenarios\":[{}]}}", scenarios.join(","));
    Ok(())
}

fn parse_arguments(arguments: &[String]) -> Result<Options<'_>, String> {
    if arguments.first().map(String::as_str) != Some("baseline") {
        return Err(USAGE.into());
    }

    let mut target = None;
    let mut toolchain = None;
    let mut profile = None;
    let mut jit = false;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--target" => {
                index += 1;
                let value = arguments.get(index).ok_or(USAGE)?;
                if target.replace(value.as_str()).is_some() || value.is_empty() {
                    return Err(USAGE.into());
                }
            }
            "--toolchain" => {
                index += 1;
                let value = arguments.get(index).ok_or(USAGE)?;
                if toolchain.replace(value.as_str()).is_some()
                    || value.trim().is_empty()
                    || value.chars().any(char::is_control)
                {
                    return Err(USAGE.into());
                }
            }
            "lua54" | "lua55" if profile.is_none() => {
                profile = Some(arguments[index].as_str());
            }
            "--jit" if !jit => jit = true,
            _ => return Err(USAGE.into()),
        }
        index += 1;
    }

    Ok(Options {
        target: target.ok_or(USAGE)?,
        toolchain: toolchain.ok_or(USAGE)?,
        profile,
        jit,
    })
}

// shortcut: 僅映射已知的 macOS／Linux GNU host；新增平台時補上核實過的 target triple。
fn current_host_target() -> Option<&'static str> {
    CURRENT_HOST_TARGET
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CURRENT_HOST_TARGET: Option<&str> = Some("aarch64-apple-darwin");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CURRENT_HOST_TARGET: Option<&str> = Some("x86_64-apple-darwin");
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
const CURRENT_HOST_TARGET: Option<&str> = Some("x86_64-unknown-linux-gnu");
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"))]
const CURRENT_HOST_TARGET: Option<&str> = Some("aarch64-unknown-linux-gnu");
#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "linux", target_arch = "aarch64", target_env = "gnu")
)))]
const CURRENT_HOST_TARGET: Option<&str> = None;

fn validate_target(requested: &str, host: Option<&str>) -> Result<(), String> {
    let host = host.ok_or_else(|| "目前 host target 沒有受支援的固定映射".to_owned())?;
    if requested == host {
        Ok(())
    } else {
        Err(format!("只接受目前 host target {host}，收到 {requested}"))
    }
}

fn run_scenario(
    workload: &Workload,
    profile_name: &str,
    profile: LuaProfile,
    target: &str,
    toolchain: &str,
    jit: bool,
) -> Result<String, String> {
    let source_hash = crate::p17::package_sha256_bytes(workload.source.as_bytes())?;
    let engine = Engine::new(profile);
    let compile_start = Instant::now();
    let module = engine
        .compile_named(workload.source.as_bytes(), workload.id.as_bytes())
        .map_err(|error| format!("{} 編譯失敗：{error:?}", workload.id))?;
    let compile_ns = compile_start.elapsed().as_nanos();

    let transport_budget = TransportBudget::new(ContainerLimits::default());
    let module_bytes = engine
        .save_module(&module, &transport_budget)
        .map_err(|error| format!("{} RVCT-v1 編碼失敗：{error:?}", workload.id))?;
    let module_hash = crate::p17::package_sha256_bytes(&module_bytes)?;

    let mut vm = engine
        .new_vm()
        .map_err(|error| format!("{} VM 初始化失敗：{error:?}", workload.id))?;
    vm.set_allocation_limit(HEAP_LIMIT);
    if jit {
        vm.set_jit_policy(JitPolicy::Enabled)
            .map_err(|error| format!("{} 啟用 JIT 失敗：{error:?}", workload.id))?;
    }

    let first = measure_sample(
        &mut vm,
        &module,
        workload,
        SampleKind::First,
        0,
        Some(compile_ns),
        jit,
    )?;
    let mut raw_samples = vec![sample_json(&first)];
    for iteration in 1..=WARMUP {
        let _ = measure_sample(
            &mut vm,
            &module,
            workload,
            SampleKind::Warmup,
            iteration,
            None,
            jit,
        )?;
    }

    let mut hot_times = Vec::with_capacity(ITERATIONS);
    for iteration in 1..=ITERATIONS {
        let sample = measure_sample(
            &mut vm,
            &module,
            workload,
            SampleKind::Hot,
            iteration,
            None,
            jit,
        )?;
        hot_times.push(sample.hot_ns.ok_or("缺少 hot_ns 樣本")?);
        raw_samples.push(sample_json(&sample));
    }
    let p50 = nearest_rank(&hot_times, 50).ok_or("無法計算 hot_ns p50")?;
    let p95 = nearest_rank(&hot_times, 95).ok_or("無法計算 hot_ns p95")?;

    Ok(format!(
        "{{\"identity\":{{\"workload_id\":\"{}\",\"lua_profile\":\"{}\",\"numeric_config\":\"i64f64\",\"target\":\"{}\",\"toolchain\":\"{}\",\"jit_mode\":\"{}\",\"warmup\":{},\"iterations\":{},\"fuel\":{},\"heap_limit\":{},\"callback_policy\":\"deny-all\",\"source_hash\":\"{}\",\"module_format\":\"RVCT-v1\",\"module_hash\":\"{}\"}},\"raw_samples\":[{}],\"summary\":{{\"hot_ns_p50\":{},\"hot_ns_p95\":{}}}}}",
        super::json_escape(workload.id),
        super::json_escape(profile_name),
        super::json_escape(target),
        super::json_escape(toolchain),
        if jit { "jit" } else { "interpreter" },
        WARMUP,
        ITERATIONS,
        FUEL,
        HEAP_LIMIT,
        source_hash,
        module_hash,
        raw_samples.join(","),
        p50,
        p95,
    ))
}

pub(super) fn p23_workloads() -> Vec<(&'static str, &'static str)> {
    WORKLOADS
        .iter()
        .map(|workload| (workload.id, workload.source))
        .collect()
}

pub(super) fn p23_collect(
    profile_name: &str,
    profile: LuaProfile,
    target: &str,
    toolchain: &str,
    jit: bool,
) -> Result<Vec<String>, String> {
    WORKLOADS
        .iter()
        .map(|workload| run_scenario(workload, profile_name, profile, target, toolchain, jit))
        .collect()
}

fn measure_sample(
    vm: &mut rivetlua::Vm,
    module: &rivetlua::Module,
    workload: &Workload,
    kind: SampleKind,
    iteration: usize,
    compile_ns: Option<u128>,
    jit: bool,
) -> Result<Sample, String> {
    let ledger_before_load = vm.allocation_snapshot();
    let trace_before_load = vm.gc_trace();
    let load_start = Instant::now();
    let mut execution = vm
        .load_module(module)
        .map_err(|error| format!("{} 模組載入失敗：{error:?}", workload.id))?;
    let load_ns = load_start.elapsed().as_nanos();
    execution
        .set_fuel(FUEL)
        .map_err(|error| format!("{} 設定 fuel 失敗：{error:?}", workload.id))?;
    let run_start = Instant::now();
    let outcome = execution
        .run()
        .map_err(|error| format!("{} 執行失敗：{error:?}", workload.id))?;
    let run_ns = run_start.elapsed().as_nanos();
    let cache_bytes = execution.lookup_cache_metadata_bytes();
    let jit_stats = execution.jit_stats();
    drop(execution);
    ensure_expected_return(workload, &outcome)?;

    let ledger_after_run = vm.allocation_snapshot();
    let trace_after_run = vm.gc_trace();
    let gc_start = Instant::now();
    vm.collect()
        .map_err(|error| format!("{} GC 失敗：{error:?}", workload.id))?;
    let gc_ns = gc_start.elapsed().as_nanos();
    let ledger_after_collect = vm.allocation_snapshot();
    let trace_after_collect = vm.gc_trace();

    let (first_ns, hot_ns) = match kind {
        SampleKind::First => (Some(run_ns), None),
        SampleKind::Hot => (None, Some(run_ns)),
        SampleKind::Warmup => (None, None),
    };
    Ok(Sample {
        kind,
        iteration,
        compile_ns,
        load_ns,
        first_ns,
        hot_ns,
        gc_ns,
        cache_bytes,
        jit_stats,
        jit,
        ledger_before_load,
        ledger_after_run,
        ledger_after_collect,
        trace_before_load,
        trace_after_run,
        trace_after_collect,
    })
}

fn ensure_expected_return(workload: &Workload, outcome: &RunOutcome) -> Result<(), String> {
    let matches = match outcome {
        RunOutcome::Returned(values) => match (workload.expected, values.as_slice()) {
            (Expected::Integer(expected), [Value::Integer(actual)]) => *actual == expected,
            (Expected::Float(expected), [Value::Float(actual)]) => *actual == expected,
            _ => false,
        },
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(format!("{} 回傳非預期結果：{outcome:?}", workload.id))
    }
}

fn sample_json(sample: &Sample) -> String {
    format!(
        "{{\"kind\":\"{}\",\"iteration\":{},\"compile_ns\":{},\"load_ns\":{},\"first_ns\":{},\"hot_ns\":{},\"gc_ns\":{},\"jit_compile_ns\":{},\"allocation_ledger\":{{\"before_load\":{},\"after_run\":{},\"after_collect\":{}}},\"gc_trace\":{{\"before_load\":{},\"after_run\":{},\"after_collect\":{}}},\"code_bytes\":{},\"cache_bytes\":{},\"lookup_cache_metadata_bytes\":{},\"metadata_bytes\":{},\"shared_module_resident_bytes\":null,\"physical_rss_bytes\":null,\"native_executed\":{},\"total_logical_instructions\":{},\"native_ratio\":{:.6},\"fallback_reason\":{}}}",
        sample.kind.as_str(),
        sample.iteration,
        optional_number(sample.compile_ns),
        sample.load_ns,
        optional_number(sample.first_ns),
        optional_number(sample.hot_ns),
        sample.gc_ns,
        if sample.jit {
            sample.jit_stats.jit_compile_ns.to_string()
        } else {
            "null".into()
        },
        ledger_json(sample.ledger_before_load),
        ledger_json(sample.ledger_after_run),
        ledger_json(sample.ledger_after_collect),
        trace_json(sample.trace_before_load),
        trace_json(sample.trace_after_run),
        trace_json(sample.trace_after_collect),
        sample.jit_stats.code_bytes,
        sample
            .cache_bytes
            .saturating_add(sample.jit_stats.metadata_bytes),
        sample.cache_bytes,
        sample.jit_stats.metadata_bytes,
        sample.jit_stats.native_executed_instructions,
        sample.jit_stats.total_logical_instructions,
        if sample.jit_stats.total_logical_instructions == 0 {
            0.0
        } else {
            sample.jit_stats.native_executed_instructions as f64
                / sample.jit_stats.total_logical_instructions as f64
        },
        sample
            .jit_stats
            .fallback_reason
            .map_or_else(|| "null".to_owned(), |reason| format!("\"{reason:?}\""),),
    )
}

fn optional_number(value: Option<u128>) -> String {
    value.map_or_else(|| "null".into(), |number| number.to_string())
}

fn ledger_json(snapshot: LedgerSnapshot) -> String {
    let shared_rss = snapshot
        .shared_rss_observation
        .map_or_else(|| "null".into(), |bytes| bytes.to_string());
    format!(
        "{{\"limit\":{},\"committed\":{},\"reserved\":{},\"lua_heap_bytes\":{},\"host_allocation_bytes\":{},\"shared_rss_observation\":{shared_rss}}}",
        snapshot.limit,
        snapshot.committed,
        snapshot.reserved,
        snapshot.lua_heap_bytes,
        snapshot.host_allocation_bytes,
    )
}

fn trace_json(trace: GcTrace) -> String {
    format!(
        "{{\"barrier_count\":{},\"reclaimed_bytes\":{},\"transition_count\":{}}}",
        trace.barrier_count, trace.reclaimed_bytes, trace.transition_count,
    )
}

fn nearest_rank(samples: &[u128], percentile: usize) -> Option<u128> {
    if samples.is_empty() || !(1..=100).contains(&percentile) {
        return None;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = ordered.len().saturating_mul(percentile).div_ceil(100);
    ordered.get(rank.saturating_sub(1)).copied()
}

#[cfg(test)]
mod tests {
    use super::{
        WORKLOADS, ensure_expected_return, nearest_rank, parse_arguments, validate_target,
    };
    use rivetlua::{RunOutcome, Value};

    #[test]
    fn p20_nearest_rank_uses_sorted_ceil_rank() {
        let samples = [50, 10, 40, 30, 20];
        assert_eq!(nearest_rank(&samples, 50), Some(30));
        assert_eq!(nearest_rank(&samples, 95), Some(50));
        assert_eq!(nearest_rank(&[], 95), None);
    }

    #[test]
    fn p20_target_must_match_declared_host() {
        assert!(validate_target("aarch64-apple-darwin", Some("aarch64-apple-darwin")).is_ok());
        assert!(validate_target("x86_64-apple-darwin", Some("aarch64-apple-darwin")).is_err());
        assert!(validate_target("aarch64-apple-darwin", None).is_err());
    }

    #[test]
    fn p20_cli_requires_target_and_toolchain_metadata() {
        let valid = [
            "baseline",
            "--target",
            "aarch64-apple-darwin",
            "--toolchain",
            "rust-1.94.1",
            "lua54",
        ]
        .map(str::to_owned);
        let parsed = parse_arguments(&valid).unwrap();
        assert_eq!(parsed.target, "aarch64-apple-darwin");
        assert_eq!(parsed.toolchain, "rust-1.94.1");
        assert_eq!(parsed.profile, Some("lua54"));
        assert!(parse_arguments(&["baseline".to_owned()]).is_err());
    }

    #[test]
    fn p20_rejects_unexpected_guest_results() {
        assert!(
            ensure_expected_return(
                &WORKLOADS[0],
                &RunOutcome::Returned(vec![Value::Integer(500_500)])
            )
            .is_ok()
        );
        assert!(
            ensure_expected_return(
                &WORKLOADS[0],
                &RunOutcome::Returned(vec![Value::Integer(1)])
            )
            .is_err()
        );
    }
}
