//! P23 手動效能收集與唯讀比較；不修改基線或啟動外部工具。

use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Instant;

use rivetlua::{CallbackResult, Engine, LuaProfile, RunOutcome, Value};

use super::manifest::ExperimentManifest;
use crate::{StrictJsonParser, StrictJsonValue};

const CALLBACK_WORKLOAD: &[u8] = b"host-callback:return-7";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub(super) fn regression_requires_triage(
    baseline_ns: u64,
    candidate_ns: u64,
) -> Result<bool, &'static str> {
    if baseline_ns == 0 || candidate_ns == 0 {
        return Err("E_PERF_SAMPLE");
    }
    Ok(u128::from(candidate_ns) * 10 > u128::from(baseline_ns) * 11)
}

pub(super) fn workload_digest() -> Result<String, String> {
    let mut input = Vec::new();
    for (id, source) in crate::p20::p23_workloads() {
        input.extend_from_slice(id.as_bytes());
        input.push(0);
        input.extend_from_slice(source.as_bytes());
        input.push(0);
    }
    input.extend_from_slice(CALLBACK_WORKLOAD);
    crate::p17::package_sha256_bytes(&input).map_err(|_| "E_PERF_DIGEST".into())
}

pub(super) struct PerfCollection {
    pub json: String,
    pub all_jit_fallback: bool,
}

pub(super) fn collect(manifest: &ExperimentManifest) -> Result<PerfCollection, String> {
    manifest.validate()?;
    if manifest.batch != "P23-B04" || manifest.worker_policy != "Compatibility" {
        return Err("E_PERF_MANIFEST".into());
    }
    if super::host_triple() != Some(manifest.target.as_str()) {
        return Err("E_PERF_HOST_UNSUPPORTED".into());
    }
    let profile = match manifest.profile.as_str() {
        "lua55-i64f64" => LuaProfile::Lua55,
        "lua54-i64f64" => LuaProfile::Lua54,
        _ => return Err("E_PERF_PROFILE".into()),
    };
    let digest = workload_digest()?;
    if !digest.eq_ignore_ascii_case(&manifest.scenario_sha256)
        || !manifest.input_sha256.eq_ignore_ascii_case(EMPTY_SHA256)
        || !manifest.corpus_sha256.eq_ignore_ascii_case(EMPTY_SHA256)
    {
        return Err("E_PERF_INPUT_DIGEST".into());
    }
    let jit = manifest.features.iter().any(|feature| feature == "jit");
    let modes = if jit { 2 } else { 1 };
    let required_cases = 3 * crate::p20::P23_RUNS_PER_WORKLOAD * modes + 6;
    let longest_source = crate::p20::p23_workloads()
        .into_iter()
        .map(|(_, source)| source.len())
        .max()
        .unwrap_or(0);
    if manifest.budget.fuel < crate::p20::P23_FUEL
        || manifest.budget.heap_bytes < crate::p20::P23_HEAP_LIMIT as u64
        || manifest.budget.cases < required_cases as u64
        || manifest.budget.max_input_bytes < longest_source as u64
    {
        return Err("E_PERF_BUDGET".into());
    }

    let start = Instant::now();
    let engine = Engine::new(profile);
    let cold_start = Instant::now();
    let mut callback_vm = engine.new_vm().map_err(|_| "E_PERF_VM")?;
    let cold_vm_ns = cold_start.elapsed().as_nanos();
    callback_vm.set_allocation_limit(crate::p20::P23_HEAP_LIMIT);
    let callback = callback_vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(7)])),
        )
        .map_err(|_| "E_PERF_CALLBACK")?;
    let mut callback_ns = Vec::with_capacity(5);
    for _ in 0..5 {
        let mut execution = callback_vm
            .call(&callback, &[])
            .map_err(|_| "E_PERF_CALLBACK")?;
        execution
            .set_fuel(crate::p20::P23_FUEL)
            .map_err(|_| "E_PERF_FUEL")?;
        let tick = Instant::now();
        let outcome = execution.run().map_err(|_| "E_PERF_CALLBACK")?;
        callback_ns.push(tick.elapsed().as_nanos());
        if !matches!(outcome, RunOutcome::Returned(ref values) if values.as_slice() == [Value::Integer(7)])
        {
            return Err("E_PERF_CALLBACK_RESULT".into());
        }
    }
    drop(callback);
    callback_vm.collect().map_err(|_| "E_PERF_GC")?;
    let callback_ledger = callback_vm.allocation_snapshot();
    drop(callback_vm);

    let mut scenarios = crate::p20::p23_collect(
        &manifest.profile,
        profile,
        &manifest.target,
        &manifest.toolchain,
        false,
    )
    .map_err(|_| "E_PERF_COLLECT")?;
    let mut native_executed = 0u128;
    let mut total_logical = 0u128;
    if jit {
        for scenario in crate::p20::p23_collect(
            &manifest.profile,
            profile,
            &manifest.target,
            &manifest.toolchain,
            true,
        )
        .map_err(|_| "E_PERF_COLLECT")?
        {
            let value = StrictJsonParser::parse(&scenario).map_err(|_| "E_PERF_REPORT")?;
            for sample in field(&value, "raw_samples")?
                .as_array()
                .ok_or("E_PERF_REPORT")?
            {
                native_executed = native_executed
                    .checked_add(number(sample, "native_executed")?)
                    .ok_or("E_PERF_REPORT")?;
                total_logical = total_logical
                    .checked_add(number(sample, "total_logical_instructions")?)
                    .ok_or("E_PERF_REPORT")?;
            }
            scenarios.push(scenario);
        }
    }
    if start.elapsed().as_secs() >= manifest.budget.seconds {
        return Err("E_PERF_DEADLINE".into());
    }
    let features = manifest
        .features
        .iter()
        .map(|item| quoted(item))
        .collect::<Vec<_>>()
        .join(",");
    let callback_samples = callback_ns
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let jit_status = if !jit {
        "NOT_REQUESTED"
    } else if native_executed == 0 {
        "FALLBACK"
    } else {
        "NATIVE_EXECUTED"
    };
    let json = format!(
        "{{\"version\":1,\"identity\":{{\"experiment_id\":{},\"commit\":{},\"dirty\":{},\"crate\":{},\"target_id\":{},\"seed\":{},\"worker_policy\":{},\"profile\":{},\"numeric\":{},\"target\":{},\"cpu\":{},\"os\":{},\"toolchain\":{},\"features\":[{features}],\"scenario_sha256\":{},\"corpus_sha256\":{},\"input_sha256\":{},\"fuel\":{},\"heap_bytes\":{},\"cases\":{},\"seconds\":{},\"max_input_bytes\":{},\"max_depth\":{},\"iterations\":5,\"warmup\":2}},\"environment_source\":\"supplied-manifest\",\"cold_vm_ns\":{cold_vm_ns},\"host_callback_ns\":[{callback_samples}],\"host_callback_ledger\":{{\"committed\":{},\"reserved\":{},\"lua_heap_bytes\":{},\"host_allocation_bytes\":{}}},\"memory\":{{\"heap_limit_bytes\":{},\"shared_module_resident_bytes\":null,\"physical_rss_bytes\":null}},\"jit\":{{\"status\":{},\"native_executed\":{native_executed},\"total_logical\":{total_logical},\"native_ratio\":{}}},\"scenarios\":[{}],\"baseline_approved\":false}}",
        quoted(&manifest.experiment_id),
        quoted(&manifest.commit),
        manifest.dirty,
        quoted(&manifest.crate_name),
        quoted(&manifest.target_id),
        manifest.seed,
        quoted(&manifest.worker_policy),
        quoted(&manifest.profile),
        quoted(&manifest.numeric),
        quoted(&manifest.target),
        quoted(&manifest.cpu),
        quoted(&manifest.os),
        quoted(&manifest.toolchain),
        quoted(&manifest.scenario_sha256),
        quoted(&manifest.corpus_sha256),
        quoted(&manifest.input_sha256),
        manifest.budget.fuel,
        manifest.budget.heap_bytes,
        manifest.budget.cases,
        manifest.budget.seconds,
        manifest.budget.max_input_bytes,
        manifest.budget.max_depth,
        callback_ledger.committed,
        callback_ledger.reserved,
        callback_ledger.lua_heap_bytes,
        callback_ledger.host_allocation_bytes,
        crate::p20::P23_HEAP_LIMIT,
        quoted(jit_status),
        if total_logical == 0 {
            "null".to_owned()
        } else {
            format!("{:.6}", native_executed as f64 / total_logical as f64)
        },
        scenarios.join(","),
    );
    Ok(PerfCollection {
        json,
        all_jit_fallback: jit && native_executed == 0,
    })
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}

fn field<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(key).ok_or_else(|| "E_PERF_REPORT".into())
}

fn number(value: &StrictJsonValue, key: &str) -> Result<u128, String> {
    let StrictJsonValue::Number(text) = field(value, key)? else {
        return Err("E_PERF_REPORT".into());
    };
    text.parse::<u128>().map_err(|_| "E_PERF_REPORT".into())
}

struct Report {
    experiment_id: String,
    commit: String,
    comparable: Vec<String>,
    samples: BTreeMap<(String, String), u64>,
}

fn report(input: &str) -> Result<Report, String> {
    let value = StrictJsonParser::parse(input).map_err(|_| "E_PERF_REPORT")?;
    if number(&value, "version")? != 1 {
        return Err("E_PERF_REPORT".into());
    }
    let identity = field(&value, "identity")?;
    if !matches!(field(identity, "dirty")?, StrictJsonValue::Bool(false)) {
        return Err("E_PERF_DIRTY".into());
    }
    let get = |key| -> Result<String, String> {
        match field(identity, key)? {
            StrictJsonValue::String(text) => Ok(text.clone()),
            StrictJsonValue::Number(text) => Ok(text.clone()),
            _ => Err("E_PERF_REPORT".into()),
        }
    };
    let experiment_id = get("experiment_id")?;
    let commit = get("commit")?;
    if experiment_id.is_empty()
        || commit.len() != 40
        || !commit.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("E_PERF_REPORT".into());
    }
    let mut comparable = [
        "crate",
        "target_id",
        "seed",
        "worker_policy",
        "profile",
        "numeric",
        "target",
        "cpu",
        "os",
        "toolchain",
        "scenario_sha256",
        "corpus_sha256",
        "input_sha256",
        "fuel",
        "heap_bytes",
        "cases",
        "seconds",
        "max_input_bytes",
        "max_depth",
        "iterations",
        "warmup",
    ]
    .iter()
    .map(|key| get(key))
    .collect::<Result<Vec<_>, _>>()?;
    let mut features = field(identity, "features")?
        .as_array()
        .ok_or("E_PERF_REPORT")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or("E_PERF_REPORT".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    features.sort();
    comparable.push(features.join("\0"));
    let mut samples = BTreeMap::new();
    let jit_expected = features.iter().any(|feature| feature == "jit");
    let jit = field(&value, "jit")?;
    let jit_status = field(jit, "status")?.as_str().ok_or("E_PERF_REPORT")?;
    if (jit_expected && (jit_status != "NATIVE_EXECUTED" || number(jit, "native_executed")? == 0))
        || (!jit_expected && jit_status != "NOT_REQUESTED")
    {
        return Err("E_PERF_JIT_FALLBACK".into());
    }
    for scenario in field(&value, "scenarios")?
        .as_array()
        .ok_or("E_PERF_REPORT")?
    {
        let info = field(scenario, "identity")?;
        let workload_id = field(info, "workload_id")?
            .as_str()
            .ok_or("E_PERF_REPORT")?;
        let Some((_, source)) = crate::p20::p23_workloads()
            .into_iter()
            .find(|(id, _)| *id == workload_id)
        else {
            return Err("E_PERF_REPORT".into());
        };
        let source_sha =
            crate::p17::package_sha256_bytes(source.as_bytes()).map_err(|_| "E_PERF_REPORT")?;
        for (key, expected) in [
            ("lua_profile", get("profile")?),
            ("target", get("target")?),
            ("toolchain", get("toolchain")?),
            ("source_hash", source_sha),
        ] {
            if field(info, key)?.as_str() != Some(expected.as_str()) {
                return Err("E_PERF_REPORT".into());
            }
        }
        let mode = field(info, "jit_mode")?.as_str().ok_or("E_PERF_REPORT")?;
        if !matches!(mode, "interpreter" | "jit") || (mode == "jit" && !jit_expected) {
            return Err("E_PERF_REPORT".into());
        }
        let key = (workload_id.to_owned(), mode.to_owned());
        let raw = field(scenario, "raw_samples")?
            .as_array()
            .ok_or("E_PERF_REPORT")?;
        if raw.len() != 6 {
            return Err("E_PERF_REPORT".into());
        }
        let mut hot = Vec::new();
        for sample in raw {
            match field(sample, "kind")?.as_str().ok_or("E_PERF_REPORT")? {
                "hot" => {
                    hot.push(u64::try_from(number(sample, "hot_ns")?).map_err(|_| "E_PERF_REPORT")?)
                }
                "first" => {}
                _ => return Err("E_PERF_REPORT".into()),
            }
        }
        if hot.len() != 5 || hot.contains(&0) {
            return Err("E_PERF_REPORT".into());
        }
        hot.sort_unstable();
        let summary = field(scenario, "summary")?;
        let p50 = u64::try_from(number(summary, "hot_ns_p50")?).map_err(|_| "E_PERF_REPORT")?;
        if p50 != hot[2] || samples.insert(key, p50).is_some() {
            return Err("E_PERF_REPORT".into());
        }
    }
    if samples.len() != if jit_expected { 6 } else { 3 } {
        return Err("E_PERF_REPORT".into());
    }
    Ok(Report {
        experiment_id,
        commit,
        comparable,
        samples,
    })
}

fn pair_regressions(baseline: &Report, candidate: &Report) -> Result<Vec<String>, String> {
    if baseline.comparable != candidate.comparable
        || baseline.samples.keys().ne(candidate.samples.keys())
    {
        return Err("E_PERF_INCOMPARABLE".into());
    }
    baseline
        .samples
        .iter()
        .filter_map(|(key, baseline_ns)| {
            let candidate_ns = candidate.samples[key];
            match regression_requires_triage(*baseline_ns, candidate_ns) {
                Ok(true) => Some(Ok(format!("{}:{}", key.0, key.1))),
                Ok(false) => None,
                Err(code) => Some(Err(code.to_owned())),
            }
        })
        .collect()
}

pub(super) fn compare(
    initial_baseline: &str,
    initial_candidate: &str,
    reruns: &[(&str, &str)],
) -> Result<String, String> {
    if reruns.len() > 3 {
        return Err("E_PERF_RERUNS".into());
    }
    let baseline = report(initial_baseline)?;
    let candidate = report(initial_candidate)?;
    let mut regressions = pair_regressions(&baseline, &candidate)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut seen = std::collections::BTreeSet::from([
        baseline.experiment_id.clone(),
        candidate.experiment_id.clone(),
    ]);
    if seen.len() != 2 {
        return Err("E_PERF_RERUNS".into());
    }
    let mut rerun_regressions = 0usize;
    for (left_text, right_text) in reruns {
        let left = report(left_text)?;
        let right = report(right_text)?;
        if left.commit != baseline.commit
            || right.commit != candidate.commit
            || left.comparable != baseline.comparable
            || right.comparable != candidate.comparable
            || !seen.insert(left.experiment_id.clone())
            || !seen.insert(right.experiment_id.clone())
        {
            return Err("E_PERF_RERUNS".into());
        }
        let pair_affected = pair_regressions(&left, &right)?;
        rerun_regressions += usize::from(!pair_affected.is_empty());
        regressions.extend(pair_affected);
    }
    let state = if regressions.is_empty() {
        "NO_REGRESSION"
    } else if reruns.len() < 3 {
        "PAIRED_RERUNS_REQUIRED"
    } else {
        "INDEPENDENT_REVIEW_REQUIRED"
    };
    let affected = regressions
        .iter()
        .map(|item| quoted(item))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"version\":1,\"comparison_scope\":\"hot_ns_p50\",\"baseline_commit\":{},\"candidate_commit\":{},\"regressed_scenarios\":[{affected}],\"paired_reruns\":{},\"rerun_pairs_with_regression\":{rerun_regressions},\"rerun_evidence\":\"supplied-reports\",\"independence_verified\":false,\"triage_state\":{},\"baseline_approved\":false}}",
        quoted(&baseline.commit),
        quoted(&candidate.commit),
        reruns.len(),
        quoted(state),
    ))
}
