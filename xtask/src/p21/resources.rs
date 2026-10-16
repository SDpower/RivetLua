//! P21 宿主進程內的產品資源與終止量測；輸出原始觀察值，不執行外部工具。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rivetlua::{
    AllocationPeaks, Engine, GcTrace, LedgerSnapshot, LuaProfile, Module, RunOutcome, Vm,
};

const NORMAL_SOURCE: &[u8] = b"local t = {}\nlocal sum = 0\nfor i = 1, 64 do\n  t[i] = i\n  sum = sum + t[i]\nend\nreturn sum";
const FUEL_SOURCE: &[u8] = b"while true do end";
const INTERRUPT_SOURCE: &[u8] = b"return 7";
const NORMAL_FUEL: u64 = 50_000;
const STOP_FUEL: u64 = 32;
const RECOVERY_FUEL: u64 = 128;

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let profiles: &[LuaProfile] = match args {
        [] => &[LuaProfile::Lua54, LuaProfile::Lua55],
        [name] if name == "lua54" => &[LuaProfile::Lua54],
        [name] if name == "lua55" => &[LuaProfile::Lua55],
        _ => return Err("用法：platform resources [lua54|lua55]".into()),
    };
    let mut reports = Vec::with_capacity(profiles.len());
    for &profile in profiles {
        reports.push(profile_report(profile)?);
    }
    println!("{{\"version\":1,\"measurement_kind\":\"in-process-interpreter\",\"unavailable\":{{\"flash_bytes\":null,\"static_ram_bytes\":null,\"physical_peak_ram_bytes\":null,\"rss_bytes\":null,\"reason\":\"沒有受測映像與記憶體映射或獨立實體量測；邏輯帳本不能替代這些數值\"}},\"profiles\":[{}]}}", reports.join(","));
    Ok(())
}

fn profile_report(profile: LuaProfile) -> Result<String, String> {
    let engine = Engine::new(profile);
    let normal = compile(&engine, NORMAL_SOURCE, "normal")?;
    let fuel = compile(&engine, FUEL_SOURCE, "fuel")?;
    let interrupt = compile(&engine, INTERRUPT_SOURCE, "interrupt")?;
    let started = Instant::now();
    let mut vm = engine.new_vm().map_err(|error| format!("建立 VM 失敗：{error:?}"))?;
    let vm_init_ns = started.elapsed().as_nanos();
    vm.set_allocation_limit(16 * 1024 * 1024);

    let normal_case = run_case(&mut vm, &normal, "normal-table-numeric", NORMAL_FUEL, None)?;
    let fuel_case = run_case(&mut vm, &fuel, "fuel-exhaustion", STOP_FUEL, None)?;
    let interrupt_flag = Arc::new(AtomicBool::new(true));
    let interrupted_case = run_case(
        &mut vm, &interrupt, "interrupt", RECOVERY_FUEL, Some(interrupt_flag),
    )?;
    // 前一個 execution 已終止；恢復量測是在同一 VM 上建立新的 execution。
    let recovery_case = run_case(&mut vm, &interrupt, "new-execution-recovery", RECOVERY_FUEL, None)?;
    let profile_name = match profile { LuaProfile::Lua54 => "lua54", LuaProfile::Lua55 => "lua55" };
    Ok(format!("{{\"lua_profile\":\"{profile_name}\",\"vm_init_ns\":{vm_init_ns},\"recovery_scope\":\"same_vm_new_execution_after_terminal\",\"cases\":[{normal_case},{fuel_case},{interrupted_case},{recovery_case}]}}"))
}

fn compile(engine: &Engine, source: &[u8], name: &str) -> Result<Module, String> {
    engine.compile_named(source, name.as_bytes())
        .map_err(|error| format!("{name} 編譯失敗：{error:?}"))
}

fn run_case(
    vm: &mut Vm,
    module: &Module,
    id: &str,
    fuel_limit: u64,
    interrupt_flag: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    let started = Instant::now();
    let mut execution = vm.load_module(module)
        .map_err(|error| format!("{id} 載入失敗：{error:?}"))?;
    execution.set_fuel(fuel_limit)
        .map_err(|error| format!("{id} 設定 fuel 失敗：{error:?}"))?;
    if let Some(flag) = &interrupt_flag {
        execution.set_interrupt_flag(Arc::clone(flag))
            .map_err(|error| format!("{id} 設定中斷旗標失敗：{error:?}"))?;
    }
    let outcome = execution.run();
    drop(execution);
    let elapsed_ns = started.elapsed().as_nanos();
    let result = outcome_json(&outcome);
    drop(outcome);
    let flag_after = interrupt_flag.as_ref().map_or_else(
        || "null".to_owned(),
        |flag| flag.load(Ordering::Acquire).to_string(),
    );
    let snapshot = vm.allocation_snapshot();
    let peaks = vm.allocation_peaks();
    let trace = vm.gc_trace();
    Ok(format!("{{\"id\":{},\"fuel_limit\":{fuel_limit},\"elapsed_ns\":{elapsed_ns},\"outcome\":{result},\"interrupt_flag_after\":{flag_after},\"ledger\":{},\"logical_peaks\":{},\"gc\":{},\"native\":{{\"mode\":\"interpreter\",\"code_cache_bytes\":0}}}}",
        quoted(id), ledger_json(snapshot), peaks_json(peaks), gc_json(trace)))
}

fn outcome_json(outcome: &Result<RunOutcome, rivetlua::RuntimeError>) -> String {
    match outcome {
        Ok(RunOutcome::Returned(values)) => format!(
            "{{\"kind\":\"Returned\",\"values_debug\":{}}}", quoted(&format!("{values:?}"))),
        Ok(RunOutcome::Aborted(reason)) => format!(
            "{{\"kind\":\"Aborted\",\"reason\":{}}}", quoted(&format!("{reason:?}"))),
        Ok(RunOutcome::LuaError(error)) => format!(
            "{{\"kind\":\"LuaError\",\"diagnostic_id\":{},\"reason\":{}}}",
            quoted(error.diagnostic_id), quoted(&format!("{:?}", error.kind))),
        Ok(other) => format!(
            "{{\"kind\":\"Other\",\"value_debug\":{}}}", quoted(&format!("{other:?}"))),
        Err(error) => format!(
            "{{\"kind\":\"RuntimeError\",\"diagnostic_id\":{},\"reason\":{}}}",
            quoted(error.diagnostic_id), quoted(&format!("{:?}", error.kind))),
    }
}

fn ledger_json(snapshot: LedgerSnapshot) -> String {
    format!("{{\"limit\":{},\"committed\":{},\"reserved\":{},\"lua_heap_bytes\":{},\"host_allocation_bytes\":{}}}",
        snapshot.limit, snapshot.committed, snapshot.reserved,
        snapshot.lua_heap_bytes, snapshot.host_allocation_bytes)
}

fn peaks_json(peaks: AllocationPeaks) -> String {
    format!("{{\"committed\":{},\"outstanding\":{},\"lua_heap_bytes\":{},\"host_allocation_bytes\":{}}}",
        peaks.committed, peaks.outstanding, peaks.lua_heap_bytes, peaks.host_allocation_bytes)
}

fn gc_json(trace: GcTrace) -> String {
    format!("{{\"phase\":{},\"transition_count\":{},\"reclaimed_bytes\":{}}}",
        quoted(&format!("{:?}", trace.phase)), trace.transition_count, trace.reclaimed_bytes)
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}
