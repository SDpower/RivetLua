use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value, VerifiedModule,
    VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{
    DumpCapability, DumpLimits, HostServices, LoadCapability, LoadLimits, RootKind, RunOutcome, Vm,
};

// Dump 先預扣完整 work 上限；fuel 配給一次 dump、一次 load 與原預設 guest 指令額度。
const P17_HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const P17_EXECUTION_FUEL: u64 = P17_HOST_WORK_UNITS * 2 + 1_000_000;

const SOURCE: &[u8] = br#"
local function exercise()
  local c = "abc"
  local expected = {"bbc", "acc", "abd"}
  local checksum = 0
  for i = 1, #c do
    local s = string.sub(c, 1, i - 1) ..
              string.char((string.byte(string.sub(c, i, i)) + 1) & 0xFF) ..
              string.sub(c, i + 1, -1)
    assert(s == expected[i])
    checksum = checksum + #s
    assert(s ~= "")
  end
  assert(checksum == 9)
  return checksum
end

assert(exercise() == 9)
local bytes = string.dump(exercise, false)
local loaded = assert(load(bytes, "@p17-calls-slot-overlap", "b", _ENV))
assert(loaded() == 9)
return 9
"#;

fn compile(source: &[u8], language: LanguageProfile) -> Result<VerifiedModule, String> {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).map_err(|error| format!("lex: {error:?}"))?;
    let syntax = parse(&chunk, language, &limits)
        .map_err(|error| format!("parse: {error:?}"))?;
    let resolved = resolve(&syntax, &chunk, language, &limits)
        .map_err(|error| format!("resolve: {error:?}"))?;
    let ir = lower(&resolved, &IrLimits::default())
        .map_err(|error| format!("lower: {error:?}"))?;
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-calls-slot-overlap.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn official_roundtrip(
    module: &VerifiedModule,
    profile: LuaProfile,
    strip: bool,
) -> Result<VerifiedModule, String> {
    let limits = OfficialChunkLimits::default();
    let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default())
        .map_err(|error| format!("{profile:?} strip={strip} work budget: {error:?}"))?;
    let bytes = emit_official_chunk(module, ProtoId(0), profile, strip, &limits, &mut work)
        .map_err(|error| format!("{profile:?} strip={strip} export: {error:?}"))?;
    let decoded = decode_official_chunk(&bytes, profile, &limits)
        .map_err(|error| format!("{profile:?} strip={strip} decode: {error:?}"))?;
    translate_official_chunk(&decoded, &VerifyLimits::default())
        .map(|translated| translated.verified().clone())
        .map_err(|error| format!("{profile:?} strip={strip} translate: {error:?}"))
}

// 沿用 P17 完整 db.lua 的有限 work 額度；其餘容量限制保留預設值。
fn run_with_p17_finite_dump_load_limits(
    module: VerifiedModule,
    profile: LuaProfile,
    origin: &str,
) -> Result<(), String> {
    let dump_limits = DumpLimits {
        max_work_units: P17_HOST_WORK_UNITS as usize,
        ..DumpLimits::default()
    };
    // P17 roundtrip 測試沿用 dump 的有限暫存上限，讓 load／dump 使用同一 4 MiB 額度。
    let load_limits = LoadLimits {
        max_work_units: P17_HOST_WORK_UNITS as usize,
        max_temporary_bytes: dump_limits.max_temporary_bytes,
        ..LoadLimits::default()
    };
    let services = HostServices::deny_all()
        .and_dump(
            DumpCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(dump_limits),
        )
        .and_load(
            LoadCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(load_limits),
        );
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("{profile:?} {origin}: VM creation: {error:?}"))?;
    let environment = match vm.allocate_table() {
        Ok(environment) => environment,
        Err(error) => {
            let ledger = vm.ledger_snapshot();
            return Err(format!(
                "{profile:?} {origin}: environment allocation: {error:?}; run_result=not_run; roots={}; reserved={}",
                vm.roots().total_count(),
                ledger.reserved
            ));
        }
    };
    let mut failures = Vec::new();
    if let Err(error) = vm.install_basic_builtins(environment) {
        failures.push(format!("basic builtins: {error:?}"));
    }
    if let Err(error) = vm.install_string_builtins(environment) {
        failures.push(format!("string builtins: {error:?}"));
    }

    // 以 Basic／String builtins 安裝後的 VM roots 為基線；string metatable 會保留 Registry root。
    let roots_before = vm.roots().total_count();
    let root_counts_before = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = if failures.is_empty() {
        match vm.add_root(RootKind::Host, environment) {
            Ok(root) => Some(root),
            Err(error) => {
                failures.push(format!("environment root: {error:?}"));
                None
            }
        }
    } else {
        None
    };

    let run_result = if failures.is_empty() {
        match vm.load_with_environment(module, Value::Object(environment)) {
            Ok(mut execution) => {
                let result = execution
                    .set_fuel(P17_EXECUTION_FUEL)
                    .and_then(|()| execution.run());
                drop(execution);
                result.map_err(|error| format!("{error:?}"))
            }
            Err(error) => Err(format!("load: {error:?}")),
        }
    } else {
        Err("not run: builtin installation failed".to_owned())
    };
    match &run_result {
        Err(_) => failures.push(format!("run_result={run_result:?}")),
        Ok(outcome) if outcome != &RunOutcome::Returned(vec![Value::Integer(9)]) => {
            failures.push(format!("unexpected run_result={run_result:?}; expected integer 9"));
        }
        Ok(_) => {}
    }

    if let Some(environment_root) = environment_root {
        if let Err(error) = vm.remove_root(environment_root) {
            failures.push(format!("root cleanup: {error:?}"));
        }
    }
    let roots = vm.roots().total_count();
    let root_counts_after = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let ledger = vm.ledger_snapshot();
    if roots != roots_before {
        failures.push(format!(
            "roots after cleanup={roots}; expected baseline {roots_before}"
        ));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        if root_counts_after[index] != root_counts_before[index] {
            failures.push(format!(
                "{kind:?} roots after cleanup={}; expected baseline {}",
                root_counts_after[index],
                root_counts_before[index]
            ));
        }
    }
    if ledger.reserved != 0 {
        failures.push(format!(
            "reserved ledger after cleanup={}; expected 0",
            ledger.reserved
        ));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{profile:?} {origin}: {}; run_result={run_result:?}; roots_after_cleanup={roots} (baseline={roots_before}); reserved_after_cleanup={}",
            failures.join("; "),
            ledger.reserved
        ))
    }
}

#[test]
fn p17_calls_slot_overlap_runtime_roundtrip() {
    let mut failures = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let native = match compile(SOURCE, language) {
            Ok(module) => module,
            Err(error) => {
                failures.push(format!("{profile:?} native compile: {error}"));
                continue;
            }
        };

        let mut origins = vec![("native", native.clone())];
        for (origin, strip) in [("official-unstripped", false), ("official-stripped", true)] {
            match official_roundtrip(&native, profile, strip) {
                Ok(module) => origins.push((origin, module)),
                Err(error) => failures.push(format!("{profile:?} {origin} preparation: {error}")),
            }
        }

        for (origin, module) in origins {
            if let Err(error) = run_with_p17_finite_dump_load_limits(module, profile, origin) {
                failures.push(error);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "P17 calls slot overlap failures:\n{}",
        failures.join("\n")
    );
}
