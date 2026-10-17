use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value, VerifiedModule,
    VerifyLimits, decode_official_chunk, preflight_official_chunk,
    translate_official_chunk_with_work,
};
use rivetlua_runtime::{
    AbortReason, DumpCapability, DumpLimits, HostServices, RootKind, RunOutcome, RuntimeErrorKind,
    Vm,
};

const DUMP_WORK_CAP: usize = 512 * 1024 * 1024;
const SOURCE: &[u8] =
    b"local bytes = string.dump(function() return 1 end, false); return #bytes > 0\n";

#[derive(Debug)]
enum ObservedOutcome {
    Returned(Vec<Value>),
    LuaError(RuntimeErrorKind),
    Aborted(AbortReason),
    Other { _detail: String },
}

#[derive(Debug)]
struct RunEvidence {
    outcome: ObservedOutcome,
    fuel_remaining: u64,
}

fn compile_source(profile: LuaProfile, source: &[u8]) -> Result<VerifiedModule, String> {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).map_err(|error| format!("lex: {error:?}"))?;
    let syntax = parse(&chunk, language, &limits).map_err(|error| format!("parse: {error:?}"))?;
    let resolved = resolve(&syntax, &chunk, language, &limits)
        .map_err(|error| format!("resolve: {error:?}"))?;
    let ir = lower(&resolved, &IrLimits::default()).map_err(|error| format!("lower: {error:?}"))?;
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-calls-prefix-budget.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn compile(profile: LuaProfile) -> Result<VerifiedModule, String> {
    compile_source(profile, SOURCE)
}

fn actual_dump_work(module: &VerifiedModule, profile: LuaProfile) -> Result<u64, String> {
    let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default())
        .map_err(|error| format!("export work budget: {error:?}"))?;
    let bytes = emit_official_chunk(
        module,
        ProtoId(1),
        profile,
        false,
        &OfficialChunkLimits::default(),
        &mut work,
    )
    .map_err(|error| format!("export: {error:?}"))?;
    work.charge(bytes.len(), ProtoId(1), 0)
        .map_err(|error| format!("output copy work: {error:?}"))?;
    Ok(work.consumed())
}

fn run_case(
    profile: LuaProfile,
    module: &VerifiedModule,
    dump_limits: Option<DumpLimits>,
    fuel: u64,
) -> Result<RunEvidence, String> {
    let services = match dump_limits {
        Some(limits) => HostServices::deny_all().and_dump(
            DumpCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(limits),
        ),
        None => HostServices::deny_all(),
    };
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("VM creation: {error:?}"))?;
    let environment = vm
        .allocate_table()
        .map_err(|error| format!("environment allocation: {error:?}"))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("basic installation: {error:?}"))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("string installation: {error:?}"))?;
    let roots_before = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm
        .add_root(RootKind::Host, environment)
        .map_err(|error| format!("environment root: {error:?}"))?;
    let run_result = (|| -> Result<RunEvidence, String> {
        let mut execution = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .map_err(|error| format!("module load: {error:?}"))?;
        execution
            .set_fuel(fuel)
            .map_err(|error| format!("set fuel: {error:?}"))?;
        let outcome = execution
            .run()
            .map_err(|error| format!("execution: {error:?}"))?;
        let outcome = match outcome {
            RunOutcome::Returned(values) => ObservedOutcome::Returned(values),
            RunOutcome::LuaError(error) => ObservedOutcome::LuaError(error.kind),
            RunOutcome::Aborted(reason) => ObservedOutcome::Aborted(reason),
            other => ObservedOutcome::Other {
                _detail: format!("{other:?}"),
            },
        };
        Ok(RunEvidence {
            outcome,
            fuel_remaining: execution.fuel_remaining(),
        })
    })();
    let mut cleanup = Vec::new();
    if let Err(error) = vm.remove_root(environment_root) {
        cleanup.push(format!("environment root cleanup: {error:?}"));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let after = vm.roots().count(kind);
        if after != roots_before[index] {
            cleanup.push(format!(
                "{kind:?} roots after cleanup={after}, before={}",
                roots_before[index]
            ));
        }
    }
    if vm.ledger_snapshot().reserved != 0 {
        cleanup.push(format!(
            "reserved ledger after cleanup={}",
            vm.ledger_snapshot().reserved
        ));
    }
    if cleanup.is_empty() {
        run_result
    } else {
        Err(format!("{}; run_result={run_result:?}", cleanup.join("; ")))
    }
}

#[test]
fn p17_calls_dump_fuel_reservation_uses_actual_work() {
    let mut failures = Vec::new();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let module = match compile(profile) {
            Ok(module) => module,
            Err(error) => {
                failures.push(format!("{profile:?} compile: {error}"));
                continue;
            }
        };
        let limits = DumpLimits {
            max_work_units: DUMP_WORK_CAP,
            ..DumpLimits::default()
        };
        let high_fuel = DUMP_WORK_CAP as u64 + 1_000_000;
        let consumed = match run_case(profile, &module, Some(limits), high_fuel) {
            Ok(RunEvidence {
                outcome: ObservedOutcome::Returned(values),
                fuel_remaining,
            }) if values.as_slice() == [Value::Boolean(true)] => high_fuel - fuel_remaining,
            other => {
                failures.push(format!("{profile:?} ample fuel: {other:?}"));
                continue;
            }
        };
        let low_fuel = consumed.saturating_add(128);
        if low_fuel >= DUMP_WORK_CAP as u64 || consumed == 0 {
            failures.push(format!(
                "{profile:?} small dump consumed {consumed}, unsuitable for bounded-fuel test"
            ));
            continue;
        }
        match run_case(profile, &module, Some(limits), low_fuel) {
            Ok(RunEvidence {
                outcome: ObservedOutcome::Returned(values),
                fuel_remaining,
            }) if values.as_slice() == [Value::Boolean(true)] && fuel_remaining == 128 => {}
            other => failures.push(format!(
                "{profile:?} fuel {low_fuel} below cap {} should dump and retain 128 fuel: {other:?}",
                DUMP_WORK_CAP
            )),
        }
        let dump_work = match actual_dump_work(&module, profile) {
            Ok(work) if work > 1 && work < DUMP_WORK_CAP as u64 => work,
            other => {
                failures.push(format!("{profile:?} invalid actual dump work: {other:?}"));
                continue;
            }
        };
        match run_case(profile, &module, Some(limits), dump_work - 1) {
            Ok(RunEvidence {
                outcome: ObservedOutcome::Aborted(AbortReason::FuelExhausted),
                ..
            }) => {}
            other => failures.push(format!(
                "{profile:?} fuel one unit below actual dump work {dump_work} should abort: {other:?}"
            )),
        }
        let tiny_cap = DumpLimits {
            max_work_units: 1,
            ..limits
        };
        match run_case(profile, &module, Some(tiny_cap), high_fuel) {
            Ok(RunEvidence {
                outcome: ObservedOutcome::LuaError(error_kind),
                ..
            }) if error_kind == RuntimeErrorKind::HostDumpBudget => {}
            other => failures.push(format!(
                "{profile:?} policy work cap should report HostDumpBudget: {other:?}"
            )),
        }
        match run_case(profile, &module, None, high_fuel) {
            Ok(RunEvidence {
                outcome: ObservedOutcome::LuaError(error_kind),
                ..
            }) if error_kind == RuntimeErrorKind::HostPolicyStringDump => {}
            other => failures.push(format!(
                "{profile:?} denied dump should report HostPolicyStringDump: {other:?}"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "P17 dump fuel reservation failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn p17_official_export_reused_temporaries_across_open_calls() {
    let mut source = String::from(
        "assert((function(...) return ... end)(1))\nlocal function pass(...) return ... end\nlocal function sink(...) return ... end\n",
    );
    for index in 0..48 {
        source.push_str(&format!("local keep_{index} = {index}\n"));
    }
    for _ in 0..8 {
        source.push_str("sink(pass(keep_0))\n");
    }
    source.push_str("return keep_0\n");
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let module = compile_source(profile, source.as_bytes())
            .unwrap_or_else(|error| panic!("{profile:?} compile: {error}"));
        let mut work = OfficialWorkBudget::new(DUMP_WORK_CAP as u64);
        emit_official_chunk(
            &module,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_or_else(|error| panic!("{profile:?} export: {error:?}"));
    }
}

#[test]
fn p17_official_export_many_open_call_statements_stays_bounded() {
    let mut source = String::from(
        "assert((function(...) return ... end)(1))\nlocal function pass(...) return ... end\nlocal function sink(...) return ... end\n",
    );
    for index in 0..48 {
        source.push_str(&format!("local keep_{index} = {index}\n"));
    }
    for _ in 0..64 {
        source.push_str("sink(pass(keep_0))\n");
    }
    source.push_str("return keep_0\n");
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let module = compile_source(profile, source.as_bytes())
            .unwrap_or_else(|error| panic!("{profile:?} compile: {error}"));
        let root = module
            .module()
            .prototypes
            .iter()
            .find(|proto| proto.id == ProtoId(0))
            .expect("root prototype");
        assert!(
            root.register_count < 128,
            "{profile:?} sequential calls retained {} virtual registers",
            root.register_count
        );
        let mut work = OfficialWorkBudget::new(DUMP_WORK_CAP as u64);
        emit_official_chunk(
            &module,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_or_else(|error| panic!("{profile:?} export: {error:?}"));
    }
}

#[test]
fn p17_official_export_pending_callee_survives_short_local_scope() {
    let mut source = String::from(
        "local function pass(...) return ... end\nlocal function sink(...) return ... end\n",
    );
    for index in 0..9 {
        source.push_str(&format!("local keep_{index} = {index}\n"));
    }
    source.push_str(
        "sink(pass(keep_0))\nsink(pass(keep_0))\n\
         do local short_lived = 7; assert(short_lived == 7) end\n\
         sink(pass(keep_0))\nreturn keep_0\n",
    );
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let module = compile_source(profile, source.as_bytes())
            .unwrap_or_else(|error| panic!("{profile:?} compile: {error}"));
        let mut work = OfficialWorkBudget::new(DUMP_WORK_CAP as u64);
        emit_official_chunk(
            &module,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_or_else(|error| panic!("{profile:?} export: {error:?}"));
    }
}

#[derive(Clone, Copy)]
enum P17ExpectedValues {
    Integers(i64, i64),
    Bytes(&'static [u8]),
}

fn p17_run_module(
    profile: LuaProfile,
    module: &VerifiedModule,
    expected: P17ExpectedValues,
) -> Result<(), String> {
    let mut vm = Vm::new_with_services(profile, HostServices::deny_all())
        .map_err(|error| format!("VM creation: {error:?}"))?;
    let environment = vm
        .allocate_table()
        .map_err(|error| format!("environment allocation: {error:?}"))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("basic installation: {error:?}"))?;
    vm.install_table_builtins(environment)
        .map_err(|error| format!("table installation: {error:?}"))?;
    let root = vm
        .add_root(RootKind::Host, environment)
        .map_err(|error| format!("environment root: {error:?}"))?;
    let outcome = {
        let mut execution = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .map_err(|error| format!("module load: {error:?}"))?;
        execution
            .set_fuel(1_000_000)
            .map_err(|error| format!("set fuel: {error:?}"))?;
        execution
            .run()
            .map_err(|error| format!("execution: {error:?}"))?
    };
    let result = match (outcome, expected) {
        (RunOutcome::Returned(values), P17ExpectedValues::Integers(first, second))
            if values.as_slice() == [Value::Integer(first), Value::Integer(second)] =>
        {
            Ok(())
        }
        (RunOutcome::Returned(values), P17ExpectedValues::Bytes(expected)) => {
            match values.as_slice() {
                [Value::Object(object)] => {
                    let actual = vm
                        .with_byte_string(*object, |string| string.as_bytes().to_vec())
                        .map_err(|error| format!("returned string: {error:?}"))?;
                    if actual == expected {
                        Ok(())
                    } else {
                        Err(format!("returned bytes {actual:?}, expected {expected:?}"))
                    }
                }
                other => Err(format!(
                    "returned values {other:?}, expected bytes {expected:?}"
                )),
            }
        }
        (other, _) => Err(format!("unexpected outcome {other:?}")),
    };
    vm.remove_root(root)
        .map_err(|error| format!("environment root cleanup: {error:?}"))?;
    result
}

fn p17_run_native_and_official(
    profile: LuaProfile,
    source: &[u8],
    expected: P17ExpectedValues,
) -> Result<(), String> {
    let native = compile_source(profile, source)?;
    p17_run_module(profile, &native, expected).map_err(|error| format!("native {error}"))?;
    let limits = OfficialChunkLimits::default();
    let verify = VerifyLimits::default();
    let mut export_work = OfficialWorkBudget::new(DUMP_WORK_CAP as u64);
    let encoded = emit_official_chunk(
        &native,
        ProtoId(0),
        profile,
        false,
        &limits,
        &mut export_work,
    )
    .map_err(|error| format!("official export: {error:?}"))?;
    let stats = preflight_official_chunk(&encoded, profile, &limits, &verify)
        .map_err(|error| format!("official load preflight: {error:?}"))?;
    let decoded = decode_official_chunk(&encoded, profile, &limits)
        .map_err(|error| format!("official decode: {error:?}"))?;
    let mut translate_work = OfficialWorkBudget::new(stats.subsequent_work);
    let translated = translate_official_chunk_with_work(&decoded, &verify, &mut translate_work)
        .map_err(|error| format!("official translate: {error:?}"))?;
    p17_run_module(profile, translated.verified(), expected)
        .map_err(|error| format!("official roundtrip {error}"))
}

#[test]
fn p17_backward_goto_closes_captured_local_before_reentry() {
    let source = b"local f={}; local n=0; ::again:: local x=n; f[n+1]=function() return x end; n=n+1; if n<2 then goto again end; return f[1](), f[2]();";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Integers(0, 1))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_backward_goto_closes_tbc_once_in_order() {
    let source = b"local log={}; do local n=0; ::again:: n=n+1; local x<close> = setmetatable({v=n},{__close=function(o) log[#log+1]=o.v end}); if n<2 then goto again end end; return table.concat(log,',')";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Bytes(b"1,2"))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_function_root_terminal_label_closes_once_on_goto_and_fallthrough() {
    let source = br#"
local function mk(id, log)
  return setmetatable({id=id}, {__close=function(value) log[#log+1]=value.id end})
end
local function run(skip, log, out)
  local captured = skip and 11 or 22
  local outer <close> = mk('O', log)
  out.get = function() return captured end
  if skip then goto done end
  local inner <close> = mk('I', log)
  ::done::
end
local first_log, first_out = {}, {}
run(true, first_log, first_out)
local first = table.concat(first_log, ',') .. ':' .. first_out.get()
local second_log, second_out = {}, {}
run(false, second_log, second_out)
return first .. '|' .. table.concat(second_log, ',') .. ':' .. second_out.get()
"#;
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Bytes(b"O:11|I,O:22"))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_generic_for_hidden_close_survives_each_body_exit() {
    let source = br#"
local function closing(log, name)
  return setmetatable({name=name}, {
    __close=function(value) log[#log+1]=value.name end
  })
end
local function iter(_, i)
  if i < 2 then return i+1 end
end
local function perform(mode, log, captured)
  for i in iter, nil, 0, closing(log, 'G') do
    captured[#captured+1]=function() return i end
    local body <close> = closing(log, 'B'..i)
    if mode == 'break' then break end
    if mode == 'return' then return captured[1] end
    if mode == 'error' then error('stop') end
  end
end
local normal_log, normal_values = {}, {}
perform('normal', normal_log, normal_values)
local break_log, break_values = {}, {}
perform('break', break_log, break_values)
local return_log, return_values = {}, {}
local returned = perform('return', return_log, return_values)
local error_log, error_values = {}, {}
local ok = pcall(perform, 'error', error_log, error_values)
return table.concat(normal_log, ',')..':'..
  normal_values[1]()..','..normal_values[2]()..'|'..
  table.concat(break_log, ',')..':'..break_values[1]()..'|'..
  table.concat(return_log, ',')..':'..returned()..'|'..
  table.concat(error_log, ',')..':'..error_values[1]()..
  ':'..(ok and 'unexpected' or 'caught')
"#;
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(
            profile,
            source,
            P17ExpectedValues::Bytes(b"B1,B2,G:1,2|B1,G:1|B1,G:1|B1,G:1:caught"),
        )
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_initializer_cleanup_preserves_non_nil_new_local() {
    let source = b"local function values(...) return ... end\n\
        local prior = values(0)\n\
        local s,a,b,c,d = values(1,2,3,4,'alive')\n\
        return d\n";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Bytes(b"alive"))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_large_table_literal_reuses_dead_register_homes() {
    let mut source = String::from("local values = {");
    for value in 1..=256 {
        source.push_str(&format!("{value},"));
    }
    source.push_str("}; return values[1], values[256]");
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(
            profile,
            source.as_bytes(),
            P17ExpectedValues::Integers(1, 256),
        )
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_first_open_call_after_local_binding_uses_new_temporary_generation() {
    let mut source = String::from(
        "local function pass(...) return ... end; local function sink(...) return ... end;",
    );
    for _ in 0..24 {
        source.push_str("sink(1);");
    }
    source.push_str("do local keep=7; sink(keep); return sink(pass(keep), pass(8)) end");
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(
            profile,
            source.as_bytes(),
            P17ExpectedValues::Integers(7, 8),
        )
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_open_result_tailcall_keeps_callee_in_prefix() {
    let source = b"local function identity(...) return ... end; local function choose() return identity end; return choose()(identity(1, 2))";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Integers(1, 2))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_numeric_for_limit_after_length_and_calls_roundtrips() {
    let source = br#"
local function pass(...) return ... end
local function sink(value) return value end
local data = 'abcd'
local earlier = #data
assert(earlier == 4)
local sum = 0
for i = 1, #data do
  sum = sum + sink(i)
  sum = sum + sink(pass(i))
end
return sum, sum
"#;
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        p17_run_native_and_official(profile, source, P17ExpectedValues::Integers(20, 20))
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    }
}

#[test]
fn p17_sequential_and_nested_numeric_loops_bound_official_stack() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut stacks = Vec::new();
        for count in [8usize, 32] {
            let mut source = String::from("local sum=0;");
            for _ in 0..count {
                source.push_str("for i=1,4 do sum=sum+i end;");
            }
            source.push_str("for i=1,3 do for j=1,2 do sum=sum+i+j end end; return sum,sum");
            let native = compile_source(profile, source.as_bytes())
                .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
            let root = native
                .module()
                .prototypes
                .iter()
                .find(|proto| proto.id == ProtoId(0))
                .unwrap();
            assert!(
                usize::from(root.register_count) < count * 24 + 64,
                "{profile:?} count={count} virtual={}",
                root.register_count
            );
            let mut work = OfficialWorkBudget::new(DUMP_WORK_CAP as u64);
            let encoded = emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap_or_else(|error| panic!("{profile:?} count={count}: {error:?}"));
            let decoded = decode_official_chunk(&encoded, profile, &OfficialChunkLimits::default())
                .unwrap_or_else(|error| panic!("{profile:?} count={count}: {error:?}"));
            stacks.push(decoded.main.max_stack_size);
            p17_run_native_and_official(
                profile,
                source.as_bytes(),
                P17ExpectedValues::Integers((count * 10 + 21) as i64, (count * 10 + 21) as i64),
            )
            .unwrap_or_else(|error| panic!("{profile:?} count={count}: {error}"));
        }
        assert!(
            stacks[1] <= stacks[0].saturating_add(8),
            "{profile:?} 8 loops stack={} 32 loops stack={}",
            stacks[0],
            stacks[1]
        );
        assert!(
            stacks[1] < 128,
            "{profile:?} 32 loops official stack={}",
            stacks[1]
        );
    }
}
