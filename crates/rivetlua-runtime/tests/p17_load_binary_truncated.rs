use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    AbortReason, DumpCapability, DumpLimits, HostLoadCompiler, HostLoadError, HostLoadErrorKind,
    HostServices, LoadBudget, LoadCapability, LoadLimits, RootKind, RunOutcome, RuntimeErrorKind,
    Vm,
};

const HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const EXECUTION_FUEL: u64 = HOST_WORK_UNITS * 2 + 1_000_000;

const CHUNK: &[u8] = br#"
local c = string.dump(function ()
  local a = 1; local b = 3;
  local f = function () return a + b + _ENV.c; end
  local s1 = "a constant"
  local s2 = "another constant"
  return a + b * 3
end, false)
local function read1(x)
  local i = 0
  return function()
    i = i + 1
    return string.sub(x, i, i)
  end
end
"#;

const PREFIXES: &[u8] = br#"
local direct = assert(load(c))
local from_reader = assert(load(read1(c)))
local direct_value, reader_value = direct(), from_reader()
local count = 0
for i = 1, #c - 1 do
  local prefix = string.sub(c, 1, i)
  local st, msg = load(prefix)
  assert(not st and type(msg) == "string" and string.find(msg, "truncated"), i)
  local rst, rmsg = load(read1(prefix))
  assert(not rst and type(rmsg) == "string" and string.find(rmsg, "truncated"), i)
  count = count + 1
end
return direct_value, reader_value, count, #c
"#;

const TEXT_MODE: &[u8] = br#"
local prefix = string.sub(c, 1, 1)
local a, b = load(prefix, "@p17-binary-text-mode", "t", _ENV)
local d, e = load(read1(prefix), "@p17-binary-text-mode", "t", _ENV)
return a, b, d, e
"#;
const POLICY_DIRECT: &[u8] = b"return load(string.sub(c, 1, 1))\n";
const POLICY_READER: &[u8] = b"return load(read1(string.sub(c, 1, 1)))\n";
const BUDGET_DIRECT: &[u8] = b"return load(c)\n";
const BUDGET_READER: &[u8] = b"return load(read1(c))\n";
const FUEL: &[u8] = b"return load(chunk)\n";

#[derive(Clone, Copy, Debug)]
enum Case {
    Prefixes,
    TextMode,
    PolicyDirect,
    PolicyReader,
    BudgetDirect,
    BudgetReader,
    Fuel,
}

struct MemoryCompiler;
struct MeteredCompileSink<'a, 'b>(&'a mut LoadBudget<'b>);

impl CompileBudgetSink for MeteredCompileSink<'_, '_> {
    type Error = HostLoadError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.0.spend_work(units)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.0.claim_temporary(bytes)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.0.claim_module_allocation(bytes)
    }
}

impl HostLoadCompiler for MemoryCompiler {
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<VerifiedModule, HostLoadError> {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        match compile_with_budget(
            source,
            chunkname,
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut MeteredCompileSink(budget),
        ) {
            Ok(module) => Ok(module),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(BudgetedCompileError::Frontend(error)) => {
                let message = error.message.as_bytes();
                let work = message.len().checked_add(1)
                    .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
                let capacity_upper = message.len().checked_mul(2)
                    .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
                budget.spend_work(work)?;
                budget.claim_temporary(capacity_upper)?;
                let mut diagnostic = Vec::new();
                diagnostic.try_reserve_exact(message.len())
                    .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
                if diagnostic.capacity() > capacity_upper {
                    return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
                }
                diagnostic.extend_from_slice(message);
                Err(HostLoadError::new(HostLoadErrorKind::Compile, diagnostic))
            }
            Err(
                BudgetedCompileError::AdmissionOverflow
                | BudgetedCompileError::AdmissionUnderestimated,
            ) => Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new())),
            Err(BudgetedCompileError::Ir(_) | BudgetedCompileError::Bytecode(_)) => {
                const MESSAGE: &[u8] = b"compile failed";
                budget.spend_work(MESSAGE.len() + 1)?;
                budget.claim_temporary(MESSAGE.len())?;
                Err(HostLoadError::new(HostLoadErrorKind::Compile, MESSAGE))
            }
        }
    }
}

fn compile_runner(source: &[u8], language: LanguageProfile) -> Result<VerifiedModule, String> {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).map_err(|error| format!("lex: {error:?}"))?;
    let syntax = parse(&chunk, language, &limits).map_err(|error| format!("parse: {error:?}"))?;
    let resolved = resolve(&syntax, &chunk, language, &limits)
        .map_err(|error| format!("resolve: {error:?}"))?;
    let ir = lower(&resolved, &IrLimits::default())
        .map_err(|error| format!("lower: {error:?}"))?;
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-load-binary-truncated.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn source(case: Case, official_origin: bool) -> Vec<u8> {
    if matches!(case, Case::Fuel) {
        return FUEL.to_vec();
    }
    let body = match case {
        Case::Prefixes => PREFIXES,
        Case::TextMode => TEXT_MODE,
        Case::PolicyDirect => POLICY_DIRECT,
        Case::PolicyReader => POLICY_READER,
        Case::BudgetDirect => BUDGET_DIRECT,
        Case::BudgetReader => BUDGET_READER,
        Case::Fuel => FUEL,
    };
    let mut result = b"local function exercise()\n".to_vec();
    result.extend_from_slice(CHUNK);
    result.extend_from_slice(body);
    result.extend_from_slice(b"\nend\n");
    if official_origin {
        result.extend_from_slice(
            b"local bytes = string.dump(exercise, false)\n\
              local loaded = assert(load(bytes, '@p17-truncated-origin', 'b', _ENV))\n\
              return loaded()\n",
        );
    } else {
        result.extend_from_slice(b"return exercise()\n");
    }
    result
}

fn diagnostic_contains(vm: &Vm, value: Value, expected: &[u8]) -> bool {
    let Value::Object(object) = value else { return false };
    vm.with_byte_string(object, |text| {
        text.as_bytes().windows(expected.len()).any(|part| part == expected)
    })
    .unwrap_or(false)
}

fn check_outcome(vm: &Vm, case: Case, outcome: &RunOutcome) -> Result<(), String> {
    match (case, outcome) {
        (Case::Prefixes, RunOutcome::Returned(values)) => match values.as_slice() {
            [Value::Integer(10), Value::Integer(10), Value::Integer(count), Value::Integer(len)]
                if *len > 4 && *count == *len - 1 => Ok(()),
            _ => Err(format!("full load and every direct/reader prefix: {values:?}")),
        },
        (Case::TextMode, RunOutcome::Returned(values)) => match values.as_slice() {
            [Value::Nil, first, Value::Nil, second]
                if diagnostic_contains(vm, *first, b"attempt to load a binary chunk")
                    && diagnostic_contains(vm, *second, b"attempt to load a binary chunk") => Ok(()),
            _ => Err(format!("binary text-mode diagnostics: {values:?}")),
        },
        (Case::PolicyDirect | Case::PolicyReader, RunOutcome::LuaError(error))
            if error.kind == RuntimeErrorKind::HostPolicyLoad => Ok(()),
        (Case::BudgetDirect | Case::BudgetReader, RunOutcome::LuaError(error))
            if error.kind == RuntimeErrorKind::HostLoadBudget => Ok(()),
        (Case::Fuel, RunOutcome::Aborted(AbortReason::FuelExhausted)) => Ok(()),
        (_, other) => Err(format!("unexpected {case:?} outcome: {other:?}")),
    }
}

fn run_case(
    language: LanguageProfile,
    profile: LuaProfile,
    case: Case,
    official_origin: bool,
) -> Result<(), String> {
    let label = format!("{profile:?} {case:?} {}", if official_origin { "official" } else { "native" });
    let module = compile_runner(&source(case, official_origin), language)
        .map_err(|error| format!("{label} compile: {error}"))?;
    let dump_limits = DumpLimits {
        max_work_units: HOST_WORK_UNITS as usize,
        ..DumpLimits::default()
    };
    let mut load_limits = LoadLimits {
        max_work_units: if matches!(case, Case::BudgetDirect | Case::BudgetReader) {
            0
        } else {
            HOST_WORK_UNITS as usize
        },
        max_temporary_bytes: dump_limits.max_temporary_bytes,
        ..LoadLimits::default()
    };
    if matches!(case, Case::Prefixes) {
        // 單 byte reader 必須可讀完整官方 chunk；產品預設 chunk 上限不變。
        load_limits.max_reader_chunks = 1024;
    }
    let mut load = LoadCapability::deny_all()
        .and_compiler(MemoryCompiler)
        .with_limits(load_limits);
    if !matches!(case, Case::PolicyDirect | Case::PolicyReader) {
        load = load.with_official_bytecode(true);
    }
    let services = HostServices::deny_all()
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true).with_limits(dump_limits))
        .and_load(load);
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("{label} VM: {error:?}"))?;
    let environment = vm.allocate_table()
        .map_err(|error| format!("{label} environment: {error:?}"))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{label} basic: {error:?}"))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{label} string: {error:?}"))?;
    if matches!(case, Case::Fuel) {
        let fixture = match profile {
            LuaProfile::Lua54 => include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
            LuaProfile::Lua55 => include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        };
        let key = vm.allocate_byte_string(b"chunk")
            .map_err(|error| format!("{label} key: {error:?}"))?;
        let value = vm.allocate_byte_string(fixture)
            .map_err(|error| format!("{label} fixture: {error:?}"))?;
        vm.raw_set(environment, Value::Object(key), Value::Object(value))
            .map_err(|error| format!("{label} fixture global: {error:?}"))?;
    }
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm.add_root(RootKind::Host, environment)
        .map_err(|error| format!("{label} root: {error:?}"))?;
    vm.set_collect_every_allocation(true);
    let run_result = {
        match vm.load_with_environment(module, Value::Object(environment)) {
            Ok(mut execution) => {
                let result = execution
                    .set_fuel(if matches!(case, Case::Fuel) { 100 } else { EXECUTION_FUEL })
                    .and_then(|()| execution.run());
                drop(execution);
                result.map_err(|error| ("run", error))
            }
            Err(error) => Err(("module load", error)),
        }
    };
    let mut failures = match run_result {
        Ok(outcome) => {
            let result = check_outcome(&vm, case, &outcome);
            drop(outcome);
            result.err().into_iter().collect::<Vec<_>>()
        }
        Err((stage, error)) => vec![format!(
            "{stage} kind={:?} id={} proto={:?} pc={:?} depth={:?} value={:?}",
            error.kind, error.diagnostic_id, error.source_prototype,
            error.source_pc, error.source_depth, error.value
        )],
    };
    if let Err(error) = vm.remove_root(environment_root) {
        failures.push(format!("environment root cleanup: {error:?}"));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let actual = vm.roots().count(kind);
        if actual != baseline[index] {
            failures.push(format!("{kind:?} roots={actual}; baseline={}", baseline[index]));
        }
    }
    let reserved = vm.ledger_snapshot().reserved;
    if reserved != 0 {
        failures.push(format!("ledger reserved={reserved}; expected 0"));
    }
    if failures.is_empty() { Ok(()) } else { Err(format!("{label}: {}", failures.join("; "))) }
}

#[test]
fn p17_load_binary_truncated_prefixes_and_fatal_boundaries() {
    let mut failures = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for official_origin in [false, true] {
            if let Err(error) = run_case(language, profile, Case::Prefixes, official_origin) {
                failures.push(error);
            }
        }
        for case in [
            Case::TextMode,
            Case::PolicyDirect,
            Case::PolicyReader,
            Case::BudgetDirect,
            Case::BudgetReader,
            Case::Fuel,
        ] {
            if let Err(error) = run_case(language, profile, case, false) {
                failures.push(error);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "P17 truncated binary prefixes (2 profiles x [2 full origins + 6 boundary cases]):\n{}",
        failures.join("\n")
    );
}

#[derive(Clone, Copy, Debug)]
enum ReturnLimitCase {
    Native,
    Official,
    Policy,
    Budget,
}

fn return_limit_source(case: ReturnLimitCase) -> Vec<u8> {
    let body = match case {
        ReturnLimitCase::Native | ReturnLimitCase::Official => br#"
local code = "return 10" .. string.rep(",10", 253)
local good = assert(load(code))
local values = {good()}
assert(#values == 254 and values[254] == 10)
local bad, message = load(code .. ",10")
assert(not bad and type(message) == "string" and string.find(message, "too many returns"))
return #values, values[254], bad, message
"#.as_slice(),
        ReturnLimitCase::Policy | ReturnLimitCase::Budget => br#"
local code = "return 10" .. string.rep(",10", 254)
return load(code)
"#.as_slice(),
    };
    let mut source = b"local function exercise()\n".to_vec();
    source.extend_from_slice(body);
    source.extend_from_slice(b"\nend\n");
    if matches!(case, ReturnLimitCase::Official) {
        source.extend_from_slice(
            b"local bytes = string.dump(exercise, false)\n\
              local loaded = assert(load(bytes, '@p17-return-limit-driver', 'b', _ENV))\n\
              return loaded()\n",
        );
    } else {
        source.extend_from_slice(b"return exercise()\n");
    }
    source
}

fn run_return_limit_case(case: ReturnLimitCase) -> Result<(), String> {
    let label = format!("Lua55 {case:?}");
    let module = compile_runner(&return_limit_source(case), LanguageProfile::Lua55)
        .map_err(|error| format!("{label} compile: {error}"))?;
    let dump_limits = DumpLimits {
        max_work_units: HOST_WORK_UNITS as usize,
        ..DumpLimits::default()
    };
    const CLI_LOAD_WORK_UNITS: usize = 2 * 1024 * 1024 * 1024;
    let normal = matches!(case, ReturnLimitCase::Native | ReturnLimitCase::Official);
    let load_limits = LoadLimits {
        max_work_units: if matches!(case, ReturnLimitCase::Budget) {
            0
        } else if normal {
            CLI_LOAD_WORK_UNITS
        } else {
            HOST_WORK_UNITS as usize
        },
        // 寬回傳的正向編譯沿用 CLI 既有有限 load 配額；fatal 案例不擴額。
        max_temporary_bytes: if normal {
            256 * 1024 * 1024
        } else {
            dump_limits.max_temporary_bytes
        },
        max_module_allocation_bytes: if normal {
            64 * 1024 * 1024
        } else {
            LoadLimits::default().max_module_allocation_bytes
        },
        ..LoadLimits::default()
    };
    let mut load = LoadCapability::deny_all();
    if !matches!(case, ReturnLimitCase::Policy) {
        load = load.and_compiler(MemoryCompiler);
    }
    load = load.with_limits(load_limits);
    if matches!(case, ReturnLimitCase::Official) {
        load = load.with_official_bytecode(true);
    }
    let services = HostServices::deny_all()
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true).with_limits(dump_limits))
        .and_load(load);
    let mut vm = Vm::new_with_services(LuaProfile::Lua55, services)
        .map_err(|error| format!("{label} VM: {error:?}"))?;
    let environment = vm.allocate_table()
        .map_err(|error| format!("{label} environment: {error:?}"))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{label} basic: {error:?}"))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{label} string: {error:?}"))?;
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm.add_root(RootKind::Host, environment)
        .map_err(|error| format!("{label} root: {error:?}"))?;
    vm.set_collect_every_allocation(true);
    let run_result = {
        match vm.load_with_environment(module, Value::Object(environment)) {
            Ok(mut execution) => {
                let result = execution
                    .set_fuel(if normal {
                        (CLI_LOAD_WORK_UNITS as u64) * 2 + 1_000_000
                    } else {
                        EXECUTION_FUEL
                    })
                    .and_then(|()| execution.run());
                drop(execution);
                result.map_err(|error| ("run", error))
            }
            Err(error) => Err(("module load", error)),
        }
    };
    let mut failures = match run_result {
        Ok(outcome) => {
            let result = match (case, &outcome) {
                (
                    ReturnLimitCase::Native | ReturnLimitCase::Official,
                    RunOutcome::Returned(values),
                ) => match values.as_slice() {
                    [Value::Integer(254), Value::Integer(10), Value::Nil, message]
                        if diagnostic_contains(&vm, *message, b"too many returns") => Ok(()),
                    _ => Err(format!("254/255 return boundary: {values:?}")),
                },
                (ReturnLimitCase::Policy, RunOutcome::LuaError(error))
                    if error.kind == RuntimeErrorKind::HostPolicyLoad => Ok(()),
                (ReturnLimitCase::Budget, RunOutcome::LuaError(error))
                    if error.kind == RuntimeErrorKind::HostLoadBudget => Ok(()),
                (_, other) => Err(format!("unexpected return-limit outcome: {other:?}")),
            };
            drop(outcome);
            result.err().into_iter().collect::<Vec<_>>()
        }
        Err((stage, error)) => vec![format!(
            "{stage} kind={:?} id={} proto={:?} pc={:?} depth={:?} value={:?}",
            error.kind, error.diagnostic_id, error.source_prototype,
            error.source_pc, error.source_depth, error.value
        )],
    };
    if let Err(error) = vm.remove_root(environment_root) {
        failures.push(format!("environment root cleanup: {error:?}"));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let actual = vm.roots().count(kind);
        if actual != baseline[index] {
            failures.push(format!("{kind:?} roots={actual}; baseline={}", baseline[index]));
        }
    }
    let reserved = vm.ledger_snapshot().reserved;
    if reserved != 0 {
        failures.push(format!("ledger reserved={reserved}; expected 0"));
    }
    if failures.is_empty() { Ok(()) } else { Err(format!("{label}: {}", failures.join("; "))) }
}

#[test]
fn p17_lua55_fixed_return_limit_guest_load_and_fatal_boundaries() {
    let mut failures = Vec::new();
    for case in [
        ReturnLimitCase::Native,
        ReturnLimitCase::Official,
        ReturnLimitCase::Policy,
        ReturnLimitCase::Budget,
    ] {
        if let Err(error) = run_return_limit_case(case) {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "P17 Lua55 fixed return limit (native/official/policy/budget):\n{}",
        failures.join("\n")
    );
}
