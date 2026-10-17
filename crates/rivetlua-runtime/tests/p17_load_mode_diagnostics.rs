use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    DumpCapability, DumpLimits, HostLoadCompiler, HostLoadError, HostLoadErrorKind, HostServices,
    LoadBudget, LoadCapability, LoadLimits, RootKind, RunOutcome, Vm,
};

const P17_HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const P17_EXECUTION_FUEL: u64 = P17_HOST_WORK_UNITS * 2 + 1_000_000;

const TEXT_DIRECT_BINARY_MODE: &[u8] = br#"
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local x = "-- a comment\0\0\0\n  x = 10 + \n23; \
     local a = function () x = 'hi' end; \
     return '\0'"
local a, b = load(x, "modname", "b")
local c, d, forwarded_msg, ok = capture("attempt to load a text chunk", load(x, "modname", "b"))
return a, b, c, d, forwarded_msg, ok
"#;

const TEXT_READER_BINARY_MODE: &[u8] = br#"
local function read1(x)
  local i = 0
  return function()
    collectgarbage()
    i = i + 1
    return string.sub(x, i, i)
  end
end
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local x = "-- a comment\0\0\0\n  x = 10 + \n23; \
     local a = function () x = 'hi' end; \
     return '\0'"
local a, b = load(read1(x), "modname", "b", {})
local c, d, forwarded_msg, ok = capture("attempt to load a text chunk", load(read1(x), "modname", "b", {}))
return a, b, c, d, forwarded_msg, ok
"#;

const BINARY_DIRECT_TEXT_MODE: &[u8] = br#"
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local binary = string.dump(function() return 33 end, false)
local a, b = load(binary, "modname", "t", _ENV)
local c, d, forwarded_msg, ok = capture("attempt to load a binary chunk", load(binary, "modname", "t", _ENV))
return a, b, c, d, forwarded_msg, ok
"#;

const BINARY_READER_TEXT_MODE: &[u8] = br#"
local function read1(x)
  local i = 0
  return function()
    collectgarbage()
    i = i + 1
    return string.sub(x, i, i)
  end
end
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local binary = string.dump(function() return 33 end, false)
local a, b = load(read1(binary), "modname", "t", _ENV)
local c, d, forwarded_msg, ok = capture("attempt to load a binary chunk", load(read1(binary), "modname", "t", _ENV))
return a, b, c, d, forwarded_msg, ok
"#;

const INVALID_PREFIX_DIRECT: &[u8] = br#"
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local a, b = load("*a = 123")
local c, d, forwarded_msg, ok = capture("unexpected symbol", load("*a = 123"))
assert(not a and string.find(b, "unexpected symbol"))
assert(not c and string.find(d, "unexpected symbol"))
return a, b, c, d, forwarded_msg, ok
"#;

const INVALID_PREFIX_READER: &[u8] = br#"
local function read1(x)
  local i = 0
  return function()
    collectgarbage()
    i = i + 1
    return string.sub(x, i, i)
  end
end
local function capture(msg, a, b)
  local ok = not a and string.find(b, msg)
  return a, b, msg, ok
end
local a, b = load(read1("*a = 123"))
local c, d, forwarded_msg, ok = capture("unexpected symbol", load(read1("*a = 123")))
assert(not a and string.find(b, "unexpected symbol"))
assert(not c and string.find(d, "unexpected symbol"))
return a, b, c, d, forwarded_msg, ok
"#;

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    body: &'static [u8],
    diagnostic: &'static [u8],
}

const CASES: [Case; 6] = [
    Case {
        name: "text_direct_binary_mode",
        body: TEXT_DIRECT_BINARY_MODE,
        diagnostic: b"attempt to load a text chunk",
    },
    Case {
        name: "text_reader_binary_mode",
        body: TEXT_READER_BINARY_MODE,
        diagnostic: b"attempt to load a text chunk",
    },
    Case {
        name: "binary_direct_text_mode",
        body: BINARY_DIRECT_TEXT_MODE,
        diagnostic: b"attempt to load a binary chunk",
    },
    Case {
        name: "binary_reader_text_mode",
        body: BINARY_READER_TEXT_MODE,
        diagnostic: b"attempt to load a binary chunk",
    },
    Case {
        name: "invalid_prefix_direct",
        body: INVALID_PREFIX_DIRECT,
        diagnostic: b"unexpected symbol",
    },
    Case {
        name: "invalid_prefix_reader",
        body: INVALID_PREFIX_READER,
        diagnostic: b"unexpected symbol",
    },
];

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
                budget.spend_work(error.message.len() + 1)?;
                budget.claim_temporary(error.message.len())?;
                Err(HostLoadError::new(
                    HostLoadErrorKind::Compile,
                    error.message.as_bytes(),
                ))
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

fn source(case: Case, official: bool) -> Vec<u8> {
    let mut source = b"local function exercise()\n".to_vec();
    source.extend_from_slice(case.body);
    source.extend_from_slice(b"\nend\n");
    if official {
        source.extend_from_slice(
            b"local bytes = string.dump(exercise, false)\n\
              local loaded = assert(load(bytes, '@p17-load-mode', 'b', _ENV))\n\
              return loaded()\n",
        );
    } else {
        source.extend_from_slice(b"return exercise()\n");
    }
    source
}

fn compile_runner(source: &[u8], language: LanguageProfile) -> Result<VerifiedModule, String> {
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
        b"@p17-load-mode-diagnostics.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn describe_value(vm: &Vm, value: Value) -> String {
    match value {
        Value::Object(object) => vm
            .with_byte_string(object, |text| {
                let bytes = text.as_bytes();
                format!(
                    "bytes={:?} total_len={}",
                    &bytes[..bytes.len().min(160)],
                    bytes.len()
                )
            })
            .unwrap_or_else(|_| format!("{value:?}")),
        _ => format!("{value:?}"),
    }
}

fn check_outcome(vm: &Vm, outcome: &RunOutcome, case: Case) -> Vec<String> {
    let mut failures = Vec::new();
    match outcome {
        RunOutcome::Returned(values) => {
            if values.len() != 6 {
                failures.push(format!(
                    "expected exactly six values (direct a/b, forwarded a/b/msg/predicate); actual_len={} visible={:?}",
                    values.len(),
                    values.iter().take(6).map(|value| describe_value(vm, *value)).collect::<Vec<_>>()
                ));
            }
            for (slot, label) in [(0, "direct a"), (2, "forwarded a")] {
                if values.get(slot) != Some(&Value::Nil) {
                    failures.push(format!(
                        "{label} expected nil; actual={:?}",
                        values.get(slot).map(|value| describe_value(vm, *value))
                    ));
                }
            }
            for (slot, label) in [(1, "direct b"), (3, "forwarded b")] {
                match values.get(slot).copied() {
                    Some(Value::Object(object)) => match vm.with_byte_string(object, |text| {
                        let bytes = text.as_bytes();
                        (
                            bytes
                                .windows(case.diagnostic.len())
                                .any(|window| window == case.diagnostic),
                            bytes[..bytes.len().min(160)].to_vec(),
                            bytes.len(),
                        )
                    }) {
                        Ok((true, _, _)) => {}
                        Ok((false, visible, len)) => failures.push(format!(
                            "{label} missing {:?}; actual_bytes={visible:?} total_len={len}",
                            case.diagnostic
                        )),
                        Err(error) => {
                            failures.push(format!("{label} not a byte string: {error:?}"))
                        }
                    },
                    other => failures.push(format!(
                        "{label} expected byte string; actual={:?}",
                        other.map(|value| describe_value(vm, value))
                    )),
                }
            }
            match values.get(4).copied() {
                Some(Value::Object(object)) => match vm.with_byte_string(object, |text| {
                    let bytes = text.as_bytes();
                    (bytes == case.diagnostic, bytes[..bytes.len().min(160)].to_vec(), bytes.len())
                }) {
                    Ok((true, _, _)) => {}
                    Ok((false, visible, len)) => failures.push(format!(
                        "forwarded msg mismatch: expected={:?} actual_bytes={visible:?} total_len={len}",
                        case.diagnostic
                    )),
                    Err(error) => failures.push(format!("forwarded msg not a byte string: {error:?}")),
                },
                other => failures.push(format!(
                    "forwarded msg missing: actual={:?}", other.map(|value| describe_value(vm, value))
                )),
            }
            if matches!(
                values.get(5).copied(),
                None | Some(Value::Nil | Value::Boolean(false))
            ) {
                failures.push(format!(
                    "original cannotload predicate is false/nil: actual={:?}",
                    values.get(5).map(|value| describe_value(vm, *value))
                ));
            }
        }
        RunOutcome::LuaError(error) => failures.push(format!(
            "LuaError kind={:?} id={} proto={:?} pc={:?} depth={:?} value={}",
            error.kind,
            error.diagnostic_id,
            error.source_prototype,
            error.source_pc,
            error.source_depth,
            describe_value(vm, error.value)
        )),
        other => failures.push(format!("unexpected outcome={other:?}")),
    }
    failures
}

fn run_case(
    case: Case,
    language: LanguageProfile,
    profile: LuaProfile,
    official: bool,
) -> Result<(), String> {
    let origin = if official {
        "official_dump_load"
    } else {
        "native"
    };
    let source = source(case, official);
    let module = compile_runner(&source, language)
        .map_err(|error| format!("{profile:?} {} {origin} compile: {error}", case.name))?;
    let dump_limits = DumpLimits {
        max_work_units: P17_HOST_WORK_UNITS as usize,
        ..DumpLimits::default()
    };
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
                .and_compiler(MemoryCompiler)
                .with_official_bytecode(true)
                .with_limits(load_limits),
        );
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("{profile:?} {} {origin} VM: {error:?}", case.name))?;
    let environment = vm
        .allocate_table()
        .map_err(|error| format!("{profile:?} {} {origin} environment: {error:?}", case.name))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} basic: {error:?}", case.name))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} string: {error:?}", case.name))?;
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm
        .add_root(RootKind::Host, environment)
        .map_err(|error| format!("{profile:?} {} {origin} root: {error:?}", case.name))?;
    vm.set_collect_every_allocation(true);

    let run_result = {
        match vm.load_with_environment(module, Value::Object(environment)) {
            Ok(mut execution) => {
                let result = execution
                    .set_fuel(P17_EXECUTION_FUEL)
                    .and_then(|()| execution.run());
                drop(execution);
                result.map_err(|error| ("run", error))
            }
            Err(error) => Err(("module load", error)),
        }
    };
    let mut failures = match run_result {
        Ok(outcome) => {
            let failures = check_outcome(&vm, &outcome, case);
            drop(outcome);
            failures
        }
        Err((stage, error)) => vec![format!(
            "{stage} kind={:?} id={} proto={:?} pc={:?} depth={:?} value={}",
            error.kind,
            error.diagnostic_id,
            error.source_prototype,
            error.source_pc,
            error.source_depth,
            describe_value(&vm, error.value)
        )],
    };
    if let Err(error) = vm.remove_root(environment_root) {
        failures.push(format!("environment root cleanup: {error:?}"));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let actual = vm.roots().count(kind);
        if actual != baseline[index] {
            failures.push(format!(
                "{kind:?} roots after execution={actual}; baseline={}",
                baseline[index]
            ));
        }
    }
    let reserved = vm.ledger_snapshot().reserved;
    if reserved != 0 {
        failures.push(format!("ledger reserved={reserved}; expected 0"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{profile:?} {} {origin}: {}",
            case.name,
            failures.join("; ")
        ))
    }
}

#[test]
fn p17_load_mode_diagnostics_native_and_official() {
    let mut failures = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for case in CASES {
            for official in [false, true] {
                if let Err(error) = run_case(case, language, profile, official) {
                    failures.push(error);
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "P17 load mode diagnostics (2 profiles x 6 fixtures x 2 origins; direct and forwarded):\n{}",
        failures.join("\n")
    );
}
