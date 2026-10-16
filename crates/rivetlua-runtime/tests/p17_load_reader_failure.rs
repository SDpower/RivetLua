use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, ProtoId, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    DumpCapability, DumpLimits, HostLoadCompiler, HostLoadError, HostLoadErrorKind, HostServices,
    LoadBudget, LoadCapability, LoadLimits, RootKind, RunOutcome, Vm,
};

const P17_HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const P17_EXECUTION_FUEL: u64 = P17_HOST_WORK_UNITS * 2 + 1_000_000;

const BYTE_READER: &[u8] = br#"
local function read1(x)
  local i = 0
  return function()
    collectgarbage()
    i = i + 1
    return string.sub(x, i, i)
  end
end
local f, message = load(read1("return 33"), "modname", "t", _ENV)
if f == nil then return nil, message end
return f()
"#;

const BOOLEAN_READER: &[u8] = br#"
local f, message = load(function() return true end)
return f, message
"#;

const THROWING_READER: &[u8] = br#"
local f, message = load(function() error("hhi") end)
return f, message
"#;

#[derive(Clone, Copy)]
enum Expected {
    Integer33,
    NilDiagnostic { contains: Option<&'static [u8]> },
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    body: &'static [u8],
    expected: Expected,
}

const CASES: [Case; 3] = [
    Case {
        name: "byte_reader_with_gc",
        body: BYTE_READER,
        expected: Expected::Integer33,
    },
    Case {
        name: "boolean_reader",
        body: BOOLEAN_READER,
        expected: Expected::NilDiagnostic { contains: None },
    },
    Case {
        name: "throwing_reader",
        body: THROWING_READER,
        expected: Expected::NilDiagnostic {
            contains: Some(b"hhi"),
        },
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
              local loaded = assert(load(bytes, '@p17-load-reader', 'b', _ENV))\n\
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
    let ir = lower(&resolved, &IrLimits::default())
        .map_err(|error| format!("lower: {error:?}"))?;
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-load-reader-failure.lua",
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

fn check_outcome(vm: &Vm, outcome: &RunOutcome, expected: Expected) -> Vec<String> {
    let mut failures = Vec::new();
    match outcome {
        RunOutcome::Returned(values) => match expected {
            Expected::Integer33 => {
                if values.as_slice() != [Value::Integer(33)] {
                    failures.push(format!("expected exactly integer 33; actual={values:?}"));
                }
            }
            Expected::NilDiagnostic { contains } => {
                if values.len() != 2 {
                    failures.push(format!("expected exactly 2 results; actual={values:?}"));
                }
                if values.first() != Some(&Value::Nil) {
                    failures.push(format!("expected nil first result; actual={values:?}"));
                }
                match values.get(1).copied() {
                    Some(Value::Object(object)) => match vm.with_byte_string(object, |text| {
                        let bytes = text.as_bytes();
                        let matches = match contains {
                            Some(part) => bytes.windows(part.len()).any(|window| window == part),
                            None => true,
                        };
                        (matches, bytes.is_empty(), bytes[..bytes.len().min(160)].to_vec())
                    }) {
                        Ok((true, false, _)) => {}
                        Ok((matches, empty, visible)) => failures.push(format!(
                            "diagnostic mismatch: contains={contains:?} matches={matches} empty={empty} bytes={visible:?}"
                        )),
                        Err(error) => failures.push(format!(
                            "diagnostic is not a byte string: {error:?}; value={:?}",
                            values[1]
                        )),
                    },
                    other => failures.push(format!("second result is not a byte string: {other:?}")),
                }
            }
        },
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

fn native_instruction_window(
    module: &VerifiedModule,
    prototype: Option<usize>,
    source_pc: Option<usize>,
) -> String {
    let (Some(prototype), Some(pc)) = (prototype, source_pc) else {
        return "native instruction window unavailable: no source prototype/pc".to_owned();
    };
    let Some(code) = module.module().prototypes.get(prototype) else {
        return format!("native instruction window unavailable: prototype={prototype:?}");
    };
    let start = pc.saturating_sub(4);
    let end = pc.saturating_add(1).min(code.instructions.len());
    let debug = u32::try_from(prototype)
        .ok()
        .and_then(|id| module.native_debug().and_then(|entry| entry.prototype(ProtoId(id))));
    let mut window = Vec::new();
    for index in start..end {
        window.push(format!(
            "pc={index} line={:?} instruction={:?}",
            debug.and_then(|entry| entry.lines.get(index)),
            code.instructions[index].instruction
        ));
    }
    format!(
        "native prototype={} source_pc={pc} register_count={} instruction_count={} debug={} environment={:?} global_environment={:?} environment_source={:?} bindings={:?} upvalues={:?} window=[{}]",
        prototype,
        code.register_count,
        code.instructions.len(),
        debug.is_some(),
        code.frame.environment,
        code.global_environment,
        code.frame.environment_source,
        &code.binding_registers[..code.binding_registers.len().min(5)],
        &code.upvalues[..code.upvalues.len().min(3)],
        window.join(" | ")
    )
}

fn run_case(
    case: Case,
    language: LanguageProfile,
    profile: LuaProfile,
    official: bool,
) -> Result<(), String> {
    let origin = if official { "official_dump_load" } else { "native" };
    let source = source(case, official);
    let module = compile_runner(&source, language)
        .map_err(|error| format!("{profile:?} {} {origin} compile: {error}", case.name))?;
    let native_positive = !official
        && matches!(profile, LuaProfile::Lua55)
        && matches!(case.expected, Expected::Integer33);
    let diagnostic_module = native_positive.then(|| module.clone());
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
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true).with_limits(dump_limits))
        .and_load(
            LoadCapability::deny_all()
                .and_compiler(MemoryCompiler)
                .with_official_bytecode(true)
                .with_limits(load_limits),
        );
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("{profile:?} {} {origin} VM: {error:?}", case.name))?;
    let environment = vm.allocate_table()
        .map_err(|error| format!("{profile:?} {} {origin} environment: {error:?}", case.name))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} basic: {error:?}", case.name))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} string: {error:?}", case.name))?;
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm.add_root(RootKind::Host, environment)
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
            let mut failures = check_outcome(&vm, &outcome, case.expected);
            if !failures.is_empty() {
                if let (Some(module), RunOutcome::LuaError(error)) = (&diagnostic_module, &outcome) {
                    failures.push(native_instruction_window(
                        module,
                        error.source_prototype,
                        error.source_pc,
                    ));
                }
            }
            drop(outcome);
            failures
        }
        Err((stage, error)) => {
            let mut failures = vec![format!(
                "{stage} kind={:?} id={} proto={:?} pc={:?} depth={:?} value={}",
                error.kind,
                error.diagnostic_id,
                error.source_prototype,
                error.source_pc,
                error.source_depth,
                describe_value(&vm, error.value)
            )];
            if let Some(module) = &diagnostic_module {
                failures.push(native_instruction_window(
                    module,
                    error.source_prototype,
                    error.source_pc,
                ));
            }
            failures
        }
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
fn p17_load_reader_failures_native_and_official() {
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
        "P17 load reader failures (2 profiles x 3 fixtures x 2 origins):\n{}",
        failures.join("\n")
    );
}
