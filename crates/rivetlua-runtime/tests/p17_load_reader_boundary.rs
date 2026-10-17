use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    DebugCapability, DebugPermission, DumpCapability, DumpLimits, HostLoadCompiler, HostLoadError,
    HostLoadErrorKind, HostServices, LoadBudget, LoadCapability, LoadLimits, RootKind, RunOutcome,
    Vm,
};

const P17_HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const P17_EXECUTION_FUEL: u64 = P17_HOST_WORK_UNITS * 2 + 1_000_000;
const P17_LOAD_TEMPORARY_BYTES: usize = 4 * 1024 * 1024;

const TABLE_ERROR_READER: &[u8] = br#"
local marker = { tag = "reader-table-error" }
local function reader()
  collectgarbage()
  error(marker)
end
local loaded, message = load(reader, "@reader-table-error", "t", _ENV)
local same = message == marker
marker = nil
collectgarbage()
return loaded == nil, message ~= nil, type(message) == "table", same,
       message.tag == "reader-table-error"
"#;

const CLOSE_TAIL_ERROR_READER: &[u8] = br#"
local closed = 0
local marker = { tag = "tail-reader-error" }
local function raise_reader_error()
  error(marker)
end
local function tail_callback()
  return raise_reader_error()
end
local function reader()
  local guard <close> = setmetatable({}, {
    __close = function() closed = closed + 1 end
  })
  return tail_callback()
end
local ok, loaded, message = pcall(load, reader, "@tail-reader-error", "t", _ENV)
local same = message == marker
marker = nil
collectgarbage()
return ok, loaded == nil, message ~= nil, type(message) == "table", same,
       message.tag == "tail-reader-error", closed == 1
"#;

const NORMAL_READER_TRACEBACK: &[u8] = br#"
local supplied = false
local reader_trace
local function reader()
  if supplied then return nil end
  supplied = true
  reader_trace = debug.traceback()
  return "return 73"
end
local loaded, message = load(reader, "@normal-reader", "t", _ENV)
if loaded == nil then return false, false, false, false, false end
local value = loaded()
local trace = debug.traceback()
return supplied, message == nil, value == 73,
       string.find(reader_trace, "pcall", 1, true) == nil,
       string.find(trace, "pcall", 1, true) == nil
"#;

const DENIED_DEBUG_READER_OUTER_CLOSE: &[u8] = br#"
local reader_closed, outer_closed = 0, 0
local function body()
  local outer <close> = setmetatable({}, {
    __close = function() outer_closed = outer_closed + 1 end
  })
  local function reader()
    local inner <close> = setmetatable({}, {
      __close = function() reader_closed = reader_closed + 1 end
    })
    debug.getinfo(1)
    return nil
  end
  local loaded, diagnostic = load(reader, "@denied-info-reader", "t", _ENV)
  return loaded, diagnostic
end
local ok, message, extra = pcall(body)
return ok == false, type(message) == "string",
       type(message) == "string"
         and string.find(message, "E_HOST_POLICY_DEBUG", 1, true) ~= nil,
       extra == nil, reader_closed == 1, outer_closed == 1
"#;

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    body: &'static [u8],
    checks: &'static [&'static str],
    install_debug: bool,
}

const CASES: [Case; 4] = [
    Case {
        name: "reader_error_table_identity_gc",
        body: TABLE_ERROR_READER,
        checks: &[
            "load returned nil",
            "reader error value is non-nil",
            "reader error remains a table",
            "reader error preserves object identity",
            "reader error table survives GC with its marker",
        ],
        install_debug: false,
    },
    Case {
        name: "reader_close_tail_error_outer_pcall",
        body: CLOSE_TAIL_ERROR_READER,
        checks: &[
            "outer pcall returns normally",
            "load returned nil",
            "reader error value is non-nil",
            "reader error remains a table",
            "reader error preserves object identity",
            "reader error table survives GC with its marker",
            "reader <close> callback ran exactly once",
        ],
        install_debug: false,
    },
    Case {
        name: "normal_reader_has_no_phantom_pcall_traceback_frame",
        body: NORMAL_READER_TRACEBACK,
        checks: &[
            "normal reader supplied source",
            "normal load has no error value",
            "loaded chunk returned its expected value",
            "traceback has no pcall frame marker while reader callback is active",
            "traceback has no pcall frame marker after load returned",
        ],
        install_debug: true,
    },
    Case {
        name: "denied_debug_reader_closes_outer_protected_frame",
        body: DENIED_DEBUG_READER_OUTER_CLOSE,
        checks: &[
            "outer pcall catches denied debug operation",
            "outer pcall receives a string error",
            "error preserves E_HOST_POLICY_DEBUG rather than reader nil/error",
            "reader did not return a second nil/error value",
            "reader <close> callback ran exactly once",
            "outer <close> callback ran exactly once",
        ],
        install_debug: true,
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
              local loaded = assert(load(bytes, '@p17-load-reader-boundary', 'b', _ENV))\n\
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
        b"@p17-load-reader-boundary.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn check_outcome(outcome: &RunOutcome, case: Case) -> Vec<String> {
    let mut failures = Vec::new();
    match outcome {
        RunOutcome::Returned(values) => {
            if values.len() != case.checks.len() {
                failures.push(format!(
                    "returned {} values; expected {} named checks; values={values:?}",
                    values.len(),
                    case.checks.len()
                ));
            }
            for (index, name) in case.checks.iter().enumerate() {
                if values.get(index) != Some(&Value::Boolean(true)) {
                    failures.push(format!(
                        "{name}: expected true; actual={:?}",
                        values.get(index)
                    ));
                }
            }
        }
        RunOutcome::LuaError(error) => failures.push(format!(
            "LuaError kind={:?} id={} proto={:?} pc={:?} depth={:?} value={:?}",
            error.kind,
            error.diagnostic_id,
            error.source_prototype,
            error.source_pc,
            error.source_depth,
            error.value
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
        max_temporary_bytes: P17_LOAD_TEMPORARY_BYTES,
        ..DumpLimits::default()
    };
    let load_limits = LoadLimits {
        max_work_units: P17_HOST_WORK_UNITS as usize,
        max_temporary_bytes: P17_LOAD_TEMPORARY_BYTES,
        ..LoadLimits::default()
    };
    let mut services = HostServices::deny_all()
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
    if case.install_debug {
        services =
            services.and_debug(DebugCapability::deny_all().allow(DebugPermission::Traceback));
    }
    let mut vm = Vm::new_with_services(profile, services)
        .map_err(|error| format!("{profile:?} {} {origin} VM: {error:?}", case.name))?;
    let environment = vm
        .allocate_table()
        .map_err(|error| format!("{profile:?} {} {origin} environment: {error:?}", case.name))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} basic: {error:?}", case.name))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{profile:?} {} {origin} string: {error:?}", case.name))?;
    if case.install_debug {
        vm.install_debug_builtins(environment)
            .map_err(|error| format!("{profile:?} {} {origin} debug: {error:?}", case.name))?;
    }
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm
        .add_root(RootKind::Host, environment)
        .map_err(|error| format!("{profile:?} {} {origin} root: {error:?}", case.name))?;
    vm.set_collect_every_allocation(true);

    let run_result = match vm.load_with_environment(module, Value::Object(environment)) {
        Ok(mut execution) => {
            let result = execution
                .set_fuel(P17_EXECUTION_FUEL)
                .and_then(|()| execution.run());
            drop(execution);
            result.map_err(|error| ("run", error))
        }
        Err(error) => Err(("module load", error)),
    };
    let mut failures = match run_result {
        Ok(outcome) => {
            let failures = check_outcome(&outcome, case);
            drop(outcome);
            failures
        }
        Err((stage, error)) => vec![format!(
            "{stage} kind={:?} id={} proto={:?} pc={:?} depth={:?} value={:?}",
            error.kind,
            error.diagnostic_id,
            error.source_prototype,
            error.source_pc,
            error.source_depth,
            error.value
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
    if let Err(error) = vm.collect() {
        failures.push(format!("post-execution collection: {error:?}"));
    }
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let actual = vm.roots().count(kind);
        if actual != baseline[index] {
            failures.push(format!(
                "{kind:?} roots after collection={actual}; baseline={}",
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
fn p17_load_reader_boundary_identity_close_and_traceback_native_and_official() {
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
        "P17 load(reader) boundary (2 profiles x 4 fixtures x 2 origins):\n{}",
        failures.join("\n")
    );
}
