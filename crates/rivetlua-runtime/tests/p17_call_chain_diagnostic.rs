use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    DumpCapability, DumpLimits, HostServices, LoadCapability, LoadLimits, RootKind, RunOutcome, Vm,
};

const P17_HOST_WORK_UNITS: u64 = 512 * 1024 * 1024;
const P17_EXECUTION_FUEL: u64 = P17_HOST_WORK_UNITS * 2 + 1_000_000;

const LUA54_CHAIN: &[u8] = br#"
local N = 20
local u = table and table.pack
if type(u) ~= "function" then return false, false, false, false, false end
for i = 1, N do
  u = setmetatable({i}, {__call = u})
end
local Res = u("a", "b", "c")
if type(Res) ~= "table" then return true, false, false, false, false end
local order = true
for i = 1, N do
  order = order and type(Res[i]) == "table" and Res[i][1] == i
end
return true, true, Res.n == N + 3, order,
       Res[N + 1] == "a" and Res[N + 2] == "b" and Res[N + 3] == "c"
"#;

const LUA54_CLOSURES: &[u8] = br#"
a = nil
(function (x) a=x end)(23)
local direct = a == 23 and (function (x) return x*2 end)(20) == 40
local Z = function (le)
  local function a (f)
    return le(function (x) return f(f)(x) end)
  end
  return a(a)
end
local F = function (f)
  return function (n)
    if n == 0 then return 1
    else return n*f(n-1) end
  end
end
local fat = Z(F)
local factorial = fat(0) == 1 and fat(4) == 24 and Z(F)(5) == 5*Z(F)(4)
local function g (z)
  local function f (a,b,c,d)
    return function (x,y) return a+b+c+d+a+x+y+z end
  end
  return f(z,z+1,z+2,z+3)
end
local f = g(10)
local closure = f(9, 16) == 10+11+12+13+10+9+16+10
return direct, factorial, closure
"#;

const LUA55_SIXTEEN: &[u8] = br#"
local a = {}
for i = 1, 16 do
  a = setmetatable({}, {__call = a})
end
return pcall(a)
"#;

const LUA55_CYCLE: &[u8] = br#"
local a = {}
for i = 1, 16 do
  a = setmetatable({}, {__call = a})
end
setmetatable(a, {__call = a})
return pcall(a)
"#;

const LUA55_TAIL: &[u8] = br#"
local a = {}
for i = 1, 16 do
  a = setmetatable({}, {__call = a})
end
setmetatable(a, {__call = a})
return pcall(function () return a() end)
"#;

#[derive(Clone, Copy)]
enum Expected {
    Booleans(&'static [&'static str]),
    CallChainTooLong,
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    language: LanguageProfile,
    profile: LuaProfile,
    body: &'static [u8],
    expected: Expected,
    needs_table: bool,
}

const CASES: [Case; 5] = [
    Case {
        name: "lua54_regular_table_pack_chain",
        language: LanguageProfile::Lua54,
        profile: LuaProfile::Lua54,
        body: LUA54_CHAIN,
        expected: Expected::Booleans(&[
            "table.pack precondition",
            "table result",
            "n=23",
            "chain order",
            "original arguments",
        ]),
        needs_table: true,
    },
    Case {
        name: "lua54_direct_closures",
        language: LanguageProfile::Lua54,
        profile: LuaProfile::Lua54,
        body: LUA54_CLOSURES,
        expected: Expected::Booleans(&[
            "anonymous direct calls",
            "fixed-point factorial",
            "captured closure",
        ]),
        needs_table: false,
    },
    Case {
        name: "lua55_sixteen_call_chain",
        language: LanguageProfile::Lua55,
        profile: LuaProfile::Lua55,
        body: LUA55_SIXTEEN,
        expected: Expected::CallChainTooLong,
        needs_table: false,
    },
    Case {
        name: "lua55_self_call_chain",
        language: LanguageProfile::Lua55,
        profile: LuaProfile::Lua55,
        body: LUA55_CYCLE,
        expected: Expected::CallChainTooLong,
        needs_table: false,
    },
    Case {
        name: "lua55_tail_call_chain",
        language: LanguageProfile::Lua55,
        profile: LuaProfile::Lua55,
        body: LUA55_TAIL,
        expected: Expected::CallChainTooLong,
        needs_table: false,
    },
];

fn source(case: Case, official: bool) -> Vec<u8> {
    let mut source = b"local function exercise()\n".to_vec();
    source.extend_from_slice(case.body);
    source.extend_from_slice(b"\nend\n");
    if official {
        source.extend_from_slice(
            b"local bytes = string.dump(exercise, false)\n\
              local loaded = assert(load(bytes, '@p17-call-chain', 'b', _ENV))\n\
              return loaded()\n",
        );
    } else {
        source.extend_from_slice(b"return exercise()\n");
    }
    source
}

fn compile(source: &[u8], language: LanguageProfile) -> Result<VerifiedModule, String> {
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
        b"@p17-call-chain-diagnostic.lua",
        &VerifyLimits::default(),
    )
    .map(|compiled| compiled.verified().clone())
    .map_err(|error| format!("native emit: {error:?}"))
}

fn describe_value(vm: &Vm, value: Value) -> String {
    match value {
        Value::Object(object) => vm
            .with_byte_string(object, |string| {
                let bytes = string.as_bytes();
                let visible = &bytes[..bytes.len().min(160)];
                format!("bytes={visible:?} total_len={}", bytes.len())
            })
            .unwrap_or_else(|_| format!("{value:?}")),
        _ => format!("{value:?}"),
    }
}

fn check_outcome(vm: &Vm, outcome: RunOutcome, expected: Expected) -> Vec<String> {
    let mut failures = Vec::new();
    match outcome {
        RunOutcome::Returned(values) => match expected {
            Expected::Booleans(names) => {
                if values.len() != names.len() {
                    failures.push(format!(
                        "returned {} values; expected {} named checks; values={:?}",
                        values.len(),
                        names.len(),
                        values
                    ));
                }
                for (index, name) in names.iter().enumerate() {
                    if values.get(index) != Some(&Value::Boolean(true)) {
                        failures.push(format!(
                            "{name}: expected true; actual={}",
                            values
                                .get(index)
                                .map_or("missing".to_owned(), |value| describe_value(vm, *value))
                        ));
                    }
                }
            }
            Expected::CallChainTooLong => {
                if values.first() != Some(&Value::Boolean(false)) {
                    failures.push(format!(
                        "pcall status: expected false; actual={}",
                        values
                            .first()
                            .map_or("missing".to_owned(), |value| describe_value(vm, *value))
                    ));
                }
                match values.get(1).copied() {
                    Some(Value::Object(object)) => match vm.with_byte_string(object, |text| {
                        let bytes = text.as_bytes();
                        (
                            bytes
                                .windows(b"too long".len())
                                .any(|part| part == b"too long"),
                            bytes[..bytes.len().min(160)].to_vec(),
                            bytes.len(),
                        )
                    }) {
                        Ok((true, _, _)) => {}
                        Ok((false, visible, len)) => failures.push(format!(
                            "pcall message lacks 'too long': bytes={visible:?} total_len={len}"
                        )),
                        Err(error) => failures.push(format!(
                            "pcall message is not a byte string: {error:?}; value={:?}",
                            values[1]
                        )),
                    },
                    other => failures.push(format!("pcall message is not an object: {other:?}")),
                }
                if values.len() != 2 {
                    failures.push(format!(
                        "pcall returned {} values; expected 2",
                        values.len()
                    ));
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

fn run_case(case: Case, official: bool) -> Result<(), String> {
    let origin = if official {
        "official_dump_load"
    } else {
        "native"
    };
    let source = source(case, official);
    let module = compile(&source, case.language)
        .map_err(|error| format!("{} {origin} compile: {error}", case.name))?;
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
                .with_official_bytecode(true)
                .with_limits(load_limits),
        );
    let mut vm = Vm::new_with_services(case.profile, services)
        .map_err(|error| format!("{} {origin} VM creation: {error:?}", case.name))?;
    let environment = vm
        .allocate_table()
        .map_err(|error| format!("{} {origin} environment: {error:?}", case.name))?;
    vm.install_basic_builtins(environment)
        .map_err(|error| format!("{} {origin} basic builtins: {error:?}", case.name))?;
    vm.install_string_builtins(environment)
        .map_err(|error| format!("{} {origin} string builtins: {error:?}", case.name))?;
    if case.needs_table {
        vm.install_table_builtins(environment)
            .map_err(|error| format!("{} {origin} table builtins: {error:?}", case.name))?;
    }
    let baseline = RootKind::ALL.map(|kind| vm.roots().count(kind));
    let environment_root = vm
        .add_root(RootKind::Host, environment)
        .map_err(|error| format!("{} {origin} environment root: {error:?}", case.name))?;
    vm.set_collect_every_allocation(true);

    let run_result = {
        match vm.load_with_environment(module, Value::Object(environment)) {
            Ok(mut execution) => {
                let result = execution
                    .set_fuel(P17_EXECUTION_FUEL)
                    .and_then(|()| execution.run());
                drop(execution);
                result.map_err(|error| ("runtime failure", error))
            }
            Err(error) => Err(("module load", error)),
        }
    };
    let mut failures = match run_result {
        Ok(outcome) => check_outcome(&vm, outcome, case.expected),
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
        Err(format!("{} {origin}: {}", case.name, failures.join("; ")))
    }
}

#[test]
fn p17_call_chain_native_and_official_diagnostics() {
    let mut failures = Vec::new();
    for case in CASES {
        for official in [false, true] {
            if let Err(error) = run_case(case, official) {
                failures.push(error);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "P17 call chain failures (5 fixtures x 2 origins):\n{}",
        failures.join("\n")
    );
}
