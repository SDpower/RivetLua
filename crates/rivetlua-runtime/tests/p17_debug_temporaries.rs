use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value, VerifyLimits,
    decode_official_chunk,
};
use rivetlua_runtime::{DebugCapability, DebugPermission, HostServices, RootKind, RunOutcome, Vm};
use std::env;

fn profile() -> (&'static str, LanguageProfile, LuaProfile) {
    match env::var("RIVETLUA_P13_PROFILE").as_deref() {
        Ok("lua55-i64f64") => ("lua55-i64f64", LanguageProfile::Lua55, LuaProfile::Lua55),
        Ok("lua54-i64f64") => ("lua54-i64f64", LanguageProfile::Lua54, LuaProfile::Lua54),
        Err(env::VarError::NotPresent) => {
            ("lua55-i64f64", LanguageProfile::Lua55, LuaProfile::Lua55)
        }
        other => panic!("無效 P13 profile: {other:?}"),
    }
}

fn compile_debug(
    source: &[u8],
    chunk_name: &[u8],
    language: LanguageProfile,
) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(&ir, &resolved, source, chunk_name, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_with_h_debug(
    module: rivetlua_core::VerifiedModule,
    services: HostServices,
    fuel: u64,
) -> (Vm, RunOutcome) {
    let (_, _, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    vm.set_allocation_limit(64 * 1024 * 1024);
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_table_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_io_os_builtins(environment).unwrap();
    vm.set_collect_every_allocation(false);
    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    execution.set_fuel(fuel).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.remove_root(root).unwrap();
    (vm, outcome)
}

fn case_source(nested_select: bool, hook_enabled: bool) -> String {
    let getter = if nested_select {
        "  assert(select(2,debug.getlocal(2,3))==1)\n  assert(select(1,debug.getlocal(2,3))=='(temporary)')"
    } else {
        "  local name,value=debug.getlocal(2,3)\n  assert(name=='(temporary)' and value==1)"
    };
    let hook_setup = if hook_enabled {
        r#"debug.sethook(function (e,l)
  collectgarbage() -- 每個 hook event 強制 GC
  local f,m,c=debug.gethook()
  assert(m == 'crl' and c == 0)
  if e == "line" then
    if glob ~= oldglob then
      L = l-1 -- 記錄 glob 首次改變時的行號
      oldglob = glob
    end
  elseif e == "call" then
      local f = debug.getinfo(2, "f").func
      a[f] = 1
  else assert(e == "return")
  end
end, "crl")
"#
    } else {
        ""
    };
    let source = r#"glob, oldglob, L, a = 0, 0, 0, {}
__HOOK_SETUP__

function f()
__GETTER__
  assert(not debug.getlocal(2,4))
  assert(not debug.setlocal(2,4,'invalid'))
  assert(debug.setlocal(2,3,10)=='(temporary)')
  return 20
end

function g(a,b) return (a+1)+f() end

local result = g(0, 0)
debug.sethook()
return result, next(a) ~= nil, debug.gethook() == nil"#;
    source
        .replace("__HOOK_SETUP__", hook_setup)
        .replace("__GETTER__", getter)
}

fn official_root_roundtrip(
    module: &rivetlua_core::VerifiedModule,
    profile: LuaProfile,
    strip: bool,
) -> rivetlua_core::VerifiedModule {
    let verify_limits = VerifyLimits::default();
    let chunk_limits = OfficialChunkLimits::default();
    let mut work = OfficialWorkBudget::for_limits(&verify_limits).unwrap();
    let bytes =
        emit_official_chunk(module, ProtoId(0), profile, strip, &chunk_limits, &mut work).unwrap();
    let decoded = decode_official_chunk(&bytes, profile, &chunk_limits).unwrap();
    translate_official_chunk(&decoded, &verify_limits)
        .unwrap()
        .into_verified()
}

#[test]
fn p17_debug_temporary_operands_survive_select_hooks_and_dump_roundtrip() {
    let (_, language, runtime_profile) = profile();
    for nested_select in [false, true] {
        for hook_enabled in [false, true] {
            let source = case_source(nested_select, hook_enabled);
            let native = compile_debug(source.as_bytes(), b"@p17-debug-temporaries.lua", language);
            for mode in ["direct", "full", "strip"] {
                let module = match mode {
                    "direct" => native.clone(),
                    "full" => official_root_roundtrip(&native, runtime_profile, false),
                    "strip" => official_root_roundtrip(&native, runtime_profile, true),
                    _ => unreachable!("known mode"),
                };
                let debug = DebugCapability::deny_all()
                    .allow(DebugPermission::Info)
                    .allow(DebugPermission::StackInspection)
                    .allow(DebugPermission::LocalInspection)
                    .allow(DebugPermission::LocalMutation)
                    .allow(DebugPermission::EventHook);
                let (vm, outcome) =
                    run_with_h_debug(module, HostServices::deny_all().and_debug(debug), 2_000_000);
                let RunOutcome::Returned(values) = outcome else {
                    panic!(
                        "profile={}: mode={mode}, nested_select={nested_select}, hook={hook_enabled}: {outcome:?}",
                        profile().0
                    );
                };
                assert_eq!(
                    values.len(),
                    3,
                    "mode={mode}, nested_select={nested_select}, hook={hook_enabled}"
                );
                assert_eq!(
                    values[0],
                    Value::Integer(30),
                    "caller operand: mode={mode}, nested_select={nested_select}, hook={hook_enabled}"
                );
                let Value::Boolean(hook_seen) = values[1] else {
                    panic!(
                        "hook dictionary 狀態必須是 boolean: mode={mode}, nested_select={nested_select}, hook={hook_enabled}: {:?}",
                        values[1]
                    );
                };
                assert_eq!(
                    hook_seen, hook_enabled,
                    "hook call dictionary 狀態: mode={mode}, nested_select={nested_select}"
                );
                assert_eq!(
                    values[2],
                    Value::Boolean(true),
                    "hook 必須在回傳前關閉: mode={mode}, nested_select={nested_select}, hook={hook_enabled}"
                );
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            }
        }
    }
}
