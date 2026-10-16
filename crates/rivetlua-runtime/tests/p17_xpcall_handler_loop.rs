use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostHandle, RootKind, RunOutcome, Vm};

fn compile(source: &[u8], profile: LanguageProfile) -> VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, profile, &limits).unwrap();
    let parsed = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_case(profile: LanguageProfile, name: &str, source: &[u8], expected: &[Value]) {
    let lua_profile = match profile {
        LanguageProfile::Lua54 => LuaProfile::Lua54,
        LanguageProfile::Lua55 => LuaProfile::Lua55,
    };
    let mut vm = Vm::new_with_profile(lua_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let roots_with_environment = RootKind::ALL.map(|kind| vm.roots().count(kind));
    vm.set_collect_every_allocation(true);

    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(outcome, RunOutcome::Returned(expected.to_vec()), "{profile:?} {name}");
    assert_eq!(
        RootKind::ALL.map(|kind| vm.roots().count(kind)),
        roots_with_environment,
        "{profile:?} {name} 執行結束後 root 必須回到環境基線",
    );
    drop(environment_root);
    vm.collect().unwrap();
    for (index, kind) in RootKind::ALL.into_iter().enumerate() {
        let expected_count = roots_with_environment[index] - usize::from(kind == RootKind::Host);
        assert_eq!(
            vm.roots().count(kind),
            expected_count,
            "{profile:?} {name} {kind:?} root 清理",
        );
    }
    assert_eq!(vm.ledger_snapshot().reserved, 0, "{profile:?} {name} ledger 保留量");
}

const NON_TAIL_WITH_CLOSE: &[u8] = br#"
local marker = {}
local first_same = false
local n, closed, close_error = 0, 0, nil
local closer = setmetatable({}, {__close = function(_, err)
  closed = closed + 1
  close_error = err
end})
local outer_ok, inner_ok, message, after = pcall(function()
  local ok, text = xpcall(function()
    local value <close> = closer
    error(marker)
  end, function(err)
    n = n + 1
    if n == 1 then first_same = (err == marker) end
    error(err)
  end)
  local resumed = 47
  return ok, text, resumed
end)
return outer_ok, inner_ok, message == "error in error handling",
       after == 47, n, closed, close_error == message, first_same
"#;

const TAIL_RESULTS: &[u8] = br#"
local n = 0
local function invoke()
  return xpcall(function() error(7) end, function(e)
    n = n + 1
    error(e)
  end)
end
local ok, message, extra = invoke()
return ok, message == "error in error handling", extra == nil, n
"#;

#[test]
fn p17_xpcall_handler_loop_returns_failure_tuple_both_profiles() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        run_case(
            profile,
            "non_tail_outer_pcall_close",
            NON_TAIL_WITH_CLOSE,
            &[
                Value::Boolean(true),
                Value::Boolean(false),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Integer(32),
                Value::Integer(1),
                Value::Boolean(true),
                Value::Boolean(true),
            ],
        );
        run_case(
            profile,
            "tail_multi_result",
            TAIL_RESULTS,
            &[
                Value::Boolean(false),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Integer(32),
            ],
        );
    }
}
