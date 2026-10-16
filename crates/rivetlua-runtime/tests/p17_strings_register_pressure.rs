use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{HostServices, ObjectKind, RootKind, RunOutcome, Vm, VmError};

const SOURCE: &[u8] = br#"
local x = 0
local function f(a, ...)
  x = x + 1
  return x, a, ...
end
local a, b, c = f(4, 5)
assert(a == 1 and b == 4 and c == 5)
local d, e = f(6, 7)
assert(d == 2 and e == 6)
return x, d, e
"#;

#[test]
fn p17_reused_temporaries_preserve_calls_results_and_captured_locals() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compile_limits = CompileLimits::default();
        let register_limits = IrLimits {
            max_registers: 64,
            ..IrLimits::default()
        };
        let tokens = lex(SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            SOURCE,
            b"@p17-register-pressure-runtime.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();

        let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(2), Value::Integer(2), Value::Integer(6)]),
            "{runtime_profile:?}"
        );
        drop(execution);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}

const ERROR_SOURCE: &[u8] = br#"
local function check_error(fragment, f, ...)
  local ok, message = pcall(f, ...)
  assert(not ok, "expected error containing " .. fragment)
  collectgarbage("collect")
  message = tostring(message)
  assert(string.find(message, fragment, 1, true), message)
end

check_error("no literal", string.format, "%q", {})
check_error("contains zeros", string.format, "%10s", "\0")
check_error("invalid conversion", string.format, "%t", 1)
local digits = string.rep("0", 600)
check_error("too long", string.format, "%1" .. digits .. ".3d", 1)
check_error("no value", string.format, "%d %d", 1)
check_error("cannot have modifiers", string.format, "%10q", 1)

local bad_tostring = setmetatable({}, {
  __tostring = function() return {} end
})
check_error("'__tostring' must return a string", tostring, bad_tostring)
check_error("table expected", table.concat, 3)

local maxi = 9223372036854775807
local mini = -9223372036854775807 - 1
check_error("at index " .. tostring(maxi), table.concat, {}, " ", maxi, maxi)
check_error("at index " .. tostring(mini), table.concat, {}, " ", mini, mini)
collectgarbage("collect")
return true
"#;

#[test]
fn p17_string_format_tostring_and_concat_errors_survive_guest_gc() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compile_limits = CompileLimits::default();
        let register_limits = IrLimits {
            max_registers: 64,
            ..IrLimits::default()
        };
        let tokens = lex(ERROR_SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            ERROR_SOURCE,
            b"@p17-strings-register-pressure-errors.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();

        let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        vm.install_table_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{runtime_profile:?}"
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}

const FORMAT_TOSTRING_GC_SOURCE: &[u8] = br#"
collectgarbage()
local direct = setmetatable({}, {
  __tostring = function() return "hello" end,
  __name = "hi",
})
assert(string.format("%s %.10s", direct, direct) == "hello hello")

collectgarbage()
local metatable = {
  __tostring = function() return "hello" end,
  __name = "hi",
}
local indirect = setmetatable({}, metatable)
assert(string.format("%s %.10s", indirect, indirect) == "hello hello")
return true
"#;

#[test]
fn p17_string_format_tostring_survives_guest_gc_during_nested_arguments() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compile_limits = CompileLimits::default();
        let register_limits = IrLimits {
            max_registers: 64,
            ..IrLimits::default()
        };
        let tokens = lex(FORMAT_TOSTRING_GC_SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            FORMAT_TOSTRING_GC_SOURCE,
            b"@p17-string-format-tostring-guest-gc.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();

        let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{runtime_profile:?}"
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}

const METATABLE_NAME_SOURCE: &[u8] = br#"
local hello = setmetatable({}, {
  __tostring = function() return "hello" end,
  __name = "hi",
})
assert(tostring(hello) == "hello")
assert(string.format("%s %.10s", hello, hello) == "hello hello")

local named = setmetatable({}, {__name = "hi"})
assert(tostring(named):sub(1, 4) == "hi: ")
assert(string.format("%.4s", named) == "hi: ")
local nul_name = setmetatable({}, {__name = "hi\0ignored"})
assert(string.format("%.4s", nul_name) == "hi: ")

local unnamed = setmetatable({}, {__name = 123})
assert(tostring(unnamed):sub(1, 7) == "table: ")
assert(string.format("%s", unnamed):sub(1, 7) == "table: ")

local long_name = string.rep("x", 140)
local long_named = setmetatable({}, {__name = long_name})
local rendered = tostring(long_named)
assert(rendered:sub(1, #long_name + 2) == long_name .. ": ")
assert(string.format("%s", long_named):sub(1, #long_name + 2) == long_name .. ": ")

local protected_meta = {__metatable = "locked"}
local protected = setmetatable({}, protected_meta)
assert(getmetatable(protected) == "locked")
assert(rawget(protected_meta, "__metatable") == "locked")
assert(getmetatable(protected) == "locked")
assert(rawget(protected_meta, "__metatable") == "locked")
return true
"#;

const LARGE_ARRAY_METATABLE_SOURCE: &[u8] = br#"
local large_meta = {}
for i = 1, 50000 do large_meta[i] = true end
assert(tostring(setmetatable({}, large_meta)):sub(1, 7) == "table: ")
return true
"#;

#[test]
fn p17_stringification_honors_metatable_name_and_preserves_protected_key() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compile_limits = CompileLimits::default();
        let register_limits = IrLimits {
            max_registers: 64,
            ..IrLimits::default()
        };
        let tokens = lex(METATABLE_NAME_SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            METATABLE_NAME_SOURCE,
            b"@p17-stringification-metatable-name.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();

        let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{runtime_profile:?}"
        );
        drop(execution);

        let tokens = lex(LARGE_ARRAY_METATABLE_SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            LARGE_ARRAY_METATABLE_SOURCE,
            b"@p17-stringification-large-metatable.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{runtime_profile:?}"
        );
        drop(execution);

        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}


const COROUTINE_RUNNING_SOURCE: &[u8] = br#"
local main, is_main = coroutine.running()
assert(type(main) == "thread" and is_main == true)
local main_again, main_again_flag = coroutine.running()
assert(main_again == main and main_again_flag == true)
collectgarbage("collect")
local main_after_gc, main_after_gc_flag = coroutine.running()
assert(main_after_gc == main and main_after_gc_flag == true)

local child
child = coroutine.create(function()
  local running, child_is_main = coroutine.running()
  assert(type(running) == "thread" and running == child)
  assert(child_is_main == false)
  collectgarbage("collect")
  local running_again, child_again_is_main = coroutine.running()
  assert(running_again == running and child_again_is_main == false)
  return running_again
end)
local weak_child = setmetatable({child}, {__mode = "v"})
local ok, child_result = coroutine.resume(child)
assert(ok and child_result == child)
assert(coroutine.status(child) == "dead")
local main_after_child, after_child_is_main = coroutine.running()
assert(main_after_child == main and after_child_is_main == true)
collectgarbage("collect")
assert(weak_child[1] == child)

child = nil
child_result = nil
collectgarbage("collect")
assert(weak_child[1] == nil)
local main_after_child_gc, after_child_gc_is_main = coroutine.running()
assert(main_after_child_gc == main and after_child_gc_is_main == true)
return true
"#;

#[test]
fn p17_coroutine_running_preserves_main_and_child_identity_across_gc() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compile_limits = CompileLimits::default();
        let register_limits = IrLimits {
            max_registers: 64,
            ..IrLimits::default()
        };
        let tokens = lex(COROUTINE_RUNNING_SOURCE, language, &compile_limits).unwrap();
        let syntax = parse(&tokens, language, &compile_limits).unwrap();
        let resolved = resolve(&syntax, &tokens, language, &compile_limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            COROUTINE_RUNNING_SOURCE,
            b"@p17-coroutine-running-identity.lua",
            &VerifyLimits::default(),
        )
        .unwrap()
        .verified()
        .clone();

        let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        execution.set_fuel(1_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{runtime_profile:?}"
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}


#[test]
fn p17_short_string_interning_and_long_identity_preserve_gc_lifecycle() {
    const SHORT: &[u8] = b"short-0001";
    const LONG: [u8; 300] = [b'L'; 300];

    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let baseline_roots = vm.roots().total_count();
        vm.set_collect_every_allocation(true);

        let short_first = vm.allocate_byte_string(SHORT).unwrap();
        let short_first_root = vm.add_root(RootKind::Host, short_first).unwrap();
        let short_second = vm.allocate_byte_string(SHORT).unwrap();
        let short_second_root = vm.add_root(RootKind::Host, short_second).unwrap();
        assert_eq!(short_first, short_second, "{profile:?}: short bytes share identity");

        let long_first = vm.allocate_byte_string(&LONG).unwrap();
        let long_first_root = vm.add_root(RootKind::Host, long_first).unwrap();
        let long_second = vm.allocate_byte_string(&LONG).unwrap();
        let long_second_root = vm.add_root(RootKind::Host, long_second).unwrap();
        assert_ne!(long_first, long_second, "{profile:?}: long bytes keep distinct identity");
        assert_eq!(vm.object_kind(long_first), Ok(ObjectKind::ByteString));
        assert_eq!(vm.object_kind(long_second), Ok(ObjectKind::ByteString));

        vm.remove_root(short_first_root).unwrap();
        vm.remove_root(short_second_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(short_first), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(long_first), Ok(ObjectKind::ByteString));
        assert_eq!(vm.object_kind(long_second), Ok(ObjectKind::ByteString));

        let short_recreated = vm.allocate_byte_string(SHORT).unwrap();
        let short_recreated_root = vm.add_root(RootKind::Host, short_recreated).unwrap();
        assert_ne!(
            short_recreated,
            short_first,
            "{profile:?}: collected short bytes get new identity"
        );
        assert_eq!(vm.object_kind(short_recreated), Ok(ObjectKind::ByteString));
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(short_recreated), Ok(ObjectKind::ByteString));

        for root in [long_first_root, long_second_root, short_recreated_root] {
            vm.remove_root(root).unwrap();
        }
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(long_first), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(long_second), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(short_recreated), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
