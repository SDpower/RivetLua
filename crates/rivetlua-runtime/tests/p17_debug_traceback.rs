use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    HostFunctionId, LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value,
    VerifiedModule,
    VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{
    DebugCapability, DebugLimits, DebugPermission, DumpCapability, HostServices, LoadCapability,
    LoadLimits, RootKind, RunOutcome, Vm, VmError,
};

const NONSTRING_MESSAGE: &[u8] = br#"assert(debug.traceback(print, 4) == print)
return true
"#;

const TRACE_FORMAT: &[u8] = br#"
assert(debug.traceback(print, 4) == print)
assert(debug.traceback("", 100) == "\nstack traceback:")
assert(debug.traceback(nil, 100) == "stack traceback:")
assert(debug.traceback(42, 100) == "42\nstack traceback:")
local hi = debug.traceback("hi")
assert(string.find(hi, "^hi\nstack traceback:\n"))
assert(not string.find(hi, "'debug.traceback'"))
local zero = debug.traceback("hi", 0)
assert(string.find(zero, "^hi\nstack traceback:\n\t%[C%]: in function '"))
local ok, from_pcall = pcall(debug.traceback)
assert(ok and string.find(from_pcall, "pcall"))
local invalid, why = pcall(debug.traceback, nil, {})
assert(not invalid and why ~= nil)
return true
"#;

const TRACE_COROUTINE: &[u8] = br#"
local function f(n)
  if n == 0 then error(n)
  else coroutine.yield(); f(n-1) end
end
local co = coroutine.create(function(n) f(n) end)
assert(coroutine.resume(co, 3))
for depth = 3, 1, -1 do
  local tb = debug.traceback(co)
  assert(string.find(tb, "^stack traceback:\n\t%[C%]: in function '"))
  assert(string.find(tb, "yield'"))
  assert(string.find(tb, "'f'"))
  assert(debug.traceback(co, nil, 40) == "stack traceback:")
  local one = debug.traceback(co, nil, 1)
  assert(not string.find(one, "yield'"))
  local ok = coroutine.resume(co)
  if depth > 1 then assert(ok) else assert(not ok) end
end
local dead = debug.traceback(co)
assert(string.find(dead, "^stack traceback:\n\t%[C%]: in function 'error'"))
assert(string.find(dead, "'f'"))
return true
"#;

const TRACE_DEEP: &[u8] = br#"
local function countlines(s)
  return select(2, string.gsub(s, "\n", ""))
end
local function deep(lvl, n)
  if lvl == 0 then return (debug.traceback("message", n))
  else return (deep(lvl - 1, n)) end
end
local function checkdeep(total, start)
  local s = deep(total, start)
  local rest = string.match(s, "^message\nstack traceback:\n(.*)$")
  assert(rest)
  local cl = countlines(rest)
  assert(cl <= 22)
  local brk = string.find(rest, "%.%.%.\t%(skip")
  if brk then
    assert(countlines(string.sub(rest, 1, brk)) == 10)
    assert(countlines(string.sub(rest, brk, #rest)) == 11)
  else
    assert(cl == total - start + 2)
  end
end
for d = 1, 51, 10 do
  for l = 1, d do coroutine.wrap(checkdeep)(d, l) end
end
return true
"#;

const TRACE_CURRENT_THREAD: &[u8] = br#"
local co
co = coroutine.create(function()
  local default = debug.traceback(co)
  assert(string.find(default, "^stack traceback:\n"))
  assert(not string.find(default, "'debug.traceback'"))
  local zero = debug.traceback(co, nil, 0)
  assert(string.find(zero, "^stack traceback:\n\t%[C%]: in function '"))
  return true
end)
local ok, answer = coroutine.resume(co)
assert(ok and answer)
return true
"#;

const TRACE_HOOK: &[u8] = br#"
local trace
debug.sethook(function()
  debug.sethook()
  trace = debug.traceback()
end, "", 1)
local value = 1
assert(value == 1 and string.find(trace, "in hook"))
return true
"#;

const STRIPPED_LINE_HOOK: &[u8] = br#"
local function foo()
  local a = 1
  local b = 2
  return b
end
local stripped = assert(load(string.dump(foo, true), nil, "b"))

local line = true
local line_seen = false
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(event == "line")
    line = value
    line_seen = true
  end
end, "l")
assert(stripped() == 2)
debug.sethook(nil)
assert(line_seen)
assert(line == nil)

local count_events = 0
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(event == "count")
    assert(value == nil)
    count_events = count_events + 1
  end
end, "", 1)
assert(stripped() == 2)
debug.sethook(nil)
assert(count_events > 0)

local events = {}
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(value == nil)
    assert(event == "count" or event == "line")
    events[#events + 1] = event
  end
end, "l", 1)
assert(stripped() == 2)
local mixed_event_count = #events
debug.sethook(nil)
assert(events[1] == "count")
assert(events[2] == "line")
for index = 3, mixed_event_count do
  assert(events[index] == "count")
end

local cancelled_events = {}
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(value == nil)
    cancelled_events[#cancelled_events + 1] = event
    if event == "count" then
      debug.sethook(nil)
    else
      assert(event == "line")
    end
  end
end, "l", 1)
assert(stripped() == 2)
debug.sethook(nil)
assert(cancelled_events[1] == "count")
assert(#cancelled_events == 1)

local replaced_events = {}
local replacement = function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(value == nil)
    replaced_events[#replaced_events + 1] = "new-" .. event
  end
end
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == stripped then
    assert(event == "count" and value == nil)
    replaced_events[#replaced_events + 1] = "old-count"
    debug.sethook(replacement, "", 1)
  end
end, "l", 1)
assert(stripped() == 2)
debug.sethook(nil)
assert(replaced_events[1] == "old-count")
assert(replaced_events[2] == "new-line")

local function full()
  local a = 1
  local b = 2
  return b
end
local active_lines = debug.getinfo(full, "L").activelines
local full_line_seen = false
debug.sethook(function(event, value)
  local frame = debug.getinfo(2, "f")
  if frame and frame.func == full then
    assert(event == "line")
    assert(value ~= nil and active_lines[value])
    full_line_seen = true
  end
end, "l")
assert(full() == 2)
debug.sethook(nil)
assert(full_line_seen)
return true
"#;

const TRACE_BUDGET: &[u8] = br#"
local ok, reason = pcall(debug.traceback)
assert(not ok and reason ~= nil)
return true
"#;

const GETINFO_U: &[u8] = br#"
local print_info = debug.getinfo(print, "u")
assert(print_info.nparams == 0 and print_info.nups == 0 and print_info.isvararg)
local builtin_info = debug.getinfo(debug.getinfo, "u")
assert(builtin_info.nparams == 0 and builtin_info.nups == 0 and builtin_info.isvararg)
local iterator_info = debug.getinfo(string.gmatch("abc", "a"), "u")
assert(iterator_info.nparams == 0 and iterator_info.nups == 3 and iterator_info.isvararg)
local captured = 3
local function fixed(a, b) return a + b + captured end
local function variable(a, ...) return a end
local fixed_info = debug.getinfo(fixed, "u")
assert(fixed_info.nparams == 2 and fixed_info.nups == 1 and not fixed_info.isvararg)
local variable_info = debug.getinfo(variable, "u")
assert(variable_info.nparams == 1 and variable_info.nups == 0 and variable_info.isvararg)
return true
"#;

const GETINFO_C_CLOSURE_U: &[u8] = br#"
local closure_info = debug.getinfo(cclosure, "uS")
assert(closure_info.nparams == 0 and closure_info.nups == 2 and closure_info.isvararg)
assert(closure_info.what == "C")
local function_info = debug.getinfo(cfunction, "u")
assert(function_info.nparams == 0 and function_info.nups == 0 and function_info.isvararg)
return true
"#;

const GETINFO_COROUTINE_FRAME: &[u8] = br#"
local co
co = coroutine.create(function(x)
  local a = 1
  local implicit = debug.getinfo(1, "fS")
  local explicit = debug.getinfo(co, 1, "fS")
  assert(implicit.func == explicit.func and implicit.source == explicit.source)
  coroutine.yield(debug.getinfo(1, "l").currentline)
  return a + x
end)
local ok, line = coroutine.resume(co, 10)
assert(ok and type(line) == "number")
local info = debug.getinfo(co, 1, "lfLS")
assert(info.currentline == line and info.activelines[line])
assert(type(info.func) == "function")
assert(info.source == "@p17-debug-traceback.lua")
assert(info.linedefined > 0 and info.lastlinedefined >= info.linedefined)
local function_info = debug.getinfo(co, info.func, "uS")
assert(function_info.what == "Lua" and function_info.nparams == 1)
assert(function_info.source == info.source)
assert(debug.getinfo(co, 0, "S").what == "C")
assert(debug.getinfo(co, -1, "S") == nil)
assert(debug.getinfo(co, 2) == nil)
assert(debug.getinfo(co, 1000000) == nil)
return true
"#;

const GETINFO_COROUTINE_FUNCTION: &[u8] = br#"
local co = coroutine.create(function() coroutine.yield() end)
assert(coroutine.resume(co))
local info = debug.getinfo(co, print, "uS")
assert(info.what == "C" and info.nparams == 0 and info.isvararg)
return true
"#;

const GETINFO_COROUTINE_LEVEL: &[u8] = br#"
local co = coroutine.create(function() coroutine.yield() end)
assert(coroutine.resume(co))
return debug.getinfo(co, 1, "l")
"#;

const GETINFO_METAMETHOD_ORIGIN: &[u8] = br#"
local a = {}
local function f()
  local info = debug.getinfo(1, "n")
  assert(info.namewhat == "metamethod")
  a.op = info.name
  return info.name
end
setmetatable(a, {
  __index = f, __add = f, __sub = f, __mul = f, __mod = f,
  __pow = f, __div = f, __idiv = f, __band = f, __bor = f,
  __bxor = f, __shl = f, __shr = f, __unm = f, __bnot = f,
  __lt = f, __le = f, __eq = f, __len = f, __concat = f,
})
local b = setmetatable({}, getmetatable(a))
assert(a[3] == "index" and a ^ 3 == "pow" and a .. a == "concat")
assert(a / 3 == "div" and 3 % a == "mod")
assert(a + 3 == "add" and 3 - a == "sub" and a * 3 == "mul")
assert(a // 3 == "idiv" and -a == "unm" and #a == "len")
assert(a & 3 == "band" and a | 3 == "bor" and 3 ~ a == "bxor")
assert(a << 3 == "shl" and a >> 1 == "shr" and ~a == "bnot")
assert(a == b and a.op == "eq")
assert(a >= b and a.op == "le")
assert(a > b and a.op == "lt")
local c = setmetatable({}, {__newindex = function()
  local info = debug.getinfo(1, "n")
  assert(info.namewhat == "metamethod" and info.name == "newindex")
end})
c.x = 1
return true
"#;

const GETINFO_ITERATOR_ORIGIN: &[u8] = br#"
local function iterator()
  local info = debug.getinfo(1, "n")
  assert(info.namewhat == "for iterator" and info.name == "for iterator")
end
for i in iterator do end
local function ordinary(a, b)
  local info = debug.getinfo(1, "n")
  assert(info.name == "ordinary" and info.namewhat == "local")
  return nil
end
local result = ordinary(1, 2)
if result ~= nil then error("ordinary result") end
return true
"#;

const GETINFO_FINALIZER_ORIGIN: &[u8] = br#"
local name
do
  local object = setmetatable({}, {__gc = function()
    local info = debug.getinfo(1, "n")
    assert(info.namewhat == "metamethod")
    name = info.name
  end})
end
for i = 1, 8 do
  collectgarbage("collect")
  if name then break end
end
assert(name == "__gc")
return true
"#;

const GETINFO_PARKED_CALLER_ORIGIN: &[u8] = br#"
local co = coroutine.create(function()
  local function outer()
    local function inner()
      coroutine.yield()
    end
    inner()
  end
  outer()
end)
assert(coroutine.resume(co))
local info = debug.getinfo(co, 1, "n")
assert(info.name == "inner" and info.namewhat == "local")
return true
"#;

const GETINFO_DEAD_ERROR_CONTEXT: &[u8] = br#"
local co = coroutine.create(function()
  local function failed() error("boom") end
  failed()
end)
assert(not coroutine.resume(co))
local info = debug.getinfo(co, 1, "fSl")
assert(info and info.func and info.what == "Lua" and info.currentline > 0)
assert(debug.getinfo(co, 1000000) == nil)
local complete = coroutine.create(function() return true end)
assert(coroutine.resume(complete))
assert(debug.getinfo(complete, 1) == nil)
assert(debug.getinfo(complete, 1000000) == nil)
return true
"#;

fn compile(source: &[u8], language: LanguageProfile) -> VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let syntax = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&syntax, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-debug-traceback.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn official(module: &VerifiedModule, profile: LuaProfile) -> VerifiedModule {
    let bytes = emit_official_chunk(
        module,
        ProtoId(0),
        profile,
        false,
        &OfficialChunkLimits::default(),
        &mut OfficialWorkBudget::new(u64::MAX),
    )
    .unwrap();
    let chunk = decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&chunk, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_with_debug(module: VerifiedModule, profile: LuaProfile, debug: DebugCapability) -> RunOutcome {
    let mut vm = Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    execution.set_fuel(100_000_000).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    outcome
}

fn run_with_stripped_line_hook_services(
    module: VerifiedModule,
    profile: LuaProfile,
) -> RunOutcome {
    let services = HostServices::deny_all()
        .and_load(
            LoadCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(LoadLimits {
                    max_module_allocation_bytes: 16 * 1024 * 1024,
                    max_temporary_bytes: 8 * 1024 * 1024,
                    max_work_units: 10_000_000,
                    ..LoadLimits::default()
                }),
        )
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true))
        .and_debug(
            DebugCapability::deny_all()
                .allow(DebugPermission::EventHook)
                .allow(DebugPermission::CountHook)
                .allow(DebugPermission::Info)
                .allow(DebugPermission::StackInspection),
        );
    let mut vm = Vm::new_with_services(profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    execution.set_fuel(100_000_000).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    outcome
}

fn check_both_formats_with_debug(source: &[u8], debug: DebugCapability) {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(source, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            assert_eq!(
                run_with_debug(module, profile, debug),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?} {format}"
            );
        }
    }
}

fn check_both_formats(source: &[u8]) {
    check_both_formats_with_debug(
        source,
        DebugCapability::deny_all()
            .allow(DebugPermission::Traceback)
            .allow(DebugPermission::CountHook),
    );
}

#[test]
fn p17_traceback_nonstring_message_precedes_level_in_both_profiles_and_formats() {
    check_both_formats(NONSTRING_MESSAGE);
}

#[test]
fn p17_traceback_message_level_and_c_frames_in_both_profiles_and_formats() {
    check_both_formats(TRACE_FORMAT);
}

#[test]
fn p17_traceback_suspended_and_dead_coroutines_in_both_profiles_and_formats() {
    check_both_formats(TRACE_COROUTINE);
}

#[test]
fn p17_traceback_long_stack_exact_skip_in_both_profiles_and_formats() {
    check_both_formats(TRACE_DEEP);
}

#[test]
fn p17_traceback_explicit_current_coroutine_defaults_to_level_one_in_both_formats() {
    check_both_formats(TRACE_CURRENT_THREAD);
}

#[test]
fn p17_traceback_hook_frame_name_in_both_profiles_and_formats() {
    check_both_formats(TRACE_HOOK);
}

#[test]
fn p17_stripped_line_hook_nil_line_and_count_label_in_both_profiles_and_formats() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(STRIPPED_LINE_HOOK, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            assert_eq!(
                run_with_stripped_line_hook_services(module, profile),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?} {format}"
            );
        }
    }
}

#[test]
fn p17_traceback_existing_limits_reject_before_output_in_both_profiles_and_formats() {
    for limits in [
        DebugLimits {
            max_frames: 1,
            ..DebugLimits::default()
        },
        DebugLimits {
            max_trace_bytes: 10,
            ..DebugLimits::default()
        },
        DebugLimits {
            max_work_units: 10,
            ..DebugLimits::default()
        },
    ] {
        check_both_formats_with_debug(
            TRACE_BUDGET,
            DebugCapability::deny_all()
                .allow(DebugPermission::Traceback)
                .with_limits(limits),
        );
    }
}

#[test]
fn p17_getinfo_function_u_fields_match_c_and_lua_contract_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_U,
        DebugCapability::deny_all().allow(DebugPermission::Info),
    );
}

#[test]
fn p17_getinfo_c_closure_u_preserves_real_upvalue_count_in_both_profiles_and_formats() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(GETINFO_C_CLOSURE_U, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            let mut vm = Vm::new_with_services(
                profile,
                HostServices::deny_all().and_debug(
                    DebugCapability::deny_all().allow(DebugPermission::Info),
                ),
            )
            .unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            vm.install_debug_builtins(environment).unwrap();
            let id = HostFunctionId::new_unique(vm.id()).unwrap();
            let mut published = None;
            let closure = vm
                .prepare_unpublished_c_closure::<VmError>(
                    id,
                    &[Value::Integer(17), Value::Integer(23)],
                    |_, _| Ok(()),
                    |_, root| published = Some(root),
                )
                .unwrap();
            let closure_key = vm.allocate_byte_string(b"cclosure").unwrap();
            vm.raw_set(
                environment,
                Value::Object(closure_key),
                Value::Object(closure),
            )
            .unwrap();
            let function_key = vm.allocate_byte_string(b"cfunction").unwrap();
            vm.raw_set(
                environment,
                Value::Object(function_key),
                Value::CFunction(id),
            )
            .unwrap();
            drop(published);
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            execution.set_fuel(100_000_000).unwrap();
            assert_eq!(
                execution.run().unwrap(),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?} {format}"
            );
            drop(execution);
            vm.remove_root(environment_root).unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn p17_traceback_large_caller_small_callee_obeys_finite_work_in_both_profiles_and_formats() {
    let mut source = String::from(
        "local function small()\n  local text = debug.traceback()\n  return type(text) == 'string'\nend\nlocal function caller()\n  local t = {f = small}\n  local x = 0\n",
    );
    for _ in 0..700 {
        source.push_str("  x = x + 1\n");
    }
    source.push_str("  local answer = t.f()\n  return answer\nend\nreturn caller()\n");
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(source.as_bytes(), language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            let work_limit = if format == "native" { 20_000 } else { 8_000 };
            let low = run_with_debug(
                module.clone(),
                profile,
                DebugCapability::deny_all()
                    .allow(DebugPermission::Traceback)
                    .with_limits(DebugLimits {
                        max_work_units: work_limit,
                        ..DebugLimits::default()
                    }),
            );
            assert!(
                matches!(low, RunOutcome::LuaError(ref error) if error.diagnostic_id == "E_DEBUG_BUDGET"),
                "{profile:?} {format} low: {low:?}"
            );
            assert_eq!(
                run_with_debug(
                    module,
                    profile,
                    DebugCapability::deny_all().allow(DebugPermission::Traceback),
                ),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?} {format} high"
            );
        }
    }
}

#[test]
fn p17_getinfo_suspended_coroutine_level_projects_frame_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_COROUTINE_FRAME,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

#[test]
fn p17_getinfo_coroutine_function_selector_uses_offset_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_COROUTINE_FUNCTION,
        DebugCapability::deny_all().allow(DebugPermission::Info),
    );
}

#[test]
fn p17_getinfo_coroutine_level_requires_stack_permission_and_work_in_both_formats() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(GETINFO_COROUTINE_LEVEL, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            let denied = run_with_debug(
                module.clone(),
                profile,
                DebugCapability::deny_all().allow(DebugPermission::Info),
            );
            assert!(
                matches!(denied, RunOutcome::LuaError(ref error) if error.diagnostic_id == "E_HOST_POLICY_DEBUG"),
                "{profile:?} {format} denied: {denied:?}"
            );
            let bounded = run_with_debug(
                module,
                profile,
                DebugCapability::deny_all()
                    .allow(DebugPermission::Info)
                    .allow(DebugPermission::StackInspection)
                    .with_limits(DebugLimits {
                        max_work_units: 1,
                        ..DebugLimits::default()
                    }),
            );
            assert!(
                matches!(bounded, RunOutcome::LuaError(ref error) if error.diagnostic_id == "E_DEBUG_BUDGET"),
                "{profile:?} {format} bounded: {bounded:?}"
            );
        }
    }
}

#[test]
fn p17_getinfo_metamethod_origin_names_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_METAMETHOD_ORIGIN,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

#[test]
fn p17_getinfo_iterator_origin_names_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_ITERATOR_ORIGIN,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

#[test]
fn p17_getinfo_finalizer_origin_names_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_FINALIZER_ORIGIN,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

#[test]
fn p17_getinfo_parked_nested_caller_uses_its_own_origin_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_PARKED_CALLER_ORIGIN,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

#[test]
fn p17_getinfo_dead_error_context_remains_queryable_in_both_profiles_and_formats() {
    check_both_formats_with_debug(
        GETINFO_DEAD_ERROR_CONTEXT,
        DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::StackInspection),
    );
}

// 測試 runner 已安裝全域 debug；保留原 prog 的第一個區域槽和值。
const P17_STRIPPED_DEBUG_PROG: &[u8] = br#"
local debug = debug
local a = 12

local n, v = debug.getlocal(1, 1)
assert(n == "(temporary)" and v == debug)
n, v = debug.getlocal(1, 2)
assert(n == "(temporary)" and v == 12)

local f = function () local x; return a end
n, v = debug.getupvalue(f, 1)
assert(n == "(no name)" and v == 12)
assert(debug.setupvalue(f, 1, 13) == "(no name)")
assert(a == 13)

local t = debug.getinfo(f)
assert(t.name == nil and t.linedefined > 0 and
       t.lastlinedefined == t.linedefined and
       t.short_src == "?")
assert(debug.getinfo(1).currentline == -1)

t = debug.getinfo(f, "L").activelines
assert(next(t) == nil)

f = load(string.dump(f))
t = debug.getinfo(f)
assert(t.name == nil and t.linedefined > 0 and
       t.lastlinedefined == t.linedefined and
       t.short_src == "?")
assert(debug.getinfo(1).currentline == -1)

return a
"#;

const P17_STRIPPED_DEBUG_DUMP_RUNNER: &[u8] = br#"
local f = assert(load(chunk, nil, "b"))
f = assert(load(string.dump(f, true), nil, "b"))
return f()
"#;

const P17_STRIPPED_SETLOCAL_PROG: &[u8] = br#"
local debug = debug
local a = 12
local name = debug.setlocal(1, 2, 17)
assert(name == "(temporary)" and a == 17)
local observed, value = debug.getlocal(1, 2)
assert(observed == "(temporary)" and value == 17)
return a
"#;

fn run_with_stripped_debug_dump_services(
    module: VerifiedModule,
    profile: LuaProfile,
    chunk: &[u8],
) -> RunOutcome {
    let services = HostServices::deny_all()
        .and_load(
            LoadCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(LoadLimits {
                    max_module_allocation_bytes: 16 * 1024 * 1024,
                    max_temporary_bytes: 8 * 1024 * 1024,
                    max_work_units: 10_000_000,
                    ..LoadLimits::default()
                }),
        )
        .and_dump(DumpCapability::deny_all().with_official_bytecode(true))
        .and_debug(
            DebugCapability::deny_all()
                .allow(DebugPermission::LocalInspection)
                .allow(DebugPermission::LocalMutation)
                .allow(DebugPermission::StackInspection)
                .allow(DebugPermission::Upvalues)
                .allow(DebugPermission::UpvalueMutation)
                .allow(DebugPermission::Info),
        );
    let mut vm = Vm::new_with_services(profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();

    let key = vm.allocate_byte_string(b"chunk").unwrap();
    let value = vm.allocate_byte_string(chunk).unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        Value::Object(value),
    )
    .unwrap();

    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    execution.set_fuel(100_000_000).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    outcome
}

#[test]
fn p17_stripped_debug_dump_load_public_contract_in_both_profiles_and_formats() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let prog = compile(P17_STRIPPED_DEBUG_PROG, language);
        let chunk = emit_official_chunk(
            &prog,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut OfficialWorkBudget::new(100_000_000),
        )
        .unwrap();

        let native = compile(P17_STRIPPED_DEBUG_DUMP_RUNNER, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            assert_eq!(
                run_with_stripped_debug_dump_services(module, profile, &chunk),
                RunOutcome::Returned(vec![Value::Integer(13)]),
                "{profile:?} {format}"
            );
        }
    }
}

#[test]
fn p17_stripped_root_setlocal_uses_the_same_guest_slot_as_getlocal() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let prog = compile(P17_STRIPPED_SETLOCAL_PROG, language);
        let chunk = emit_official_chunk(
            &prog,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut OfficialWorkBudget::new(100_000_000),
        )
        .unwrap();
        let native = compile(P17_STRIPPED_DEBUG_DUMP_RUNNER, language);
        let imported = official(&native, profile);
        for (format, module) in [("native", native), ("official", imported)] {
            assert_eq!(
                run_with_stripped_debug_dump_services(module, profile, &chunk),
                RunOutcome::Returned(vec![Value::Integer(17)]),
                "{profile:?} {format}"
            );
        }
    }
}
