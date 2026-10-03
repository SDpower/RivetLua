use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    LuaProfile, ObjectRef, OfficialChunkErrorKind, OfficialChunkLimits, Value, VerifyLimits,
    preflight_official_chunk,
};
use rivetlua_runtime::{
    AbortReason, AllocationFailureKind, AllocationTrace, CallbackContinuation, CallbackResult,
    DebugCapability, DebugLimits, DebugPermission, DumpCapability, DumpLimits, FailPoint,
    HostEntropy, HostEntropyError, HostLoadCompiler, HostLoadError, HostLoadErrorKind,
    HostModuleBytes, HostModuleRepository, HostNativeLoader, HostNativeModule, HostOutput,
    HostOutputError, HostServices, HostSourceReader, LedgerSnapshot, LoadBudget, LoadCapability,
    LoadFormat, LoadLimits, ObjectKind, RootId, RootKind, RunOutcome, RuntimeError,
    RuntimeErrorKind, TableSortStop, Vm, VmError,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn profile() -> (&'static str, LanguageProfile, LuaProfile) {
    match std::env::var("RIVETLUA_P13_PROFILE").as_deref() {
        Ok("lua55-i64f64") => ("lua55-i64f64", LanguageProfile::Lua55, LuaProfile::Lua55),
        Ok("lua54-i64f64") => ("lua54-i64f64", LanguageProfile::Lua54, LuaProfile::Lua54),
        Err(std::env::VarError::NotPresent) => {
            ("lua55-i64f64", LanguageProfile::Lua55, LuaProfile::Lua55)
        }
        other => panic!("無效 P13 profile: {other:?}"),
    }
}

fn compile(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_with_basic_services(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
    collect: bool,
) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(environment_root).unwrap();
    (vm, outcome)
}

fn run_with_basic(source: &[u8]) -> (Vm, Vec<Value>) {
    let (vm, outcome) = run_with_basic_services(source, HostServices::deny_all(), None, false);
    let RunOutcome::Returned(values) = outcome else {
        panic!("basic 程式未正常返回: {outcome:?}");
    };
    (vm, values)
}

fn run_with_h(source: &[u8], services: HostServices) -> (Vm, RunOutcome) {
    run_with_h_config(source, services, None, false)
}

fn run_with_h_config(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
    collect: bool,
) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    (vm, outcome)
}

#[test]
fn p13_h_host_policy_default_debug_is_typed() {
    let (vm, outcome) = run_with_h(
        b"local ok,err=pcall(debug.traceback,'x'); return type(debug),ok,err",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("debug 預設拒絕應可捕捉: {outcome:?}");
    };
    assert_eq!(bytes(&vm, values[0]), b"table");
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[2]), b"E_HOST_POLICY_DEBUG");
}

#[test]
fn p13_h_function_info_upvalue_and_metatable_restricted_matrix() {
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::Info)
        .allow(DebugPermission::Upvalues)
        .allow(DebugPermission::MetatableRead)
        .allow(DebugPermission::TableMetatableWrite);
    let source = b"local x=17; local f=function(a,...) return x,a end; \
        local i=debug.getinfo(f,'f'); \
        local t,m={},{}; local same=debug.setmetatable(t,m)==t; \
        local ok,err=pcall(debug.getinfo,f,'u'); \
        local ok2,err2=pcall(debug.getupvalue,f,1); \
        return i.func==f,same,debug.getmetatable(t)==m,ok,err,ok2,err2";
    let (vm, outcome) = run_with_h_config(
        source,
        HostServices::deny_all().and_debug(debug),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("H2 查詢失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 7);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[4]), b"E_HOST_POLICY_DEBUG");
    assert_eq!(values[5], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[6]), b"E_HOST_POLICY_DEBUG");
}

#[test]
fn p13_h_string_metatable_identity_is_real() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::MetatableRead);
    let (_, outcome) = run_with_h(
        b"local a=debug.getmetatable('a'); local b=debug.getmetatable('b'); return a~=nil,a==b",
        HostServices::deny_all().and_debug(debug),
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Boolean(true)])
    );
}

#[test]
fn p13_h_unsupported_debug_selectors_and_hook_masks_deny_whole_call() {
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::Info)
        .allow(DebugPermission::CountHook);
    let source = b"local f=function() end; local i=debug.getinfo(f,'f'); \
        local a,ea=pcall(debug.getinfo,f); \
        local b,eb=pcall(debug.getinfo,f,'fl'); \
        local c,ec=pcall(debug.getinfo,0,'f'); \
        local d,ed=pcall(debug.getlocal,1,1); \
        local e,ee=pcall(debug.sethook,f,'l',1); \
        return i.func==f,a,ea,b,eb,c,ec,d,ed,e,ee,debug.gethook()==nil";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H matrix 失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 12);
    assert_eq!(values[0], Value::Boolean(true));
    for pair in values[1..11].chunks_exact(2) {
        assert_eq!(pair[0], Value::Boolean(false));
        assert_eq!(bytes(&vm, pair[1]), b"E_HOST_POLICY_DEBUG");
    }
    assert_eq!(values[11], Value::Boolean(true));
}

#[test]
fn p13_h_separate_environment_requires_restricted_upvalue_deny() {
    let (_, _, runtime_profile) = profile();
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::Info)
        .allow(DebugPermission::Upvalues);
    let source = b"local x=7; local captured=function() return x end; \
        local g=function() return missing_global end; \
        local ok1,e1=pcall(debug.getinfo,captured,'u'); \
        local ok2,e2=pcall(debug.getinfo,g,'u'); \
        local ok3,e3,v3=pcall(debug.getupvalue,g,1); \
        return ok1,e1,ok2,(ok2 and e2.nups or e2),ok3,e3,v3==_ENV";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H2 _ENV 對照失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 7);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_DEBUG");
    match runtime_profile {
        LuaProfile::Lua54 => {
            assert_eq!(values[2], Value::Boolean(true));
            assert_eq!(values[3], Value::Integer(1));
            assert_eq!(values[4], Value::Boolean(true));
            assert_eq!(bytes(&vm, values[5]), b"(no name)");
            assert_eq!(values[6], Value::Boolean(true));
        }
        LuaProfile::Lua55 => {
            assert_eq!(values[2], Value::Boolean(false));
            assert_eq!(bytes(&vm, values[3]), b"E_HOST_POLICY_DEBUG");
            assert_eq!(values[4], Value::Boolean(false));
            assert_eq!(bytes(&vm, values[5]), b"E_HOST_POLICY_DEBUG");
            assert_eq!(values[6], Value::Boolean(false));
        }
    }
}

#[test]
fn p13_h_count_hook_runs_before_original_instruction_once() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local n=0; local function hook(event,line) \
        if event~='count' or line~=nil then error('bad hook') end; \
        debug.sethook(); n=n+1 end; \
        debug.sethook(hook,'',1); n=n+10; return n,debug.gethook()==nil";
    let (_, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 count hook 失敗: {outcome:?}");
    };
    assert_eq!(values, vec![Value::Integer(11), Value::Boolean(true)]);
}

#[test]
fn p13_h_hook_error_keeps_pcall_value_and_allows_next_hook() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local fires=0; local function bad() debug.sethook(); error('boom') end; \
        local function work() debug.sethook(bad,'',1); local x=1; return x end; \
        local ok,e=pcall(work); \
        local function good() debug.sethook(); fires=fires+1 end; \
        debug.sethook(good,'',1); local y=5; return ok,e,fires,y";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 hook error 清理失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"boom");
    assert_eq!(values[2], Value::Integer(1));
    assert_eq!(values[3], Value::Integer(5));
}

#[test]
fn p13_h_hook_yield_and_host_output_failure_preserve_protected_errors() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local c=coroutine.create(function() \
        debug.sethook(function() coroutine.yield('bad') end,'',1); local x=4; return x end); \
        local ok,e=coroutine.resume(c); return ok,e,coroutine.status(c)";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 hook yield 失敗: {outcome:?}");
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_DEBUG");
    assert_eq!(bytes(&vm, values[2]), b"dead");

    let output = TestOutput(Rc::new(RefCell::new(Vec::new())), true);
    let source = b"local function work() debug.sethook(function() debug.sethook(); print('x') end,'',1); local x=3 end; \
        local ok,e=pcall(work); return ok,e";
    let (vm, outcome) = run_with_h(source, HostServices::with_output(output).and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 hook output 失敗: {outcome:?}");
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_OUTPUT_FAILED");
}

#[test]
fn p13_h_hook_fuel_abort_is_not_pcall_success_and_releases_pending_roots() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local function h() debug.sethook(); print('entered'); while true do end end; \
        local ok,e=pcall(function() debug.sethook(h,'',1); local x=1 end); return ok,e";
    let (mut vm, outcome) = run_with_h_config(
        source,
        HostServices::with_output(TestOutput(seen.clone(), false)).and_debug(debug),
        Some(500),
        true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(seen.borrow().as_slice(), b"entered\n");
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.collect().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_h_coroutine_hook_is_traced_only_from_coroutine_under_active_gc() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local c=coroutine.create(function() return 1 end); \
        local h=function() return 2 end; debug.sethook(c,h,'',1000); \
        local got,mask,count=debug.gethook(c); return c,h,got==h,mask,count";
    let (mut vm, outcome) = run_with_h_config(
        source,
        HostServices::deny_all().and_debug(debug),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 coroutine hook 失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 5);
    let Value::Object(coroutine) = values[0] else {
        panic!("coroutine 身分")
    };
    let Value::Object(hook) = values[1] else {
        panic!("hook 身分")
    };
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"");
    assert_eq!(values[4], Value::Integer(1000));
    let root = vm.add_root(RootKind::Host, coroutine).unwrap();
    vm.incremental_step(1).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(hook),
        Ok(rivetlua_runtime::ObjectKind::Closure)
    );
    vm.remove_root(root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(coroutine), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(hook), Err(VmError::StaleObject));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_h_coroutine_count_hook_runs_and_cross_coroutine_reentry_is_suppressed() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local fired=0; local c=coroutine.create(function() local x=7; return x end); \
        local function h() debug.sethook(c); fired=fired+1 end; \
        debug.sethook(c,h,'',1); local ok,value=coroutine.resume(c); return ok,value,fired";
    let (_, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(1)
        ])
    );

    let source = b"local child_hits=0; local main_hits=0; \
        local c=coroutine.create(function() return 7 end); \
        debug.sethook(c,function() child_hits=child_hits+1 end,'',1); \
        local function main_hook() debug.sethook(); main_hits=main_hits+1; coroutine.resume(c) end; \
        debug.sethook(main_hook,'',1); local x=3; return main_hits,child_hits,coroutine.status(c)";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 跨協程抑制失敗: {outcome:?}");
    };
    assert_eq!(values[0], Value::Integer(1));
    assert_eq!(values[1], Value::Integer(0));
    assert_eq!(bytes(&vm, values[2]), b"dead");
}

#[test]
fn p13_h_main_hook_may_resume_other_coroutine_through_yield_and_return() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local main_hits,child_hits=0,0; local a,b,c,d; \
        local child=coroutine.create(function() coroutine.yield(5); return 7 end); \
        debug.sethook(child,function() child_hits=child_hits+1 end,'',1); \
        local function h() debug.sethook(); main_hits=main_hits+1; \
          a,b=coroutine.resume(child); c,d=coroutine.resume(child) end; \
        debug.sethook(h,'',1); local x=3; \
        debug.sethook(function() debug.sethook(); main_hits=main_hits+10 end,'',1); \
        local y=4; return main_hits,child_hits,a,b,c,d,x,y,coroutine.status(child)";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 main hook 恢復子協程失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 9);
    assert_eq!(
        &values[..8],
        &[
            Value::Integer(11),
            Value::Integer(0),
            Value::Boolean(true),
            Value::Integer(5),
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(3),
            Value::Integer(4)
        ]
    );
    assert_eq!(bytes(&vm, values[8]), b"dead");
}

#[test]
fn p13_h_coroutine_hook_may_resume_other_coroutine_through_yield_and_return() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local outer_hits,child_hits=0,0; local a,b,c,d; \
        local child=coroutine.create(function() coroutine.yield(5); return 7 end); \
        debug.sethook(child,function() child_hits=child_hits+1 end,'',1); \
        local outer=coroutine.create(function() local x=3; return x end); \
        local function h() debug.sethook(outer); outer_hits=outer_hits+1; \
          a,b=coroutine.resume(child); c,d=coroutine.resume(child); \
          debug.sethook(outer,function() debug.sethook(outer); outer_hits=outer_hits+10 end,'',1) end; \
        debug.sethook(outer,h,'',1); local ok,value=coroutine.resume(outer); \
        return ok,value,outer_hits,child_hits,a,b,c,d,coroutine.status(child)";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 coroutine hook 恢復子協程失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 9);
    assert_eq!(
        &values[..8],
        &[
            Value::Boolean(true),
            Value::Integer(3),
            Value::Integer(11),
            Value::Integer(0),
            Value::Boolean(true),
            Value::Integer(5),
            Value::Boolean(true),
            Value::Integer(7)
        ]
    );
    assert_eq!(bytes(&vm, values[8]), b"dead");
}

#[test]
fn p13_h_hook_inside_pending_index_preserves_result_and_roots() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local fired=0; local function h() debug.sethook(); fired=fired+1 end; \
        local t=setmetatable({}, {__index=function() debug.sethook(h,'',1); local x=7; return x end}); \
        local value=t.missing; return value,fired";
    let (mut vm, outcome) = run_with_h_config(
        source,
        HostServices::deny_all().and_debug(debug),
        None,
        true,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(1)])
    );
    vm.collect().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_h_hook_error_runs_p11_close_and_preserves_original_error() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let source = b"local closed=0; local mt={__close=function() closed=closed+1 end}; \
        local function h() debug.sethook(); error('hook') end; \
        local function body() local x <close> = setmetatable({},mt); \
            debug.sethook(h,'',1); local z=1 end; \
        local ok,e=pcall(body); return ok,e,closed";
    let (mut vm, outcome) = run_with_h_config(
        source,
        HostServices::deny_all().and_debug(debug),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 P11 close 失敗: {outcome:?}");
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"hook");
    assert_eq!(values[2], Value::Integer(1));
    vm.collect().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_h_numeric_count_string_fuel_stops_before_hook_publication() {
    let (_, language, runtime_profile) = profile();
    let debug = DebugCapability::deny_all().allow(DebugPermission::CountHook);
    let mut vm =
        Vm::new_with_services(runtime_profile, HostServices::deny_all().and_debug(debug)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let digits = vm.allocate_byte_string(&vec![b'1'; 512]).unwrap();
    let name = vm.allocate_byte_string(b"long_count").unwrap();
    vm.raw_set(environment, Value::Object(name), Value::Object(digits))
        .unwrap();
    let before = vm.roots().total_count();
    let mut execution = vm
        .load_with_environment(
            compile(
                b"debug.sethook(function() end,'',long_count); return 1",
                language,
            ),
            Value::Object(environment),
        )
        .unwrap();
    execution.set_fuel(150).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), before);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let short_key = vm.allocate_byte_string(b"short_count").unwrap();
    let short_value = vm.allocate_byte_string(b"2").unwrap();
    vm.raw_set(
        environment,
        Value::Object(short_key),
        Value::Object(short_value),
    )
    .unwrap();
    let mut control = vm
        .load_with_environment(
            compile(
                b"debug.sethook(function() end,'',short_count); debug.sethook(); return 1",
                language,
            ),
            Value::Object(environment),
        )
        .unwrap();
    control.set_fuel(150).unwrap();
    assert_eq!(
        control.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(1)])
    );
    drop(control);
    assert_eq!(vm.roots().total_count(), before);
    vm.remove_root(root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_h_traceback_uses_live_rvlu_frames_and_bounded_numeric_message() {
    let debug = DebugCapability::deny_all().allow(DebugPermission::Traceback);
    let source = b"local marker={}; local function inner() return debug.traceback(42),debug.traceback(marker)==marker end; \
        local function outer() return inner() end; return outer()";
    let (vm, outcome) = run_with_h(source, HostServices::deny_all().and_debug(debug));
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 traceback 失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 2);
    let trace = bytes(&vm, values[0]);
    assert!(trace.starts_with(b"42\nstack traceback:\n"), "{trace:?}");
    assert!(
        trace
            .windows(b"RVLU prototype".len())
            .any(|window| window == b"RVLU prototype")
    );
    assert!(trace.windows(b" pc ".len()).any(|window| window == b" pc "));
    assert_eq!(values[1], Value::Boolean(true));

    let debug = debug.with_limits(DebugLimits {
        max_trace_bytes: 3,
        ..DebugLimits::default()
    });
    let (vm, outcome) = run_with_h(
        b"local ok,e=pcall(debug.traceback,'x'); return ok,e",
        HostServices::deny_all().and_debug(debug),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("H3 trace budget 失敗: {outcome:?}");
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_DEBUG_BUDGET");
}

fn run_with_io_os(source: &[u8], services: HostServices) -> (Vm, RunOutcome) {
    run_with_io_os_fuel(source, services, None)
}

fn run_with_io_os_fuel(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
) -> (Vm, RunOutcome) {
    run_with_io_os_observed(source, services, fuel, None)
}

fn run_with_io_os_observed(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
    state: Option<&Rc<RefCell<GHostState>>>,
) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    if let Some(state) = state {
        state.borrow_mut().ledger_probe = Some(vm.ledger_probe());
    }
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_io_os_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    (vm, outcome)
}

#[test]
fn p13_g_io_os_tables_are_visible_to_lua() {
    let (vm, outcome) = run_with_io_os(b"return type(io),type(os)", HostServices::deny_all());
    let RunOutcome::Returned(values) = outcome else {
        panic!("io/os 應可觀察: {outcome:?}");
    };
    assert_eq!(values.len(), 2);
    assert_eq!(bytes(&vm, values[0]), b"table");
    assert_eq!(bytes(&vm, values[1]), b"table");
}

#[derive(Default)]
struct GHostState {
    opens: usize,
    diagnostics_returned: usize,
    close_effects: usize,
    releases: usize,
    reads: usize,
    writes: usize,
    os_calls: usize,
    time_calls: usize,
    swallow_read_authorize: bool,
    swallow_close_authorize: bool,
    swallow_os_authorize: bool,
    diagnostic_read: bool,
    diagnostic_close: bool,
    io_failure_on: Option<rivetlua_runtime::FileOperation>,
    write_attempts: usize,
    write_fail_on_attempt: usize,
    write_invalid_metadata: u8,
    deny_deadline: bool,
    ledger_probe: Option<rivetlua_runtime::LedgerProbe>,
    retained_at_lease: usize,
    charge_release_violations: usize,
    swallow_open_after_lease: bool,
    claim_read_retained: bool,
    unknown_dst: bool,
}

fn g_diagnostic_error(
    state: &Rc<RefCell<GHostState>>,
    budget: &mut rivetlua_runtime::ResourceBudget<'_>,
) -> Result<rivetlua_runtime::HostResourceError, rivetlua_runtime::HostResourceError> {
    budget.claim_temporary(256)?;
    let mut diagnostic = Vec::with_capacity(256);
    diagnostic.resize(256, b'd');
    state.borrow_mut().diagnostics_returned += 1;
    Ok(rivetlua_runtime::HostResourceError::new(
        rivetlua_runtime::HostResourceErrorKind::PolicyDenied,
        diagnostic,
    ))
}

fn g_io_failure(
    budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    written: Option<usize>,
) -> Result<rivetlua_runtime::HostResourceError, rivetlua_runtime::HostResourceError> {
    budget.claim_temporary(20)?;
    let mut diagnostic = Vec::with_capacity(20);
    diagnostic.extend_from_slice(b"host io failure");
    Ok(if let Some(written) = written {
        rivetlua_runtime::HostResourceError::write_failure(diagnostic, 5, written)
    } else {
        rivetlua_runtime::HostResourceError::io_failure(diagnostic, 5)
    })
}

struct GDeadline(Rc<RefCell<GHostState>>);

impl rivetlua_runtime::HostDeadline for GDeadline {
    fn check(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        if self.0.borrow().deny_deadline {
            return Err(rivetlua_runtime::HostResourceError::new(
                rivetlua_runtime::HostResourceErrorKind::Deadline,
                Vec::new(),
            ));
        }
        budget.spend_work(1)
    }
}

struct GFile {
    state: Rc<RefCell<GHostState>>,
    bytes: [u8; 128],
    len: usize,
    position: usize,
    process: bool,
    retained_bytes: usize,
    verify_charge: bool,
    expected_host_bytes: usize,
}

impl Drop for GFile {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if let Some(probe) = &state.ledger_probe {
            if self.verify_charge
                && probe.snapshot().host_allocation_bytes < self.expected_host_bytes
            {
                state.charge_release_violations += 1;
            }
        }
        state.retained_at_lease -= self.retained_bytes;
        state.releases += 1;
    }
}

impl rivetlua_runtime::HostFileLease for GFile {
    fn authorize(
        &mut self,
        operation: rivetlua_runtime::FileOperation,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        if self.verify_charge {
            if let Some(probe) = &self.state.borrow().ledger_probe {
                self.expected_host_bytes = probe.snapshot().host_allocation_bytes;
            }
        }
        let state = self.state.borrow();
        let diagnostic = match operation {
            rivetlua_runtime::FileOperation::Read => state.diagnostic_read,
            rivetlua_runtime::FileOperation::Close => state.diagnostic_close,
            _ => false,
        };
        let swallow = match operation {
            rivetlua_runtime::FileOperation::Read => state.swallow_read_authorize,
            rivetlua_runtime::FileOperation::Close => state.swallow_close_authorize,
            _ => false,
        };
        drop(state);
        if diagnostic {
            return Err(g_diagnostic_error(&self.state, budget)?);
        }
        if swallow {
            let _ = budget.spend_work(usize::MAX);
            Ok(())
        } else {
            budget.spend_work(1)
        }
    }

    fn read(
        &mut self,
        format: rivetlua_runtime::FileReadFormat,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, rivetlua_runtime::HostResourceError> {
        if self.state.borrow().claim_read_retained {
            budget.claim_retained(128)?;
            self.retained_bytes += 128;
            self.state.borrow_mut().retained_at_lease += 128;
            if let Some(probe) = &self.state.borrow().ledger_probe {
                self.expected_host_bytes = probe.snapshot().host_allocation_bytes;
            }
        }
        if self.state.borrow().io_failure_on == Some(rivetlua_runtime::FileOperation::Read) {
            return Err(g_io_failure(budget, None)?);
        }
        let remaining = &self.bytes[self.position..self.len];
        let (count, consumed) = match format {
            rivetlua_runtime::FileReadFormat::Bytes(n) => {
                let n = n.min(remaining.len());
                (n, n)
            }
            rivetlua_runtime::FileReadFormat::All => (remaining.len(), remaining.len()),
            rivetlua_runtime::FileReadFormat::Number => {
                let n = remaining.iter().take_while(|c| c.is_ascii_digit()).count();
                (n, n)
            }
            rivetlua_runtime::FileReadFormat::Line { keep_newline } => {
                let line = remaining.iter().position(|c| *c == b'\n');
                match line {
                    Some(index) => (index + usize::from(keep_newline), index + 1),
                    None => (remaining.len(), remaining.len()),
                }
            }
        };
        if count == 0 && !matches!(format, rivetlua_runtime::FileReadFormat::All) {
            return Ok(None);
        }
        budget.spend_work(count.saturating_add(1))?;
        budget.claim_temporary(count)?;
        let value = remaining[..count].to_vec();
        self.position += consumed;
        self.state.borrow_mut().reads += 1;
        Ok(Some(value))
    }

    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<usize, rivetlua_runtime::HostResourceError> {
        budget.spend_work(bytes.len().saturating_add(1))?;
        let failing = {
            let mut state = self.state.borrow_mut();
            state.write_attempts += 1;
            state.write_fail_on_attempt == state.write_attempts
        };
        if failing {
            let written = bytes.len().min(2);
            self.bytes[self.position..self.position + written].copy_from_slice(&bytes[..written]);
            self.position += written;
            self.len = self.len.max(self.position);
            let variant = self.state.borrow().write_invalid_metadata;
            return match variant {
                1 => {
                    let claimed = g_io_failure(budget, None)?;
                    Err(rivetlua_runtime::HostResourceError::new(
                        rivetlua_runtime::HostResourceErrorKind::IoFailure,
                        claimed.diagnostic,
                    ))
                }
                2 => Err(g_io_failure(budget, Some(bytes.len() + 1))?),
                3 => Err(rivetlua_runtime::HostResourceError::write_failure(
                    Vec::new(),
                    5,
                    written,
                )),
                4 => Ok(written),
                _ => Err(g_io_failure(budget, Some(written))?),
            };
        }
        let end = self.position + bytes.len();
        if end > self.bytes.len() {
            return Err(rivetlua_runtime::HostResourceError::new(
                rivetlua_runtime::HostResourceErrorKind::IoFailure,
                Vec::new(),
            ));
        }
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
        self.len = self.len.max(end);
        self.state.borrow_mut().writes += 1;
        Ok(bytes.len())
    }

    fn seek(
        &mut self,
        origin: rivetlua_runtime::FileSeekOrigin,
        offset: i64,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<u64, rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        if self.state.borrow().io_failure_on == Some(rivetlua_runtime::FileOperation::Seek) {
            return Err(g_io_failure(budget, None)?);
        }
        let base = match origin {
            rivetlua_runtime::FileSeekOrigin::Set => 0,
            rivetlua_runtime::FileSeekOrigin::Current => self.position as i64,
            rivetlua_runtime::FileSeekOrigin::End => self.len as i64,
        };
        let position = base
            .checked_add(offset)
            .filter(|value| *value >= 0 && *value <= 128)
            .ok_or_else(|| {
                rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::IoFailure,
                    Vec::new(),
                )
            })?;
        self.position = position as usize;
        Ok(self.position as u64)
    }

    fn flush(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        if self.state.borrow().io_failure_on == Some(rivetlua_runtime::FileOperation::Flush) {
            return Err(g_io_failure(budget, None)?);
        }
        budget.spend_work(1)
    }

    fn setvbuf(
        &mut self,
        _mode: &[u8],
        _size: usize,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        if self.state.borrow().io_failure_on == Some(rivetlua_runtime::FileOperation::SetVBuf) {
            return Err(g_io_failure(budget, None)?);
        }
        budget.spend_work(1)
    }

    fn close(
        self: Box<Self>,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<rivetlua_runtime::HostCloseResult, rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        self.state.borrow_mut().close_effects += 1;
        if self.state.borrow().io_failure_on == Some(rivetlua_runtime::FileOperation::Close) {
            return Err(g_io_failure(budget, None)?);
        }
        Ok(if self.process {
            rivetlua_runtime::HostCloseResult::Process {
                success: true,
                signaled: false,
                code: 0,
            }
        } else {
            rivetlua_runtime::HostCloseResult::File
        })
    }
}

struct GIo(Rc<RefCell<GHostState>>);

impl GIo {
    fn file(
        &self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
        initial: &[u8],
        process: bool,
        verify_charge: bool,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        budget.claim_retained(256)?;
        self.0.borrow_mut().retained_at_lease += 256;
        let expected_host_bytes = self
            .0
            .borrow()
            .ledger_probe
            .as_ref()
            .map(|probe| probe.snapshot().host_allocation_bytes)
            .unwrap_or(0);
        let mut file = GFile {
            state: self.0.clone(),
            bytes: [0; 128],
            len: initial.len(),
            position: 0,
            process,
            retained_bytes: 256,
            verify_charge,
            expected_host_bytes,
        };
        file.bytes[..initial.len()].copy_from_slice(initial);
        Ok(Box::new(file))
    }
}

struct GOs(Rc<RefCell<GHostState>>);

impl rivetlua_runtime::HostOs for GOs {
    fn authorize(
        &mut self,
        operation: rivetlua_runtime::HostOsOperation<'_>,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        if self.0.borrow().swallow_os_authorize {
            let _ = budget.spend_work(usize::MAX);
            return Ok(());
        }
        budget.spend_work(1)?;
        if matches!(
            operation,
            rivetlua_runtime::HostOsOperation::Execute(Some(b"deny"))
        ) {
            return Err(rivetlua_runtime::HostResourceError::new(
                rivetlua_runtime::HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        }
        Ok(())
    }

    fn authorize_path(
        &mut self,
        path: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        if path == b"denied" {
            return Err(rivetlua_runtime::HostResourceError::new(
                rivetlua_runtime::HostResourceErrorKind::PathDenied,
                Vec::new(),
            ));
        }
        Ok(())
    }

    fn perform(
        &mut self,
        operation: rivetlua_runtime::HostOsOperation<'_>,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<rivetlua_runtime::HostOsValue, rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        {
            let mut state = self.0.borrow_mut();
            state.os_calls += 1;
            if matches!(operation, rivetlua_runtime::HostOsOperation::Time(_)) {
                state.time_calls += 1;
            }
        }
        if matches!(
            operation,
            rivetlua_runtime::HostOsOperation::GetEnv(b"DIAGNOSTIC")
        ) {
            return Err(g_diagnostic_error(&self.0, budget)?);
        }
        use rivetlua_runtime::{HostCalendar, HostExitStatus, HostOsOperation, HostOsValue};
        Ok(match operation {
            HostOsOperation::Clock => HostOsValue::Number(1.25),
            HostOsOperation::GetEnv(b"KEY") => {
                budget.claim_temporary(5)?;
                HostOsValue::Bytes(b"value".to_vec())
            }
            HostOsOperation::GetEnv(b"CANCEL") => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::Cancelled,
                    Vec::new(),
                ));
            }
            HostOsOperation::GetEnv(b"IOFAIL") => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::IoFailure,
                    Vec::new(),
                ));
            }
            HostOsOperation::GetEnv(b"POLICY") => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::PolicyDenied,
                    Vec::new(),
                ));
            }
            HostOsOperation::GetEnv(_) => HostOsValue::Nil,
            HostOsOperation::Date(b"*t", _) => HostOsValue::Calendar(HostCalendar {
                year: 2020,
                month: 1,
                day: 2,
                hour: 3,
                minute: 4,
                second: 5,
                weekday: Some(5),
                year_day: Some(2),
                daylight_saving: Some(false),
            }),
            HostOsOperation::Date(b"PLATFORM", _) => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::PlatformDifference,
                    Vec::new(),
                ));
            }
            HostOsOperation::Date(b"CANCEL", _) => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::Cancelled,
                    Vec::new(),
                ));
            }
            HostOsOperation::Date(_, _) => {
                budget.claim_temporary(4)?;
                HostOsValue::Bytes(b"date".to_vec())
            }
            HostOsOperation::Time(Some(fields)) => HostOsValue::Time {
                epoch: 1234,
                normalized: Some(HostCalendar {
                    weekday: Some(5),
                    year_day: Some(2),
                    daylight_saving: if self.0.borrow().unknown_dst {
                        None
                    } else {
                        Some(false)
                    },
                    ..fields
                }),
            },
            HostOsOperation::Time(None) => HostOsValue::Time {
                epoch: 1234,
                normalized: None,
            },
            HostOsOperation::Execute(None) => HostOsValue::Boolean(true),
            HostOsOperation::Execute(Some(_)) => HostOsValue::Exit(HostExitStatus {
                success: true,
                signaled: false,
                code: 0,
            }),
            HostOsOperation::Remove(b"iofail") | HostOsOperation::Rename(b"iofail", _) => {
                return Err(g_io_failure(budget, None)?);
            }
            HostOsOperation::Remove(_) | HostOsOperation::Rename(_, _) => {
                HostOsValue::Boolean(true)
            }
            HostOsOperation::Locale(Some(b"UNSUPPORTED"), _) => {
                return Err(rivetlua_runtime::HostResourceError::new(
                    rivetlua_runtime::HostResourceErrorKind::Unsupported,
                    Vec::new(),
                ));
            }
            HostOsOperation::Locale(_, _) => {
                budget.claim_temporary(1)?;
                HostOsValue::Bytes(b"C".to_vec())
            }
            HostOsOperation::TmpName => {
                budget.claim_temporary(3)?;
                HostOsValue::Bytes(b"tmp".to_vec())
            }
        })
    }
}

impl rivetlua_runtime::HostIo for GIo {
    fn authorize_path(
        &mut self,
        path: &[u8],
        _mode: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        if path == b"denied" {
            return Err(rivetlua_runtime::HostResourceError::new(
                rivetlua_runtime::HostResourceErrorKind::PathDenied,
                Vec::new(),
            ));
        }
        Ok(())
    }
    fn open(
        &mut self,
        path: &[u8],
        _mode: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        self.0.borrow_mut().opens += 1;
        if path == b"diagnostic" {
            return Err(g_diagnostic_error(&self.0, budget)?);
        }
        if path == b"iofail" {
            return Err(g_io_failure(budget, None)?);
        }
        let lease = self.file(
            budget,
            if path == b"lines" { b"one\ntwo\n" } else { b"" },
            false,
            true,
        )?;
        if self.0.borrow().swallow_open_after_lease {
            let _ = budget.spend_work(10_000);
        }
        Ok(lease)
    }
    fn tmpfile(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        Err(g_io_failure(budget, None)?)
    }
    fn stdin(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        self.file(budget, b"", false, false)
    }
    fn stdout(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        self.file(budget, b"", false, false)
    }
    fn stderr(
        &mut self,
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        self.file(budget, b"", false, false)
    }
    fn authorize_process(
        &mut self,
        _command: &[u8],
        _mode: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<(), rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)
    }
    fn popen(
        &mut self,
        command: &[u8],
        _mode: &[u8],
        budget: &mut rivetlua_runtime::ResourceBudget<'_>,
    ) -> Result<Box<dyn rivetlua_runtime::HostFileLease>, rivetlua_runtime::HostResourceError> {
        budget.spend_work(1)?;
        if command == b"iofail" {
            return Err(g_io_failure(budget, None)?);
        }
        self.file(budget, b"", true, true)
    }
}

fn g_services(state: Rc<RefCell<GHostState>>) -> HostServices {
    HostServices::deny_all().and_resource(
        rivetlua_runtime::ResourceCapability::deny_all()
            .and_io(GIo(state.clone()))
            .and_deadline(GDeadline(state.clone())),
    )
}

fn g_full_services(state: Rc<RefCell<GHostState>>) -> HostServices {
    HostServices::deny_all().and_resource(
        rivetlua_runtime::ResourceCapability::deny_all()
            .and_io(GIo(state.clone()))
            .and_os(GOs(state.clone()))
            .and_deadline(GDeadline(state.clone())),
    )
}

#[test]
fn p13_g_host_policy_default_deny_is_typed_and_no_fake_stdio() {
    let (vm, outcome) = run_with_io_os(
        b"local a,b=pcall(io.open,'x'); local c,d=pcall(os.getenv,'X'); return a,b,c,d,io.stdin,io.stdout",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("policy 應被 Lua 捕捉: {outcome:?}");
    };
    assert_eq!(values.len(), 6);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_IO");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"E_HOST_POLICY_OS");
    assert_eq!(values[4], Value::Nil);
    assert_eq!(values[5], Value::Nil);
}

#[test]
fn p13_g_fake_file_read_write_seek_close_and_identity() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (mut vm, outcome) = run_with_io_os(
        b"local f=io.open('mem','w+'); local t={[f]='before'}; f:write('a',42); f:seek('set',0); local value=f:read('*a'); local before=io.type(f); local ok=f:close(); local after=io.type(f); return value,before,ok,after,t[f],type(f)",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("file 操作應成功: {outcome:?}");
    };
    assert_eq!(bytes(&vm, values[0]), b"a42");
    assert_eq!(bytes(&vm, values[1]), b"file");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"closed file");
    assert_eq!(bytes(&vm, values[4]), b"before");
    assert_eq!(bytes(&vm, values[5]), b"userdata");
    assert_eq!(state.borrow().opens, 1);
    assert_eq!(state.borrow().close_effects, 1);
    assert_eq!(state.borrow().releases, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.collect().unwrap();
    drop(vm);
    assert_eq!(state.borrow().releases, 4);
}

#[test]
fn p13_g_fake_os_calendar_environment_process_and_typed_denials() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local d=os.date('*t',0); local t={year=2020,month=1,day=2}; local epoch=os.time(t); local ok,why,code=os.execute('ok'); local a,e=pcall(os.remove,'denied'); local b,f=pcall(os.getenv,'CANCEL'); return os.clock(),d.year,d.wday,epoch,t.yday,ok,why,code,os.getenv('KEY'),os.setlocale(nil,'time'),os.tmpname(),a,e,b,f",
        g_full_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("OS host 應成功且錯誤可捕捉: {outcome:?}");
    };
    assert_eq!(values.len(), 15);
    assert_eq!(values[0], Value::Float(1.25));
    assert_eq!(values[1], Value::Integer(2020));
    assert_eq!(values[2], Value::Integer(5));
    assert_eq!(values[3], Value::Integer(1234));
    assert_eq!(values[4], Value::Integer(2));
    assert_eq!(values[5], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[6]), b"exit");
    assert_eq!(values[7], Value::Integer(0));
    assert_eq!(bytes(&vm, values[8]), b"value");
    assert_eq!(bytes(&vm, values[9]), b"C");
    assert_eq!(bytes(&vm, values[10]), b"tmp");
    assert_eq!(values[11], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[12]), b"E_HOST_PATH_DENIED");
    assert_eq!(values[13], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[14]), b"E_HOST_CANCELLED");
    assert_eq!(state.borrow().os_calls, 8);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_swallowed_budget_in_authorizers_prevents_host_effects() {
    let state = Rc::new(RefCell::new(GHostState {
        swallow_read_authorize: true,
        swallow_close_authorize: true,
        swallow_os_authorize: true,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('mem','w+'); local a,e=pcall(function() return f:read('*a') end); local b,g=pcall(function() return f:close() end); local c,h=pcall(os.clock); return a,e,b,g,c,h,io.type(f)",
        g_full_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("sticky budget 應可捕捉: {outcome:?}");
    };
    assert_eq!(values.len(), 7);
    for index in [0, 2, 4] {
        assert_eq!(values[index], Value::Boolean(false));
    }
    for index in [1, 3, 5] {
        assert_eq!(bytes(&vm, values[index]), b"E_HOST_RESOURCE_BUDGET");
    }
    assert_eq!(bytes(&vm, values[6]), b"file");
    assert_eq!(state.borrow().opens, 1);
    assert_eq!(state.borrow().reads, 0);
    assert_eq!(state.borrow().close_effects, 0);
    assert_eq!(state.borrow().os_calls, 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_defaults_lines_and_process_close_keep_canonical_streams() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('mem','w+'); io.output(f); local same=io.output()==f; io.write('x'); io.flush(); io.input(f); f:seek('set',0); local value=io.read('*a'); local p=io.popen('ok','r'); local a,b,c=p:close(); local it=io.lines('lines'); local l1,l2,l3=it(),it(),it(); return same,value,a,b,c,l1,l2,l3,io.stdout==f,io.type(io.stdout)",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("default/lines/pipe 應成功: {outcome:?}");
    };
    assert_eq!(values.len(), 10);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"x");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"exit");
    assert_eq!(values[4], Value::Integer(0));
    assert_eq!(bytes(&vm, values[5]), b"one");
    assert_eq!(bytes(&vm, values[6]), b"two");
    assert_eq!(values[7], Value::Nil);
    assert_eq!(values[8], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[9]), b"file");
    assert_eq!(state.borrow().opens, 2);
    assert_eq!(state.borrow().close_effects, 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_optional_nil_and_difftime_integer_precision() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('mem',nil); local a=io.input(nil)==io.stdin; local b=io.output(nil)==io.stdout; local c=f:seek(nil,nil); local it=io.lines(nil,'*l'); local line=it(); return a,b,c,line,f:setvbuf('no',nil),os.difftime(9007199254740993,9007199254740992),os.difftime(9223372036854775807,-9223372036854775807)",
        g_full_services(state),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("optional nil/time 差值應成功: {outcome:?}");
    };
    assert_eq!(values.len(), 7);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], Value::Integer(0));
    assert_eq!(values[3], Value::Nil);
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(values[5], Value::Float(1.0));
    assert_eq!(
        values[6],
        Value::Float((i128::from(i64::MAX) - i128::from(-i64::MAX)) as f64)
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_mode_and_format_arguments_are_checked_before_host_effects() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('lines','r+b'); local part=f:read(2.0); local a=pcall(io.open,'mem','rb+'); local b=pcall(io.popen,'ok','r+b'); local c=pcall(io.type); return part,a,b,c,io.type(nil)",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("mode/format 邊界應可捕捉: {outcome:?}");
    };
    assert_eq!(values.len(), 5);
    assert_eq!(bytes(&vm, values[0]), b"on");
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(values[3], Value::Boolean(false));
    assert_eq!(values[4], Value::Nil);
    assert_eq!(state.borrow().opens, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_host_diagnostic_copy_fuel_abort_escapes_pcall_and_cleans_ledger() {
    let source = b"local ok,err=pcall(io.open,'diagnostic'); return ok,err";
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os_fuel(source, g_services(state.clone()), Some(10_000));
    let RunOutcome::Returned(values) = outcome else {
        panic!("主機診斷應進入 pcall: {outcome:?}");
    };
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), vec![b'd'; 256]);
    assert_eq!(state.borrow().diagnostics_returned, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let mut observed_copy_abort = false;
    for fuel in 1..256 {
        let state = Rc::new(RefCell::new(GHostState::default()));
        let (vm, outcome) = run_with_io_os_fuel(source, g_services(state.clone()), Some(fuel));
        if state.borrow().diagnostics_returned == 1
            && outcome == RunOutcome::Aborted(AbortReason::FuelExhausted)
        {
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            observed_copy_abort = true;
            break;
        }
    }
    assert!(observed_copy_abort, "須觀察主機已回診斷而複製耗盡 fuel");
}

#[test]
fn p13_g_file_and_os_diagnostic_copy_abort_restores_lease() {
    for case in 0..3 {
        let source: &[u8] = match case {
            0 => b"local f=io.open('mem'); local ok,err=pcall(function() return f:read('*a') end); return ok,err,io.type(f)",
            1 => b"local f=io.open('mem'); local ok,err=pcall(function() return f:close() end); return ok,err,io.type(f)",
            _ => b"local ok,err=pcall(os.getenv,'DIAGNOSTIC'); return ok,err",
        };
        let new_state = || {
            Rc::new(RefCell::new(GHostState {
                diagnostic_read: case == 0,
                diagnostic_close: case == 1,
                ..GHostState::default()
            }))
        };
        let state = new_state();
        let (vm, outcome) =
            run_with_io_os_fuel(source, g_full_services(state.clone()), Some(10_000));
        let RunOutcome::Returned(values) = outcome else {
            panic!("case {case} 診斷應進入 pcall: {outcome:?}");
        };
        assert_eq!(values[0], Value::Boolean(false));
        assert_eq!(bytes(&vm, values[1]), vec![b'd'; 256]);
        if case != 2 {
            assert_eq!(bytes(&vm, values[2]), b"file");
        }
        assert_eq!(state.borrow().diagnostics_returned, 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(vm);
        assert_eq!(state.borrow().releases, if case == 2 { 3 } else { 4 });

        let mut observed = false;
        for fuel in 1..256 {
            let state = new_state();
            let (vm, outcome) =
                run_with_io_os_fuel(source, g_full_services(state.clone()), Some(fuel));
            if state.borrow().diagnostics_returned == 1
                && outcome == RunOutcome::Aborted(AbortReason::FuelExhausted)
            {
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                drop(vm);
                assert_eq!(state.borrow().releases, if case == 2 { 3 } else { 4 });
                observed = true;
                break;
            }
        }
        assert!(observed, "case {case} 須觀察診斷複製耗盡 fuel");
    }
}

#[test]
fn p13_g_ordinary_host_io_failures_return_nil_message_errno() {
    use rivetlua_runtime::FileOperation;
    let cases: [(&[u8], Option<FileOperation>, bool); 10] = [
        (b"return io.open('iofail')", None, false),
        (b"return io.tmpfile()", None, false),
        (b"return io.popen('iofail','r')", None, false),
        (
            b"local f=io.open('mem'); return f:read('*a')",
            Some(FileOperation::Read),
            false,
        ),
        (
            b"local f=io.open('mem'); return f:flush()",
            Some(FileOperation::Flush),
            false,
        ),
        (
            b"local f=io.open('mem'); return f:seek()",
            Some(FileOperation::Seek),
            false,
        ),
        (
            b"local f=io.open('mem'); return f:setvbuf('no')",
            Some(FileOperation::SetVBuf),
            false,
        ),
        (
            b"local f=io.open('mem'); local a,b,c=f:close(); return a,b,c,io.type(f)",
            Some(FileOperation::Close),
            true,
        ),
        (b"return os.remove('iofail')", None, false),
        (b"return os.rename('iofail','next')", None, false),
    ];
    for (source, operation, closed) in cases {
        let state = Rc::new(RefCell::new(GHostState {
            io_failure_on: operation,
            ..GHostState::default()
        }));
        let (vm, outcome) = run_with_io_os(source, g_full_services(state.clone()));
        let RunOutcome::Returned(values) = outcome else {
            panic!("{source:?} 應回傳普通 I/O 失敗: {outcome:?}");
        };
        assert_eq!(values.len(), if closed { 4 } else { 3 }, "{source:?}");
        assert_eq!(values[0], Value::Nil, "{source:?}");
        assert_eq!(bytes(&vm, values[1]), b"host io failure", "{source:?}");
        assert_eq!(values[2], Value::Integer(5), "{source:?}");
        if closed {
            assert_eq!(bytes(&vm, values[3]), b"closed file");
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0, "{source:?}");
    }
}

#[test]
fn p13_g_write_partial_failure_and_profile_argument_order() {
    let (_, _, runtime_profile) = profile();
    let state = Rc::new(RefCell::new(GHostState {
        write_fail_on_attempt: 2,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('mem'); local a,b,c,d=f:write('ab','cdef'); return a,b,c,d",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("write failure 應回普通失敗: {outcome:?}");
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Nil);
    assert_eq!(bytes(&vm, values[1]), b"host io failure");
    assert_eq!(values[2], Value::Integer(5));
    assert_eq!(
        values[3],
        if runtime_profile == LuaProfile::Lua55 {
            Value::Integer(4)
        } else {
            Value::Nil
        }
    );
    assert_eq!(state.borrow().write_attempts, 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let state = Rc::new(RefCell::new(GHostState {
        write_fail_on_attempt: 2,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os(
        b"local f=io.open('mem'); local ok,value=pcall(function() return f:write('ab','cdef',{}) end); return ok,value",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("write profile 引數順序應可觀察: {outcome:?}");
    };
    assert_eq!(values.len(), 2);
    if runtime_profile == LuaProfile::Lua55 {
        assert_eq!(values, vec![Value::Boolean(true), Value::Nil]);
    } else {
        assert_eq!(values[0], Value::Boolean(false));
        assert_eq!(bytes(&vm, values[1]), b"E_IO_ARGUMENT");
    }
    assert_eq!(state.borrow().write_attempts, 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_write_rejects_missing_or_inconsistent_host_metadata() {
    for (variant, expected) in [
        (1, RuntimeErrorKind::HostIoFailed),
        (2, RuntimeErrorKind::HostPlatformDifference),
        (3, RuntimeErrorKind::HostPlatformDifference),
        (4, RuntimeErrorKind::HostPlatformDifference),
    ] {
        let state = Rc::new(RefCell::new(GHostState {
            write_fail_on_attempt: 1,
            write_invalid_metadata: variant,
            ..GHostState::default()
        }));
        let (vm, outcome) = run_with_io_os(
            b"local f=io.open('mem'); return f:write('abcd')",
            g_services(state.clone()),
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("variant {variant} 應拒絕: {outcome:?}");
        };
        assert_eq!(error.kind, expected, "variant {variant}");
        assert_eq!(state.borrow().write_attempts, 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_g_resource_error_kinds_and_budget_gate_are_distinct() {
    let cases: [(&[u8], RuntimeErrorKind, bool); 7] = [
        (
            b"return os.getenv('POLICY')",
            RuntimeErrorKind::HostPolicyOs,
            false,
        ),
        (
            b"return os.setlocale('UNSUPPORTED')",
            RuntimeErrorKind::HostUnsupported,
            false,
        ),
        (
            b"return os.remove('denied')",
            RuntimeErrorKind::HostPathDenied,
            false,
        ),
        (
            b"return os.getenv('IOFAIL')",
            RuntimeErrorKind::HostIoFailed,
            false,
        ),
        (
            b"return os.date('PLATFORM',0)",
            RuntimeErrorKind::HostPlatformDifference,
            false,
        ),
        (
            b"return os.getenv('CANCEL')",
            RuntimeErrorKind::HostCancelled,
            false,
        ),
        (b"return os.clock()", RuntimeErrorKind::HostDeadline, true),
    ];
    for (source, kind, deadline) in cases {
        let state = Rc::new(RefCell::new(GHostState {
            deny_deadline: deadline,
            ..GHostState::default()
        }));
        let services = if deadline {
            HostServices::deny_all().and_resource(
                rivetlua_runtime::ResourceCapability::deny_all()
                    .and_os(GOs(state.clone()))
                    .and_deadline(GDeadline(state.clone())),
            )
        } else {
            g_full_services(state.clone())
        };
        let (vm, outcome) = run_with_io_os(source, services);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("{source:?} 應保留型別: {outcome:?}");
        };
        assert_eq!(error.kind, kind, "{source:?}");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        if deadline {
            assert_eq!(state.borrow().os_calls, 0);
        }
    }

    let state = Rc::new(RefCell::new(GHostState::default()));
    let limits = rivetlua_runtime::ResourceLimits {
        max_work_units: 0,
        ..rivetlua_runtime::ResourceLimits::default()
    };
    let services = HostServices::deny_all().and_resource(
        rivetlua_runtime::ResourceCapability::deny_all()
            .and_os(GOs(state.clone()))
            .and_deadline(GDeadline(state.clone()))
            .with_limits(limits),
    );
    let (vm, outcome) = run_with_io_os(b"return os.clock()", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("零預算應先拒絕: {outcome:?}");
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostResourceBudget);
    assert_eq!(state.borrow().os_calls, 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_lease_drop_observes_retained_charge_on_abort_and_absorbed_growth() {
    let state = Rc::new(RefCell::new(GHostState {
        swallow_open_after_lease: true,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os_observed(
        b"return io.open('mem')",
        g_services(state.clone()),
        Some(100),
        Some(&state),
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(vm);
    assert_eq!(state.borrow().retained_at_lease, 0);
    assert_eq!(state.borrow().charge_release_violations, 0);

    let state = Rc::new(RefCell::new(GHostState {
        claim_read_retained: true,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os_observed(
        b"local f=io.open('mem'); f:read('*a'); f:close(); return true",
        g_services(state.clone()),
        None,
        Some(&state),
    );
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(true)]));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(vm);
    assert_eq!(state.borrow().retained_at_lease, 0);
    assert_eq!(state.borrow().charge_release_violations, 0);
}

#[test]
fn p13_g_io_installer_failures_restore_globals_roots_and_leases_under_active_gc() {
    fn setup(
        reinstall: bool,
        active_gc: bool,
    ) -> (
        Vm,
        ObjectRef,
        ObjectRef,
        ObjectRef,
        ObjectRef,
        ObjectRef,
        Rc<RefCell<GHostState>>,
    ) {
        let (_, _, runtime_profile) = profile();
        let state = Rc::new(RefCell::new(GHostState::default()));
        let mut vm = Vm::new_with_services(runtime_profile, g_services(state.clone())).unwrap();
        state.borrow_mut().ledger_probe = Some(vm.ledger_probe());
        let env = vm.allocate_table().unwrap();
        vm.add_root(RootKind::Host, env).unwrap();
        let io_key = vm.allocate_byte_string(b"io").unwrap();
        let os_key = vm.allocate_byte_string(b"os").unwrap();
        vm.add_root(RootKind::Host, io_key).unwrap();
        vm.add_root(RootKind::Host, os_key).unwrap();
        if reinstall {
            vm.install_io_os_builtins(env).unwrap();
        }
        let old_io = vm.allocate_table().unwrap();
        let old_os = vm.allocate_table().unwrap();
        vm.raw_set(env, Value::Object(io_key), Value::Object(old_io))
            .unwrap();
        vm.raw_set(env, Value::Object(os_key), Value::Object(old_os))
            .unwrap();
        vm.collect().unwrap();
        if active_gc {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(
            vm.gc_trace().phase == rivetlua_runtime::GcPhase::Pause,
            !active_gc
        );
        (vm, env, io_key, os_key, old_io, old_os, state)
    }

    for (reinstall, active_gc) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut dry, env, _, _, _, _, dry_state) = setup(reinstall, active_gc);
        let start = dry.allocation_trace().next_ordinal;
        dry.install_io_os_builtins(env).unwrap();
        let attempts = dry.allocation_trace().next_ordinal - start;
        assert!(attempts > 10);
        drop(dry);
        assert_eq!(dry_state.borrow().retained_at_lease, 0);
        let mut failures = 0;
        for offset in 0..attempts {
            let (mut vm, env, io_key, os_key, old_io, old_os, state) = setup(reinstall, active_gc);
            assert_eq!(vm.allocation_trace().next_ordinal, start);
            let roots = vm.roots().total_count();
            let before_trace = vm.gc_trace();
            let before_live = before_trace.young + before_trace.survivor + before_trace.old;
            vm.inject_allocation_failure_at(start + offset);
            let result = vm.install_io_os_builtins(env);
            if result.is_err() {
                failures += 1;
                let failure = vm
                    .allocation_trace()
                    .last_failure
                    .expect("注入點須記錄失敗 site");
                assert_eq!(failure.attempt.ordinal, start + offset);
                assert_eq!(
                    failure.kind,
                    rivetlua_runtime::AllocationFailureKind::Injection
                );
                assert!(
                    failure
                        .attempt
                        .site
                        .file
                        .starts_with("crates/rivetlua-runtime/src/")
                );
                assert_eq!(
                    vm.roots().total_count(),
                    roots,
                    "reinstall={reinstall} active={active_gc} offset={offset}"
                );
                assert_eq!(vm.raw_get(env, Value::Object(io_key)).unwrap_or_else(|error| panic!(
                    "io get reinstall={reinstall} active={active_gc} offset={offset} error={error:?} trace={:?} gc={:?}",
                    vm.allocation_trace(), vm.gc_trace()
                )), Value::Object(old_io));
                assert_eq!(vm.raw_get(env, Value::Object(os_key)).unwrap_or_else(|error| panic!(
                    "os get reinstall={reinstall} active={active_gc} offset={offset} error={error:?} trace={:?} gc={:?}",
                    vm.allocation_trace(), vm.gc_trace()
                )), Value::Object(old_os));
                assert_eq!(
                    state.borrow().retained_at_lease,
                    if reinstall { 768 } else { 0 },
                    "reinstall={reinstall} active={active_gc} offset={offset}"
                );
                let trace = vm.allocation_trace();
                vm.collect().unwrap_or_else(|error| panic!(
                    "reinstall={reinstall} active={active_gc} offset={offset} collect={error:?} trace={trace:?}"
                ));
                assert_eq!(
                    state.borrow().retained_at_lease,
                    if reinstall { 768 } else { 0 },
                    "reinstall={reinstall} active={active_gc} offset={offset} first finalizer cycle"
                );
                assert_eq!(state.borrow().close_effects, 0);
                // 第一輪可能執行新檔案的 __gc；第二輪回收已 finalizable 的殘留物件。
                vm.collect().unwrap();
                let after_trace = vm.gc_trace();
                assert_eq!(
                    after_trace.young + after_trace.survivor + after_trace.old,
                    before_live,
                    "reinstall={reinstall} active={active_gc} offset={offset} transient installer objects must collect"
                );
                vm.install_io_os_builtins(env).unwrap();
                assert_eq!(vm.roots().total_count(), roots + usize::from(!reinstall));
            }
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            drop(vm);
            assert_eq!(state.borrow().retained_at_lease, 0);
            assert_eq!(state.borrow().charge_release_violations, 0);
        }
        assert!(failures > 10, "reinstall={reinstall} active={active_gc}");
    }
}

#[test]
fn p13_g_unaliased_file_finalizer_and_vm_drop_release_once() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (mut vm, outcome) = run_with_io_os(
        b"do local f=io.open('mem') end; return true",
        g_services(state.clone()),
    );
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(true)]));
    assert_eq!(state.borrow().opens, 1);
    assert_eq!(state.borrow().releases, 0);
    vm.collect().unwrap();
    assert_eq!(state.borrow().close_effects, 1);
    assert_eq!(state.borrow().releases, 1);
    vm.collect().unwrap();
    assert_eq!(state.borrow().releases, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(vm);
    assert_eq!(state.borrow().close_effects, 1);
    assert_eq!(state.borrow().releases, 4);
    assert_eq!(state.borrow().retained_at_lease, 0);
}

#[test]
fn p13_g_p11_close_runs_once_on_normal_and_error_exit() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (mut vm, outcome) = run_with_io_os(
        b"do local f <close> = io.open('mem') end; local ok=pcall(function() local f <close> = io.open('mem'); error('boom') end); return ok",
        g_services(state.clone()),
    );
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(false)]));
    assert_eq!(state.borrow().opens, 2);
    assert_eq!(state.borrow().close_effects, 2);
    assert_eq!(state.borrow().releases, 2);
    vm.collect().unwrap();
    assert_eq!(state.borrow().close_effects, 2);
    assert_eq!(state.borrow().releases, 2);
    drop(vm);
    assert_eq!(state.borrow().releases, 5);
    assert_eq!(state.borrow().retained_at_lease, 0);
}

#[test]
fn p13_g_file_lease_and_stdio_registry_are_vm_isolated() {
    let first = Rc::new(RefCell::new(GHostState::default()));
    let second = Rc::new(RefCell::new(GHostState::default()));
    let (first_vm, first_outcome) = run_with_io_os(
        b"local f=io.open('mem'); return io.type(f)",
        g_services(first.clone()),
    );
    let (second_vm, second_outcome) = run_with_io_os(
        b"local f=io.open('mem'); return io.type(f)",
        g_services(second.clone()),
    );
    let RunOutcome::Returned(first_values) = first_outcome else {
        panic!("first VM failed: {first_outcome:?}");
    };
    let RunOutcome::Returned(second_values) = second_outcome else {
        panic!("second VM failed: {second_outcome:?}");
    };
    assert_eq!(bytes(&first_vm, first_values[0]), b"file");
    assert_eq!(bytes(&second_vm, second_values[0]), b"file");
    assert_eq!(first.borrow().releases, 0);
    assert_eq!(second.borrow().releases, 0);
    drop(first_vm);
    assert_eq!(first.borrow().releases, 4);
    assert_eq!(first.borrow().retained_at_lease, 0);
    assert_eq!(second.borrow().releases, 0);
    drop(second_vm);
    assert_eq!(second.borrow().releases, 4);
    assert_eq!(second.borrow().retained_at_lease, 0);
}

fn run_in_io_vm(vm: &mut Vm, environment: ObjectRef, source: &[u8]) -> RunOutcome {
    let (_, language, _) = profile();
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    outcome
}

#[test]
fn p13_g_file_lines_iterator_alone_traces_file_and_formats_through_gc() {
    let (_, _, runtime_profile) = profile();
    let state = Rc::new(RefCell::new(GHostState::default()));
    let mut vm = Vm::new_with_services(runtime_profile, g_services(state.clone())).unwrap();
    state.borrow_mut().ledger_probe = Some(vm.ledger_probe());
    let env = vm.allocate_table().unwrap();
    let env_root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    vm.install_io_os_builtins(env).unwrap();
    let outcome = run_in_io_vm(
        &mut vm,
        env,
        b"it=io.open('lines'):lines('*L'); return type(it)",
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("iterator setup failed: {outcome:?}");
    };
    assert_eq!(bytes(&vm, values[0]), b"function");
    assert_eq!(state.borrow().opens, 1);
    vm.collect().unwrap();
    assert_eq!(state.borrow().releases, 0);
    let outcome = run_in_io_vm(&mut vm, env, b"return it(),it()");
    let RunOutcome::Returned(values) = outcome else {
        panic!("iterator failed after GC: {outcome:?}");
    };
    assert_eq!(bytes(&vm, values[0]), b"one\n");
    assert_eq!(bytes(&vm, values[1]), b"two\n");
    assert_eq!(
        run_in_io_vm(&mut vm, env, b"it=nil; return true"),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    vm.collect().unwrap();
    assert_eq!(state.borrow().close_effects, 1);
    assert_eq!(state.borrow().releases, 1);
    vm.remove_root(env_root).unwrap();
    drop(vm);
    assert_eq!(state.borrow().releases, 4);
    assert_eq!(state.borrow().retained_at_lease, 0);
}

#[test]
fn p13_g_default_input_output_are_sole_file_roots_until_replaced() {
    let (_, _, runtime_profile) = profile();
    let state = Rc::new(RefCell::new(GHostState::default()));
    let mut vm = Vm::new_with_services(runtime_profile, g_services(state.clone())).unwrap();
    state.borrow_mut().ledger_probe = Some(vm.ledger_probe());
    let env = vm.allocate_table().unwrap();
    let env_root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    vm.install_io_os_builtins(env).unwrap();
    assert_eq!(
        run_in_io_vm(
            &mut vm,
            env,
            b"io.input(io.open('lines')); io.output(io.open('mem','w+')); return true"
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    assert_eq!(state.borrow().opens, 2);
    vm.collect().unwrap();
    assert_eq!(state.borrow().releases, 0);
    let outcome = run_in_io_vm(&mut vm, env, b"io.write('x'); return io.read('*l')");
    let RunOutcome::Returned(values) = outcome else {
        panic!("defaults failed after GC: {outcome:?}");
    };
    assert_eq!(bytes(&vm, values[0]), b"one");
    assert_eq!(state.borrow().writes, 1);
    assert_eq!(
        run_in_io_vm(
            &mut vm,
            env,
            b"io.input(io.stdin); io.output(io.stdout); return true"
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    vm.collect().unwrap();
    assert_eq!(state.borrow().close_effects, 2);
    assert_eq!(state.borrow().releases, 2);
    vm.remove_root(env_root).unwrap();
    drop(vm);
    assert_eq!(state.borrow().releases, 5);
    assert_eq!(state.borrow().retained_at_lease, 0);
}

#[test]
fn p13_g_os_time_uses_regular_calendar_get_and_set_callbacks() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local gets,writes=0,0; local t=setmetatable({}, {__index=function(_,k) gets=gets+1; if k=='year' then return 2020 elseif k=='month' then return 1 elseif k=='day' then return 2 end end, __newindex=function(self,k,v) writes=writes+1; rawset(self,k,v) end}); local epoch=os.time(t); local weekday=t.wday; local bad=setmetatable({}, {__index=function() error('lookup') end}); local ok=pcall(os.time,bad); return epoch,gets,writes,weekday,ok",
        g_full_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("calendar callback 應正常續接: {outcome:?}");
    };
    assert_eq!(
        values,
        vec![
            Value::Integer(1234),
            Value::Integer(7),
            Value::Integer(9),
            Value::Integer(5),
            Value::Boolean(false)
        ]
    );
    assert_eq!(state.borrow().os_calls, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_os_time_calendar_callbacks_resume_after_yield() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local t=setmetatable({}, {__index=function(_,k) if k=='year' then coroutine.yield('read'); return 2020 elseif k=='month' then return 1 elseif k=='day' then return 2 end end, __newindex=function(self,k,v) if k=='yday' then coroutine.yield('write') end rawset(self,k,v) end}); local co=coroutine.create(function() return os.time(t) end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); local e,f=coroutine.resume(co); return a,b,c,d,e,f,t.yday",
        g_full_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("calendar yield 應正常續接: {outcome:?}");
    };
    assert_eq!(values.len(), 7);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"read");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"write");
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(values[5], Value::Integer(1234));
    assert_eq!(values[6], Value::Integer(2));
    assert_eq!(state.borrow().os_calls, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_g_os_time_unknown_dst_skips_write_and_numeric_copy_can_abort() {
    let state = Rc::new(RefCell::new(GHostState {
        unknown_dst: true,
        ..GHostState::default()
    }));
    let (vm, outcome) = run_with_io_os(
        b"local writes=0; local t=setmetatable({isdst=true}, {__index=function(_,k) if k=='year' then return 2020 elseif k=='month' then return 1 elseif k=='day' then return 2 end end, __newindex=function(self,k,v) writes=writes+1; rawset(self,k,v) end}); return os.time(t),t.isdst,writes",
        g_full_services(state.clone()),
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(1234),
            Value::Boolean(true),
            Value::Integer(8)
        ])
    );
    assert_eq!(state.borrow().time_calls, 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let digits = "0".repeat(200);
    let source = format!(
        "local t=setmetatable({{}}, {{__index=function(_,k) if k=='year' then os.clock(); return '{digits}2020' elseif k=='month' then return 1 elseif k=='day' then return 2 end end}}); return os.time(t)"
    );
    let mut observed = false;
    for fuel in 1..350 {
        let state = Rc::new(RefCell::new(GHostState::default()));
        let (vm, outcome) = run_with_io_os_fuel(
            source.as_bytes(),
            g_full_services(state.clone()),
            Some(fuel),
        );
        if state.borrow().os_calls == 1
            && state.borrow().time_calls == 0
            && outcome == RunOutcome::Aborted(AbortReason::FuelExhausted)
        {
            assert_eq!(vm.roots().total_count(), 1);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            observed = true;
            break;
        }
    }
    assert!(observed, "字串轉整數 prepay 應可在 time host 呼叫前中止");
}

#[test]
fn p13_g_lines_filename_returns_close_value_and_closes_at_loop_exit() {
    let state = Rc::new(RefCell::new(GHostState::default()));
    let (vm, outcome) = run_with_io_os(
        b"local it,s,c,f=io.lines('lines'); local four=type(it)=='function' and s==nil and c==nil and io.type(f)=='file'; for line in io.lines('lines') do break end; local breaks=io.type(f); local ok=pcall(function() for line in io.lines('lines') do error('body') end end); local o=io.open('mem'); o:close(); local valid=pcall(function() return o:lines() end); return four,breaks,ok,valid",
        g_services(state.clone()),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("lines 關閉語意應成功: {outcome:?}");
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"file");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(values[3], Value::Boolean(false));
    assert_eq!(state.borrow().close_effects, 3);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_basic_load_functions_are_visible_to_lua() {
    let (vm, values) = run_with_basic(b"return type(load),type(loadfile),type(dofile)");
    assert_eq!(values.len(), 3);
    assert!(values.iter().all(|value| matches!(value, Value::Object(_))));
    assert!(values.iter().all(|value| bytes(&vm, *value) == b"function"));
}

#[test]
fn p13_f_package_require_preload_returns_loader_data_then_cached_single_value() {
    let (vm, outcome) = run_with_load(
        b"package.preload.alpha=function(name,data) return name..':'..data end; local a,b=require('alpha'); local n=select('#',require('alpha')); return a,b,n,package.loaded.alpha",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("preload require 應成功: {outcome:?}")
    };
    assert_eq!(values.len(), 4);
    assert_eq!(bytes(&vm, values[0]), b"alpha::preload:");
    assert_eq!(bytes(&vm, values[1]), b":preload:");
    assert_eq!(values[2], Value::Integer(1));
    assert_eq!(values[0], values[3]);
}

#[test]
fn p13_f_custom_searcher_data_and_first_nil_boundary() {
    let (vm, outcome) = run_with_load(
        b"package.searchers={function(name) return function(n,d) return n..':'..d end, 42 end}; local v,d=require('custom'); return v,d",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("自訂 searcher 應成功: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"custom:42");
    assert_eq!(values[1], Value::Integer(42));

    let (_, outcome) = run_with_load(
        b"local n=0; package.searchers={[1]=function() return 'first diagnostic' end,[3]=function() n=n+1; return function() end end}; local ok,e=pcall(require,'missing'); return ok,n",
        HostServices::deny_all(),
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(0)])
    );
}

#[test]
fn p13_f_preload_index_event_supplies_loader_and_data() {
    let (vm, outcome) = run_with_load(
        b"setmetatable(package.preload,{__index=function(t,k) return function(name,data) return name..data end end}); local x,d=require('virtual'); return x,d",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("preload __index 應提供 loader: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"virtual:preload:");
    assert_eq!(bytes(&vm, values[1]), b":preload:");
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_preload_index_yield_resume_keeps_loader_and_data_alive_with_gc() {
    let (vm, outcome) = run_with_load_config(
        b"setmetatable(package.preload,{__index=function(t,k) coroutine.yield('pause'); return function(name,data) return name..data end end}); local co=coroutine.create(function() return require('virtual') end); local a,b=coroutine.resume(co); local c,d,e=coroutine.resume(co); return a,b,c,d,e",
        HostServices::deny_all(), true, true, None,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("preload yield/resume 應完成: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"virtual:preload:");
    assert_eq!(bytes(&vm, values[4]), b":preload:");
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_searcher_and_loader_yield_resume_preserve_pending_state_with_gc() {
    let (vm, outcome) = run_with_load_config(
        b"package.searchers={function(name) coroutine.yield('search'); return function(n,d) coroutine.yield('load'); return n..d end,'-data' end}; local co=coroutine.create(function() return require('m') end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); local e,f,g=coroutine.resume(co); return a,b,c,d,e,f,g,package.loaded.m",
        HostServices::deny_all(), true, true, None,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("searcher/loader yield 應完成: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"search");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"load");
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[5]), b"m-data");
    assert_eq!(bytes(&vm, values[6]), b"-data");
    assert_eq!(values[5], values[7]);
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_loader_data_survives_loaded_write_yield_and_gc() {
    let (mut vm, outcome) = run_with_load_config(
        b"setmetatable(package.loaded,{__newindex=function(t,k,v) coroutine.yield('set'); rawset(t,k,v) end}); package.searchers={function() return function() return 17 end,{marker=73} end}; local co=coroutine.create(function() return require('m') end); local a,b=coroutine.resume(co); local junk={}; for i=1,30 do junk[i]={i} end; local c,v,d=coroutine.resume(co); return a,b,c,v,d,d.marker",
        HostServices::deny_all(), true, true, None,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pending loader data 應跨 yield: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"set");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(17));
    assert_eq!(values[5], Value::Integer(73));
    let Value::Object(data) = values[4] else {
        panic!("loader data 應為 table")
    };
    assert_eq!(
        vm.object_kind(data),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(data), Err(VmError::StaleObject));
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_package_require_nil_false_and_truthy_cache_rules() {
    let (vm, outcome) = run_with_load(
        b"local n=0; package.searchers={function() return function() n=n+1; return nil end,'D' end}; local a,d=require('x'); local b=require('x'); package.loaded.x=false; local c,e=require('x'); return a,d,b,c,e,n",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("nil/false cache 應可重搜: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(true),
            values[1],
            Value::Boolean(true),
            Value::Boolean(false),
            values[4],
            Value::Integer(2)
        ]
    );
    assert_eq!(bytes(&vm, values[1]), b"D");
    assert_eq!(bytes(&vm, values[4]), b"D");
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_require_cache_zero_empty_and_loader_mutations() {
    let (vm, outcome) = run_with_load(
        b"package.loaded.zero=0; package.loaded.empty=''; local a=require('zero'); local b=require('empty'); local n=0; package.searchers={function() return function() n=n+1; package.loaded.x=false; return nil end,'D' end}; local x,d=require('x'); local y,e=require('x'); return a,b,x,d,y,e,n",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("cache 真值與 loader mutation 應成功: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(0));
    assert_eq!(bytes(&vm, values[1]), b"");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"D");
    assert_eq!(values[4], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[5]), b"D");
    assert_eq!(values[6], Value::Integer(2));
}

#[test]
fn p13_f_require_registry_identity_survives_package_field_reassignment() {
    let (vm, outcome) = run_with_load(
        b"local oldloaded=package.loaded; local oldpreload=package.preload; oldpreload.k=function() return 19 end; package.loaded={}; package.preload={}; local x,d=require('k'); return x,d,oldloaded.k,package.loaded.k",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("registry identity 應穩定: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(19));
    assert_eq!(bytes(&vm, values[1]), b":preload:");
    assert_eq!(values[2], Value::Integer(19));
    assert_eq!(values[3], Value::Nil);
}

#[test]
fn p13_f_package_require_searcher_numeric_diagnostic_and_original_loader_error() {
    let (vm, outcome) = run_with_load(
        b"package.searchers={function() return 27 end}; local ok,e=pcall(require,'gone'); local marker={}; package.searchers={function() return function() error(marker) end end}; local ok2,e2=pcall(require,'bad'); return ok,e,ok2,e2==marker",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("診斷與原錯誤身分應保留: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    let diagnostic = bytes(&vm, values[1]);
    assert!(
        diagnostic.windows(2).any(|part| part == b"27"),
        "{diagnostic:?}"
    );
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(values[3], Value::Boolean(true));
}

#[test]
fn p13_f_protected_require_preload_not_found_waits_for_continuation() {
    let (vm, outcome) = run_with_load(
        b"local ok,e=pcall(require,'missing'); return ok,e",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall 應捕捉 require notfound: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert!(
        bytes(&vm, values[1])
            .windows(b"not found".len())
            .any(|part| part == b"not found")
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_recursive_require_stops_at_execution_fuel_limit() {
    let (vm, outcome) = run_with_load_config(
        b"package.searchers={function() return function(name) return require(name) end end}; return require('loop')",
        HostServices::deny_all(),
        false,
        false,
        Some(240),
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_protected_immediate_deferred_reader_and_closure_calls() {
    let calls = Rc::new(Cell::new(0));
    let load = LoadCapability::deny_all().and_compiler(TestLoadCompiler {
        calls: calls.clone(),
        names: None,
    });
    let (vm, outcome) = run_with_load(
        b"local a,x=pcall(assert,true,'ok'); local seen=false; local b,f=pcall(load,function() if seen then return nil end; seen=true; return 'return 9' end); local c,v=pcall(f); local d,e=pcall(load,function() error('reader-error') end); local q,z=pcall(function() return 5 end); return a,x,b,c,v,d,e,q,z",
        HostServices::deny_all().and_load(load),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall 三種路徑應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(values[4], Value::Integer(9));
    assert_eq!(values[5], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[6]), b"reader-error");
    assert_eq!(values[7], Value::Boolean(true));
    assert_eq!(values[8], Value::Integer(5));
    assert_eq!(calls.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_preload_diagnostic_suffix_prepays_long_name_copy() {
    let (_, language, runtime_profile) = profile();
    let name = "x".repeat(128);
    let source = format!("return pcall(require,'{name}')");
    let module = compile(source.as_bytes(), language);
    let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_package_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    // 1032 是長名稱下舊路徑於 suffix 搬移前恰好用盡的額度；
    // suffix 必須預付包含名稱的新緩衝區長度。
    execution.set_fuel(1032).unwrap();
    let outcome = execution.run().unwrap();
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    drop(execution);
    vm.remove_root(root).unwrap();
}

struct TestRepository(Rc<RefCell<Vec<Vec<u8>>>>);

impl HostModuleRepository for TestRepository {
    fn search(
        &mut self,
        _modname: &[u8],
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        budget.spend_work(path.len())?;
        self.0.borrow_mut().push(path.to_vec());
        if path != b"pkg/item/init.lua" {
            return Ok(None);
        }
        let source = b"return marker";
        let data = b"host-data";
        budget.claim_temporary(source.len() + data.len())?;
        Ok(Some(HostModuleBytes {
            data: source.to_vec(),
            loader_data: data.to_vec(),
            format: LoadFormat::Source,
        }))
    }
}

#[test]
fn p13_f_repository_path_expansion_and_loader_data() {
    let paths = Rc::new(RefCell::new(Vec::new()));
    let calls = Rc::new(Cell::new(0));
    let load = LoadCapability::deny_all()
        .and_compiler(TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        })
        .and_repository(TestRepository(paths.clone()));
    let (vm, outcome) = run_with_load(
        b"marker=73; package.path='?/init.lua;?.lua'; local x,d=require('pkg.item'); return x,d,select('#',require('pkg.item'))",
        HostServices::deny_all().and_load(load),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("repository 載入應成功: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(73));
    assert_eq!(bytes(&vm, values[1]), b"host-data");
    assert_eq!(values[2], Value::Integer(1));
    assert_eq!(&*paths.borrow(), &[b"pkg/item/init.lua".to_vec()]);
    assert_eq!(calls.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

struct OfficialRouteRepository {
    official: Vec<u8>,
    other_profile: Vec<u8>,
    rivet: Vec<u8>,
    calls: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl HostModuleRepository for OfficialRouteRepository {
    fn search(
        &mut self,
        modname: &[u8],
        _path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        let retrying =
            modname == b"retry" && self.calls.borrow().iter().any(|name| name == b"retry");
        self.calls.borrow_mut().push(modname.to_vec());
        let (source, format): (&[u8], LoadFormat) = match modname {
            b"official" => (&self.official, LoadFormat::OfficialBytecode),
            b"retry" if !retrying => (&self.other_profile, LoadFormat::OfficialBytecode),
            b"retry" => (&self.official, LoadFormat::OfficialBytecode),
            b"source" => (b"return 7", LoadFormat::Source),
            b"rivet" => (&self.rivet, LoadFormat::RivetBytecode),
            _ => return Ok(None),
        };
        let loader_data = b"repository-data";
        budget.spend_work(modname.len() + 1)?;
        budget.claim_temporary(source.len() + loader_data.len())?;
        Ok(Some(HostModuleBytes {
            data: source.to_vec(),
            loader_data: loader_data.to_vec(),
            format,
        }))
    }
}

fn official_route_rivet_bytes(language: LanguageProfile) -> Vec<u8> {
    let source = b"return 9";
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .bytes()
        .to_vec()
}

fn run_official_require_in_vm(
    vm: &mut Vm,
    environment: ObjectRef,
    language: LanguageProfile,
    source: &[u8],
) -> RunOutcome {
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    outcome
}

#[test]
fn p13_f_official_repository_uses_shared_load_admission_cache_and_existing_formats() {
    for (language, profile, official, other) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let repo = OfficialRouteRepository {
            official: official.to_vec(),
            other_profile: other.to_vec(),
            rivet: official_route_rivet_bytes(language),
            calls: calls.clone(),
        };
        let compiler_calls = Rc::new(Cell::new(0));
        let load = LoadCapability::deny_all()
            .and_repository(repo)
            .and_compiler(TestLoadCompiler {
                calls: compiler_calls.clone(),
                names: None,
            })
            .with_bytecode(true)
            .with_official_bytecode(true);
        let mut vm =
            Vm::new_with_services(profile, HostServices::deny_all().and_load(load)).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"package.path='?.lua'; local a,d=require('official'); local b=require('official'); local s=require('source'); local r=require('rivet'); return a,b,d,select('#',require('official')),s,r",
        );
        let RunOutcome::Returned(values) = outcome else {
            panic!("repository 三格式應成功：{profile:?}, {outcome:?}")
        };
        assert_eq!(values[0], Value::Integer(41));
        assert_eq!(values[1], Value::Integer(41));
        assert_eq!(bytes(&vm, values[2]), b"repository-data");
        assert_eq!(values[3], Value::Integer(1));
        assert_eq!(values[4], Value::Integer(7));
        assert_eq!(values[5], Value::Integer(9));
        assert_eq!(
            &*calls.borrow(),
            &[b"official".to_vec(), b"source".to_vec(), b"rivet".to_vec()]
        );
        assert_eq!(compiler_calls.get(), 1);

        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"package.path='?.lua'; local ok=pcall(require,'retry'); return ok,package.loaded.retry==nil,(require('retry'))",
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Boolean(false),
                Value::Boolean(true),
                Value::Integer(41)
            ])
        );
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|name| name.as_slice() == b"retry")
                .count(),
            2
        );
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_official_repository_denial_does_not_authorize_rivet_or_poison_cache() {
    for (language, profile, official, other) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
    ] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let repo = OfficialRouteRepository {
            official: official.to_vec(),
            other_profile: other.to_vec(),
            rivet: official_route_rivet_bytes(language),
            calls: calls.clone(),
        };
        let load = LoadCapability::deny_all()
            .and_repository(repo)
            .and_compiler(TestLoadCompiler {
                calls: Rc::new(Cell::new(0)),
                names: None,
            })
            .with_bytecode(true);
        let mut vm =
            Vm::new_with_services(profile, HostServices::deny_all().and_load(load)).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"package.path='?.lua'; return require('official')",
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("官方 repository 應拒絕：{profile:?}, {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);
        drop(error);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"return package.loaded.official==nil,require('source'),(require('rivet'))",
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Integer(7),
                Value::Integer(9)
            ])
        );
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"return require('official')",
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("拒絕後重試仍應拒絕：{outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);
        drop(error);
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|name| name.as_slice() == b"official")
                .count(),
            2
        );
        assert_eq!(vm.roots().total_count(), baseline_roots);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_official_repository_pays_shared_admission_and_rolls_back_on_budget_error() {
    for (language, profile, official, other) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
        ),
    ] {
        let stats = preflight_official_chunk(
            official,
            profile,
            &OfficialChunkLimits::default(),
            &VerifyLimits::default(),
        )
        .unwrap();
        let total_work = official.len() * 2 + 1 + stats.subsequent_work as usize;
        let calls = Rc::new(RefCell::new(Vec::new()));
        let repo = OfficialRouteRepository {
            official: official.to_vec(),
            other_profile: other.to_vec(),
            rivet: official_route_rivet_bytes(language),
            calls: calls.clone(),
        };
        let load = LoadCapability::deny_all()
            .and_repository(repo)
            .and_compiler(TestLoadCompiler {
                calls: Rc::new(Cell::new(0)),
                names: None,
            })
            .with_official_bytecode(true)
            .with_limits(LoadLimits {
                max_work_units: total_work - 1,
                ..LoadLimits::default()
            });
        let mut vm =
            Vm::new_with_services(profile, HostServices::deny_all().and_load(load)).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        let baseline_roots = vm.roots().total_count();
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"package.path='?.lua'; return require('official')",
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("官方 require 額度 one-below 應拒絕：{profile:?}, {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
        drop(error);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let outcome = run_official_require_in_vm(
            &mut vm,
            environment,
            language,
            b"return package.loaded.official==nil,(require('source'))",
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
        );
        assert_eq!(
            &*calls.borrow(),
            &[b"official".to_vec(), b"source".to_vec()]
        );
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

struct FailingRepository(usize);

impl HostModuleRepository for FailingRepository {
    fn search(
        &mut self,
        _modname: &[u8],
        _path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        budget.claim_temporary(self.0)?;
        Err(HostLoadError::new(
            HostLoadErrorKind::Failed,
            b"bad".to_vec(),
        ))
    }
}

#[test]
fn p13_f_repository_rejects_unclaimed_host_diagnostic_capacity() {
    for claimed in [0, 1] {
        let load = LoadCapability::deny_all().and_repository(FailingRepository(claimed));
        let (_, outcome) = run_with_load(
            b"package.path='?'; return require('x')",
            HostServices::deny_all().and_load(load),
        );
        let RunOutcome::LuaError(error) = outcome else {
            panic!("未申報 host buffer 應拒絕: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    }
}

#[test]
fn p13_f_repository_path_stops_at_first_nul() {
    let (_, length) = run_with_load(
        b"package.path='\\0?/init.lua'; return #package.path",
        HostServices::deny_all(),
    );
    assert_eq!(length, RunOutcome::Returned(vec![Value::Integer(11)]));
    let paths = Rc::new(RefCell::new(Vec::new()));
    let load = LoadCapability::deny_all().and_repository(TestRepository(paths.clone()));
    let (_, outcome) = run_with_load(
        b"package.path='\\0?/init.lua'; return require('pkg.item')",
        HostServices::deny_all().and_load(load),
    );
    assert!(matches!(outcome, RunOutcome::LuaError(_)), "{outcome:?}");
    assert!(paths.borrow().is_empty(), "首 NUL 後不可形成候選路徑");
}

struct TestNativeLoader {
    module: rivetlua_core::VerifiedModule,
    calls: Rc<RefCell<Vec<(Vec<u8>, bool)>>>,
}

impl HostNativeLoader for TestNativeLoader {
    fn search(
        &mut self,
        name: &[u8],
        root: bool,
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostNativeModule>, HostLoadError> {
        budget.spend_work(1)?;
        self.calls.borrow_mut().push((name.to_vec(), root));
        if root {
            return Ok(None);
        }
        budget.claim_module_allocation(200_000)?;
        budget.claim_temporary(6)?;
        Ok(Some(HostNativeModule {
            module: self.module.clone(),
            loader_data: b"native".to_vec(),
        }))
    }
}

#[test]
fn p13_f_native_provider_is_explicit_and_returns_verified_loader() {
    let (_, language, _) = profile();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let load = LoadCapability::deny_all().and_native_loader(TestNativeLoader {
        module: compile(b"return 44", language),
        calls: calls.clone(),
    });
    let (vm, outcome) = run_with_load(
        b"local x,d=require('native.mod'); return x,d",
        HostServices::deny_all().and_load(load),
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native provider 應載入: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(44));
    assert_eq!(bytes(&vm, values[1]), b"native");
    assert_eq!(&*calls.borrow(), &[(b"native.mod".to_vec(), false)]);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

struct FallbackNativeLoader {
    module: rivetlua_core::VerifiedModule,
    calls: Rc<RefCell<Vec<(Vec<u8>, bool)>>>,
}

impl HostNativeLoader for FallbackNativeLoader {
    fn search(
        &mut self,
        name: &[u8],
        root: bool,
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostNativeModule>, HostLoadError> {
        budget.spend_work(1)?;
        self.calls.borrow_mut().push((name.to_vec(), root));
        if !root {
            return Ok(None);
        }
        budget.claim_module_allocation(200_000)?;
        budget.claim_temporary(b"all-in-one".len())?;
        Ok(Some(HostNativeModule {
            module: self.module.clone(),
            loader_data: b"all-in-one".to_vec(),
        }))
    }
}

#[test]
fn p13_f_native_all_in_one_fallback_uses_installer_environment() {
    let (_, language, runtime_profile) = profile();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let load = LoadCapability::deny_all().and_native_loader(FallbackNativeLoader {
        module: compile(b"return marker", language),
        calls: calls.clone(),
    });
    let mut vm =
        Vm::new_with_services(runtime_profile, HostServices::deny_all().and_load(load)).unwrap();
    let installer = vm.allocate_table().unwrap();
    let installer_root = vm.add_root(RootKind::Host, installer).unwrap();
    vm.install_basic_builtins(installer).unwrap();
    vm.install_package_builtins(installer).unwrap();
    let marker_key = vm.allocate_byte_string(b"marker").unwrap();
    vm.raw_set(installer, Value::Object(marker_key), Value::Integer(41))
        .unwrap();
    let require_key = vm.allocate_byte_string(b"require").unwrap();
    let require = vm.raw_get(installer, Value::Object(require_key)).unwrap();
    let caller = vm.allocate_table().unwrap();
    let caller_root = vm.add_root(RootKind::Host, caller).unwrap();
    vm.raw_set(caller, Value::Object(marker_key), Value::Integer(92))
        .unwrap();
    vm.raw_set(caller, Value::Object(require_key), require)
        .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"local x,d=require('native.mod'); return x,d", language),
            Value::Object(caller),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    let RunOutcome::Returned(values) = outcome else {
        panic!("all-in-one 回退應載入: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(41));
    assert_eq!(bytes(&vm, values[1]), b"all-in-one");
    assert_eq!(
        &*calls.borrow(),
        &[
            (b"native.mod".to_vec(), false),
            (b"native.mod".to_vec(), true)
        ]
    );
    vm.remove_root(caller_root).unwrap();
    vm.remove_root(installer_root).unwrap();
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_native_verified_module_profile_mismatch_is_bytecode_error() {
    let (_, language, _) = profile();
    let other = if language == LanguageProfile::Lua55 {
        LanguageProfile::Lua54
    } else {
        LanguageProfile::Lua55
    };
    let calls = Rc::new(RefCell::new(Vec::new()));
    let load = LoadCapability::deny_all().and_native_loader(TestNativeLoader {
        module: compile(b"return 44", other),
        calls: calls.clone(),
    });
    let (vm, outcome) = run_with_load(
        b"return require('native.mod')",
        HostServices::deny_all().and_load(load),
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("profile mismatch 應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::LoadBytecode);
    assert_eq!(calls.borrow().len(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

struct DenyingNative(Rc<Cell<usize>>);

impl HostNativeLoader for DenyingNative {
    fn search(
        &mut self,
        _name: &[u8],
        _root: bool,
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostNativeModule>, HostLoadError> {
        self.0.set(self.0.get() + 1);
        let diagnostic = b"native denied";
        budget.claim_temporary(diagnostic.len())?;
        Err(HostLoadError::new(
            HostLoadErrorKind::PolicyDenied,
            diagnostic.to_vec(),
        ))
    }
}

#[test]
fn p13_f_host_policy_native_absence_and_configured_denial_are_distinct() {
    let (_, visible) = run_with_load(
        b"return package.searchers[2]==nil",
        HostServices::deny_all(),
    );
    assert_eq!(visible, RunOutcome::Returned(vec![Value::Boolean(true)]));
    let (vm, outcome) = run_with_load(b"return require('absent')", HostServices::deny_all());
    let RunOutcome::LuaError(error) = outcome else {
        panic!("缺 native provider 時仍應 not found: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::ModuleNotFound);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let calls = Rc::new(Cell::new(0));
    let load = LoadCapability::deny_all().and_native_loader(DenyingNative(calls.clone()));
    let (vm, outcome) = run_with_load(
        b"return require('denied')",
        HostServices::deny_all().and_load(load),
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("configured native 拒絕應保留型別: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyNative);
    assert_eq!(bytes(&vm, error.value), b"native denied");
    assert_eq!(calls.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_native_measurement_uses_fuel_before_nested_scan() {
    let (_, language, runtime_profile) = profile();
    let mut body = b"marker=1; local n=0;".to_vec();
    for _ in 0..300 {
        body.extend_from_slice(b"n=n+1;");
    }
    body.extend_from_slice(b"return n");
    let calls = Rc::new(RefCell::new(Vec::new()));
    let load = LoadCapability::deny_all().and_native_loader(TestNativeLoader {
        module: compile(&body, language),
        calls: calls.clone(),
    });
    let mut vm =
        Vm::new_with_services(runtime_profile, HostServices::deny_all().and_load(load)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_package_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return package.searchers[2]('native.mod')", language),
            Value::Object(environment),
        )
        .unwrap();
    execution.set_fuel(600).unwrap();
    let outcome = execution.run().unwrap();
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(calls.borrow().len(), 1);
    drop(execution);
    let marker = vm.allocate_byte_string(b"marker").unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(marker)).unwrap(),
        Value::Nil
    );
    vm.remove_root(root).unwrap();
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_loaded_module_charge_is_released_after_last_closure_is_collected() {
    let (_, language, runtime_profile) = profile();
    let calls = Rc::new(Cell::new(0));
    let load = LoadCapability::deny_all().and_compiler(TestLoadCompiler { calls, names: None });
    let mut vm =
        Vm::new_with_services(runtime_profile, HostServices::deny_all().and_load(load)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_package_builtins(environment).unwrap();
    vm.collect().unwrap();
    let baseline = vm.ledger_snapshot().committed;
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(
            compile(b"return load('return 7')", language),
            Value::Object(environment),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("load 應回傳 closure: {outcome:?}")
    };
    let Value::Object(closure) = values[0] else {
        panic!("load 應回傳 closure")
    };
    drop(execution);
    assert_eq!(
        vm.object_kind(closure),
        Ok(rivetlua_runtime::ObjectKind::Closure)
    );
    let before_collect = vm.ledger_snapshot().committed;
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(closure), Err(VmError::StaleObject));
    let after_collect = vm.ledger_snapshot().committed;
    assert!(
        before_collect.saturating_sub(after_collect) > 1024,
        "{baseline} {before_collect} {after_collect}"
    );
    vm.remove_root(root).unwrap();
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_package_cache_and_preload_are_vm_local() {
    let (left, left_outcome) = run_with_load(
        b"package.preload.same=function() return 'left' end; local x=require('same'); return x,package.loaded.same",
        HostServices::deny_all(),
    );
    let (right, right_outcome) = run_with_load(
        b"package.preload.same=function() return 'right' end; local x=require('same'); return x,package.loaded.same",
        HostServices::deny_all(),
    );
    let RunOutcome::Returned(left_values) = left_outcome else {
        panic!("左 VM: {left_outcome:?}")
    };
    let RunOutcome::Returned(right_values) = right_outcome else {
        panic!("右 VM: {right_outcome:?}")
    };
    assert_eq!(bytes(&left, left_values[0]), b"left");
    assert_eq!(bytes(&right, right_values[0]), b"right");
    assert_eq!(left_values[0], left_values[1]);
    assert_eq!(right_values[0], right_values[1]);
    assert_eq!(left.roots().total_count(), 2);
    assert_eq!(right.roots().total_count(), 2);
}

struct TestLoadCompiler {
    calls: Rc<Cell<usize>>,
    names: Option<Rc<RefCell<Vec<Vec<u8>>>>>,
}

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

struct MeteredTestCompiler;

struct UnderMeteredCompiler {
    calls: Rc<Cell<usize>>,
    module: rivetlua_core::VerifiedModule,
}

impl HostLoadCompiler for UnderMeteredCompiler {
    fn compile(
        &mut self,
        _source: &[u8],
        _chunkname: &[u8],
        _profile: LuaProfile,
        _budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.module.clone())
    }
}

#[test]
fn p13_f_source_module_measurement_pays_work_before_capacity_walk() {
    let (_, language, _) = profile();
    let mut large_source = b"return '".to_vec();
    large_source.extend(std::iter::repeat_n(b'x', 4096));
    large_source.push(b'\'');
    let module = compile(&large_source, language);

    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(UnderMeteredCompiler {
                calls: calls.clone(),
                module: module.clone(),
            })
            .with_limits(LoadLimits {
                max_work_units: 1,
                ..LoadLimits::default()
            }),
    );
    let (vm, outcome) = run_with_load(b"return load('return 7')", services);
    assert!(
        matches!(outcome, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget)
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        UnderMeteredCompiler {
            calls: calls.clone(),
            module,
        },
    ));
    let (vm, outcome) = run_with_load_config(
        b"return load('return 7')",
        services,
        false,
        false,
        Some(500),
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(calls.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

impl HostLoadCompiler for MeteredTestCompiler {
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let result = compile_with_budget(
            source,
            chunkname,
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut MeteredCompileSink(budget),
        );
        match result {
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

#[test]
fn p13_f_metered_compiler_loads_short_source_and_reports_syntax_and_budget() {
    let services = HostServices::deny_all()
        .and_load(LoadCapability::deny_all().and_compiler(MeteredTestCompiler));
    let (_, outcome) = run_with_load(b"return load('return 7')()", services);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));

    let services = HostServices::deny_all()
        .and_load(LoadCapability::deny_all().and_compiler(MeteredTestCompiler));
    let (vm, outcome) = run_with_load(b"return load('return *')", services);
    let RunOutcome::Returned(values) = outcome else {
        panic!("syntax error 應回傳 nil+diagnostic: {outcome:?}");
    };
    assert_eq!(values[0], Value::Nil);
    assert!(!bytes(&vm, values[1]).is_empty());

    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(MeteredTestCompiler)
            .with_limits(LoadLimits {
                max_work_units: 1,
                ..LoadLimits::default()
            }),
    );
    let (_, outcome) = run_with_load(b"return load('return 7')", services);
    assert!(
        matches!(outcome, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget)
    );
}

#[test]
fn p13_f_metered_compiler_spends_fuel_inside_callback_and_cleans_budget() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (vm, outcome) = run_with_load_config(
        b"return load('return 7')()",
        services,
        false,
        false,
        Some(500),
    );
    assert_eq!(calls.get(), 1, "燃料應在進入 compiler 後耗盡");
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_metered_compiler_allocation_faults_release_escrow_and_retry_in_same_vm() {
    let (_, language, profile) = profile();
    let runner = compile(b"return load('return 7')()", language);
    let make_vm = |calls: Rc<Cell<usize>>| {
        let services = HostServices::deny_all().and_load(
            LoadCapability::deny_all().and_compiler(TestLoadCompiler { calls, names: None }),
        );
        let mut vm = Vm::new_with_services(profile, services).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        (vm, environment, root)
    };
    let calls = Rc::new(Cell::new(0));
    let (mut vm, environment, root) = make_vm(calls.clone());
    vm.collect_major().unwrap();
    let probe = vm.ledger_probe();
    let baseline = probe.trace().next_ordinal;
    let mut execution = vm
        .load_with_environment(runner.clone(), Value::Object(environment))
        .unwrap();
    let callback_start = probe.trace().next_ordinal;
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );
    let callback_end = probe.trace().next_ordinal;
    drop(execution);
    assert_eq!(calls.get(), 1);
    assert!(callback_end > callback_start && callback_end - callback_start < 128);
    vm.remove_root(root).unwrap();

    let mut inside_compiler = 0;
    for ordinal in callback_start..callback_end {
        let calls = Rc::new(Cell::new(0));
        let (mut vm, environment, root) = make_vm(calls.clone());
        vm.collect_major().unwrap();
        let probe = vm.ledger_probe();
        assert_eq!(probe.trace().next_ordinal, baseline);
        let baseline_roots = vm.roots().total_count();
        let baseline_heap = vm.ledger_snapshot().host_allocation_bytes;
        vm.inject_allocation_failure_at(ordinal);
        let mut execution = vm
            .load_with_environment(runner.clone(), Value::Object(environment))
            .unwrap();
        let failed = execution.run();
        drop(execution);
        assert!(failed.is_err(), "ordinal {ordinal} 意外成功: {failed:?}");
        drop(failed);
        assert_eq!(probe.trace().last_failure.unwrap().attempt.ordinal, ordinal);
        assert_eq!(
            probe.trace().last_failure.unwrap().kind,
            AllocationFailureKind::Injection
        );
        if calls.get() != 0 {
            inside_compiler += 1;
        }
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.collect_major().unwrap();
        assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline_heap);
        let outcome = vm
            .load_with_environment(runner.clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
        assert_eq!(vm.roots().total_count(), baseline_roots);
        vm.remove_root(root).unwrap();
    }
    assert!(
        inside_compiler > 0,
        "至少一個真實 compiler quota allocation site 須受測"
    );
}

impl HostLoadCompiler for TestLoadCompiler {
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        if let Some(names) = &self.names {
            budget.spend_work(chunkname.len() + 1)?;
            budget.claim_temporary(chunkname.len())?;
            names.borrow_mut().push(chunkname.to_vec());
        }
        MeteredTestCompiler.compile(source, chunkname, profile, budget)
    }
}

fn run_with_load(source: &[u8], services: HostServices) -> (Vm, RunOutcome) {
    run_with_load_config(source, services, false, false, None)
}

fn run_with_load_config(
    source: &[u8],
    services: HostServices,
    collect_every_allocation: bool,
    coroutine: bool,
    fuel: Option<u64>,
) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_package_builtins(environment).unwrap();
    if coroutine {
        vm.install_coroutine_builtins(environment).unwrap();
    }
    vm.set_collect_every_allocation(collect_every_allocation);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    (vm, outcome)
}

#[test]
fn p13_f_host_policy_default_load_denies_before_host_and_budget_admission() {
    let (_, outcome) = run_with_load(b"return load('return 3')", HostServices::deny_all());
    let RunOutcome::LuaError(error) = outcome else {
        panic!("未配置 compiler 應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);

    let calls = Rc::new(Cell::new(0));
    let limits = LoadLimits {
        max_work_units: 0,
        ..LoadLimits::default()
    };
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(TestLoadCompiler {
                calls: calls.clone(),
                names: None,
            })
            .with_limits(limits),
    );
    let (_, outcome) = run_with_load(b"return load('return 3')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("零 work 上限應於 callback 前拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    assert_eq!(calls.get(), 0);
}

struct RejectingLoadCompiler {
    calls: Rc<Cell<usize>>,
    kind: HostLoadErrorKind,
    diagnostic: &'static [u8],
}

impl HostLoadCompiler for RejectingLoadCompiler {
    fn compile(
        &mut self,
        _source: &[u8],
        _chunkname: &[u8],
        _profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        budget.claim_temporary(self.diagnostic.len())?;
        Err(HostLoadError::new(self.kind, self.diagnostic))
    }
}

#[test]
fn p13_f_configured_compiler_policy_denial_keeps_kind_and_diagnostic() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        RejectingLoadCompiler {
            calls: calls.clone(),
            kind: HostLoadErrorKind::PolicyDenied,
            diagnostic: b"compiler policy denied",
        },
    ));
    let (vm, outcome) = run_with_load(b"return load('return 1')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("已配置 compiler 明示拒絕應為 Lua error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);
    assert_eq!(bytes(&vm, error.value), b"compiler policy denied");
    assert_eq!(calls.get(), 1);
}

#[test]
fn p13_f_configured_compiler_failure_preserves_diagnostic_bytes() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        RejectingLoadCompiler {
            calls: calls.clone(),
            kind: HostLoadErrorKind::Failed,
            diagnostic: b"host compiler failed: \xff",
        },
    ));
    let (vm, outcome) = run_with_load(b"return load('return 1')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("宿主 compiler 失敗應為 Lua error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadFailed);
    assert_eq!(bytes(&vm, error.value), b"host compiler failed: \xff");
    assert_eq!(calls.get(), 1);
}

struct SwallowingCompiler;

impl HostLoadCompiler for SwallowingCompiler {
    fn compile(
        &mut self,
        _source: &[u8],
        _chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        let _ = budget.spend_work(2);
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        Ok(compile(b"return 9", language))
    }
}

#[test]
fn p13_f_compiler_cannot_swallow_budget_failure() {
    let limits = LoadLimits {
        max_work_units: 1,
        ..LoadLimits::default()
    };
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(SwallowingCompiler)
            .with_limits(limits),
    );
    let (_, outcome) = run_with_load(b"return load('return 9')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("compiler 吞 budget error 不可假成功: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
}

struct TestSourceReader {
    path_calls: Rc<Cell<usize>>,
    stdin_calls: Rc<Cell<usize>>,
    denial: bool,
}

impl HostSourceReader for TestSourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, HostLoadError> {
        self.path_calls.set(self.path_calls.get() + 1);
        if self.denial {
            budget.claim_temporary(b"path denied".len())?;
            return Err(HostLoadError::new(
                HostLoadErrorKind::PolicyDenied,
                b"path denied",
            ));
        }
        assert_eq!(path, b"code.lua");
        budget.spend_work(24)?;
        budget.claim_temporary(24)?;
        Ok(b"return 3, 4".to_vec())
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget) -> Result<Vec<u8>, HostLoadError> {
        self.stdin_calls.set(self.stdin_calls.get() + 1);
        if self.denial {
            budget.claim_temporary(b"stdin denied".len())?;
            return Err(HostLoadError::new(
                HostLoadErrorKind::PolicyDenied,
                b"stdin denied",
            ));
        }
        budget.spend_work(24)?;
        budget.claim_temporary(24)?;
        Ok(b"return 5, 6".to_vec())
    }
}

#[test]
fn p13_f_loadfile_dofile_use_only_configured_reader_and_preserve_multret() {
    let path_calls = Rc::new(Cell::new(0));
    let stdin_calls = Rc::new(Cell::new(0));
    let compiler_calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(TestSourceReader {
                path_calls: path_calls.clone(),
                stdin_calls: stdin_calls.clone(),
                denial: false,
            })
            .and_compiler(TestLoadCompiler {
                calls: compiler_calls.clone(),
                names: None,
            }),
    );
    let (_, outcome) = run_with_load(
        b"local f=loadfile('code.lua'); local a,b=f(); local c,d=dofile('code.lua'); local e,g=dofile(); return a,b,c,d,e,g",
        services,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(4),
            Value::Integer(3),
            Value::Integer(4),
            Value::Integer(5),
            Value::Integer(6)
        ])
    );
    assert_eq!(path_calls.get(), 2);
    assert_eq!(stdin_calls.get(), 1);
    assert_eq!(compiler_calls.get(), 3);
}

#[test]
fn p13_f_load_function_reader_accumulates_chunks_and_stops_at_empty() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (_, outcome) = run_with_load(
        b"local n=0; local f=load(function() n=n+1; if n==1 then return 'return ' end; if n==2 then return 21 end; return '' end); return f(),n",
        services,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(21), Value::Integer(3)])
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn p13_f_load_function_reader_bad_type_and_lua_error_propagate() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (_, outcome) = run_with_load(b"return load(function() return {} end)", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("reader 非字串應報錯: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::LoadReaderType);
    assert_eq!(calls.get(), 0);

    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (vm, outcome) = run_with_load(
        b"return load(function() error('reader boom') end)",
        services,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("reader error 應傳遞: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::Thrown);
    assert_eq!(bytes(&vm, error.value), b"reader boom");
    assert_eq!(calls.get(), 0);
}

#[test]
fn p13_f_reader_absence_and_explicit_denial_are_distinct_from_host_failure() {
    let (_, outcome) = run_with_load(b"return loadfile('code.lua')", HostServices::deny_all());
    let RunOutcome::LuaError(error) = outcome else {
        panic!("缺 reader 應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyReader);

    let path_calls = Rc::new(Cell::new(0));
    let stdin_calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(
        TestSourceReader {
            path_calls: path_calls.clone(),
            stdin_calls: stdin_calls.clone(),
            denial: true,
        },
    ));
    let (vm, outcome) = run_with_load(b"return loadfile('code.lua')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("reader 明示拒絕應為 Lua error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyReader);
    assert_eq!(bytes(&vm, error.value), b"path denied");
    assert_eq!(path_calls.get(), 1);
    assert_eq!(stdin_calls.get(), 0);
}

#[test]
fn p13_f_loadfile_mode_errors_and_mode_fuel_precede_reader_call() {
    let path_calls = Rc::new(Cell::new(0));
    let stdin_calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(
        TestSourceReader {
            path_calls: path_calls.clone(),
            stdin_calls: stdin_calls.clone(),
            denial: false,
        },
    ));
    let (_, outcome) = run_with_load(b"return loadfile('code.lua', true)", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("無效 mode 應先拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::LoadArgument);
    assert_eq!(path_calls.get(), 0);

    let (_, language, runtime_profile) = profile();
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(
        TestSourceReader {
            path_calls: path_calls.clone(),
            stdin_calls: stdin_calls.clone(),
            denial: false,
        },
    ));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let env = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    let key = vm.allocate_byte_string(b"m").unwrap();
    let value = vm.allocate_byte_string(&vec![b't'; 500]).unwrap();
    vm.raw_set(env, Value::Object(key), Value::Object(value))
        .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return loadfile('code.lua',m)", language),
            Value::Object(env),
        )
        .unwrap();
    execution.set_fuel(200).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(path_calls.get(), 0);
    assert_eq!(stdin_calls.get(), 0);
    vm.remove_root(root).unwrap();
}

struct ProbeSourceReader {
    calls: Rc<Cell<usize>>,
    allocations: Rc<Cell<usize>>,
    work: usize,
    claim: usize,
    ignore_budget_error: bool,
    capacity: usize,
    source: &'static [u8],
}

impl HostSourceReader for ProbeSourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, b"a");
        self.calls.set(self.calls.get() + 1);
        let work = budget.spend_work(self.work);
        if !self.ignore_budget_error {
            work?;
        }
        let claim = budget.claim_temporary(self.claim);
        if !self.ignore_budget_error {
            claim?;
        }
        self.allocations.set(self.allocations.get() + 1);
        let mut bytes = Vec::with_capacity(self.capacity.max(self.source.len()));
        bytes.extend_from_slice(self.source);
        Ok(bytes)
    }

    fn read_stdin(&mut self, _budget: &mut LoadBudget) -> Result<Vec<u8>, HostLoadError> {
        panic!("未預期的 stdin 呼叫")
    }
}

#[test]
fn p13_f_short_path_reader_is_metered_and_unclaimed_capacity_is_denied() {
    let calls = Rc::new(Cell::new(0));
    let allocations = Rc::new(Cell::new(0));
    let compiler_calls = Rc::new(Cell::new(0));
    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: 24,
        claim: 8,
        ignore_budget_error: false,
        capacity: 8,
        source: b"return 1",
    };
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(reader)
            .and_compiler(TestLoadCompiler {
                calls: compiler_calls.clone(),
                names: None,
            }),
    );
    let (_, outcome) = run_with_load(b"return loadfile('a')()", services);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    assert_eq!(calls.get(), 1);
    assert_eq!(allocations.get(), 1);
    assert_eq!(compiler_calls.get(), 1);

    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: 1,
        claim: 1,
        ignore_budget_error: false,
        capacity: 32,
        source: b"return 1",
    };
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(reader));
    let (_, outcome) = run_with_load(b"return loadfile('a')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("未申報 capacity 應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    assert_eq!(calls.get(), 2);
    assert_eq!(allocations.get(), 2);
}

#[test]
fn p13_f_reader_budget_stops_before_host_allocation_and_cannot_be_swallowed() {
    let (_, language, runtime_profile) = profile();
    let calls = Rc::new(Cell::new(0));
    let allocations = Rc::new(Cell::new(0));
    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: 99_999,
        claim: 8,
        ignore_budget_error: false,
        capacity: 8,
        source: b"return 1",
    };
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(reader));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let env = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return loadfile('a')", language),
            Value::Object(env),
        )
        .unwrap();
    execution.set_fuel(2_000).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(execution);
    assert_eq!(calls.get(), 1);
    assert_eq!(allocations.get(), 0);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: 1,
        claim: 1_000_000,
        ignore_budget_error: false,
        capacity: 8,
        source: b"return 1",
    };
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(reader));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let env = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    vm.set_allocation_limit(vm.ledger_snapshot().committed + 200_000);
    let mut execution = vm
        .load_with_environment(
            compile(b"return loadfile('a')", language),
            Value::Object(env),
        )
        .unwrap();
    let error = execution.run().unwrap_err();
    drop(execution);
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(allocations.get(), 0);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let limits = LoadLimits {
        max_work_units: 1,
        ..LoadLimits::default()
    };
    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: 1,
        claim: 8,
        ignore_budget_error: true,
        capacity: 8,
        source: b"return 1",
    };
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(reader)
            .with_limits(limits),
    );
    let (_, outcome) = run_with_load(b"return loadfile('a')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("吞掉 budget error 不可假成功: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    assert_eq!(calls.get(), 3);
}

struct DiagnosticReader {
    calls: Rc<Cell<usize>>,
    claim: usize,
    capacity: usize,
}

impl HostSourceReader for DiagnosticReader {
    fn read_path(
        &mut self,
        _path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        budget.claim_temporary(self.claim)?;
        let mut diagnostic = Vec::with_capacity(self.capacity);
        diagnostic.resize(self.capacity, b'x');
        Err(HostLoadError::new(
            HostLoadErrorKind::PolicyDenied,
            diagnostic,
        ))
    }

    fn read_stdin(&mut self, _budget: &mut LoadBudget) -> Result<Vec<u8>, HostLoadError> {
        panic!("未預期的 stdin 呼叫")
    }
}

#[test]
fn p13_f_reader_error_diagnostic_capacity_and_copy_lifetime_are_charged() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(
        DiagnosticReader {
            calls: calls.clone(),
            claim: 1,
            capacity: 64,
        },
    ));
    let (_, outcome) = run_with_load(b"return loadfile('a')", services);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("未申報診斷容量應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    assert_eq!(calls.get(), 1);

    let (_, language, runtime_profile) = profile();
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_reader(
        DiagnosticReader {
            calls: calls.clone(),
            claim: 64 * 1024,
            capacity: 64 * 1024,
        },
    ));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let env = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    vm.set_allocation_limit(vm.ledger_snapshot().committed + 96 * 1024);
    let mut execution = vm
        .load_with_environment(
            compile(b"return loadfile('a')", language),
            Value::Object(env),
        )
        .unwrap();
    let error = execution.run().unwrap_err();
    drop(execution);
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    assert_eq!(calls.get(), 2);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_file_reader_skips_bom_and_shebang_before_compiling_text() {
    let calls = Rc::new(Cell::new(0));
    let allocations = Rc::new(Cell::new(0));
    let source = b"\xef\xbb\xbf#!/usr/bin/env rivet\nreturn 7";
    let reader = ProbeSourceReader {
        calls: calls.clone(),
        allocations: allocations.clone(),
        work: source.len(),
        claim: source.len(),
        ignore_budget_error: false,
        capacity: source.len(),
        source,
    };
    let compiler_calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(reader)
            .and_compiler(TestLoadCompiler {
                calls: compiler_calls.clone(),
                names: None,
            }),
    );
    let (_, outcome) = run_with_load(b"return loadfile('a')()", services);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
    assert_eq!(calls.get(), 1);
    assert_eq!(compiler_calls.get(), 1);
}

struct OwnedSourceReader {
    data: Vec<u8>,
    calls: Rc<Cell<usize>>,
}

impl HostSourceReader for OwnedSourceReader {
    fn read_path(
        &mut self,
        _path: &[u8],
        budget: &mut LoadBudget,
    ) -> Result<Vec<u8>, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        budget.spend_work(self.data.len())?;
        budget.claim_temporary(self.data.len())?;
        Ok(self.data.clone())
    }

    fn read_stdin(&mut self, _budget: &mut LoadBudget) -> Result<Vec<u8>, HostLoadError> {
        panic!("未預期的 stdin 呼叫")
    }
}

#[test]
fn p13_f_file_reader_bom_shebang_binary_uses_encoded_limit() {
    let (_, language, runtime_profile) = profile();
    let chunk = lex(b"return 14", language, &CompileLimits::default()).unwrap();
    let parsed = parse(&chunk, language, &CompileLimits::default()).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &CompileLimits::default()).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
    let mut data = b"\xef\xbb\xbf#!/usr/bin/env rivet\n".to_vec();
    data.extend_from_slice(encoded.bytes());
    let calls = Rc::new(Cell::new(0));
    let limits = LoadLimits {
        max_source_bytes: 8,
        max_encoded_bytes: data.len(),
        ..LoadLimits::default()
    };
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(OwnedSourceReader {
                data,
                calls: calls.clone(),
            })
            .with_bytecode(true)
            .with_limits(limits),
    );
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return loadfile('a','b')()", language),
            Value::Object(environment),
        )
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(14)])
    );
    drop(execution);
    assert_eq!(calls.get(), 1);
    vm.remove_root(root).unwrap();
}

#[test]
fn p13_f_deterministic_compiler_loads_in_same_execution_and_explicit_env() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (vm, outcome) = run_with_load(
        b"x=11; local f=load('return x'); local g=load('return x',nil,'t',{x=23}); return f(),g()",
        services,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(11), Value::Integer(23)])
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_text_identifier_rvl_prefix_is_not_binary() {
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let (_, outcome) = run_with_load(
        b"local a=load('RVL=7; return RVL',nil,'t'); local b=load('RVLU=8; return RVLU',nil,'bt'); local c=load('RVLU\\n=9; return RVLU',nil,'t'); local d=load('RVLU\\t=10; return RVLU',nil,'t'); return a(),b(),c(),d()",
        services,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(7),
            Value::Integer(8),
            Value::Integer(9),
            Value::Integer(10)
        ])
    );
    assert_eq!(calls.get(), 4);
}

#[test]
fn p13_f_encoded_limit_is_independent_of_text_source_limit() {
    let (_, language, runtime_profile) = profile();
    let chunk = lex(b"return 5", language, &CompileLimits::default()).unwrap();
    let parsed = parse(&chunk, language, &CompileLimits::default()).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &CompileLimits::default()).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
    assert!(encoded.bytes().len() > 8);
    let limits = LoadLimits {
        max_source_bytes: 8,
        max_encoded_bytes: encoded.bytes().len() + 8,
        ..LoadLimits::default()
    };
    let mut vm = Vm::new_with_services(
        runtime_profile,
        HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .with_bytecode(true)
                .with_limits(limits),
        ),
    )
    .unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let chunk_key = vm.allocate_byte_string(b"chunk").unwrap();
    let chunk_value = vm.allocate_byte_string(encoded.bytes()).unwrap();
    vm.raw_set(
        environment,
        Value::Object(chunk_key),
        Value::Object(chunk_value),
    )
    .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return load(chunk,nil,'b')()", language),
            Value::Object(environment),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(5)]));
    vm.remove_root(root).unwrap();
}

#[test]
fn p13_f_raw_rvlu_shared_preflight_loads() {
    let (_, language, runtime_profile) = profile();
    let chunk = lex(b"return 42", language, &CompileLimits::default()).unwrap();
    let parsed = parse(&chunk, language, &CompileLimits::default()).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &CompileLimits::default()).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
    let services =
        HostServices::deny_all().and_load(LoadCapability::deny_all().with_bytecode(true));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"chunk").unwrap();
    let value = vm.allocate_byte_string(encoded.bytes()).unwrap();
    vm.raw_set(environment, Value::Object(key), Value::Object(value))
        .unwrap();
    let runner = compile(
        b"local f,e=load(chunk,nil,'b'); if not f then return e end; return f()",
        language,
    );
    let mut execution = vm
        .load_with_environment(runner, Value::Object(environment))
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(42)]));
    vm.remove_root(root).unwrap();
}

#[test]
fn p13_f_bytecode_rejects_v1_unknown_profile_and_invalid_payload() {
    let (_, language, runtime_profile) = profile();
    let chunk = lex(b"return 5", language, &CompileLimits::default()).unwrap();
    let parsed = parse(&chunk, language, &CompileLimits::default()).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &CompileLimits::default()).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
    let mut v1 = encoded.bytes().to_vec();
    v1[4..6].copy_from_slice(&1_u16.to_le_bytes());
    let mut unknown = encoded.bytes().to_vec();
    unknown[4..6].copy_from_slice(&99_u16.to_le_bytes());
    let mut wrong_profile = encoded.bytes().to_vec();
    wrong_profile[6] ^= 1;
    let invalid = encoded.bytes()[..8].to_vec();
    for (case, source, mode) in [
        ("v1", v1, b"b".as_slice()),
        ("unknown", unknown, b"b"),
        ("profile", wrong_profile, b"b"),
        ("invalid", invalid, b"b"),
        ("text mode", encoded.bytes().to_vec(), b"t"),
    ] {
        let mut vm = Vm::new_with_services(
            runtime_profile,
            HostServices::deny_all().and_load(LoadCapability::deny_all().with_bytecode(true)),
        )
        .unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let key = vm.allocate_byte_string(b"chunk").unwrap();
        let value = vm.allocate_byte_string(&source).unwrap();
        vm.raw_set(environment, Value::Object(key), Value::Object(value))
            .unwrap();
        let mode_key = vm.allocate_byte_string(b"mode").unwrap();
        let mode_value = vm.allocate_byte_string(mode).unwrap();
        vm.raw_set(
            environment,
            Value::Object(mode_key),
            Value::Object(mode_value),
        )
        .unwrap();
        let mut execution = vm
            .load_with_environment(
                compile(b"return load(chunk,nil,mode)", language),
                Value::Object(environment),
            )
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        let RunOutcome::Returned(values) = outcome else {
            panic!("{case} 應以 nil+diagnostic 拒絕: {outcome:?}")
        };
        assert_eq!(values[0], Value::Nil, "{case}");
        assert!(!bytes(&vm, values[1]).is_empty(), "{case}");
        vm.remove_root(root).unwrap();
    }

    let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"chunk").unwrap();
    let value = vm.allocate_byte_string(encoded.bytes()).unwrap();
    vm.raw_set(environment, Value::Object(key), Value::Object(value))
        .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return load(chunk,nil,'b')", language),
            Value::Object(environment),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("未授權 bytecode 應有 policy error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);
    vm.remove_root(root).unwrap();
}

#[test]
fn p13_f_official_bytecode_requires_separate_capability_and_executes_both_profiles() {
    for (language, runtime_profile, source) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
    ] {
        for (authorized, expected) in [(false, None), (true, Some(vec![Value::Integer(41)]))] {
            let capability = LoadCapability::deny_all()
                .with_bytecode(!authorized)
                .with_official_bytecode(authorized);
            let mut vm = Vm::new_with_services(
                runtime_profile,
                HostServices::deny_all().and_load(capability),
            )
            .unwrap();
            let environment = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            let key = vm.allocate_byte_string(b"chunk").unwrap();
            let bytes = vm.allocate_byte_string(source).unwrap();
            vm.raw_set(environment, Value::Object(key), Value::Object(bytes))
                .unwrap();
            let mut execution = vm
                .load_with_environment(
                    compile(b"return load(chunk,nil,'b')()", language),
                    Value::Object(environment),
                )
                .unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            match expected {
                Some(values) => assert_eq!(outcome, RunOutcome::Returned(values)),
                None => match outcome {
                    RunOutcome::LuaError(error) => {
                        assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad)
                    }
                    other => panic!("應拒絕未授權官方 chunk：{other:?}"),
                },
            }
            vm.remove_root(root).unwrap();
        }
    }
}

#[test]
fn p13_f_official_load_checks_mode_profile_and_full_preflight_budget() {
    for (language, profile, own, other, list) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
        ),
    ] {
        let run = |chunk: &[u8], mode: &[u8], max_work_units: usize, call: bool| {
            let mut vm = Vm::new_with_services(
                profile,
                HostServices::deny_all().and_load(
                    LoadCapability::deny_all()
                        .with_official_bytecode(true)
                        .with_limits(LoadLimits {
                            max_work_units,
                            ..LoadLimits::default()
                        }),
                ),
            )
            .unwrap();
            let environment = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            let key = vm.allocate_byte_string(b"chunk").unwrap();
            let source = vm.allocate_byte_string(chunk).unwrap();
            vm.raw_set(environment, Value::Object(key), Value::Object(source))
                .unwrap();
            let key = vm.allocate_byte_string(b"mode").unwrap();
            let mode = vm.allocate_byte_string(mode).unwrap();
            vm.raw_set(environment, Value::Object(key), Value::Object(mode))
                .unwrap();
            let script = if call {
                b"return load(chunk,nil,mode)()".as_slice()
            } else {
                b"return load(chunk,nil,mode)".as_slice()
            };
            let mut execution = vm
                .load_with_environment(compile(script, language), Value::Object(environment))
                .unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            vm.remove_root(root).unwrap();
            outcome
        };

        for (chunk, mode) in [(own, b"t".as_slice()), (other, b"b".as_slice())] {
            let RunOutcome::Returned(values) = run(chunk, mode, 1, false) else {
                panic!("模式／版本應早於預掃描 work 拒絕：{profile:?}")
            };
            assert_eq!(values[0], Value::Nil);
            assert!(matches!(values[1], Value::Object(_)));
        }
        let truncated = &own[..own.len() - 1];
        assert_eq!(
            preflight_official_chunk(
                truncated,
                profile,
                &OfficialChunkLimits::default(),
                &VerifyLimits::default(),
            )
            .unwrap_err()
            .kind,
            OfficialChunkErrorKind::Truncated,
        );
        let RunOutcome::Returned(values) = run(truncated, b"b", 10_000, false) else {
            panic!("格式截斷應回傳 nil+diagnostic：{profile:?}")
        };
        assert_eq!(values[0], Value::Nil);
        assert!(matches!(values[1], Value::Object(_)));
        for chunk in [own, list] {
            let stats = preflight_official_chunk(
                chunk,
                profile,
                &OfficialChunkLimits::default(),
                &VerifyLimits::default(),
            )
            .unwrap();
            let total = chunk.len() * 2 + 1 + stats.subsequent_work as usize;
            let RunOutcome::LuaError(error) = run(chunk, b"b", total - 1, false) else {
                panic!("預掃描總工作 one-below 應拒絕：{profile:?}")
            };
            assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
            let expected = if chunk == own {
                vec![Value::Integer(41)]
            } else {
                vec![
                    Value::Integer(22),
                    Value::Integer(44),
                    Value::Integer(55),
                    Value::Integer(66),
                    Value::Integer(0),
                    Value::Integer(11),
                    Value::Integer(33),
                ]
            };
            assert_eq!(
                run(chunk, b"b", total, true),
                RunOutcome::Returned(expected)
            );
        }
    }
}

fn run_official_load_in_same_vm(
    vm: &mut Vm,
    language: LanguageProfile,
    environment: ObjectRef,
    fuel: Option<u64>,
) -> (Result<RunOutcome, RuntimeError>, u64) {
    let roots = vm.roots().total_count();
    let mut roots_before = Vec::new();
    vm.visit_roots(|kind, id, object| roots_before.push((kind, id, object)));
    let reserved = vm.ledger_snapshot().reserved;
    let mut execution = vm
        .load_with_environment(
            compile(b"return load(chunk,nil,'b')", language),
            Value::Object(environment),
        )
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run();
    let remaining = execution.fuel_remaining();
    drop(execution);
    let mut roots_after = Vec::new();
    vm.visit_roots(|kind, id, object| roots_after.push((kind, id, object)));
    if let Ok(RunOutcome::LuaError(error)) = &outcome {
        let extra: Vec<_> = roots_after
            .iter()
            .filter(|entry| !roots_before.contains(entry))
            .collect();
        assert_eq!(extra.len(), 1, "{roots_before:?} → {roots_after:?}");
        assert_eq!(extra[0].0, RootKind::Host);
        assert_eq!(error.value, Value::Object(extra[0].2));
        assert_eq!(vm.object_kind(extra[0].2), Ok(ObjectKind::ByteString));
        assert_eq!(vm.roots().total_count(), roots + 1);
    } else {
        assert_eq!(roots_after, roots_before, "{outcome:?}");
    }
    assert_eq!(vm.ledger_snapshot().reserved, reserved);
    (outcome, remaining)
}

fn official_load_vm(
    profile: LuaProfile,
    chunk: &[u8],
    limits: LoadLimits,
) -> (Vm, ObjectRef, RootId) {
    let mut vm = Vm::new_with_services(
        profile,
        HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(limits),
        ),
    )
    .unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"chunk").unwrap();
    let value = vm.allocate_byte_string(chunk).unwrap();
    vm.raw_set(environment, Value::Object(key), Value::Object(value))
        .unwrap();
    (vm, environment, root)
}

#[test]
fn p13_f_official_temporary_and_retained_exact_one_below_retry_in_same_vm() {
    for (language, profile, list, small) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
    ] {
        let list_stats = preflight_official_chunk(
            list,
            profile,
            &OfficialChunkLimits::default(),
            &VerifyLimits::default(),
        )
        .unwrap();
        let small_stats = preflight_official_chunk(
            small,
            profile,
            &OfficialChunkLimits::default(),
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(small_stats.temporary_bytes < list_stats.temporary_bytes);
        assert!(small_stats.retained_bytes < list_stats.retained_bytes);

        for (temporary, exact) in [(true, false), (true, true), (false, false), (false, true)] {
            let limits = LoadLimits {
                max_work_units: 200_000,
                max_temporary_bytes: if temporary {
                    list_stats.temporary_bytes - usize::from(!exact)
                } else {
                    LoadLimits::default().max_temporary_bytes
                },
                max_module_allocation_bytes: if temporary {
                    LoadLimits::default().max_module_allocation_bytes
                } else {
                    list_stats.retained_bytes - usize::from(!exact)
                },
                ..LoadLimits::default()
            };
            let (mut vm, environment, root) = official_load_vm(profile, list, limits);
            let (outcome, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
            if exact {
                let RunOutcome::Returned(values) = outcome.unwrap() else {
                    panic!("exact 額度應載入成功：{profile:?}, temporary={temporary}")
                };
                assert!(matches!(values.as_slice(), [Value::Object(_)]));
            } else {
                let RunOutcome::LuaError(error) = outcome.unwrap() else {
                    panic!("one-below 額度應由 Lua error 呈現：{profile:?}")
                };
                assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
                drop(error);
                assert_eq!(vm.roots().total_count(), 1);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                let key = vm.allocate_byte_string(b"chunk").unwrap();
                let value = vm.allocate_byte_string(small).unwrap();
                vm.raw_set(environment, Value::Object(key), Value::Object(value))
                    .unwrap();
                let (retry, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
                assert!(
                    matches!(retry.unwrap(), RunOutcome::Returned(values) if matches!(values.as_slice(), [Value::Object(_)]))
                );
            }
            vm.remove_root(root).unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn p13_f_official_public_fuel_abort_leaves_same_vm_retryable() {
    for (language, profile, list) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
        ),
    ] {
        let stats = preflight_official_chunk(
            list,
            profile,
            &OfficialChunkLimits::default(),
            &VerifyLimits::default(),
        )
        .unwrap();
        let prescan = (list.len() * 2 + 1) as u64;
        let (mut vm, environment, root) = official_load_vm(
            profile,
            list,
            LoadLimits {
                max_work_units: 200_000,
                ..LoadLimits::default()
            },
        );
        let full_fuel = 1_000_000;
        let (calibration, remaining) =
            run_official_load_in_same_vm(&mut vm, language, environment, Some(full_fuel));
        assert!(matches!(calibration.unwrap(), RunOutcome::Returned(_)));
        let wrapper_work = full_fuel - remaining - prescan - stats.subsequent_work;
        assert!(stats.subsequent_work > wrapper_work + 1);
        vm.collect().unwrap();

        // 完整成功路徑的非官方預付成本包含輸入複製與回傳；以其作上界，
        // 確保本次通過 wrapper 和 prescan，於 subsequent 預付處耗盡 fuel。
        let fuel = wrapper_work + prescan + 1;
        let (outcome, remaining) =
            run_official_load_in_same_vm(&mut vm, language, environment, Some(fuel));
        assert_eq!(
            outcome.unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted)
        );
        assert_eq!(remaining, 0);
        assert_eq!(vm.roots().total_count(), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let (retry, _) =
            run_official_load_in_same_vm(&mut vm, language, environment, Some(full_fuel));
        assert!(matches!(retry.unwrap(), RunOutcome::Returned(_)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_official_admission_and_closure_failure_refund_and_retry() {
    for (language, profile, small) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
    ] {
        let stats = preflight_official_chunk(
            small,
            profile,
            &OfficialChunkLimits::default(),
            &VerifyLimits::default(),
        )
        .unwrap();
        let (mut vm, environment, root) = official_load_vm(profile, small, LoadLimits::default());
        let admission = stats.temporary_bytes + stats.retained_bytes;
        vm.set_allocation_limit(vm.ledger_snapshot().committed + admission - 1);
        let (outcome, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
        assert_eq!(
            outcome.unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::AllocationFailed)
        );
        let admission_failure = vm.allocation_trace().last_failure.unwrap();
        assert_eq!(admission_failure.kind, AllocationFailureKind::Budget);
        assert_eq!(admission_failure.attempt.bytes, admission);
        vm.set_allocation_limit(usize::MAX);
        let (retry, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
        assert!(matches!(retry.unwrap(), RunOutcome::Returned(_)));
        vm.collect().unwrap();

        vm.inject_failure_once(FailPoint::ClosureCapturesReserve);
        let (outcome, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
        assert_eq!(
            outcome.unwrap_err().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::ClosureCapturesReserve))
        );
        let closure_failure = vm.allocation_trace().last_failure.unwrap();
        assert_eq!(closure_failure.kind, AllocationFailureKind::Injection);
        assert_eq!(
            closure_failure.attempt.point,
            Some(FailPoint::ClosureCapturesReserve)
        );
        let (retry, _) = run_official_load_in_same_vm(&mut vm, language, environment, None);
        assert!(matches!(retry.unwrap(), RunOutcome::Returned(_)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_binary_decode_requires_full_work_admission() {
    let (_, language, runtime_profile) = profile();
    let chunk = lex(b"return 5", language, &CompileLimits::default()).unwrap();
    let parsed = parse(&chunk, language, &CompileLimits::default()).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &CompileLimits::default()).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
    let limits = LoadLimits {
        max_work_units: 1,
        ..LoadLimits::default()
    };
    let mut vm = Vm::new_with_services(
        runtime_profile,
        HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .with_bytecode(true)
                .with_limits(limits),
        ),
    )
    .unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"chunk").unwrap();
    let chunk_value = vm.allocate_byte_string(encoded.bytes()).unwrap();
    vm.raw_set(environment, Value::Object(key), Value::Object(chunk_value))
        .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return load(chunk,nil,'b')", language),
            Value::Object(environment),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("不足 decode work 應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostLoadBudget);
    vm.remove_root(root).unwrap();
}

#[test]
fn p13_f_explicit_empty_chunkname_reaches_compiler() {
    let calls = Rc::new(Cell::new(0));
    let names = Rc::new(RefCell::new(Vec::new()));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: Some(names.clone()),
        },
    ));
    let (_, outcome) = run_with_load(b"return load('return 1','')()", services);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    assert_eq!(calls.get(), 1);
    assert_eq!(&*names.borrow(), &[Vec::<u8>::new()]);
}

#[test]
fn p13_f_mode_scan_exhausts_fuel_before_host_compile() {
    let (_, language, runtime_profile) = profile();
    let calls = Rc::new(Cell::new(0));
    let services = HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(
        TestLoadCompiler {
            calls: calls.clone(),
            names: None,
        },
    ));
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"m").unwrap();
    let value = vm.allocate_byte_string(&vec![b't'; 500]).unwrap();
    vm.raw_set(environment, Value::Object(key), Value::Object(value))
        .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return load('return 1',nil,m)", language),
            Value::Object(environment),
        )
        .unwrap();
    execution.set_fuel(500).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(calls.get(), 0);
    vm.remove_root(root).unwrap();
}

fn run_with_table(source: &[u8], fuel: Option<u64>, collect: bool) -> (Vm, RunOutcome, ObjectRef) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_table_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(environment_root).unwrap();
    (vm, outcome, environment)
}

fn run_with_string(source: &[u8], fuel: Option<u64>, collect: bool) -> (Vm, RunOutcome, ObjectRef) {
    run_with_string_services(source, HostServices::deny_all(), fuel, collect)
}

fn run_with_string_services(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
    collect: bool,
) -> (Vm, RunOutcome, ObjectRef) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(environment_root).unwrap();
    (vm, outcome, environment)
}

fn run_with_math(
    source: &[u8],
    services: HostServices,
    fuel: Option<u64>,
    collect: bool,
) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_math_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(environment_root).unwrap();
    (vm, outcome)
}

fn run_with_utf8(source: &[u8], fuel: Option<u64>, collect: bool) -> (Vm, RunOutcome) {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_utf8_builtins(environment).unwrap();
    vm.set_collect_every_allocation(collect);
    let mut execution = vm
        .load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap();
    if let Some(fuel) = fuel {
        execution.set_fuel(fuel).unwrap();
    }
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(environment_root).unwrap();
    (vm, outcome)
}

#[test]
fn p13_e_utf8_entrypoints_use_byte_positions_and_pattern() {
    let (vm, outcome) = run_with_utf8(
        b"return utf8.len('a'),utf8.codepoint('a'),utf8.char(65),utf8.charpattern",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("utf8 入口應回值: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(1));
    assert_eq!(values[1], Value::Integer(97));
    assert_eq!(bytes(&vm, values[2]), b"A");
    assert_eq!(bytes(&vm, values[3]), b"[\0-\x7f\xc2-\xfd][\x80-\xbf]*");
}

#[test]
fn p13_e_utf8_offsets_codes_and_identity_use_lua_byte_positions() {
    let (_, outcome) = run_with_utf8(
        b"local s=utf8.char(65,0,0x1f34e,66); local it,source,zero=utf8.codes(s); local it2=utf8.codes(s); local lax=utf8.codes(s,true); local p1,c1=it(source,zero); local p2,c2=it(source,p1); local p3,c3=it(source,p2); local p4,c4=it(source,p3); return #s,utf8.len(s),utf8.codepoint(s,3,6),p1,c1,p2,c2,p3,c3,p4,c4,select('#',it(source,p4)),it==it2,it~=lax,source==s,zero,utf8.offset(s,3),select('#',utf8.offset(s,3)),utf8.offset(s,5),utf8.offset(s,-1),utf8.offset(s,0,5)",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("utf8 byte position/codes: {outcome:?}")
    };
    assert_eq!(
        &values[..16],
        &[
            Value::Integer(7),
            Value::Integer(4),
            Value::Integer(0x1f34e),
            Value::Integer(1),
            Value::Integer(65),
            Value::Integer(2),
            Value::Integer(0),
            Value::Integer(3),
            Value::Integer(0x1f34e),
            Value::Integer(7),
            Value::Integer(66),
            Value::Integer(0),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(0),
        ]
    );
    assert_eq!(values[16], Value::Integer(3));
    assert_eq!(
        values[17],
        Value::Integer(if profile().2 == LuaProfile::Lua55 {
            2
        } else {
            1
        })
    );
    assert_eq!(values[18], Value::Integer(8));
    assert_eq!(values[19], Value::Integer(7));
    assert_eq!(values[20], Value::Integer(3));
    if profile().2 == LuaProfile::Lua55 {
        assert_eq!(values.len(), 22);
        assert_eq!(values[21], Value::Integer(6));
    } else {
        assert_eq!(values.len(), 21);
    }
}

#[test]
fn p13_e_utf8_strict_lax_extended_and_malformed_sequences() {
    let (vm, outcome) = run_with_utf8(
        b"local surrogate=utf8.char(0xd800); local high=utf8.char(0x110000); local extended=utf8.char(0x7fffffff); local n1,p1=utf8.len(surrogate); local n2,p2=utf8.len(high); local n3,p3=utf8.len(extended); local it,s=utf8.codes(extended,true); local ip,ic=it(s,0); return n1,p1,n2,p2,n3,p3,utf8.len(surrogate,1,-1,true),utf8.len(high,1,-1,true),utf8.len(extended,1,-1,true),utf8.codepoint(surrogate,1,1,true),utf8.codepoint(high,1,1,true),utf8.codepoint(extended,1,1,true),ip,ic,surrogate,high,extended",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("utf8 strict/lax: {outcome:?}")
    };
    assert_eq!(
        &values[..14],
        &[
            Value::Nil,
            Value::Integer(1),
            Value::Nil,
            Value::Integer(1),
            Value::Nil,
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(0xd800),
            Value::Integer(0x110000),
            Value::Integer(0x7fffffff),
            Value::Integer(1),
            Value::Integer(0x7fffffff),
        ]
    );
    assert_eq!(bytes(&vm, values[14]), &[0xed, 0xa0, 0x80]);
    assert_eq!(bytes(&vm, values[15]), &[0xf4, 0x90, 0x80, 0x80]);
    assert_eq!(
        bytes(&vm, values[16]),
        &[0xfd, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf]
    );

    let (vm, outcome) = run_with_utf8(
        b"local five=utf8.char(0x200000); local n,p=utf8.len(five); local apple=utf8.char(0xe9,0x1f34e); return five,n,p,utf8.len(five,1,-1,true),utf8.codepoint(five,1,1,true),#apple,utf8.len(apple)",
        None, false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("5-byte/lax 與蘋果: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), &[0xf8, 0x88, 0x80, 0x80, 0x80]);
    assert_eq!(
        &values[1..],
        &[
            Value::Nil,
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(0x200000),
            Value::Integer(6),
            Value::Integer(2),
        ]
    );

    for source in [
        b"local s=string.char(0x80); return utf8.len(s,1,-1,true)".as_slice(),
        b"local s=string.char(0xc0,0x80); return utf8.len(s,1,-1,true)".as_slice(),
        b"local s=string.char(0xe2,0x28,0xa1); return utf8.len(s,1,-1,true)".as_slice(),
        b"local s=string.char(0xc2); return utf8.len(s,1,-1,true)".as_slice(),
        b"local s=string.char(0xfe); return utf8.len(s,1,-1,true)".as_slice(),
    ] {
        let (_, outcome) = run_with_utf8(source, None, true);
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Nil, Value::Integer(1)]),
            "{source:?}"
        );
    }
    let (_, outcome) = run_with_utf8(
        b"local s='a'..string.char(0x80); return utf8.len(s)",
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Nil, Value::Integer(2)])
    );
    for source in [
        b"return utf8.codepoint(string.char(0xc0,0x80),1,1,true)".as_slice(),
        b"return utf8.codepoint(utf8.char(0xd800))".as_slice(),
        b"return utf8.codepoint(utf8.char(0x110000))".as_slice(),
        b"return utf8.char(-1)".as_slice(),
        b"return utf8.char(0x80000000)".as_slice(),
    ] {
        let (_, outcome) = run_with_utf8(source, None, false);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("utf8 invalid 應報錯 {source:?}: {outcome:?}")
        };
        assert!(matches!(
            error.kind,
            RuntimeErrorKind::Utf8Sequence | RuntimeErrorKind::Utf8Argument
        ));
    }
}

#[test]
fn p13_e_utf8_index_extremes_and_profile_offset_arity() {
    let (_, outcome) = run_with_utf8(
        b"return utf8.len('',1,-1),utf8.len('abc',4,3),select('#',utf8.codepoint('abc',4,0)),select('#',utf8.codepoint('abc',9223372036854775807,0)),select('#',utf8.codepoint('abc',4,3)),utf8.offset('abc',4),select('#',utf8.offset('abc',4)),utf8.offset('abc',5),select('#',utf8.offset('abc',5)),utf8.offset('abc',-1),utf8.offset('abc',-4),utf8.offset(string.char(0xff),1)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("utf8 邊界索引: {outcome:?}")
    };
    assert_eq!(
        &values[..6],
        &[
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(4),
        ]
    );
    assert_eq!(
        values[6],
        Value::Integer(if profile().2 == LuaProfile::Lua55 {
            2
        } else {
            1
        })
    );
    let mut suffix = vec![
        Value::Nil,
        Value::Integer(1),
        Value::Integer(3),
        Value::Nil,
        Value::Integer(1),
    ];
    if profile().2 == LuaProfile::Lua55 {
        suffix.push(Value::Integer(1));
    }
    assert_eq!(&values[7..], suffix);

    for source in [
        b"return utf8.len('abc',0)".as_slice(),
        b"return utf8.len('abc',5)".as_slice(),
        b"return utf8.len('abc',-9223372036854775807-1)".as_slice(),
        b"return utf8.codepoint('abc',0,0)".as_slice(),
        b"return utf8.codepoint('abc',1,4)".as_slice(),
        b"return utf8.offset('abc',1,0)".as_slice(),
        b"return utf8.offset('abc',1,-9223372036854775807-1)".as_slice(),
    ] {
        let (_, outcome) = run_with_utf8(source, None, false);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("utf8 index 應拒絕 {source:?}: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Utf8Argument);
    }
    let (_, outcome) = run_with_utf8(b"return utf8.offset(string.char(0x80),0,1)", None, false);
    if profile().2 == LuaProfile::Lua55 {
        let RunOutcome::LuaError(error) = outcome else {
            panic!("Lua55 n=0 leading continuation 應報錯: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::Utf8Sequence);
    } else {
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    }
}

#[test]
fn p13_e_utf8_codes_uses_supplied_source_control_and_rejects_extra_continuation() {
    let (vm, outcome) = run_with_utf8(
        b"local it,s,zero=utf8.codes('A'); local p1,c1=it('B',zero); local p2,c2=it('B',1.5); local p3,c3=it('B','oops'); local p4,c4=it('B',nil); local numeric,ns,nz=utf8.codes(123); local np,nc=numeric(ns,nz); return p1,c1,p2,c2,p3,c3,p4,c4,select('#',it('B',-1)),select('#',it('B',1)),type(ns),ns,np,nc",
        None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("codes supplied source/control: {outcome:?}")
    };
    assert_eq!(
        &values[..10],
        &[
            Value::Integer(1),
            Value::Integer(66),
            Value::Integer(1),
            Value::Integer(66),
            Value::Integer(1),
            Value::Integer(66),
            Value::Integer(1),
            Value::Integer(66),
            Value::Integer(0),
            Value::Integer(0),
        ]
    );
    assert_eq!(bytes(&vm, values[10]), b"string");
    assert_eq!(bytes(&vm, values[11]), b"123");
    assert_eq!(values[12], Value::Integer(1));
    assert_eq!(values[13], Value::Integer(49));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (_, outcome) = run_with_utf8(
        b"local it,s=utf8.codes('A'..string.char(0x80)); return it(s,0)",
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("多餘 continuation 應先報錯: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::Utf8Sequence);
    let (_, outcome) = run_with_utf8(b"return utf8.codes(string.char(0x80))", None, false);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("首 byte continuation 應報錯: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::Utf8Sequence);
}

#[test]
fn p13_e_utf8_codes_generic_for_close_and_error_preserve_lua_boundary() {
    let (vm, outcome) = run_with_utf8(
        b"local closed=0; local seen=nil; local closer=setmetatable({},{__close=function(_,e) closed=closed+1; seen=e end}); local it,s,c=utf8.codes('AB'); local sum=0; for p,v in it,s,c,closer do sum=sum+v end; return sum,closed,seen==nil",
        None, true,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(131),
            Value::Integer(1),
            Value::Boolean(true)
        ])
    );
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome) = run_with_utf8(
        b"local closed=0; local closer=setmetatable({},{__close=function() closed=closed+1 end}); local it,s,c=utf8.codes('AB'); for p,v in it,s,c,closer do break end; return closed",
        None, true,
    );
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome) = run_with_utf8(
        b"local closed=0; local seen=nil; local closer=setmetatable({},{__close=function(_,e) closed=closed+1; seen=e end}); local it,s,c=utf8.codes('A'..string.char(0x80)); local ok,e=pcall(function() for p,v in it,s,c,closer do end end); return ok,closed,seen==e,type(e)",
        None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("codes error/close: {outcome:?}")
    };
    assert_eq!(
        &values[..3],
        &[
            Value::Boolean(false),
            Value::Integer(1),
            Value::Boolean(true)
        ]
    );
    assert_eq!(bytes(&vm, values[3]), b"string");
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_e_utf8_codes_coroutine_yield_gc_and_native_entry() {
    let (vm, outcome) = run_with_utf8(
        b"local co=coroutine.create(function() local sum=0; for p,v in utf8.codes(utf8.char(65,0x1f34e,66)) do if p==1 then coroutine.yield('pause') end; sum=sum+v end; return sum end); local a,x=coroutine.resume(co); for i=1,40 do local garbage={i} end; local b,y=coroutine.resume(co); return a,x,b,y",
        None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("codes coroutine yield: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(127_953));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome) = run_with_utf8(
        b"local it,s,c=utf8.codes('A'); local co=coroutine.create(it); return coroutine.resume(co,s,c)",
        None, true,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(1),
            Value::Integer(65)
        ])
    );
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_e_utf8_fuel_counts_decode_encode_and_iteration() {
    let minimum = |source: &[u8]| {
        (0..128)
            .find(|fuel| {
                let (_, outcome) = run_with_utf8(source, Some(*fuel), false);
                matches!(outcome, RunOutcome::Returned(_))
            })
            .expect("128 fuel 內應完成小 utf8 工作")
    };
    assert_eq!(
        minimum(b"return utf8.char(0x7fffffff)"),
        minimum(b"return utf8.char(65)") + 10
    );
    assert_eq!(
        minimum(b"return utf8.len('AAAAAAAAAAAA')"),
        minimum(b"return utf8.len('A')") + 11
    );

    let mut source = b"local s='".to_vec();
    source.extend(core::iter::repeat_n(b'A', 512));
    source.extend_from_slice(
        b"'; local sum=0; for p,c in utf8.codes(s) do sum=sum+c end; return sum",
    );
    let (vm, outcome) = run_with_utf8(&source, Some(100), true);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let mut source = b"return utf8.codepoint('".to_vec();
    source.extend(core::iter::repeat_n(b'A', 1024));
    source.extend_from_slice(b"',1,1024)");
    let (vm, outcome) = run_with_utf8(&source, Some(100), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_e_utf8_codepoint_return_failpoint_cleans_state_and_retries() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_utf8_builtins(environment).unwrap();
    vm.set_collect_every_allocation(true);
    let module = compile(b"return utf8.codepoint('AB',1,2)", language);
    vm.inject_failure_once(FailPoint::ReturnReserve);
    let mut execution = vm
        .load_with_environment(module.clone(), Value::Object(environment))
        .unwrap();
    let outcome = execution.run();
    drop(execution);
    let Err(error) = outcome else {
        panic!("codepoint 回傳配置點應失敗: {outcome:?}")
    };
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::ReturnReserve))
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut retry = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    assert_eq!(
        retry.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(65), Value::Integer(66)])
    );
    drop(retry);
    vm.remove_root(root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_e_utf8_numeric_codes_result_failpoint_releases_temporary_roots() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_utf8_builtins(environment).unwrap();
    vm.set_collect_every_allocation(true);
    let module = compile(b"return utf8.codes(123)", language);
    vm.inject_failure_once(FailPoint::ReturnReserve);
    let mut execution = vm
        .load_with_environment(module.clone(), Value::Object(environment))
        .unwrap();
    let outcome = execution.run();
    drop(execution);
    let Err(error) = outcome else {
        panic!("numeric codes 回傳配置點應失敗: {outcome:?}")
    };
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::ReturnReserve))
    );
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.collect().unwrap();
    let mut retry = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    let outcome = retry.run().unwrap();
    drop(retry);
    let RunOutcome::Returned(values) = outcome else {
        panic!("numeric codes retry: {outcome:?}")
    };
    assert_eq!(values.len(), 3);
    assert_eq!(bytes(&vm, values[1]), b"123");
    assert_eq!(values[2], Value::Integer(0));
    let Value::Object(source) = values[1] else {
        panic!("numeric codes source")
    };
    vm.remove_root(root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(source), Err(VmError::StaleObject));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_math_numeric_entrypoints_return_lua_values() {
    let (_, outcome) = run_with_math(
        b"return math.abs(-3),math.floor(2.9),math.max(1,3,2)",
        HostServices::deny_all(),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(2),
            Value::Integer(3)
        ])
    );
}

#[test]
fn p13_d_math_integer_float_identity_and_constants() {
    let (vm, outcome) = run_with_math(
        b"local a,b=math.modf(-3.25); local c,d=math.modf(math.huge); local e,f=math.modf(math.mininteger); return math.abs(math.mininteger),math.abs('-9223372036854775808'),math.floor('9223372036854775807'),math.floor(math.maxinteger),math.ceil(-3.2),math.fmod(math.mininteger,-1),math.fmod('3','2'),a,b,c,d,e,f,math.tointeger('9223372036854775807'),math.type('2'),math.type(2.0),math.pi,math.huge,math.mininteger,math.maxinteger",
        HostServices::deny_all(),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("math 數值應返回：{outcome:?}")
    };
    assert_eq!(values.len(), 20);
    assert_eq!(values[0], Value::Integer(i64::MIN));
    assert_eq!(values[1], Value::Float(9_223_372_036_854_775_808.0));
    assert_eq!(values[2], Value::Float(9_223_372_036_854_775_808.0));
    assert_eq!(values[3], Value::Integer(i64::MAX));
    assert_eq!(values[4], Value::Integer(-3));
    assert_eq!(values[5], Value::Integer(0));
    assert_eq!(values[6], Value::Float(1.0));
    assert_eq!(values[7], Value::Integer(-3));
    assert_eq!(values[8], Value::Float(-0.25));
    assert_eq!(values[9], Value::Float(f64::INFINITY));
    assert_eq!(values[10], Value::Float(0.0));
    assert_eq!(values[11], Value::Integer(i64::MIN));
    assert_eq!(values[12], Value::Float(0.0));
    assert_eq!(values[13], Value::Integer(i64::MAX));
    assert_eq!(values[14], Value::Nil);
    assert_eq!(bytes(&vm, values[15]), b"float");
    assert_eq!(values[16], Value::Float(core::f64::consts::PI));
    assert_eq!(values[17], Value::Float(f64::INFINITY));
    assert_eq!(values[18], Value::Integer(i64::MIN));
    assert_eq!(values[19], Value::Integer(i64::MAX));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_math_scalar_functions_and_profile_extensions() {
    let (vm, outcome) = run_with_math(
        b"return math.acos(1),math.asin(0),math.atan(0),math.cos(0),math.deg(math.pi),math.exp(0),math.log(1),math.log(8,2),math.rad(180),math.sin(0),math.sqrt(9),math.tan(0),math.ult(-1,0),math.frexp,math.ldexp",
        HostServices::deny_all(),
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("math scalar 應返回：{outcome:?}")
    };
    assert_eq!(values.len(), 15);
    for index in [0, 1, 2, 9, 11] {
        assert_eq!(values[index], Value::Float(0.0));
    }
    for index in [3, 5] {
        assert_eq!(values[index], Value::Float(1.0));
    }
    assert_eq!(values[6], Value::Float(0.0));
    assert_eq!(values[7], Value::Float(3.0));
    assert_eq!(values[10], Value::Float(3.0));
    assert_eq!(values[12], Value::Boolean(false));
    let Value::Float(degrees) = values[4] else {
        panic!("deg 應是 float")
    };
    let Value::Float(radians) = values[8] else {
        panic!("rad 應是 float")
    };
    assert!((degrees - 180.0).abs() < 1e-12);
    assert!((radians - core::f64::consts::PI).abs() < 1e-12);
    match profile().2 {
        LuaProfile::Lua55 => {
            assert!(matches!(values[13], Value::Object(_)));
            assert!(matches!(values[14], Value::Object(_)));
            let (_, outcome) = run_with_math(
                b"local a,b=math.frexp(math.ldexp(1,-1074)); return a,b,math.ldexp(a,b),math.ldexp(-0.0,-1075),math.ldexp(1,-1075)",
                HostServices::deny_all(),
                None,
                true,
            );
            let RunOutcome::Returned(edge) = outcome else {
                panic!("frexp/ldexp 應返回：{outcome:?}")
            };
            assert_eq!(edge[0], Value::Float(0.5));
            assert_eq!(edge[1], Value::Integer(-1073));
            assert_eq!(edge[2], Value::Float(f64::from_bits(1)));
            let Value::Float(negative_zero) = edge[3] else {
                panic!("ldexp 應是 float")
            };
            assert_eq!(negative_zero.to_bits(), (-0.0_f64).to_bits());
            assert_eq!(edge[4], Value::Float(0.0));
        }
        LuaProfile::Lua54 => {
            assert_eq!(values[13], Value::Nil);
            assert_eq!(values[14], Value::Nil);
        }
    }
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_math_minmax_preserve_values_and_nan_order() {
    let (vm, outcome) = run_with_math(
        b"local nan=0/0; local a=math.min('b','a'); local b=math.max('a','b'); local x=math.min(nan,1); local y=math.min(1,nan); local mt={__lt=function(a,b) return a.n<b.n end}; local p=setmetatable({n=2},mt); local q=setmetatable({n=1},mt); local r=math.min(p,q,p); local s=math.max(q,p,q); return math.min(9007199254740993,9007199254740992),math.max(9007199254740992,9007199254740993),math.min(1.0,1),math.max(1,1.0),a,b,x~=x,y,r==q,s==p",
        HostServices::deny_all(),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("math min/max 應返回：{outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(9_007_199_254_740_992));
    assert_eq!(values[1], Value::Integer(9_007_199_254_740_993));
    assert_eq!(values[2], Value::Float(1.0));
    assert_eq!(values[3], Value::Integer(1));
    assert_eq!(bytes(&vm, values[4]), b"a");
    assert_eq!(bytes(&vm, values[5]), b"b");
    assert_eq!(values[6], Value::Boolean(true));
    assert_eq!(values[7], Value::Integer(1));
    assert_eq!(values[8], Value::Boolean(true));
    assert_eq!(values[9], Value::Boolean(true));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_random_explicit_seed_is_reproducible() {
    let (vm, outcome) = run_with_math(
        b"local a,b=math.randomseed(123,456); local x=math.random(); local y=math.random(0); local z=math.random(1,10); math.randomseed(123,456); return a,b,x,y,z,math.random(),math.random(0),math.random(1,10)",
        HostServices::deny_all(),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("explicit seed 應可重現：{outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(123));
    assert_eq!(values[1], Value::Integer(456));
    let Value::Float(sample) = values[2] else {
        panic!("random() 應回 float")
    };
    assert!((0.0..1.0).contains(&sample));
    assert!(matches!(values[3], Value::Integer(_)));
    let Value::Integer(range) = values[4] else {
        panic!("random(a,b) 應回 integer")
    };
    assert!((1..=10).contains(&range));
    assert_eq!(values[2], values[5]);
    assert_eq!(values[3], values[6]);
    assert_eq!(values[4], values[7]);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[derive(Clone)]
struct EntropyProbe {
    calls: Rc<RefCell<usize>>,
    seed: Result<u64, HostEntropyError>,
}

impl HostEntropy for EntropyProbe {
    fn seed(&mut self) -> Result<u64, HostEntropyError> {
        *self.calls.borrow_mut() += 1;
        self.seed
    }
}

#[test]
fn p13_d_random_matches_official_xoshiro_stream_and_rejection() {
    let (_, outcome) = run_with_math(
        b"math.randomseed(123,456); return math.random(),math.random(0),math.random(1,10),math.random(math.mininteger,math.maxinteger),math.random(1)",
        HostServices::deny_all(), None, false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("random golden stream: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Float(f64::from_bits(0x3fe30534d59c7f72)),
            Value::Integer(-4_076_395_480_158_212_337),
            Value::Integer(3),
            Value::Integer(1_704_599_587_560_253_662),
            Value::Integer(1),
        ]
    );
    let (_, outcome) = run_with_math(
        b"math.randomseed(123,456); local a=math.random(1,10); return a,math.random(0)",
        HostServices::deny_all(),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(-7_518_772_449_294_522_146)
        ])
    );
}

#[test]
fn p13_d_random_entropy_is_lazy_explicit_and_vm_local() {
    let calls = Rc::new(RefCell::new(0));
    let service = || {
        HostServices::with_entropy(EntropyProbe {
            calls: calls.clone(),
            seed: Ok(77),
        })
    };
    let (_, outcome) = run_with_math(
        b"math.randomseed(123,456); return math.random(0)",
        service(),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(-7_482_266_044_409_867_603)])
    );
    assert_eq!(*calls.borrow(), 0);

    let (_, outcome) = run_with_math(b"return math.randomseed()", service(), None, false);
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(77), Value::Integer(0)])
    );
    assert_eq!(*calls.borrow(), 1);

    let (_, outcome) = run_with_math(
        b"math.randomseed(123,456); local a,b=math.randomseed(); local x=math.random(0); math.randomseed(a,b); return a,b,x,math.random(0)",
        service(), None, false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("noarg seed 應可重播: {outcome:?}")
    };
    assert_eq!(
        &values[..2],
        &[
            Value::Integer(77),
            Value::Integer(-7_482_266_044_409_867_603)
        ]
    );
    assert_eq!(values[2], values[3]);
    assert_eq!(*calls.borrow(), 2);

    let (_, first) = run_with_math(
        b"math.randomseed(1,2); return math.random(0)",
        service(),
        None,
        false,
    );
    let (_, second) = run_with_math(
        b"math.randomseed(3,4); return math.random(0)",
        service(),
        None,
        false,
    );
    assert_ne!(first, second);
    assert_eq!(*calls.borrow(), 2);

    let (_, outcome) = run_with_math(
        b"return math.random(0),math.random(0)",
        service(),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(-1_246_570_784_467_252_051),
            Value::Integer(7_124_718_699_654_277_936)
        ])
    );
    assert_eq!(*calls.borrow(), 3);

    let written = Rc::new(RefCell::new(Vec::new()));
    let (_, outcome) = run_with_math(
        b"print('ready'); return math.randomseed()",
        HostServices::with_output(TestOutput(written.clone(), false)).and_entropy(EntropyProbe {
            calls: calls.clone(),
            seed: Ok(77),
        }),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(77), Value::Integer(0)])
    );
    assert_eq!(&*written.borrow(), b"ready\n");
    assert_eq!(*calls.borrow(), 4);
}

#[test]
fn p13_d_random_interleaved_vms_and_math_reinstall_keep_separate_streams() {
    let (_, language, runtime_profile) = profile();
    let calls = Rc::new(RefCell::new(0));
    let make_vm = || {
        let mut vm = Vm::new_with_services(
            runtime_profile,
            HostServices::with_entropy(EntropyProbe {
                calls: calls.clone(),
                seed: Ok(99),
            }),
        )
        .unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_math_builtins(environment).unwrap();
        (vm, environment, root)
    };
    let (mut first, first_env, first_root) = make_vm();
    let (mut second, second_env, second_root) = make_vm();
    assert_eq!(*calls.borrow(), 0);
    let run = |vm: &mut Vm, environment: ObjectRef, source: &[u8]| {
        let mut execution = vm
            .load_with_environment(compile(source, language), Value::Object(environment))
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        outcome
    };
    assert_eq!(
        run(&mut first, first_env, b"return math.randomseed(1,2)"),
        RunOutcome::Returned(vec![Value::Integer(1), Value::Integer(2)])
    );
    assert_eq!(
        run(&mut second, second_env, b"return math.randomseed(3,4)"),
        RunOutcome::Returned(vec![Value::Integer(3), Value::Integer(4)])
    );
    assert_eq!(
        run(&mut first, first_env, b"return math.random(0)"),
        RunOutcome::Returned(vec![Value::Integer(8_291_693_048_688_576_641)])
    );
    assert_eq!(
        run(&mut second, second_env, b"return math.random(0)"),
        RunOutcome::Returned(vec![Value::Integer(-8_904_508_047_278_803_908)])
    );
    first.install_math_builtins(first_env).unwrap();
    assert_eq!(*calls.borrow(), 0);
    assert_eq!(
        run(&mut first, first_env, b"return math.random(0)"),
        RunOutcome::Returned(vec![Value::Integer(4_164_699_302_279_098_248)])
    );
    assert_eq!(
        run(&mut second, second_env, b"return math.random(0)"),
        RunOutcome::Returned(vec![Value::Integer(2_924_459_486_855_298_593)])
    );
    first.remove_root(first_root).unwrap();
    second.remove_root(second_root).unwrap();
    assert_eq!(first.roots().total_count(), 0);
    assert_eq!(second.roots().total_count(), 0);
    assert_eq!(first.ledger_snapshot().reserved, 0);
    assert_eq!(second.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_random_entropy_policy_failure_and_error_draw_are_distinct() {
    let (_, outcome) = run_with_math(
        b"return math.random()",
        HostServices::deny_all(),
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("缺 entropy 應回 policy error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyEntropy);
    assert_eq!(error.diagnostic_id, "E_HOST_POLICY_ENTROPY");

    let calls = Rc::new(RefCell::new(0));
    let (_, outcome) = run_with_math(
        b"return math.randomseed()",
        HostServices::with_entropy(EntropyProbe {
            calls: calls.clone(),
            seed: Err(HostEntropyError::ReadFailed),
        }),
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("entropy 失敗應保留種類: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostEntropyFailed);
    assert_eq!(error.diagnostic_id, "E_HOST_ENTROPY_FAILED");
    assert_eq!(*calls.borrow(), 1);

    let (_, outcome) = run_with_math(
        b"math.randomseed(123,456); local ok=pcall(math.random,1,0); return ok,math.random(0)",
        HostServices::deny_all(),
        None,
        false,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(false),
            Value::Integer(-4_076_395_480_158_212_337)
        ])
    );
}

#[test]
fn p13_d_math_argument_nan_and_range_errors_are_lua_errors() {
    for source in [
        b"return math.abs()".as_slice(),
        b"return math.min()".as_slice(),
        b"return math.max()".as_slice(),
        b"return math.type()".as_slice(),
        b"return math.tointeger()".as_slice(),
        b"return math.fmod(1,0)".as_slice(),
        b"math.randomseed(1); return math.random(1,0)".as_slice(),
        b"math.randomseed(1); return math.random(-1)".as_slice(),
        b"math.randomseed(1); return math.random(1,2,3)".as_slice(),
        b"math.randomseed(1); return math.random(1.5)".as_slice(),
        b"return math.randomseed(nil)".as_slice(),
    ] {
        let (vm, outcome) = run_with_math(source, HostServices::deny_all(), None, true);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("math 參數應為 LuaError {source:?}: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::MathArgument, "{source:?}");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    let (_, outcome) = run_with_math(
        b"local n=0/0; return math.type(n),math.tointeger(n),math.tointeger(math.huge),math.fmod(1.0,0.0)~=math.fmod(1.0,0.0),math.min(n,1)~=math.min(n,1)",
        HostServices::deny_all(), None, false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("NaN/inf 應受控返回: {outcome:?}")
    };
    assert_eq!(values[1], Value::Nil);
    assert_eq!(values[2], Value::Nil);
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(values[4], Value::Boolean(true));
}

#[test]
fn p13_d_math_minmax_callback_yield_gc_reentry_and_error_cleanup() {
    let (vm, outcome) = run_with_math(
        b"local paused=false; local mt={__lt=function(a,b) if not paused then paused=true; coroutine.yield('pause') end; return a.n<b.n and math.min(3,2,1)==1 end}; local a=setmetatable({n=3},mt); local b=setmetatable({n=2},mt); local c=setmetatable({n=1},mt); local co=coroutine.create(function() return math.min(a,b,c)==c end); local x,y=coroutine.resume(co); for i=1,12 do local garbage={i} end; local z,w=coroutine.resume(co); return x,y,z,w",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("min callback yield/reentry: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome) = run_with_math(
        b"local mt={__lt=function() error('lt failure') end}; local a=setmetatable({},mt); local b=setmetatable({},mt); local ok=pcall(math.max,a,b); return ok,math.min(2,1)",
        HostServices::deny_all(), None, true,
    );
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(1)])
    );
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome) = run_with_math(
        b"local mt={__lt=function() while true do end end}; local a=setmetatable({},mt); local b=setmetatable({},mt); return math.min(a,b)",
        HostServices::deny_all(), Some(200), true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_math_minmax_pending_alone_keeps_later_candidates_alive() {
    let (vm, outcome) = run_with_math(
        b"local paused=false; local mt={__lt=function(a,b) if not paused then paused=true; coroutine.yield('pause') end; return a.n<b.n end}; local co=coroutine.create(function() return math.min(setmetatable({n=3},mt),setmetatable({n=2},mt),setmetatable({n=1},mt)) end); local a,x=coroutine.resume(co); for i=1,40 do local garbage={i,i+1} end; local b,y=coroutine.resume(co); return a,x,b,y.n",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pending min/max 候選應存活: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(1));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_math_minmax_native_coroutine_entry_yields_with_gc() {
    let (vm, outcome) = run_with_math(
        b"local once=false; local mt={__lt=function(a,b) if not once then once=true; coroutine.yield('native') end; return a.n<b.n end}; local co=coroutine.create(math.min); local a,x=coroutine.resume(co,setmetatable({n=3},mt),setmetatable({n=2},mt),setmetatable({n=1},mt)); for i=1,40 do local garbage={i} end; local b,y=coroutine.resume(co); return a,x,b,y.n",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native math.min coroutine: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"native");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(1));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_d_random_fuel_charges_host_warmup_draw_and_rejection() {
    let calls = Rc::new(RefCell::new(0));
    let mut saw_pre_host_abort = false;
    let mut saw_after_host_abort = false;
    let mut saw_success = false;
    for fuel in 0..128 {
        *calls.borrow_mut() = 0;
        let (_, outcome) = run_with_math(
            b"return math.randomseed()",
            HostServices::with_entropy(EntropyProbe {
                calls: calls.clone(),
                seed: Ok(9),
            }),
            Some(fuel),
            false,
        );
        match outcome {
            RunOutcome::Aborted(AbortReason::FuelExhausted) => {
                if *calls.borrow() == 0 {
                    saw_pre_host_abort = true
                } else {
                    saw_after_host_abort = true
                }
            }
            RunOutcome::Returned(values) => {
                assert_eq!(values, vec![Value::Integer(9), Value::Integer(0)]);
                assert_eq!(*calls.borrow(), 1);
                saw_success = true;
                break;
            }
            other => panic!("entropy fuel outcome {fuel}: {other:?}"),
        }
    }
    assert!(saw_pre_host_abort && saw_after_host_abort && saw_success);

    let min_fuel = |upper: i64| {
        let source = format!("math.randomseed(123,456); return math.random(1,{upper})");
        (0..128)
            .find(|fuel| {
                let (_, outcome) = run_with_math(
                    source.as_bytes(),
                    HostServices::deny_all(),
                    Some(*fuel),
                    false,
                );
                matches!(outcome, RunOutcome::Returned(_))
            })
            .expect("128 fuel 內應返回")
    };
    assert_eq!(min_fuel(10), min_fuel(16) + 2);
}

#[test]
fn p13_d_random_return_allocation_failure_preserves_next_draw() {
    let (_, language, runtime_profile) = profile();
    let seed_module = compile(b"return math.randomseed(123,456)", language);
    let draw_module = compile(b"return math.random(0)", language);
    for offset in 0..32 {
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_math_builtins(environment).unwrap();
        let mut seed_execution = vm
            .load_with_environment(seed_module.clone(), Value::Object(environment))
            .unwrap();
        assert_eq!(
            seed_execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(123), Value::Integer(456)])
        );
        drop(seed_execution);
        let ordinal = vm.allocation_trace().next_ordinal + offset;
        vm.inject_allocation_failure_at(ordinal);
        let Ok(mut execution) =
            vm.load_with_environment(draw_module.clone(), Value::Object(environment))
        else {
            continue;
        };
        let outcome = execution.run();
        drop(execution);
        let Err(error) = outcome else { continue };
        let RuntimeErrorKind::Heap(VmError::InjectedAllocation(attempt)) = error.kind else {
            continue;
        };
        if !attempt.site.file.ends_with("stdlib/math.rs") {
            continue;
        }
        assert_eq!(attempt.ordinal, ordinal);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let mut retry = vm
            .load_with_environment(draw_module, Value::Object(environment))
            .unwrap();
        assert_eq!(
            retry.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(-4_076_395_480_158_212_337)])
        );
        drop(retry);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        return;
    }
    panic!("未命中 math 回傳配置點");
}

#[test]
fn p13_c_byte_string_functions_preserve_binary_values() {
    let (vm, outcome, _) = run_with_string(
        b"local s=string.char(0,255,65); local a,b,c=string.byte(s,1,3); return a,b,c,string.len(s),string.reverse(s)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("byte string 函式應返回值: {outcome:?}");
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Integer(0),
            Value::Integer(255),
            Value::Integer(65),
            Value::Integer(3)
        ]
    );
    let Value::Object(reversed) = values[4] else {
        panic!("reverse 應返回 bytes")
    };
    assert_eq!(
        vm.with_byte_string(reversed, |s| s.as_bytes().to_vec())
            .unwrap(),
        &[65, 255, 0]
    );
}

#[test]
fn p13_c_string_methods_sub_positions_and_case_are_bytes() {
    let (vm, outcome, _) = run_with_string(
        b"local s=string.char(0,65,255,66); return ('abc'):sub(2),string.sub('abc',2),string.sub(s,-2,-1),string.upper('abz'),string.lower('AZ'),string.rep('a',3,'!')",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("string methods 與 bytes 函式應完成: {outcome:?}");
    };
    for (index, expected) in [
        (0, b"bc".as_slice()),
        (1, b"bc".as_slice()),
        (2, &[255, 66][..]),
        (3, b"ABZ".as_slice()),
        (4, b"az".as_slice()),
        (5, b"a!a!a".as_slice()),
    ] {
        let Value::Object(object) = values[index] else {
            panic!("string result 應為 bytes")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn p13_c_format_integer_quote_and_binary_s() {
    let (vm, outcome, _) = run_with_string(
        b"return string.format('%05d,%x,%s',12,255,string.char(0,65)),string.format('%q',string.char(0,49))",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("format 應返回 bytes: {outcome:?}");
    };
    let Value::Object(formatted) = values[0] else {
        panic!("format 應為 string")
    };
    let Value::Object(quoted) = values[1] else {
        panic!("quote 應為 string")
    };
    assert_eq!(
        vm.with_byte_string(formatted, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"00012,ff,\0A"
    );
    assert_eq!(
        vm.with_byte_string(quoted, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"\"\\0001\""
    );
}

#[test]
fn p13_c_format_printf_numeric_edges_match_lua_rules() {
    let (vm, outcome, _) = run_with_string(
        b"return string.format('%.3g',12345),string.format('%#.3g',12.0),string.format('%.1e',1),string.format('%a',1.5),string.format('%a',0.0),string.format('%q',1.5),string.format('%#.4o',10),string.format('%.0d',0),string.format('%#08x',26)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("numeric format 應返回: {outcome:?}");
    };
    for (index, expected) in [
        (0, b"1.23e+04".as_slice()),
        (1, b"12.0".as_slice()),
        (2, b"1.0e+00".as_slice()),
        (3, b"0x1.8p+0".as_slice()),
        (4, b"0x0p+0".as_slice()),
        (5, b"0x1.8p+0".as_slice()),
        (6, b"0012".as_slice()),
        (7, b"".as_slice()),
        (8, b"0x00001a".as_slice()),
    ] {
        let Value::Object(object) = values[index] else {
            panic!("format 項目應為 string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec())
                .unwrap(),
            expected,
            "format 項目 {index}"
        );
    }
}

#[test]
fn p13_c_format_raw_s_accepts_nul_but_modified_s_rejects_it() {
    let (vm, outcome, _) = run_with_string(
        b"local s=string.rep(string.char(0),100); return string.format('%s',s)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("raw %s 應接受 NUL: {outcome:?}")
    };
    let Value::Object(object) = values[0] else {
        panic!("raw %s 應返回 string")
    };
    assert_eq!(
        vm.with_byte_string(object, |s| s.as_bytes().to_vec())
            .unwrap(),
        vec![0; 100]
    );
    let (_, outcome, _) = run_with_string(
        b"local s=string.rep(string.char(0),100); return string.format('%1s',s)",
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("modified %s 應受控拒絕 NUL: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::StringFormat);
}

#[test]
fn p13_c_string_metatable_tostring_numeric_result_flows_to_format_and_print() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome, _) = run_with_string_services(
        b"getmetatable('').__tostring=function() return 7 end; local a=tostring('abc'); local b=string.format('<%s>','abc'); print('abc'); return a,b",
        HostServices::with_output(TestOutput(sink.clone(), false)),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("string meta tostring 應繼續: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"7");
    assert_eq!(bytes(&vm, values[1]), b"<7>");
    assert_eq!(&*sink.borrow(), b"7\n");
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_format_modified_s_callback_scan_charges_fuel() {
    let mut source = b"local obj=setmetatable({},{__tostring=function() return '".to_vec();
    source.extend(core::iter::repeat_n(b'A', 1024));
    source.extend_from_slice(b"' end}); return string.format('%.0s',obj)");
    let (_, outcome, _) = run_with_string(&source, Some(300), true);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
}

#[test]
fn p13_c_format_s_callback_yield_gc_resume() {
    let (vm, outcome, _) = run_with_string(
        b"local t=setmetatable({},{__tostring=function() coroutine.yield('pause'); return 'resume' end}); local co=coroutine.create(function() return string.format('<%s>',t) end); local a,x=coroutine.resume(co); local b,y=coroutine.resume(co); return a,x,b,y",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("format callback 應 yield/resume: {outcome:?}");
    };
    assert_eq!(
        (values[0], values[2]),
        (Value::Boolean(true), Value::Boolean(true))
    );
    for (index, expected) in [(1, b"pause".as_slice()), (3, b"<resume>".as_slice())] {
        let Value::Object(object) = values[index] else {
            panic!("callback 結果應為 string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn p13_c_string_errors_and_dump_policy_are_structured() {
    for (source, expected) in [
        (
            b"return string.char(256)".as_slice(),
            RuntimeErrorKind::StringArgument,
        ),
        (
            b"return string.format('%999d',1)".as_slice(),
            RuntimeErrorKind::StringFormat,
        ),
        (
            b"return string.dump(function() end)".as_slice(),
            RuntimeErrorKind::HostPolicyStringDump,
        ),
    ] {
        let (vm, outcome, _) = run_with_string(source, None, true);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("應為結構化 string LuaError: {outcome:?}");
        };
        assert_eq!(error.kind, expected);
        assert_eq!(vm.roots().total_count(), 2);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_string_dump_native_child_strip_omits_captured_values() {
    let source = b"local function outer(x) return function() return x+1 end end; \
        local first,second=outer(41),outer(99); \
        return string.dump(first,true),string.dump(second,true),first(),second()";
    let (vm, outcome, _) = run_with_string_services(
        source,
        HostServices::deny_all().and_dump(DumpCapability::deny_all().with_official_bytecode(true)),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("應可輸出 native child prototype: {outcome:?}");
    };
    assert_eq!(values[2], Value::Integer(42));
    assert_eq!(values[3], Value::Integer(100));
    let Value::Object(bytes_ref) = values[0] else {
        panic!("應回傳 binary string")
    };
    let chunk_bytes = vm
        .with_byte_string(bytes_ref, |s| s.as_bytes().to_vec())
        .unwrap();
    assert_eq!(chunk_bytes, bytes(&vm, values[1]));
    let decoded = rivetlua_core::decode_official_chunk(
        &chunk_bytes,
        profile().2,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    assert!(decoded.main.debug.line_info.is_empty());
    assert!(decoded.main.debug.locals.is_empty());
    assert_eq!(decoded.main.children.len(), 0);
}

#[test]
fn p13_f_string_dump_budget_and_policy_are_independent_of_load() {
    let load = LoadCapability::deny_all().with_official_bytecode(true);
    let (vm, outcome, _) = run_with_string_services(
        b"local ok,err=pcall(string.dump,function() end); return ok,err",
        HostServices::deny_all().and_load(load),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("policy 應為 LuaError: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_STRING_DUMP");

    let limits = DumpLimits {
        max_work_units: 1,
        ..DumpLimits::default()
    };
    let (_, outcome, _) = run_with_string_services(
        b"return string.dump(function() end)",
        HostServices::deny_all().and_dump(
            DumpCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(limits),
        ),
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("work 上限應拒絕: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostDumpBudget);
}

#[test]
fn p13_f_string_dump_imported_strip_and_reload_both_profiles() {
    for (language, runtime_profile, source) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
    ] {
        let services = HostServices::deny_all()
            .and_load(LoadCapability::deny_all().with_official_bytecode(true))
            .and_dump(DumpCapability::deny_all().with_official_bytecode(true));
        let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        let key = vm.allocate_byte_string(b"chunk").unwrap();
        let value = vm.allocate_byte_string(source).unwrap();
        vm.raw_set(environment, Value::Object(key), Value::Object(value))
            .unwrap();
        let mut execution = vm
            .load_with_environment(
                compile(b"local f=assert(load(chunk,nil,'b')); local full=string.dump(f,false); \
                    local strip=string.dump(f,true); return full,strip,assert(load(strip,nil,'b'))()", language),
                Value::Object(environment),
            )
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        let RunOutcome::Returned(values) = outcome else {
            panic!("imported dump 失敗: {outcome:?}")
        };
        assert_eq!(values[2], Value::Integer(41));
        let full = bytes(&vm, values[0]);
        let stripped = bytes(&vm, values[1]);
        let full = rivetlua_core::decode_official_chunk(
            &full,
            runtime_profile,
            &OfficialChunkLimits::default(),
        )
        .unwrap();
        let stripped = rivetlua_core::decode_official_chunk(
            &stripped,
            runtime_profile,
            &OfficialChunkLimits::default(),
        )
        .unwrap();
        assert!(!full.main.debug.line_info.is_empty());
        assert!(stripped.main.debug.line_info.is_empty());
        assert!(stripped.main.debug.locals.is_empty());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
    }
}

#[test]
fn p13_f_string_dump_limits_fuel_and_same_vm_retry() {
    let (_, language, runtime_profile) = profile();
    let source = b"local ok,err=pcall(string.dump,function() return 42 end); return ok,err";
    let limits = DumpLimits {
        max_work_units: 40_000,
        max_temporary_bytes: 256 * 1024,
        max_encoded_bytes: 256 * 1024,
    };
    let mut vm = Vm::new_with_services(
        runtime_profile,
        HostServices::deny_all().and_dump(
            DumpCapability::deny_all()
                .with_official_bytecode(true)
                .with_limits(limits),
        ),
    )
    .unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    let run = |vm: &mut Vm, fuel: u64| {
        let mut execution = vm
            .load_with_environment(compile(source, language), Value::Object(environment))
            .unwrap();
        execution.set_fuel(fuel).unwrap();
        let result = execution.run().unwrap();
        let remaining = execution.fuel_remaining();
        drop(execution);
        (result, remaining)
    };
    let (aborted, fuel) = run(&mut vm, 100);
    assert_eq!(aborted, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(fuel, 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let (returned, _) = run(&mut vm, 300_000);
    let RunOutcome::Returned(values) = returned else {
        panic!("同 VM 重試應成功: {returned:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.remove_root(root).unwrap();

    for changed in [
        DumpLimits {
            max_work_units: 40_000,
            max_temporary_bytes: 1,
            max_encoded_bytes: 256 * 1024,
        },
        DumpLimits {
            max_work_units: 40_000,
            max_temporary_bytes: 256 * 1024,
            max_encoded_bytes: 32,
        },
    ] {
        let (vm, outcome, _) = run_with_string_services(
            source,
            HostServices::deny_all().and_dump(
                DumpCapability::deny_all()
                    .with_official_bytecode(true)
                    .with_limits(changed),
            ),
            Some(300_000),
            false,
        );
        let RunOutcome::Returned(values) = outcome else {
            panic!("limit 應由 pcall 捕捉: {outcome:?}")
        };
        assert_eq!(values[0], Value::Boolean(false));
        assert_eq!(bytes(&vm, values[1]), b"E_HOST_DUMP_BUDGET");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_f_host_call_uses_same_vm_frames_and_rejects_cross_vm_values() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let RunOutcome::Returned(values) = vm
        .load_with_environment(
            compile(b"return function(a,b) return a+b end", language),
            Value::Object(environment),
        )
        .unwrap()
        .run()
        .unwrap()
    else {
        panic!("應建立 host callable")
    };
    let Value::Object(function) = values[0] else {
        panic!("應回傳 closure")
    };
    let _handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, function).unwrap();
    let mut execution = vm
        .call(
            Value::Object(function),
            &[Value::Integer(20), Value::Integer(22)],
        )
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(42)])
    );
    drop(execution);

    let key = vm.allocate_byte_string(b"type").unwrap();
    let builtin = vm.raw_get(environment, Value::Object(key)).unwrap();
    let mut execution = vm.call(builtin, &[Value::Integer(1)]).unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("builtin 應成功")
    };
    drop(execution);
    assert_eq!(bytes(&vm, values[0]), b"number");

    let RunOutcome::Returned(values) = vm
        .load_with_environment(
            compile(b"return function(x) error(x) end", language),
            Value::Object(environment),
        )
        .unwrap()
        .run()
        .unwrap()
    else {
        panic!("應建立 error closure")
    };
    let Value::Object(thrower) = values[0] else {
        panic!("應回傳 closure")
    };
    let _thrower = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, thrower).unwrap();
    let mut execution = vm
        .call(Value::Object(thrower), &[Value::Integer(13)])
        .unwrap();
    let RunOutcome::LuaError(error) = execution.run().unwrap() else {
        panic!("錯誤應交宿主")
    };
    drop(execution);
    assert_eq!(error.value, Value::Integer(13));
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let pcall_key = vm.allocate_byte_string(b"pcall").unwrap();
    let pcall = vm.raw_get(environment, Value::Object(pcall_key)).unwrap();
    let mut execution = vm
        .call(pcall, &[Value::Object(thrower), Value::Integer(13)])
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(13)])
    );
    drop(execution);

    let roots = vm.roots().total_count();
    drop(
        vm.call(Value::Object(function), &[Value::Integer(1)])
            .unwrap(),
    );
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.inject_failure_once(FailPoint::RootReserve);
    assert_eq!(
        vm.call(
            Value::Object(function),
            &[Value::Integer(20), Value::Integer(22)]
        )
        .err()
        .unwrap()
        .kind,
        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve)),
    );
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut execution = vm
        .call(
            Value::Object(function),
            &[Value::Integer(20), Value::Integer(22)],
        )
        .unwrap();
    execution.set_fuel(0).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), roots);
    let mut execution = vm
        .call(
            Value::Object(function),
            &[Value::Integer(20), Value::Integer(22)],
        )
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(42)])
    );
    drop(execution);

    let mut other = Vm::new_with_profile(runtime_profile).unwrap();
    let foreign_argument = other.allocate_table().unwrap();
    assert_eq!(
        other.call(Value::Object(function), &[]).err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm),
    );
    assert_eq!(
        vm.call(Value::Object(function), &[Value::Object(foreign_argument)])
            .err()
            .unwrap()
            .kind,
        RuntimeErrorKind::Heap(VmError::WrongVm),
    );
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_explicit_capture_return_throw_and_gc() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let captured = vm.allocate_table().unwrap();
    let callback = vm
        .register_callback(
            &[Value::Object(captured)],
            Rc::new(|context, args| {
                CallbackResult::Return(vec![
                    context.capture(0).unwrap(),
                    args.first().copied().unwrap_or(Value::Nil),
                ])
            }),
        )
        .unwrap();
    let retained_callback = callback.try_clone(&mut vm).unwrap();
    drop(callback);
    let callback_key = vm.allocate_byte_string(b"host").unwrap();
    vm.raw_set(
        environment,
        Value::Object(callback_key),
        retained_callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    let thrower = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Throw(Value::Integer(13))),
        )
        .unwrap();
    let thrower_key = vm.allocate_byte_string(b"host_error").unwrap();
    vm.raw_set(
        environment,
        Value::Object(thrower_key),
        thrower.as_value(&vm).unwrap(),
    )
    .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
    let mut execution = vm
        .load_with_environment(
            compile(
                b"local a,b=host(7); local ok,e=pcall(host_error); return a,b,ok,e",
                language,
            ),
            Value::Object(environment),
        )
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Object(captured),
            Value::Integer(7),
            Value::Boolean(false),
            Value::Integer(13)
        ])
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(retained_callback);
    drop(thrower);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_failed_registration_reuse_and_gc() {
    let mut vm = Vm::new().unwrap();
    let captured = vm.allocate_table().unwrap();
    vm.inject_failure_once(FailPoint::ChildReserve);
    assert!(matches!(
        vm.register_callback(
            &[Value::Object(captured)],
            Rc::new(|_, _| CallbackResult::Return(vec![]))
        ),
        Err(VmError::InjectedFailure(FailPoint::ChildReserve))
    ));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let retry = vm
        .register_callback(
            &[Value::Object(captured)],
            Rc::new(|context, _| CallbackResult::Return(vec![context.capture(0).unwrap()])),
        )
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
    let target = retry.as_value(&vm).unwrap();
    let mut execution = vm.call(target, &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Object(captured)])
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(retry);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));

    vm.inject_failure_once(FailPoint::RootReserve);
    assert!(matches!(
        vm.register_callback(&[], Rc::new(|_, _| CallbackResult::Return(vec![]))),
        Err(VmError::InjectedFailure(FailPoint::RootReserve))
    ));
    let retry = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(9)])),
        )
        .unwrap();
    vm.collect().unwrap();
    let mut execution = vm.call(retry.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(9)])
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_host_callback_registry_growth_failure_keeps_ledger_and_allows_retry() {
    let mut vm = Vm::new().unwrap();
    let before = vm.ledger_snapshot();
    vm.set_allocation_limit(before.committed);
    assert_eq!(
        vm.register_callback(&[], Rc::new(|_, _| CallbackResult::Return(vec![])))
            .err(),
        Some(VmError::AllocationFailed)
    );
    assert_eq!(vm.ledger_snapshot().committed, before.committed);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    vm.set_allocation_limit(usize::MAX);
    let retry = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(17)])),
        )
        .unwrap();
    let mut execution = vm.call(retry.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(17)])
    );
    drop(execution);
    drop(retry);
    vm.collect().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let after_first_collection = vm.ledger_snapshot().committed;
    assert!(after_first_collection >= before.committed);
    let reused = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(18)])),
        )
        .unwrap();
    let mut execution = vm.call(reused.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(18)])
    );
    drop(execution);
    drop(reused);
    vm.collect().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    assert_eq!(vm.ledger_snapshot().committed, after_first_collection);
}

#[test]
fn p13_f_host_callback_call_continuation_receives_all_results_once() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let mut helper_execution = vm
        .load_with_environment(
            compile(b"return function(x) return x+1,x+2 end", language),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(helper_values) = helper_execution.run().unwrap() else {
        panic!("helper 應回傳 Lua closure");
    };
    drop(helper_execution);
    let helper = helper_values[0];
    let marker = Value::Object(vm.allocate_table().unwrap());
    let callback = vm
        .register_callback(
            &[helper, marker],
            Rc::new(|context, args| {
                let continuation = CallbackContinuation::new(
                    vec![context.capture(1).unwrap()],
                    Rc::new(|context, results| {
                        CallbackResult::Return(vec![
                            context.capture(0).unwrap(),
                            results[0],
                            results[1],
                        ])
                    }),
                );
                context.call(context.capture(0).unwrap(), args.to_vec(), continuation)
            }),
        )
        .unwrap();
    let key = vm.allocate_byte_string(b"host_call").unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    vm.collect().unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return host_call(5)", language),
            Value::Object(environment),
        )
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![marker, Value::Integer(6), Value::Integer(7)])
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_call_error_skips_continuation_and_cleans_pending() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let mut helper_execution = vm
        .load_with_environment(
            compile(b"return function() error(17) end", language),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(helper_values) = helper_execution.run().unwrap() else {
        panic!("helper 應回傳 Lua closure");
    };
    drop(helper_execution);
    let calls = Rc::new(Cell::new(0));
    let observed = Rc::clone(&calls);
    let callback = vm
        .register_callback(
            &[helper_values[0]],
            Rc::new(move |context, _| {
                let observed = Rc::clone(&observed);
                context.call(
                    context.capture(0).unwrap(),
                    vec![],
                    CallbackContinuation::new(
                        vec![],
                        Rc::new(move |_, _| {
                            observed.set(observed.get() + 1);
                            CallbackResult::Return(vec![Value::Integer(99)])
                        }),
                    ),
                )
            }),
        )
        .unwrap();
    let key = vm.allocate_byte_string(b"host_bad").unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"local ok,e=pcall(host_bad); return ok,e,42", language),
            Value::Object(environment),
        )
        .unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![
            Value::Boolean(false),
            Value::Integer(17),
            Value::Integer(42)
        ])
    );
    drop(execution);
    assert_eq!(calls.get(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_chains_use_dispatch_loop_and_fuel_abort() {
    let (_, language, runtime_profile) = profile();
    fn next_type_chain(remaining: Rc<Cell<usize>>, target: Value) -> CallbackContinuation {
        CallbackContinuation::new(
            vec![target],
            Rc::new(move |context, values| {
                let count = remaining.get();
                if count == 0 {
                    CallbackResult::Return(values.to_vec())
                } else {
                    remaining.set(count - 1);
                    let target = context.capture(0).unwrap();
                    context.call(
                        target,
                        vec![Value::Integer(1)],
                        next_type_chain(Rc::clone(&remaining), target),
                    )
                }
            }),
        )
    }
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"type").unwrap();
    let target = vm.raw_get(environment, Value::Object(key)).unwrap();
    let remaining = Rc::new(Cell::new(2_000));
    let chain_remaining = Rc::clone(&remaining);
    let callback = vm
        .register_callback(
            &[target],
            Rc::new(move |context, _| {
                let target = context.capture(0).unwrap();
                context.call(
                    target,
                    vec![Value::Integer(1)],
                    next_type_chain(Rc::clone(&chain_remaining), target),
                )
            }),
        )
        .unwrap();
    let callback_value = callback.as_value(&vm).unwrap();
    let mut execution = vm.call(callback_value, &[]).unwrap();
    execution.set_fuel(200_000).unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("immediate builtin continuation 長鏈應完成");
    };
    drop(execution);
    assert_eq!(remaining.get(), 0);
    assert_eq!(bytes(&vm, values[0]), b"number");
    remaining.set(100_000);
    let mut execution = vm.call(callback_value, &[]).unwrap();
    execution.set_fuel(100).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let callback_target = Rc::new(RefCell::new(Value::Nil));
    let callback_target_for_call = Rc::clone(&callback_target);
    let unwind_count = Rc::new(Cell::new(0));
    let unwind_count_for_call = Rc::clone(&unwind_count);
    let invocation_count = Rc::new(Cell::new(0));
    let invocation_count_for_call = Rc::clone(&invocation_count);
    let recursive = vm
        .register_callback(
            &[],
            Rc::new(move |_, args| {
                invocation_count_for_call.set(invocation_count_for_call.get() + 1);
                let n = match args.first().copied().unwrap_or(Value::Nil) {
                    Value::Integer(n) => n,
                    _ => 0,
                };
                if n == 0 {
                    CallbackResult::Return(vec![Value::Integer(0)])
                } else {
                    let unwind_count = Rc::clone(&unwind_count_for_call);
                    CallbackResult::Call {
                        target: *callback_target_for_call.borrow(),
                        args: vec![Value::Integer(n - 1)],
                        continuation: CallbackContinuation::new(
                            vec![],
                            Rc::new(move |_, values| {
                                unwind_count.set(unwind_count.get() + 1);
                                CallbackResult::Return(values.to_vec())
                            }),
                        ),
                    }
                }
            }),
        )
        .unwrap();
    let recursive_value = recursive.as_value(&vm).unwrap();
    *callback_target.borrow_mut() = recursive_value;
    let mut execution = vm
        .call(recursive_value, &[Value::Integer(100_000)])
        .unwrap();
    execution.set_fuel(80).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(execution);
    let mut execution = vm.call(recursive_value, &[Value::Integer(24)]).unwrap();
    execution.set_fuel(10_000).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(0)])
    );
    drop(execution);
    assert_eq!(unwind_count.get(), 24);
    let mut execution = vm.call(recursive_value, &[Value::Integer(33)]).unwrap();
    execution.set_fuel(10_000).unwrap();
    let RunOutcome::LuaError(error) = execution.run().unwrap() else {
        panic!("超過既有 basic pending 深度應為 StackLimit");
    };
    assert_eq!(error.kind, RuntimeErrorKind::StackLimit);
    drop(execution);
    assert_eq!(unwind_count.get(), 24);
    let mut execution = vm.call(recursive_value, &[Value::Integer(0)]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(0)])
    );
    drop(execution);
    let chain_key = vm.allocate_byte_string(b"chain").unwrap();
    vm.raw_set(environment, Value::Object(chain_key), recursive_value)
        .unwrap();
    let roots_before = vm.roots().total_count();
    let calls_before = invocation_count.get();
    let mut protected = vm
        .load_with_environment(
            compile(b"local ok,e=pcall(chain,100000); return ok,e", language),
            Value::Object(environment),
        )
        .unwrap();
    protected.set_fuel(80).unwrap();
    assert_eq!(
        protected.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(protected);
    assert!(invocation_count.get() > calls_before);
    assert_eq!(vm.roots().total_count(), roots_before);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut retry = vm
        .load_with_environment(
            compile(b"local ok,v=pcall(chain,0); return ok,v", language),
            Value::Object(environment),
        )
        .unwrap();
    assert_eq!(
        retry.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(0)])
    );
    drop(retry);
    let unwound_before_protected = unwind_count.get();
    let mut nested_retry = vm
        .load_with_environment(
            compile(b"local ok,v=pcall(chain,3); return ok,v", language),
            Value::Object(environment),
        )
        .unwrap();
    nested_retry.set_fuel(10_000).unwrap();
    assert_eq!(
        nested_retry.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(0)])
    );
    drop(nested_retry);
    assert_eq!(unwind_count.get(), unwound_before_protected + 3);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(recursive);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_resume_preserves_coroutine_contract() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(
                b"return coroutine.create(function(x) coroutine.yield(x+1); return x+2 end)",
                language,
            ),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("應建立 coroutine");
    };
    drop(execution);
    let callback = vm
        .register_callback(
            &[values[0]],
            Rc::new(|context, args| {
                context.resume(
                    context.capture(0).unwrap(),
                    args.to_vec(),
                    CallbackContinuation::new(
                        vec![],
                        Rc::new(|_, results| CallbackResult::Return(results.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    let target = callback.as_value(&vm).unwrap();
    let mut execution = vm.call(target, &[Value::Integer(10)]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(11)])
    );
    drop(execution);
    vm.collect().unwrap();
    let mut execution = vm.call(target, &[Value::Integer(99)]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(12)])
    );
    drop(execution);
    let mut execution = vm.call(target, &[]).unwrap();
    let RunOutcome::Returned(dead) = execution.run().unwrap() else {
        panic!("dead resume 應回傳 false/error")
    };
    drop(execution);
    assert_eq!(dead[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, dead[1]), b"cannot resume dead coroutine");
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_yield_continuation_survives_gc_and_invalid_site() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let marker = Value::Object(vm.allocate_table().unwrap());
    let resumed = Rc::new(Cell::new(0));
    let resumed_for_callback = Rc::clone(&resumed);
    let callback = vm
        .register_callback(
            &[marker],
            Rc::new(move |context, _| {
                let resumed = Rc::clone(&resumed_for_callback);
                context.yield_with(
                    vec![Value::Integer(7)],
                    CallbackContinuation::new(
                        vec![context.capture(0).unwrap()],
                        Rc::new(move |context, args| {
                            resumed.set(resumed.get() + 1);
                            CallbackResult::Return(vec![
                                context.capture(0).unwrap(),
                                args.first().copied().unwrap_or(Value::Nil),
                            ])
                        }),
                    ),
                )
            }),
        )
        .unwrap();
    let callback_value = callback.as_value(&vm).unwrap();
    let mut invalid = vm.call(callback_value, &[]).unwrap();
    let RunOutcome::LuaError(error) = invalid.run().unwrap() else {
        panic!("coroutine 外 Yield 應是 Lua error");
    };
    assert_eq!(error.kind, RuntimeErrorKind::CoroutineYield);
    drop(invalid);
    assert_eq!(resumed.get(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let key = vm.allocate_byte_string(b"host_yield").unwrap();
    vm.raw_set(environment, Value::Object(key), callback_value)
        .unwrap();
    let mut setup = vm.load_with_environment(
        compile(b"return coroutine.create(function() local a,b=host_yield(); return a,b end), function(co,...) return coroutine.resume(co,...) end", language),
        Value::Object(environment),
    ).unwrap();
    let RunOutcome::Returned(objects) = setup.run().unwrap() else {
        panic!("應建立 coroutine 與 resumer");
    };
    drop(setup);
    let Value::Object(coroutine) = objects[0] else {
        panic!("coroutine 應為物件")
    };
    let Value::Object(resumer) = objects[1] else {
        panic!("resumer 應為 closure")
    };
    let coroutine_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, coroutine).unwrap();
    let resumer_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, resumer).unwrap();
    let mut first = vm
        .call(Value::Object(resumer), &[Value::Object(coroutine)])
        .unwrap();
    assert_eq!(
        first.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
    );
    drop(first);
    assert_eq!(resumed.get(), 0);
    vm.collect().unwrap();
    let Value::Object(marker_object) = marker else {
        panic!("marker 應為 table")
    };
    assert_eq!(vm.object_kind(marker_object), Ok(ObjectKind::Table));
    let mut second = vm
        .call(
            Value::Object(resumer),
            &[Value::Object(coroutine), Value::Integer(42)],
        )
        .unwrap();
    assert_eq!(
        second.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), marker, Value::Integer(42)])
    );
    drop(second);
    assert_eq!(resumed.get(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(coroutine_handle);
    drop(resumer_handle);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_rejects_foreign_capture_return_throw_and_action() {
    let mut foreign = Vm::new().unwrap();
    let foreign_value = Value::Object(foreign.allocate_table().unwrap());
    let mut vm = Vm::new().unwrap();
    assert!(matches!(
        vm.register_callback(
            &[foreign_value],
            Rc::new(|_, _| CallbackResult::Return(vec![]))
        ),
        Err(VmError::WrongVm)
    ));
    let ret = vm
        .register_callback(
            &[],
            Rc::new(move |_, _| CallbackResult::Return(vec![foreign_value])),
        )
        .unwrap();
    let mut execution = vm.call(ret.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    drop(execution);
    let thrower = vm
        .register_callback(
            &[],
            Rc::new(move |_, _| CallbackResult::Throw(foreign_value)),
        )
        .unwrap();
    let mut execution = vm.call(thrower.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    drop(execution);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"type").unwrap();
    let target = vm.raw_get(environment, Value::Object(key)).unwrap();
    let continuation_capture = vm
        .register_callback(
            &[target],
            Rc::new(move |context, _| {
                context.call(
                    context.capture(0).unwrap(),
                    vec![Value::Integer(1)],
                    CallbackContinuation::new(
                        vec![foreign_value],
                        Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    let mut execution = vm
        .call(continuation_capture.as_value(&vm).unwrap(), &[])
        .unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    drop(execution);
    let action_args = vm
        .register_callback(
            &[target],
            Rc::new(move |context, _| {
                context.call(
                    context.capture(0).unwrap(),
                    vec![foreign_value],
                    CallbackContinuation::new(
                        vec![],
                        Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    let mut execution = vm.call(action_args.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    drop(execution);
    let retry = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(9)])),
        )
        .unwrap();
    let mut execution = vm.call(retry.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(9)])
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(ret);
    drop(thrower);
    drop(continuation_capture);
    drop(action_args);
    drop(retry);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_parked_continuation_is_only_marker_root() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let marker = vm.allocate_table().unwrap();
    let marker_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, marker).unwrap();
    let marker_slot = Rc::new(RefCell::new(Some(Value::Object(marker))));
    let marker_for_callback = Rc::clone(&marker_slot);
    let callback = vm
        .register_callback(
            &[],
            Rc::new(move |context, _| {
                let marker = marker_for_callback
                    .borrow()
                    .expect("首次 yield 前有 host 保護的 marker");
                context.yield_with(
                    vec![Value::Integer(7)],
                    CallbackContinuation::new(
                        vec![marker],
                        Rc::new(|context, args| {
                            CallbackResult::Return(vec![
                                context.capture(0).unwrap(),
                                args.first().copied().unwrap_or(Value::Nil),
                            ])
                        }),
                    ),
                )
            }),
        )
        .unwrap();
    let key = vm.allocate_byte_string(b"host_yield").unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    let mut setup = vm.load_with_environment(
        compile(b"return coroutine.create(function() return host_yield() end), function(co,...) return coroutine.resume(co,...) end", language),
        Value::Object(environment),
    ).unwrap();
    let RunOutcome::Returned(objects) = setup.run().unwrap() else {
        panic!("應建立 coroutine/resumer")
    };
    drop(setup);
    let Value::Object(co) = objects[0] else {
        panic!("應為 coroutine")
    };
    let Value::Object(resumer) = objects[1] else {
        panic!("應為 resumer")
    };
    let co_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, co).unwrap();
    let resumer_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, resumer).unwrap();
    let mut first = vm
        .call(Value::Object(resumer), &[Value::Object(co)])
        .unwrap();
    assert_eq!(
        first.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
    );
    drop(first);
    marker_slot.replace(None);
    drop(marker_handle);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(marker), Ok(ObjectKind::Table));
    let mut second = vm
        .call(
            Value::Object(resumer),
            &[Value::Object(co), Value::Integer(42)],
        )
        .unwrap();
    assert_eq!(
        second.run().unwrap(),
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Object(marker),
            Value::Integer(42)
        ])
    );
    drop(second);
    drop(co_handle);
    drop(resumer_handle);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(marker), Err(VmError::StaleObject));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_host_callback_unreachable_suspended_continuation_cycle_is_collected() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let co_slot = Rc::new(RefCell::new(None));
    let co_for_callback = Rc::clone(&co_slot);
    let callback = vm
        .register_callback(
            &[],
            Rc::new(move |context, _| {
                let co = co_for_callback
                    .borrow()
                    .expect("首次 yield 前有 host 保護的 coroutine");
                context.yield_with(
                    vec![Value::Integer(1)],
                    CallbackContinuation::new(
                        vec![co],
                        Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(2)])),
                    ),
                )
            }),
        )
        .unwrap();
    let key = vm.allocate_byte_string(b"host_cycle").unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    let mut setup = vm.load_with_environment(
        compile(b"return coroutine.create(function() return host_cycle() end), function(co) return coroutine.resume(co) end", language),
        Value::Object(environment),
    ).unwrap();
    let RunOutcome::Returned(objects) = setup.run().unwrap() else {
        panic!("應建立 coroutine/resumer")
    };
    drop(setup);
    let Value::Object(co) = objects[0] else {
        panic!("應為 coroutine")
    };
    let Value::Object(resumer) = objects[1] else {
        panic!("應為 resumer")
    };
    let co_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, co).unwrap();
    let resumer_handle = rivetlua_runtime::HostHandle::<Value>::new(&mut vm, resumer).unwrap();
    co_slot.replace(Some(Value::Object(co)));
    let mut first = vm
        .call(Value::Object(resumer), &[Value::Object(co)])
        .unwrap();
    assert_eq!(
        first.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(1)])
    );
    drop(first);
    co_slot.replace(None);
    drop(co_handle);
    drop(resumer_handle);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(co), Err(VmError::StaleObject));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_f_host_new_coroutine_and_resume_share_vm_state_and_reject_foreign_values() {
    let (_, language, runtime_profile) = profile();
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let mut setup = vm
        .load_with_environment(
            compile(
                b"return function(x) coroutine.yield(x+1); return x+2 end",
                language,
            ),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = setup.run().unwrap() else {
        panic!("應建立 closure")
    };
    drop(setup);
    let coroutine = vm.new_coroutine(values[0]).unwrap();
    let coroutine_value = coroutine.as_value(&vm).unwrap();
    vm.inject_failure_once(FailPoint::RootReserve);
    assert_eq!(
        vm.resume(coroutine_value, &[]).err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve))
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut exhausted = vm.resume(coroutine_value, &[Value::Integer(10)]).unwrap();
    exhausted.set_fuel(0).unwrap();
    assert_eq!(
        exhausted.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(exhausted);
    let mut first = vm.resume(coroutine_value, &[Value::Integer(10)]).unwrap();
    assert_eq!(
        first.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(11)])
    );
    drop(first);
    vm.collect().unwrap();
    let mut second = vm.resume(coroutine_value, &[Value::Integer(99)]).unwrap();
    assert_eq!(
        second.run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(12)])
    );
    drop(second);
    let mut foreign = Vm::new().unwrap();
    let foreign_value = Value::Object(foreign.allocate_table().unwrap());
    assert_eq!(
        vm.new_coroutine(foreign_value).err(),
        Some(VmError::WrongVm)
    );
    assert_eq!(
        vm.resume(foreign_value, &[]).err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    assert_eq!(
        vm.resume(coroutine_value, &[foreign_value])
            .err()
            .unwrap()
            .kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(coroutine);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_return_and_continuation_budget_fail_then_retry() {
    let mut vm = Vm::new().unwrap();
    let large_return = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(1); 4_096])),
        )
        .unwrap();
    let target = large_return.as_value(&vm).unwrap();
    let probe = vm.ledger_probe();
    let constructed = {
        let _execution = vm.call(target, &[]).unwrap();
        probe.snapshot().committed
    };
    vm.set_allocation_limit(constructed + 8_192);
    let mut execution = vm.call(target, &[]).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.set_allocation_limit(usize::MAX);

    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let key = vm.allocate_byte_string(b"type").unwrap();
    let type_target = vm.raw_get(environment, Value::Object(key)).unwrap();
    let large_capture = vm
        .register_callback(
            &[type_target],
            Rc::new(|context, _| {
                context.call(
                    context.capture(0).unwrap(),
                    vec![Value::Integer(1)],
                    CallbackContinuation::new(
                        vec![Value::Integer(7); 4_096],
                        Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    let target = large_capture.as_value(&vm).unwrap();
    let constructed = {
        let _execution = vm.call(target, &[]).unwrap();
        probe.snapshot().committed
    };
    vm.set_allocation_limit(constructed + 8_192);
    let mut execution = vm.call(target, &[]).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.set_allocation_limit(usize::MAX);
    let retry = vm
        .register_callback(
            &[],
            Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(9)])),
        )
        .unwrap();
    let mut execution = vm.call(retry.as_value(&vm).unwrap(), &[]).unwrap();
    assert_eq!(
        execution.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(9)])
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(retry);
    drop(large_return);
    drop(large_capture);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_f_host_callback_yield_rejects_foreign_values_and_recovers() {
    let (_, language, runtime_profile) = profile();
    let mut foreign = Vm::new().unwrap();
    let foreign_value = Value::Object(foreign.allocate_table().unwrap());
    let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let callback = vm
        .register_callback(
            &[],
            Rc::new(move |context, _| {
                context.yield_with(
                    vec![foreign_value],
                    CallbackContinuation::new(
                        vec![],
                        Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    let key = vm.allocate_byte_string(b"host_foreign_yield").unwrap();
    vm.raw_set(
        environment,
        Value::Object(key),
        callback.as_value(&vm).unwrap(),
    )
    .unwrap();
    let mut execution = vm.load_with_environment(
        compile(b"return coroutine.resume(coroutine.create(function() return host_foreign_yield() end))", language),
        Value::Object(environment),
    ).unwrap();
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::WrongVm)
    );
    drop(execution);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut retry = vm
        .load_with_environment(compile(b"return 9", language), Value::Object(environment))
        .unwrap();
    assert_eq!(
        retry.run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(9)])
    );
    drop(retry);
    drop(callback);
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p13_c_rep_profile_size_preflight_precedes_large_allocation() {
    let (vm, outcome, _) = run_with_string(
        b"return string.rep('a',1073741824,'!')",
        Some(10_000),
        false,
    );
    match profile().2 {
        LuaProfile::Lua54 => {
            let RunOutcome::LuaError(error) = outcome else {
                panic!("Lua54 應以 MAXSIZE 拒絕: {outcome:?}");
            };
            assert_eq!(error.kind, RuntimeErrorKind::StringArgument);
        }
        LuaProfile::Lua55 => {
            assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
        }
    }
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    assert!(vm.ledger_snapshot().committed < 1_000_000);
}

#[test]
fn p13_c_numeric_string_argument_charges_fuel_before_parse() {
    let mut source = b"return string.char('".to_vec();
    source.extend(core::iter::repeat_n(b'9', 1024));
    source.extend_from_slice(b"')");
    let (vm, outcome, _) = run_with_string(&source, Some(100), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_string_pattern_balanced_frontier_and_substitution() {
    let (vm, outcome, _) = run_with_string(
        b"local a=string.match('(a) xyz','%b()'); local i,j=string.find('abc123','%f[%d]%d+'); local b,n=string.gsub('ab','(%a)','<%1>'); return a,i,j,b,n",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("Lua pattern 函式應返回值: {outcome:?}");
    };
    assert_eq!(
        (values[1], values[2], values[4]),
        (Value::Integer(4), Value::Integer(6), Value::Integer(2))
    );
    for (index, expected) in [(0, b"(a)".as_slice()), (3, b"<a><b>".as_slice())] {
        let Value::Object(object) = values[index] else {
            panic!("pattern 結果應為 bytes")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn p13_c_string_pattern_capture_backreference_anchor_quantifiers() {
    let (vm, outcome, _) = run_with_string(
        b"local a=string.match('xxababyy','(ab)%1'); local b,b2=string.match('abc123','(%a+)(%d+)'); local c=string.match('abc','()b'); local d=string.match('a1b2b','a.-b'); local e=string.match('aab','a+b'); local f=string.find('cab','^ab'); local g,h=pcall(string.match,'a','()%1'); local i=string.match('ab','a?(a)b'); local j,k=string.match('aaa','(a*)(a)$'); local l,m=string.match('aaa','(a-)(a)$'); return a,b,c,d,e,f,b2,g,h,i,j,k,l,m",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pattern 應完成: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"ab");
    assert_eq!(bytes(&vm, values[1]), b"abc");
    assert_eq!(values[2], Value::Integer(2));
    assert_eq!(bytes(&vm, values[3]), b"a1b");
    assert_eq!(bytes(&vm, values[4]), b"aab");
    assert_eq!(values[5], Value::Nil);
    assert_eq!(bytes(&vm, values[6]), b"123");
    assert_eq!(values[7], Value::Boolean(true));
    assert_eq!(values[8], Value::Nil);
    assert_eq!(bytes(&vm, values[9]), b"a");
    assert_eq!(bytes(&vm, values[10]), b"aa");
    assert_eq!(bytes(&vm, values[11]), b"a");
    assert_eq!(bytes(&vm, values[12]), b"aa");
    assert_eq!(bytes(&vm, values[13]), b"a");
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_string_pattern_malformed_and_fuel_are_controlled() {
    for source in [
        b"return string.match('a','[')".as_slice(),
        b"return string.match('a','%fX')".as_slice(),
        b"return string.match('a','(')".as_slice(),
        b"return string.match('a','%0')".as_slice(),
    ] {
        let (_, outcome, _) = run_with_string(source, None, false);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("malformed pattern 應是 LuaError: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::StringPattern);
    }
    let (_, outcome, _) = run_with_string(
        b"return string.match(string.rep('a',150)..'b','a*a*a*a*a*a*a*c')",
        Some(700),
        false,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    let mut long_class = b"return string.find('aaaaaaaa','[".to_vec();
    long_class.extend(core::iter::repeat_n(b'Z', 512));
    long_class.extend_from_slice(b"]')");
    let (_, outcome, _) = run_with_string(&long_class, Some(1200), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    let mut plain = b"return string.find('".to_vec();
    plain.extend(core::iter::repeat_n(b'a', 256));
    plain.extend_from_slice(b"','");
    plain.extend(core::iter::repeat_n(b'a', 64));
    plain.extend_from_slice(b"Z',1,true)");
    let (_, outcome, _) = run_with_string(&plain, Some(1100), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    let mut captures = b"return string.match('".to_vec();
    captures.extend(core::iter::repeat_n(b'a', 256));
    captures.extend_from_slice(b"','((.+))')");
    let (vm, outcome, _) = run_with_string(&captures, Some(800), true);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut backreference = b"return string.match('".to_vec();
    backreference.extend(core::iter::repeat_n(b'a', 512));
    backreference.extend_from_slice(b"c','(a+)%1b')");
    let (_, outcome, _) = run_with_string(&backreference, Some(1800), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    let (vm, outcome, _) = run_with_string(
        b"local s=string.char(11); return string.match(s,'%s'),string.match(s,'[%s]')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("%s 應辨識 vertical tab: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), &[11]);
    assert_eq!(bytes(&vm, values[1]), &[11]);
}

#[test]
fn p13_c_string_pattern_capture_and_depth_limits_are_controlled() {
    const CHILD: &str = "RIVETLUA_P13_PATTERN_LIMIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("p13_c_string_pattern_capture_and_depth_limits_are_controlled")
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "pattern 上限子程序失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for source in [
        b"return string.match('a',string.rep('()',33))".as_slice(),
        b"return string.match(string.rep('a',200),string.rep('a?',201))".as_slice(),
    ] {
        let (vm, outcome, _) = run_with_string(source, None, true);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("pattern 上限應是 LuaError：{outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::StringPattern);
        assert_eq!(vm.roots().total_count(), 2);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_c_string_pattern_gmatch_iterator_empty_and_literal_anchor() {
    let (vm, outcome, _) = run_with_string(
        b"local it=string.gmatch('ab','()'); local a=it(); local b=it(); local c=it(); local n=select('#',it()); local anchored=string.gmatch('^a','^a'); return a,b,c,n,anchored()",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("gmatch 應迭代: {outcome:?}")
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
            Value::Integer(0)
        ]
    );
    assert_eq!(bytes(&vm, values[4]), b"^a");
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_string_pattern_gsub_replacement_matrix_and_delayed_errors() {
    let (vm, outcome, _) = run_with_string(
        b"local a,n=string.gsub('ab','(.)','<%1>'); local b,m=string.gsub('abc','z','%'); local c,k=string.gsub('ab','(.)',function(x) if x=='a' then return false else return x..x end end); local d,l=string.gsub('abc','.',{a='A',c='C'}); local e,q=string.gsub('abc','.',{a='A',c='C'},0); local f,r=string.gsub('abc','abc','%1'); return a,n,b,m,c,k,d,l,e,q,f,r",
        None,true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("gsub replacement matrix 應返回: {outcome:?}")
    };
    for (index, expected) in [
        (0, b"<a><b>".as_slice()),
        (2, b"abc".as_slice()),
        (4, b"abb".as_slice()),
        (6, b"AbC".as_slice()),
        (8, b"abc".as_slice()),
        (10, b"abc".as_slice()),
    ] {
        assert_eq!(bytes(&vm, values[index]), expected);
    }
    assert_eq!(
        [
            values[1], values[3], values[5], values[7], values[9], values[11]
        ],
        [
            Value::Integer(2),
            Value::Integer(0),
            Value::Integer(2),
            Value::Integer(3),
            Value::Integer(0),
            Value::Integer(1)
        ]
    );
    for source in [
        b"return string.gsub('a','a','%')".as_slice(),
        b"return string.gsub('a','a','%2')".as_slice(),
        b"return string.gsub('a','a',function() return true end)".as_slice(),
    ] {
        let (_, outcome, _) = run_with_string(source, None, true);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("invalid replacement 應 LuaError: {outcome:?}")
        };
        assert!(matches!(
            error.kind,
            RuntimeErrorKind::StringPattern | RuntimeErrorKind::StringArgument
        ));
    }
}

#[test]
fn p13_c_string_pattern_gsub_callback_yield_gc_resume() {
    for source in [
        b"local co=coroutine.create(function() return string.gsub('ab','(.)',function(x) if x=='a' then coroutine.yield('pause') end return x..x end) end); local a,b=coroutine.resume(co); local c,d,n=coroutine.resume(co); return a,b,c,d,n".as_slice(),
        b"local t=setmetatable({},{__index=function(_,k) coroutine.yield('pause'); return '<'..k..'>' end}); local co=coroutine.create(function() return string.gsub('a','(.)',t) end); local a,b=coroutine.resume(co); local c,d,n=coroutine.resume(co); return a,b,c,d,n".as_slice(),
    ] {
        let (vm,outcome,_) = run_with_string(source,None,true);
        let RunOutcome::Returned(values) = outcome else { panic!("gsub callback 應 resume: {outcome:?}") };
        assert_eq!((values[0],values[2]),(Value::Boolean(true),Value::Boolean(true)));
        assert_eq!(bytes(&vm,values[1]),b"pause");
        assert!(bytes(&vm,values[3]) == b"aabb" || bytes(&vm,values[3]) == b"<a>");
        assert!(matches!(values[4], Value::Integer(1) | Value::Integer(2)));
        assert_eq!(vm.ledger_snapshot().reserved,0);
    }
}

#[test]
fn p13_c_string_pattern_gsub_callback_error_and_fuel_cleanup() {
    let (vm,outcome,_) = run_with_string(
        b"local t=setmetatable({},{__index=function() error('callback') end}); return string.gsub('a','(.)',t)",
        None,true,
    );
    assert!(matches!(outcome, RunOutcome::LuaError(_)));
    assert_eq!(vm.roots().total_count(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let mut source = b"return string.gsub('a','(.)',function() return '".to_vec();
    source.extend(core::iter::repeat_n(b'Z', 1024));
    source.extend_from_slice(b"' end)");
    let (vm, outcome, _) = run_with_string(&source, Some(300), true);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_string_pattern_gsub_long_unmatched_growth_and_budget() {
    let mut source = b"local s='".to_vec();
    source.extend(core::iter::repeat_n(b'a', 2048));
    source.extend_from_slice(b"'; local out,n=string.gsub(s,'z','X'); return s,out,n");
    let (vm, outcome, _) = run_with_string(&source, None, true);
    let RunOutcome::Returned(values) = outcome else {
        panic!("無匹配長字串應完成: {outcome:?}")
    };
    assert_eq!(values[0], values[1]);
    assert_eq!(values[2], Value::Integer(0));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let (vm, outcome, _) = run_with_string(&source, Some(3000), true);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_c_string_pack_unpack_endian_and_offset() {
    let (vm, outcome, _) = run_with_string(
        b"local s=string.pack('<I2i2',65535,-2); local a,b,p=string.unpack('<I2i2',s); return s,a,b,p,string.packsize('<I2i2')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pack/unpack 應返回值: {outcome:?}");
    };
    let Value::Object(bytes) = values[0] else {
        panic!("pack 應返回 bytes")
    };
    assert_eq!(
        vm.with_byte_string(bytes, |s| s.as_bytes().to_vec())
            .unwrap(),
        &[255, 255, 254, 255]
    );
    assert_eq!(
        &values[1..],
        &[
            Value::Integer(65535),
            Value::Integer(-2),
            Value::Integer(5),
            Value::Integer(4)
        ]
    );
}

#[test]
fn p13_c_string_pack_extended_width_alignment_and_strings() {
    let (vm,outcome,_) = run_with_string(
        b"local a=string.pack('>i16',-2); local b=string.pack('<I8',-1); local c=string.pack('<!4bXhh',1,2); local d=string.pack('<s2zc4','ab','q','X'); local x,y,z=string.unpack('<s2zc4',d); return a,b,c,d,x,y,z,string.packsize('<!4bXhh'),string.packsize('>i16')",
        None,true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pack 擴充規則應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), [vec![255; 15], vec![254]].concat());
    assert_eq!(bytes(&vm, values[1]), vec![255; 8]);
    assert_eq!(bytes(&vm, values[2]), &[1, 0, 2, 0]);
    assert_eq!(
        bytes(&vm, values[3]),
        &[2, 0, b'a', b'b', b'q', 0, b'X', 0, 0, 0]
    );
    assert_eq!(bytes(&vm, values[4]), b"ab");
    assert_eq!(bytes(&vm, values[5]), b"q");
    assert_eq!(bytes(&vm, values[6]), b"X\0\0\0");
    assert_eq!(
        (values[7], values[8]),
        (Value::Integer(4), Value::Integer(16))
    );
}

#[test]
fn p13_c_string_pack_errors_and_profile_maxsize_preflight() {
    for source in [
        b"return string.pack('<i1',128)".as_slice(),
        b"return string.pack('<I1',256)".as_slice(),
        b"return string.unpack('<I4','abc')".as_slice(),
        b"return string.packsize('Xc2')".as_slice(),
        b"return string.packsize('!3i4')".as_slice(),
        b"return string.packsize('s2')".as_slice(),
        b"return string.pack('z',string.char(0))".as_slice(),
    ] {
        let (vm, outcome, _) = run_with_string(source, None, false);
        let RunOutcome::LuaError(error) = outcome else {
            panic!("pack 錯誤應 LuaError: {outcome:?}")
        };
        assert_eq!(error.kind, RuntimeErrorKind::StringArgument);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    let (_, outcome, _) = run_with_string(b"return string.packsize('c2147483648')", None, false);
    match profile().2 {
        LuaProfile::Lua54 => assert!(matches!(outcome, RunOutcome::LuaError(_))),
        LuaProfile::Lua55 => assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(2_147_483_648)])
        ),
    }
}

#[test]
fn p13_c_string_pack_float_extension_and_negative_unpack_offset() {
    let (vm,outcome,_) = run_with_string(
        b"local f=string.pack('>fdn',1.5,-2.25,3.5); local a,b,c,p=string.unpack('>fdn',f); local s=string.pack('>i16I16',-2,-1); local x,y,q=string.unpack('>i16I16',s); local t=string.pack('>i2',-7); local z,r=string.unpack('>i2','xxxx'..t,-2); return f,a,b,c,p,s,x,y,q,z,r",
        None,true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pack float/extension 應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]).len(), 20);
    assert_eq!(
        (values[1], values[2], values[3], values[4]),
        (
            Value::Float(1.5),
            Value::Float(-2.25),
            Value::Float(3.5),
            Value::Integer(21)
        )
    );
    let packed = bytes(&vm, values[5]);
    assert_eq!(packed.len(), 32);
    assert_eq!(&packed[..15], &[255; 15]);
    assert_eq!(packed[15], 254);
    assert_eq!(&packed[16..24], &[0; 8]);
    assert_eq!(&packed[24..], &[255; 8]);
    assert_eq!(
        (values[6], values[7], values[8]),
        (Value::Integer(-2), Value::Integer(-1), Value::Integer(33))
    );
    assert_eq!(
        (values[9], values[10]),
        (Value::Integer(-7), Value::Integer(7))
    );
}

#[test]
fn p13_c_string_pack_native_alignment_follows_profile() {
    let (_, outcome, _) = run_with_string(
        b"return string.packsize('!xi16'),string.packsize('!xXi16')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native alignment packsize 應返回: {outcome:?}")
    };
    let align = if profile().2 == LuaProfile::Lua54
        || cfg!(target_os = "windows")
        || cfg!(all(target_arch = "aarch64", target_vendor = "apple"))
    {
        8
    } else {
        16
    };
    assert_eq!(values, [Value::Integer(align + 16), Value::Integer(align)]);
}

#[test]
fn p13_b_pack_unpack_keep_nil_and_explicit_count() {
    let (vm, outcome, _) = run_with_table(
        b"local t=table.pack(1,nil,3); return t.n,rawget(t,1),rawget(t,2),rawget(t,3),select('#',table.unpack(t,1,3)),table.unpack(t,1,3)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pack/unpack 應返回: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Integer(3),
            Value::Integer(1),
            Value::Nil,
            Value::Integer(3),
            Value::Integer(3),
            Value::Integer(1),
            Value::Nil,
            Value::Integer(3)
        ]
    );
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_b_table_reads_use_index_and_length_events() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({}, {__len=function() return 3 end, __index=function(_,k) return k*10 end}); local a,b=table.unpack(t,1,2); return table.concat(t,':'),table.concat(t,':',1,2),a,b,select('#',table.unpack(t))",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("table 讀取事件應返回: {outcome:?}")
    };
    let Value::Object(joined) = values[0] else {
        panic!("concat 應返回字串")
    };
    assert_eq!(
        vm.with_byte_string(joined, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"10:20:30"
    );
    let Value::Object(short) = values[1] else {
        panic!("concat 應返回字串")
    };
    assert_eq!(
        vm.with_byte_string(short, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"10:20"
    );
    assert_eq!(
        &values[2..],
        &[Value::Integer(10), Value::Integer(20), Value::Integer(3)]
    );
}

#[test]
fn p13_b_explicit_last_at_max_integer_returns_final_value() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({}, {__len=function() return 1 end, __index=function() return 'z' end}); local k=9223372036854775807; return table.concat(t,',',k,k),table.unpack(t,k,k)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("最大索引應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"z");
    assert_eq!(bytes(&vm, values[1]), b"z");
}

#[test]
fn p13_b_length_event_order_follows_profile() {
    let (_, language, _) = profile();
    let (vm, outcome, _) = run_with_table(
        b"local log={}; local t=setmetatable({}, {__len=function() log[#log+1]='len'; return 1 end, __index=function() return 'x' end}); local a=table.concat(t,'',1,1); local b=table.unpack(t,1,1); local c=pcall(table.concat,t,{},1,1); local d=pcall(table.unpack,t,{},1); return a,b,c,d,table.concat(log,':')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("長度事件順序應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"x");
    assert_eq!(bytes(&vm, values[1]), b"x");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(values[3], Value::Boolean(false));
    let expected: &[u8] = if language == LanguageProfile::Lua55 {
        b"len:len:len:len"
    } else {
        b"len:len"
    };
    assert_eq!(bytes(&vm, values[4]), expected);
}

#[test]
fn p13_b_table_writes_use_newindex_event() {
    let (vm, outcome, _) = run_with_table(
        b"local seen={}; local function mark(_,k,v) seen[#seen+1]=k*10+(v or 0) end; local t=setmetatable({}, {__len=function() return 2 end, __index=function(_,k) return k end, __newindex=mark}); table.insert(t,2,7); local removed=table.remove(t,1); local source=setmetatable({}, {__index=function(_,k) return k end}); table.move(source,1,2,5,t); return removed,table.concat(seen,':')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("table 寫入事件應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Integer(1));
    let Value::Object(joined) = values[1] else {
        panic!("事件紀錄應為字串")
    };
    assert_eq!(
        vm.with_byte_string(joined, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"32:27:12:20:51:62"
    );
}

#[test]
fn p13_b_sort_uses_length_index_and_newindex_events() {
    let (vm, outcome, _) = run_with_table(
        b"local writes={}; local t=setmetatable({}, {__len=function() return 3 end, __index=function(_,k) return 4-k end, __newindex=function(t,k,v) writes[#writes+1]=k; rawset(t,k,v) end}); table.sort(t); return t[1],t[2],t[3],table.concat(writes,':')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("sort 事件應返回: {outcome:?}")
    };
    assert_eq!(
        &values[..3],
        &[Value::Integer(1), Value::Integer(2), Value::Integer(3)]
    );
    let Value::Object(joined) = values[3] else {
        panic!("事件紀錄應為字串")
    };
    assert_eq!(
        vm.with_byte_string(joined, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"1:2:3"
    );
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
}

#[test]
fn p13_b_table_events_yield_resume_with_gc() {
    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local t=setmetatable({}, {__len=function() coroutine.yield('len'); return 2 end, __index=function(_,k) if k==1 then coroutine.yield('get') end; return k*10 end}); return table.concat(t,':') end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); local e,f=coroutine.resume(co); return a,b,c,d,e,f",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("表讀取 yield 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"len");
    assert_eq!(bytes(&vm, values[3]), b"get");
    assert_eq!(bytes(&vm, values[5]), b"10:20");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local t=setmetatable({}, {__len=function() return 2 end, __index=function(_,k) return k end, __newindex=function(t,k,v) if k==3 then coroutine.yield('write') end; rawset(t,k,v) end}); table.insert(t,2,7); return table.concat(t,',',1,3) end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("表寫入 yield 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"write");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"1,7,2");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_table_event_error_preserves_partial_writes_and_cleans_roots() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({}, {__len=function() return 2 end, __index=function(_,k) return k end, __newindex=function(t,k,v) if k==2 then error('stop') end; rawset(t,k,v) end}); local ok=pcall(table.insert,t,1,9); return ok,rawget(t,1),rawget(t,2),rawget(t,3)",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("寫入錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(false),
            Value::Nil,
            Value::Nil,
            Value::Integer(2)
        ]
    );
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_length_event_rejects_non_integer_and_overflow() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({}, {__len=function() return 1.5 end}); local a=pcall(table.concat,t); local b=pcall(table.unpack,t); local c=pcall(table.insert,t,1); local d=pcall(table.remove,t); local e=pcall(table.sort,t); local u=setmetatable({}, {__len=function() return 1e100 end}); local f=pcall(table.concat,u); return a,b,c,d,e,f",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("長度錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(values, vec![Value::Boolean(false); 6]);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_concat_event_bytes_charge_fuel() {
    let long = "a".repeat(2000);
    let source = format!(
        "local t=setmetatable({{}}, {{__index=function() return '{long}' end}}); return table.concat(t,'',1,1)"
    );
    let (vm, outcome, _) = run_with_table(source.as_bytes(), Some(500), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let short = b"local t=setmetatable({}, {__index=function() return 'a' end}); return table.concat(t,'',1,1)";
    let (vm, outcome, _) = run_with_table(short, Some(500), false);
    assert!(matches!(outcome, RunOutcome::Returned(_)));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_table_events_yield_resume_with_gc() {
    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local t=setmetatable({}, {__len=function() coroutine.yield('len'); return 3 end, __index=function(_,k) if k==2 then coroutine.yield('read') end; return 4-k end, __newindex=function(t,k,v) if k==1 then coroutine.yield('write') end; rawset(t,k,v) end}); table.sort(t); return t[1],t[2],t[3] end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); local e,f=coroutine.resume(co); local g,h,i,j=coroutine.resume(co); return a,b,c,d,e,f,g,h,i,j",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("sort 事件 yield 應返回: {outcome:?}")
    };
    for index in [0, 2, 4, 6] {
        assert_eq!(values[index], Value::Boolean(true));
    }
    assert_eq!(bytes(&vm, values[1]), b"len");
    assert_eq!(bytes(&vm, values[3]), b"read");
    assert_eq!(bytes(&vm, values[5]), b"write");
    assert_eq!(
        &values[7..],
        &[Value::Integer(1), Value::Integer(2), Value::Integer(3)]
    );
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_newindex_error_keeps_first_partial_write() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({}, {__len=function() return 3 end, __index=function(_,k) return 4-k end, __newindex=function(t,k,v) if k==2 then error('stop') end; rawset(t,k,v) end}); local ok=pcall(table.sort,t); return ok,rawget(t,1),rawget(t,2),rawget(t,3)",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("sort 寫入錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(false),
            Value::Integer(2),
            Value::Nil,
            Value::Nil
        ]
    );
    assert_eq!(vm.table_sort_trace().comparisons, 2);
    assert_eq!(vm.table_sort_trace().swaps, 0);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_newindex_partial_write_then_fuel_abort_cleans_state() {
    let source = b"input=setmetatable({}, {__len=function() return 3 end, __index=function(_,k) return k end, __newindex=function(t,k,v) rawset(t,k,v) end}); table.insert(input,1,9)";
    let mut seen = false;
    for fuel in 1..500 {
        let (mut vm, outcome, environment) = run_with_table(source, Some(fuel), false);
        if outcome != RunOutcome::Aborted(AbortReason::FuelExhausted) {
            continue;
        }
        let key = vm.allocate_byte_string(b"input").unwrap();
        let Value::Object(input) = vm.raw_get(environment, Value::Object(key)).unwrap() else {
            continue;
        };
        if vm.raw_get(input, Value::Integer(4)) == Ok(Value::Integer(3)) {
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            seen = true;
            break;
        }
    }
    assert!(seen, "應於一次 __newindex 寫入後找到 fuel 中止");
}

#[test]
fn p13_b_table_pending_keeps_callback_objects_reachable() {
    let (vm, outcome, _) = run_with_table(
        b"local source=setmetatable({}, {__len=function() return 3 end, __index=function(_,k) return {k} end}); local a,b,c=table.unpack(source); local target=setmetatable({}, {__newindex=function(t,k,v) rawset(t,k,v) end}); table.move(source,1,2,1,target); return a[1],b[1],c[1],target[1][1],target[2][1]",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("待續物件應可達: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![1, 2, 3, 1, 2]
            .into_iter()
            .map(Value::Integer)
            .collect::<Vec<_>>()
    );
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_unpack_output_survives_yield_and_outer_gc() {
    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local t=setmetatable({}, {__index=function(_,k) if k==2 then coroutine.yield('pause') end; return {k} end}); local a,b=table.unpack(t,1,2); return a[1],b[1] end); local ok,pause=coroutine.resume(co); for i=1,12 do local garbage={i} end; local resumed,a,b=coroutine.resume(co); return ok,pause,resumed,a,b",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("unpack 待續結果應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(&values[3..], &[Value::Integer(1), Value::Integer(2)]);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_move_equal_destination_reverses_and_short_circuits() {
    let (vm, outcome, _) = run_with_table(
        b"local log={}; local mt={__eq=function() log[#log+1]='eq'; return true end,__index=function(_,k) log[#log+1]='g'..k; return k end,__newindex=function(_,k) log[#log+1]='s'..k end}; local a=setmetatable({},mt); local b=setmetatable({},mt); table.move(a,1,3,2,b); local first=table.concat(log,':'); log={}; table.move(a,1,3,5,b); table.move(a,1,3,0,b); return first,table.concat(log,':')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("move 相等事件應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"eq:g3:s4:g2:s3:g1:s2");
    assert_eq!(
        bytes(&vm, values[1]),
        b"g1:s5:g2:s6:g3:s7:g1:s0:g2:s1:g3:s2"
    );
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_move_equal_event_yield_and_error_clean_state() {
    let (vm, outcome, _) = run_with_table(
        b"local log={}; local mt={__eq=function() coroutine.yield('eq'); return true end,__index=function(_,k) log[#log+1]='g'..k; return k end,__newindex=function(_,k) log[#log+1]='s'..k end}; local a=setmetatable({},mt); local b=setmetatable({},mt); local co=coroutine.create(function() table.move(a,1,2,2,b) end); local x,y=coroutine.resume(co); local z=coroutine.resume(co); local bad=setmetatable({}, {__eq=function() error('eq failure') end}); local bad2=setmetatable({}, getmetatable(bad)); local ok=pcall(table.move,bad,1,2,2,bad2); return x,y,z,table.concat(log,':'),ok",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("move 比較續行應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"eq");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"g2:s3:g1:s2");
    assert_eq!(values[4], Value::Boolean(false));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_numeric_string_indices_and_length_event() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({'a','b'}, {__len=function() return '2' end}); local joined=table.concat(t,':','1','2'); local a,b=table.unpack(t,'1','2'); table.insert(t,'2','x'); local dest={}; table.move(t,'1','2','4',dest); local removed=table.remove(t,'2'); local sorted=setmetatable({3,1,2}, {__len=function() return '3' end}); table.sort(sorted); return joined,a,b,dest[4],dest[5],removed,t[2],table.concat(sorted,',')",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("數字字串引數應返回: {outcome:?}")
    };
    for (index, expected) in [
        (0, b"a:b".as_slice()),
        (1, b"a"),
        (2, b"b"),
        (3, b"a"),
        (4, b"x"),
        (5, b"x"),
        (7, b"1,2,3"),
    ] {
        assert_eq!(bytes(&vm, values[index]), expected);
    }
    assert_eq!(values[6], Value::Nil);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_invalid_numeric_strings_are_controlled_errors() {
    let (vm, outcome, _) = run_with_table(
        b"local t=setmetatable({'a','b'}, {__len=function() return '2.5' end}); local a=pcall(table.concat,t); local b=pcall(table.unpack,t); local c=pcall(table.insert,t,1); local d=pcall(table.remove,t); local e=pcall(table.sort,t); local s={'a','b'}; local f=pcall(table.concat,s,':','1.5','2'); local g=pcall(table.move,s,'x','2','4'); return a,b,c,d,e,f,g",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("無效數字字串應受控返回: {outcome:?}")
    };
    assert_eq!(values, vec![Value::Boolean(false); 7]);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_numeric_string_parsing_charges_fuel_by_bytes() {
    let padded = format!("{}1", " ".repeat(2000));
    let source = format!("local t={{'x'}}; return table.concat(t,'','{padded}','{padded}')");
    let (vm, outcome, _) = run_with_table(source.as_bytes(), Some(500), false);
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let (vm, outcome, _) = run_with_table(
        b"local t={'x'}; return table.concat(t,'','1','1')",
        Some(500),
        false,
    );
    assert!(matches!(outcome, RunOutcome::Returned(_)));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_insert_remove_move_overlap_and_concat_bytes() {
    let (vm, outcome, _) = run_with_table(
        b"local t={'a','b','c'}; table.insert(t,2,'x'); local removed=table.remove(t,3); local same=table.move(t,1,2,2)==t; local d={}; table.move(t,1,2,5,d); return table.concat(t,':'),removed,same,t[3],d[5],d[6]",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("table 操作應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"a:a:x");
    assert_eq!(bytes(&vm, values[1]), b"b");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"x");
    assert_eq!(bytes(&vm, values[4]), b"a");
    assert_eq!(bytes(&vm, values[5]), b"a");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_b_sort_calls_lua_comparator_and_records_trace() {
    let (vm, outcome, _) = run_with_table(
        b"local t={4,1,3,2}; table.sort(t,function(a,b) return a<b end); return table.concat(t,','),#t",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("sort 應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"1,2,3,4");
    assert_eq!(values[1], Value::Integer(4));
    let trace = vm.table_sort_trace();
    assert!(trace.comparisons >= 4);
    assert!(trace.swaps >= 2);
    assert_eq!(trace.stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_comparator_error_keeps_table_valid_and_trace() {
    let (vm, outcome, _) = run_with_table(
        b"local t={3,1,2}; local ok,err=pcall(table.sort,t,function() error('boom') end); return ok,err,table.concat(t,','),#t",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall 應捕捉 comparator: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"boom");
    assert_eq!(bytes(&vm, values[2]), b"3,1,2");
    assert_eq!(values[3], Value::Integer(3));
    let trace = vm.table_sort_trace();
    assert_eq!(trace.comparisons, 1);
    assert_eq!(trace.swaps, 0);
    assert_eq!(trace.stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_default_bytes_and_inconsistent_comparator() {
    let (vm, outcome, _) = run_with_table(
        b"local a={'b','a','c'}; table.sort(a); local b={3,1,2}; local ok,err=pcall(table.sort,b,function() return true end); return table.concat(a,','),ok,err,table.concat(b,','),#b",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("排序應受控返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"a,b,c");
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"3,1,2");
    assert_eq!(values[4], Value::Integer(3));
    assert_eq!(vm.table_sort_trace().comparisons, 2);
    assert_eq!(vm.table_sort_trace().swaps, 0);
    assert_eq!(
        vm.table_sort_trace().stop,
        TableSortStop::InconsistentComparator
    );
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_callable_comparator_and_default_lt_event() {
    let (vm, outcome, _) = run_with_table(
        b"local t={3,1,2}; local cmp=setmetatable({},{__call=function(_,a,b) return a<b end}); table.sort(t,function(a,b) return cmp(a,b) end); local mt={__lt=function(a,b) return a.n<b.n end}; local a=setmetatable({n=2},mt); local b=setmetatable({n=1},mt); local o={a,b}; table.sort(o); return table.concat(t,','),o[1]==b,o[2]==a",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("函式比較器應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"1,2,3");
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_rejects_non_function_comparators_before_read() {
    let (vm, outcome, _) = run_with_table(
        b"local reads=0; local calls=0; local t=setmetatable({}, {__len=function() return 2 end,__index=function(_,k) reads=reads+1; return 3-k end}); local cmp=setmetatable({}, {__call=function() calls=calls+1; return true end}); local a=pcall(table.sort,t,cmp); local b=pcall(table.sort,t,12); return a,b,reads,calls",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("比較器型別錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(false),
            Value::Boolean(false),
            Value::Integer(0),
            Value::Integer(0)
        ]
    );
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_ignores_invalid_comparator_for_small_table() {
    let (vm, outcome, _) = run_with_table(
        b"local empty=setmetatable({}, {__len=function() return 0 end}); local one=setmetatable({7}, {__len=function() return 1 end}); local a=pcall(table.sort,empty,12); local b=pcall(table.sort,one,{}); return a,b,one[1]",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("小表應略過比較器: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(7)
        ]
    );
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_rejects_int_max_length_before_comparator() {
    let (vm, outcome, _) = run_with_table(
        b"local reads=0; local calls=0; local lengths=0; local t=setmetatable({}, {__len=function() lengths=lengths+1; return 2147483647 end,__index=function() reads=reads+1; return 1 end}); local function cmp() calls=calls+1; return true end; local ok=pcall(table.sort,t,cmp); return ok,lengths,reads,calls",
        Some(500),
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("過大表應先受控拒絕: {outcome:?}")
    };
    assert_eq!(
        values,
        vec![
            Value::Boolean(false),
            Value::Integer(1),
            Value::Integer(0),
            Value::Integer(0)
        ]
    );
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_partial_reorder_then_lua_error() {
    let (vm, outcome, _) = run_with_table(
        b"local n=0; local t={3,1,2}; local ok=pcall(table.sort,t,function(a,b) n=n+1; if n==3 then error('stop') end; return a<b end); return ok,table.concat(t,','),#t,n",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("比較錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"1,3,2");
    assert_eq!(values[2], Value::Integer(3));
    assert_eq!(values[3], Value::Integer(3));
    assert_eq!(vm.table_sort_trace().comparisons, 3);
    assert_eq!(vm.table_sort_trace().swaps, 1);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_comparator_yield_resume_with_gc() {
    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local once=false; local t={4,1,3,2}; table.sort(t,function(a,b) if not once then once=true; coroutine.yield('pause') end; return a<b end); return table.concat(t,',') end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("協程排序應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"1,2,3,4");
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_direct_native_coroutine_entry() {
    let (vm, outcome, _) = run_with_table(
        b"local t={3,1,2}; local co=coroutine.create(table.sort); local ok=coroutine.resume(co,t,function(a,b) return a<b end); return ok,table.concat(t,','),coroutine.status(co)",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native sort 協程應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"1,2,3");
    assert_eq!(bytes(&vm, values[2]), b"dead");
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_fuel_abort_keeps_ledger_and_roots_clean() {
    let source = b"local t={6,5,4,3,2,1}; local ok=pcall(table.sort,t,function(a,b) return a<b end); return ok,table.concat(t,',')";
    let mut seen_sort_abort = false;
    for fuel in 1..500 {
        let (vm, outcome, _) = run_with_table(source, Some(fuel), false);
        if outcome == RunOutcome::Aborted(AbortReason::FuelExhausted)
            && vm.table_sort_trace().comparisons > 0
        {
            assert_eq!(vm.table_sort_trace().stop, TableSortStop::Aborted);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            seen_sort_abort = true;
            break;
        }
    }
    assert!(seen_sort_abort, "必須在實際比較後找到 fuel 中止");
}

#[test]
fn p13_b_sort_comparator_reenters_table_api() {
    let (vm, outcome, _) = run_with_table(
        b"local t={4,2,3,1}; local log={}; table.sort(t,function(a,b) table.insert(log,a); return a<b end); return table.concat(t,','),#log",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("重入排序應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"1,2,3,4");
    assert!(matches!(values[1], Value::Integer(n) if n >= 4));
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_comparator_recovers_its_own_protected_error() {
    let (vm, outcome, _) = run_with_table(
        b"local t={3,1,2}; table.sort(t,function(a,b) local ok=pcall(error,'ignored'); return a<b end); return table.concat(t,',')",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("受保護的內層錯誤應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"1,2,3");
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_nested_sort_restores_outer_trace_after_inner_error() {
    let (vm, outcome, _) = run_with_table(
        b"local outer={3,1,2}; local calls=0; table.sort(outer,function(a,b) calls=calls+1; local inner={2,1}; local ok=pcall(table.sort,inner,function() return true end); assert(not ok); return a<b end); return table.concat(outer,','),calls",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀比較應返回: {outcome:?}")
    };
    assert_eq!(bytes(&vm, values[0]), b"1,2,3");
    assert_eq!(values[1], Value::Integer(5));
    assert_eq!(vm.table_sort_trace().comparisons, 5);
    assert_eq!(vm.table_sort_trace().swaps, 2);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_nested_sort_error_stops_outer_trace() {
    let (vm, outcome, _) = run_with_table(
        b"local outer={3,1,2}; local inner={2,1}; local ok=pcall(table.sort,outer,function(a,b) table.sort(inner,function() return true end); return a<b end); return ok,table.concat(outer,','),#outer",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀錯誤應受控返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"3,1,2");
    assert_eq!(values[2], Value::Integer(3));
    assert_eq!(vm.table_sort_trace().comparisons, 1);
    assert_eq!(vm.table_sort_trace().swaps, 0);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::LuaError);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_nested_sort_yield_resumes_outer_trace() {
    let (vm, outcome, _) = run_with_table(
        b"local co=coroutine.create(function() local outer={3,1,2}; local once=false; table.sort(outer,function(a,b) local inner={2,1}; table.sort(inner,function(x,y) if not once then once=true; coroutine.yield('pause') end; return x<y end); return a<b end); return table.concat(outer,',') end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀 yield 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"1,2,3");
    assert_eq!(vm.table_sort_trace().comparisons, 5);
    assert_eq!(vm.table_sort_trace().swaps, 2);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_nested_sort_abort_stops_outer_trace() {
    let (vm, outcome, _) = run_with_table(
        b"local outer={3,1,2}; table.sort(outer,function(a,b) local inner={2,1}; table.sort(inner,function() while true do end end); return a<b end)",
        Some(200),
        true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert_eq!(vm.table_sort_trace().comparisons, 1);
    assert_eq!(vm.table_sort_trace().swaps, 0);
    assert_eq!(vm.table_sort_trace().stop, TableSortStop::Aborted);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_static_boundaries_and_binary_concat() {
    let (vm, outcome, _) = run_with_table(
        b"local t={'a\\0b','x'}; local bad=pcall(table.insert,t,0,'z'); local empty=table.concat(t,',',3,2); local moved=table.move(t,2,1,5); return bad,table.concat(t,':'),empty,moved==t,table.remove(t,3),#t",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("table 邊界應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"a\0b:x");
    assert_eq!(bytes(&vm, values[2]), b"");
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(values[4], Value::Nil);
    assert_eq!(values[5], Value::Integer(2));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_concat_validates_separator_before_empty_range() {
    let (vm, outcome, _) = run_with_table(
        b"local t={}; local ok,err=pcall(table.concat,t,{},2,1); return ok,type(err)",
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("錯誤應受保護: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"string");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_b_sort_allocation_failure_is_recoverable() {
    let (_, language, runtime_profile) = profile();
    let source = b"table.sort(input,function(a,b) return a<b end)";
    let setup = || {
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_basic_builtins(env).unwrap();
        vm.install_table_builtins(env).unwrap();
        let input = vm.allocate_table().unwrap();
        for (index, value) in [3, 1, 2].into_iter().enumerate() {
            vm.raw_set(
                input,
                Value::Integer(index as i64 + 1),
                Value::Integer(value),
            )
            .unwrap();
        }
        let key = vm.allocate_byte_string(b"input").unwrap();
        vm.raw_set(env, Value::Object(key), Value::Object(input))
            .unwrap();
        (vm, env, env_root, input)
    };
    let (mut baseline, env, root, _) = setup();
    let probe = baseline.ledger_probe();
    let execution = baseline
        .load_with_environment(compile(source, language), Value::Object(env))
        .unwrap();
    let first_execution_ordinal = probe.trace().next_ordinal;
    drop(execution);
    baseline.remove_root(root).unwrap();
    let mut found = false;
    for ordinal in first_execution_ordinal..first_execution_ordinal + 128 {
        let (mut vm, env, root, input) = setup();
        vm.inject_allocation_failure_at(ordinal);
        let mut execution = vm
            .load_with_environment(compile(source, language), Value::Object(env))
            .unwrap();
        let outcome = execution.run();
        drop(execution);
        if vm.table_sort_trace().stop == TableSortStop::Allocation {
            let Err(error) = outcome else {
                panic!("sort 配置失敗應保留結構化 Err")
            };
            let RuntimeErrorKind::Heap(VmError::InjectedAllocation(attempt)) = error.kind else {
                panic!("sort 應回傳注入配置點: {error:?}");
            };
            assert_eq!(attempt.ordinal, ordinal);
            println!(
                "P13_B_SORT_ALLOC\tordinal={}\tsite={}:{}\tstop={:?}",
                ordinal,
                attempt.site.file,
                attempt.site.line,
                vm.table_sort_trace().stop
            );
            assert!(vm.table_sort_trace().comparisons <= 1);
            for index in 1..=3 {
                assert!(vm.raw_get(input, Value::Integer(index)).is_ok());
            }
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            let mut retry = vm
                .load_with_environment(compile(source, language), Value::Object(env))
                .unwrap();
            assert!(matches!(retry.run(), Ok(RunOutcome::Returned(_))));
            drop(retry);
            assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
            assert_eq!(vm.raw_get(input, Value::Integer(1)), Ok(Value::Integer(1)));
            assert_eq!(vm.raw_get(input, Value::Integer(2)), Ok(Value::Integer(2)));
            assert_eq!(vm.raw_get(input, Value::Integer(3)), Ok(Value::Integer(3)));
            vm.remove_root(root).unwrap();
            assert_eq!(vm.roots().total_count(), 0);
            found = true;
            break;
        }
        vm.remove_root(root).unwrap();
    }
    assert!(found, "128 個配置 ordinal 中應觸及 sort 的受控失敗點");
}

fn bytes(vm: &Vm, value: Value) -> Vec<u8> {
    let Value::Object(object) = value else {
        panic!("預期 byte string: {value:?}");
    };
    vm.with_byte_string(object, |string| string.as_bytes().to_vec())
        .unwrap()
}

#[test]
fn p13_a_stdlib_basic_type_select_and_assert_return_lua_values() {
    let (vm, values) = run_with_basic(
        b"return type(12), select('#', 1, nil, 3), assert(7, 8), tostring(12), tonumber('12'), select(-2, 4, 5, 6)",
    );
    assert_eq!(values.len(), 7);
    assert_eq!(bytes(&vm, values[0]), b"number");
    assert_eq!(values[1], Value::Integer(3));
    assert_eq!(values[2], Value::Integer(7));
    assert_eq!(bytes(&vm, values[3]), b"12");
    assert_eq!(values[4], Value::Integer(12));
    assert_eq!(values[5], Value::Integer(5));
    assert_eq!(values[6], Value::Integer(6));
}

#[test]
fn p13_a_stdlib_basic_raw_metatable_next_pairs_ipairs_follow_lua_values() {
    let (vm, values) = run_with_basic(
        b"local t={[1]=11,[2]=22}; local mt={__index=function() return 99 end}; setmetatable(t,mt); local k,v=next(t,nil); local p,s,c,z=pairs(t); local i,st,n=ipairs(t); return rawget(t,1),rawset(t,3,33)==t,rawequal(1,1.0),rawlen(t),getmetatable(t)==mt,k,v,type(p),s==t,c,z,type(i),st==t,n",
    );
    assert_eq!(values[0], Value::Integer(11));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(3));
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(values[5], Value::Integer(1));
    assert_eq!(values[6], Value::Integer(11));
    assert_eq!(bytes(&vm, values[7]), b"function");
    assert_eq!(values[8], Value::Boolean(true));
    assert_eq!(values[9], Value::Nil);
    assert_eq!(values[10], Value::Nil);
    assert_eq!(bytes(&vm, values[11]), b"function");
    assert_eq!(values[12], Value::Boolean(true));
    assert_eq!(values[13], Value::Integer(0));
}

#[test]
fn p13_a_stdlib_basic_pcall_xpcall_and_assert_preserve_error_boundary() {
    let (vm, values) = run_with_basic(
        b"local a,b=pcall(error,'boom'); local c,d=xpcall(function() error('bad') end,function(e) return 'handled' end); local e,f=pcall(assert,false,'no'); return a,b,c,d,e,f",
    );
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"boom");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"handled");
    assert_eq!(values[4], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[5]), b"no");
}

struct TestOutput(Rc<RefCell<Vec<u8>>>, bool);

impl HostOutput for TestOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        if self.1 {
            return Err(HostOutputError::WriteFailed);
        }
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn p13_a_host_policy_print_default_is_distinct_and_protected() {
    let (_, outcome) =
        run_with_basic_services(b"print('x')", HostServices::deny_all(), None, false);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("必須回 policy error: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyOutput);
    assert_eq!(error.diagnostic_id, "E_HOST_POLICY_OUTPUT");
    let (vm, values) = run_with_basic(b"return pcall(print,'x')");
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_OUTPUT");
}

#[test]
fn p13_a_print_sink_bytes_failure_and_vm_isolation() {
    let left = Rc::new(RefCell::new(Vec::new()));
    let right = Rc::new(RefCell::new(Vec::new()));
    let (_, outcome) = run_with_basic_services(
        b"print('A',12); return 5",
        HostServices::with_output(TestOutput(left.clone(), false)),
        None,
        false,
    );
    assert!(matches!(outcome, RunOutcome::Returned(values) if values == vec![Value::Integer(5)]));
    assert_eq!(&*left.borrow(), b"A\t12\n");
    let (_, outcome) = run_with_basic_services(
        b"print('B')",
        HostServices::with_output(TestOutput(right.clone(), true)),
        None,
        false,
    );
    let RunOutcome::LuaError(error) = outcome else {
        panic!("必須回 host failure: {outcome:?}")
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostOutputFailed);
    assert_eq!(error.diagnostic_id, "E_HOST_OUTPUT_FAILED");
    assert!(right.borrow().is_empty());
    assert_eq!(&*left.borrow(), b"A\t12\n");
}

#[test]
fn p13_a_fuel_abort_prevents_host_output_and_gc_keeps_values() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"print('unreached')",
        HostServices::with_output(TestOutput(sink.clone(), false)),
        Some(0),
        true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_print_long_bytes_aborts_inside_pcall_before_output() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let long = "x".repeat(1024);
    let source = format!("return pcall(print,'prefix','{long}')");
    let (vm, outcome) = run_with_basic_services(
        source.as_bytes(),
        HostServices::with_output(TestOutput(sink.clone(), false)),
        Some(100),
        true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_print_tostring_continuation_long_bytes_aborts_before_output() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let long = "y".repeat(1024);
    let source = format!(
        "local t=setmetatable({{}},{{__tostring=function() return '{long}' end}}); return pcall(print,t)"
    );
    let (vm, outcome) = run_with_basic_services(
        source.as_bytes(),
        HostServices::with_output(TestOutput(sink.clone(), false)),
        Some(100),
        true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_metamethod_tostring_pairs_and_ipairs_continue_in_vm() {
    let (vm, values) = run_with_basic(
        b"local t=setmetatable({}, {__tostring=function() return 'special' end, __pairs=function(self) return function(_,k) if k==nil then return 7,8 end end,self,nil,nil end, __index=function(_,k) if k==1 then return 42 end end}); local f,s,k,z=pairs(t); local a,b=f(s,k); local i,st,n=ipairs(t); local j,v=i(st,n); return tostring(t),a,b,z,j,v",
    );
    assert_eq!(bytes(&vm, values[0]), b"special");
    assert_eq!(values[1], Value::Integer(7));
    assert_eq!(values[2], Value::Integer(8));
    assert_eq!(values[3], Value::Nil);
    assert_eq!(values[4], Value::Integer(1));
    assert_eq!(values[5], Value::Integer(42));
}

#[test]
fn p13_a_protected_metatable_and_raw_key_errors_remain_lua_errors() {
    let (vm, values) = run_with_basic(
        b"local t=setmetatable({x=3},{__metatable='locked',__index=function() return 99 end}); local a,b=pcall(setmetatable,t,{}); local c,d=pcall(rawset,t,nil,1); local e,f=pcall(rawset,t,0/0,1); local g,h=pcall(next,t,'missing'); return getmetatable(t),rawget(t,'missing'),a,c,e,g",
    );
    assert_eq!(bytes(&vm, values[0]), b"locked");
    assert_eq!(values[1], Value::Nil);
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(values[3], Value::Boolean(false));
    assert_eq!(values[4], Value::Boolean(false));
    assert_eq!(values[5], Value::Boolean(false));
}

#[test]
fn p13_a_tonumber_and_number_text_match_concat_in_each_profile() {
    let (vm, values) = run_with_basic(
        b"return tonumber('ff',16),tonumber('  -12  '),tonumber('bad'),tostring(1.5),1.5 .. '',tostring(-0.0),-0.0 .. ''",
    );
    assert_eq!(values[0], Value::Integer(255));
    assert_eq!(values[1], Value::Integer(-12));
    assert_eq!(values[2], Value::Nil);
    assert_eq!(bytes(&vm, values[3]), bytes(&vm, values[4]));
    assert_eq!(bytes(&vm, values[5]), bytes(&vm, values[6]));
}

#[test]
fn p13_a_print_uses_tostring_metamethod_and_protects_host_failure() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (_, outcome) = run_with_basic_services(
        b"local t=setmetatable({},{__tostring=function() return 'special' end}); print(t)",
        HostServices::with_output(TestOutput(sink.clone(), false)),
        None,
        false,
    );
    assert!(matches!(outcome, RunOutcome::Returned(_)));
    assert_eq!(&*sink.borrow(), b"special\n");
    let (vm, outcome) = run_with_basic_services(
        b"return pcall(print,'x')",
        HostServices::with_output(TestOutput(Rc::new(RefCell::new(Vec::new())), true)),
        None,
        false,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall 應捕捉 host failure: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_OUTPUT_FAILED");
}

#[test]
fn p13_a_print_callback_yield_resume_preserves_output_and_roots() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__tostring=function() coroutine.yield('pause'); return 'ready' end}); print(t); return 9 end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        HostServices::with_output(TestOutput(sink.clone(), false)),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("coroutine 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(9));
    assert_eq!(&*sink.borrow(), b"ready\n");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_ipairs_index_callback_yield_resume_returns_pair() {
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__index=function() coroutine.yield('pause'); return 42 end}); local i,s,n=ipairs(t); return i(s,n) end); local a,b=coroutine.resume(co); local c,d,e=coroutine.resume(co); return a,b,c,d,e",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("ipairs coroutine 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(1));
    assert_eq!(values[4], Value::Integer(42));
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_callback_error_and_nonstring_result_leave_no_output() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local bad=setmetatable({},{__tostring=function() error('boom') end}); local invalid=setmetatable({},{__tostring=function() return true end}); local a,b=pcall(print,'prefix',bad); local c,d=pcall(tostring,invalid); return a,b,c,d",
        HostServices::with_output(TestOutput(sink.clone(), false)), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"boom");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"E_BASIC_ARGUMENT");
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_pairs_profile_count_and_ipairs_nil_termination() {
    let (_, language, _) = profile();
    let expected = if language == LanguageProfile::Lua54 {
        3
    } else {
        4
    };
    let (vm, values) = run_with_basic(
        b"local t={}; local iter,state,index=ipairs(t); local a,b=iter(state,index); return select('#',pairs(t)),a,b",
    );
    assert_eq!(values[0], Value::Integer(expected));
    assert_eq!(values[1], Value::Nil);
    assert_eq!(values[2], Value::Nil);
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_pairs_metamethod_yield_resumes_with_profile_arity() {
    let (_, language, _) = profile();
    let expected = if language == LanguageProfile::Lua54 {
        3
    } else {
        4
    };
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__pairs=function() coroutine.yield('pause'); return 1,2,3,4,5 end}); return select('#',pairs(t)) end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pairs 應繼續: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(expected));
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_pairs_and_ipairs_callback_errors_stay_protected() {
    let (vm, values) = run_with_basic(
        b"local p=setmetatable({},{__pairs=function() error('pair-fail') end}); local i=setmetatable({},{__index=function() error('index-fail') end}); local a,b=pcall(pairs,p); local iter,state,key=ipairs(i); local c,d=pcall(iter,state,key); return a,b,c,d",
    );
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"pair-fail");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[3]), b"index-fail");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_callback_fuel_abort_cleans_pending_and_never_writes_output() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local t=setmetatable({},{__tostring=function() while true do end end}); return pcall(print,'prefix',t)",
        HostServices::with_output(TestOutput(sink.clone(), false)), Some(150), true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_tonumber_accepts_lua_hex_and_rejects_host_float_words() {
    let (_, values) = run_with_basic(
        b"return tonumber('0xff'),tonumber('0x1.8p+2'),tonumber('nan'),tonumber('inf'),tonumber('0xG')",
    );
    assert_eq!(
        values,
        vec![
            Value::Integer(255),
            Value::Float(6.0),
            Value::Nil,
            Value::Nil,
            Value::Nil,
        ]
    );
}

#[test]
fn p13_a_ipairs_index_table_chain_uses_lua_lookup() {
    let (_, values) = run_with_basic(
        b"local t=setmetatable({},{__index={[1]=88}}); local iter,state,key=ipairs(t); local a,b=iter(state,key); return a,b",
    );
    assert_eq!(values, vec![Value::Integer(1), Value::Integer(88)]);
}

#[test]
fn p13_a_pairs_accepts_native_builtin_metamethod() {
    let (_, language, _) = profile();
    let expected = if language == LanguageProfile::Lua54 {
        3
    } else {
        4
    };
    let (_, values) = run_with_basic(
        b"local t=setmetatable({[1]=7},{__pairs=ipairs}); return select('#',pairs(t))",
    );
    assert_eq!(values, vec![Value::Integer(expected)]);
}

#[test]
fn p13_a_pairs_recursive_builtin_reports_protected_stack_limit() {
    let (vm, values) =
        run_with_basic(b"local t=setmetatable({},{__pairs=pairs}); return pcall(pairs,t)");
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_STACK_LIMIT");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_tostring_recursive_builtin_reports_protected_stack_limit() {
    const CHILD: &str = "RIVETLUA_P13_TOSTRING_INTEGRATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("p13_a_tostring_recursive_builtin_reports_protected_stack_limit")
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "遞迴 builtin 子程序失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (vm, values) =
        run_with_basic(b"local t=setmetatable({},{__tostring=tostring}); return pcall(tostring,t)");
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_STACK_LIMIT");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_tostring_recursive_builtin_coroutine_reports_error() {
    let (vm, values) = run_with_basic(
        b"local t=setmetatable({},{__tostring=tostring}); local co=coroutine.create(function() return tostring(t) end); return coroutine.resume(co)",
    );
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_STACK_LIMIT");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_integral_float_arguments_follow_lua_integer_checks() {
    let (vm, values) = run_with_basic(
        b"local iter,state=ipairs({[1]=9}); local key,value=iter(state,0.0); return tonumber('ff',16.0),select(1.0,'ok'),key,value",
    );
    assert_eq!(values[0], Value::Integer(255));
    assert_eq!(bytes(&vm, values[1]), b"ok");
    assert_eq!(values[2], Value::Integer(1));
    assert_eq!(values[3], Value::Integer(9));
}

#[test]
fn p13_a_coroutine_pcall_print_keeps_yieldable_tostring() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__tostring=function() coroutine.yield('pause'); return 'ready' end}); return pcall(print,t) end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        HostServices::with_output(TestOutput(sink.clone(), false)), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("pcall coroutine 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(&*sink.borrow(), b"ready\n");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_native_pcall_coroutine_print_callback_yields() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local t=setmetatable({},{__tostring=function() coroutine.yield('pause'); return 'ready' end}); local co=coroutine.create(pcall); local a,b,x=coroutine.resume(co,print,t); local c,d,e=coroutine.resume(co); return a,b,x,c,d,e",
        HostServices::with_output(TestOutput(sink.clone(), false)), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native pcall coroutine 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Nil);
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(values[5], Value::Nil);
    assert_eq!(&*sink.borrow(), b"ready\n");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_direct_native_basic_coroutine_runs_and_returns_values() {
    let (vm, values) = run_with_basic(
        b"local co=coroutine.create(type); local ok,result=coroutine.resume(co,12); return ok,result",
    );
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"number");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_direct_native_print_coroutine_yields_and_cleans_roots() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local t=setmetatable({},{__tostring=function() coroutine.yield('pause'); return 'ready' end}); local co=coroutine.create(print); local a,b=coroutine.resume(co,t); local c,d=coroutine.resume(co); return a,b,c,d",
        HostServices::with_output(TestOutput(sink.clone(), false)), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native print coroutine 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Nil);
    assert_eq!(&*sink.borrow(), b"ready\n");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_native_protected_basic_error_and_nested_pcall_recover() {
    let (vm, values) = run_with_basic(
        b"local a=coroutine.create(pcall); local x,y,z=coroutine.resume(a,assert,false,'bad'); local b=coroutine.create(pcall); local p,q,r,s=coroutine.resume(b,pcall,assert,false,'nested'); return x,y,z,p,q,r,s",
    );
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[2]), b"bad");
    assert_eq!(values[3], Value::Boolean(true));
    assert_eq!(values[4], Value::Boolean(true));
    assert_eq!(values[5], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[6]), b"nested");
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_native_print_callback_fuel_abort_keeps_output_empty() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local t=setmetatable({},{__tostring=function() while true do end end}); local co=coroutine.create(print); return coroutine.resume(co,t)",
        HostServices::with_output(TestOutput(sink.clone(), false)), Some(160), true,
    );
    assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_native_protected_output_policy_and_host_fail_are_distinct() {
    let (vm, values) = run_with_basic(
        b"local co=coroutine.create(pcall); return coroutine.resume(co,print,'denied')",
    );
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[2]), b"E_HOST_POLICY_OUTPUT");
    assert_eq!(vm.roots().total_count(), 0);

    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(pcall); return coroutine.resume(co,print,'failed')",
        HostServices::with_output(TestOutput(sink.clone(), true)),
        None,
        true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("native pcall 應捕捉 host failure: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[2]), b"E_HOST_OUTPUT_FAILED");
    assert!(sink.borrow().is_empty());
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_pairs_native_tostring_preserves_nested_callback_yield() {
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__pairs=tostring,__tostring=function() coroutine.yield('pause'); return 'done' end}); local a,b,c,d=pairs(t); return a,b,c,d end); local x,y=coroutine.resume(co); local z,a,b,c,d=coroutine.resume(co); return x,y,z,a,b,c,d",
        HostServices::deny_all(), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("nested callback 應返回: {outcome:?}")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[3]), b"done");
    assert_eq!(values[4], Value::Nil);
    assert_eq!(values[5], Value::Nil);
    assert_eq!(values[6], Value::Nil);
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p13_a_pairs_native_print_nested_callback_writes_once() {
    let sink = Rc::new(RefCell::new(Vec::new()));
    let (vm, outcome) = run_with_basic_services(
        b"local co=coroutine.create(function() local t=setmetatable({},{__pairs=print,__tostring=function() coroutine.yield('pause'); return 'done' end}); return select('#',pairs(t)) end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d",
        HostServices::with_output(TestOutput(sink.clone(), false)), None, true,
    );
    let RunOutcome::Returned(values) = outcome else {
        panic!("nested print 應返回: {outcome:?}")
    };
    let (_, language, _) = profile();
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&vm, values[1]), b"pause");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(
        values[3],
        Value::Integer(if language == LanguageProfile::Lua54 {
            3
        } else {
            4
        })
    );
    assert_eq!(&*sink.borrow(), b"done\n");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_nested_native_pairs_error_clears_pending() {
    let (vm, values) =
        run_with_basic(b"local t=setmetatable({},{__pairs=print}); return pcall(pairs,t)");
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[1]), b"E_HOST_POLICY_OUTPUT");
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p13_a_pairs_and_ipairs_callback_fuel_abort_cleans_roots() {
    for source in [
        b"local t=setmetatable({},{__pairs=function() while true do end end}); return pcall(pairs,t)".as_slice(),
        b"local t=setmetatable({},{__index=function() while true do end end}); local iter,state,key=ipairs(t); return pcall(iter,state,key)".as_slice(),
    ] {
        let (vm, outcome) = run_with_basic_services(source, HostServices::deny_all(), Some(150), true);
        assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p13_a_native_xpcall_basic_body_preserves_handler_and_error() {
    let (vm, values) = run_with_basic(
        b"local co=coroutine.create(xpcall); return coroutine.resume(co,assert,function(e) return 'handled' end,false,'bad')",
    );
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(bytes(&vm, values[2]), b"handled");
    assert_eq!(vm.roots().total_count(), 0);
}

struct FormalVm {
    vm: Vm,
    environment: ObjectRef,
    environment_root: RootId,
}

impl FormalVm {
    fn new(services: HostServices) -> Self {
        let (_, _, runtime_profile) = profile();
        let mut vm = Vm::new_with_services(runtime_profile, services).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        vm.install_table_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        vm.install_math_builtins(environment).unwrap();
        vm.install_utf8_builtins(environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        vm.install_io_os_builtins(environment).unwrap();
        vm.install_debug_builtins(environment).unwrap();
        Self {
            vm,
            environment,
            environment_root,
        }
    }

    fn run(&mut self, source: &[u8], fuel: u64) -> FormalRun {
        let (_, language, _) = profile();
        let allocation_before = self.vm.allocation_trace();
        let ledger_before = self.vm.ledger_snapshot();
        let mut execution = self
            .vm
            .load_with_environment(compile(source, language), Value::Object(self.environment))
            .unwrap();
        execution.set_fuel(fuel).unwrap();
        let outcome = execution.run();
        let remaining = execution.fuel_remaining();
        drop(execution);
        FormalRun {
            outcome,
            trace: FormalTrace {
                initial: fuel,
                remaining,
                allocation_before,
                allocation_after: self.vm.allocation_trace(),
                ledger_before,
                ledger_after: self.vm.ledger_snapshot(),
                roots_after: self.vm.roots().total_count(),
            },
        }
    }

    fn release_environment(&mut self) {
        self.vm.remove_root(self.environment_root).unwrap();
    }
}

struct FormalTrace {
    initial: u64,
    remaining: u64,
    allocation_before: AllocationTrace,
    allocation_after: AllocationTrace,
    ledger_before: LedgerSnapshot,
    ledger_after: LedgerSnapshot,
    roots_after: usize,
}

struct FormalRun {
    outcome: Result<RunOutcome, RuntimeError>,
    trace: FormalTrace,
}

fn formal_returned(run: &FormalRun) -> &[Value] {
    match &run.outcome {
        Ok(RunOutcome::Returned(values)) => values,
        other => panic!("正式案例應返回 Lua 值: {other:?}"),
    }
}

fn formal_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

fn formal_value(vm: &Vm, value: Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Boolean(value) => format!("bool:{value}"),
        Value::Integer(value) => format!("int:{value}"),
        Value::Float(value) => format!("float:{value:?}"),
        Value::Object(object) if vm.object_kind(object) == Ok(ObjectKind::ByteString) => {
            format!("bytes:{}", formal_hex(&bytes(vm, value)))
        }
        other => panic!("正式案例的非純量值須先轉成可斷言結果: {other:?}"),
    }
}

fn formal_values(vm: &Vm, values: &[Value]) -> String {
    values
        .iter()
        .map(|value| formal_value(vm, *value))
        .collect::<Vec<_>>()
        .join(",")
}

fn record_lib_case(
    id: &str,
    actual: &str,
    diagnostic: &str,
    capability: &str,
    scenes: &[(&str, &FormalTrace)],
    resource_detail: &str,
) {
    assert!(!scenes.is_empty());
    let fuel = scenes
        .iter()
        .map(|(name, trace)| {
            assert!(trace.remaining <= trace.initial);
            format!(
                "{name}:initial={},remaining={},used={}",
                trace.initial,
                trace.remaining,
                trace.initial - trace.remaining
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    let allocation = scenes
        .iter()
        .map(|(name, trace)| {
            format!(
                "{name}:ordinals={}..{},committed={}..{},reserved={}",
                trace.allocation_before.next_ordinal,
                trace.allocation_after.next_ordinal,
                trace.ledger_before.committed,
                trace.ledger_after.committed,
                trace.ledger_after.reserved
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    let resource = format!(
        "{};{resource_detail}",
        scenes
            .iter()
            .map(|(name, trace)| {
                format!(
                    "{name}:roots={},reserved={}",
                    trace.roots_after, trace.ledger_after.reserved
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    );
    for field in [
        id,
        actual,
        diagnostic,
        capability,
        &fuel,
        &allocation,
        &resource,
    ] {
        assert!(!field.is_empty() && !field.contains(['\t', '\n', '\r']));
    }
    println!(
        "P13_CASE\t{id}\t{}\tstatus=PASS;actual={actual};diagnostic={diagnostic}\tcapability={capability}\tfuel={fuel}\tallocation={allocation}\tresource={resource}",
        profile().0
    );
}

#[test]
fn lib_case_001() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run("return #'蘋果',utf8.len('蘋果')".as_bytes(), 20_000);
    let values = formal_returned(&run);
    assert_eq!(values, &[Value::Integer(6), Value::Integer(2)]);
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-001",
        &actual,
        "byte-length-and-codepoints-asserted",
        "utf8=installed;host=deny",
        &[("length", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_002() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(
        b"local t=table.pack(1,nil,3); return t.n,select('#',table.unpack(t,1,t.n)),t[1],t[2],t[3]",
        20_000,
    );
    let values = formal_returned(&run);
    assert_eq!(
        values,
        &[
            Value::Integer(3),
            Value::Integer(3),
            Value::Integer(1),
            Value::Nil,
            Value::Integer(3)
        ]
    );
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-002",
        &actual,
        "pack-n-and-interior-nil-asserted",
        "table=installed;host=deny",
        &[("pack", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_003() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(b"return string.match('x=123','%d+')", 20_000);
    let values = formal_returned(&run);
    assert_eq!(values.len(), 1);
    assert_eq!(bytes(&formal.vm, values[0]), b"123");
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-003",
        &actual,
        "lua-pattern-digit-capture-asserted",
        "pattern=vm-local;host=deny",
        &[("match", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_004() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(b"package.preload['m']=function(name,data) assert(name=='m' and data==':preload:'); return nil end; local v,d=require('m'); return v,d,package.loaded.m,select('#',require('m'))", 40_000);
    let values = formal_returned(&run);
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(bytes(&formal.vm, values[1]), b":preload:");
    assert_eq!(values[2], Value::Boolean(true));
    assert_eq!(values[3], Value::Integer(1));
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-004",
        &actual,
        "nil-loader-publishes-true-and-data",
        "preload=vm-local;host=deny",
        &[("require", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_005() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(b"local searches,loads=0,0; package.searchers={function(name) assert(name=='m'); searches=searches+1; return function(n,d) assert(n=='m' and d=='payload'); loads=loads+1; return false end,'payload' end}; local a,ad=require('m'); local b,bd=require('m'); return a,ad,b,bd,searches,loads,package.loaded.m", 40_000);
    let values = formal_returned(&run);
    assert_eq!(values.len(), 7);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&formal.vm, values[1]), b"payload");
    assert_eq!(values[2], Value::Boolean(false));
    assert_eq!(bytes(&formal.vm, values[3]), b"payload");
    assert_eq!(
        &values[4..],
        &[Value::Integer(2), Value::Integer(2), Value::Boolean(false)]
    );
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-005",
        &actual,
        "false-cache-researched-twice",
        "searchers=mutable-vm-local;host=deny",
        &[("require-twice", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_006() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let huge = formal.run(b"return string.rep('a',1073741824,'!')", 10_000);
    let huge_actual = match (&huge.outcome, profile().2) {
        (Ok(RunOutcome::LuaError(error)), LuaProfile::Lua54) => {
            assert_eq!(error.kind, RuntimeErrorKind::StringArgument);
            format!("size:{:?}", error.kind)
        }
        (Ok(RunOutcome::Aborted(AbortReason::FuelExhausted)), LuaProfile::Lua55) => {
            "size:FuelExhausted".to_owned()
        }
        other => panic!("巨大 rep 應在配置前受控拒絕: {other:?}"),
    };
    assert_eq!(huge.trace.ledger_after.reserved, 0);
    assert!(huge.trace.ledger_after.committed < 1_000_000);

    let limit = formal.vm.ledger_snapshot().committed + 50_000;
    formal.vm.set_allocation_limit(limit);
    let budget = formal.run(b"return string.rep('x',100000)", 300_000);
    let budget_actual = match &budget.outcome {
        Err(error) => {
            assert_eq!(
                error.kind,
                RuntimeErrorKind::Heap(VmError::AllocationFailed)
            );
            format!("budget:{:?}", error.kind)
        }
        Ok(RunOutcome::LuaError(error)) => {
            assert_eq!(
                error.kind,
                RuntimeErrorKind::Heap(VmError::AllocationFailed)
            );
            format!("budget:{:?}", error.kind)
        }
        other => panic!("rep 應受配置額度拒絕: {other:?}"),
    };
    assert_eq!(budget.trace.ledger_after.reserved, 0);
    assert!(budget.trace.ledger_after.committed <= limit);
    let actual = format!("{huge_actual},{budget_actual}");
    record_lib_case(
        "LIB-006",
        &actual,
        "rep-size-fuel-and-allocation-preflight",
        "string=installed;allocation_limit=explicit;host=deny",
        &[("huge", &huge.trace), ("budget", &budget.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_007() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let inconsistent = formal.run(b"local t={3,1,2}; local ok=pcall(table.sort,t,function() return true end); return ok,table.concat(t,','),#t", 30_000);
    let values = formal_returned(&inconsistent);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&formal.vm, values[1]), b"3,1,2");
    assert_eq!(values[2], Value::Integer(3));
    let first = formal.vm.table_sort_trace();
    assert_eq!(
        (first.comparisons, first.swaps, first.stop),
        (2, 0, TableSortStop::InconsistentComparator)
    );
    let first_actual = formal_values(&formal.vm, values);

    let partial = formal.run(b"local n=0; local t={3,1,2}; local ok=pcall(table.sort,t,function(a,b) n=n+1; if n==3 then error('stop') end; return a<b end); return ok,table.concat(t,','),#t,n", 30_000);
    let values = formal_returned(&partial);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(bytes(&formal.vm, values[1]), b"1,3,2");
    assert_eq!(&values[2..], &[Value::Integer(3), Value::Integer(3)]);
    let second = formal.vm.table_sort_trace();
    assert_eq!(
        (second.comparisons, second.swaps, second.stop),
        (3, 1, TableSortStop::LuaError)
    );
    let actual = format!(
        "inconsistent:{first_actual};comparisons={};swaps={};stop={:?};partial:{};comparisons={};swaps={};stop={:?}",
        first.comparisons,
        first.swaps,
        first.stop,
        formal_values(&formal.vm, values),
        second.comparisons,
        second.swaps,
        second.stop
    );
    assert_eq!(partial.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-007",
        &actual,
        "comparator-stop-and-partial-table-valid",
        "table=installed;host=deny",
        &[
            ("inconsistent", &inconsistent.trace),
            ("partial", &partial.trace),
        ],
        "host_calls=0",
    );
}

#[test]
fn lib_case_008() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(b"return load('return 3')", 20_000);
    let error = match &run.outcome {
        Ok(RunOutcome::LuaError(error)) => error,
        other => panic!("未設定 compiler 應回 Lua policy error: {other:?}"),
    };
    assert_eq!(error.kind, RuntimeErrorKind::HostPolicyLoad);
    let actual = format!("{:?}", error.kind);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-008",
        &actual,
        "compiler-absent-load-policy",
        "compiler=absent;host=deny",
        &[("load", &run.trace)],
        "compiler_calls=0;system_lua_calls=0",
    );
}

#[test]
fn lib_case_009() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run(b"local bal=string.match('(a(b)c)','%b()'); local p,q=string.find(' hi','%f[%a]hi'); local a,b=string.match('name=abc','(%a+)=(%a+)'); local s,n=string.gsub('a1b2','%d','x'); local f,m=string.gsub('a1b2','%d',function(d) return tostring(tonumber(d)+1) end); local t,k=string.gsub('ab','%a',{a='X',b='Y'}); assert(bal=='(a(b)c)' and p==2 and q==3 and a=='name' and b=='abc' and s=='axbx' and n==2 and f=='a2b3' and m==2 and t=='XY' and k==2); return bal,p,q,a,b,s,n,f,m,t,k", 100_000);
    let values = formal_returned(&run);
    assert_eq!(values.len(), 11);
    assert_eq!(bytes(&formal.vm, values[0]), b"(a(b)c)");
    assert_eq!(&values[1..3], &[Value::Integer(2), Value::Integer(3)]);
    assert_eq!(bytes(&formal.vm, values[3]), b"name");
    assert_eq!(bytes(&formal.vm, values[4]), b"abc");
    assert_eq!(bytes(&formal.vm, values[5]), b"axbx");
    assert_eq!(values[6], Value::Integer(2));
    assert_eq!(bytes(&formal.vm, values[7]), b"a2b3");
    assert_eq!(values[8], Value::Integer(2));
    assert_eq!(bytes(&formal.vm, values[9]), b"XY");
    assert_eq!(values[10], Value::Integer(2));
    let actual = formal_values(&formal.vm, values);
    assert_eq!(run.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-009",
        &actual,
        "balanced-frontier-capture-gsub-three-replacements",
        "patterns=vm-local;host=deny",
        &[("patterns", &run.trace)],
        "host_calls=0",
    );
}

#[test]
fn lib_case_010() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let invalid = formal.run(b"local bad=string.char(0xff); local n,pos=utf8.len(bad); local iter,s,z=utf8.codes(bad); local ok=pcall(iter,s,z); local surrogate=utf8.char(0xd800); return bad,n,pos,ok,utf8.codepoint(surrogate,1,1,true),surrogate", 40_000);
    let values = formal_returned(&invalid);
    assert_eq!(bytes(&formal.vm, values[0]), &[0xff]);
    assert_eq!(
        &values[1..4],
        &[Value::Nil, Value::Integer(1), Value::Boolean(false)]
    );
    assert_eq!(values[4], Value::Integer(0xd800));
    assert_eq!(bytes(&formal.vm, values[5]), &[0xed, 0xa0, 0x80]);
    let first_actual = formal_values(&formal.vm, values);

    let boundary = formal.run(b"return utf8.offset(string.char(0x80),0,1)", 20_000);
    let second_actual = match (&boundary.outcome, profile().2) {
        (Ok(RunOutcome::LuaError(error)), LuaProfile::Lua55) => {
            assert_eq!(error.kind, RuntimeErrorKind::Utf8Sequence);
            format!("offset:{:?}", error.kind)
        }
        (Ok(RunOutcome::Returned(values)), LuaProfile::Lua54) => {
            assert_eq!(values, &[Value::Integer(1)]);
            format!("offset:{}", formal_values(&formal.vm, values))
        }
        other => panic!("profile UTF-8 offset 邊界: {other:?}"),
    };
    assert_eq!(boundary.trace.ledger_after.reserved, 0);
    record_lib_case(
        "LIB-010",
        &format!("{first_actual};{second_actual}"),
        "invalid-codes-lax-surrogate-and-profile-offset",
        "utf8=strict-and-lax;host=deny",
        &[("invalid", &invalid.trace), ("offset", &boundary.trace)],
        "host_calls=0;original_byte=ff",
    );
}

#[test]
fn lib_case_011() {
    let mut left = FormalVm::new(HostServices::deny_all());
    let lookup = left.run(b"package.preload.same=function(name,data) assert(name=='same' and data==':preload:'); return 'left' end; local a,ad=require('same'); package.searchers={function(name) if name=='custom' then return function(n,d) assert(n=='custom' and d==':data'); return n..d end,':data' end; return 27 end}; local b,bd=require('custom'); local missing,diagnostic=pcall(require,'gone'); local marker={}; package.searchers={function() return function() error(marker) end end}; local throws,err=pcall(require,'bad'); return a,ad,b,bd,missing,diagnostic,throws,err==marker,package.loaded.same,select('#',require('same'))", 80_000);
    let values = formal_returned(&lookup);
    assert_eq!(values.len(), 10);
    assert_eq!(bytes(&left.vm, values[0]), b"left");
    assert_eq!(bytes(&left.vm, values[1]), b":preload:");
    assert_eq!(bytes(&left.vm, values[2]), b"custom:data");
    assert_eq!(bytes(&left.vm, values[3]), b":data");
    assert_eq!(values[4], Value::Boolean(false));
    let diagnostic = bytes(&left.vm, values[5]);
    assert!(diagnostic.windows(2).any(|window| window == b"27"));
    assert_eq!(values[6], Value::Boolean(false));
    assert_eq!(values[7], Value::Boolean(true));
    assert_eq!(values[8], values[0]);
    assert_eq!(values[9], Value::Integer(1));
    let lookup_actual = formal_values(&left.vm, values);

    let recursive = left.run(b"package.searchers={function() return function(name) return require(name) end end}; return require('loop')", 240);
    assert_eq!(
        recursive.outcome,
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    assert_eq!(recursive.trace.ledger_after.reserved, 0);
    let mut right = FormalVm::new(HostServices::deny_all());
    let independent = right.run(b"package.preload.same=function() return 'right' end; local x=require('same'); return x,package.loaded.same", 40_000);
    let right_values = formal_returned(&independent);
    assert_eq!(bytes(&right.vm, right_values[0]), b"right");
    assert_eq!(right_values[0], right_values[1]);
    let actual = format!(
        "lookup:{lookup_actual};recursive:FuelExhausted;other-vm:{}",
        formal_values(&right.vm, right_values)
    );
    record_lib_case(
        "LIB-011",
        &actual,
        "preload-custom-data-numeric-missing-original-error-recursion-vm-cache",
        "package=vm-local;host=deny",
        &[
            ("lookup", &lookup.trace),
            ("recursive", &recursive.trace),
            ("other-vm", &independent.trace),
        ],
        "host_calls=0;vm_count=2",
    );
}

#[test]
fn lib_case_012() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let io = formal.run(b"return io.open('hidden','r')", 20_000);
    let io_kind = match &io.outcome {
        Ok(RunOutcome::LuaError(error)) => error.kind,
        other => panic!("io policy: {other:?}"),
    };
    assert_eq!(io_kind, RuntimeErrorKind::HostPolicyIo);
    let os = formal.run(b"return os.getenv('HOME')", 20_000);
    let os_kind = match &os.outcome {
        Ok(RunOutcome::LuaError(error)) => error.kind,
        other => panic!("os policy: {other:?}"),
    };
    assert_eq!(os_kind, RuntimeErrorKind::HostPolicyOs);
    let debug = formal.run(b"return debug.setmetatable({}, {})", 20_000);
    let debug_kind = match &debug.outcome {
        Ok(RunOutcome::LuaError(error)) => error.kind,
        other => panic!("debug mutation policy: {other:?}"),
    };
    assert_eq!(debug_kind, RuntimeErrorKind::HostPolicyDebug);

    let native_calls = Rc::new(Cell::new(0));
    let load = LoadCapability::deny_all().and_native_loader(DenyingNative(native_calls.clone()));
    let mut native = FormalVm::new(HostServices::deny_all().and_load(load));
    let denied = native.run(b"return require('denied')", 30_000);
    let native_kind = match &denied.outcome {
        Ok(RunOutcome::LuaError(error)) => {
            assert_eq!(bytes(&native.vm, error.value), b"native denied");
            error.kind
        }
        other => panic!("native provider policy: {other:?}"),
    };
    assert_eq!(native_kind, RuntimeErrorKind::HostPolicyNative);
    assert_eq!(native_calls.get(), 1);
    for trace in [&io.trace, &os.trace, &debug.trace, &denied.trace] {
        assert_eq!(trace.ledger_after.reserved, 0);
    }
    let actual =
        format!("io:{io_kind:?};os:{os_kind:?};debug:{debug_kind:?};native:{native_kind:?}");
    record_lib_case(
        "LIB-012",
        &actual,
        "four-typed-policy-denials-without-implicit-resource-effects",
        "io=absent;os=absent;debug=deny;native=configured-deny",
        &[
            ("io", &io.trace),
            ("os", &os.trace),
            ("debug", &debug.trace),
            ("native", &denied.trace),
        ],
        &format!(
            "io_calls=0;os_calls=0;debug_host_calls=0;native_calls={}",
            native_calls.get()
        ),
    );
}

struct FormalOutput {
    bytes: Rc<RefCell<Vec<u8>>>,
    calls: Rc<Cell<usize>>,
    fail: bool,
}

impl HostOutput for FormalOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(HostOutputError::WriteFailed);
        }
        self.bytes.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn lib_case_013() {
    let left_bytes = Rc::new(RefCell::new(Vec::new()));
    let right_bytes = Rc::new(RefCell::new(Vec::new()));
    let left_calls = Rc::new(Cell::new(0));
    let right_calls = Rc::new(Cell::new(0));
    let left_output = FormalOutput {
        bytes: left_bytes.clone(),
        calls: left_calls.clone(),
        fail: false,
    };
    let right_output = FormalOutput {
        bytes: right_bytes.clone(),
        calls: right_calls.clone(),
        fail: false,
    };
    let mut left = FormalVm::new(HostServices::with_output(left_output));
    let mut right = FormalVm::new(HostServices::with_output(right_output));
    let left_run = left.run(b"local prior=string.private; package.preload.same=function() return 'left' end; local m=require('same'); math.randomseed(1,2); local r=math.random(0); string.private='left'; print('left'); return prior,m,package.loaded.same,r,string.private", 60_000);
    let right_run = right.run(b"local prior=string.private; package.preload.same=function() return 'right' end; local m=require('same'); math.randomseed(3,4); local r=math.random(0); string.private='right'; print('right'); return prior,m,package.loaded.same,r,string.private", 60_000);
    let lv = formal_returned(&left_run);
    let rv = formal_returned(&right_run);
    assert_eq!(lv[0], Value::Nil);
    assert_eq!(rv[0], Value::Nil);
    assert_eq!(bytes(&left.vm, lv[1]), b"left");
    assert_eq!(bytes(&right.vm, rv[1]), b"right");
    assert_eq!(lv[1], lv[2]);
    assert_eq!(rv[1], rv[2]);
    assert_ne!(lv[3], rv[3]);
    assert_eq!(bytes(&left.vm, lv[4]), b"left");
    assert_eq!(bytes(&right.vm, rv[4]), b"right");
    assert_eq!(&*left_bytes.borrow(), b"left\n");
    assert_eq!(&*right_bytes.borrow(), b"right\n");
    assert_eq!((left_calls.get(), right_calls.get()), (1, 1));
    let first_random = lv[3];
    let second_random = rv[3];
    let left_replay = left.run(
        b"math.randomseed(1,2); return math.random(0),string.private,package.loaded.same",
        30_000,
    );
    let right_replay = right.run(
        b"math.randomseed(3,4); return math.random(0),string.private,package.loaded.same",
        30_000,
    );
    assert_eq!(formal_returned(&left_replay)[0], first_random);
    assert_eq!(formal_returned(&right_replay)[0], second_random);
    assert_eq!(bytes(&left.vm, formal_returned(&left_replay)[1]), b"left");
    assert_eq!(
        bytes(&right.vm, formal_returned(&right_replay)[1]),
        b"right"
    );
    let actual = format!(
        "left:{};right:{};left-replay:{};right-replay:{}",
        formal_values(&left.vm, lv),
        formal_values(&right.vm, rv),
        formal_values(&left.vm, formal_returned(&left_replay)),
        formal_values(&right.vm, formal_returned(&right_replay))
    );
    record_lib_case(
        "LIB-013",
        &actual,
        "two-vms-isolate-package-rng-output-and-mutable-library",
        "output=two-explicit-sinks;entropy=seeded;package=vm-local",
        &[
            ("left", &left_run.trace),
            ("right", &right_run.trace),
            ("left-replay", &left_replay.trace),
            ("right-replay", &right_replay.trace),
        ],
        &format!(
            "left_output_calls={};right_output_calls={};left_output_hex={};right_output_hex={}",
            left_calls.get(),
            right_calls.get(),
            formal_hex(&left_bytes.borrow()),
            formal_hex(&right_bytes.borrow())
        ),
    );
}

#[test]
fn lib_case_014() {
    let output_bytes = Rc::new(RefCell::new(Vec::new()));
    let output_calls = Rc::new(Cell::new(0));
    let output = FormalOutput {
        bytes: output_bytes.clone(),
        calls: output_calls.clone(),
        fail: true,
    };
    let mut formal = FormalVm::new(HostServices::with_output(output));
    let fuel = formal.run(b"return string.rep('x',100000)", 200);
    assert_eq!(
        fuel.outcome,
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    let lua = formal.run(b"error('marker')", 20_000);
    let lua_error = match &lua.outcome {
        Ok(RunOutcome::LuaError(error)) => error,
        other => panic!("Lua error: {other:?}"),
    };
    assert_eq!(lua_error.kind, RuntimeErrorKind::Thrown);
    assert_eq!(bytes(&formal.vm, lua_error.value), b"marker");
    let host = formal.run(b"print('rejected')", 20_000);
    let host_kind = match &host.outcome {
        Ok(RunOutcome::LuaError(error)) => error.kind,
        other => panic!("host output: {other:?}"),
    };
    assert_eq!(host_kind, RuntimeErrorKind::HostOutputFailed);
    assert_eq!(output_calls.get(), 1);
    assert!(output_bytes.borrow().is_empty());
    let sort = formal.run(b"local n=0; local t={3,1,2}; local ok=pcall(table.sort,t,function(a,b) n=n+1; if n==3 then error('stop') end; return a<b end); return ok,table.concat(t,','),#t,n", 30_000);
    let sort_values = formal_returned(&sort);
    assert_eq!(sort_values[0], Value::Boolean(false));
    assert_eq!(bytes(&formal.vm, sort_values[1]), b"1,3,2");
    assert_eq!(&sort_values[2..], &[Value::Integer(3), Value::Integer(3)]);
    let sort_trace = formal.vm.table_sort_trace();
    assert_eq!(
        (sort_trace.comparisons, sort_trace.swaps, sort_trace.stop),
        (3, 1, TableSortStop::LuaError)
    );
    let sort_actual = formal_values(&formal.vm, sort_values);
    let allocation_limit = formal.vm.ledger_snapshot().committed + 50_000;
    formal.vm.set_allocation_limit(allocation_limit);
    let allocation = formal.run(b"return string.rep('x',100000)", 300_000);
    let allocation_kind = match &allocation.outcome {
        Ok(RunOutcome::LuaError(error)) => error.kind,
        Err(error) => error.kind,
        other => panic!("allocation limit: {other:?}"),
    };
    assert_eq!(
        allocation_kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    assert!(allocation.trace.ledger_after.committed <= allocation_limit);
    for trace in [
        &fuel.trace,
        &lua.trace,
        &host.trace,
        &sort.trace,
        &allocation.trace,
    ] {
        assert_eq!(trace.ledger_after.reserved, 0);
    }
    let actual_before_other = format!(
        "fuel:FuelExhausted;lua:{:?}:{};host:{host_kind:?};sort:{sort_actual};comparisons={};swaps={};stop={:?};allocation:{allocation_kind:?}",
        lua_error.kind,
        formal_hex(&bytes(&formal.vm, lua_error.value)),
        sort_trace.comparisons,
        sort_trace.swaps,
        sort_trace.stop
    );
    drop(lua.outcome);
    drop(host.outcome);
    drop(allocation.outcome);
    let root_before_release = formal.vm.roots().total_count();
    assert_eq!(root_before_release, 5);
    formal.release_environment();
    assert_eq!(formal.vm.roots().total_count(), root_before_release - 1);
    formal.vm.collect().unwrap();
    let cleaned_roots = formal.vm.roots().total_count();
    assert_eq!(cleaned_roots, 4);
    assert_eq!(formal.vm.ledger_snapshot().reserved, 0);
    let mut independent = FormalVm::new(HostServices::deny_all());
    let other = independent.run(b"return type(print),package.loaded.missing,42", 20_000);
    let other_values = formal_returned(&other);
    assert_eq!(bytes(&independent.vm, other_values[0]), b"function");
    assert_eq!(&other_values[1..], &[Value::Nil, Value::Integer(42)]);
    assert_eq!(other.trace.ledger_after.reserved, 0);
    let actual = format!(
        "{actual_before_other};other:{}",
        formal_values(&independent.vm, other_values)
    );
    record_lib_case(
        "LIB-014",
        &actual,
        "error-classes-sort-progress-clean-gc-and-other-vm",
        "output=explicit-failing-sink;allocation_limit=explicit;other-vm=deny",
        &[
            ("fuel", &fuel.trace),
            ("lua", &lua.trace),
            ("host", &host.trace),
            ("sort", &sort.trace),
            ("allocation", &allocation.trace),
            ("other", &other.trace),
        ],
        &format!(
            "output_calls={};output_bytes={};roots_after_collect={};reserved_after_collect={};vm_count=2",
            output_calls.get(),
            output_bytes.borrow().len(),
            cleaned_roots,
            formal.vm.ledger_snapshot().reserved
        ),
    );
}

#[test]
fn p13_math_utf8_mixed_boundary_regression() {
    let mut formal = FormalVm::new(HostServices::deny_all());
    let run = formal.run("local n=utf8.len('蘋果'); local cp=utf8.codepoint('蘋果',1,3); local rounded=math.floor(n*1.5); local clipped=math.min(cp,0x1f34e); local bad=pcall(utf8.char,math.maxinteger); return n,rounded,clipped,math.type(cp),utf8.char(clipped),utf8.len(utf8.char(clipped)),bad".as_bytes(), 40_000);
    let values = formal_returned(&run);
    assert_eq!(values.len(), 7);
    assert_eq!(
        &values[..3],
        &[Value::Integer(2), Value::Integer(3), Value::Integer(0x860b)]
    );
    assert_eq!(bytes(&formal.vm, values[3]), b"integer");
    assert_eq!(bytes(&formal.vm, values[4]), "蘋".as_bytes());
    assert_eq!(values[5], Value::Integer(1));
    assert_eq!(values[6], Value::Boolean(false));
    assert_eq!(run.trace.ledger_after.reserved, 0);
}
