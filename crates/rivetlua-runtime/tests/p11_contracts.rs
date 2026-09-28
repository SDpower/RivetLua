use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{ObjectRef, Value, VerifyLimits};
use rivetlua_runtime::{AbortReason, HostHandle, ObjectKind, RunOutcome, Vm};

fn profile() -> (LanguageProfile, String) {
    let name = std::env::var("RIVETLUA_P11_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match name.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P11 profile 無效"),
    };
    (profile, name)
}

fn compile(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
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

#[test]
fn review_builtin_close_event_yield_continues_once() {
    let (profile, _) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = coroutine_environment(&mut vm);
    let closer = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_closer = vm.allocate_byte_string(b"closer").unwrap();
    vm.raw_set(env, Value::Object(key_closer), Value::Object(closer))
        .unwrap();
    vm.set_metatable(closer, Some(metatable)).unwrap();
    let key_coroutine = vm.allocate_byte_string(b"coroutine").unwrap();
    let Value::Object(coroutine) = vm.raw_get(env, Value::Object(key_coroutine)).unwrap() else {
        panic!("coroutine table 必須存在")
    };
    let key_yield = vm.allocate_byte_string(b"yield").unwrap();
    let builtin = vm.raw_get(coroutine, Value::Object(key_yield)).unwrap();
    let key_close = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(metatable, Value::Object(key_close), builtin)
        .unwrap();
    vm.set_collect_every_allocation(true);
    let source = b"local co=coroutine.create(function() local x <close> = closer; return 5 end); local ok,a=coroutine.resume(co); local ok2,b=coroutine.resume(co,7); return ok,a==closer,ok2,b";
    let mut execution = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(5),
        ]))
    );
    drop(execution);
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn review_builtin_close_event_error_preserves_replacement_value() {
    let (profile, _) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = environment(&mut vm);
    let closer = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_closer = vm.allocate_byte_string(b"closer").unwrap();
    vm.raw_set(env, Value::Object(key_closer), Value::Object(closer))
        .unwrap();
    vm.set_metatable(closer, Some(metatable)).unwrap();
    let key_error = vm.allocate_byte_string(b"error").unwrap();
    let builtin = vm.raw_get(env, Value::Object(key_error)).unwrap();
    let key_close = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(metatable, Value::Object(key_close), builtin)
        .unwrap();
    vm.set_collect_every_allocation(true);
    let source =
        b"local ok,e=pcall(function() local x <close> = closer; error(9) end); return ok,e==closer";
    let mut execution = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Boolean(false),
            Value::Boolean(true)
        ]))
    );
    drop(execution);
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

fn environment(vm: &mut Vm) -> (ObjectRef, HostHandle<Value>) {
    let table = vm.allocate_table().unwrap();
    let root = HostHandle::<Value>::new(vm, table).unwrap();
    vm.install_error_builtins(table).unwrap();
    (table, root)
}

fn coroutine_environment(vm: &mut Vm) -> (ObjectRef, HostHandle<Value>) {
    let (table, root) = environment(vm);
    vm.install_coroutine_builtins(table).unwrap();
    (table, root)
}

fn close_environment(
    vm: &mut Vm,
    profile: LanguageProfile,
) -> (
    ObjectRef,
    HostHandle<Value>,
    ObjectRef,
    ObjectRef,
    ObjectRef,
) {
    let (env, root) = environment(vm);
    let log = vm.allocate_table().unwrap();
    let first = vm.allocate_table().unwrap();
    let second = vm.allocate_table().unwrap();
    for (name, object) in [(b"log".as_slice(), log), (b"one", first), (b"two", second)] {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.raw_set(env, Value::Object(key), Value::Object(object))
            .unwrap();
    }
    let outcome = vm
        .load_with_environment(
            compile(
                b"return function(v,e) log[#log+1]=v; log.error=e end",
                profile,
            ),
            Value::Object(env),
        )
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("close handler 應產生 closure")
    };
    let Value::Object(handler) = values[0] else {
        panic!("close handler 應為 closure")
    };
    let mt = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(mt, Value::Object(key), Value::Object(handler))
        .unwrap();
    vm.set_metatable(first, Some(mt)).unwrap();
    vm.set_metatable(second, Some(mt)).unwrap();
    (env, root, log, first, second)
}

fn install_close_handler(
    vm: &mut Vm,
    env: ObjectRef,
    profile: LanguageProfile,
    object: ObjectRef,
    source: &[u8],
) {
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("close handler 必須返回 closure")
    };
    let mt = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(mt, Value::Object(key), values[0]).unwrap();
    vm.set_metatable(object, Some(mt)).unwrap();
}

fn put_name(vm: &mut Vm, env: ObjectRef, name: &[u8], value: Value) {
    let key = vm.allocate_byte_string(name).unwrap();
    vm.raw_set(env, Value::Object(key), value).unwrap();
}

#[test]
fn err_case_005_close_failure_continues_and_replaces_error() {
    let (profile, name) = profile();
    for source in [
        b"local ok,e=pcall(function() local a <close> = one; local b <close> = two; error(9) end); return ok,e".as_slice(),
        b"local a <close> = one; local b <close> = two; return 7".as_slice(),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, second) = close_environment(&mut vm, profile);
        let new_error = vm.allocate_table().unwrap();
        put_name(&mut vm, env, b"new_error", Value::Object(new_error));
        install_close_handler(
            &mut vm,
            env,
            profile,
            second,
            b"return function(v,e) log[#log+1]=v; error(new_error) end",
        );
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        match outcome {
            RunOutcome::Returned(values) => {
                assert_eq!(values, vec![Value::Boolean(false), Value::Object(new_error)]);
            }
            RunOutcome::LuaError(error) => assert_eq!(error.value, Value::Object(new_error)),
            other => panic!("close error 應回傳原值：{other:?}"),
        }
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(second)));
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
        let key = vm.allocate_byte_string(b"error").unwrap();
        assert_eq!(vm.raw_get(log, Value::Object(key)), Ok(Value::Object(new_error)));
    }
    println!("P11_STAGE\terr_case_005\t{name}\tstatus=PASS;continued=LIFO;error=identity");
}

#[test]
fn err_case_003_pcall_fuel_abort_remains_host_terminal() {
    let (profile, name) = profile();
    for source in [
        b"return pcall(function() while true do end end)".as_slice(),
        b"return xpcall(function() error({}) end,function(e) while true do end end)".as_slice(),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, env_root) = environment(&mut vm);
        let mut execution = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap();
        execution.set_fuel(80).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(
            execution.run().unwrap_err().kind,
            rivetlua_runtime::RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(100).unwrap_err().kind,
            rivetlua_runtime::RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 1);
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    println!("P11_STAGE\terr_case_003\t{name}\tstatus=PASS;abort=host;terminal=true");
}

#[test]
fn close_case_004_reentrant_close_and_xpcall_handler_survive_gc() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root, log, first, _) = close_environment(&mut vm, profile);
    vm.install_coroutine_builtins(env).unwrap();
    install_close_handler(
        &mut vm,
        env,
        profile,
        first,
        b"return function(v,e) local f=function(x) return x end; local co=coroutine.create(function() return e end); local ok,x=coroutine.resume(co); for i=1,8 do local t={i} end; log[#log+1]=v; log.error=f(x); log.resume_ok=ok end",
    );
    vm.set_collect_every_allocation(true);
    let source = b"local original={}; local ok,value=xpcall(function() local x <close> = one; error(original) end,function(e) local f=function(x) return x end; for i=1,8 do local t={i} end; log.handler=f(e); return e end); return ok,value,original";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("xpcall 必須回傳 close 後的錯誤物件")
    };
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(values[1], values[2]);
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
    for key in [b"error".as_slice(), b"handler".as_slice()] {
        let key = vm.allocate_byte_string(key).unwrap();
        assert_eq!(vm.raw_get(log, Value::Object(key)), Ok(values[2]));
    }
    let key = vm.allocate_byte_string(b"resume_ok").unwrap();
    assert_eq!(
        vm.raw_get(log, Value::Object(key)),
        Ok(Value::Boolean(true))
    );
    let Value::Object(original) = values[2] else {
        panic!("原始 error 應維持 table handle")
    };
    assert_eq!(vm.object_kind(original), Ok(ObjectKind::Table));
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P11_STAGE\tclose_case_004\t{name}\tstatus=PASS;reentry=once;gc=forced");
}

#[test]
fn close_case_005_coroutine_hard_abort_is_not_close_or_resume_tuple() {
    let (profile, name) = profile();
    for in_close in [false, true] {
        let mut vm = Vm::new().unwrap();
        let (env, env_root, _log, first, _) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        if in_close {
            install_close_handler(
                &mut vm,
                env,
                profile,
                first,
                b"return function(v,e) while true do end end",
            );
        }
        let source = if in_close {
            b"local co=coroutine.create(function() local x <close> = one; return 7 end); return coroutine.resume(co)".as_slice()
        } else {
            b"local co=coroutine.create(function() local x <close> = one; while true do end end); return coroutine.resume(co)".as_slice()
        };
        let mut execution = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap();
        execution.set_fuel(100).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(
            execution.run().unwrap_err().kind,
            rivetlua_runtime::RuntimeErrorKind::TerminalExecution
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 1);
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    println!("P11_STAGE\tclose_case_005\t{name}\tstatus=PASS;abort=host;close=unpromised");
}

#[test]
fn cor_case_005_close_suspended_error_and_invalid_state() {
    let (profile, name) = profile();
    for (source, expected) in [
        (
            b"local co=coroutine.create(function() local x <close> = one; coroutine.yield(4) end); local ok,v=coroutine.resume(co); local closed=coroutine.close(co); return ok,v,closed,coroutine.status(co)".as_slice(),
            vec![Value::Boolean(true), Value::Integer(4), Value::Boolean(true)],
        ),
        (
            b"local co=coroutine.create(function() local x <close> = one; error(9) end); local ok,e=coroutine.resume(co); local closed,err=coroutine.close(co); return ok,e,closed,err,coroutine.status(co)".as_slice(),
            vec![Value::Boolean(false), Value::Integer(9), Value::Boolean(false), Value::Integer(9)],
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("coroutine.close 須正常回傳 tuple")
        };
        assert_eq!(&values[..expected.len()], expected.as_slice());
        let Value::Object(status) = values[expected.len()] else {
            panic!("close 後 status 應是 byte string")
        };
        assert_eq!(vm.with_byte_string(status, |s| s.as_bytes().to_vec()).unwrap(), b"dead");
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, second) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        let new_error = vm.allocate_table().unwrap();
        put_name(&mut vm, env, b"new_error", Value::Object(new_error));
        install_close_handler(
            &mut vm,
            env,
            profile,
            second,
            b"return function(v,e) log[#log+1]=v; error(new_error) end",
        );
        vm.set_collect_every_allocation(true);
        let source = b"local co=coroutine.create(function() local a <close> = one; local b <close> = two; coroutine.yield() end); coroutine.resume(co); local ok,e=coroutine.close(co); return ok,e,coroutine.status(co)";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("close handler error 必須回 false,error")
        };
        assert_eq!(
            values[0..2],
            [Value::Boolean(false), Value::Object(new_error)]
        );
        let Value::Object(status) = values[2] else {
            panic!("close 後須為 Dead")
        };
        assert_eq!(
            vm.with_byte_string(status, |s| s.as_bytes().to_vec())
                .unwrap(),
            b"dead"
        );
        assert_eq!(
            vm.raw_get(log, Value::Integer(1)),
            Ok(Value::Object(second))
        );
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
        let key = vm.allocate_byte_string(b"error").unwrap();
        assert_eq!(
            vm.raw_get(log, Value::Object(key)),
            Ok(Value::Object(new_error))
        );
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root) = coroutine_environment(&mut vm);
        let source = b"local co; co=coroutine.create(function() return coroutine.close(co) end); local ok,e=coroutine.resume(co); local valid,value=pcall(coroutine.close,{}); return ok,valid,coroutine.status(co)";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("self-close 應失敗且主執行可續行")
        };
        assert_eq!(values[0], Value::Boolean(false));
        assert_eq!(values[1], Value::Boolean(false));
        let Value::Object(status) = values[2] else {
            panic!("self-close 後協程須為 Dead")
        };
        assert_eq!(
            vm.with_byte_string(status, |s| s.as_bytes().to_vec())
                .unwrap(),
            b"dead"
        );
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        vm.set_collect_every_allocation(true);
        let source = b"local co=coroutine.create(xpcall); local a,b,c=coroutine.resume(co,function() local x <close> = one; error(9) end,function(e) return e end); local d,e=coroutine.close(co); return a,b,c,d,e";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(false),
                Value::Integer(9),
                Value::Boolean(true),
                Value::Nil,
            ])
        );
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    }
    println!("P11_STAGE\tcor_case_005\t{name}\tstatus=PASS;suspended+error=closed");
}

#[test]
fn cor_case_006_wrap_unwraps_results_and_closes_on_error() {
    let (profile, name) = profile();
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root) = coroutine_environment(&mut vm);
        let source = b"local f=coroutine.wrap(function(x) return x,nil,9 end); return f(7)";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(7), Value::Nil, Value::Integer(9)])
        );
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        vm.set_collect_every_allocation(true);
        let source = b"local f=coroutine.wrap(function() local x <close> = one; local next=coroutine.yield(4); return next,9 end); local a=f(); local b,c=f(7); return a,b,c";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Integer(4),
                Value::Integer(7),
                Value::Integer(9)
            ])
        );
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        let original = vm.allocate_table().unwrap();
        put_name(&mut vm, env, b"original", Value::Object(original));
        vm.set_collect_every_allocation(true);
        let source = b"local f=coroutine.wrap(function() local x <close> = one; error(original) end); return pcall(f)";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Boolean(false), Value::Object(original)])
        );
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    }
    {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, second) = close_environment(&mut vm, profile);
        vm.install_coroutine_builtins(env).unwrap();
        let original = vm.allocate_table().unwrap();
        let replacement = vm.allocate_table().unwrap();
        put_name(&mut vm, env, b"original", Value::Object(original));
        put_name(&mut vm, env, b"replacement", Value::Object(replacement));
        install_close_handler(
            &mut vm,
            env,
            profile,
            second,
            b"return function(v,e) log[#log+1]=v; error(replacement) end",
        );
        vm.set_collect_every_allocation(true);
        let source = b"local f=coroutine.wrap(function() local a <close> = one; local b <close> = two; error(original) end); return pcall(f)";
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Boolean(false), Value::Object(replacement)])
        );
        assert_eq!(
            vm.raw_get(log, Value::Integer(1)),
            Ok(Value::Object(second))
        );
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
    }
    println!("P11_STAGE\tcor_case_006\t{name}\tstatus=PASS;wrap=unboxed+close_error");
}

#[test]
fn cor_case_005_new_builtin_can_be_coroutine_body() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root, log, first, _) = close_environment(&mut vm, profile);
    vm.install_coroutine_builtins(env).unwrap();
    vm.set_collect_every_allocation(true);
    let source = b"local target=coroutine.create(function() local x <close> = one; coroutine.yield() end); coroutine.resume(target); local closer=coroutine.create(coroutine.close); local ok,closed=coroutine.resume(closer,target); return ok,closed,coroutine.status(target)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("coroutine.close 原生 body 必須回到 resume")
    };
    assert_eq!(values[0..2], [Value::Boolean(true), Value::Boolean(true)]);
    let Value::Object(status) = values[2] else {
        panic!("target 應為 Dead")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"dead"
    );
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    println!("P11_STAGE\tcor_case_005_native\t{name}\tstatus=PASS;body=close");
}

#[test]
fn cor_case_006_new_wrapper_can_be_coroutine_body() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root) = coroutine_environment(&mut vm);
    let source = b"local maker=coroutine.create(coroutine.wrap); local ok,f=coroutine.resume(maker,function(x) return x,9 end); local body=coroutine.create(f); local resumed,a,b=coroutine.resume(body,7); return ok,resumed,a,b";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(9),
        ])
    );
    let mut vm = Vm::new().unwrap();
    let (env, _root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local f=coroutine.wrap(function() return {} end); local body=coroutine.create(f); return coroutine.resume(body)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("包裝協程的物件結果應可返回")
    };
    assert_eq!(values[0], Value::Boolean(true));
    let Value::Object(object) = values[1] else {
        panic!("包裝協程應返回原 table")
    };
    assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
    println!("P11_STAGE\tcor_case_006_native\t{name}\tstatus=PASS;body=wrap");
}

#[test]
fn close_case_001_lifo_return_and_nil_false_skip() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root, log, first, second) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let result = vm.load_with_environment(
        compile(b"local a <close> = one; local b <close> = nil; local c <close> = false; local d <close> = two; return 7", profile),
        Value::Object(env),
    ).unwrap().run().unwrap();
    assert_eq!(result, RunOutcome::Returned(vec![Value::Integer(7)]));
    assert_eq!(
        vm.raw_get(log, Value::Integer(1)),
        Ok(Value::Object(second))
    );
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
    assert_eq!(vm.raw_get(log, Value::Integer(3)), Ok(Value::Nil));
    println!("P11_STAGE\tclose_case_001_lifo\t{name}\tstatus=PASS;order=LIFO;gc=forced");
}

#[test]
fn close_case_002_block_goto_break_and_generic_fourth() {
    let (profile, name) = profile();
    for source in [
        b"do local x <close> = one end; return 7".as_slice(),
        b"do local x <close> = one; goto done end ::done:: return 7".as_slice(),
        b"while true do local x <close> = one; break end; return 7".as_slice(),
        b"local function iter() return nil end; for k in iter,nil,nil,one do end; return 7"
            .as_slice(),
        b"local function iter() return 1 end; for k in iter,nil,nil,one do break end; return 7"
            .as_slice(),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(7)]),
            "{source:?}"
        );
        assert_eq!(
            vm.raw_get(log, Value::Integer(1)),
            Ok(Value::Object(first)),
            "{source:?}"
        );
        assert_eq!(
            vm.raw_get(log, Value::Integer(2)),
            Ok(Value::Nil),
            "{source:?}"
        );
    }
    println!("P11_STAGE\tclose_case_002_paths\t{name}\tstatus=PASS;paths=5;gc=forced");
}

#[test]
fn err_case_004_protected_close_receives_original_error() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root, log, first, second) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let source = b"local ok,e=pcall(function() local a <close> = one; local function inner() local b <close> = two; error(9) end; inner() end); return ok,e";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(9)])
    );
    assert_eq!(
        vm.raw_get(log, Value::Integer(1)),
        Ok(Value::Object(second))
    );
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
    let key = vm.allocate_byte_string(b"error").unwrap();
    assert_eq!(vm.raw_get(log, Value::Object(key)), Ok(Value::Integer(9)));
    println!("P11_STAGE\terr_case_004_close\t{name}\tstatus=PASS;error=original;order=LIFO");
}

#[test]
fn close_case_003_coroutine_body_error_keeps_close_entry() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root, log, _, _) = close_environment(&mut vm, profile);
    vm.install_coroutine_builtins(env).unwrap();
    let source = b"local co=coroutine.create(function() local x <close> = one; error(9) end); local ok,e=coroutine.resume(co); return ok,e";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(9)])
    );
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Nil));
    println!("P11_STAGE\tclose_case_003_coroutine\t{name}\tstatus=PASS;auto_close=false");
}

#[test]
fn close_case_001_generic_for_normal_and_break_close_once() {
    let (profile, name) = profile();
    for (source, expected_log_len) in [
        (
            b"local function iter() return nil end; for k in iter,nil,nil,one do end; return 7"
                .as_slice(),
            1,
        ),
        (
            b"local function iter() return 1 end; for k in iter,nil,nil,one do break end; return 7"
                .as_slice(),
            1,
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
        assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
        assert_eq!(expected_log_len, 1);
    }
    println!(
        "P11_CASE\tCLOSE-001\t{name}\tstatus=PASS;actual=normal:close-once,break:close-once;diagnostic=generic-for-fourth-binding-observed;metamethod=__close;gc=forced"
    );
}

#[test]
fn close_case_002_generic_for_protected_error_passes_original_value() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _root, log, first, _) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let source = b"local original={}; local n=0; local function iter() n=n+1; if n==1 then return 1 end end; local ok,e=pcall(function() for k in iter,nil,nil,one do error(original) end end); return ok,e,original";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("generic-for close error 必須由 pcall 捕捉")
    };
    assert_eq!(values.len(), 3);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(
        values[1], values[2],
        "protected close 必須保留原 error identity"
    );
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    let error_key = vm.allocate_byte_string(b"error").unwrap();
    assert_eq!(vm.raw_get(log, Value::Object(error_key)), Ok(values[2]));
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
    println!(
        "P11_CASE\tCLOSE-002\t{name}\tstatus=PASS;actual=protected-false;error-identity=preserved;close-count=1;diagnostic=generic-for-fourth-binding;close-handler-received-inflight-error;pcall-boundary"
    );
}

#[test]
fn close_case_003_return_and_goto_close_before_transfer() {
    let (profile, name) = profile();
    for source in [
        b"local function f() do local x <close> = one; return 9 end end; local result=f(); return result,#log,log[1]".as_slice(),
        b"do local x <close> = one; goto finished end; ::finished:: return #log,log[1]".as_slice(),
    ] {
        let mut vm = Vm::new().unwrap();
        let (env, _root, log, first, _) = close_environment(&mut vm, profile);
        vm.set_collect_every_allocation(true);
        let outcome = vm
            .load_with_environment(compile(source, profile), Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("return/goto scope exit 應正常完成")
        };
        if values.len() == 3 {
            assert_eq!(values[0], Value::Integer(9));
            assert_eq!(values[1], Value::Integer(1));
            assert_eq!(values[2], Value::Object(first));
        } else {
            assert_eq!(values, vec![Value::Integer(1), Value::Object(first)]);
        }
        assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Nil));
    }
    println!(
        "P11_CASE\tCLOSE-003\t{name}\tstatus=PASS;actual=return:closed-once,goto:closed-once;diagnostic=close-before-control-transfer;no-repeat;gc=forced"
    );
}

#[test]
fn close_case_001_invalid_value_fails_at_declaration() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = environment(&mut vm);
    let outcome = vm
        .load_with_environment(
            compile(b"local x <close> = 1; marker = 9; return marker", profile),
            Value::Object(env),
        )
        .unwrap()
        .run()
        .unwrap();
    let marker = vm.allocate_byte_string(b"marker").unwrap();
    assert_eq!(vm.raw_get(env, Value::Object(marker)), Ok(Value::Nil));
    assert!(matches!(outcome, RunOutcome::LuaError(_)));
    println!("P11_STAGE\tclose_case_001_invalid\t{name}\tstatus=PASS;declaration=checked");
}

#[test]
fn err_case_001_escaped_environment_survives_gc() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (original_env, original_root) = environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local function make() return function() return pcall end end; return make()";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(original_env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("make 應回傳 closure")
    };
    let Value::Object(closure) = values[0] else {
        panic!("make 應回傳 closure")
    };
    let closure_root = HostHandle::<Value>::new(&mut vm, closure).unwrap();
    drop(original_root);
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(original_env),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );

    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
    let key = vm.allocate_byte_string(b"f").unwrap();
    vm.raw_set(env, Value::Object(key), Value::Object(closure))
        .unwrap();
    let outcome = vm
        .load_with_environment(compile(b"return f()", profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("逃逸 closure 應讀取原 _ENV")
    };
    let Value::Object(builtin) = values[0] else {
        panic!("原 _ENV.pcall 應為內建物件")
    };
    assert_eq!(
        vm.object_kind(builtin),
        Ok(rivetlua_runtime::ObjectKind::Builtin)
    );
    drop(env_root);
    drop(closure_root);
    println!(
        "P11_STAGE\terr_case_001_env\t{name}\tstatus=PASS;escaped_environment=traced;gc=forced"
    );
}

#[test]
fn err_case_001_original_table_and_nested_boundary() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local t={}; local outer,a,b=pcall(function() return pcall(function() error(t) end) end); return outer,a,b,t";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀 pcall 應返回四值")
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(true), "{values:?}");
    assert_eq!(values[1], Value::Boolean(false));
    assert!(matches!(values[2], Value::Object(_)));
    assert_eq!(values[2], values[3]);

    let ordinary = b"local ok,e=pcall(function() return 1//0 end); return ok,e";
    let outcome = vm
        .load_with_environment(compile(ordinary, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("一般 Lua runtime error 應由最近 pcall 捕捉")
    };
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], Value::Boolean(false));
    let Value::Object(message) = values[1] else {
        panic!("一般錯誤值應為 byte string")
    };
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(b"E_INTEGER_DIVIDE_BY_ZERO".to_vec())
    );

    let no_boundary = b"local t={}; error(t)";
    let outcome = vm
        .load_with_environment(compile(no_boundary, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::LuaError(error) = outcome else {
        panic!("無保護邊界須向宿主交付 LuaError")
    };
    let Value::Object(table) = error.value else {
        panic!("錯誤值須保留 table")
    };
    assert_eq!(error.source_pc.is_some(), true);
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(table),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );
    drop(error);
    vm.collect().unwrap();
    assert!(vm.object_kind(table).is_err());
    assert_eq!(vm.roots().total_count(), 1);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P11_STAGE\terr_case_001\t{name}\tstatus=PASS;identity=preserved;nested=nearest;host_root=owned"
    );
}

#[test]
fn err_case_001_unprotected_runtime_error_has_message_value() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let outcome = vm
        .load_with_environment(compile(b"return 1//0", profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::LuaError(error) = outcome else {
        panic!("無 protected boundary 的隱含錯誤須交付 LuaError")
    };
    assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
    let Value::Object(message) = error.value else {
        panic!("隱含錯誤值須為 byte string")
    };
    vm.collect().unwrap();
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(b"E_INTEGER_DIVIDE_BY_ZERO".to_vec())
    );
    drop(error);
    vm.collect().unwrap();
    assert!(vm.object_kind(message).is_err());

    let outcome = vm
        .load_with_environment(compile(b"error(nil)", profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::LuaError(error) = outcome else {
        panic!("明確 error(nil) 應交付 LuaError")
    };
    assert_eq!(error.value, Value::Nil);
    drop(error);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P11_STAGE\terr_case_001_unprotected\t{name}\tstatus=PASS;message=value;host_root=owned;explicit_nil=preserved"
    );
}

#[test]
fn err_case_002_xpcall_handler_reentry_and_abort() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local t={}; local n=0; local ok,v=xpcall(function() error(t) end,function(e) n=n+1; if n<3 then error(n) end; return {original=e,count=n} end); return ok,v,n";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("xpcall handler 應回傳失敗 tuple")
    };
    assert_eq!(values.len(), 3);
    assert_eq!(values[0], Value::Boolean(false));
    let Value::Object(handler_result) = values[1] else {
        panic!("handler 應返回 table")
    };
    assert_eq!(values[2], Value::Integer(3));
    let handler_root = HostHandle::<Value>::new(&mut vm, handler_result).unwrap();
    let key_count = vm.allocate_byte_string(b"count").unwrap();
    assert_eq!(
        vm.raw_get(handler_result, Value::Object(key_count)),
        Ok(Value::Integer(3))
    );
    let key_original = vm.allocate_byte_string(b"original").unwrap();
    assert_eq!(
        vm.raw_get(handler_result, Value::Object(key_original)),
        Ok(Value::Integer(2))
    );
    drop(handler_root);

    let loop_source =
        b"n=0; return xpcall(function() error(7) end,function(e) n=n+1; error(e) end)";
    let outcome = vm
        .load_with_environment(compile(loop_source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::LuaError(error) = outcome else {
        panic!("32 次 handler 失敗應停止")
    };
    assert_eq!(error.diagnostic_id, "E_ERROR_HANDLER_LOOP");
    let Value::Object(message) = error.value else {
        panic!("handler-loop error 應為 byte string")
    };
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(b"error in error handling".to_vec())
    );
    let key_n = vm.allocate_byte_string(b"n").unwrap();
    assert_eq!(
        vm.raw_get(env, Value::Object(key_n)),
        Ok(Value::Integer(32))
    );
    drop(error);

    let abort_source = b"return pcall(function() while true do end end)";
    let mut execution = vm
        .load_with_environment(compile(abort_source, profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(25).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 1);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P11_STAGE\terr_case_002\t{name}\tstatus=PASS;handler_reentry=3;handler_limit=32;abort=bypassed"
    );
}

#[test]
fn err_case_002_builtin_target_preserves_nested_results() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"return pcall(pcall, function() return 7,8 end)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(8),
        ])
    );

    let success =
        b"local t={v=9}; local a,b,c=pcall(pcall,function() return t end); return a,b,c,t";
    let outcome = vm
        .load_with_environment(compile(success, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀內建 pcall 應成功")
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[2], values[3]);

    let failed = b"local t={v=9}; local a,b,c=pcall(pcall,function() error(t) end); return a,b,c,t";
    let outcome = vm
        .load_with_environment(compile(failed, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("內層錯誤應由內層 pcall 捕捉")
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(values[2], values[3]);

    let source = b"return xpcall(function() error(7) end,error)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::LuaError(error) = outcome else {
        panic!("內建 error handler 應遵守 32 次上限")
    };
    assert_eq!(error.diagnostic_id, "E_ERROR_HANDLER_LOOP");
    let Value::Object(message) = error.value else {
        panic!("handler-loop 須保存 byte string")
    };
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(b"error in error handling".to_vec())
    );
    drop(error);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P11_STAGE\terr_case_002_builtin\t{name}\tstatus=PASS;nested_results=4;handler_limit=32"
    );
}

#[test]
fn cor_case_001_yield_resumes_without_replaying_side_effect() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"n=0; local co=coroutine.create(function(x) n=n+1; local y=coroutine.yield(x+1); return y+n end); local a,b=coroutine.resume(co,9); local c,d=coroutine.resume(co,20); return a,b,c,d,n,coroutine.status(co)";
    let result = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = result else {
        panic!("協程應完成")
    };
    assert_eq!(
        &values[..5],
        &[
            Value::Boolean(true),
            Value::Integer(10),
            Value::Boolean(true),
            Value::Integer(21),
            Value::Integer(1)
        ]
    );
    let Value::Object(status) = values[5] else {
        panic!("status 須為字串")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    println!("P11_STAGE\tcor_case_001\t{name}\tstatus=PASS;side_effect=1");
}

#[test]
fn cor_case_002_nested_resume_reports_normal_parent() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local a; a=coroutine.create(function() local b=coroutine.create(function() return coroutine.status(a) end); local ok,s=coroutine.resume(b); return ok,s,coroutine.status(b) end); local ok,x,y,z=coroutine.resume(a); return ok,x,y,z,coroutine.status(a)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀 resume 應完成")
    };
    assert_eq!(values.len(), 5);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    for (index, expected) in [(2, b"normal".as_slice()), (3, b"dead"), (4, b"dead")] {
        let Value::Object(object) = values[index] else {
            panic!("status 應是 byte string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );
    }
    println!("P11_STAGE\tcor_case_002\t{name}\tstatus=PASS;parent=normal");
}

#[test]
fn cor_case_002_nested_yield_restores_running_parent() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local a,b; a=coroutine.create(function() b=coroutine.create(function() coroutine.yield(coroutine.status(a)); return coroutine.status(a) end); local ok,x=coroutine.resume(b); local suspended=coroutine.status(b); local ok2,y=coroutine.resume(b); return ok,x,suspended,ok2,y,coroutine.status(a) end); local ok,p,q,r,s,t,u=coroutine.resume(a); return ok,p,q,r,s,t,u,coroutine.status(a)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("巢狀 yield 應完成")
    };
    assert_eq!(values.len(), 8);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(values[4], Value::Boolean(true));
    for (index, expected) in [
        (2, b"normal".as_slice()),
        (3, b"suspended"),
        (5, b"normal"),
        (6, b"running"),
        (7, b"dead"),
    ] {
        let Value::Object(object) = values[index] else {
            panic!("狀態須為字串")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );
    }
    println!("P11_STAGE\tcor_case_002_yield\t{name}\tstatus=PASS;normal_running_suspended=checked");
}

#[test]
fn cor_case_003_dead_resume_is_lua_failure_without_replay() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"n=0; local co=coroutine.create(function() n=n+1; return 4 end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co); return a,b,c,d,n,coroutine.status(co)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("dead resume 應返回 Lua tuple")
    };
    assert_eq!(values.len(), 6);
    assert_eq!(
        &values[..3],
        &[
            Value::Boolean(true),
            Value::Integer(4),
            Value::Boolean(false)
        ]
    );
    assert_eq!(values[4], Value::Integer(1));
    for index in [3, 5] {
        let Value::Object(object) = values[index] else {
            panic!("錯誤與狀態應是 byte string")
        };
        let bytes = vm
            .with_byte_string(object, |s| s.as_bytes().to_vec())
            .unwrap();
        if index == 3 {
            assert!(bytes.starts_with(b"cannot resume"));
        } else {
            assert_eq!(bytes, b"dead");
        }
    }
    println!("P11_STAGE\tcor_case_003\t{name}\tstatus=PASS;dead_replay=0");
}

#[test]
fn cor_case_004_main_yield_is_catchable_lua_error() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"return pcall(coroutine.yield,7)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("main yield 應由 pcall 捕捉")
    };
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], Value::Boolean(false));
    let Value::Object(message) = values[1] else {
        panic!("main yield error 應是 byte string")
    };
    assert_eq!(
        vm.with_byte_string(message, |s| s.as_bytes().starts_with(b"E_COROUTINE_YIELD")),
        Ok(true)
    );
    println!("P11_STAGE\tcor_case_004\t{name}\tstatus=PASS;main_yield=LuaError");
}

#[test]
fn cor_case_001_escaped_open_upvalue_and_distinct_slots() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local f,g; local a=coroutine.create(function() local x=7; f=function() return x end; coroutine.yield(); x=9; return x end); local b=coroutine.create(function() local x=40; g=function() return x end; coroutine.yield(); x=41; return x end); coroutine.resume(a); coroutine.resume(b); local p,q=f(),g(); coroutine.resume(a); coroutine.resume(b); return p,q,f(),g()";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Integer(7),
            Value::Integer(40),
            Value::Integer(9),
            Value::Integer(41)
        ])
    );
    println!("P11_STAGE\tcor_case_001_upvalue\t{name}\tstatus=PASS;slots=separate");
}

#[test]
fn cor_case_001_escaped_closure_keeps_suspended_thread_reachable() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = coroutine_environment(&mut vm);
    let source = b"local co=coroutine.create(function() local x={v=8}; getter=function() return x end; coroutine.yield() end); coroutine.resume(co); local t=getter(); co=nil; return t";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("須返回捕獲的 table")
    };
    let Value::Object(table) = values[0] else {
        panic!("須是 table")
    };
    let table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
    vm.set_collect_every_allocation(true);
    vm.collect().unwrap();
    let outcome = vm
        .load_with_environment(compile(b"return getter()", profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Object(table)]));
    drop(table_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(table),
        Err(rivetlua_runtime::VmError::StaleObject)
    );
    assert_eq!(vm.roots().total_count(), 0);
    println!("P11_STAGE\tcor_case_001_owner_gc\t{name}\tstatus=PASS;closure_thread_edge=traced");
}

#[test]
fn cor_case_001_pending_metamethod_survives_yield_and_gc() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let table = vm.allocate_table().unwrap();
    let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let _meta_root = HostHandle::<Value>::new(&mut vm, metatable).unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();
    let name_t = vm.allocate_byte_string(b"t").unwrap();
    vm.raw_set(env, Value::Object(name_t), Value::Object(table))
        .unwrap();
    let outcome = vm
        .load_with_environment(
            compile(
                b"return function(a,b) local x=coroutine.yield(7); return x+1 end",
                profile,
            ),
            Value::Object(env),
        )
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("須建立 event closure")
    };
    let Value::Object(event) = values[0] else {
        panic!("須回傳 event closure")
    };
    let event_root = HostHandle::<Value>::new(&mut vm, event).unwrap();
    let key_add = vm.allocate_byte_string(b"__add").unwrap();
    vm.raw_set(metatable, Value::Object(key_add), Value::Object(event))
        .unwrap();
    drop(event_root);
    vm.set_collect_every_allocation(true);
    let source = b"local co=coroutine.create(function() return t+2 end); local a,b=coroutine.resume(co); local c,d=coroutine.resume(co,20); return a,b,c,d,coroutine.status(co)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("PendingOp 續接應完成")
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Boolean(true),
            Value::Integer(7),
            Value::Boolean(true),
            Value::Integer(21)
        ]
    );
    let Value::Object(status) = values[4] else {
        panic!("須返回狀態字串")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    println!("P11_STAGE\tcor_case_001_pending\t{name}\tstatus=PASS;pending=once;gc=forced");
}

#[test]
fn cor_case_003_body_error_keeps_original_value_and_dead_thread() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local t={v=3}; local co=coroutine.create(function() local retained=t; error(t) end); local ok,e=coroutine.resume(co); return ok,e==t,coroutine.status(co),co";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("body error 應返回 resume tuple")
    };
    assert_eq!(values.len(), 4);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(values[1], Value::Boolean(true));
    let Value::Object(status) = values[2] else {
        panic!("須返回狀態")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    let Value::Object(co) = values[3] else {
        panic!("須返回 thread")
    };
    let co_root = HostHandle::<Value>::new(&mut vm, co).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(co),
        Ok(rivetlua_runtime::ObjectKind::Coroutine)
    );
    drop(co_root);
    println!(
        "P11_STAGE\tcor_case_003_body_error\t{name}\tstatus=PASS;identity=preserved;dead=retained"
    );
}

#[test]
fn cor_case_001_yield_result_modes_and_tail_call() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local a=coroutine.create(function(...) local x,y=coroutine.yield(...); return x,y end); local p,q,r=coroutine.resume(a,1,2); local s,t,u=coroutine.resume(a,3,4); local b=coroutine.create(function() return coroutine.yield(8) end); local v,w=coroutine.resume(b); local z,j,k=coroutine.resume(b,5,6); return p,q,r,s,t,u,v,w,z,j,k";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(1),
            Value::Integer(2),
            Value::Boolean(true),
            Value::Integer(3),
            Value::Integer(4),
            Value::Boolean(true),
            Value::Integer(8),
            Value::Boolean(true),
            Value::Integer(5),
            Value::Integer(6),
        ])
    );
    println!("P11_STAGE\tcor_case_001_results\t{name}\tstatus=PASS;all=2;tail=2");
}

#[test]
fn cor_case_001_yield_inside_protected_call_resumes_boundary() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local co=coroutine.create(function() local ok,x=pcall(function() return coroutine.yield(7) end); return ok,x end); local a,b=coroutine.resume(co); local c,d,e=coroutine.resume(co,20); return a,b,c,d,e";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(7),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(20)
        ])
    );
    println!("P11_STAGE\tcor_case_001_pcall\t{name}\tstatus=PASS;boundary=preserved");
}

#[test]
fn cor_case_001_builtin_yield_target_preserves_protected_boundary() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local co=coroutine.create(function() return pcall(coroutine.yield,7) end); local a,b=coroutine.resume(co); local c,d,e=coroutine.resume(co,20); local f,g=pcall(coroutine.status,co); return a,b,c,d,e,f,g";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("內建目標應可續接")
    };
    assert_eq!(
        &values[..6],
        &[
            Value::Boolean(true),
            Value::Integer(7),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(20),
            Value::Boolean(true)
        ]
    );
    let Value::Object(status) = values[6] else {
        panic!("狀態須為字串")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    println!("P11_STAGE\tcor_case_001_builtin_pcall\t{name}\tstatus=PASS;boundary=inline");
}

#[test]
fn cor_case_001_builtin_create_and_resume_as_protected_targets() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local a,co=pcall(coroutine.create,function() return 9 end); local b,c,d=pcall(coroutine.resume,co); return a,b,c,d,coroutine.status(co)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("內建目標應返回多重結果")
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(9)
        ]
    );
    let Value::Object(status) = values[4] else {
        panic!("status 須為字串")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    println!("P11_STAGE\tcor_case_001_builtin_targets\t{name}\tstatus=PASS;pcall_results=3");
}

#[test]
fn cor_case_003_coroutine_key_and_invalid_raw_length() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source =
        b"local co=coroutine.create(function() end); local t={}; t[co]=9; c=co; return t[co]";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(9)]));
    let error = vm
        .load_with_environment(compile(b"return #c", profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap_err();
    assert_eq!(
        error.kind,
        rivetlua_runtime::RuntimeErrorKind::UnsupportedUnaryOperation(
            rivetlua_core::UnaryOperation::Length
        )
    );
    println!("P11_STAGE\tcor_case_003_object\t{name}\tstatus=PASS;key=identity;length=error");
}

#[test]
fn cor_case_004_hard_abort_is_terminal_and_not_a_resume_tuple() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, env_root) = coroutine_environment(&mut vm);
    let source =
        b"local co=coroutine.create(function() while true do end end); return coroutine.resume(co)";
    let mut execution = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(60).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    assert_eq!(
        execution.run().unwrap_err().kind,
        rivetlua_runtime::RuntimeErrorKind::TerminalExecution
    );
    drop(execution);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P11_STAGE\tcor_case_004_abort\t{name}\tstatus=PASS;abort=terminal;resume_tuple=none");
}

#[test]
fn cor_case_001_native_builtin_body_yield_and_error() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local s=coroutine.create(coroutine.status); local a,b=coroutine.resume(s,s); local y=coroutine.create(coroutine.yield); local c,d,e=coroutine.resume(y,7,8); local f,g,h=coroutine.resume(y,9,10); local t={}; local z=coroutine.create(error); local i,j=coroutine.resume(z,t); return a,b,coroutine.status(s),c,d,e,f,g,h,coroutine.status(y),i,j==t,coroutine.status(z)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("native builtin body 應回傳 Lua 結果")
    };
    assert_eq!(values.len(), 13);
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(
        &values[3..9],
        &[
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(8),
            Value::Boolean(true),
            Value::Integer(9),
            Value::Integer(10)
        ]
    );
    assert_eq!(values[10], Value::Boolean(false));
    assert_eq!(values[11], Value::Boolean(true));
    for (index, expected) in [
        (1, b"running".as_slice()),
        (2, b"dead"),
        (9, b"dead"),
        (12, b"dead"),
    ] {
        let Value::Object(object) = values[index] else {
            panic!("狀態須為 byte string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );
    }
    println!("P11_STAGE\tcor_case_001_native\t{name}\tstatus=PASS;body=status,yield,error");
}

#[test]
fn cor_case_001_native_protected_and_nested_resume() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local p=coroutine.create(pcall); local a,b,c,d=coroutine.resume(p,function() return 2,3 end); local q=coroutine.create(pcall); local e,f,g=coroutine.resume(q,function() error(9) end); local x=coroutine.create(xpcall); local h,i,j=coroutine.resume(x,function() error(5) end,function(v) return v+1 end); local inner=coroutine.create(function() return 4 end); local outer=coroutine.create(coroutine.resume); local k,l,m=coroutine.resume(outer,inner); return a,b,c,d,e,f,g,h,i,j,k,l,m";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(2),
            Value::Integer(3),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Integer(9),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Integer(6),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(4),
        ])
    );
    println!("P11_STAGE\tcor_case_001_native_wrappers\t{name}\tstatus=PASS;pcall=xpcall=resume");
}

#[test]
fn cor_case_001_native_resume_yield_propagates_two_statuses() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local inner=coroutine.create(function(x) local z=coroutine.yield(x); return z+1 end); local outer=coroutine.create(coroutine.resume); local a,b,c=coroutine.resume(outer,inner,11); local d,e=coroutine.resume(inner,12); return a,b,c,d,e";
    let mut execution = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .expect("native resume yield load");
    let outcome = execution.run().expect("native resume yield run");
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(11),
            Value::Boolean(true),
            Value::Integer(13)
        ])
    );
    println!(
        "P11_STAGE\tcor_case_001_native_resume_yield\t{name}\tstatus=PASS;statuses=2;inner=continued"
    );
}

#[test]
fn cor_case_001_native_nested_builtin_and_handler_limit() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local p=coroutine.create(pcall); local a,b,c,d=coroutine.resume(p,pcall,function() return 2 end); local x=coroutine.create(xpcall); local e,f=coroutine.resume(x,function() error(1) end,error); return a,b,c,d,e,f";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("原生巢狀內建目標應回傳 Lua 結果")
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(2)
        ]
    );
    assert_eq!(values[4], Value::Boolean(false));
    let Value::Object(message) = values[5] else {
        panic!("handler loop 應回傳 byte string")
    };
    assert_eq!(
        vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
        Ok(b"error in error handling".to_vec())
    );
    println!(
        "P11_STAGE\tcor_case_001_native_nested\t{name}\tstatus=PASS;builtin=protected;handler=32"
    );
}

#[test]
fn cor_case_003_native_resume_dead_inner_and_gc_roots() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local t={}; local p=coroutine.create(pcall); local a,b,c=coroutine.resume(p,function() return t end); local inner=coroutine.create(function() return 1 end); coroutine.resume(inner); local outer=coroutine.create(coroutine.resume); local d,e,f=coroutine.resume(outer,inner); return a,b,c==t,d,e,coroutine.status(outer)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("原生 wrapper 應回傳")
    };
    assert_eq!(
        &values[..5],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(false)
        ]
    );
    let Value::Object(message) = values[5] else {
        panic!("dead resume 訊息應是字串")
    };
    assert_eq!(
        vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
        Ok(b"dead".to_vec())
    );
    println!("P11_STAGE\tcor_case_003_native_gc\t{name}\tstatus=PASS;gc=forced;dead=reported");
}

#[test]
fn cor_case_003_native_resume_missing_target_stays_lua_tuple() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local co=coroutine.create(coroutine.resume); local a,b=coroutine.resume(co); return a,b,coroutine.status(co)";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("native resume 錯誤應在 Lua tuple")
    };
    assert_eq!(values[0], Value::Boolean(false));
    for (index, expected) in [(1, b"E_WRONG_OBJECT_TYPE".as_slice()), (2, b"dead")] {
        let Value::Object(object) = values[index] else {
            panic!("錯誤和狀態須是 byte string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );
    }
    println!(
        "P11_STAGE\tcor_case_003_native_invalid\t{name}\tstatus=PASS;failure=tuple;state=dead"
    );
}

#[test]
fn cor_case_001_native_protected_builtin_error_and_handler() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local t={}; local p=coroutine.create(pcall); local a,b,c=coroutine.resume(p,error,9); local x=coroutine.create(xpcall); local d,e,f=coroutine.resume(x,nil,function(v) return t end); return a,b,c,d,e,f==t";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Integer(9),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Boolean(true)
        ])
    );
    println!(
        "P11_STAGE\tcor_case_001_native_target_error\t{name}\tstatus=PASS;error=original;handler=called"
    );
}

#[test]
fn cor_case_001_native_protected_builtin_success_and_resume() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local p=coroutine.create(pcall); local a,b,c=coroutine.resume(p,coroutine.status,p); local inner=coroutine.create(function() return 7,8 end); local q=coroutine.create(pcall); local d,e,f,g,h=coroutine.resume(q,coroutine.resume,inner); return a,b,c,d,e,f,g,h";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("Builtin target 成功應回傳")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Boolean(true));
    let Value::Object(status) = values[2] else {
        panic!("status 應為 byte string")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"running".to_vec())
    );
    assert_eq!(
        &values[3..],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(8)
        ]
    );
    println!(
        "P11_STAGE\tcor_case_001_native_target_success\t{name}\tstatus=PASS;status=running;resume=multi"
    );
}

#[test]
fn cor_case_001_native_protected_builtin_yield_continues() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local p=coroutine.create(pcall); local a,b=coroutine.resume(p,coroutine.yield,7); local c,d,e=coroutine.resume(p,8); local x=coroutine.create(xpcall); local f,g=coroutine.resume(x,coroutine.yield,function(v) return v end,9); local h,i,j=coroutine.resume(x,10); return a,b,c,d,e,f,g,h,i,j";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(7),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(8),
            Value::Boolean(true),
            Value::Integer(9),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(10)
        ])
    );
    println!(
        "P11_STAGE\tcor_case_001_native_target_yield\t{name}\tstatus=PASS;yield=once;protected=continued"
    );
}

#[test]
fn cor_case_001_native_protected_nested_builtin_targets() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local p=coroutine.create(pcall); local a,b,c,d=coroutine.resume(p,xpcall,function() return 3 end,function(v) return v end); local x=coroutine.create(xpcall); local e,f,g,h=coroutine.resume(x,pcall,function(v) return v end,function() error(4) end); local z=coroutine.create(pcall); local i,j,k,l,m=coroutine.resume(z,xpcall,pcall,function(v) return v end,function() return 6 end); return a,b,c,d,e,f,g,h,i,j,k,l,m";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(3),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Integer(4),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(6)
        ])
    );
    println!(
        "P11_STAGE\tcor_case_001_native_nested_targets\t{name}\tstatus=PASS;pcall_xpcall=callable"
    );
}

#[test]
fn cor_case_001_native_nested_builtin_yield_keeps_outer_suspended() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    vm.set_collect_every_allocation(true);
    let source = b"local p=coroutine.create(pcall); local a,b=coroutine.resume(p,xpcall,function() local x=coroutine.yield(7); return x+1 end,function(v) return v end); local s=coroutine.status(p); local c,d,e,f=coroutine.resume(p,9); local z=coroutine.create(pcall); local h,i=coroutine.resume(z,xpcall,pcall,function(v) return v end,function() local y=coroutine.yield(12); return y+1 end); local s2=coroutine.status(z); local j,k,l,m,n=coroutine.resume(z,13); local t={}; local q=coroutine.create(pcall); local u,v,w,x,y=coroutine.resume(q,xpcall,pcall,function(v) return v end,function() return t end); return a,b,s,c,d,e,f,h,i,s2,j,k,l,m,n,u,v,w,x,y==t";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("nested target yield 應續接")
    };
    assert_eq!(values[0], Value::Boolean(true));
    assert_eq!(values[1], Value::Integer(7));
    let Value::Object(status) = values[2] else {
        panic!("外層應暫停")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"suspended".to_vec())
    );
    assert_eq!(
        &values[3..7],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(10)
        ]
    );
    assert_eq!(&values[7..9], &[Value::Boolean(true), Value::Integer(12)]);
    let Value::Object(status) = values[9] else {
        panic!("第三層外層應暫停")
    };
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"suspended".to_vec())
    );
    assert_eq!(
        &values[10..15],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(14)
        ]
    );
    assert_eq!(
        &values[15..],
        &[
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true)
        ]
    );
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P11_STAGE\tcor_case_001_native_nested_yield\t{name}\tstatus=PASS;outer=suspended;continuation=once"
    );
}

#[test]
fn cor_case_001_native_pcall_yield_keeps_protected_continuation() {
    let (profile, name) = profile();
    let mut vm = Vm::new().unwrap();
    let (env, _env_root) = coroutine_environment(&mut vm);
    let source = b"local n=0; local p=coroutine.create(pcall); local a,b=coroutine.resume(p,function() n=n+1; local v=coroutine.yield(7); return n,v end); local c,d,e,f=coroutine.resume(p,8); return a,b,c,d,e,f,n";
    let outcome = vm
        .load_with_environment(compile(source, profile), Value::Object(env))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(7),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(1),
            Value::Integer(8),
            Value::Integer(1)
        ])
    );
    println!(
        "P11_STAGE\tcor_case_001_native_yield\t{name}\tstatus=PASS;protected=continued;side_effect=1"
    );
}
