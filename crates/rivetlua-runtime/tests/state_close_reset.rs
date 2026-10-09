use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, LuaProfile, ObjectRef, Value, VerifyLimits};
use rivetlua_runtime::{
    CoroutineState, ExternalCommand, FailPoint, FinalizerState, RootKind, RunOutcome, Vm, VmError,
};

fn compile(source: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
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

fn idle_thread(vm: &mut Vm, profile: LuaProfile) -> ObjectRef {
    let environment = vm.allocate_table().unwrap();
    let mut setup = vm
        .load_with_environment(
            compile(b"return function() end", profile),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = setup.run().unwrap() else {
        panic!("必須建立 Lua closure");
    };
    drop(setup);
    let coroutine = vm.new_coroutine(values[0]).unwrap();
    let Value::Object(thread) = coroutine.as_value(vm).unwrap() else {
        panic!("coroutine 必須是物件");
    };
    vm.add_root(RootKind::Host, thread).unwrap();
    thread
}

#[test]
fn reset_suspended_thread_closes_lifo_and_returns_idle_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let closer = HostFunctionId::new_unique(vm.id()).unwrap();
        let mark = vm.allocate_table().unwrap();
        let mark_metatable = vm.allocate_table().unwrap();
        let close_key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(
            mark_metatable,
            Value::Object(close_key),
            Value::CFunction(closer),
        )
        .unwrap();
        vm.set_metatable(mark, Some(mark_metatable)).unwrap();
        let mark_key = vm.allocate_byte_string(b"mark").unwrap();
        vm.raw_set(environment, Value::Object(mark_key), Value::Object(mark))
            .unwrap();
        let mut setup = vm
            .load_with_environment(
                compile(
                    b"return function() local x <close> = mark; coroutine.yield(7) end",
                    profile,
                ),
                Value::Object(environment),
            )
            .unwrap();
        let RunOutcome::Returned(values) = setup.run().unwrap() else {
            panic!("必須建立 closure");
        };
        drop(setup);
        let coroutine = vm.new_coroutine(values[0]).unwrap();
        let coroutine_value = coroutine.as_value(&vm).unwrap();
        let mut resumed = vm.resume(coroutine_value, &[]).unwrap();
        assert_eq!(
            resumed.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
        );
        drop(resumed);

        let token = {
            let mut reset = vm.reset_thread_execution(coroutine_value).unwrap();
            let RunOutcome::External(token) = reset.run().unwrap() else {
                panic!("reset 必須停在 C __close callback");
            };
            token
        };
        assert_eq!(vm.external_event(token).unwrap().function, closer);
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
        );
        vm.finalize_thread_reset(coroutine_value).unwrap();
        let Value::Object(object) = coroutine_value else {
            panic!("coroutine identity 必須保留");
        };
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn shutdown_queues_rooted_registered_finalizers_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(function))
            .unwrap();
        let object = vm.allocate_table().unwrap();
        vm.set_metatable(object, Some(metatable)).unwrap();
        let _root = vm.add_root(RootKind::Host, object).unwrap();
        vm.queue_shutdown_finalizers().unwrap();
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Pending));
        let token = {
            let mut execution = vm.gc_finalizer_execution(None).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("rooted finalizer 必須可驅動 C callback");
            };
            token
        };
        assert_eq!(vm.external_event(token).unwrap().function, function);
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
    }
}

#[test]
fn reset_close_error_replaces_success_and_clears_old_execution_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let closer = HostFunctionId::new_unique(vm.id()).unwrap();
        let mark = vm.allocate_table().unwrap();
        let metatable = vm.allocate_table().unwrap();
        let close_key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(
            metatable,
            Value::Object(close_key),
            Value::CFunction(closer),
        )
        .unwrap();
        vm.set_metatable(mark, Some(metatable)).unwrap();
        let mark_key = vm.allocate_byte_string(b"mark").unwrap();
        vm.raw_set(environment, Value::Object(mark_key), Value::Object(mark))
            .unwrap();
        let closure = {
            let mut setup = vm
                .load_with_environment(
                    compile(
                        b"return function() local x <close> = mark; coroutine.yield() end",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::Returned(values) = setup.run().unwrap() else {
                panic!("必須建立 closure");
            };
            values[0]
        };
        let coroutine = vm.new_coroutine(closure).unwrap();
        let value = coroutine.as_value(&vm).unwrap();
        assert_eq!(
            vm.resume(value, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        let token = {
            let mut reset = vm.reset_thread_execution(value).unwrap();
            let RunOutcome::External(token) = reset.run().unwrap() else {
                panic!("reset __close 必須停放");
            };
            token
        };
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Error(Value::Integer(91))),
            Ok(RunOutcome::Returned(vec![
                Value::Boolean(false),
                Value::Integer(91)
            ]))
        );
        vm.finalize_thread_reset(value).unwrap();
        let Value::Object(object) = value else {
            panic!("保留 identity");
        };
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn shutdown_queue_failure_preserves_registration_and_retries_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(function))
            .unwrap();
        let object = vm.allocate_table().unwrap();
        vm.set_metatable(object, Some(metatable)).unwrap();
        let _root = vm.add_root(RootKind::Host, object).unwrap();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            vm.queue_shutdown_finalizers(),
            Err(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Registered));
        assert!(!vm.gc_finalizers_pending());
        vm.queue_shutdown_finalizers().unwrap();
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Pending));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn prepared_reset_parked_arena_allocation_rolls_back_and_retries_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut baseline = Vm::new_with_profile(profile).unwrap();
        let thread = idle_thread(&mut baseline, profile);
        let before = baseline.allocation_trace().next_ordinal;
        baseline.prepare_thread_reset_b11(thread).unwrap();
        let after = baseline.allocation_trace().next_ordinal;
        assert!(after > before);
        baseline.cancel_prepared_thread_reset_b11().unwrap();
        assert_eq!(baseline.ledger_snapshot().reserved, 0);

        let mut vm = Vm::new_with_profile(profile).unwrap();
        let thread = idle_thread(&mut vm, profile);
        assert_eq!(vm.allocation_trace().next_ordinal, before);
        vm.inject_allocation_failure_at(after - 1);
        assert!(vm.prepare_thread_reset_b11(thread).is_err());
        let failure = vm.allocation_trace().last_failure.unwrap();
        assert_eq!(failure.attempt.ordinal, after - 1);
        assert_eq!(failure.attempt.point, Some(FailPoint::WorkReserve));
        assert_eq!(vm.coroutine_state(thread), Ok(CoroutineState::Suspended));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.cancel_prepared_thread_reset_b11().unwrap();
        vm.prepare_thread_reset_b11(thread).unwrap();
        assert_eq!(
            vm.run_prepared_thread_reset_b11(thread, None),
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
        );
        vm.finalize_thread_reset(Value::Object(thread)).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn shutdown_reverse_order_error_continues_and_requeues_new_work_b11() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(function))
            .unwrap();
        let first = vm.allocate_table().unwrap();
        let second = vm.allocate_table().unwrap();
        vm.set_metatable(first, Some(metatable)).unwrap();
        vm.set_metatable(second, Some(metatable)).unwrap();
        let _first_root = vm.add_root(RootKind::Host, first).unwrap();
        let _second_root = vm.add_root(RootKind::Host, second).unwrap();
        vm.queue_shutdown_finalizers().unwrap();
        let second_token = {
            let mut execution = vm.gc_finalizer_execution(None).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("第二個註冊者應先執行");
            };
            token
        };
        assert_eq!(
            vm.external_event(second_token).unwrap().args[0],
            Value::Object(second)
        );
        vm.set_metatable(second, Some(metatable)).unwrap();
        let new_object = vm.allocate_table().unwrap();
        vm.set_metatable(new_object, Some(metatable)).unwrap();
        let _new_root = vm.add_root(RootKind::Host, new_object).unwrap();
        let RunOutcome::External(first_token) = vm
            .continue_external(second_token, ExternalCommand::Error(Value::Integer(91)))
            .unwrap()
        else {
            panic!("第一個 finalizer 應在錯誤後繼續");
        };
        assert_eq!(
            vm.external_event(first_token).unwrap().args[0],
            Value::Object(first)
        );
        assert_eq!(
            vm.continue_external(first_token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert_eq!(vm.gc_trace().finalizer_warnings, 1);
        assert_eq!(vm.finalizer_state(first), Ok(FinalizerState::Finalized));
        assert_eq!(vm.finalizer_state(second), Ok(FinalizerState::Registered));
        assert_eq!(
            vm.finalizer_state(new_object),
            Ok(FinalizerState::Registered)
        );
        vm.queue_shutdown_finalizers().unwrap();
        assert_eq!(vm.gc_trace().finalizer_pending, 2);
        let token = {
            let mut execution = vm.gc_finalizer_execution(None).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("重新註冊項目應被重新排程");
            };
            token
        };
        assert_eq!(
            vm.external_event(token).unwrap().args[0],
            Value::Object(new_object)
        );
        let RunOutcome::External(token) = vm
            .continue_external(token, ExternalCommand::Return(vec![]))
            .unwrap()
        else {
            panic!("重註冊項目應接續執行");
        };
        assert_eq!(
            vm.external_event(token).unwrap().args[0],
            Value::Object(second)
        );
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn lua55_self_close_current_callback_stops_resume_and_resets_identity_b11() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let callback = HostFunctionId::new_unique(vm.id()).unwrap();
    let closure = {
        let mut setup = vm
            .load(compile(b"return function(f) f() end", LuaProfile::Lua55))
            .unwrap();
        let RunOutcome::Returned(values) = setup.run().unwrap() else {
            panic!("必須建立 closure");
        };
        values[0]
    };
    let coroutine = vm.new_coroutine(closure).unwrap();
    let value = coroutine.as_value(&vm).unwrap();
    let token = {
        let mut resumed = vm.resume(value, &[Value::CFunction(callback)]).unwrap();
        let RunOutcome::External(token) = resumed.run().unwrap() else {
            panic!("running coroutine 應停在 C callback");
        };
        token
    };
    assert_eq!(vm.external_event(token).unwrap().function, callback);
    assert_eq!(
        vm.self_close_external(token),
        Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
    );
    vm.finalize_thread_reset(value).unwrap();
    let Value::Object(object) = value else {
        panic!("保留 thread identity");
    };
    assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
}

#[test]
fn nested_c_callback_inside_running_coroutine_restores_outer_token_b11() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let outer = HostFunctionId::new_unique(vm.id()).unwrap();
    let inner = HostFunctionId::new_unique(vm.id()).unwrap();
    let closure = {
        let mut setup = vm
            .load(compile(b"return function(f) f() end", LuaProfile::Lua55))
            .unwrap();
        let RunOutcome::Returned(values) = setup.run().unwrap() else {
            panic!("必須建立 closure");
        };
        values[0]
    };
    let coroutine = vm.new_coroutine(closure).unwrap();
    let value = coroutine.as_value(&vm).unwrap();
    let outer_token = {
        let mut execution = vm.resume(value, &[Value::CFunction(outer)]).unwrap();
        let RunOutcome::External(token) = execution.run().unwrap() else {
            panic!("協程應停在外層 C callback");
        };
        token
    };
    let RunOutcome::External(inner_token) = vm
        .continue_external(
            outer_token,
            ExternalCommand::NestedCall {
                target: Value::CFunction(inner),
                args: vec![],
                results: rivetlua_core::ResultMode::All,
            },
        )
        .unwrap()
    else {
        panic!("巢狀 C callback 應停放");
    };
    assert_eq!(
        vm.continue_external(inner_token, ExternalCommand::Return(vec![])),
        Ok(RunOutcome::NestedReturned(vec![]))
    );
    assert_eq!(vm.external_event(outer_token).unwrap().function, outer);
    assert_eq!(
        vm.self_close_external(outer_token),
        Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
    );
    vm.finalize_thread_reset(value).unwrap();
}
