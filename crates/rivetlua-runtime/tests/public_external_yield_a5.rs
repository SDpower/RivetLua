use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, LuaProfile, ResultMode, Value};
use rivetlua_runtime::{
    CoroutineState, ExternalCommand, FailPoint, HostHandle, RootKind, RunOutcome, RuntimeErrorKind,
    Vm,
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
    emit(&ir, &rivetlua_core::VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn c_coroutine_yield_detaches_global_lifo_and_restores_by_identity_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let first = vm.new_coroutine(Value::CFunction(function)).unwrap();
        let second = vm.new_coroutine(Value::CFunction(function)).unwrap();
        let Value::Object(first_object) = first.as_value(&vm).unwrap() else {
            panic!("首個 child 身分遺失");
        };
        let Value::Object(second_object) = second.as_value(&vm).unwrap() else {
            panic!("第二個 child 身分遺失");
        };
        let first_token = {
            let mut execution = vm.resume(Value::Object(first_object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("首個 C child 未進入外部 callback");
            };
            token
        };
        assert_eq!(
            vm.coroutine_state(first_object),
            Ok(CoroutineState::Running)
        );
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(vm.suspend_external_a5(first_token, first_object).is_err());
        assert_eq!(
            vm.coroutine_state(first_object),
            Ok(CoroutineState::Running)
        );
        assert_eq!(vm.external_event(first_token).unwrap().function, function);
        assert_eq!(vm.suspend_external_a5(first_token, first_object), Ok(1));
        assert_eq!(
            vm.coroutine_state(first_object),
            Ok(CoroutineState::Suspended)
        );
        assert!(vm.external_event(first_token).is_err());

        let second_token = {
            let mut execution = vm.resume(Value::Object(second_object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("第二個 C child 被首個暫停 child 擋住");
            };
            token
        };
        assert_eq!(vm.suspend_external_a5(second_token, second_object), Ok(1));
        vm.collect_major().unwrap();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(vm.resume_external_a5(first_object).is_err());
        assert_eq!(
            vm.coroutine_state(first_object),
            Ok(CoroutineState::Suspended)
        );
        assert_eq!(
            vm.coroutine_state(second_object),
            Ok(CoroutineState::Suspended)
        );
        let resumed_first = vm.resume_external_a5(first_object).unwrap();
        let resumed_first_token = resumed_first.top_token().unwrap();
        assert_ne!(resumed_first_token, first_token);
        assert_eq!(
            vm.external_event(resumed_first_token).unwrap().function,
            function
        );
        assert_eq!(
            vm.continue_external(
                resumed_first_token,
                ExternalCommand::Return(vec![Value::Integer(11)])
            ),
            Ok(RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Integer(11)
            ]))
        );
        assert_eq!(vm.coroutine_state(first_object), Ok(CoroutineState::Dead));

        let resumed_second = vm.resume_external_a5(second_object).unwrap();
        let resumed_second_token = resumed_second.top_token().unwrap();
        assert_ne!(resumed_second_token, second_token);
        assert_eq!(
            vm.continue_external(
                resumed_second_token,
                ExternalCommand::Return(vec![Value::Integer(22)])
            ),
            Ok(RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Integer(22)
            ]))
        );
        assert_eq!(vm.coroutine_state(second_object), Ok(CoroutineState::Dead));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn abandoned_c_resume_closes_context_and_allows_thread_reset_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let child = vm.new_coroutine(Value::CFunction(function)).unwrap();
        let Value::Object(object) = child.as_value(&vm).unwrap() else {
            panic!("child 身分遺失");
        };
        let token = {
            let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("C callback 未停放");
            };
            token
        };
        assert_eq!(vm.suspend_external_a5(token, object), Ok(1));
        vm.collect_major().unwrap();
        vm.abort_suspended_external_a5(object).unwrap();
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Dead));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.finalize_thread_reset(Value::Object(object)).unwrap();
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
        assert!(vm.resume_external_a5(object).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn suspended_lua_close_handler_runs_once_and_closes_captured_upvalue_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        let closer = HostFunctionId::new_unique(vm.id()).unwrap();
        let probe = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let close_key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(
            metatable,
            Value::Object(close_key),
            Value::CFunction(closer),
        )
        .unwrap();
        let closable = vm.allocate_table().unwrap();
        vm.set_metatable(closable, Some(metatable)).unwrap();
        let module = compile(
            b"return function(probe, marker) local x <close> = marker; local f = function() return x end; probe(f); return 9 end",
            profile,
        );
        let RunOutcome::Returned(values) = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap()
            .run()
            .unwrap()
        else {
            panic!("Lua 入口閉包未返回");
        };
        let entry = values[0];
        let child = vm.new_coroutine(entry).unwrap();
        let Value::Object(object) = child.as_value(&vm).unwrap() else {
            panic!("child 身分遺失");
        };
        let token = {
            let mut execution = vm
                .resume(
                    Value::Object(object),
                    &[Value::CFunction(probe), Value::Object(closable)],
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("Lua frame 內的 C probe 未停放");
            };
            token
        };
        let captured = match vm.external_event(token).unwrap().args {
            [Value::Object(captured)] => *captured,
            _ => panic!("probe 未取得捕獲閉包"),
        };
        let held = HostHandle::<Value>::new(&mut vm, captured).unwrap();
        let cell = vm
            .capi_upvalue_cell(Value::Object(captured), 1)
            .unwrap()
            .unwrap();
        assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(closable)));
        assert_eq!(vm.suspend_external_a5(token, object), Ok(1));
        vm.collect_major().unwrap();
        assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(closable)));
        vm.capi_set_upvalue(cell, Value::Object(closable)).unwrap();
        let RunOutcome::External(close_token) =
            vm.close_suspended_external_a5(object, None).unwrap()
        else {
            panic!("reset 未啟動 Lua close walker");
        };
        assert_eq!(vm.external_event(close_token).unwrap().function, closer);
        assert_eq!(
            vm.external_event(close_token).unwrap().args[0],
            Value::Object(closable)
        );
        assert_eq!(
            vm.continue_external(close_token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
        );
        assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(closable)));
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Dead));
        vm.finalize_thread_reset(Value::Object(object)).unwrap();
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
        drop(held);
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn nested_c_callback_keeps_outer_core_and_rebinds_both_tokens_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let child = vm.new_coroutine(Value::CFunction(outer)).unwrap();
        let Value::Object(object) = child.as_value(&vm).unwrap() else {
            panic!("child 身分遺失");
        };
        let outer_token = {
            let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("外層 callback 未停放");
            };
            token
        };
        let RunOutcome::External(inner_token) = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![Value::Integer(4)],
                    results: ResultMode::Fixed(1),
                },
            )
            .unwrap()
        else {
            panic!("內層 callback 未停放");
        };
        assert_eq!(vm.suspend_external_a5(inner_token, object), Ok(2));
        vm.collect_major().unwrap();
        let resumed = vm.resume_external_a5(object).unwrap();
        assert_eq!(resumed.mappings().len(), 2);
        assert_eq!(resumed.mappings()[0].0, outer_token);
        assert_eq!(resumed.mappings()[1].0, inner_token);
        let outer_new = resumed.mappings()[0].1;
        let inner_new = resumed.mappings()[1].1;
        assert_eq!(
            vm.external_event(inner_new).unwrap().args,
            &[Value::Integer(4)]
        );
        assert_eq!(
            vm.continue_external(inner_new, ExternalCommand::Return(vec![Value::Integer(5)])),
            Ok(RunOutcome::NestedReturned(vec![Value::Integer(5)]))
        );
        assert_eq!(vm.external_event(outer_new).unwrap().function, outer);
        assert_eq!(
            vm.continue_external(outer_new, ExternalCommand::Return(vec![Value::Integer(6)])),
            Ok(RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Integer(6)
            ]))
        );
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Dead));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn mixed_lua_close_boundary_preserves_upvalue_and_error_across_detach_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for close_error in [false, true] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let outer = HostFunctionId::new_unique(vm.id()).unwrap();
            let inner = HostFunctionId::new_unique(vm.id()).unwrap();
            let closer = HostFunctionId::new_unique(vm.id()).unwrap();
            let metatable = vm.allocate_table().unwrap();
            let key = vm.allocate_byte_string(b"__close").unwrap();
            vm.raw_set(metatable, Value::Object(key), Value::CFunction(closer))
                .unwrap();
            let marker = vm.allocate_table().unwrap();
            vm.set_metatable(marker, Some(metatable)).unwrap();
            let module = compile(
                b"return function(inner, marker) local x <close> = marker; local f = function() return x end; inner(f) end",
                profile,
            );
            let RunOutcome::Returned(values) = vm.load(module).unwrap().run().unwrap() else {
                panic!("Lua 入口閉包未返回");
            };
            let Value::Object(entry) = values[0] else {
                panic!("Lua 入口不是閉包");
            };
            let entry_root = HostHandle::<Value>::new(&mut vm, entry).unwrap();
            let child = vm.new_coroutine(Value::CFunction(outer)).unwrap();
            let Value::Object(object) = child.as_value(&vm).unwrap() else {
                panic!("child 身分遺失");
            };
            let outer_token = {
                let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("外層 C callback 未停放");
                };
                token
            };
            let RunOutcome::External(inner_token) = vm
                .continue_external(
                    outer_token,
                    ExternalCommand::NestedCall {
                        target: Value::Object(entry),
                        args: vec![Value::CFunction(inner), Value::Object(marker)],
                        results: ResultMode::Fixed(0),
                    },
                )
                .unwrap()
            else {
                panic!("內層 C callback 未停放");
            };
            let Value::Object(captured) = vm.external_event(inner_token).unwrap().args[0] else {
                panic!("內層 C callback 未取得 open closure");
            };
            let captured_root = HostHandle::<Value>::new(&mut vm, captured).unwrap();
            let cell = vm
                .capi_upvalue_cell(Value::Object(captured), 1)
                .unwrap()
                .unwrap();
            assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(marker)));
            assert_eq!(vm.suspend_external_a5(inner_token, object), Ok(2));
            vm.collect_major().unwrap();
            assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(marker)));
            let RunOutcome::External(close_token) =
                vm.close_suspended_external_a5(object, None).unwrap()
            else {
                panic!("Lua 中間 close handler 未呼叫");
            };
            assert_eq!(vm.external_event(close_token).unwrap().function, closer);
            let error = if close_error {
                Some(Value::Object(
                    vm.allocate_byte_string(b"mixed close failure").unwrap(),
                ))
            } else {
                None
            };
            let outcome = vm
                .continue_external(
                    close_token,
                    error.map_or_else(|| ExternalCommand::Return(vec![]), ExternalCommand::Error),
                )
                .unwrap();
            let RunOutcome::CloseBoundaryA5 {
                token: boundary,
                error: current_error,
            } = outcome
            else {
                panic!("close walker 未交還外層 C frame");
            };
            assert_eq!(current_error, error);
            assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(marker)));
            assert_eq!(vm.suspend_external_a5(boundary, object), Ok(1));
            vm.collect_major().unwrap();
            assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(marker)));
            let restored = vm.resume_external_a5(object).unwrap();
            let final_outcome = vm
                .continue_external_close_boundary_a5(restored.top_token().unwrap(), error)
                .unwrap();
            assert_eq!(
                final_outcome,
                if let Some(error) = error {
                    RunOutcome::Returned(vec![Value::Boolean(false), error])
                } else {
                    RunOutcome::Returned(vec![Value::Boolean(true)])
                }
            );
            assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Dead));
            vm.finalize_thread_reset(Value::Object(object)).unwrap();
            drop(captured_root);
            drop(entry_root);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn close_boundary_replacement_root_failure_aborts_without_parked_leak_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let closer = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(closer))
            .unwrap();
        let marker = vm.allocate_table().unwrap();
        vm.set_metatable(marker, Some(metatable)).unwrap();
        let module = compile(
            b"return function(inner, marker) local x <close> = marker; local f = function() return x end; inner(f) end",
            profile,
        );
        let RunOutcome::Returned(values) = vm.load(module).unwrap().run().unwrap() else {
            panic!("Lua 入口閉包未返回");
        };
        let Value::Object(entry) = values[0] else {
            panic!("Lua 入口不是閉包");
        };
        let entry_root = HostHandle::<Value>::new(&mut vm, entry).unwrap();
        let child = vm.new_coroutine(Value::CFunction(outer)).unwrap();
        let Value::Object(object) = child.as_value(&vm).unwrap() else {
            panic!("child 身分遺失");
        };
        let outer_token = {
            let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("外層 C callback 未停放");
            };
            token
        };
        let RunOutcome::External(inner_token) = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::Object(entry),
                    args: vec![Value::CFunction(inner), Value::Object(marker)],
                    results: ResultMode::Fixed(0),
                },
            )
            .unwrap()
        else {
            panic!("內層 C callback 未停放");
        };
        let Value::Object(captured) = vm.external_event(inner_token).unwrap().args[0] else {
            panic!("內層 C callback 未取得 open closure");
        };
        let captured_root = HostHandle::<Value>::new(&mut vm, captured).unwrap();
        let cell = vm
            .capi_upvalue_cell(Value::Object(captured), 1)
            .unwrap()
            .unwrap();
        vm.suspend_external_a5(inner_token, object).unwrap();
        let RunOutcome::External(close_token) =
            vm.close_suspended_external_a5(object, None).unwrap()
        else {
            panic!("Lua 中間 close handler 未呼叫");
        };
        let prior = Value::Object(vm.allocate_byte_string(b"middle error").unwrap());
        let RunOutcome::CloseBoundaryA5 { token, error } = vm
            .continue_external(close_token, ExternalCommand::Error(prior))
            .unwrap()
        else {
            panic!("未返回外層 C close 邊界");
        };
        assert_eq!(error, Some(prior));
        let replacement = vm.allocate_byte_string(b"outer error").unwrap();
        let replacement_root = HostHandle::<Value>::new(&mut vm, replacement).unwrap();
        let ordinal = vm.allocation_trace().next_ordinal;
        vm.inject_allocation_failure_at(ordinal);
        let failed = vm
            .continue_external_close_boundary_a5(token, Some(Value::Object(replacement)))
            .unwrap_err();
        assert!(matches!(
            failed.kind,
            RuntimeErrorKind::Heap(rivetlua_runtime::VmError::InjectedAllocation(_))
        ));
        let attempt = vm.allocation_trace().last_failure.unwrap().attempt;
        assert_eq!(attempt.ordinal, ordinal);
        assert!(attempt.site.file.ends_with("roots.rs"));
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Dead));
        assert!(vm.external_event(token).is_err());
        assert_eq!(vm.capi_read_upvalue(cell), Ok(Value::Object(marker)));
        vm.collect_major().unwrap();
        let mut temporary_roots = 0;
        vm.visit_roots(|kind, _, _| {
            if kind == RootKind::Temporary {
                temporary_roots += 1;
            }
        });
        assert_eq!(temporary_roots, 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.abort_closing_external_a5(object).unwrap();
        vm.finalize_thread_reset(Value::Object(object)).unwrap();
        assert_eq!(vm.coroutine_state(object), Ok(CoroutineState::Suspended));
        drop(replacement_root);
        drop(captured_root);
        drop(entry_root);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn foreign_and_stale_external_resume_are_rejected_without_mutation_a5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let child = vm.new_coroutine(Value::CFunction(function)).unwrap();
        let Value::Object(object) = child.as_value(&vm).unwrap() else {
            panic!("child 身分遺失");
        };
        let token = {
            let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("child 未進入外部 callback");
            };
            token
        };
        let mut other = Vm::new_with_profile(profile).unwrap();
        assert_eq!(
            other.suspend_external_a5(token, object).unwrap_err().kind,
            RuntimeErrorKind::Heap(rivetlua_runtime::VmError::WrongVm)
        );
        assert!(vm.resume_external_a5(object).is_err());
        assert_eq!(vm.external_event(token).unwrap().function, function);
        assert_eq!(vm.suspend_external_a5(token, object), Ok(1));
        let resumed = vm.resume_external_a5(object).unwrap();
        assert!(vm.external_event(token).is_err());
        vm.continue_external(
            resumed.top_token().unwrap(),
            ExternalCommand::Return(vec![]),
        )
        .unwrap();
        assert!(vm.resume_external_a5(object).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
