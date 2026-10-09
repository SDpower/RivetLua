use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{
    CallbackResult, ExternalCommand, FailPoint, FinalizerState, GcControl, HostHandle, ObjectKind,
    RootKind, RunOutcome, RuntimeErrorKind, TableSortStop, Vm, VmError,
};
use std::rc::Rc;

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

#[test]
fn external_c_function_parks_and_resumes_same_execution_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let outcome = {
            let mut execution = vm
                .call(Value::CFunction(function), &[Value::Integer(7)])
                .unwrap();
            execution.run().unwrap()
        };
        let RunOutcome::External(token) = outcome else {
            panic!("C 函式必須讓同一 execution 停在外部邊界");
        };
        let event = vm.external_event(token).unwrap();
        assert_eq!(event.function, function);
        assert_eq!(event.args, &[Value::Integer(7)]);
        vm.collect_major().unwrap();
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![Value::Integer(12)])),
            Ok(RunOutcome::Returned(vec![Value::Integer(12)]))
        );
        assert!(vm.external_event(token).is_err());
    }
}

#[test]
fn nested_c_call_uses_lifo_tokens_and_restores_outer_callback_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let first = {
            let mut execution = vm.call(Value::CFunction(outer), &[]).unwrap();
            execution.run().unwrap()
        };
        let RunOutcome::External(outer_token) = first else {
            panic!("外層 callback 未停放");
        };
        let nested = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![Value::Integer(9)],
                    results: rivetlua_core::ResultMode::Fixed(2),
                },
            )
            .unwrap();
        let RunOutcome::External(inner_token) = nested else {
            panic!("內層 callback 未停放");
        };
        assert_eq!(
            vm.external_event(inner_token).unwrap().args,
            &[Value::Integer(9)]
        );
        assert_ne!(inner_token, outer_token);
        assert!(vm.external_event(outer_token).is_err());
        assert!(
            vm.continue_external(outer_token, ExternalCommand::Return(vec![]))
                .is_err()
        );
        vm.collect_major().unwrap();
        assert_eq!(
            vm.continue_external(
                inner_token,
                ExternalCommand::Return(vec![Value::Integer(10)])
            ),
            Ok(RunOutcome::NestedReturned(vec![
                Value::Integer(10),
                Value::Nil,
            ]))
        );
        assert!(
            vm.continue_external(inner_token, ExternalCommand::Return(vec![]))
                .is_err()
        );
        assert_eq!(
            vm.continue_external(
                outer_token,
                ExternalCommand::Return(vec![Value::Integer(11)])
            ),
            Ok(RunOutcome::Returned(vec![Value::Integer(11)]))
        );
    }
}

#[test]
fn nested_callback_abort_preserves_outer_close_unwind_b7() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let captured = vm.allocate_table().unwrap();
        let closure = vm
            .prepare_unpublished_c_closure::<VmError>(
                outer,
                &[Value::Object(captured)],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        let outer_token = {
            let mut execution = vm.call(Value::Object(closure), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("外層 callback 未停放");
            };
            token
        };
        let inner_token = match vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![],
                    results: rivetlua_core::ResultMode::Fixed(0),
                },
            )
            .unwrap()
        {
            RunOutcome::External(token) => token,
            _ => panic!("內層 callback 未停放"),
        };
        assert!(vm.external_event(outer_token).is_err());
        vm.abort_external_nested_callback(inner_token).unwrap();
        assert!(vm.external_event(inner_token).is_err());
        assert_eq!(
            vm.external_event(outer_token).unwrap().captures,
            &[Value::Object(captured)]
        );
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
        let retry = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![],
                    results: rivetlua_core::ResultMode::Fixed(0),
                },
            )
            .unwrap();
        let RunOutcome::External(retry_token) = retry else {
            panic!("下層關閉處理器無法續接同一外層 execution");
        };
        assert_eq!(
            vm.continue_external(retry_token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::NestedReturned(vec![]))
        );
        assert_eq!(
            vm.continue_external(outer_token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));
    }
}

#[test]
fn external_token_rejects_cross_vm_and_abort_releases_closure_captures_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let mut other = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let captured = vm.allocate_table().unwrap();
        let closure = vm
            .prepare_unpublished_c_closure::<VmError>(
                function,
                &[Value::Object(captured)],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        let token = {
            let mut execution = vm.call(Value::Object(closure), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("C closure 未停放");
            };
            token
        };
        assert_eq!(
            vm.external_event(token).unwrap().captures,
            &[Value::Object(captured)]
        );
        assert!(other.external_event(token).is_err());
        assert!(
            other
                .continue_external(token, ExternalCommand::Return(vec![]))
                .is_err()
        );
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
        vm.abort_external(token).unwrap();
        assert!(vm.abort_external(token).is_err());
        assert!(vm.external_event(token).is_err());
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn nested_callback_panic_cleans_marker_and_allows_retry_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let callback = vm
            .register_callback(
                &[],
                Rc::new(|_, _| -> CallbackResult { panic!("B4 callback panic") }),
            )
            .unwrap();
        let callback_value = callback.as_value(&vm).unwrap();
        let baseline = vm.ledger_snapshot();
        let token = {
            let mut execution = vm.call(Value::CFunction(function), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("C 函式未停放");
            };
            token
        };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vm.continue_external(
                token,
                ExternalCommand::NestedCall {
                    target: callback_value,
                    args: vec![],
                    results: rivetlua_core::ResultMode::All,
                },
            )
        }));
        assert!(panic.is_err());
        assert!(vm.abort_external(token).is_err());
        assert_eq!(vm.ledger_snapshot().committed, baseline.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let retry = {
            let mut execution = vm.call(Value::CFunction(function), &[]).unwrap();
            execution.run().unwrap()
        };
        let RunOutcome::External(retry) = retry else {
            panic!("panic 後同 VM 不可重試");
        };
        vm.abort_external(retry).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn nested_start_allocation_failure_preserves_outer_token_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for failpoint in [
            FailPoint::WorkReserve,
            FailPoint::CallFrameReserve,
            FailPoint::RootReserve,
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let outer = HostFunctionId::new_unique(vm.id()).unwrap();
            let inner = HostFunctionId::new_unique(vm.id()).unwrap();
            let argument = vm.allocate_table().unwrap();
            let _held = HostHandle::<Value>::new(&mut vm, argument).unwrap();
            let token = {
                let mut execution = vm.call(Value::CFunction(outer), &[]).unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("外層未停放");
                };
                token
            };
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(failpoint);
            let failure = vm.continue_external(
                token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![Value::Object(argument)],
                    results: rivetlua_core::ResultMode::All,
                },
            );
            assert!(failure.is_err(), "{profile:?} {failpoint:?}");
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.ledger_snapshot().committed, before.committed);
            assert_eq!(
                vm.continue_external(token, ExternalCommand::Return(vec![])),
                Ok(RunOutcome::Returned(vec![]))
            );
        }
    }
}

#[test]
fn vm_drop_cleans_parked_c_closure_and_capture_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let probe = vm.ledger_probe();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        let captured = vm.allocate_table().unwrap();
        let closure = vm
            .prepare_unpublished_c_closure::<VmError>(
                function,
                &[Value::Object(captured)],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        let token = {
            let mut execution = vm.call(Value::Object(closure), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("C closure 未停放");
            };
            token
        };
        assert_eq!(
            vm.external_event(token).unwrap().captures,
            &[Value::Object(captured)]
        );
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}

#[test]
fn unrelated_execution_cannot_run_beside_parked_core_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let unrelated = HostFunctionId::new_unique(vm.id()).unwrap();
        let captured = vm.allocate_table().unwrap();
        let closure = vm
            .prepare_unpublished_c_closure::<VmError>(
                outer,
                &[Value::Object(captured)],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        let token = {
            let mut execution = vm.call(Value::Object(closure), &[]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("外層 C closure 未停放");
            };
            token
        };
        let parked_ledger = vm.ledger_snapshot();
        let parked_roots = vm.roots().count(rivetlua_runtime::RootKind::Temporary);

        let mut independent = vm.call(Value::CFunction(unrelated), &[]).unwrap();
        assert_eq!(
            independent.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(independent);
        assert_eq!(vm.ledger_snapshot().committed, parked_ledger.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(
            vm.roots().count(rivetlua_runtime::RootKind::Temporary),
            parked_roots
        );

        let mut other_constructor = vm.resume(Value::Nil, &[]).unwrap();
        assert_eq!(
            other_constructor.run().unwrap_err().kind,
            RuntimeErrorKind::TerminalExecution
        );
        drop(other_constructor);
        vm.collect_major().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
        let event = vm.external_event(token).unwrap();
        assert_eq!(event.function, outer);
        assert_eq!(event.captures, &[Value::Object(captured)]);
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![Value::Integer(42)])),
            Ok(RunOutcome::Returned(vec![Value::Integer(42)]))
        );
    }
}

#[test]
fn abort_parked_sort_restores_trace_and_allows_retry_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_table_builtins(environment).unwrap();
        let comparator = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"cmp").unwrap();
        vm.raw_set(
            environment,
            Value::Object(key),
            Value::CFunction(comparator),
        )
        .unwrap();
        assert_eq!(
            vm.raw_get(environment, Value::Object(key)),
            Ok(Value::CFunction(comparator))
        );
        let module = compile(b"local t={3,1,2}; table.sort(t,function(a,b) return cmp(a,b) end); return t[1],t[2],t[3]", profile);
        let token = {
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            let RunOutcome::External(token) = outcome else {
                panic!(
                    "排序 comparator 未停放: {outcome:?}, trace={:?}",
                    vm.table_sort_trace()
                );
            };
            token
        };
        assert_eq!(vm.external_event(token).unwrap().function, comparator);
        assert_eq!(vm.table_sort_trace().stop, TableSortStop::Running);
        assert!(vm.table_sort_trace().comparisons > 0);
        let comparisons = vm.table_sort_trace().comparisons;
        vm.abort_external(token).unwrap();
        assert_eq!(vm.table_sort_trace().stop, TableSortStop::Aborted);
        assert_eq!(vm.table_sort_trace().comparisons, comparisons);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut outcome = {
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            execution.run().unwrap()
        };
        for _ in 0..20 {
            let RunOutcome::External(next) = outcome else {
                break;
            };
            let event = vm.external_event(next).unwrap();
            let [Value::Integer(left), Value::Integer(right)] = event.args else {
                panic!("排序 comparator 參數錯誤");
            };
            outcome = vm
                .continue_external(
                    next,
                    ExternalCommand::Return(vec![Value::Boolean(left < right)]),
                )
                .unwrap();
        }
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
            ])
        );
        assert_eq!(vm.table_sort_trace().stop, TableSortStop::Completed);
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn abort_parked_finalizer_finishes_once_and_allows_next_finalizer_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for c_closure in [false, true] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let finalizer = HostFunctionId::new_unique(vm.id()).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            let key = vm.allocate_byte_string(b"finalize").unwrap();
            let callback = if c_closure {
                Value::Object(
                    vm.prepare_unpublished_c_closure::<VmError>(
                        finalizer,
                        &[Value::Integer(7)],
                        |_, _| Ok(()),
                        |_, root| drop(root),
                    )
                    .unwrap(),
                )
            } else {
                Value::CFunction(finalizer)
            };
            vm.raw_set(environment, Value::Object(key), callback)
                .unwrap();
            let entry = HostFunctionId::new_unique(vm.id()).unwrap();
            let first_token = {
                let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local function make() local a=setmetatable({}, {__gc=finalize}); local b=setmetatable({}, {__gc=finalize}) end; make(); collectgarbage('collect'); return 1",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
                let outcome = execution.run().unwrap();
                drop(execution);
                let RunOutcome::External(token) = outcome else {
                    panic!("finalizer 未停放: {outcome:?}, gc={:?}", vm.gc_trace());
                };
                token
            };
            assert_eq!(vm.gc_trace().finalizer_pending, 2);
            let object = match vm.external_event(first_token).unwrap().args {
                [Value::Object(object)] => *object,
                args => panic!("finalizer 參數錯誤: {args:?}"),
            };
            assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Running));
            vm.abort_external(first_token).unwrap();
            assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
            assert_eq!(vm.gc_trace().finalizer_pending, 1);
            assert_eq!(vm.gc_trace().finalizer_warnings, 1);
            assert_eq!(vm.ledger_snapshot().reserved, 0);

            let second_token = {
                let mut execution = vm.call(Value::CFunction(entry), &[]).unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("下一個 finalizer 未停放");
                };
                token
            };
            let next = match vm.external_event(second_token).unwrap().args {
                [Value::Object(object)] => *object,
                args => panic!("下一個 finalizer 參數錯誤: {args:?}"),
            };
            assert_ne!(next, object);
            vm.abort_external(second_token).unwrap();
            assert_eq!(vm.finalizer_state(next), Ok(FinalizerState::Finalized));
            assert_eq!(vm.gc_trace().finalizer_pending, 0);
            assert_eq!(vm.gc_trace().finalizer_warnings, 2);
            let entry_token = {
                let mut execution = vm.call(Value::CFunction(entry), &[]).unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("finalizer 清理後原始呼叫未停放");
                };
                token
            };
            assert_eq!(
                vm.continue_external(entry_token, ExternalCommand::Return(vec![])),
                Ok(RunOutcome::Returned(vec![]))
            );
            vm.remove_root(environment_root).unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn returned_external_finalizer_resumes_script_once_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let finalizer = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"finalize").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(finalizer))
            .unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local function make() local x=setmetatable({}, {__gc=finalize}) end; make(); collectgarbage('collect'); return 37",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("finalizer 未停放");
            };
            token
        };
        let object = match vm.external_event(token).unwrap().args {
            [Value::Object(object)] => *object,
            args => panic!("finalizer 參數錯誤: {args:?}"),
        };
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Running));
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![Value::Integer(37)]))
        );
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.gc_trace().finalizer_warnings, 0);
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn gc_control_error_finalizer_warns_and_continues_b8() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let finalizer = HostFunctionId::new_unique(vm.id()).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(finalizer))
            .unwrap();
        let objects = [vm.allocate_table().unwrap(), vm.allocate_table().unwrap()];
        for object in objects {
            vm.set_metatable(object, Some(metatable)).unwrap();
        }
        vm.gc_control(GcControl::Collect).unwrap();
        assert_eq!(vm.gc_trace().finalizer_pending, 2);
        let first = {
            let mut execution = vm.gc_finalizer_execution(None).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("第一個 finalizer 未停放");
            };
            token
        };
        let RunOutcome::External(second) = vm
            .continue_external(first, ExternalCommand::Error(Value::Integer(88)))
            .unwrap()
        else {
            panic!("錯誤後未執行下一個 finalizer");
        };
        assert_eq!(vm.gc_trace().finalizer_warnings, 1);
        assert_eq!(vm.gc_trace().finalizer_pending, 1);
        assert_eq!(
            vm.continue_external(second, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.gc_trace().finalizer_warnings, 1);
        for object in objects {
            assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn direct_gc_external_finalizer_aborts_once_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for c_closure in [false, true] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let finalizer = HostFunctionId::new_unique(vm.id()).unwrap();
            let callback = if c_closure {
                Value::Object(
                    vm.prepare_unpublished_c_closure::<VmError>(
                        finalizer,
                        &[Value::Integer(9)],
                        |_, _| Ok(()),
                        |_, root| drop(root),
                    )
                    .unwrap(),
                )
            } else {
                Value::CFunction(finalizer)
            };
            let metatable = vm.allocate_table().unwrap();
            let key = vm.allocate_byte_string(b"__gc").unwrap();
            vm.raw_set(metatable, Value::Object(key), callback).unwrap();
            let object = vm.allocate_table().unwrap();
            vm.set_metatable(object, Some(metatable)).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
            assert_eq!(vm.gc_trace().finalizer_pending, 0);
            assert_eq!(vm.gc_trace().finalizer_warnings, 1);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn vm_drop_cleans_parked_sort_and_finalizer_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut sort_vm = Vm::new_with_profile(profile).unwrap();
        let sort_probe = sort_vm.ledger_probe();
        let environment = sort_vm.allocate_table().unwrap();
        sort_vm.install_basic_builtins(environment).unwrap();
        sort_vm.install_table_builtins(environment).unwrap();
        let comparator = HostFunctionId::new_unique(sort_vm.id()).unwrap();
        let key = sort_vm.allocate_byte_string(b"cmp").unwrap();
        sort_vm
            .raw_set(
                environment,
                Value::Object(key),
                Value::CFunction(comparator),
            )
            .unwrap();
        let sort_token = {
            let mut execution = sort_vm
                .load_with_environment(
                    compile(
                        b"local t={2,1}; table.sort(t,function(a,b) return cmp(a,b) end)",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("排序 comparator 未停放");
            };
            token
        };
        assert_eq!(
            sort_vm.external_event(sort_token).unwrap().function,
            comparator
        );
        drop(sort_vm);
        assert_eq!(sort_probe.snapshot().committed, 0);
        assert_eq!(sort_probe.snapshot().reserved, 0);

        let mut finalizer_vm = Vm::new_with_profile(profile).unwrap();
        let finalizer_probe = finalizer_vm.ledger_probe();
        let environment = finalizer_vm.allocate_table().unwrap();
        let environment_root = finalizer_vm.add_root(RootKind::Host, environment).unwrap();
        finalizer_vm.install_basic_builtins(environment).unwrap();
        let finalizer = HostFunctionId::new_unique(finalizer_vm.id()).unwrap();
        let key = finalizer_vm.allocate_byte_string(b"finalize").unwrap();
        finalizer_vm
            .raw_set(environment, Value::Object(key), Value::CFunction(finalizer))
            .unwrap();
        let finalizer_token = {
            let mut execution = finalizer_vm
                .load_with_environment(
                    compile(
                        b"local function make() local x=setmetatable({}, {__gc=finalize}) end; make(); collectgarbage('collect')",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("finalizer 未停放");
            };
            token
        };
        assert_eq!(
            finalizer_vm
                .external_event(finalizer_token)
                .unwrap()
                .function,
            finalizer
        );
        finalizer_vm.remove_root(environment_root).unwrap();
        drop(finalizer_vm);
        assert_eq!(finalizer_probe.snapshot().committed, 0);
        assert_eq!(finalizer_probe.snapshot().reserved, 0);
    }
}

#[test]
fn failed_external_return_aborts_owned_sort_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_table_builtins(environment).unwrap();
        let comparator = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"cmp").unwrap();
        vm.raw_set(
            environment,
            Value::Object(key),
            Value::CFunction(comparator),
        )
        .unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local t={3,1}; table.sort(t,function(a,b) return cmp(a,b) end)",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("排序 comparator 未停放");
            };
            token
        };
        let comparisons = vm.table_sort_trace().comparisons;
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(
            vm.continue_external(
                token,
                ExternalCommand::Return(vec![Value::Object(environment)]),
            )
            .is_err()
        );
        assert!(vm.external_event(token).is_err());
        assert_eq!(vm.table_sort_trace().comparisons, comparisons);
        assert_eq!(vm.table_sort_trace().stop, TableSortStop::Aborted);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(environment_root).unwrap();
    }
}

#[test]
fn nested_callback_panic_aborts_owned_finalizer_b4() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let finalizer = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"finalize").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(finalizer))
            .unwrap();
        let callback = vm
            .register_callback(
                &[],
                Rc::new(|_, _| -> CallbackResult { panic!("B4 finalizer nested panic") }),
            )
            .unwrap();
        let callback_value = callback.as_value(&vm).unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local function make() local x=setmetatable({}, {__gc=finalize}) end; make(); collectgarbage('collect')",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("finalizer 未停放");
            };
            token
        };
        let object = match vm.external_event(token).unwrap().args {
            [Value::Object(object)] => *object,
            args => panic!("finalizer 參數錯誤: {args:?}"),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vm.continue_external(
                token,
                ExternalCommand::NestedCall {
                    target: callback_value,
                    args: vec![],
                    results: rivetlua_core::ResultMode::All,
                },
            )
        }));
        assert!(result.is_err());
        assert_eq!(vm.finalizer_state(object), Ok(FinalizerState::Finalized));
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.gc_trace().finalizer_warnings, 1);
        assert!(vm.external_event(token).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(environment_root).unwrap();
    }
}
