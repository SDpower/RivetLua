use std::cell::RefCell;
use std::rc::Rc;

use rivetlua::{
    CallbackContinuation, CallbackResult, CompileError, CompileLimits, Engine, FromValue,
    HostOutput, HostOutputError, HostServices, IntoValue, IrLimits, LuaProfile, ModuleOrigin,
    RVLU_V2, RunOutcome, SdkError, Value, VerifyLimits, Vm,
};

fn profiles() -> [LuaProfile; 2] {
    [LuaProfile::Lua54, LuaProfile::Lua55]
}

#[test]
fn sdk_compile_load_and_call_runs_in_both_profiles() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return 40 + 2").unwrap();
        assert_eq!(module.profile(), profile);
        let mut vm = engine.new_vm().unwrap();
        let outcome = vm.load_module(&module).unwrap().run().unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(42)]));
    }
}

#[test]
fn sdk_compiled_module_reports_verified_profile_origin_and_format() {
    let module = Engine::new(LuaProfile::Lua55)
        .compile_named(b"return 42", b"=named-sdk-chunk")
        .unwrap();
    assert_eq!(module.profile(), LuaProfile::Lua55);
    assert_eq!(module.format_version(), RVLU_V2);
    assert_eq!(module.origin(), ModuleOrigin::NativeRvlu);
}

#[test]
fn sdk_module_exposes_only_verified_native_source_and_main_line_range() {
    let source = b"\nreturn 42\n";
    let module = Engine::new(LuaProfile::Lua55)
        .compile_named(source, b"=sdk-native-source")
        .unwrap();
    assert_eq!(module.source_name(), Some(b"=sdk-native-source".as_slice()));
    assert_eq!(module.main_line_range(), Some((0, 0)));
}

#[test]
fn sdk_compile_failure_is_structured() {
    for profile in profiles() {
        let error = Engine::new(profile).compile(b"return )").unwrap_err();
        assert!(matches!(error, CompileError::Diagnostic(_)));
    }
}

#[test]
fn sdk_compile_limits_are_applied_before_lowering() {
    let engine = Engine::new(LuaProfile::Lua55).with_limits(
        CompileLimits {
            max_source_bytes: 1,
            ..CompileLimits::default()
        },
        IrLimits::default(),
        VerifyLimits::default(),
    );
    assert!(matches!(
        engine.compile(b"return 42"),
        Err(CompileError::Diagnostic(_))
    ));
}

#[test]
fn sdk_vm_initializes_standard_libraries_with_host_services_denied_by_default() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let math_module = engine.compile(b"return math.max(6, 7)").unwrap();
        let io_module = engine
            .compile(b"return io.open('blocked-by-default')")
            .unwrap();
        let mut vm = engine.new_vm().unwrap();

        assert_eq!(
            vm.load_module(&math_module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(7)])
        );
        assert!(matches!(
            vm.load_module(&io_module).unwrap().run().unwrap(),
            RunOutcome::LuaError(_)
        ));
    }
}

#[test]
fn sdk_host_output_capability_is_explicit_and_vm_local() {
    struct Capture(Rc<RefCell<Vec<u8>>>);
    impl HostOutput for Capture {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }
    }

    let output = Rc::new(RefCell::new(Vec::new()));
    let services = HostServices::with_output(Capture(Rc::clone(&output)));
    let engine = Engine::new(LuaProfile::Lua55);
    let module = engine.compile(b"print('sdk-output')").unwrap();
    let mut enabled = engine.new_vm_with_services(services).unwrap();
    let mut denied = engine.new_vm().unwrap();

    assert!(matches!(
        enabled.load_module(&module).unwrap().run().unwrap(),
        RunOutcome::Returned(_)
    ));
    assert_eq!(&*output.borrow(), b"sdk-output\n");
    assert!(matches!(
        denied.load_module(&module).unwrap().run().unwrap(),
        RunOutcome::LuaError(_)
    ));
    assert_eq!(&*output.borrow(), b"sdk-output\n");
}

#[test]
fn sdk_globals_tables_and_byte_strings_use_owned_checked_operations() {
    for profile in profiles() {
        let mut vm = Vm::new(profile).unwrap();
        let table = vm.new_table().unwrap();
        let table_value = table.value(&vm).unwrap();
        let key = vm.new_string(b"payload\0bytes").unwrap();
        let key_value = key.value(&vm).unwrap();
        vm.table_raw_set(&table, key_value, Value::Integer(42))
            .unwrap();
        assert_eq!(
            vm.table_raw_get(&table, key_value).unwrap(),
            Value::Integer(42)
        );
        assert_eq!(vm.read_byte_string(&key).unwrap(), b"payload\0bytes");

        vm.set_global(b"host_table", table_value).unwrap();
        assert_eq!(vm.get_global(b"host_table").unwrap(), table_value);
        vm.collect().unwrap();
        assert_eq!(vm.read_byte_string(&key).unwrap(), b"payload\0bytes");

        let mut foreign = Vm::new(profile).unwrap();
        let foreign_table = foreign.new_table().unwrap();
        let foreign_value = foreign_table.value(&foreign).unwrap();
        assert!(matches!(
            vm.table_raw_set(&table, Value::Integer(1), foreign_value),
            Err(SdkError::RuntimeVm(_))
        ));
        assert!(matches!(
            vm.table_raw_set(&table, foreign_value, Value::Integer(2)),
            Err(SdkError::RuntimeVm(_))
        ));
        assert!(matches!(
            vm.table_raw_get(&table, foreign_value),
            Err(SdkError::RuntimeVm(_))
        ));
        assert!(matches!(
            vm.set_global(b"foreign", foreign_value),
            Err(SdkError::RuntimeVm(_))
        ));
    }
}

#[test]
fn sdk_module_profile_mismatch_is_rejected() {
    let module = Engine::new(LuaProfile::Lua54).compile(b"return 1").unwrap();
    let mut vm = Engine::new(LuaProfile::Lua55).new_vm().unwrap();
    assert!(matches!(
        vm.load_module(&module),
        Err(SdkError::ProfileMismatch {
            vm: LuaProfile::Lua55,
            module: LuaProfile::Lua54,
        })
    ));
}

#[test]
fn sdk_modules_and_roots_are_vm_local() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return {}").unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();

        let first_value = match first.load_module(&module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期回傳表格，得到 {other:?}"),
        };
        let first_root = first.root(first_value).unwrap();
        let second_value = match second.load_module(&module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期回傳表格，得到 {other:?}"),
        };
        let second_root = second.root(second_value).unwrap();

        assert_ne!(
            first_root.value(&first).unwrap(),
            second_root.value(&second).unwrap()
        );
        assert!(matches!(
            first_root.value(&second),
            Err(SdkError::RuntimeVm(_))
        ));
    }
}

#[test]
fn sdk_callback_errors_and_fuel_abort_remain_distinct() {
    for profile in profiles() {
        let mut vm = Vm::new(profile).unwrap();
        let callback = vm
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(8)])),
            )
            .unwrap();
        let returned = vm.call(&callback, &[]).unwrap().run().unwrap();
        assert_eq!(returned, RunOutcome::Returned(vec![Value::Integer(8)]));

        let throwing = vm
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Throw(Value::Integer(9))),
            )
            .unwrap();
        assert!(matches!(
            vm.call(&throwing, &[]).unwrap().run().unwrap(),
            RunOutcome::LuaError(_)
        ));
        let retry = vm
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(8)])),
            )
            .unwrap();
        assert_eq!(
            vm.call(&retry, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(8)])
        );

        let module = Engine::new(profile).compile(b"return 10").unwrap();
        let mut execution = vm.load_module(&module).unwrap();
        execution.set_fuel(0).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Aborted(rivetlua::AbortReason::FuelExhausted)
        );
        drop(execution);
        assert_eq!(
            vm.call(&retry, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(8)])
        );
    }
}

#[test]
fn sdk_callback_call_continuation_and_hostcall_preserve_multiple_values() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let target_module = engine
            .compile(b"return function(a, b) return a + b, a * b end")
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        let target_value = match vm.load_module(&target_module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期回傳函式，得到 {other:?}"),
        };
        let target = vm.root(target_value).unwrap();
        let callback = vm
            .register_callback(
                &[target_value],
                Rc::new(|context, args| {
                    context.call(
                        context.capture(0).unwrap(),
                        args.to_vec(),
                        CallbackContinuation::new(
                            vec![],
                            Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                        ),
                    )
                }),
            )
            .unwrap();
        assert_eq!(
            vm.call(&callback, &[Value::Integer(3), Value::Integer(4)])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(12)])
        );

        vm.set_global(b"host_multi", callback.value(&vm).unwrap())
            .unwrap();
        let hostcall = engine.compile(b"return host_multi(5, 6)").unwrap();
        assert_eq!(
            vm.load_module(&hostcall).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(11), Value::Integer(30)])
        );
        let pcall_value = vm.get_global(b"pcall").unwrap();
        let pcall = vm.root(pcall_value).unwrap();
        assert_eq!(
            vm.call(
                &pcall,
                &[target_value, Value::Integer(5), Value::Integer(6)]
            )
            .unwrap()
            .run()
            .unwrap(),
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Integer(11),
                Value::Integer(30)
            ])
        );
        assert!(matches!(target.value(&vm), Ok(Value::Object(_))));
    }
}

#[test]
fn sdk_callback_yield_continuation_resumes_through_host_api() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let mut vm = engine.new_vm().unwrap();
        let marker = vm.new_table().unwrap();
        let marker_value = marker.value(&vm).unwrap();
        let callback = vm
            .register_callback(
                &[marker_value],
                Rc::new(|context, _| {
                    context.yield_with(
                        vec![Value::Integer(7)],
                        CallbackContinuation::new(
                            vec![context.capture(0).unwrap()],
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
        vm.set_global(b"host_yield", callback.value(&vm).unwrap())
            .unwrap();
        let module = engine
            .compile(b"return coroutine.create(function() local a,b=host_yield(); return a,b end)")
            .unwrap();
        let coroutine_value = match vm.load_module(&module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期建立 coroutine，得到 {other:?}"),
        };
        let coroutine = vm.root(coroutine_value).unwrap();
        assert_eq!(
            vm.resume(&coroutine, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
        );
        assert_eq!(
            vm.resume(&coroutine, &[Value::Integer(42)])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), marker_value, Value::Integer(42)])
        );
        assert!(matches!(marker.value(&vm), Ok(Value::Object(_))));
    }
}

#[test]
fn sdk_callback_resume_action_uses_runtime_continuation() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine
            .compile(
                b"return coroutine.create(function(x) coroutine.yield(x + 1); return x + 2 end)",
            )
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        let coroutine_value = match vm.load_module(&module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期建立 coroutine，得到 {other:?}"),
        };
        let coroutine = vm.root(coroutine_value).unwrap();
        let callback = vm
            .register_callback(
                &[coroutine_value],
                Rc::new(|context, args| {
                    context.resume(
                        context.capture(0).unwrap(),
                        args.to_vec(),
                        CallbackContinuation::new(
                            vec![],
                            Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                        ),
                    )
                }),
            )
            .unwrap();
        assert_eq!(
            vm.call(&callback, &[Value::Integer(10)])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(11)])
        );
        assert!(matches!(coroutine.value(&vm), Ok(Value::Object(_))));
    }
}

#[test]
fn sdk_cross_vm_callback_inputs_and_actions_are_rejected() {
    let mut foreign = Vm::new(LuaProfile::Lua55).unwrap();
    let foreign_object = foreign.new_table().unwrap();
    let foreign_value = foreign_object.value(&foreign).unwrap();
    let mut vm = Vm::new(LuaProfile::Lua55).unwrap();
    assert!(matches!(
        vm.register_callback(
            &[foreign_value],
            Rc::new(|_, _| CallbackResult::Return(vec![]))
        ),
        Err(SdkError::RuntimeVm(_))
    ));

    let echo = vm
        .register_callback(
            &[],
            Rc::new(|_, args| CallbackResult::Return(args.to_vec())),
        )
        .unwrap();
    {
        let foreign_args = vm.call(&echo, &[foreign_value]);
        assert!(matches!(foreign_args, Err(SdkError::Runtime(_))));
    }

    let foreign_action = foreign_value;
    let action = vm
        .register_callback(
            &[],
            Rc::new(move |context, _| {
                context.call(
                    foreign_action,
                    vec![],
                    CallbackContinuation::new(
                        vec![],
                        Rc::new(|_, values| CallbackResult::Return(values.to_vec())),
                    ),
                )
            }),
        )
        .unwrap();
    assert!(matches!(
        vm.call(&action, &[]).unwrap().run(),
        Err(rivetlua::RuntimeError {
            kind: rivetlua::RuntimeErrorKind::Heap(rivetlua::VmError::WrongVm),
            ..
        })
    ));
    assert!(matches!(
        foreign_object.value(&foreign),
        Ok(Value::Object(_))
    ));
}

#[test]
fn sdk_callback_captures_and_returned_objects_are_rooted_across_gc() {
    for profile in profiles() {
        let mut vm = Vm::new(profile).unwrap();
        let captured_root = vm.new_table().unwrap();
        let captured_value = captured_root.value(&vm).unwrap();
        let callback = vm
            .register_callback(
                &[captured_value],
                Rc::new(|context, _| CallbackResult::Return(vec![context.capture(0).unwrap()])),
            )
            .unwrap();
        drop(captured_root);
        vm.collect().unwrap();

        let returned = {
            let mut execution = vm.call(&callback, &[]).unwrap();
            match execution.run().unwrap() {
                RunOutcome::Returned(mut values) => values.remove(0),
                other => panic!("預期 callback 回傳 capture，得到 {other:?}"),
            }
        };
        let returned_root = vm.root(returned).unwrap();
        vm.collect().unwrap();
        assert_eq!(returned_root.value(&vm).unwrap(), captured_value);
    }
}

#[test]
fn sdk_coroutine_can_resume_through_sdk() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return function() return 12 end").unwrap();
        let mut vm = Vm::new(profile).unwrap();
        let function_value = match vm.load_module(&module).unwrap().run().unwrap() {
            RunOutcome::Returned(values) => values[0],
            other => panic!("預期回傳函式，得到 {other:?}"),
        };
        let function = vm.root(function_value).unwrap();
        let coroutine = vm.new_coroutine(&function).unwrap();
        let resumed = vm.resume(&coroutine, &[]).unwrap().run().unwrap();
        assert_eq!(
            resumed,
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(12)])
        );
    }
}

#[test]
fn sdk_roots_survive_gc_clone_safely_and_reject_other_vm() {
    for profile in profiles() {
        let mut first = Vm::new(profile).unwrap();
        let second = Vm::new(profile).unwrap();
        let root = first.new_table().unwrap();
        let clone = root.try_clone(&mut first).unwrap();

        first.collect().unwrap();
        drop(root);
        first.collect().unwrap();
        assert!(matches!(clone.value(&second), Err(SdkError::RuntimeVm(_))));
        let mut second_mut = second;
        assert!(matches!(
            clone.try_clone(&mut second_mut),
            Err(SdkError::RuntimeVm(_))
        ));
        assert!(matches!(clone.value(&first), Ok(Value::Object(_))));
    }
}

#[test]
fn sdk_dropped_last_root_collects_and_stale_value_is_rejected() {
    for profile in profiles() {
        let mut vm = Vm::new(profile).unwrap();
        let root = vm.new_table().unwrap();
        let copied_value = root.value(&vm).unwrap();
        drop(root);
        vm.collect().unwrap();
        assert!(matches!(vm.root(copied_value), Err(SdkError::RuntimeVm(_))));
    }
}

#[test]
fn sdk_allocation_limit_and_injected_failure_allow_clean_same_vm_retry() {
    for profile in profiles() {
        let mut vm = Vm::new(profile).unwrap();
        let committed = vm.allocation_snapshot().committed;
        vm.set_allocation_limit(committed);
        assert!(vm.new_table().is_err());
        assert_eq!(vm.allocation_snapshot().reserved, 0);

        vm.set_allocation_limit(committed.saturating_add(1024 * 1024));
        vm.inject_next_allocation_failure();
        assert!(vm.new_table().is_err());
        assert_eq!(vm.allocation_snapshot().reserved, 0);

        let recovered = vm.new_table().unwrap();
        assert!(matches!(recovered.value(&vm), Ok(Value::Object(_))));
        assert_eq!(vm.allocation_snapshot().reserved, 0);
    }
}

#[test]
fn sdk_primitive_value_conversions_are_explicit_and_checked() {
    assert_eq!(true.into_value(), Value::Boolean(true));
    assert_eq!(42_i64.into_value(), Value::Integer(42));
    assert_eq!(().into_value(), Value::Nil);
    assert_eq!(f64::from_value(Value::Integer(42)), Some(42.0));
    assert_eq!(i64::from_value(Value::Float(1.5)), None);
}
