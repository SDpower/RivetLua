use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{BinaryOperation, HostFunctionId, LuaProfile, UnaryOperation, Value};
use rivetlua_runtime::{ExternalCommand, RootKind, RunOutcome, ValueOperation, Vm};

fn compile(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
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
fn typed_operation_uses_vm_execution_for_raw_and_external_results_b5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let mut execution = vm
            .value_operation(
                ValueOperation::Binary(BinaryOperation::Add),
                &[Value::Integer(20), Value::Integer(22)],
            )
            .unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(42)]))
        );
        drop(execution);
        let raw_cases = [
            (
                ValueOperation::Unary(UnaryOperation::Negate),
                vec![Value::Integer(9)],
                Value::Integer(-9),
            ),
            (
                ValueOperation::Binary(BinaryOperation::Less),
                vec![Value::Integer(3), Value::Integer(4)],
                Value::Boolean(true),
            ),
            (
                ValueOperation::Concat,
                vec![Value::Integer(42)],
                Value::Integer(42),
            ),
        ];
        for (operation, args, expected) in raw_cases {
            let outcome = vm.value_operation(operation, &args).unwrap().run().unwrap();
            assert_eq!(outcome, RunOutcome::Returned(vec![expected]));
        }
        let empty = vm
            .value_operation(ValueOperation::Concat, &[])
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = empty else {
            panic!("空串接未產生字串");
        };
        let [Value::Object(empty)] = values.as_slice() else {
            panic!("空串接結果數量錯誤");
        };
        assert_eq!(
            vm.with_byte_string(*empty, |s| s.as_bytes().to_vec())
                .unwrap(),
            b""
        );
    }
}

#[test]
fn c_metamethod_and_nested_operation_resume_same_core_b5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let object = vm.allocate_table().unwrap();
        let object_root = vm.add_root(RootKind::Host, object).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let metatable_root = vm.add_root(RootKind::Host, metatable).unwrap();
        let metamethod = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"__add").unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(metamethod))
            .unwrap();
        vm.set_metatable(object, Some(metatable)).unwrap();
        let outcome = vm
            .value_operation(
                ValueOperation::Binary(BinaryOperation::Add),
                &[Value::Object(object), Value::Integer(2)],
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(outer) = outcome else {
            panic!("C metamethod 未停放: {outcome:?}")
        };
        assert_eq!(vm.external_event(outer).unwrap().function, metamethod);
        let nested = vm
            .continue_external(
                outer,
                ExternalCommand::NestedOperation {
                    operation: ValueOperation::Binary(BinaryOperation::Multiply),
                    args: vec![Value::Integer(6), Value::Integer(7)],
                },
            )
            .unwrap();
        assert_eq!(nested, RunOutcome::NestedReturned(vec![Value::Integer(42)]));
        assert_eq!(vm.external_event(outer).unwrap().function, metamethod);
        assert_eq!(
            vm.continue_external(outer, ExternalCommand::Return(vec![Value::Integer(42)]))
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42)])
        );
        vm.remove_root(metatable_root).unwrap();
        vm.remove_root(object_root).unwrap();
    }
}

#[test]
fn lua_metamethod_uses_original_operation_frame_b5() {
    for (profile, language) in [
        (LuaProfile::Lua54, LanguageProfile::Lua54),
        (LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        let RunOutcome::Returned(values) = vm
            .load_with_environment(
                compile(b"return function(a,b) return 42 end", language),
                Value::Object(environment),
            )
            .unwrap()
            .run()
            .unwrap()
        else {
            panic!("Lua metamethod closure 未返回")
        };
        let Value::Object(function) = values[0] else {
            panic!("closure 類型錯誤")
        };
        let function_root = vm.add_root(RootKind::Host, function).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let metatable_root = vm.add_root(RootKind::Host, metatable).unwrap();
        for name in [b"__add".as_slice(), b"__len", b"__lt", b"__concat"] {
            let key = vm.allocate_byte_string(name).unwrap();
            vm.raw_set(metatable, Value::Object(key), Value::Object(function))
                .unwrap();
        }
        vm.set_metatable(table, Some(metatable)).unwrap();
        for (operation, args, expected) in [
            (
                ValueOperation::Binary(BinaryOperation::Add),
                vec![Value::Object(table), Value::Integer(2)],
                Value::Integer(42),
            ),
            (
                ValueOperation::Unary(UnaryOperation::Length),
                vec![Value::Object(table)],
                Value::Integer(42),
            ),
            (
                ValueOperation::Concat,
                vec![Value::Object(table), Value::Integer(2)],
                Value::Integer(42),
            ),
        ] {
            assert_eq!(
                vm.value_operation(operation, &args).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![expected])
            );
        }
        assert_eq!(
            vm.value_operation(
                ValueOperation::Binary(BinaryOperation::Less),
                &[Value::Object(table), Value::Object(table)]
            )
            .unwrap()
            .run()
            .unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        vm.remove_root(metatable_root).unwrap();
        vm.remove_root(table_root).unwrap();
        vm.remove_root(function_root).unwrap();
        vm.remove_root(environment_root).unwrap();
    }
}

#[test]
fn nested_operation_rejects_wrong_and_stale_external_tokens_b5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let mut other = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let meta_root = vm.add_root(RootKind::Host, metatable).unwrap();
        let key = vm.allocate_byte_string(b"__add").unwrap();
        let function = HostFunctionId::new_unique(vm.id()).unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(function))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        let RunOutcome::External(token) = vm
            .value_operation(
                ValueOperation::Binary(BinaryOperation::Add),
                &[Value::Object(table), Value::Integer(2)],
            )
            .unwrap()
            .run()
            .unwrap()
        else {
            panic!("C operation 未停放")
        };
        let command = || ExternalCommand::NestedOperation {
            operation: ValueOperation::Binary(BinaryOperation::Add),
            args: vec![Value::Integer(20), Value::Integer(22)],
        };
        assert!(other.continue_external(token, command()).is_err());
        assert_eq!(vm.external_event(token).unwrap().function, function);
        assert_eq!(
            vm.continue_external(token, command()).unwrap(),
            RunOutcome::NestedReturned(vec![Value::Integer(42)])
        );
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![Value::Integer(42)]))
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42)])
        );
        assert!(vm.continue_external(token, command()).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(meta_root).unwrap();
        vm.remove_root(table_root).unwrap();
    }
}

#[test]
fn concat_metamethod_visits_operands_from_right_to_left_b5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let values = [
            vm.allocate_table().unwrap(),
            vm.allocate_table().unwrap(),
            vm.allocate_table().unwrap(),
        ];
        let roots = values.map(|table| vm.add_root(RootKind::Host, table).unwrap());
        let metatable = vm.allocate_table().unwrap();
        let meta_root = vm.add_root(RootKind::Host, metatable).unwrap();
        let key = vm.allocate_byte_string(b"__concat").unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        vm.raw_set(metatable, Value::Object(key), Value::CFunction(callback))
            .unwrap();
        for table in values {
            vm.set_metatable(table, Some(metatable)).unwrap();
        }
        let outcome = vm
            .value_operation(ValueOperation::Concat, &values.map(Value::Object))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(first) = outcome else {
            panic!("第一次 concat event 未停放: {outcome:?}")
        };
        assert_eq!(
            vm.external_event(first).unwrap().args,
            &[Value::Object(values[1]), Value::Object(values[2])]
        );
        let bc = vm.allocate_byte_string(b"BC").unwrap();
        let outcome = vm
            .continue_external(first, ExternalCommand::Return(vec![Value::Object(bc)]))
            .unwrap();
        let RunOutcome::External(second) = outcome else {
            panic!("第二次 concat event 未停放: {outcome:?}")
        };
        assert!(vm.external_event(first).is_err());
        assert_eq!(
            vm.external_event(second).unwrap().args,
            &[Value::Object(values[0]), Value::Object(bc)]
        );
        let abc = vm.allocate_byte_string(b"ABC").unwrap();
        assert_eq!(
            vm.continue_external(second, ExternalCommand::Return(vec![Value::Object(abc)]))
                .unwrap(),
            RunOutcome::Returned(vec![Value::Object(abc)])
        );
        assert_eq!(
            vm.with_byte_string(abc, |string| string.as_bytes().to_vec())
                .unwrap(),
            b"ABC"
        );
        vm.remove_root(meta_root).unwrap();
        for root in roots {
            vm.remove_root(root).unwrap();
        }
    }
}

#[test]
fn lua54_less_equal_uses_reverse_less_when_le_absent_b5() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let a = vm.allocate_table().unwrap();
        let b = vm.allocate_table().unwrap();
        let roots = [
            vm.add_root(RootKind::Host, a).unwrap(),
            vm.add_root(RootKind::Host, b).unwrap(),
        ];
        let meta = vm.allocate_table().unwrap();
        let meta_root = vm.add_root(RootKind::Host, meta).unwrap();
        let key = vm.allocate_byte_string(b"__lt").unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        vm.raw_set(meta, Value::Object(key), Value::CFunction(callback))
            .unwrap();
        vm.set_metatable(a, Some(meta)).unwrap();
        vm.set_metatable(b, Some(meta)).unwrap();
        let outcome = vm
            .value_operation(
                ValueOperation::Binary(BinaryOperation::LessEqual),
                &[Value::Object(a), Value::Object(b)],
            )
            .unwrap()
            .run();
        if profile == LuaProfile::Lua54 {
            let RunOutcome::External(token) = outcome.unwrap() else {
                panic!("5.4 __lt fallback 未停放")
            };
            assert_eq!(
                vm.external_event(token).unwrap().args,
                &[Value::Object(b), Value::Object(a)]
            );
            assert_eq!(
                vm.continue_external(token, ExternalCommand::Return(vec![Value::Boolean(true)]))
                    .unwrap(),
                RunOutcome::Returned(vec![Value::Boolean(false)])
            );
        } else {
            assert!(
                matches!(outcome, Ok(RunOutcome::LuaError(_))),
                "5.5 缺少 __le 應回報 Lua 錯誤: {outcome:?}"
            );
        }
        vm.remove_root(meta_root).unwrap();
        for root in roots {
            vm.remove_root(root).unwrap();
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
