use std::cell::{Cell, RefCell};
use std::rc::Rc;

use rivetlua::{
    AbortReason, CallbackResult, ContainerLimits, HostEntropy, HostEntropyError, HostOutput,
    HostOutputError, HostServices, LuaProfile, RunOutcome, RuntimeErrorKind, SdkError,
    TransportBudget, Value, Vm,
};

fn profiles() -> [LuaProfile; 2] {
    [LuaProfile::Lua54, LuaProfile::Lua55]
}

fn run(vm: &mut Vm, module: &rivetlua::Module) -> RunOutcome {
    vm.load_module(module).unwrap().run().unwrap()
}

fn returned_object(vm: &mut Vm, outcome: RunOutcome) -> rivetlua::Root {
    match outcome {
        RunOutcome::Returned(mut values) if values.len() == 1 => vm.root(values.remove(0)).unwrap(),
        other => panic!("預期單一物件回傳，得到 {other:?}"),
    }
}

fn string_field(vm: &mut Vm, table: &rivetlua::Root, field: &[u8]) -> rivetlua::Root {
    let key = vm.new_string(field).unwrap();
    let value = vm.table_raw_get(table, key.value(vm).unwrap()).unwrap();
    vm.root(value).unwrap()
}

fn array_value(vm: &Vm, table: &rivetlua::Root, index: i64) -> Value {
    vm.table_raw_get(table, Value::Integer(index)).unwrap()
}

fn assert_returned_values(outcome: RunOutcome, expected: &[Value]) {
    match outcome {
        RunOutcome::Returned(values) => assert_eq!(values, expected),
        other => panic!("預期 Returned({expected:?})，得到 {other:?}"),
    }
}

fn assert_entropy_seed(outcome: RunOutcome, seed: i64) {
    match outcome {
        RunOutcome::Returned(values) => {
            assert_eq!(values.len(), 2);
            assert_eq!(values[0], Value::Integer(seed));
            assert!(matches!(values[1], Value::Integer(_)));
        }
        other => panic!("預期 randomseed 回傳兩個整數，得到 {other:?}"),
    }
}

fn assert_same_lua_error(
    first: &mut Vm,
    first_outcome: RunOutcome,
    second: &mut Vm,
    second_outcome: RunOutcome,
) {
    let (RunOutcome::LuaError(first_error), RunOutcome::LuaError(second_error)) =
        (first_outcome, second_outcome)
    else {
        panic!("兩 VM 應回傳同類 LuaError");
    };
    assert_eq!(first_error.kind, RuntimeErrorKind::Thrown);
    assert_eq!(first_error.kind, second_error.kind);
    assert_eq!(first_error.diagnostic_id, second_error.diagnostic_id);
    assert_eq!(first_error.source_pc, second_error.source_pc);
    assert_eq!(first_error.source_prototype, second_error.source_prototype);
    assert_eq!(first_error.source_depth, second_error.source_depth);
    match (first_error.value, second_error.value) {
        (Value::Integer(first_value), Value::Integer(second_value)) => {
            assert_eq!(first_value, second_value);
        }
        (Value::Boolean(first_value), Value::Boolean(second_value)) => {
            assert_eq!(first_value, second_value);
        }
        (Value::Object(first_value), Value::Object(second_value)) => {
            let first_root = first.root(Value::Object(first_value)).unwrap();
            let second_root = second.root(Value::Object(second_value)).unwrap();
            let first_bytes = first.read_byte_string(&first_root).unwrap();
            let second_bytes = second.read_byte_string(&second_root).unwrap();
            assert_eq!(first_bytes, b"same failure");
            assert_eq!(second_bytes, b"same failure");
            assert_eq!(first_bytes, second_bytes);
        }
        (first_value, second_value) => {
            panic!("LuaError payload 類型不同：{first_value:?} 與 {second_value:?}")
        }
    }
}

fn package_subtable(vm: &mut Vm, name: &[u8]) -> rivetlua::Root {
    let package_value = vm.get_global(b"package").unwrap();
    let package = vm.root(package_value).unwrap();
    let key = vm.new_string(name).unwrap();
    let value = vm.table_raw_get(&package, key.value(vm).unwrap()).unwrap();
    vm.root(value).unwrap()
}

fn install_preload(
    vm: &mut Vm,
    preload: &rivetlua::Root,
    name: &[u8],
    value: i64,
    calls: Rc<Cell<usize>>,
) {
    let loader = vm
        .register_callback(
            &[],
            Rc::new(move |_, _| {
                calls.set(calls.get() + 1);
                CallbackResult::Return(vec![Value::Integer(value)])
            }),
        )
        .unwrap();
    let key = vm.new_string(name).unwrap();
    vm.table_raw_set(preload, key.value(vm).unwrap(), loader.value(vm).unwrap())
        .unwrap();
}

struct FixedEntropy {
    seed: u64,
    calls: Rc<Cell<usize>>,
}

impl HostEntropy for FixedEntropy {
    fn seed(&mut self) -> Result<u64, HostEntropyError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.seed)
    }
}

#[test]
fn sdk_state_separation_shared_clone_and_restored_module_keep_vm_state_local() {
    let source = br#"
return {
    read_marker = function() return marker end,
    build = function(seed)
        return function(...)
            local values = {...}
            values[#values + 1] = seed
            return values
        end
    end,
    coroutine = function(tag)
        return function()
            local resumed = coroutine.yield(tag)
            return tag, resumed
        end
    end,
}
"#;

    for profile in profiles() {
        let engine = rivetlua::Engine::new(profile);
        let module = engine
            .compile_named(source, b"=state-separation-native")
            .unwrap();
        let module_clone = module.clone();
        let budget = TransportBudget::new(ContainerLimits::default());
        let container = engine.save_module(&module, &budget).unwrap();
        let restored_engine = rivetlua::Engine::new(profile);
        let restored = restored_engine.load_module(&container, &budget).unwrap();
        assert_eq!(module_clone.profile(), restored.profile());
        assert_eq!(module_clone.source_name(), restored.source_name());

        let restored_clone = restored.clone();
        let exercise_pair = |first_engine: &rivetlua::Engine,
                             first_module: &rivetlua::Module,
                             second_engine: &rivetlua::Engine,
                             second_module: &rivetlua::Module| {
            // 同一 clone 組與 original／RVCT-restored 組都在兩個存活 VM 上完整驗收。
            let mut first = first_engine.new_vm().unwrap();
            let mut second = second_engine.new_vm().unwrap();
            let first_outcome = run(&mut first, first_module);
            let first_exports = returned_object(&mut first, first_outcome);
            let second_outcome = run(&mut second, second_module);
            let second_exports = returned_object(&mut second, second_outcome);

            first.set_global(b"marker", Value::Integer(11)).unwrap();
            second.set_global(b"marker", Value::Integer(22)).unwrap();
            let first_reader = string_field(&mut first, &first_exports, b"read_marker");
            let second_reader = string_field(&mut second, &second_exports, b"read_marker");
            assert_returned_values(
                first.call(&first_reader, &[]).unwrap().run().unwrap(),
                &[Value::Integer(11)],
            );
            assert_returned_values(
                second.call(&second_reader, &[]).unwrap().run().unwrap(),
                &[Value::Integer(22)],
            );

            let first_build = string_field(&mut first, &first_exports, b"build");
            let second_build = string_field(&mut second, &second_exports, b"build");
            let first_inner_outcome = first
                .call(&first_build, &[Value::Integer(41)])
                .unwrap()
                .run()
                .unwrap();
            let first_inner = returned_object(&mut first, first_inner_outcome);
            let second_inner_outcome = second
                .call(&second_build, &[Value::Integer(99)])
                .unwrap()
                .run()
                .unwrap();
            let second_inner = returned_object(&mut second, second_inner_outcome);
            let first_text = first.new_string(b"first-vm").unwrap();
            let second_text = second.new_string(b"second-vm").unwrap();
            let first_text_value = first_text.value(&first).unwrap();
            let second_text_value = second_text.value(&second).unwrap();
            let first_result_outcome = first
                .call(&first_inner, &[Value::Integer(7), first_text_value])
                .unwrap()
                .run()
                .unwrap();
            let first_result = returned_object(&mut first, first_result_outcome);
            let second_result_outcome = second
                .call(&second_inner, &[Value::Integer(8), second_text_value])
                .unwrap()
                .run()
                .unwrap();
            let second_result = returned_object(&mut second, second_result_outcome);
            assert_eq!(array_value(&first, &first_result, 1), Value::Integer(7));
            let first_result_text_value = array_value(&first, &first_result, 2);
            let first_result_text = first.root(first_result_text_value).unwrap();
            assert_eq!(
                first.read_byte_string(&first_result_text).unwrap(),
                b"first-vm"
            );
            assert_eq!(array_value(&first, &first_result, 3), Value::Integer(41));
            assert_eq!(array_value(&second, &second_result, 1), Value::Integer(8));
            let second_result_text_value = array_value(&second, &second_result, 2);
            let second_result_text = second.root(second_result_text_value).unwrap();
            assert_eq!(
                second.read_byte_string(&second_result_text).unwrap(),
                b"second-vm"
            );
            assert_eq!(array_value(&second, &second_result, 3), Value::Integer(99));

            assert!(matches!(
                first.root(second_result.value(&second).unwrap()),
                Err(SdkError::RuntimeVm(_))
            ));
            assert!(matches!(
                first.root(second_text_value),
                Err(SdkError::RuntimeVm(_))
            ));
            assert!(matches!(
                first.table_raw_get(&first_result, second_text_value),
                Err(SdkError::RuntimeVm(_))
            ));
            assert!(matches!(
                first.call(&second_inner, &[]),
                Err(SdkError::RuntimeVm(_))
            ));

            let first_coroutine_factory = string_field(&mut first, &first_exports, b"coroutine");
            let second_coroutine_factory = string_field(&mut second, &second_exports, b"coroutine");
            let first_coroutine_function_outcome = first
                .call(&first_coroutine_factory, &[Value::Integer(31)])
                .unwrap()
                .run()
                .unwrap();
            let first_coroutine_function =
                returned_object(&mut first, first_coroutine_function_outcome);
            let second_coroutine_function_outcome = second
                .call(&second_coroutine_factory, &[Value::Integer(52)])
                .unwrap()
                .run()
                .unwrap();
            let second_coroutine_function =
                returned_object(&mut second, second_coroutine_function_outcome);
            let first_coroutine = first.new_coroutine(&first_coroutine_function).unwrap();
            let second_coroutine = second.new_coroutine(&second_coroutine_function).unwrap();
            assert_returned_values(
                first.resume(&first_coroutine, &[]).unwrap().run().unwrap(),
                &[Value::Boolean(true), Value::Integer(31)],
            );
            assert_returned_values(
                second
                    .resume(&second_coroutine, &[])
                    .unwrap()
                    .run()
                    .unwrap(),
                &[Value::Boolean(true), Value::Integer(52)],
            );
            assert!(matches!(
                first.resume(&second_coroutine, &[Value::Integer(1)]),
                Err(SdkError::RuntimeVm(_))
            ));
            assert_returned_values(
                first
                    .resume(&first_coroutine, &[Value::Integer(71)])
                    .unwrap()
                    .run()
                    .unwrap(),
                &[Value::Boolean(true), Value::Integer(31), Value::Integer(71)],
            );
            assert_returned_values(
                second
                    .resume(&second_coroutine, &[Value::Integer(82)])
                    .unwrap()
                    .run()
                    .unwrap(),
                &[Value::Boolean(true), Value::Integer(52), Value::Integer(82)],
            );

            // 一個 VM 的 GC 不得影響另一 VM 的 rooted heap 值。
            first.collect().unwrap();
            assert_eq!(array_value(&second, &second_result, 1), Value::Integer(8));
            let second_result_text = second
                .root(array_value(&second, &second_result, 2))
                .unwrap();
            assert_eq!(
                second.read_byte_string(&second_result_text).unwrap(),
                b"second-vm"
            );

            let stale = second.new_table().unwrap();
            let stale_value = stale.value(&second).unwrap();
            drop(stale);
            second.collect().unwrap();
            assert!(matches!(
                second.root(stale_value),
                Err(SdkError::RuntimeVm(_))
            ));

            // VM 執行後重新保存同一 immutable Module，bytes 必須與執行前完全一致。
            let saved_after_execution = first_engine.save_module(first_module, &budget).unwrap();
            assert_eq!(saved_after_execution, container);
            let restored_after_execution = restored_engine
                .load_module(&saved_after_execution, &budget)
                .unwrap();
            let mut third = restored_engine.new_vm().unwrap();
            let third_outcome = run(&mut third, &restored_after_execution);
            let third_exports = returned_object(&mut third, third_outcome);
            let third_reader = string_field(&mut third, &third_exports, b"read_marker");
            assert_returned_values(
                third.call(&third_reader, &[]).unwrap().run().unwrap(),
                &[Value::Nil],
            );

            let error_module = first_engine.compile(b"error('same failure')").unwrap();
            let first_error = run(&mut first, &error_module);
            let second_error = run(&mut second, &error_module);
            assert_same_lua_error(&mut first, first_error, &mut second, second_error);

            let aborted_module = first_engine.compile(b"return 42").unwrap();
            let mut first_execution = first.load_module(&aborted_module).unwrap();
            first_execution.set_fuel(0).unwrap();
            let first_aborted = first_execution.run().unwrap();
            drop(first_execution);
            let mut second_execution = second.load_module(&aborted_module).unwrap();
            second_execution.set_fuel(0).unwrap();
            let second_aborted = second_execution.run().unwrap();
            drop(second_execution);
            assert_eq!(
                first_aborted,
                RunOutcome::Aborted(AbortReason::FuelExhausted)
            );
            assert_eq!(first_aborted, second_aborted);
        };

        // native original、RVCT restored 各自與 clone 共用 VerifiedModule，再測兩種版本互通。
        exercise_pair(&engine, &module, &engine, &module_clone);
        exercise_pair(&engine, &module, &restored_engine, &restored);
        exercise_pair(
            &restored_engine,
            &restored,
            &restored_engine,
            &restored_clone,
        );
    }
}

#[test]
fn sdk_state_separation_keeps_package_registry_callbacks_and_host_providers_local() {
    struct FixedOutput(Rc<RefCell<Vec<u8>>>);
    impl HostOutput for FixedOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }
    }

    for profile in profiles() {
        let engine = rivetlua::Engine::new(profile);
        let first_output = Rc::new(RefCell::new(Vec::new()));
        let second_output = Rc::new(RefCell::new(Vec::new()));
        let first_entropy_calls = Rc::new(Cell::new(0));
        let second_entropy_calls = Rc::new(Cell::new(0));
        let first_services = HostServices::with_output(FixedOutput(Rc::clone(&first_output)))
            .and_entropy(FixedEntropy {
                seed: 111,
                calls: Rc::clone(&first_entropy_calls),
            });
        let second_services = HostServices::with_output(FixedOutput(Rc::clone(&second_output)))
            .and_entropy(FixedEntropy {
                seed: 222,
                calls: Rc::clone(&second_entropy_calls),
            });
        let mut first = engine.new_vm_with_services(first_services).unwrap();
        let mut second = engine.new_vm_with_services(second_services).unwrap();

        let print_module = engine.compile(b"print('host output')").unwrap();
        assert_returned_values(run(&mut first, &print_module), &[]);
        assert_returned_values(run(&mut second, &print_module), &[]);
        assert_eq!(&*first_output.borrow(), b"host output\n");
        assert_eq!(&*second_output.borrow(), b"host output\n");
        first_output.borrow_mut().clear();
        let mut denied_vm = engine.new_vm().unwrap();
        let denied_output = run(&mut denied_vm, &print_module);
        assert!(matches!(
            denied_output,
            RunOutcome::LuaError(ref error) if error.kind == RuntimeErrorKind::HostPolicyOutput
        ));
        assert!(first_output.borrow().is_empty());
        assert_eq!(&*second_output.borrow(), b"host output\n");

        let entropy_module = engine.compile(b"return math.randomseed()").unwrap();
        assert_entropy_seed(run(&mut first, &entropy_module), 111);
        assert_entropy_seed(run(&mut second, &entropy_module), 222);
        assert_eq!(first_entropy_calls.get(), 1);
        assert_eq!(second_entropy_calls.get(), 1);
        assert_entropy_seed(run(&mut first, &entropy_module), 111);
        assert_eq!(first_entropy_calls.get(), 2);
        assert_eq!(second_entropy_calls.get(), 1);

        let callback_module = engine.compile(b"return vm_callback()").unwrap();
        let first_callback = first
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(301)])),
            )
            .unwrap();
        let second_callback = second
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(402)])),
            )
            .unwrap();
        first
            .set_global(b"vm_callback", first_callback.value(&first).unwrap())
            .unwrap();
        second
            .set_global(b"vm_callback", second_callback.value(&second).unwrap())
            .unwrap();
        assert_returned_values(run(&mut first, &callback_module), &[Value::Integer(301)]);
        assert_returned_values(run(&mut second, &callback_module), &[Value::Integer(402)]);
        assert!(matches!(
            first.root(second_callback.value(&second).unwrap()),
            Err(SdkError::RuntimeVm(_))
        ));

        let first_calls = Rc::new(Cell::new(0));
        let second_calls = Rc::new(Cell::new(0));
        let first_preload = package_subtable(&mut first, b"preload");
        let second_preload = package_subtable(&mut second, b"preload");
        install_preload(
            &mut first,
            &first_preload,
            b"state-isolation-module",
            503,
            Rc::clone(&first_calls),
        );
        install_preload(
            &mut second,
            &second_preload,
            b"state-isolation-module",
            604,
            Rc::clone(&second_calls),
        );
        let require_module = engine
            .compile(b"local loaded = require('state-isolation-module'); return loaded")
            .unwrap();
        assert_returned_values(run(&mut first, &require_module), &[Value::Integer(503)]);
        assert_returned_values(run(&mut second, &require_module), &[Value::Integer(604)]);
        assert_eq!(first_calls.get(), 1);
        assert_eq!(second_calls.get(), 1);

        // 丟棄宿主 table roots，再替換 package global；require 仍使用各 VM 的隱藏 registry。
        drop(first_preload);
        drop(second_preload);
        first.set_global(b"package", Value::Nil).unwrap();
        second.set_global(b"package", Value::Nil).unwrap();
        assert_returned_values(run(&mut first, &require_module), &[Value::Integer(503)]);
        assert_returned_values(run(&mut second, &require_module), &[Value::Integer(604)]);
        assert_eq!(first_calls.get(), 1);
        assert_eq!(second_calls.get(), 1);

        let denied_entropy = run(&mut denied_vm, &entropy_module);
        assert!(matches!(
            denied_entropy,
            RunOutcome::LuaError(ref error)
                if error.kind == RuntimeErrorKind::HostPolicyEntropy
        ));
        assert_eq!(first_entropy_calls.get(), 2);
        assert_eq!(second_entropy_calls.get(), 1);
    }
}
