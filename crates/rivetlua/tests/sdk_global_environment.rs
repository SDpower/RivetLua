use rivetlua::{Engine, LuaProfile, Module, RunOutcome, Value, Vm};

fn returned(vm: &mut Vm, module: &Module) -> Vec<Value> {
    match vm.load_module(module).unwrap().run().unwrap() {
        RunOutcome::Returned(values) => values,
        other => panic!("預期正常返回：{other:?}"),
    }
}

#[test]
fn sdk_vm_exposes_global_alias_and_guest_arg_assignment() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(b"_G.ARG = arg; return _G == _ENV, _G.ARG == arg")
            .unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        let first_arg = first.new_table().unwrap();
        let second_arg = second.new_table().unwrap();
        let first_arg_value = first_arg.value(&first).unwrap();
        let second_arg_value = second_arg.value(&second).unwrap();
        first.set_global(b"arg", first_arg_value).unwrap();
        second.set_global(b"arg", second_arg_value).unwrap();
        let first_globals = first.globals().value(&first).unwrap();
        let second_globals = second.globals().value(&second).unwrap();
        assert_ne!(first_globals, second_globals, "{profile:?} VM identity");
        assert_eq!(first.get_global(b"_G").unwrap(), first_globals);
        assert_eq!(second.get_global(b"_G").unwrap(), second_globals);
        assert_eq!(
            returned(&mut first, &module),
            [Value::Boolean(true), Value::Boolean(true)]
        );
        assert_eq!(
            returned(&mut second, &module),
            [Value::Boolean(true), Value::Boolean(true)]
        );
        assert_eq!(first.get_global(b"ARG").unwrap(), first_arg_value);
        assert_eq!(second.get_global(b"ARG").unwrap(), second_arg_value);
        assert!(second.set_global(b"foreign", first_globals).is_err());
        assert_eq!(first.allocation_snapshot().reserved, 0);
        assert_eq!(second.allocation_snapshot().reserved, 0);
    }
}

#[test]
fn sdk_global_alias_is_guest_mutable_without_redirecting_globals() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        let original = first.globals().value(&first).unwrap();
        let replacement = first.new_table().unwrap();
        let replacement_value = replacement.value(&first).unwrap();
        first.set_global(b"_G", replacement_value).unwrap();
        drop(replacement);
        first.collect().unwrap();
        assert_eq!(first.get_global(b"_G").unwrap(), replacement_value);
        assert_eq!(
            returned(
                &mut first,
                &engine
                    .compile(b"marker=11; return _G == _ENV, _G.marker, marker")
                    .unwrap(),
            ),
            [Value::Boolean(false), Value::Nil, Value::Integer(11)]
        );
        assert_eq!(first.globals().value(&first).unwrap(), original);
        assert_eq!(
            second.get_global(b"_G").unwrap(),
            second.globals().value(&second).unwrap()
        );
        first.set_global(b"_G", Value::Nil).unwrap();
        first.collect().unwrap();
        assert_eq!(first.get_global(b"_G").unwrap(), Value::Nil);
        assert_eq!(
            returned(&mut first, &engine.compile(b"return marker").unwrap()),
            [Value::Integer(11)]
        );
        assert_eq!(
            returned(&mut second, &engine.compile(b"return marker").unwrap()),
            [Value::Nil]
        );
        assert_eq!(first.allocation_snapshot().reserved, 0);
        assert_eq!(second.allocation_snapshot().reserved, 0);
    }
}
