use rivetlua::{Engine, LuaProfile, Module, RunOutcome, Value, Vm};

fn returned_version(vm: &mut Vm, module: &Module) -> Vec<u8> {
    let RunOutcome::Returned(values) = vm.load_module(module).unwrap().run().unwrap() else {
        panic!("_VERSION chunk 應正常返回")
    };
    let [Value::Object(version)] = values.as_slice() else {
        panic!("_VERSION 必須是 ByteString")
    };
    let root = vm.root(Value::Object(*version)).unwrap();
    vm.read_byte_string(&root).unwrap()
}

#[test]
fn sdk_profile_identity_is_visible_through_standard_globals() {
    for (profile, expected) in [
        (LuaProfile::Lua54, b"Lua 5.4".as_slice()),
        (LuaProfile::Lua55, b"Lua 5.5".as_slice()),
    ] {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return _VERSION").unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        assert_eq!(returned_version(&mut first, &module), expected);
        assert_eq!(returned_version(&mut second, &module), expected);
        first.collect().unwrap();
        assert_eq!(returned_version(&mut first, &module), expected);

        let replacement = first.new_string(b"guest version").unwrap();
        let value = replacement.value(&first).unwrap();
        first.set_global(b"_VERSION", value).unwrap();
        drop(replacement);
        first.collect().unwrap();
        assert_eq!(returned_version(&mut first, &module), b"guest version");
        assert_eq!(returned_version(&mut second, &module), expected);

        first.set_global(b"_VERSION", Value::Nil).unwrap();
        first.collect().unwrap();
        assert_eq!(first.get_global(b"_VERSION").unwrap(), Value::Nil);
        assert_eq!(returned_version(&mut second, &module), expected);
    }
}
