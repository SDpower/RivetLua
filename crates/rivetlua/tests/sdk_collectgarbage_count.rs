use rivetlua::{Engine, LuaProfile, RunOutcome, Value};

#[test]
fn sdk_standard_globals_expose_count_as_a_float_in_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return collectgarbage('count')").unwrap();
        let mut vm = engine.new_vm().unwrap();
        let global = vm.get_global(b"collectgarbage").unwrap();
        let outcome = vm.load_module(&module).unwrap().run().unwrap();
        assert!(matches!(global, Value::Object(_)), "{profile:?}");
        assert!(
            matches!(outcome, RunOutcome::Returned(values)
            if matches!(values.as_slice(), [Value::Float(value)] if value.is_finite() && *value >= 0.0)),
            "{profile:?}"
        );
        assert_eq!(vm.allocation_snapshot().reserved, 0);
    }
}

#[test]
fn sdk_count_binding_is_mutable_and_other_vm_keeps_its_own_binding() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return collectgarbage('count')").unwrap();
        let mut changed = engine.new_vm().unwrap();
        changed
            .set_global(b"collectgarbage", Value::Integer(7))
            .unwrap();
        assert_eq!(
            changed.get_global(b"collectgarbage").unwrap(),
            Value::Integer(7)
        );
        let outcome = changed.load_module(&module).unwrap().run().unwrap();
        assert!(
            matches!(outcome, RunOutcome::LuaError(_)),
            "{profile:?}: {outcome:?}"
        );
        changed.set_global(b"collectgarbage", Value::Nil).unwrap();
        assert_eq!(changed.get_global(b"collectgarbage").unwrap(), Value::Nil);
        let mut fresh = engine.new_vm().unwrap();
        let outcome = fresh.load_module(&module).unwrap().run().unwrap();
        assert!(
            matches!(outcome, RunOutcome::Returned(values)
            if matches!(values.as_slice(), [Value::Float(value)] if value.is_finite() && *value >= 0.0)),
            "{profile:?}"
        );
        assert_eq!(changed.allocation_snapshot().reserved, 0);
        assert_eq!(fresh.allocation_snapshot().reserved, 0);
    }
}
