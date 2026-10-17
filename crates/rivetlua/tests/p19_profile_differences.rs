use rivetlua::{Engine, LuaProfile, RunOutcome, Value};

#[test]
fn sdk_profile_rules_cover_generic_for_and_table_create() {
    let readonly_first = b"for key, value in ipairs({1}) do key = 2 end; return true";
    assert!(
        Engine::new(LuaProfile::Lua55)
            .compile(readonly_first)
            .is_err()
    );
    assert!(
        Engine::new(LuaProfile::Lua54)
            .compile(readonly_first)
            .is_ok()
    );

    let writable_later = b"local result = 0; for _, value in ipairs({1}) do value = value + 1; result = value end; return result == 2";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine.compile(writable_later).unwrap();
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
    }

    let lua55 = Engine::new(LuaProfile::Lua55);
    let table_create = lua55
        .compile(
            b"local function empty(t) return type(t) == 'table' and next(t) == nil and #t == 0 end; \
              local valid = empty(table.create(2, 3)) and empty(table.create(0)) and empty(table.create(0, nil)); \
              local invalid = not pcall(table.create) and not pcall(table.create, -1) and not pcall(table.create, 1.5) and \
                not pcall(table.create, 2147483648) and not pcall(table.create, 2, -1) and \
                not pcall(table.create, 2, 1.5) and not pcall(table.create, 2, 2147483648); \
              return valid and invalid",
        )
        .unwrap();
    let mut vm = lua55.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&table_create).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );

    let lua54 = Engine::new(LuaProfile::Lua54);
    let no_table_create = lua54.compile(b"return table.create == nil").unwrap();
    let mut vm = lua54.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&no_table_create).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
}
