use rivetlua::{Engine, LuaProfile, RunOutcome, Value};

#[test]
fn lookup_cache_preserves_table_mutation_and_weak_gc_behavior() {
    let source = br#"
        local values = {}
        values[-1] = false
        local false_first = values[-1]
        local false_second = values[-1]

        values[-1] = 7
        local updated_first = values[-1]
        local updated_second = values[-1]

        values[-1] = nil
        setmetatable(values, { __index = function() return 9 end })
        local after_meta = values[-1]
        setmetatable(values, nil)
        local after_remove = values[-1]

        local weak = setmetatable({}, { __mode = "v" })
        local weak_was_present = false
        do
            local object = {}
            weak[-1] = object
            weak_was_present = type(weak[-1]) == "table"
        end
        collectgarbage("collect")
        local weak_collected = weak[-1] == nil

        return false_first == false and false_second == false
            and updated_first == 7 and updated_second == 7
            and after_meta == 9 and after_remove == nil
            and weak_was_present and weak_collected
    "#;

    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine.compile(source).unwrap();
        let mut vm = engine.new_vm().unwrap();
        let mut execution = vm.load_module(&module).unwrap();

        assert!(execution.lookup_cache_metadata_bytes() > 0);
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("lookup cache scenario should return normally")
        };
        assert_eq!(values.as_slice(), &[Value::Boolean(true)]);
    }
}
