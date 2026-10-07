use rivetlua::{Engine, LuaProfile, RunOutcome, RuntimeErrorKind, Value};

#[test]
fn sdk_vm_registers_standard_library_tables_for_require_in_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(
                b"local names={'_G','package','coroutine','string','table','math','utf8','io','os','debug'}; for i=1,#names do local name=names[i]; if type(_G[name])~='table' or package.loaded[name]~=_G[name] or require(name)~=_G[name] then return false,name end end; return true",
            )
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn sdk_require_math_and_debug_matches_existing_globals() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(b"return require('math')==math and require('debug')==debug")
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn sdk_cleared_or_false_standard_cache_uses_preload_searcher() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(b"local oldm,oldd=math,debug; local calls=0; package.preload.math=function() calls=calls+1; return {tag=11} end; package.preload.debug=function() calls=calls+1; return {tag=22} end; package.loaded.math=nil; package.loaded.debug=false; local m=require('math'); local d=require('debug'); return m.tag,d.tag,calls,m~=oldm,d~=oldd,math==oldm,debug==oldd")
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![
                Value::Integer(11),
                Value::Integer(22),
                Value::Integer(2),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(true),
            ]),
            "{profile:?}"
        );
    }
}

#[test]
fn sdk_standard_module_mutation_is_vm_local_and_debug_policy_stays_denied() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let mutate = engine
            .compile(b"math.private_marker=17; return package.loaded.math==math")
            .unwrap();
        let inspect = engine
            .compile(b"return math.private_marker==nil and package.loaded.math==math")
            .unwrap();
        let denied = engine
            .compile(b"return require('debug').setmetatable({}, {})")
            .unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        assert_eq!(
            first.load_module(&mutate).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert_eq!(
            second.load_module(&inspect).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert!(matches!(
            first.load_module(&denied).unwrap().run().unwrap(),
            RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostPolicyDebug
        ));
    }
}
