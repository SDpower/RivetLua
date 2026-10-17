use std::rc::Rc;

use rivetlua::{
    CallbackResult, Engine, ExternalCommand, ForeignNativeKind, HostServices, LoadCapability,
    LuaProfile, RunOutcome, Value,
};

#[test]
fn sdk_package_cpath_and_loadlib_are_absent_without_host_capability() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(b"return package.cpath == '' and package.loadlib == nil")
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
fn sdk_package_loadlib_uses_host_path_and_returns_host_function() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let module = engine
            .compile(
                b"assert(package.cpath == 'mock/?.so'); \
                  local loader=package.loadlib('mock/libsample.so','luaopen_sample'); \
                  assert(type(loader)=='function'); return loader()",
            )
            .unwrap();
        let services = HostServices::deny_all()
            .and_load(LoadCapability::deny_all().with_foreign_native_cpath(b"mock/?.so".to_vec()));
        let mut vm = engine.new_vm_with_services(services).unwrap();
        let fake_loader = vm
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(73)])),
            )
            .unwrap();
        let fake_loader_value = fake_loader.value(&vm).unwrap();
        let outcome = vm.load_module(&module).unwrap().run().unwrap();
        let RunOutcome::External(token) = outcome else {
            panic!("package.loadlib 應停放宿主 native-load 請求：{outcome:?}");
        };
        let (function, args) = {
            let event = vm.external_event(token).unwrap();
            (event.function, event.args.to_vec())
        };
        assert_eq!(
            vm.foreign_native_kind(function),
            Some(ForeignNativeKind::LoadLib),
            "{profile:?}"
        );
        assert_eq!(args.len(), 2, "{profile:?}");
        let library = vm.root(args[0]).unwrap();
        let entrypoint = vm.root(args[1]).unwrap();
        assert_eq!(vm.read_byte_string(&library).unwrap(), b"mock/libsample.so");
        assert_eq!(vm.read_byte_string(&entrypoint).unwrap(), b"luaopen_sample");

        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![fake_loader_value]),)
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(73)]),
            "{profile:?}"
        );
    }
}
