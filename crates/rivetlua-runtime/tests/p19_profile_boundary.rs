use rivetlua_compiler::{CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{RunOutcome, Vm};

#[test]
fn vm_load_enforces_module_language_profile() {
    let compile_return = |profile: LanguageProfile| {
        let limits = CompileLimits::default();
        let tokens = lex(b"return 42", profile, &limits).unwrap();
        let syntax = parse(&tokens, profile, &limits).unwrap();
        let resolved = resolve(&syntax, &tokens, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    };

    for module_profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let compiler_profile: LanguageProfile = module_profile;
        let core_profile: LuaProfile = compiler_profile;
        assert_eq!(core_profile, module_profile);

        let module = compile_return(compiler_profile);
        let matching_outcome = {
            let mut vm = Vm::new_with_profile(module_profile).unwrap();
            vm.load(module.clone()).unwrap().run().unwrap()
        };
        assert_eq!(
            matching_outcome,
            RunOutcome::Returned(vec![Value::Integer(42)])
        );

        let runtime_profile = match module_profile {
            LuaProfile::Lua54 => LuaProfile::Lua55,
            LuaProfile::Lua55 => LuaProfile::Lua54,
        };
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        let error = match vm.load(module) {
            Err(error) => error,
            Ok(execution) => {
                drop(execution);
                panic!("VM must reject a module compiled for the other profile");
            }
        };
        let diagnostic = format!("{error:?}");
        assert!(
            diagnostic.contains(&format!("{runtime_profile:?}")),
            "diagnostic must include the VM profile: {diagnostic}"
        );
        assert!(
            diagnostic.contains(&format!("{module_profile:?}")),
            "diagnostic must include the module profile: {diagnostic}"
        );
    }
}
