use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{HostHandle, RunOutcome, Vm};

fn compile(source: &[u8]) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
    let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default()).unwrap().into_verified()
}

#[test]
fn explicit_wildcard_compiles_and_runs_through_vm_without_special_environment() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.set_collect_every_allocation(true);
    for (source, expected) in [
        (
            b"global<const>*; global a; return _VERSION".as_slice(),
            vec![b"Lua 5.5".to_vec()],
        ),
        (
            b"global<const>*; local function f() return _VERSION end; return f()",
            vec![b"Lua 5.5".to_vec()],
        ),
        (
            b"global<const>*; global a; local function f() return _VERSION end; return f()",
            vec![b"Lua 5.5".to_vec()],
        ),
    ] {
        let outcome = vm
            .load_with_environment(compile(source), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("有效 wildcard chunk 應返回：{outcome:?}")
        };
        assert_eq!(values.len(), expected.len());
        for (value, bytes) in values.into_iter().zip(expected) {
            let Value::Object(object) = value else {
                panic!("預期 ByteString")
            };
            assert_eq!(
                vm.with_byte_string(object, |value| value.as_bytes().to_vec()),
                Ok(bytes)
            );
        }
    }
    assert_eq!(
        vm.load_with_environment(
            compile(b"global *; global a; a=3; free=4; return a,free"),
            Value::Object(environment)
        )
        .unwrap()
        .run()
        .unwrap(),
        RunOutcome::Returned(vec![Value::Integer(3), Value::Integer(4)])
    );
    assert!(matches!(
        vm.load_with_environment(
            compile(b"global *; local f=nil; return f()"),
            Value::Object(environment)
        )
        .unwrap()
        .run()
        .unwrap(),
        RunOutcome::LuaError(_)
    ));
}
