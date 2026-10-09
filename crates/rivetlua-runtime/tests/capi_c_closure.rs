use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, Value, VerifyLimits};
use rivetlua_runtime::{HostHandle, ObjectKind, RunOutcome, Vm, VmError};

fn compile(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, profile, &limits).unwrap();
    let parsed = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn capi_c_closure_closed_cells_trace_and_reclaim() {
    for profile in [
        rivetlua_core::LuaProfile::Lua54,
        rivetlua_core::LuaProfile::Lua55,
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let id = HostFunctionId::new_unique(vm.id()).unwrap();
        let captured = vm.allocate_table().unwrap();
        let mut published = None;
        let closure = vm
            .prepare_unpublished_c_closure::<VmError>(
                id,
                &[Value::Integer(17), Value::Object(captured)],
                |_, _| Ok(()),
                |object, root| published = Some((object, root)),
            )
            .unwrap();
        let (published_object, root) = published.unwrap();
        assert_eq!(closure, published_object);
        assert_eq!(vm.object_kind(closure), Ok(ObjectKind::CClosure));
        assert_eq!(vm.capi_c_closure_function(closure), Ok(id));
        let first = vm
            .capi_upvalue_cell(Value::Object(closure), 1)
            .unwrap()
            .unwrap();
        let second = vm
            .capi_upvalue_cell(Value::Object(closure), 2)
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(vm.capi_closed_upvalue(first), Ok(Some(Value::Integer(17))));
        assert_eq!(
            vm.capi_closed_upvalue(second),
            Ok(Some(Value::Object(captured)))
        );
        assert_eq!(
            vm.capi_upvalue_identity_token(first),
            vm.capi_upvalue_identity_token(first)
        );
        assert_ne!(
            vm.capi_upvalue_identity_token(first),
            vm.capi_upvalue_identity_token(second)
        );
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
        drop(root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(closure), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn capi_lua_closure_join_shares_closed_cell_and_rejects_invalid() {
    for (runtime_profile, source_profile) in [
        (rivetlua_core::LuaProfile::Lua54, LanguageProfile::Lua54),
        (rivetlua_core::LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        let source =
            b"local function make(x) return function() return x end end; return make(1), make(2)";
        let outcome = vm
            .load(compile(source, source_profile))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("Lua closure fixture 須正常返回");
        };
        let [Value::Object(first), Value::Object(second)] = values.as_slice() else {
            panic!("Lua closure fixture 須返回兩個 closure");
        };
        let first = *first;
        let second = *second;
        let first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
        let second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
        assert_eq!(vm.object_kind(first), Ok(ObjectKind::Closure));
        assert_eq!(vm.object_kind(second), Ok(ObjectKind::Closure));
        let first_cell = vm
            .capi_upvalue_cell(Value::Object(first), 1)
            .unwrap()
            .unwrap();
        let second_cell = vm
            .capi_upvalue_cell(Value::Object(second), 1)
            .unwrap()
            .unwrap();
        assert_ne!(first_cell, second_cell);
        assert_eq!(
            vm.capi_closed_upvalue(first_cell),
            Ok(Some(Value::Integer(1)))
        );
        assert_eq!(
            vm.capi_closed_upvalue(second_cell),
            Ok(Some(Value::Integer(2)))
        );
        assert_eq!(vm.capi_join_lua_upvalues(first, 1, second, 1), Ok(true));
        assert_eq!(
            vm.capi_upvalue_cell(Value::Object(first), 1),
            Ok(Some(second_cell))
        );
        assert_eq!(
            vm.capi_set_closed_upvalue(second_cell, Value::Integer(8)),
            Ok(true)
        );
        assert_eq!(
            vm.capi_closed_upvalue(second_cell),
            Ok(Some(Value::Integer(8)))
        );
        assert_eq!(vm.capi_join_lua_upvalues(first, 2, second, 1), Ok(false));
        assert_eq!(vm.capi_join_lua_upvalues(first, 1, second, 2), Ok(false));
        assert_eq!(vm.capi_join_lua_upvalues(first, 1, first, 1), Ok(true));
        drop(first_root);
        drop(second_root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(second), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn capi_lua_environment_upvalue_has_cell_identity() {
    for (runtime_profile, source_profile) in [
        (rivetlua_core::LuaProfile::Lua54, LanguageProfile::Lua54),
        (rivetlua_core::LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        let source = b"return function() return _G end";
        let outcome = vm
            .load(compile(source, source_profile))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("環境 closure fixture 須正常返回");
        };
        let [Value::Object(function)] = values.as_slice() else {
            panic!("環境 closure fixture 須返回 closure");
        };
        let function = *function;
        let root = HostHandle::<Value>::new(&mut vm, function).unwrap();
        let cell = vm.capi_upvalue_cell(Value::Object(function), 1).unwrap();
        assert!(cell.is_some(), "_ENV 須有 Lua upvalue cell");
        let cell = cell.unwrap();
        assert_eq!(
            vm.capi_upvalue_identity_token(cell),
            vm.capi_upvalue_identity_token(cell)
        );
        drop(root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(cell), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
