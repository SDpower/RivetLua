use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{
    HostFunctionId, LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value,
    VerifyLimits, decode_official_chunk, translate_official_chunk,
};
use rivetlua_runtime::{
    ExternalCommand, FailPoint, GcControl, GcMode, RootKind, RunOutcome, RuntimeErrorKind, Vm,
    VmError,
};

fn compile(
    source: &[u8],
    language: LanguageProfile,
    official: bool,
) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let native = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@capi_open_upvalue_a4b",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone();
    if !official {
        return native;
    }
    let profile = match language {
        LanguageProfile::Lua54 => LuaProfile::Lua54,
        LanguageProfile::Lua55 => LuaProfile::Lua55,
    };
    let chunk = rivetlua_core::bytecode::official_export::emit_official_chunk(
        &native,
        ProtoId(0),
        profile,
        false,
        &OfficialChunkLimits::default(),
        &mut OfficialWorkBudget::new(64 * 1024 * 1024),
    )
    .unwrap();
    let decoded = decode_official_chunk(&chunk, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&decoded, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn parked_lua_frame_open_cell_reads_writes_and_closes_a4b() {
    for (profile, language) in [
        (LuaProfile::Lua54, LanguageProfile::Lua54),
        (LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        for official in [false, true] {
            for mode in [GcMode::Incremental, GcMode::Generational] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                vm.set_gc_mode(mode).unwrap();
                let environment = vm.allocate_table().unwrap();
                let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
                let probe = HostFunctionId::new_unique(vm.id()).unwrap();
                let key = vm.allocate_byte_string(b"probe").unwrap();
                vm.raw_set(environment, Value::Object(key), Value::CFunction(probe))
                    .unwrap();
                let module = compile(
                    b"local x=17; local f=function() return x end; probe(f); return x, f",
                    language,
                    official,
                );
                let outcome = vm
                    .load_with_environment(module, Value::Object(environment))
                    .unwrap()
                    .run()
                    .unwrap();
                let RunOutcome::External(token) = outcome else {
                    panic!("Lua frame 應停在 C callback")
                };
                let Value::Object(function) = vm.external_event(token).unwrap().args[0] else {
                    panic!("callback 應收到 Lua closure")
                };
                let cell = vm
                    .capi_upvalue_cell(Value::Object(function), 1)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    vm.capi_lua_upvalue_name(function, 1).unwrap(),
                    Some(b"x".as_slice())
                );
                assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(17));
                let table = vm.allocate_table().unwrap();
                let table_root = vm.add_root(RootKind::Host, table).unwrap();
                let before_failure = vm.ledger_snapshot();
                vm.inject_failure_once(FailPoint::RootReserve);
                let error = vm.capi_set_upvalue(cell, Value::Object(table)).unwrap_err();
                assert_eq!(
                    error.kind,
                    RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve))
                );
                assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(17));
                assert_eq!(vm.ledger_snapshot(), before_failure);
                vm.capi_set_upvalue(cell, Value::Object(table)).unwrap();
                assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Object(table));
                vm.collect_major().unwrap();
                assert!(vm.object_kind(table).is_ok());
                vm.capi_set_upvalue(cell, Value::Integer(23)).unwrap();
                vm.remove_root(table_root).unwrap();
                vm.collect_major().unwrap();
                assert!(vm.object_kind(table).is_err());
                assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(23));
                let outcome = vm
                    .continue_external(token, ExternalCommand::Return(Vec::new()))
                    .unwrap();
                let RunOutcome::Returned(values) = outcome else {
                    panic!("callback 後應完成 Lua frame")
                };
                assert_eq!(values[0], Value::Integer(23));
                assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(23));
                vm.remove_root(environment_root).unwrap();
            }
        }
    }
}

#[test]
fn suspended_coroutine_open_cell_writes_resume_and_closes_a4b() {
    for (profile, language) in [
        (LuaProfile::Lua54, LanguageProfile::Lua54),
        (LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        for mode in [GcMode::Incremental, GcMode::Generational] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_mode(mode).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_coroutine_builtins(environment).unwrap();
            let module = compile(
                b"return function() local x=17; local f=function() return x end; coroutine.yield(f); return x end",
                language,
                false,
            );
            let function = {
                let mut execution = vm
                    .load_with_environment(module, Value::Object(environment))
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("應取得 coroutine 函式")
                };
                values[0]
            };
            let Value::Object(coroutine) =
                vm.new_coroutine(function).unwrap().as_value(&vm).unwrap()
            else {
                panic!("應取得 coroutine")
            };
            let coroutine_root = vm.add_root(RootKind::Host, coroutine).unwrap();
            let outcome = vm
                .resume(Value::Object(coroutine), &[])
                .unwrap()
                .run()
                .unwrap();
            let RunOutcome::Returned(values) = outcome else {
                panic!("應 yield Lua closure")
            };
            assert_eq!(values[0], Value::Boolean(true));
            let Value::Object(closure) = values[1] else {
                panic!("應 yield closure")
            };
            let closure_root = vm.add_root(RootKind::Host, closure).unwrap();
            let cell = vm
                .capi_upvalue_cell(Value::Object(closure), 1)
                .unwrap()
                .unwrap();
            assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(17));
            vm.capi_set_upvalue(cell, Value::Integer(23)).unwrap();
            assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(23));
            vm.collect_major().unwrap();
            let outcome = vm
                .resume(Value::Object(coroutine), &[])
                .unwrap()
                .run()
                .unwrap();
            assert_eq!(
                outcome,
                RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(23)])
            );
            assert_eq!(vm.capi_read_upvalue(cell).unwrap(), Value::Integer(23));
            vm.remove_root(closure_root).unwrap();
            vm.remove_root(coroutine_root).unwrap();
            vm.remove_root(environment_root).unwrap();
        }
    }
}

#[test]
fn open_and_closed_join_share_cell_across_parked_frame_a4b() {
    for (profile, language) in [
        (LuaProfile::Lua54, LanguageProfile::Lua54),
        (LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        for official in [false, true] {
            for mode in [GcMode::Incremental, GcMode::Generational] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                vm.set_gc_mode(mode).unwrap();
                let closed = compile(
                    b"local function make(x) return function() return x end end; return make(49),make(59)",
                    language, false,
                );
                let RunOutcome::Returned(closed_values) = vm.load(closed).unwrap().run().unwrap()
                else {
                    panic!("應建立兩個 closed Lua closure")
                };
                let [Value::Object(target_closed), Value::Object(source_closed)] =
                    closed_values.as_slice()
                else {
                    panic!("closed closure 回傳值不符")
                };
                let target_closed = *target_closed;
                let source_closed = *source_closed;
                let target_root = vm.add_root(RootKind::Host, target_closed).unwrap();
                let source_root = vm.add_root(RootKind::Host, source_closed).unwrap();
                let environment = vm.allocate_table().unwrap();
                let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
                let probe = HostFunctionId::new_unique(vm.id()).unwrap();
                let key = vm.allocate_byte_string(b"probe").unwrap();
                vm.raw_set(environment, Value::Object(key), Value::CFunction(probe))
                    .unwrap();
                vm.set_collect_every_allocation(true);
                let module = compile(
                    b"local x,y,z=17,29,37; local f=function() return x end; local g=function() return y end; local k=function() return z end; probe(f,g,k); return x,y,z,f,g,k",
                    language, official,
                );
                let RunOutcome::External(token) = vm
                    .load_with_environment(module, Value::Object(environment))
                    .unwrap()
                    .run()
                    .unwrap()
                else {
                    panic!("應停在 probe")
                };
                let [
                    Value::Object(first),
                    Value::Object(second),
                    Value::Object(third),
                ] = vm.external_event(token).unwrap().args
                else {
                    panic!("應有三個 open closure")
                };
                let first = *first;
                let second = *second;
                let third = *third;
                let second_cell = vm
                    .capi_upvalue_cell(Value::Object(second), 1)
                    .unwrap()
                    .unwrap();
                let source_closed_cell = vm
                    .capi_upvalue_cell(Value::Object(source_closed), 1)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    vm.capi_read_upvalue(second_cell).unwrap(),
                    Value::Integer(29)
                );
                assert_eq!(vm.capi_join_lua_upvalues(first, 1, second, 1), Ok(true));
                assert_eq!(
                    vm.capi_join_lua_upvalues(target_closed, 1, second, 1),
                    Ok(true)
                );
                assert_eq!(
                    vm.capi_join_lua_upvalues(third, 1, source_closed, 1),
                    Ok(true)
                );
                assert_eq!(vm.capi_join_lua_upvalues(first, 1, first, 1), Ok(true));
                assert_eq!(vm.capi_join_lua_upvalues(first, 2, second, 1), Ok(false));
                assert_eq!(
                    vm.capi_upvalue_cell(Value::Object(first), 1).unwrap(),
                    Some(second_cell)
                );
                assert_eq!(
                    vm.capi_upvalue_cell(Value::Object(target_closed), 1)
                        .unwrap(),
                    Some(second_cell)
                );
                assert_eq!(
                    vm.capi_upvalue_cell(Value::Object(third), 1).unwrap(),
                    Some(source_closed_cell)
                );
                vm.capi_set_upvalue(second_cell, Value::Integer(33))
                    .unwrap();
                vm.collect_major().unwrap();
                assert_eq!(
                    vm.capi_read_upvalue(second_cell).unwrap(),
                    Value::Integer(33)
                );
                assert_eq!(
                    vm.capi_read_upvalue(source_closed_cell).unwrap(),
                    Value::Integer(59)
                );
                let identity = vm.capi_upvalue_identity_token(second_cell).unwrap();
                let RunOutcome::Returned(values) = vm
                    .continue_external(token, ExternalCommand::Return(Vec::new()))
                    .unwrap()
                else {
                    panic!("parked frame 應恢復並關閉 cell")
                };
                assert_eq!(
                    &values[..3],
                    &[Value::Integer(17), Value::Integer(33), Value::Integer(37)]
                );
                assert_eq!(
                    vm.capi_upvalue_identity_token(second_cell).unwrap(),
                    identity
                );
                assert_eq!(
                    vm.capi_read_upvalue(second_cell).unwrap(),
                    Value::Integer(33)
                );
                vm.remove_root(target_root).unwrap();
                vm.remove_root(source_root).unwrap();
                vm.remove_root(environment_root).unwrap();
            }
        }
    }
}

#[test]
fn old_closure_join_to_open_cell_rolls_back_remembered_failure_a4b() {
    for (profile, language) in [
        (LuaProfile::Lua54, LanguageProfile::Lua54),
        (LuaProfile::Lua55, LanguageProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.gc_control(GcControl::Stop).unwrap();
        vm.set_gc_mode(GcMode::Generational).unwrap();
        let closed = compile(
            b"local x=49; return function() return x end",
            language,
            false,
        );
        let RunOutcome::Returned(values) = vm.load(closed).unwrap().run().unwrap() else {
            panic!("應建立 closed closure")
        };
        let Value::Object(target) = values[0] else {
            panic!("closed closure 應為 object")
        };
        let target_root = vm.add_root(RootKind::Host, target).unwrap();
        let original = vm
            .capi_upvalue_cell(Value::Object(target), 1)
            .unwrap()
            .unwrap();
        vm.collect_major().unwrap();
        vm.collect_major().unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        let probe = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"probe").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(probe))
            .unwrap();
        let module = compile(
            b"local y=29; local g=function() return y end; probe(g); return y,g",
            language,
            false,
        );
        let RunOutcome::External(token) = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap()
            .run()
            .unwrap()
        else {
            panic!("應停在 probe")
        };
        let Value::Object(source) = vm.external_event(token).unwrap().args[0] else {
            panic!("應取得 open closure")
        };
        let source_cell = vm
            .capi_upvalue_cell(Value::Object(source), 1)
            .unwrap()
            .unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::RememberedReserve);
        assert_eq!(
            vm.capi_join_lua_upvalues(target, 1, source, 1),
            Err(VmError::InjectedFailure(FailPoint::RememberedReserve)),
        );
        assert_eq!(
            vm.capi_upvalue_cell(Value::Object(target), 1).unwrap(),
            Some(original)
        );
        assert_eq!(vm.capi_read_upvalue(original).unwrap(), Value::Integer(49));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.capi_join_lua_upvalues(target, 1, source, 1), Ok(true));
        assert_eq!(
            vm.capi_upvalue_cell(Value::Object(target), 1).unwrap(),
            Some(source_cell)
        );
        vm.collect_minor().unwrap();
        assert_eq!(
            vm.capi_read_upvalue(source_cell).unwrap(),
            Value::Integer(29)
        );
        let RunOutcome::Returned(_) = vm
            .continue_external(token, ExternalCommand::Return(Vec::new()))
            .unwrap()
        else {
            panic!("frame 應正常返回")
        };
        assert_eq!(
            vm.capi_read_upvalue(source_cell).unwrap(),
            Value::Integer(29)
        );
        vm.remove_root(target_root).unwrap();
        vm.remove_root(environment_root).unwrap();
    }
}
