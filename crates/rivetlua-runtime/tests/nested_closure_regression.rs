use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    Instruction, InstructionOffset, LuaProfile, Register, UpvalueId, Value, VerifyLimits,
    native_builtin_candidate_from_calls, verify_module, verify_native_builtin_plan,
};
use rivetlua_runtime::{
    AbortReason, AllocationFailureKind, HostHandle, HostServices, RunOutcome, Vm,
};

const MAKE: &str = "local function make(n)\n  local captured = 'saved'\n  return function(x, ...)\n    local inner = function() return n, captured end\n    local a, b = inner()\n    collectgarbage('collect')\n    return a + x, b, select('#', ...), ...\n  end\nend\n";

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

fn vm_with_basic_globals(profile: LanguageProfile) -> (Vm, HostHandle<Value>) {
    let runtime_profile = match profile {
        LanguageProfile::Lua54 => LuaProfile::Lua54,
        LanguageProfile::Lua55 => LuaProfile::Lua55,
    };
    let mut vm = Vm::new_with_services(runtime_profile, HostServices::deny_all()).unwrap();
    let globals = vm.allocate_table().unwrap();
    let globals_root = HostHandle::<Value>::new(&mut vm, globals).unwrap();
    vm.install_basic_builtins(globals).unwrap();
    (vm, globals_root)
}

fn with_returned(source: &[u8], profile: LanguageProfile, check: impl FnOnce(&mut Vm, &[Value])) {
    let (mut vm_inner, globals) = vm_with_basic_globals(profile);
    vm_inner.set_collect_every_allocation(true);
    let environment = globals.as_value(&vm_inner).unwrap();
    let outcome = vm_inner
        .load_with_environment(compile(source, profile), environment)
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("有效巢狀 closure 須成功返回，實際：{outcome:?}")
    };
    check(&mut vm_inner, &values);
}

fn assert_bytes(vm: &Vm, value: Value, expected: &[u8]) {
    let Value::Object(object) = value else {
        panic!("預期 byte string，實際：{value:?}")
    };
    assert_eq!(
        vm.with_byte_string(object, |string| string.as_bytes().to_vec()),
        Ok(expected.to_vec())
    );
}

fn assert_five_values(vm: &mut Vm, values: &[Value]) {
    assert_eq!(values.len(), 5);
    assert_eq!(values[0], Value::Integer(42));
    assert_bytes(vm, values[1], b"saved");
    assert_eq!(values[2], Value::Integer(2));
    assert_bytes(vm, values[3], b"left");
    assert_bytes(vm, values[4], b"right");
}

#[test]
fn native_nested_closure_returns_packed_and_direct_multivalue() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        // 產品目前未提供 collectgarbage；host 每次配置觸發 GC。
        let make = MAKE.replace("    collectgarbage('collect')\n", "");
        let packed = format!(
            "{make}local callback = make(40)\nlocal packed = {{callback(2, 'left', 'right')}}\npacked.n = #packed\nreturn packed\n"
        );
        with_returned(packed.as_bytes(), profile, |vm, values| {
            assert_eq!(values.len(), 1);
            let Value::Object(table) = values[0] else {
                panic!("預期 packed table，實際：{:?}", values[0])
            };
            let _table_root = HostHandle::<Value>::new(vm, table).unwrap();
            let n = vm.allocate_byte_string(b"n").unwrap();
            assert_eq!(vm.raw_get(table, Value::Object(n)), Ok(Value::Integer(5)));
            let packed_values = (1..=5)
                .map(|index| vm.raw_get(table, Value::Integer(index)).unwrap())
                .collect::<Vec<_>>();
            assert_five_values(vm, &packed_values);
        });

        let direct = format!("{make}return make(40)(2, 'left', 'right')\n");
        with_returned(direct.as_bytes(), profile, assert_five_values);
    }
}

#[test]
fn native_nested_closure_direct_multivalue_without_collectgarbage() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let make = MAKE.replace("    collectgarbage('collect')\n", "");
        let direct = format!("{make}return make(40)(2, 'left', 'right')\n");
        with_returned(direct.as_bytes(), profile, assert_five_values);
    }
}

fn check_final_array_call(profile: LanguageProfile) {
    let source = b"local function values() return 7, 8, 9 end\nlocal packed = {values()}\nreturn #packed, packed[1], packed[2], packed[3]\n";
    with_returned(source, profile, |_, values| {
        assert_eq!(
            values,
            &[
                Value::Integer(3),
                Value::Integer(7),
                Value::Integer(8),
                Value::Integer(9),
            ]
        );
    });
}

#[test]
fn native_table_constructor_expands_final_call_lua54() {
    check_final_array_call(LanguageProfile::Lua54);
}

#[test]
fn native_table_constructor_expands_final_call_lua55() {
    check_final_array_call(LanguageProfile::Lua55);
}

#[test]
fn native_table_constructor_expands_final_vararg_and_preserves_nil() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source = b"local function pack(...) local t={...}; return t[1],t[2],t[3],t[4] end\nreturn pack(7,nil,9,nil)\n";
        with_returned(source, profile, |_, values| {
            assert_eq!(
                values,
                &[Value::Integer(7), Value::Nil, Value::Integer(9), Value::Nil]
            );
        });
    }
}

#[test]
fn native_table_constructor_keeps_nonfinal_and_parenthesized_calls_single() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source = b"local function many() return 7,8,9 end\nlocal a={4,many(),6}\nlocal b={(many())}\nlocal c={many()}\nreturn a[1],a[2],a[3],a[4],b[1],b[2],c[1],c[2],c[3]\n";
        with_returned(source, profile, |_, values| {
            assert_eq!(
                values,
                &[
                    Value::Integer(4),
                    Value::Integer(7),
                    Value::Integer(6),
                    Value::Nil,
                    Value::Integer(7),
                    Value::Nil,
                    Value::Integer(7),
                    Value::Integer(8),
                    Value::Integer(9),
                ]
            );
        });
    }
}

#[test]
fn native_table_constructor_preserves_zero_results_nil_holes_and_field_order() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source = b"local order={}\nlocal n=0\nlocal function mark(x) n=n+1; order[n]=x; return x end\nlocal function none() mark(4) end\nlocal t={mark(1), [mark(2)]=mark(3), none()}\nreturn n,order[1],order[2],order[3],order[4],t[1],t[2]\n";
        with_returned(source, profile, |_, values| {
            assert_eq!(
                values,
                &[
                    Value::Integer(4),
                    Value::Integer(1),
                    Value::Integer(2),
                    Value::Integer(3),
                    Value::Integer(4),
                    Value::Integer(1),
                    Value::Integer(3),
                ]
            );
        });
        let source = b"local function many() return 7,nil,9,nil end\nlocal t={3,many()}\nreturn t[1],t[2],t[3],t[4],t[5]\n";
        with_returned(source, profile, |_, values| {
            assert_eq!(
                values,
                &[
                    Value::Integer(3),
                    Value::Integer(7),
                    Value::Nil,
                    Value::Integer(9),
                    Value::Nil,
                ]
            );
        });
    }
}

#[test]
fn native_multiple_helpers_in_deep_closure_keep_guest_captures_and_varargs() {
    let source = b"local n=11\nlocal function outer(x)\n  local hold='ok'\n  return function(...)\n    local function values() return n+x,hold,9 end\n    local a={values()}\n    local b={...}\n    return a[1],a[2],a[3],b[1],b[2]\n  end\nend\nreturn outer(20)(7,8)\n";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        with_returned(source, profile, |vm, values| {
            assert_eq!(values.len(), 5);
            assert_eq!(values[0], Value::Integer(31));
            assert_bytes(vm, values[1], b"ok");
            assert_eq!(
                values[2..],
                [Value::Integer(9), Value::Integer(7), Value::Integer(8)]
            );
        });
    }
}

#[test]
fn native_plan_rejects_hidden_read_in_ancestor_without_helper_call() {
    let source = b"local function inner() local function values() return 7,8 end; local t={values()}; return t[1] end; return inner()";
    let compiled = compile(source, LanguageProfile::Lua55);
    let calls = compiled.official_execution().unwrap().calls().to_vec();
    assert!(
        calls
            .iter()
            .all(|call| call.prototype != compiled.module().prototypes[0].id)
    );
    let mut altered = compiled.module().clone();
    altered.prototypes[0].instructions[0].instruction = Instruction::GetUpvalue {
        dest: Register(0),
        upvalue: UpvalueId(0),
    };
    let plain = verify_module(altered, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let candidate = native_builtin_candidate_from_calls(&plain, calls).unwrap();
    assert!(verify_native_builtin_plan(plain, candidate, &VerifyLimits::default()).is_err());
}

#[test]
fn native_plan_rejects_later_out_of_bounds_call_pc_without_panic() {
    let source = b"local function values() return 7,8 end; return {values()}";
    let compiled = compile(source, LanguageProfile::Lua54);
    let mut calls = compiled.official_execution().unwrap().calls().to_vec();
    let mut forged = calls[0].clone();
    forged.call_pc = InstructionOffset(u32::MAX);
    calls.push(forged);
    let plain = verify_module(
        compiled.module().clone(),
        LuaProfile::Lua54,
        &VerifyLimits::default(),
    )
    .unwrap();
    let candidate = native_builtin_candidate_from_calls(&plain, calls).unwrap();
    assert!(verify_native_builtin_plan(plain, candidate, &VerifyLimits::default()).is_err());
}

#[test]
fn native_plan_rejects_cfg_entry_into_private_setup() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let compiled = compile(
            b"local function values() return 7,8 end; local t={values()}; return t[1]",
            language,
        );
        let calls = compiled.official_execution().unwrap().calls().to_vec();
        let call = &calls[0];
        let mut altered = compiled.module().clone();
        let proto = altered
            .prototypes
            .iter_mut()
            .find(|proto| proto.id == call.prototype)
            .unwrap();
        let load_pc = proto
            .instructions
            .iter()
            .enumerate()
            .find_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::GetUpvalue { dest, upvalue }
                if dest == call.function_register && upvalue == call.source_upvalue)
                .then_some(pc)
            })
            .unwrap();
        assert!(load_pc > 0);
        proto.instructions[load_pc - 1].instruction = Instruction::Jump {
            target: InstructionOffset((load_pc + 1) as u32),
        };
        let plain = verify_module(altered, runtime_profile, &VerifyLimits::default()).unwrap();
        let candidate = native_builtin_candidate_from_calls(&plain, calls).unwrap();
        assert!(verify_native_builtin_plan(plain, candidate, &VerifyLimits::default()).is_err());
    }
}

fn live_objects(vm: &Vm) -> usize {
    let trace = vm.gc_trace();
    trace.young + trace.survivor + trace.old
}

#[test]
fn native_raw_list_write_allocation_failures_cleanup_and_retry_both_profiles() {
    let source =
        b"local function values() return 7,8,9 end; local t={values()}; return t[1],t[2],t[3]";
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = compile(source, language);
        let mut baseline = Vm::new_with_profile(runtime_profile).unwrap();
        baseline.set_collect_every_allocation(true);
        let probe = baseline.ledger_probe();
        let mut execution = baseline.load(module.clone()).unwrap();
        let start = probe.trace().next_ordinal;
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(8),
                Value::Integer(9),
            ]))
        );
        let end = probe.trace().next_ordinal;
        drop(execution);
        assert!(end > start && end - start < 256);
        for ordinal in start..end {
            let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
            vm.set_collect_every_allocation(true);
            let probe = vm.ledger_probe();
            vm.inject_allocation_failure_at(ordinal);
            let mut execution = vm.load(module.clone()).unwrap();
            assert_eq!(probe.trace().next_ordinal, start);
            let result = execution.run();
            assert!(
                result.is_err(),
                "{runtime_profile:?} ordinal {ordinal}: {result:?}"
            );
            let failure = probe.trace().last_failure.unwrap();
            assert_eq!(failure.attempt.ordinal, ordinal);
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            vm.collect_major().unwrap();
            assert_eq!(live_objects(&vm), 0);
            assert_eq!(
                vm.load(module.clone()).unwrap().run(),
                Ok(RunOutcome::Returned(vec![
                    Value::Integer(7),
                    Value::Integer(8),
                    Value::Integer(9),
                ]))
            );
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn native_raw_list_write_fuel_abort_and_error_cleanup_retry() {
    for (language, runtime_profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let successful = compile(
            b"local function values() return 7,8 end; local t={values()}; return t[1],t[2]",
            language,
        );
        let mut vm = Vm::new_with_profile(runtime_profile).unwrap();
        vm.set_collect_every_allocation(true);
        let mut aborted = vm.load(successful.clone()).unwrap();
        aborted.set_fuel(1).unwrap();
        assert_eq!(
            aborted.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        drop(aborted);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(
            vm.load(successful.clone()).unwrap().run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(8),
            ]))
        );
        let (mut vm, globals) = vm_with_basic_globals(language);
        vm.set_collect_every_allocation(true);
        let failing = compile(
            b"local function values() return 7,8 end; local t={values()}; error('boom')",
            language,
        );
        let environment = globals.as_value(&vm).unwrap();
        let failed = vm
            .load_with_environment(failing, environment)
            .unwrap()
            .run();
        assert!(matches!(failed, Ok(RunOutcome::LuaError(_))), "{failed:?}");
        drop(failed);
        assert_eq!(vm.roots().total_count(), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(
            vm.load_with_environment(successful, environment)
                .unwrap()
                .run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(8),
            ]))
        );
    }
}
