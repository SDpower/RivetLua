#![forbid(unsafe_code)]

use rivetlua_capi::stack::{StackError, StateOwner};
use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{
    ConstId, Instruction, LuaProfile, Register, Value, VerifyLimits, decode_module, encode_module,
    verify_module,
};
#[cfg(feature = "lua55")]
use rivetlua_runtime::ExternalStringStorage;
use rivetlua_runtime::{
    CoroutineState, FailPoint, HostHandle, ObjectKind, RootKind, RunOutcome, Vm, VmError,
};
#[cfg(feature = "lua55")]
use rivetlua_runtime::{GcControl, GcControlResult};
#[cfg(feature = "lua55")]
use std::cell::Cell;
#[cfg(feature = "lua55")]
use std::rc::Rc;

fn active_profile() -> LuaProfile {
    #[cfg(feature = "lua54")]
    {
        LuaProfile::Lua54
    }
    #[cfg(not(feature = "lua54"))]
    {
        LuaProfile::Lua55
    }
}

fn language_profile(profile: LuaProfile) -> LanguageProfile {
    match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    }
}

fn compile(source: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let language = language_profile(profile);
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-internal",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

#[test]
fn p17_internal_allocation_ledger() {
    let owner = StateOwner::new().unwrap();
    let object = owner.with_vm(|vm| vm.allocate_table()).unwrap().unwrap();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();

    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert!(matches!(
        owner.push_value(Value::Object(object)),
        Err(StackError::Runtime(VmError::InjectedFailure(
            FailPoint::RootReserve
        )))
    ));
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);

    owner.push_value(Value::Object(object)).unwrap();
    assert!(probe.snapshot().committed > before.committed);
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn p17_internal_gc_roots() {
    let mut vm = Vm::new_with_profile(active_profile()).unwrap();
    let object = vm.allocate_table().unwrap();
    let root = HostHandle::<Value>::new(&mut vm, object).unwrap();

    assert_eq!(vm.roots().count(RootKind::Host), 1);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
    assert_eq!(root.as_value(&vm), Ok(Value::Object(object)));

    drop(root);
    assert_eq!(vm.roots().count(RootKind::Host), 0);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p17_internal_table_string() {
    let mut vm = Vm::new_with_profile(active_profile()).unwrap();
    let table = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"\0\xffp17-long-key").unwrap();
    let equal_key = vm.allocate_byte_string(b"\0\xffp17-long-key").unwrap();
    let value = vm.allocate_byte_string(b"value\0\xfe").unwrap();

    vm.raw_set(table, Value::Object(key), Value::Object(value))
        .unwrap();
    assert_eq!(
        vm.raw_get(table, Value::Object(equal_key)),
        Ok(Value::Object(value))
    );
    assert_eq!(
        vm.with_byte_string(value, |bytes| bytes.as_bytes().to_vec()),
        Ok(b"value\0\xfe".to_vec())
    );

    assert!(vm.raw_set(table, Value::Nil, Value::Integer(1)).is_err());
    assert_eq!(
        vm.raw_set(table, Value::Float(f64::NAN), Value::Integer(2)),
        Err(VmError::NaNTableKey)
    );
    assert_eq!(
        vm.raw_get(table, Value::Object(equal_key)),
        Ok(Value::Object(value))
    );

    vm.raw_set(table, Value::Integer(17), Value::Integer(23))
        .unwrap();
    assert_eq!(
        vm.raw_get(table, Value::Float(17.0)),
        Ok(Value::Integer(23))
    );
}

#[test]
fn p17_internal_verified_code() {
    let profile = active_profile();
    let module = compile(b"return 20 + 22", profile);
    let encoded =
        encode_module(module.module().clone(), profile, &VerifyLimits::default()).unwrap();
    let bytes = encoded.bytes().to_vec();
    let decoded = decode_module(&bytes, profile, &VerifyLimits::default()).unwrap();

    let mut vm = Vm::new_with_profile(profile).unwrap();
    assert_eq!(
        vm.load(decoded).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(42)])
    );

    let other_profile = match profile {
        LuaProfile::Lua54 => LuaProfile::Lua55,
        LuaProfile::Lua55 => LuaProfile::Lua54,
    };
    assert!(decode_module(&bytes, other_profile, &VerifyLimits::default()).is_err());
    let mut corrupt = bytes;
    corrupt[0] ^= 0xff;
    assert!(decode_module(&corrupt, profile, &VerifyLimits::default()).is_err());

    let branch_source = b"local choice = 3\nlocal label = 'selected'\nif choice == 3 then\n  return choice, label, 41 + 1\nelse\n  return 0\nend";
    let branch_module = compile(branch_source, profile);
    let branch_encoded = encode_module(
        branch_module.module().clone(),
        profile,
        &VerifyLimits::default(),
    )
    .unwrap();
    let branch_decoded =
        decode_module(branch_encoded.bytes(), profile, &VerifyLimits::default()).unwrap();
    let RunOutcome::Returned(values) = vm.load(branch_decoded).unwrap().run().unwrap() else {
        panic!("branch module 必須正常返回");
    };
    let [Value::Integer(3), Value::Object(label), Value::Integer(42)] = values.as_slice() else {
        panic!("branch / 多常數結果不符: {values:?}");
    };
    assert_eq!(
        vm.with_byte_string(*label, |string| string.as_bytes().to_vec()),
        Ok(b"selected".to_vec())
    );

    let debug_source = b"local function named()\n  local value = 4\n  if value > 0 then\n    return value\n  end\n  return 0\nend\nreturn named";
    let debug_module = compile(debug_source, profile);
    let RunOutcome::Returned(values) = vm.load(debug_module).unwrap().run().unwrap() else {
        panic!("debug module 必須返回 closure");
    };
    let info = vm.debug_function_info(values[0]).unwrap();
    assert!(info.source.ends_with(b"p17-internal"));
    assert!(info.linedefined >= 1);
    assert!(info.lastlinedefined > info.linedefined);
    assert!(!info.active_lines.is_empty());

    let candidate = branch_module.module().clone();
    let bounded = VerifyLimits {
        max_instructions: 0,
        ..VerifyLimits::default()
    };
    assert!(verify_module(candidate.clone(), profile, &bounded).is_err());
    let mut invalid_operand = candidate;
    invalid_operand.prototypes[0].instructions[0].instruction = Instruction::LoadConst {
        dest: Register(u16::MAX),
        constant: ConstId(u32::MAX),
    };
    assert!(verify_module(invalid_operand, profile, &VerifyLimits::default()).is_err());
}

#[test]
fn p17_internal_c_stack_errors() {
    let owner = StateOwner::new().unwrap();
    let stack_roots_before = owner
        .with_vm(|vm| vm.roots().count(RootKind::Stack))
        .unwrap();
    let nested = owner.with_vm(|_| owner.push_value(Value::Integer(8)));
    assert_eq!(nested, Ok(Err(StackError::Busy)));
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Stack))
            .unwrap(),
        stack_roots_before
    );

    let mut stack_objects = Vec::new();
    for _ in 0..64 {
        let object = owner.with_vm(|vm| vm.allocate_table()).unwrap().unwrap();
        owner.push_value(Value::Object(object)).unwrap();
        stack_objects.push(object);
    }
    let live_host_roots = owner
        .with_vm(|vm| vm.roots().count(RootKind::Host))
        .unwrap();
    let pending = owner.with_vm(|vm| vm.allocate_table()).unwrap().unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert!(matches!(
        owner.push_value(Value::Object(pending)),
        Err(StackError::Runtime(VmError::InjectedFailure(
            FailPoint::RootReserve
        )))
    ));
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        live_host_roots
    );
    owner.push_value(Value::Object(pending)).unwrap();
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            for &object in &stack_objects {
                assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
            }
            assert_eq!(vm.object_kind(pending), Ok(ObjectKind::Table));
        })
        .unwrap();

    owner
        .with_vm(|vm| {
            let env = vm.allocate_table().unwrap();
            let _env_root = HostHandle::<Value>::new(vm, env).unwrap();
            vm.install_basic_builtins(env).unwrap();
            let baseline_roots = vm.roots().total_count();

            let normal = {
                let mut execution = vm
                    .load_with_environment(
                        compile(
                            b"local function inner(v) return v + 1 end; local function outer(v) return inner(v) * 2 end; return outer(20)",
                            active_profile(),
                        ),
                        Value::Object(env),
                    )
                    .unwrap();
                let outcome = execution.run().unwrap();
                drop(execution);
                outcome
            };
            assert_eq!(normal, RunOutcome::Returned(vec![Value::Integer(42)]));
            assert_eq!(vm.roots().total_count(), baseline_roots);

            let failure = {
                let mut execution = vm
                    .load_with_environment(
                        compile(
                            b"local function inner() error('p17 nested error') end; local function outer() return inner() end; return outer()",
                            active_profile(),
                        ),
                        Value::Object(env),
                    )
                    .unwrap();
                let outcome = execution.run().unwrap();
                drop(execution);
                outcome
            };
            let RunOutcome::LuaError(error) = &failure else {
                panic!("巢狀錯誤必須回傳 LuaError");
            };
            let Value::Object(error_object) = error.value else {
                panic!("錯誤字串必須由 LuaError 持根");
            };
            assert_eq!(vm.roots().total_count(), baseline_roots + 1);
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(error_object), Ok(ObjectKind::ByteString));
            let error_bytes = vm
                .with_byte_string(error_object, |string| string.as_bytes().to_vec())
                .unwrap();
            assert!(error_bytes
                .windows(b"p17 nested error".len())
                .any(|bytes| bytes == b"p17 nested error"));
            drop(failure);
            assert_eq!(vm.roots().total_count(), baseline_roots);

            let reusable = vm
                .load_with_environment(
                    compile(b"return 99", active_profile()),
                    Value::Object(env),
                )
                .unwrap()
                .run()
                .unwrap();
            assert_eq!(reusable, RunOutcome::Returned(vec![Value::Integer(99)]));
            assert_eq!(vm.roots().total_count(), baseline_roots);
        })
        .unwrap();

    let foreign_owner = StateOwner::new().unwrap();
    let foreign_object = foreign_owner
        .with_vm(|vm| vm.allocate_table())
        .unwrap()
        .unwrap();
    let roots_before_foreign = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
    assert_eq!(
        owner.push_value(Value::Object(foreign_object)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    assert_eq!(
        owner.with_vm(|vm| vm.roots().total_count()).unwrap(),
        roots_before_foreign
    );
    owner.push_value(Value::Integer(9)).unwrap();
}

#[test]
fn p17_internal_userdata_registry() {
    let mut vm = Vm::new_with_profile(active_profile()).unwrap();
    let registry = vm.allocate_table().unwrap();
    let _registry_root = HostHandle::<Value>::new(&mut vm, registry).unwrap();
    let userdata = vm.allocate_userdata(0, 1).unwrap();
    let _userdata_root = HostHandle::<Value>::new(&mut vm, userdata).unwrap();
    assert_eq!(vm.userdata_len(userdata), Ok(0));
    assert_eq!(vm.get_uservalue(userdata, 0), Ok(None));
    assert_eq!(vm.get_uservalue(userdata, 1), Ok(Some(Value::Nil)));
    assert_eq!(vm.get_uservalue(userdata, 2), Ok(None));
    assert_eq!(vm.set_uservalue(userdata, 0, Value::Integer(1)), Ok(false));
    assert_eq!(vm.set_uservalue(userdata, 2, Value::Integer(2)), Ok(false));

    let child = vm.allocate_table().unwrap();
    assert_eq!(
        vm.set_uservalue(userdata, 1, Value::Object(child)),
        Ok(true)
    );
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
    assert_eq!(
        vm.get_uservalue(userdata, 1),
        Ok(Some(Value::Object(child)))
    );
    assert_eq!(vm.set_uservalue(userdata, 1, Value::Nil), Ok(true));
    assert_eq!(vm.get_uservalue(userdata, 1), Ok(Some(Value::Nil)));
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));

    let (first, first_root, created) = vm
        .new_named_metatable::<VmError>(registry, b"p17.internal.meta", |_| Ok(()))
        .unwrap();
    assert!(created);
    let Value::Object(metatable) = first else {
        panic!("new named metatable 必須回傳 table");
    };
    let (second, second_root, created_again) = vm
        .new_named_metatable::<VmError>(registry, b"p17.internal.meta", |_| Ok(()))
        .unwrap();
    assert!(!created_again);
    assert_eq!(second, Value::Object(metatable));
    assert!(
        vm.new_named_metatable::<VmError>(userdata, b"invalid", |_| Ok(()))
            .is_err()
    );

    let name = vm.allocate_byte_string(b"p17.internal.meta").unwrap();
    assert_eq!(vm.raw_get(registry, Value::Object(name)), Ok(first));
    let name_field = vm.allocate_byte_string(b"__name").unwrap();
    let name_value = vm.raw_get(metatable, Value::Object(name_field)).unwrap();
    let Value::Object(name_object) = name_value else {
        panic!("named metatable 必須發布 __name byte string");
    };
    assert_eq!(
        vm.with_byte_string(name_object, |value| value.as_bytes().to_vec()),
        Ok(b"p17.internal.meta".to_vec())
    );
    drop((first_root, second_root));
}

#[test]
fn p17_internal_state_coroutine() {
    let profile = active_profile();
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let function = {
        let mut execution = vm
            .load(compile(b"return function() return 42 end", profile))
            .unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("module 須回傳 Lua closure");
        };
        values[0]
    };
    assert_eq!(
        vm.new_coroutine(Value::Integer(1)).err(),
        Some(VmError::WrongObjectType)
    );
    let coroutine = vm.new_coroutine(function).unwrap();
    let coroutine_value = coroutine.as_value(&vm).unwrap();
    let Value::Object(coroutine_object) = coroutine_value else {
        panic!("coroutine 必須是 heap object");
    };
    assert_eq!(
        vm.coroutine_state(coroutine_object),
        Ok(CoroutineState::Suspended)
    );
    assert_eq!(
        vm.resume(coroutine_value, &[]).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(42)])
    );
    assert_eq!(
        vm.coroutine_state(coroutine_object),
        Ok(CoroutineState::Dead)
    );
    drop(coroutine);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(coroutine_object), Err(VmError::StaleObject));
}

#[test]
fn p17_internal_upvalue_debug() {
    let profile = active_profile();
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let closure = {
        let mut execution = vm
            .load(compile(
                b"local captured = 10; return function() captured = captured + 1; return captured end",
                profile,
            ))
            .unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("module 須回傳 closure");
        };
        values[0]
    };
    let Value::Object(closure_object) = closure else {
        panic!("capturing function 必須是 closure object");
    };
    let _closure_root = HostHandle::<Value>::new(&mut vm, closure_object).unwrap();

    let before_debug = vm.ledger_snapshot();
    let info = vm.debug_function_info(closure).unwrap();
    assert_eq!(info.nups, 1);
    assert!(!info.source.is_empty());
    drop(info);
    assert_eq!(vm.ledger_snapshot().reserved, before_debug.reserved);

    vm.collect().unwrap();
    for expected in [11, 12, 13] {
        assert_eq!(
            vm.call(closure, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(expected)])
        );
        if expected == 12 {
            vm.collect().unwrap();
        }
    }
}

#[test]
fn p17_internal_numeric_bytes() {
    let vm = Vm::new_with_profile(active_profile()).unwrap();
    let before = vm.ledger_snapshot();
    for (bytes, expected) in [
        (b"  -12  ".as_slice(), Some(Value::Integer(-12))),
        (b"0x1.8p+2".as_slice(), Some(Value::Float(6.0))),
        (b"nan".as_slice(), None),
        (b"inf".as_slice(), None),
        (b"12\0suffix".as_slice(), None),
        (b"\xff".as_slice(), None),
    ] {
        assert_eq!(vm.parse_lua_number_bytes(bytes), expected);
    }
    let (negative_zero, length) = vm.format_lua_number(Value::Float(-0.0)).unwrap();
    assert_eq!(&negative_zero[..length], b"-0.0");
    assert!(vm.format_lua_number(Value::Nil).is_err());
    assert_eq!(vm.ledger_snapshot(), before);
}

#[cfg(feature = "lua55")]
#[test]
fn p17_internal_external_strings() {
    struct ExternalBytes {
        bytes: Vec<u8>,
        drops: Rc<Cell<usize>>,
    }

    impl ExternalStringStorage for ExternalBytes {
        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for ExternalBytes {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    let drops = Rc::new(Cell::new(0));
    let external = Rc::new(ExternalBytes {
        bytes: b"external\0bytes".to_vec(),
        drops: Rc::clone(&drops),
    });
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let object = vm.allocate_external_byte_string(external.clone()).unwrap();
    let root = HostHandle::<Value>::new(&mut vm, object).unwrap();
    drop(external);

    vm.collect().unwrap();
    assert_eq!(drops.get(), 0);
    assert_eq!(
        vm.with_byte_string(object, |bytes| bytes.as_bytes().to_vec()),
        Ok(b"external\0bytes".to_vec())
    );
    drop(root);
    vm.collect().unwrap();
    assert_eq!(drops.get(), 1);
    assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
}

#[cfg(feature = "lua55")]
#[test]
fn p17_internal_gc_parameters() {
    const PERCENTAGES: [i32; 8] = [5, 10, 12, 20, 50, 100, 200, 500];
    const VALUES: [usize; 8] = [1, 2, 10, 100, 257, 1023, 6500, 100_000];

    for value in VALUES {
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let payload = vec![b'x'; value];
        let object = vm.allocate_byte_string(&payload).unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, object).unwrap();
        vm.collect_major().unwrap();
        let base = vm.ledger_snapshot().lua_heap_bytes;

        for percentage in PERCENTAGES {
            vm.gc_control(GcControl::Parameter {
                index: 2,
                value: percentage,
            })
            .unwrap();
            let GcControlResult::Integer(applied) = vm
                .gc_control(GcControl::Parameter {
                    index: 2,
                    value: -1,
                })
                .unwrap();
            let expected = base.saturating_mul(percentage as usize) / 100;
            let observed = vm.gc_trace().major_threshold_bytes;
            let difference = observed.abs_diff(expected);
            assert!(
                difference <= expected / 10 + 1,
                "heap={base}, requested={percentage}%, expected threshold={expected}, observed={observed}"
            );
            assert_eq!(
                observed,
                base.saturating_mul(applied as usize) / 100,
                "公開讀回比例須解釋實際 major threshold"
            );
        }
        assert_eq!(
            vm.gc_control(GcControl::Parameter {
                index: 6,
                value: 100,
            }),
            Err(VmError::InvalidGcConfig)
        );
    }
}
