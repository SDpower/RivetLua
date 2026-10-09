use rivetlua_core::{LuaProfile, Value};
use rivetlua_runtime::{
    FailPoint, GcPhase, HostHandle, ObjectKind, RootKind, RuntimeErrorKind, Vm, VmError,
};

#[test]
fn capi_numeric_adapter_reuses_runtime_parser_and_profile_formatter() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let before = vm.ledger_snapshot();
        for (text, expected) in [
            (b"  -12  ".as_slice(), Some(Value::Integer(-12))),
            (b"0x1.8p+2", Some(Value::Float(6.0))),
            (b"nan", None),
            (b"inf", None),
            (b"12\0suffix", None),
        ] {
            assert_eq!(vm.parse_lua_number_bytes(text), expected);
        }
        assert_eq!(vm.ledger_snapshot(), before);

        let object = vm.allocate_byte_string(b" 0xff ").unwrap();
        assert_eq!(
            vm.coerce_lua_number(Value::Object(object)),
            Ok(Some(Value::Integer(255)))
        );
        assert_eq!(vm.coerce_lua_number(Value::Boolean(true)), Ok(None));
        assert_eq!(vm.lua_integer_from_value(Value::Float(6.0)), Some(6));
        assert_eq!(vm.lua_integer_from_value(Value::Float(6.5)), None);
        let (bytes, len) = vm.format_lua_number(Value::Float(-0.0)).unwrap();
        assert_eq!(&bytes[..len], b"-0.0");
        assert_eq!(
            vm.format_lua_number(Value::Nil).unwrap_err().kind,
            RuntimeErrorKind::BasicArgument
        );
    }
}

#[test]
fn capi_unpublished_byte_string_root_and_publication_failure_refund() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for point in [FailPoint::RootReserve, FailPoint::HostLease] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let baseline = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            let result = vm.with_unpublished_byte_string(b"pending", |vm, object| {
                HostHandle::<Value>::new(vm, object)
            });
            assert!(matches!(result, Err(VmError::InjectedFailure(failed)) if failed == point));
            assert_eq!(vm.ledger_snapshot(), baseline);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut vm = Vm::new_with_profile(profile).unwrap();
        let baseline = vm.ledger_snapshot();
        let result: Result<(), VmError> = vm.with_unpublished_byte_string(b"pending", |vm, obj| {
            let _root = HostHandle::<Value>::new(vm, obj)?;
            Err(VmError::AllocationFailed)
        });
        assert_eq!(result, Err(VmError::AllocationFailed));
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);

        let root = vm
            .with_unpublished_byte_string(b"committed", |vm, object| {
                HostHandle::<Value>::new(vm, object)
            })
            .unwrap();
        let Value::Object(object) = root.as_value(&vm).unwrap() else {
            panic!("host string root 應持有物件");
        };
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(object), Ok(ObjectKind::ByteString));
        drop(root);
        assert_eq!(vm.roots().count(RootKind::Host), 0);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn capi_unpublished_byte_string_active_gc_root_failure_refunds() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let anchor = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, anchor).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        let baseline = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::RootReserve);
        let result = vm.with_unpublished_byte_string(b"active", |vm, object| {
            HostHandle::<Value>::new(vm, object)
        });
        assert!(matches!(
            result,
            Err(VmError::InjectedFailure(FailPoint::RootReserve))
        ));
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        let failed_publication: Result<(), VmError> =
            vm.with_unpublished_byte_string(b"active again", |vm, object| {
                let _root = HostHandle::<Value>::new(vm, object)?;
                Err(VmError::AllocationFailed)
            });
        assert_eq!(failed_publication, Err(VmError::AllocationFailed));
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        vm.remove_root(root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
