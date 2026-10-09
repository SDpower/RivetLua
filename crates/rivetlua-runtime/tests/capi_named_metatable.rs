use rivetlua_core::{LuaProfile, ObjectRef, Value};
use rivetlua_runtime::{
    FailPoint, GcAge, GcColor, GcMode, GcPhase, ObjectKind, RootKind, Vm, VmError,
};

fn field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> Value {
    vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
        .unwrap()
}

fn created(
    vm: &mut Vm,
    registry: ObjectRef,
    name: &[u8],
) -> (ObjectRef, rivetlua_runtime::HostHandle<Value>) {
    let (Value::Object(table), Some(root), true) = vm
        .new_named_metatable(registry, name, |_| Ok::<(), VmError>(()))
        .unwrap()
    else {
        panic!("應建立具名 metatable")
    };
    (table, root)
}

#[test]
fn capi_named_metatable_existing_new_name_and_lifetime() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let registry = vm.allocate_table().unwrap();
        let registry_root = vm.add_root(RootKind::Host, registry).unwrap();
        for name in [b"named".as_slice(), b"", b"__name"] {
            let (table, root) = created(&mut vm, registry, name);
            assert_eq!(root.as_value(&vm), Ok(Value::Object(table)));
            assert_eq!(field(&mut vm, registry, name), Value::Object(table));
            let Value::Object(name_value) = field(&mut vm, table, b"__name") else {
                panic!("__name 須是 byte string")
            };
            assert_eq!(
                vm.with_byte_string(name_value, |string| string.as_bytes().to_vec()),
                Ok(name.to_vec())
            );
            let roots_before = vm.roots().total_count();
            let (existing, independent, did_create) = vm
                .new_named_metatable(registry, name, |_| Ok::<(), VmError>(()))
                .unwrap();
            assert!(!did_create);
            assert_eq!(existing, Value::Object(table));
            assert_eq!(independent.as_ref().unwrap().as_value(&vm), Ok(existing));
            assert_eq!(vm.roots().total_count(), roots_before + 1);
            drop(independent);
            assert_eq!(vm.roots().total_count(), roots_before);
            drop(root);
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(name_value), Ok(ObjectKind::ByteString));
            vm.raw_set_byte_string_key(registry, name, Value::Nil)
                .unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(name_value), Err(VmError::StaleObject));
        }
        for value in [Value::Integer(42), Value::Boolean(false)] {
            vm.raw_set_byte_string_key(registry, b"occupied", value)
                .unwrap();
            let before = vm.roots().total_count();
            let (same, root, did_create) = vm
                .new_named_metatable(registry, b"occupied", |_| Ok::<(), VmError>(()))
                .unwrap();
            assert_eq!(same, value);
            assert!(root.is_none());
            assert!(!did_create);
            assert_eq!(vm.roots().total_count(), before);
            assert_eq!(field(&mut vm, registry, b"occupied"), value);
        }
        let existing = vm.allocate_byte_string(b"existing object").unwrap();
        vm.raw_set_byte_string_key(registry, b"occupied", Value::Object(existing))
            .unwrap();
        let before = vm.roots().total_count();
        let (same, root, did_create) = vm
            .new_named_metatable(registry, b"occupied", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert_eq!(same, Value::Object(existing));
        assert!(!did_create);
        assert_eq!(root.as_ref().unwrap().as_value(&vm), Ok(same));
        assert_eq!(vm.roots().total_count(), before + 1);
        drop(root);
        assert_eq!(vm.roots().total_count(), before);
        assert_eq!(field(&mut vm, registry, b"occupied"), same);
        vm.remove_root(registry_root).unwrap();
    }
}

#[test]
fn capi_named_metatable_unrooted_registry_and_preflight_failure() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let registry = vm.allocate_table().unwrap();
        vm.set_collect_every_allocation(true);
        let (table, root) = created(&mut vm, registry, b"unrooted");
        assert_eq!(root.as_value(&vm), Ok(Value::Object(table)));
        assert_ne!(field(&mut vm, table, b"__name"), Value::Nil);
        drop(root);

        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let registry = vm.allocate_table().unwrap();
        let registry_root = vm.add_root(RootKind::Host, registry).unwrap();
        let existing = vm.allocate_byte_string(b"preserved").unwrap();
        vm.raw_set_byte_string_key(registry, b"present", Value::Object(existing))
            .unwrap();
        for (name, expected) in [
            (b"absent".as_slice(), Value::Nil),
            (b"present".as_slice(), Value::Object(existing)),
        ] {
            let before = (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().total_count(),
            );
            assert!(matches!(
                vm.new_named_metatable(registry, name, |_| Err::<(), VmError>(
                    VmError::WrongObjectType
                )),
                Err(VmError::WrongObjectType)
            ));
            assert_eq!(field(&mut vm, registry, name), expected);
            assert_eq!(
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count()
                ),
                before
            );
        }
        assert_eq!(vm.object_kind(existing), Ok(ObjectKind::ByteString));
        vm.remove_root(registry_root).unwrap();
    }
}

#[test]
fn capi_named_metatable_ordinal_and_named_failure_rollback() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut failed = Vec::new();
        let mut passed = Vec::new();
        for offset in 0..48 {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let registry = vm.allocate_table().unwrap();
            let _root = vm.add_root(RootKind::Host, registry).unwrap();
            let before = (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().total_count(),
            );
            let next = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(next + offset);
            let result = vm.new_named_metatable(registry, b"ordinal", |_| Ok::<(), VmError>(()));
            vm.inject_allocation_failure_at(u64::MAX);
            match result {
                Err(_) => {
                    assert_eq!(field(&mut vm, registry, b"ordinal"), Value::Nil);
                    assert_eq!(
                        (
                            vm.ledger_snapshot(),
                            vm.gc_trace(),
                            vm.roots().total_count()
                        ),
                        before,
                        "profile={profile:?} offset={offset}"
                    );
                    assert_eq!(
                        vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
                        next + offset
                    );
                    failed.push(offset);
                }
                Ok((Value::Object(table), Some(root), true)) => {
                    assert_eq!(field(&mut vm, registry, b"ordinal"), Value::Object(table));
                    assert_ne!(field(&mut vm, table, b"__name"), Value::Nil);
                    drop(root);
                    passed.push(offset);
                }
                _ => panic!("非預期交易結果"),
            }
        }
        println!("A25_RUNTIME_ORDINAL {profile:?} failed={failed:?} passed={passed:?}");
        assert!(!failed.is_empty() && !passed.is_empty());
        assert_eq!(failed, (0..failed.len() as u64).collect::<Vec<_>>());

        for point in [
            FailPoint::ObjectReserve,
            FailPoint::StringBytesReserve,
            FailPoint::TableHashReserve,
            FailPoint::TableInsert,
            FailPoint::RootReserve,
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let registry = vm.allocate_table().unwrap();
            let _root = vm.add_root(RootKind::Host, registry).unwrap();
            let before = (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().total_count(),
            );
            vm.inject_failure_once(point);
            assert!(
                vm.new_named_metatable(registry, b"named", |_| Ok::<(), VmError>(()))
                    .is_err(),
                "{point:?}"
            );
            assert_eq!(field(&mut vm, registry, b"named"), Value::Nil);
            assert_eq!(
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count()
                ),
                before,
                "{point:?}"
            );
            let (table, root) = created(&mut vm, registry, b"named");
            assert_eq!(field(&mut vm, registry, b"named"), Value::Object(table));
            drop(root);
        }
    }
}

#[test]
fn capi_named_metatable_active_gc_and_registry_barrier() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let registry = vm.allocate_table().unwrap();
        let _root = vm.add_root(RootKind::Host, registry).unwrap();
        vm.set_gc_mode(GcMode::Incremental).unwrap();
        vm.collect_major().unwrap();
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(registry) == Ok(GcColor::Black)
            {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        let (table, root) = created(&mut vm, registry, b"incremental");
        drop(root);
        while vm.gc_trace().phase != GcPhase::Pause {
            vm.incremental_step(1024).unwrap();
        }
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        assert_ne!(field(&mut vm, table, b"__name"), Value::Nil);

        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let registry = vm.allocate_table().unwrap();
        let _root = vm.add_root(RootKind::Host, registry).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        vm.set_gc_mode(GcMode::Generational).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.gc_age(registry), Ok(GcAge::Old));
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(registry) == Ok(GcColor::Black)
            {
                break;
            }
        }
        assert_eq!(vm.gc_color(registry), Ok(GcColor::Black));
        let before = (
            vm.ledger_snapshot(),
            vm.gc_trace(),
            vm.roots().total_count(),
        );
        vm.inject_failure_once(FailPoint::RememberedReserve);
        assert!(
            vm.new_named_metatable(registry, b"young", |_| Ok::<(), VmError>(()))
                .is_err()
        );
        assert_eq!(field(&mut vm, registry, b"young"), Value::Nil);
        assert_eq!(
            (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().total_count()
            ),
            before
        );
        let (table, root) = created(&mut vm, registry, b"young");
        assert_eq!(vm.gc_trace().remembered_len, 1);
        drop(root);
        while vm.gc_trace().phase != GcPhase::Pause {
            vm.incremental_step(1024).unwrap();
        }
        vm.collect_minor().unwrap();
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        assert_ne!(field(&mut vm, table, b"__name"), Value::Nil);
    }
}
