use rivetlua_core::{LuaProfile, ObjectRef, Value};
use rivetlua_runtime::{
    AllocationFailureKind, FailPoint, GcAge, GcColor, GcMode, GcPhase, ObjectKind, RootKind, Vm,
    VmError,
};

fn named(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> Value {
    vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
        .unwrap()
}

#[test]
fn capi_named_subtable_identity_overwrite_and_cleanup() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let parent = vm.allocate_table().unwrap();
        let parent_root = vm.add_root(RootKind::Host, parent).unwrap();
        let (child, root, existed) = vm
            .get_or_create_byte_named_subtable(parent, b"child", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert!(!existed);
        assert_eq!(root.as_value(&vm), Ok(Value::Object(child)));
        assert_eq!(named(&mut vm, parent, b"child"), Value::Object(child));
        drop(root);
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));

        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        let objects = vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old;
        let (same, independent, existed) = vm
            .get_or_create_byte_named_subtable(parent, b"child", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert!(existed);
        assert_eq!(same, child);
        assert_eq!(independent.as_value(&vm), Ok(Value::Object(child)));
        assert_eq!(vm.roots().total_count(), roots + 1);
        drop(independent);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(
            vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old,
            objects
        );

        let old = vm.allocate_byte_string(b"old").unwrap();
        vm.raw_set_byte_string_key(parent, b"other", Value::Object(old))
            .unwrap();
        let objects_before = vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old;
        let (replacement, replacement_root, existed) = vm
            .get_or_create_byte_named_subtable(parent, b"other", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert!(!existed);
        assert_eq!(
            vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old,
            objects_before + 1,
            "覆寫僅保留新 subtable，不保留本次暫時 key"
        );
        assert_eq!(named(&mut vm, parent, b"other"), Value::Object(replacement));
        drop(replacement_root);
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(old), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(replacement), Ok(ObjectKind::Table));

        for initial in [Value::Nil, Value::Integer(7), Value::Boolean(false)] {
            vm.raw_set_byte_string_key(parent, b"scalar", initial)
                .unwrap();
            let (subtable, root, existed) = vm
                .get_or_create_byte_named_subtable(parent, b"scalar", |_| Ok::<(), VmError>(()))
                .unwrap();
            assert!(!existed);
            assert_eq!(named(&mut vm, parent, b"scalar"), Value::Object(subtable));
            drop(root);
        }
        vm.remove_root(parent_root).unwrap();
    }
}

#[test]
fn capi_named_subtable_unrooted_and_preflight_failure() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let parent = vm.allocate_table().unwrap();
        vm.set_collect_every_allocation(true);
        let (child, child_root, existed) = vm
            .get_or_create_byte_named_subtable(parent, b"unrooted", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert!(!existed);
        assert_eq!(child_root.as_value(&vm), Ok(Value::Object(child)));
        let parent_root = vm.add_root(RootKind::Host, parent).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(named(&mut vm, parent, b"unrooted"), Value::Object(child));
        drop(child_root);
        vm.remove_root(parent_root).unwrap();

        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let parent = vm.allocate_table().unwrap();
        let parent_root = vm.add_root(RootKind::Host, parent).unwrap();
        vm.raw_set_byte_string_key(parent, b"occupied", Value::Integer(99))
            .unwrap();
        let existing = vm.allocate_table().unwrap();
        vm.raw_set_byte_string_key(parent, b"existing", Value::Object(existing))
            .unwrap();
        let old_string = vm.allocate_byte_string(b"kept on failure").unwrap();
        vm.raw_set_byte_string_key(parent, b"old_object", Value::Object(old_string))
            .unwrap();
        for (name, expected) in [
            (b"missing".as_slice(), Value::Nil),
            (b"occupied".as_slice(), Value::Integer(99)),
            (b"existing".as_slice(), Value::Object(existing)),
            (b"old_object".as_slice(), Value::Object(old_string)),
        ] {
            let before = vm.ledger_snapshot();
            let roots = vm.roots().total_count();
            let gc = vm.gc_trace();
            assert!(matches!(
                vm.get_or_create_byte_named_subtable(parent, name, |_| {
                    Err::<(), VmError>(VmError::WrongObjectType)
                }),
                Err(VmError::WrongObjectType)
            ));
            assert_eq!(named(&mut vm, parent, name), expected);
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.gc_trace(), gc);
        }
        assert_eq!(vm.object_kind(old_string), Ok(ObjectKind::ByteString));
        vm.remove_root(parent_root).unwrap();
    }
}

#[test]
fn capi_named_subtable_ordinal_and_named_failures() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut failed = Vec::new();
        let mut passed = Vec::new();
        for offset in 0..28 {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let parent = vm.allocate_table().unwrap();
            let parent_root = vm.add_root(RootKind::Host, parent).unwrap();
            let before = vm.ledger_snapshot();
            let roots = vm.roots().total_count();
            let gc = vm.gc_trace();
            let ordinal = vm.allocation_trace().next_ordinal + offset;
            vm.inject_allocation_failure_at(ordinal);
            let result =
                vm.get_or_create_byte_named_subtable(parent, b"fault", |_| Ok::<(), VmError>(()));
            if result.is_err() {
                assert_eq!(vm.ledger_snapshot(), before, "{profile:?} {offset}");
                assert_eq!(vm.roots().total_count(), roots, "{profile:?} {offset}");
                assert_eq!(vm.gc_trace(), gc, "{profile:?} {offset}");
                assert_eq!(vm.with_table(parent, |stored| stored.is_empty()), Ok(true));
                let failure = vm.allocation_trace().last_failure.unwrap();
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt.ordinal, ordinal);
                failed.push((offset, failure.attempt.point, failure.attempt.site.file));
            } else {
                let (child, root, existed) = result.unwrap();
                assert!(!existed);
                vm.inject_allocation_failure_at(u64::MAX);
                assert_eq!(named(&mut vm, parent, b"fault"), Value::Object(child));
                drop(root);
                vm.collect_major().unwrap();
                assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
                passed.push(offset);
            }
            vm.remove_root(parent_root).unwrap();
        }
        println!("A24_SUBTABLE {profile:?} failed={failed:?} passed={passed:?}");
        // B14 短鍵內嵌後，兩次 canonical key 都不再複製 5-byte payload。
        assert_eq!(failed.len(), 17);
        assert_eq!(
            failed.iter().map(|entry| entry.1).collect::<Vec<_>>(),
            vec![
                None,
                Some(FailPoint::StringBytesReserve),
                Some(FailPoint::SlotReserve),
                Some(FailPoint::ObjectReserve),
                None,
                Some(FailPoint::TableArrayReserve),
                Some(FailPoint::TableHashReserve),
                Some(FailPoint::SlotReserve),
                Some(FailPoint::ObjectReserve),
                None,
                None,
                None,
                Some(FailPoint::StringBytesReserve),
                Some(FailPoint::SlotReserve),
                Some(FailPoint::ObjectReserve),
                None,
                Some(FailPoint::TableHashGrow),
            ]
        );
        assert_eq!(
            failed.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            (0..failed.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(passed, (failed.len() as u64..28).collect::<Vec<_>>());

        for point in [
            FailPoint::RootReserve,
            FailPoint::StringBytesReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::TableHashGrow,
            FailPoint::TableRehash,
            FailPoint::TableInsert,
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let parent = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, parent).unwrap();
            let before = vm.ledger_snapshot();
            let roots = vm.roots().total_count();
            vm.inject_failure_once(point);
            assert!(matches!(
                vm.get_or_create_byte_named_subtable(
                    parent, b"point", |_| Ok::<(), VmError>(())
                ),
                Err(VmError::InjectedFailure(actual)) if actual == point
            ));
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.with_table(parent, |stored| stored.is_empty()), Ok(true));
            vm.remove_root(root).unwrap();
        }
    }
}

#[test]
fn capi_named_subtable_gc_barrier_and_weak_modes() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        vm.set_gc_promotion_survivals(1).unwrap();
        vm.set_gc_mode(GcMode::Generational).unwrap();
        let parent = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, parent).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.gc_age(parent), Ok(GcAge::Old));
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(parent) == Ok(GcColor::Black) {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(vm.gc_color(parent), Ok(GcColor::Black));
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        let gc = vm.gc_trace();
        vm.inject_failure_once(FailPoint::RememberedReserve);
        assert!(matches!(
            vm.get_or_create_byte_named_subtable(parent, b"young", |_| Ok::<(), VmError>(())),
            Err(VmError::InjectedFailure(FailPoint::RememberedReserve))
        ));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.gc_trace(), gc);
        assert_eq!(vm.with_table(parent, |stored| stored.is_empty()), Ok(true));
        let (child, child_root, existed) = vm
            .get_or_create_byte_named_subtable(parent, b"young", |_| Ok::<(), VmError>(()))
            .unwrap();
        assert!(!existed);
        assert_eq!(vm.gc_trace().remembered_len, 1);
        drop(child_root);
        while vm.gc_trace().phase != GcPhase::Pause {
            vm.incremental_step(1024).unwrap();
        }
        vm.collect_minor().unwrap();
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();

        for mode in [b"k".as_slice(), b"v", b"kv"] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let parent = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, parent).unwrap();
            let mt = vm.allocate_table().unwrap();
            let mode_string = vm.allocate_byte_string(mode).unwrap();
            vm.raw_set_byte_string_key(mt, b"__mode", Value::Object(mode_string))
                .unwrap();
            vm.set_metatable(parent, Some(mt)).unwrap();
            let (child, child_root, _) = vm
                .get_or_create_byte_named_subtable(parent, b"weak", |_| Ok::<(), VmError>(()))
                .unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
            drop(child_root);
            vm.collect_major().unwrap();
            if mode == b"k" {
                assert_eq!(named(&mut vm, parent, b"weak"), Value::Object(child));
                assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
            } else {
                assert_eq!(named(&mut vm, parent, b"weak"), Value::Nil);
                assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
            }
            vm.remove_root(root).unwrap();
        }
    }
}
