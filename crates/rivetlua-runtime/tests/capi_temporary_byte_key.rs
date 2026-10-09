use rivetlua_core::{LuaProfile, Value};
use rivetlua_runtime::{
    AllocationFailureKind, FailPoint, GcAge, GcColor, GcPhase, ObjectKind, RootKind, SlotState, Vm,
    VmError,
};

#[test]
fn capi_temporary_byte_key_cleanup_and_rooted_callback() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_collect_every_allocation(true);
        let mut key_slot = None;
        let (result, result_root) = vm
            .with_temporary_byte_string(b"a\0b", |vm, key| {
                key_slot = Some(key.identity().unwrap().slot);
                assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
                assert_eq!(
                    vm.with_byte_string(key, |string| string.as_bytes().to_vec()),
                    Ok(b"a\0b".to_vec())
                );
                let result = vm.allocate_table()?;
                let root = vm.add_root(RootKind::Host, result)?;
                vm.collect()?;
                vm.collect_major()?;
                assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
                assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
                Ok::<_, VmError>((result, root))
            })
            .unwrap();
        assert_eq!(vm.slot_state(key_slot.unwrap()), Some(SlotState::Free));
        assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        vm.remove_root(result_root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(result), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let baseline = vm.ledger_snapshot();
        let error = vm.with_temporary_byte_string(b"error", |vm, key| {
            assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
            Err::<(), VmError>(VmError::WrongObjectType)
        });
        assert_eq!(error, Err(VmError::WrongObjectType));
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);

        for point in [FailPoint::StringBytesReserve, FailPoint::RootReserve] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let baseline = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.with_temporary_byte_string(b"failure", |_, _| Ok::<_, VmError>(())),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), baseline);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut failed = Vec::new();
        let mut passed = Vec::new();
        for offset in 0..16 {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let baseline = vm.ledger_snapshot();
            let ordinal = vm.allocation_trace().next_ordinal + offset;
            vm.inject_allocation_failure_at(ordinal);
            let result = vm.with_temporary_byte_string(b"ordinal", |_, _| Ok::<_, VmError>(()));
            assert_eq!(vm.ledger_snapshot(), baseline);
            assert_eq!(vm.roots().total_count(), 0);
            if result.is_err() {
                let failure = vm.allocation_trace().last_failure.unwrap();
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt.ordinal, ordinal);
                failed.push((offset, failure.attempt.point, failure.attempt.site.file));
            } else {
                assert_eq!(result, Ok(()));
                passed.push(offset);
            }
        }
        assert_eq!(failed.len(), 4);
        assert_eq!(
            failed.iter().map(|entry| entry.1).collect::<Vec<_>>(),
            vec![
                Some(FailPoint::StringBytesReserve),
                Some(FailPoint::SlotReserve),
                Some(FailPoint::ObjectReserve),
                None,
            ]
        );
        assert_eq!(passed, (4..16).collect::<Vec<_>>());
        println!("A20_TEMP_KEY {profile:?} failed={failed:?} passed={passed:?}");
    }
}

#[test]
fn capi_published_byte_key_keeps_insert_and_cleans_replacement() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        vm.raw_set_byte_string_key(table, b"published", Value::Integer(1))
            .unwrap();
        vm.collect_major().unwrap();
        let probe = vm.allocate_byte_string(b"published").unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(probe)),
            Ok(Value::Integer(1))
        );
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        let objects = vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old;
        vm.raw_set_byte_string_key(table, b"published", Value::Integer(2))
            .unwrap();
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(
            vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old,
            objects
        );
        assert_eq!(
            vm.raw_get(table, Value::Object(probe)),
            Ok(Value::Integer(2))
        );
        vm.raw_set_byte_string_key(table, b"absent", Value::Nil)
            .unwrap();
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(
            vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old,
            objects
        );
        vm.raw_set_byte_string_key(table, b"published", Value::Nil)
            .unwrap();
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(
            vm.gc_trace().young + vm.gc_trace().survivor + vm.gc_trace().old,
            objects
        );
        assert_eq!(vm.raw_get(table, Value::Object(probe)), Ok(Value::Nil));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(probe), Err(VmError::StaleObject));
        vm.remove_root(root).unwrap();
    }
}

#[test]
fn capi_published_byte_key_safe_unrooted_inputs() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let value = vm.allocate_table().unwrap();
        vm.set_collect_every_allocation(true);
        vm.raw_set_byte_string_key(table, b"edge", Value::Object(value))
            .unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        vm.collect_major().unwrap();
        let probe = vm.allocate_byte_string(b"edge").unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(probe)),
            Ok(Value::Object(value))
        );
        assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
    }
}

#[test]
fn capi_published_byte_key_ordinal_and_named_failures() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let ordinal_cases: &[(&[u8], &[Option<FailPoint>], u64)] = &[
            (
                b"fault",
                &[
                    None,
                    None,
                    Some(FailPoint::StringBytesReserve),
                    Some(FailPoint::SlotReserve),
                    Some(FailPoint::ObjectReserve),
                    None,
                    Some(FailPoint::TableHashGrow),
                ],
                7,
            ),
            (
                b"fault-key",
                &[
                    None,
                    None,
                    Some(FailPoint::StringBytesReserve),
                    Some(FailPoint::SlotReserve),
                    Some(FailPoint::ObjectReserve),
                    None,
                    Some(FailPoint::StringBytesReserve),
                    Some(FailPoint::TableKeyReserve),
                    Some(FailPoint::TableHashGrow),
                ],
                9,
            ),
        ];
        for &(key, expected_points, first_passing) in ordinal_cases {
            let mut failed = Vec::new();
            let mut passed = Vec::new();
            for offset in 0..20 {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                vm.set_gc_debt_threshold(usize::MAX);
                let table = vm.allocate_table().unwrap();
                let value = vm.allocate_table().unwrap();
                let table_root = vm.add_root(RootKind::Host, table).unwrap();
                let value_root = vm.add_root(RootKind::Host, value).unwrap();
                let before = vm.ledger_snapshot();
                let roots = vm.roots().total_count();
                let gc = vm.gc_trace();
                let ordinal = vm.allocation_trace().next_ordinal + offset;
                vm.inject_allocation_failure_at(ordinal);
                let result = vm.raw_set_byte_string_key(table, key, Value::Object(value));
                if result.is_err() {
                    assert_eq!(vm.ledger_snapshot(), before, "{profile:?} {key:?} {offset}");
                    assert_eq!(
                        vm.roots().total_count(),
                        roots,
                        "{profile:?} {key:?} {offset}"
                    );
                    assert_eq!(vm.gc_trace(), gc, "{profile:?} {key:?} {offset}");
                    assert_eq!(vm.with_table(table, |stored| stored.is_empty()), Ok(true));
                    let failure = vm.allocation_trace().last_failure.unwrap();
                    assert_eq!(failure.kind, AllocationFailureKind::Injection);
                    assert_eq!(failure.attempt.ordinal, ordinal);
                    failed.push((offset, failure.attempt.point, failure.attempt.site.file));
                } else {
                    vm.inject_allocation_failure_at(u64::MAX);
                    assert_eq!(vm.roots().total_count(), roots);
                    assert_eq!(vm.with_table(table, |stored| stored.is_empty()), Ok(false));
                    vm.remove_root(value_root).unwrap();
                    vm.collect_major().unwrap();
                    let probe = vm.allocate_byte_string(key).unwrap();
                    assert_eq!(
                        vm.raw_get(table, Value::Object(probe)),
                        Ok(Value::Object(value))
                    );
                    passed.push(offset);
                }
                if result.is_err() {
                    vm.remove_root(value_root).unwrap();
                }
                vm.remove_root(table_root).unwrap();
                assert_eq!(vm.roots().total_count(), 0);
            }
            println!(
                "A23_PUBLISHED_KEY {profile:?} key={key:?} failed={failed:?} passed={passed:?}"
            );
            assert_eq!(failed.len() as u64, first_passing);
            assert_eq!(
                failed
                    .iter()
                    .map(|entry| entry.1)
                    .collect::<Vec<_>>()
                    .as_slice(),
                expected_points
            );
            assert_eq!(passed, (first_passing..20).collect::<Vec<_>>());
        }
        let named_cases: &[(&[u8], &[FailPoint])] = &[
            (
                b"point",
                &[
                    FailPoint::RootReserve,
                    FailPoint::StringBytesReserve,
                    FailPoint::SlotReserve,
                    FailPoint::ObjectReserve,
                    FailPoint::TableHashGrow,
                    FailPoint::TableRehash,
                    FailPoint::TableInsert,
                ],
            ),
            (
                b"point-key",
                &[
                    FailPoint::RootReserve,
                    FailPoint::StringBytesReserve,
                    FailPoint::SlotReserve,
                    FailPoint::ObjectReserve,
                    FailPoint::TableKeyReserve,
                    FailPoint::TableHashGrow,
                    FailPoint::TableRehash,
                    FailPoint::TableInsert,
                ],
            ),
        ];
        for &(key, points) in named_cases {
            for &point in points {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                vm.set_gc_debt_threshold(usize::MAX);
                let table = vm.allocate_table().unwrap();
                let root = vm.add_root(RootKind::Host, table).unwrap();
                let before = vm.ledger_snapshot();
                let roots = vm.roots().total_count();
                let gc = vm.gc_trace();
                vm.inject_failure_once(point);
                assert_eq!(
                    vm.raw_set_byte_string_key(table, key, Value::Integer(4)),
                    Err(VmError::InjectedFailure(point))
                );
                assert_eq!(
                    vm.ledger_snapshot(),
                    before,
                    "{profile:?} {key:?} {point:?}"
                );
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.gc_trace(), gc);
                assert_eq!(vm.with_table(table, |stored| stored.is_empty()), Ok(true));
                vm.raw_set_byte_string_key(table, key, Value::Integer(4))
                    .unwrap();
                vm.collect_major().unwrap();
                let probe = vm.allocate_byte_string(key).unwrap();
                assert_eq!(
                    vm.raw_get(table, Value::Object(probe)),
                    Ok(Value::Integer(4))
                );
                vm.remove_root(root).unwrap();
                assert_eq!(vm.roots().total_count(), 0);
            }
        }
    }
}

#[test]
fn capi_published_byte_key_active_gc_remembered_rollback() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        vm.set_gc_promotion_survivals(1).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(table) == Ok(GcColor::Black) {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
        let value = vm.allocate_table().unwrap();
        let value_root = vm.add_root(RootKind::Host, value).unwrap();
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        let gc = vm.gc_trace();
        vm.inject_failure_once(FailPoint::RememberedReserve);
        assert_eq!(
            vm.raw_set_byte_string_key(table, b"young", Value::Object(value)),
            Err(VmError::InjectedFailure(FailPoint::RememberedReserve))
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.gc_trace(), gc);
        assert_eq!(vm.with_table(table, |stored| stored.is_empty()), Ok(true));
        vm.raw_set_byte_string_key(table, b"young", Value::Object(value))
            .unwrap();
        assert_eq!(vm.gc_trace().remembered_len, 1);
        vm.remove_root(value_root).unwrap();
        while vm.gc_trace().phase != GcPhase::Pause {
            vm.incremental_step(1024).unwrap();
        }
        vm.collect_minor().unwrap();
        assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
    }
}
