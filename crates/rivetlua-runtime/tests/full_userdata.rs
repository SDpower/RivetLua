use rivetlua_core::{LuaProfile, ObjectRef, SlotId, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, FinalizerState, GcAge, GcColor, GcMode, GcPhase, GcTrace,
    LedgerSnapshot, MetamethodEvent, ObjectKind, RootId, RootKind, SlotState, Vm, VmError,
};

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type Snapshot = (LedgerSnapshot, GcTrace, Roots, Vec<Option<SlotState>>);

fn snapshot(vm: &Vm) -> Snapshot {
    let mut roots = Vec::new();
    vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
    let slots = (0..64)
        .map(|index| vm.slot_state(SlotId::new(index)))
        .collect();
    (vm.ledger_snapshot(), vm.gc_trace(), roots, slots)
}

#[test]
fn full_userdata_a27_matrix() {
    boundary_pointer_and_drop();
    uservalues_and_table_key();
    metatable_and_finalizer();
    gc_barriers();
    allocation_failures();
}

fn boundary_pointer_and_drop() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let probe = vm.ledger_probe();
        for (size, count) in [(0, 0), (1, 3), (15, 0), (16, 3), (17, 0), (4097, 3)] {
            let userdata = vm.allocate_userdata(size, count).unwrap();
            let root = vm.add_root(RootKind::Host, userdata).unwrap();
            assert_eq!(
                vm.object_kind(userdata),
                Ok(ObjectKind::Userdata),
                "{profile:?}"
            );
            assert_eq!(vm.userdata_len(userdata), Ok(size), "{profile:?}");
            let pointer = vm.userdata_ptr(userdata).unwrap();
            assert!(!pointer.is_null(), "{profile:?} size={size}");
            assert_eq!((pointer as usize) % 16, 0, "{profile:?} size={size}");
            for index in 1..=count {
                assert_eq!(vm.get_uservalue(userdata, index), Ok(Some(Value::Nil)));
            }
            assert_eq!(vm.get_uservalue(userdata, count + 1), Ok(None));
            for _ in 0..64 {
                vm.allocate_table().unwrap();
            }
            vm.collect().unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.userdata_ptr(userdata), Ok(pointer));
            assert_eq!(vm.userdata_len(userdata), Ok(size));
            vm.remove_root(root).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(userdata), Err(VmError::StaleObject));
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0, "{profile:?}");
        assert_eq!(probe.snapshot().reserved, 0, "{profile:?}");
    }
}

fn uservalues_and_table_key() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let userdata = vm.allocate_userdata(1, 3).unwrap();
        let root = vm.add_root(RootKind::Host, userdata).unwrap();
        let child = vm.allocate_table().unwrap();
        assert_eq!(
            vm.set_uservalue(userdata, 1, Value::Object(child)),
            Ok(true)
        );
        assert_eq!(
            vm.set_uservalue(userdata, 2, Value::Object(child)),
            Ok(true)
        );
        assert_eq!(vm.set_uservalue(userdata, 3, Value::Integer(42)), Ok(true));
        let before = snapshot(&vm);
        for index in [0, 4, usize::MAX] {
            assert_eq!(vm.get_uservalue(userdata, index), Ok(None));
            assert_eq!(vm.set_uservalue(userdata, index, Value::Nil), Ok(false));
            assert_eq!(snapshot(&vm), before, "{profile:?} index={index}");
        }
        let mut other = Vm::new_with_profile(profile).unwrap();
        let foreign = other.allocate_table().unwrap();
        assert_eq!(vm.get_uservalue(foreign, 1), Err(VmError::WrongVm));
        assert_eq!(
            vm.set_uservalue(foreign, 1, Value::Nil),
            Err(VmError::WrongVm)
        );
        assert_eq!(
            vm.set_uservalue(userdata, 1, Value::Object(foreign)),
            Err(VmError::WrongVm)
        );
        assert_eq!(snapshot(&vm), before);
        assert_eq!(
            vm.set_uservalue(userdata, 0, Value::Object(foreign)),
            Ok(false)
        );
        let wrong_kind = vm.allocate_table().unwrap();
        assert_eq!(
            vm.get_uservalue(wrong_kind, 1),
            Err(VmError::WrongObjectType)
        );
        assert_eq!(
            vm.set_uservalue(wrong_kind, 1, Value::Nil),
            Err(VmError::WrongObjectType)
        );
        let stale = vm.allocate_userdata(0, 1).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.get_uservalue(stale, 1), Err(VmError::StaleObject));
        assert_eq!(
            vm.set_uservalue(stale, 1, Value::Nil),
            Err(VmError::StaleObject)
        );
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        assert_eq!(vm.get_uservalue(userdata, 3), Ok(Some(Value::Integer(42))));
        assert_eq!(vm.set_uservalue(userdata, 1, Value::Nil), Ok(true));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        assert_eq!(vm.set_uservalue(userdata, 2, Value::Nil), Ok(true));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        assert_eq!(
            vm.set_uservalue(userdata, 1, Value::Object(userdata)),
            Ok(true)
        );
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(userdata), Err(VmError::StaleObject));

        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let key = vm.allocate_userdata(0, 0).unwrap();
        let other_key = vm.allocate_userdata(0, 0).unwrap();
        let value = vm.allocate_userdata(17, 0).unwrap();
        vm.raw_set(table, Value::Object(key), Value::Object(value))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(key)),
            Ok(Value::Object(value))
        );
        assert_eq!(vm.raw_get(table, Value::Object(other_key)), Ok(Value::Nil));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Ok(ObjectKind::Userdata));
        assert_eq!(vm.object_kind(value), Ok(ObjectKind::Userdata));
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        vm.remove_root(table_root).unwrap();
    }
}

fn metatable_and_finalizer() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let userdata = vm.allocate_userdata(1, 0).unwrap();
        let root = vm.add_root(RootKind::Host, userdata).unwrap();
        assert_eq!(vm.get_metatable(userdata), Ok(None));
        let first = vm.allocate_table().unwrap();
        vm.raw_set_byte_string_key(first, b"__index", Value::Integer(9))
            .unwrap();
        vm.set_metatable(userdata, Some(first)).unwrap();
        assert_eq!(vm.get_metatable(userdata), Ok(Some(first)));
        assert_eq!(
            vm.lookup_metamethod(userdata, MetamethodEvent::Index),
            Ok(Value::Integer(9))
        );
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
        let mut other = Vm::new_with_profile(profile).unwrap();
        let foreign = other.allocate_table().unwrap();
        let wrong_kind = vm.allocate_userdata(0, 0).unwrap();
        let before = snapshot(&vm);
        assert_eq!(
            vm.set_metatable(userdata, Some(foreign)),
            Err(VmError::WrongVm)
        );
        assert_eq!(
            vm.set_metatable(userdata, Some(wrong_kind)),
            Err(VmError::WrongObjectType)
        );
        assert_eq!(snapshot(&vm), before);
        assert_eq!(vm.get_metatable(userdata), Ok(Some(first)));
        let second = vm.allocate_table().unwrap();
        vm.set_metatable(userdata, Some(second)).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(second), Ok(ObjectKind::Table));
        vm.set_metatable(userdata, None).unwrap();
        assert_eq!(vm.get_metatable(userdata), Ok(None));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(second), Err(VmError::StaleObject));

        let gc_metatable = vm.allocate_table().unwrap();
        vm.raw_set_byte_string_key(gc_metatable, b"__gc", Value::Integer(1))
            .unwrap();
        assert_eq!(
            vm.finalizer_state(userdata),
            Ok(FinalizerState::Unregistered)
        );
        vm.set_metatable(userdata, Some(gc_metatable)).unwrap();
        assert_eq!(vm.get_metatable(userdata), Ok(Some(gc_metatable)));
        assert_eq!(vm.finalizer_state(userdata), Ok(FinalizerState::Registered));
        vm.remove_root(root).unwrap();

        let table = vm.allocate_table().unwrap();
        let table_meta = vm.allocate_table().unwrap();
        vm.set_metatable(table, Some(table_meta)).unwrap();
        assert_eq!(vm.get_metatable(table), Ok(Some(table_meta)));
        vm.set_metatable(table, None).unwrap();
        assert_eq!(vm.get_metatable(table), Ok(None));
    }
}

fn gc_barriers() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let owner = vm.allocate_userdata(0, 1).unwrap();
        let root = vm.add_root(RootKind::Host, owner).unwrap();
        for _ in 0..16 {
            vm.incremental_step(1).unwrap();
            if vm.gc_color(owner) == Ok(GcColor::Black) {
                break;
            }
        }
        assert_eq!(vm.gc_color(owner), Ok(GcColor::Black));
        let child = vm.allocate_table().unwrap();
        assert_eq!(vm.gc_color(child), Ok(GcColor::White));
        assert_eq!(vm.set_uservalue(owner, 1, Value::Object(child)), Ok(true));
        assert_eq!(vm.gc_color(child), Ok(GcColor::Gray));
        let meta = vm.allocate_table().unwrap();
        assert_eq!(vm.gc_color(meta), Ok(GcColor::White));
        vm.set_metatable(owner, Some(meta)).unwrap();
        assert_eq!(vm.gc_color(meta), Ok(GcColor::Gray));
        assert!(vm.gc_trace().barrier_count >= 2);
        for _ in 0..64 {
            if vm.incremental_step(1).unwrap().phase == GcPhase::Pause {
                break;
            }
        }
        assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        assert_eq!(vm.object_kind(meta), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(owner), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(meta), Err(VmError::StaleObject));

        for metatable_edge in [false, true] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
            let owner = vm.allocate_userdata(0, 1).unwrap();
            let root = vm.add_root(RootKind::Host, owner).unwrap();
            vm.collect_minor().unwrap();
            assert_eq!(vm.gc_age(owner), Ok(GcAge::Old));
            let child = vm.allocate_table().unwrap();
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(FailPoint::RememberedReserve);
            if metatable_edge {
                assert_eq!(
                    vm.set_metatable(owner, Some(child)),
                    Err(VmError::InjectedFailure(FailPoint::RememberedReserve))
                );
                assert_eq!(vm.get_metatable(owner), Ok(None));
            } else {
                assert_eq!(
                    vm.set_uservalue(owner, 1, Value::Object(child)),
                    Err(VmError::InjectedFailure(FailPoint::RememberedReserve))
                );
                assert_eq!(vm.get_uservalue(owner, 1), Ok(Some(Value::Nil)));
            }
            assert_eq!(vm.gc_trace().remembered_len, 0);
            assert_eq!(vm.ledger_snapshot(), before);
            if metatable_edge {
                vm.set_metatable(owner, Some(child)).unwrap();
            } else {
                vm.set_uservalue(owner, 1, Value::Object(child)).unwrap();
            }
            assert_eq!(vm.gc_trace().remembered_len, 1);
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
            vm.remove_root(root).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(owner), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        }
    }
}

fn allocation_failures() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut baseline = Vm::new_with_profile(profile).unwrap();
        baseline.set_gc_debt_threshold(usize::MAX);
        baseline.allocate_userdata(17, 3).unwrap();
        let total = baseline.allocation_trace().next_ordinal - 1;
        assert!(total >= 4, "{profile:?}: {total} allocation sites");
        for ordinal in 1..=total {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let before = snapshot(&vm);
            vm.inject_allocation_failure_at(ordinal);
            let error = vm.allocate_userdata(17, 3).unwrap_err();
            let VmError::InjectedAllocation(attempt) = error else {
                panic!("{profile:?} ordinal {ordinal}: {error:?}");
            };
            assert_eq!(attempt.ordinal, ordinal);
            assert_eq!(attempt.domain, AllocationDomain::LuaHeap);
            assert_eq!(snapshot(&vm), before, "{profile:?} ordinal={ordinal}");
            let object = vm.allocate_userdata(17, 3).unwrap();
            assert_eq!(vm.object_kind(object), Ok(ObjectKind::Userdata));
            assert_eq!(vm.get_uservalue(object, 3), Ok(Some(Value::Nil)));
            let live_bytes = vm.ledger_snapshot().committed;
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
            assert!(vm.ledger_snapshot().committed < live_bytes);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        for point in [
            FailPoint::UserdataBytesReserve,
            FailPoint::UserdataUservaluesReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let before = snapshot(&vm);
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate_userdata(17, 3),
                Err(VmError::InjectedFailure(point)),
                "{profile:?} point={point:?}"
            );
            assert_eq!(snapshot(&vm), before, "{profile:?} point={point:?}");
            assert!(vm.allocate_userdata(17, 3).is_ok());
        }
        for point in [FailPoint::MarkReserve, FailPoint::WorkReserve] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            let anchor = vm.allocate_table().unwrap();
            let _root = vm.add_root(RootKind::Host, anchor).unwrap();
            vm.incremental_step(1).unwrap();
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            let before = snapshot(&vm);
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate_userdata(17, 3),
                Err(VmError::InjectedFailure(point)),
                "{profile:?} active GC point={point:?}"
            );
            assert_eq!(
                snapshot(&vm),
                before,
                "{profile:?} active GC point={point:?}"
            );
            assert!(vm.allocate_userdata(17, 3).is_ok());
        }
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        let before = snapshot(&vm);
        assert_eq!(
            vm.allocate_userdata(usize::MAX, 0),
            Err(VmError::ArithmeticOverflow)
        );
        assert_eq!(snapshot(&vm), before);
        assert_eq!(
            vm.allocate_userdata(0, usize::MAX),
            Err(VmError::ArithmeticOverflow)
        );
        assert_eq!(snapshot(&vm), before);
        let probe = vm.ledger_probe();
        let object = vm.allocate_userdata(4097, 3).unwrap();
        assert_eq!(vm.object_kind(object), Ok(ObjectKind::Userdata));
        assert!(probe.snapshot().committed > before.0.committed);
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
