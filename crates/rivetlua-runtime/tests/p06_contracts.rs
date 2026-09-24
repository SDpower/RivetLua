use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    FailPoint, Generation, HostHandle, ObjectId, RootKind, SlotId, SlotState, Vm, VmError,
};

fn record_case(case_id: &str, input: &str, actual: &str) {
    let Ok(profile) = std::env::var("RIVETLUA_P06_PROFILE") else {
        return;
    };
    assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
    println!("P06_CASE\t{case_id}\t{profile}\t{input}\t{actual}");
}

#[test]
fn public_heap_keeps_address_through_growth() {
    let mut vm = Vm::new().unwrap();
    let first = vm.allocate(Value::Integer(17)).unwrap();
    let first_id = first.identity().unwrap();
    let before = vm
        .with_value(first, |value| value as *const Value as usize)
        .unwrap();
    for n in 0..256 {
        vm.allocate(Value::Integer(n)).unwrap();
    }
    let after = vm
        .with_value(first, |value| value as *const Value as usize)
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(vm.read(first), Ok(Value::Integer(17)));
    assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Occupied));
    let wrong_generation =
        ObjectRef::from_id(ObjectId::new(vm.id(), first_id.slot, Generation::new(1)));
    assert_eq!(vm.read(wrong_generation), Err(VmError::StaleObject));
}

#[test]
fn public_lookup_rejects_foreign_legacy_and_forged_identity() {
    let mut a = Vm::new().unwrap();
    let b = Vm::new().unwrap();
    let object = a.allocate(Value::Integer(42)).unwrap();
    let id = object.identity().unwrap();
    assert_ne!(a.id(), b.id());
    assert_eq!(b.read(object), Err(VmError::WrongVm));
    assert_eq!(VmError::WrongVm.code(), "E_WRONG_VM");
    assert_eq!(VmError::StaleObject.code(), "E_STALE_HANDLE");
    assert_eq!(a.read(ObjectRef::from_id(id)), Err(VmError::StaleObject));
    assert_eq!(
        a.read(ObjectRef::new_runtime(id).unwrap()),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        a.read(ObjectRef::new_opaque().unwrap()),
        Err(VmError::StaleObject)
    );
    let forged_slot = ObjectRef::from_id(ObjectId::new(
        a.id(),
        SlotId::new(usize::MAX),
        id.generation,
    ));
    assert_eq!(a.read(forged_slot), Err(VmError::StaleObject));
    let forged_generation =
        ObjectRef::from_id(ObjectId::new(a.id(), id.slot, Generation::new(u64::MAX)));
    assert_eq!(a.read(forged_generation), Err(VmError::StaleObject));
    let raw_address = a
        .with_value(object, |value| value as *const Value as usize)
        .unwrap();
    let forged_address = ObjectRef::from_id(ObjectId::new(
        a.id(),
        SlotId::new(raw_address),
        id.generation,
    ));
    assert_eq!(a.read(forged_address), Err(VmError::StaleObject));
    assert_eq!(a.read(object), Ok(Value::Integer(42)));
}

#[test]
fn public_temporary_root_protects_pending_value_during_forced_collection() {
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let pending = vm.allocate(Value::Integer(10)).unwrap();
    assert_eq!(vm.roots().count(RootKind::Temporary), 0);
    let root = vm.add_root(RootKind::Temporary, pending).unwrap();
    let trigger = vm.allocate(Value::Integer(20)).unwrap();
    assert_eq!(vm.read(pending), Ok(Value::Integer(10)));
    assert_eq!(vm.read(trigger), Ok(Value::Integer(20)));
    assert_eq!(vm.roots().count(RootKind::Temporary), 1);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.collect().unwrap(), 2);
    assert_eq!(vm.read(pending), Err(VmError::StaleObject));
    assert_eq!(vm.read(trigger), Err(VmError::StaleObject));
}

#[test]
fn public_unrooted_pending_value_is_reclaimed_by_next_forced_collection() {
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let pending = vm.allocate(Value::Integer(10)).unwrap();
    let next = vm.allocate(Value::Integer(20)).unwrap();
    assert_eq!(vm.read(pending), Err(VmError::StaleObject));
    assert_eq!(vm.read(next), Ok(Value::Integer(20)));
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn public_all_six_root_kinds_release_and_sweep_real_objects() {
    let mut vm = Vm::new().unwrap();
    let mut roots = Vec::new();
    let mut objects = Vec::new();
    for kind in RootKind::ALL {
        let object = vm.allocate(Value::Integer(objects.len() as i64)).unwrap();
        roots.push(vm.add_root(kind, object).unwrap());
        objects.push(object);
    }
    assert_eq!(vm.roots().total_count(), 6);
    assert_eq!(vm.collect().unwrap(), 0);
    for root in roots {
        vm.remove_root(root).unwrap();
    }
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.collect().unwrap(), 6);
    for object in objects {
        assert_eq!(vm.read(object), Err(VmError::StaleObject));
        assert_eq!(
            vm.slot_state(object.identity().unwrap().slot),
            Some(SlotState::Free)
        );
    }
    record_case(
        "HEAP-006",
        "登錄再移除 stack、registry、global、temporary、coroutine、host 六類 root",
        "移除前存活; 移除後 collect 實際回收 6; 六個 slot 均為 Free",
    );
}

#[test]
fn public_root_and_edge_validation_does_not_change_live_graph() {
    let mut a = Vm::new().unwrap();
    let mut b = Vm::new().unwrap();
    let parent = a.allocate(Value::Integer(1)).unwrap();
    let foreign = b.allocate(Value::Integer(2)).unwrap();
    assert_eq!(a.add_root(RootKind::Host, foreign), Err(VmError::WrongVm));
    assert_eq!(a.add_child(parent, foreign), Err(VmError::WrongVm));
    assert_eq!(a.allocate(Value::Object(foreign)), Err(VmError::WrongVm));
    assert_eq!(a.roots().total_count(), 0);
    assert_eq!(a.collect().unwrap(), 1);
    assert_eq!(a.read(parent), Err(VmError::StaleObject));
    assert_eq!(b.read(foreign), Ok(Value::Integer(2)));
}

#[test]
fn public_host_root_keeps_object_across_forced_collections() {
    let mut vm = Vm::new().unwrap();
    let held = vm.allocate(Value::Integer(99)).unwrap();
    let host = vm.add_root(RootKind::Host, held).unwrap();
    vm.set_collect_every_allocation(true);
    for n in 0..16 {
        vm.allocate(Value::Integer(n)).unwrap();
        assert_eq!(vm.read(held), Ok(Value::Integer(99)));
    }
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    assert_eq!(vm.roots().count(RootKind::Temporary), 0);
    vm.remove_root(host).unwrap();
    assert_eq!(vm.collect().unwrap(), 2);
    assert_eq!(vm.read(held), Err(VmError::StaleObject));
}

#[test]
fn public_new_parent_temporarily_roots_its_unrooted_child() {
    let mut vm = Vm::new().unwrap();
    let child = vm.allocate(Value::Integer(4)).unwrap();
    vm.set_collect_every_allocation(true);
    let parent = vm.allocate(Value::Object(child)).unwrap();
    assert_eq!(vm.read(child), Ok(Value::Integer(4)));
    assert_eq!(vm.read(parent), Ok(Value::Object(child)));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.collect().unwrap(), 2);
}

#[test]
fn public_root_ids_reject_cross_vm_and_repeat_removal() {
    let mut a = Vm::new().unwrap();
    let mut b = Vm::new().unwrap();
    let object = a.allocate(Value::Nil).unwrap();
    let root = a.add_root(RootKind::Host, object).unwrap();
    assert_eq!(b.remove_root(root), Err(VmError::WrongVm));
    assert_eq!(a.roots().total_count(), 1);
    assert_eq!(a.remove_root(root), Ok(object));
    assert_eq!(a.remove_root(root), Err(VmError::StaleRoot));
    assert_eq!(a.roots().total_count(), 0);
}

#[test]
fn heap_001_host_handle_rejects_wrong_vm_without_mutation() {
    let mut a = Vm::new().unwrap();
    let mut b = Vm::new().unwrap();
    let object = a.allocate(Value::Integer(6)).unwrap();
    let handle = HostHandle::<Value>::new(&mut a, object).unwrap();
    let b_object = b.allocate(Value::Integer(7)).unwrap();
    assert_eq!(handle.read(&b), Err(VmError::WrongVm));
    assert_eq!(VmError::WrongVm.code(), "E_WRONG_VM");
    assert_eq!(handle.try_clone(&mut b).err(), Some(VmError::WrongVm));
    assert_eq!(a.roots().count(RootKind::Host), 1);
    assert_eq!(b.roots().count(RootKind::Host), 0);
    assert_eq!(
        a.slot_state(object.identity().unwrap().slot),
        Some(SlotState::Occupied)
    );
    assert_eq!(
        b.slot_state(b_object.identity().unwrap().slot),
        Some(SlotState::Occupied)
    );
    assert_eq!(handle.read(&a), Ok(Value::Integer(6)));
    record_case(
        "HEAP-001",
        "VM-A handle 在 VM-B read 與 clone",
        "E_WRONG_VM; VM-A host roots=1; VM-B host roots=0; 兩個物件仍 occupied",
    );
}

#[test]
fn heap_002_revoked_handle_stays_stale_after_slot_reuse() {
    let mut vm = Vm::new().unwrap();
    let first = vm.allocate(Value::Integer(10)).unwrap();
    let handle = HostHandle::<Value>::new(&mut vm, first).unwrap();
    assert_eq!(vm.remove_root(handle.root_id()), Ok(first));
    assert_eq!(vm.remove_root(handle.root_id()), Err(VmError::StaleRoot));
    assert_eq!(vm.collect().unwrap(), 1);
    let second = vm.allocate(Value::Integer(20)).unwrap();
    assert_eq!(
        second.identity().unwrap().slot,
        first.identity().unwrap().slot
    );
    assert_ne!(
        second.identity().unwrap().generation,
        first.identity().unwrap().generation
    );
    assert_eq!(handle.read(&vm), Err(VmError::StaleObject));
    assert_eq!(handle.try_clone(&mut vm).err(), Some(VmError::StaleObject));
    assert_eq!(VmError::StaleObject.code(), "E_STALE_HANDLE");
    assert_eq!(vm.read(first), Err(VmError::StaleObject));
    assert_eq!(vm.read(second), Ok(Value::Integer(20)));
    drop(handle);
    assert_eq!(vm.roots().count(RootKind::Host), 0);
    record_case(
        "HEAP-002",
        "撤銷 handle root、回收 slot，再以新 generation 配置",
        "舊 handle=E_STALE_HANDLE; slot 相同且 generation 遞增; 新值=20",
    );
}

#[test]
fn heap_003_host_handle_survives_forced_collection() {
    let mut vm = Vm::new().unwrap();
    let object = vm.allocate(Value::Integer(88)).unwrap();
    let handle = HostHandle::<Value>::new(&mut vm, object).unwrap();
    vm.set_collect_every_allocation(true);
    for n in 0..32 {
        vm.allocate(Value::Integer(n)).unwrap();
        assert_eq!(handle.read(&vm), Ok(Value::Integer(88)));
    }
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    drop(handle);
    assert_eq!(vm.roots().count(RootKind::Host), 0);
    assert_eq!(vm.collect().unwrap(), 2);
    record_case(
        "HEAP-003",
        "HostHandle 持有物件並跨越 32 次強制收集配置",
        "32 次後原 handle 讀得 88; Drop 後 collect 回收 2 個物件",
    );
}

#[test]
fn dropped_host_handle_refunds_quota_before_root_compaction() {
    let mut vm = Vm::new().unwrap();
    let object = vm.allocate(Value::Integer(5)).unwrap();
    let handle = HostHandle::<Value>::new(&mut vm, object).unwrap();
    let root = handle.root_id();
    let before = vm.ledger_snapshot();
    vm.set_allocation_limit(before.committed);

    drop(handle);
    let after = vm.ledger_snapshot();
    assert!(after.committed < before.committed);
    assert_eq!(after.reserved, 0);
    assert_eq!(vm.roots().count(RootKind::Host), 0);
    assert_eq!(vm.remove_root(root), Err(VmError::StaleRoot));
    assert_eq!(vm.ledger_snapshot(), after);
    let new_root = vm.add_root(RootKind::Stack, object).unwrap();
    vm.remove_root(new_root).unwrap();
    assert_eq!(vm.collect().unwrap(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn heap_005_quota_failure_exposes_no_object_root_or_debt() {
    let mut vm = Vm::new().unwrap();
    vm.set_allocation_limit(0);
    let before = vm.ledger_snapshot();
    assert_eq!(
        vm.allocate(Value::Integer(1)),
        Err(VmError::AllocationFailed)
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.slot_state(SlotId::new(0)), None);
    assert_eq!(vm.roots().total_count(), 0);

    vm.set_allocation_limit(usize::MAX);
    let object = vm.allocate(Value::Integer(2)).unwrap();
    let used = vm.ledger_snapshot().committed;
    assert!(used > 0);
    vm.set_allocation_limit(used);
    let before = vm.ledger_snapshot();
    assert_eq!(
        vm.allocate(Value::Integer(3)),
        Err(VmError::AllocationFailed)
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.read(object), Ok(Value::Integer(2)));
    assert_eq!(vm.roots().total_count(), 0);

    vm.set_allocation_limit(used);
    let before = vm.ledger_snapshot();
    assert_eq!(
        HostHandle::<Value>::new(&mut vm, object).err(),
        Some(VmError::AllocationFailed)
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), 0);
    record_case(
        "HEAP-005",
        "配額為 0、等於既有 committed，及不足以建立 HostHandle",
        "三次 AllocationFailed; heap/root/ledger 無半提交或差額; 舊值仍為 2",
    );
}

#[test]
fn root_child_work_and_host_clone_failures_roll_back() {
    let mut vm = Vm::new().unwrap();
    let parent = vm.allocate(Value::Integer(1)).unwrap();
    let child = vm.allocate(Value::Integer(2)).unwrap();
    for point in [FailPoint::RootReserve, FailPoint::HostLease] {
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(point);
        let result = if point == FailPoint::RootReserve {
            vm.add_root(RootKind::Stack, parent).map(|_| ())
        } else {
            HostHandle::<Value>::new(&mut vm, parent).map(|_| ())
        };
        assert_eq!(result, Err(VmError::InjectedFailure(point)));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
    }
    let host = HostHandle::<Value>::new(&mut vm, parent).unwrap();
    let before = vm.ledger_snapshot();
    vm.inject_failure_once(FailPoint::HostLease);
    assert_eq!(
        host.try_clone(&mut vm).err(),
        Some(VmError::InjectedFailure(FailPoint::HostLease))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    vm.inject_failure_once(FailPoint::ChildReserve);
    assert_eq!(
        vm.add_child(parent, child),
        Err(VmError::InjectedFailure(FailPoint::ChildReserve))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    for point in [FailPoint::MarkReserve, FailPoint::WorkReserve] {
        vm.inject_failure_once(point);
        assert_eq!(vm.collect(), Err(VmError::InjectedFailure(point)));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(host.read(&vm), Ok(Value::Integer(1)));
        assert_eq!(vm.read(child), Ok(Value::Integer(2)));
    }
    drop(host);
    assert_eq!(vm.collect().unwrap(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn failed_forced_collection_preserves_existing_handle_and_ledger() {
    let mut vm = Vm::new().unwrap();
    let object = vm.allocate(Value::Integer(7)).unwrap();
    let handle = HostHandle::<Value>::new(&mut vm, object).unwrap();
    vm.set_collect_every_allocation(true);
    let before = vm.ledger_snapshot();
    vm.inject_failure_once(FailPoint::WorkReserve);
    assert_eq!(
        vm.allocate(Value::Integer(8)),
        Err(VmError::InjectedFailure(FailPoint::WorkReserve))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.slot_state(SlotId::new(1)), None);
    assert_eq!(vm.roots().count(RootKind::Temporary), 0);
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    assert_eq!(handle.read(&vm), Ok(Value::Integer(7)));
}

#[test]
fn quota_also_covers_root_children_and_gc_workspace() {
    let mut vm = Vm::new().unwrap();
    let parent = vm.allocate(Value::Integer(1)).unwrap();
    let child = vm.allocate(Value::Integer(2)).unwrap();
    let committed = vm.ledger_snapshot().committed;
    vm.set_allocation_limit(committed);
    let before = vm.ledger_snapshot();
    assert_eq!(
        vm.add_root(RootKind::Stack, parent),
        Err(VmError::AllocationFailed)
    );
    assert_eq!(vm.add_child(parent, child), Err(VmError::AllocationFailed));
    assert_eq!(vm.collect(), Err(VmError::AllocationFailed));
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.read(parent), Ok(Value::Integer(1)));
    assert_eq!(vm.read(child), Ok(Value::Integer(2)));
    vm.set_allocation_limit(usize::MAX);
    assert_eq!(vm.collect().unwrap(), 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn heap_004_forced_collection_preserves_all_root_classes_and_new_edges() {
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut roots = Vec::new();
    let mut objects = Vec::new();
    for kind in RootKind::ALL {
        let object = vm.allocate(Value::Integer(objects.len() as i64)).unwrap();
        roots.push(vm.add_root(kind, object).unwrap());
        objects.push(object);
    }
    let host = HostHandle::<Value>::new(&mut vm, objects[0]).unwrap();
    let parent = vm.allocate(Value::Object(objects[1])).unwrap();
    let parent_root = vm.add_root(RootKind::Stack, parent).unwrap();
    vm.add_child(parent, objects[2]).unwrap();
    for n in 0..12 {
        vm.allocate(Value::Integer(n)).unwrap();
        assert_eq!(host.read(&vm), Ok(Value::Integer(0)));
        assert_eq!(vm.read(parent), Ok(Value::Object(objects[1])));
        for (index, &object) in objects.iter().enumerate() {
            assert_eq!(vm.read(object), Ok(Value::Integer(index as i64)));
        }
        assert_eq!(vm.roots().count(RootKind::Temporary), 1);
    }
    vm.remove_root(parent_root).unwrap();
    for root in roots {
        vm.remove_root(root).unwrap();
    }
    drop(host);
    assert_eq!(vm.collect().unwrap(), 8);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    record_case(
        "HEAP-004",
        "每次配置後強制收集，六類 root、新物件邊與 12 次配置",
        "全部 root 與父子邊存活; 暫存 root=1; 移除 root 後實際回收 8",
    );
}

#[test]
fn heap_008_child_growth_failures_keep_original_graph_and_ledger() {
    let mut a = Vm::new().unwrap();
    let mut b = Vm::new().unwrap();
    let parent = a.allocate(Value::Integer(1)).unwrap();
    let old_child = a.allocate(Value::Integer(2)).unwrap();
    let candidate = a.allocate(Value::Integer(3)).unwrap();
    let foreign = b.allocate(Value::Integer(4)).unwrap();
    let root = a.add_root(RootKind::Stack, parent).unwrap();
    a.add_child(parent, old_child).unwrap();
    let before = a.ledger_snapshot();

    a.inject_failure_once(FailPoint::ChildReserve);
    assert_eq!(
        a.add_child(parent, candidate),
        Err(VmError::InjectedFailure(FailPoint::ChildReserve))
    );
    assert_eq!(a.ledger_snapshot(), before);
    assert_eq!(a.add_child(parent, foreign), Err(VmError::WrongVm));
    assert_eq!(a.ledger_snapshot(), before);
    assert_eq!(a.collect().unwrap(), 1);
    assert_eq!(a.read(candidate), Err(VmError::StaleObject));
    assert_eq!(a.read(old_child), Ok(Value::Integer(2)));
    assert_eq!(a.read(parent), Ok(Value::Integer(1)));
    assert_eq!(b.read(foreign), Ok(Value::Integer(4)));

    let fresh = a.allocate(Value::Integer(5)).unwrap();
    let committed = a.ledger_snapshot().committed;
    a.set_allocation_limit(committed);
    let before = a.ledger_snapshot();
    assert_eq!(a.add_child(parent, fresh), Err(VmError::AllocationFailed));
    assert_eq!(a.ledger_snapshot(), before);
    a.set_allocation_limit(usize::MAX);
    assert_eq!(a.collect().unwrap(), 1);
    assert_eq!(a.read(fresh), Err(VmError::StaleObject));
    assert_eq!(a.read(old_child), Ok(Value::Integer(2)));
    a.remove_root(root).unwrap();
    assert_eq!(a.collect().unwrap(), 2);
    record_case(
        "HEAP-008",
        "ChildReserve 或 quota 失敗時嘗試跨配置邊界修改物件圖",
        "注入錯誤與 AllocationFailed 均未新增邊或改 ledger; 舊子物件存活; 新子物件回收",
    );
}
