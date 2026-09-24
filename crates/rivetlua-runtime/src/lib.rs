//! RivetLua 的 VM 與 heap。

#![forbid(unsafe_code)]

mod alloc;
mod handle;
mod heap;
mod roots;
mod vm;

pub use alloc::{AllocationLedger, FailPoint, LedgerSnapshot};
pub use handle::HostHandle;
pub use heap::{SlotState, Vm, VmError};
pub use rivetlua_core::{Generation, ObjectId, SlotId, VmId};
pub use roots::{RootId, RootKind, RootSet};
pub use vm::{AbortReason, Execution, RunOutcome, RuntimeError, RuntimeErrorKind};

#[cfg(test)]
mod tests {
    use super::{Generation, ObjectId, SlotId, SlotState, Vm, VmError};
    use rivetlua_core::{ObjectRef, Value};

    fn record_case(case_id: &str, input: &str, actual: &str) {
        let Ok(profile) = std::env::var("RIVETLUA_P06_PROFILE") else {
            return;
        };
        assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
        println!("P06_CASE\t{case_id}\t{profile}\t{input}\t{actual}");
    }

    #[test]
    fn complete_identity_distinguishes_vm_slot_and_generation() {
        let a = Vm::new().unwrap();
        let b = Vm::new().unwrap();
        let base = ObjectId::new(a.id(), SlotId::new(0), Generation::new(0));
        assert_ne!(
            base,
            ObjectId::new(b.id(), SlotId::new(0), Generation::new(0))
        );
        assert_ne!(
            base,
            ObjectId::new(a.id(), SlotId::new(1), Generation::new(0))
        );
        assert_ne!(
            base,
            ObjectId::new(a.id(), SlotId::new(0), Generation::new(1))
        );
    }

    #[test]
    fn occupied_free_and_retired_slots_never_alias() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(11)).unwrap();
        let first_id = first.identity().unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Occupied));
        vm.reclaim(first).unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Free));
        assert_eq!(vm.read(first), Err(VmError::StaleObject));
        assert_eq!(vm.reclaim(first), Err(VmError::StaleObject));
        let second = vm.allocate(Value::Integer(22)).unwrap();
        assert_eq!(second.identity().unwrap().slot, first_id.slot);
        assert_eq!(second.identity().unwrap().generation, Generation::new(1));
        assert!(vm.read(first).is_err());
        let last = vm.set_generation_for_test(second, Generation::new(u64::MAX));
        assert_eq!(vm.read(second), Err(VmError::StaleObject));
        vm.reclaim(last).unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Retired));
        let third = vm.allocate(Value::Integer(33)).unwrap();
        assert_ne!(third.identity().unwrap().slot, first_id.slot);
        assert!(vm.read(last).is_err());
    }

    #[test]
    fn heap_007_retired_slot_never_revives_old_host_handle() {
        let mut vm = Vm::new().unwrap();
        let original = vm.allocate(Value::Integer(10)).unwrap();
        let handle = super::HostHandle::<Value>::new(&mut vm, original).unwrap();
        assert_eq!(vm.remove_root(handle.root_id()), Ok(original));
        let terminal = vm.set_generation_for_test(original, Generation::new(u64::MAX));
        vm.reclaim(terminal).unwrap();
        let replacement = vm.allocate(Value::Integer(20)).unwrap();
        assert_eq!(
            vm.slot_state(original.identity().unwrap().slot),
            Some(SlotState::Retired)
        );
        assert_ne!(
            replacement.identity().unwrap().slot,
            original.identity().unwrap().slot
        );
        assert_eq!(handle.read(&vm), Err(VmError::StaleObject));
        assert_eq!(vm.read(terminal), Err(VmError::StaleObject));
        assert_eq!(vm.read(replacement), Ok(Value::Integer(20)));
        drop(handle);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        record_case(
            "HEAP-007",
            "將 slot generation 設為 u64::MAX 後回收並配置替代物件",
            "原 slot=Retired; 替代物件使用其他 slot; 舊 HostHandle=E_STALE_HANDLE",
        );
    }

    #[test]
    fn slot_growth_keeps_live_object_address() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(7)).unwrap();
        let before = vm
            .with_value(first, |value| value as *const Value as usize)
            .unwrap();
        for n in 0..512 {
            vm.allocate(Value::Integer(n)).unwrap();
        }
        let after = vm
            .with_value(first, |value| value as *const Value as usize)
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn rejected_reclaims_leave_occupied_slot_unchanged() {
        let mut a = Vm::new().unwrap();
        let mut b = Vm::new().unwrap();
        let object = a.allocate(Value::Integer(9)).unwrap();
        let id = object.identity().unwrap();
        assert_eq!(b.reclaim(object), Err(VmError::WrongVm));
        let forged = ObjectRef::from_id(ObjectId::new(a.id(), id.slot, Generation::new(1)));
        assert_eq!(a.reclaim(forged), Err(VmError::StaleObject));
        assert_eq!(a.slot_state(id.slot), Some(SlotState::Occupied));
        assert_eq!(a.read(object), Ok(Value::Integer(9)));
    }

    #[test]
    fn every_root_kind_is_registered_scanned_and_removed() {
        for kind in super::RootKind::ALL {
            let mut vm = Vm::new().unwrap();
            let object = vm.allocate(Value::Integer(7)).unwrap();
            let root = vm.add_root(kind, object).unwrap();
            assert_eq!(vm.roots().count(kind), 1);
            let mut visited = Vec::new();
            vm.roots().visit(kind, |reference| visited.push(reference));
            assert_eq!(visited, vec![object]);
            assert_eq!(vm.collect().unwrap(), 0);
            assert_eq!(vm.remove_root(root), Ok(object));
            assert_eq!(vm.roots().count(kind), 0);
            assert_eq!(vm.collect().unwrap(), 1);
            assert_eq!(vm.read(object), Err(VmError::StaleObject));
        }
    }

    #[test]
    fn tracing_follows_object_fields_and_collects_cycles() {
        let mut vm = Vm::new().unwrap();
        let parent = vm.allocate(Value::Nil).unwrap();
        let child = vm.allocate(Value::Nil).unwrap();
        let leaf = vm.allocate(Value::Integer(3)).unwrap();
        vm.add_child(parent, child).unwrap();
        vm.add_child(child, leaf).unwrap();
        vm.add_child(leaf, parent).unwrap();
        let root = vm.add_root(super::RootKind::Stack, parent).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(leaf), Ok(Value::Integer(3)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 3);
        assert_eq!(vm.read(parent), Err(VmError::StaleObject));
        assert_eq!(vm.read(child), Err(VmError::StaleObject));
        assert_eq!(vm.read(leaf), Err(VmError::StaleObject));
    }

    #[test]
    fn tracing_follows_value_object_field_and_rejects_bad_edges() {
        let mut vm = Vm::new().unwrap();
        let child = vm.allocate(Value::Integer(21)).unwrap();
        let parent = vm.allocate(Value::Object(child)).unwrap();
        let root = vm.add_root(super::RootKind::Registry, parent).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(child), Ok(Value::Integer(21)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(vm.add_child(parent, child), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn removing_one_of_two_roots_does_not_reclaim_object() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        let stack = vm.add_root(super::RootKind::Stack, object).unwrap();
        let host = vm.add_root(super::RootKind::Host, object).unwrap();
        vm.remove_root(stack).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(object), Ok(Value::Integer(8)));
        vm.remove_root(host).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn mark_error_does_not_start_sweep() {
        let mut vm = Vm::new().unwrap();
        let invalid = vm.allocate(Value::Integer(1)).unwrap();
        let unreachable = vm.allocate(Value::Integer(2)).unwrap();
        let root = vm.add_root(super::RootKind::Stack, invalid).unwrap();
        vm.reclaim(invalid).unwrap();
        assert_eq!(vm.collect(), Err(VmError::StaleObject));
        assert_eq!(vm.read(unreachable), Ok(Value::Integer(2)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_clone_transfer_and_drop_have_exact_root_counts() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(31)).unwrap();
        let base = vm.ledger_snapshot().committed;
        let first = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        let after_first = vm.ledger_snapshot().committed;
        assert!(after_first > base);
        assert_eq!(vm.roots().count(super::RootKind::Host), 1);
        let cloned = first.try_clone(&mut vm).unwrap();
        assert!(vm.ledger_snapshot().committed > after_first);
        assert_eq!(vm.roots().count(super::RootKind::Host), 2);
        let transferred = first;
        assert_eq!(vm.roots().count(super::RootKind::Host), 2);
        drop(transferred);
        assert_eq!(vm.ledger_snapshot().committed, after_first);
        assert_eq!(vm.roots().count(super::RootKind::Host), 1);
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(cloned.read(&vm), Ok(Value::Integer(31)));
        drop(cloned);
        assert_eq!(vm.ledger_snapshot().committed, base);
        assert_eq!(vm.roots().count(super::RootKind::Host), 0);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_drop_never_borrows_or_collects_vm() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(5)).unwrap();
        let handle = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        let roots = vm.roots();
        drop(handle);
        assert_eq!(roots.count(super::RootKind::Host), 0);
        assert_eq!(vm.read(object), Ok(Value::Integer(5)));
        let second = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        vm.with_value(object, |_| drop(second)).unwrap();
        assert_eq!(vm.roots().count(super::RootKind::Host), 0);
        assert_eq!(
            vm.slot_state(object.identity().unwrap().slot),
            Some(SlotState::Occupied)
        );
        assert_eq!(vm.read(object), Ok(Value::Integer(5)));
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_can_outlive_vm_without_retaining_heap() {
        let handle = {
            let mut vm = Vm::new().unwrap();
            let object = vm.allocate(Value::Integer(1)).unwrap();
            super::HostHandle::<Value>::new(&mut vm, object).unwrap()
        };
        drop(handle);
    }

    #[test]
    fn injected_allocation_failures_preserve_heap_root_and_ledger_state() {
        for point in [
            super::FailPoint::SlotReserve,
            super::FailPoint::ObjectReserve,
            super::FailPoint::ObjectInitialize,
            super::FailPoint::RootReserve,
            super::FailPoint::MarkReserve,
            super::FailPoint::WorkReserve,
        ] {
            let mut vm = Vm::new().unwrap();
            if matches!(
                point,
                super::FailPoint::RootReserve
                    | super::FailPoint::MarkReserve
                    | super::FailPoint::WorkReserve
            ) {
                vm.set_collect_every_allocation(true);
            }
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate(Value::Integer(1)),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.slot_state(SlotId::new(0)), None);
            assert_eq!(vm.roots().total_count(), 0);
        }
    }

    #[test]
    fn sweep_refunds_objects_and_child_edges_but_keeps_reusable_slot_charge() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(1)).unwrap();
        let second = vm.allocate(Value::Integer(2)).unwrap();
        let after_objects = vm.ledger_snapshot().committed;
        vm.add_child(first, second).unwrap();
        let after_edge = vm.ledger_snapshot().committed;
        assert!(after_edge > after_objects);
        let root = vm.add_root(super::RootKind::Stack, first).unwrap();
        assert!(vm.ledger_snapshot().committed > after_edge);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().committed, after_edge);
        assert_eq!(vm.collect().unwrap(), 2);
        let after_sweep = vm.ledger_snapshot();
        assert!(after_sweep.committed > 0);
        assert!(after_sweep.committed < after_objects);
        assert_eq!(after_sweep.reserved, 0);
        let replacement = vm.allocate(Value::Integer(3)).unwrap();
        assert_eq!(
            replacement.identity().unwrap().slot,
            first.identity().unwrap().slot
        );
        assert!(vm.ledger_snapshot().committed > after_sweep.committed);
    }
}
