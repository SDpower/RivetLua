use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use rivetlua_core::{LuaProfile, SlotId, Value};
use rivetlua_runtime::{ExternalStringStorage, FailPoint, RootKind, SlotState, Vm, VmError};

struct ExternalBytes {
    bytes: Box<[u8]>,
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

fn owner(bytes: &[u8], drops: &Rc<Cell<usize>>) -> Rc<dyn ExternalStringStorage> {
    Rc::new(ExternalBytes {
        bytes: bytes.into(),
        drops: Rc::clone(drops),
    })
}

fn hash(value: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn external_string_bytes_root_gc_and_vm_drop_b9() {
    let drops = Rc::new(Cell::new(0));
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let external = vm
        .allocate_external_byte_string(owner(&[0, b'A', 0x80, 0], &drops))
        .unwrap();
    let equal = vm.allocate_byte_string(&[0, b'A', 0x80, 0]).unwrap();
    vm.with_byte_string(external, |a| {
        vm.with_byte_string(equal, |b| {
            assert_eq!(a, b);
            assert_eq!(hash(a), hash(b));
            assert_eq!(a.as_bytes(), &[0, b'A', 0x80, 0]);
        })
        .unwrap();
    })
    .unwrap();
    let root = vm.add_root(RootKind::Host, external).unwrap();
    vm.collect().unwrap();
    assert_eq!(drops.get(), 0);
    vm.remove_root(root).unwrap();
    vm.collect().unwrap();
    assert_eq!(drops.get(), 1);
    assert_eq!(
        vm.slot_state(external.identity().unwrap().slot),
        Some(SlotState::Free)
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let second = vm
        .allocate_external_byte_string(owner(b"vm-drop", &drops))
        .unwrap();
    assert!(
        vm.with_byte_string(second, |s| s.as_bytes() == b"vm-drop")
            .unwrap()
    );
    drop(vm);
    assert_eq!(drops.get(), 2);
}

#[test]
fn external_string_unpublished_failures_drop_once_and_roll_back_b9() {
    for point in [FailPoint::ObjectReserve, FailPoint::RootReserve] {
        let drops = Rc::new(Cell::new(0));
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(point);
        let result = if point == FailPoint::ObjectReserve {
            vm.allocate_external_byte_string(owner(b"failed", &drops))
                .map(|_| ())
        } else {
            vm.with_unpublished_external_byte_string(owner(b"failed", &drops), |vm, object| {
                let root = vm.add_root(RootKind::Host, object)?;
                vm.remove_root(root)?;
                Ok(())
            })
        };
        assert_eq!(result, Err(VmError::InjectedFailure(point)));
        assert_eq!(drops.get(), 1);
        assert_eq!(vm.slot_state(SlotId::new(0)), None);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn external_long_key_shares_owner_and_is_content_equal_b9() {
    let mut deltas = [0usize; 2];
    let mut allocation_deltas = [0usize; 2];
    for (index, length) in [32, 64 * 1024].into_iter().enumerate() {
        let drops = Rc::new(Cell::new(0));
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let bytes = vec![0x81; length];
        let before_allocation = vm.ledger_snapshot().lua_heap_bytes;
        let external = vm
            .allocate_external_byte_string(owner(&bytes, &drops))
            .unwrap();
        allocation_deltas[index] = vm.ledger_snapshot().lua_heap_bytes - before_allocation;
        let external_root = vm.add_root(RootKind::Host, external).unwrap();
        let before = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(external), Value::Integer(27))
            .unwrap();
        deltas[index] = vm.ledger_snapshot().lua_heap_bytes - before;
        vm.remove_root(external_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(drops.get(), 0);
        let equal_owned = vm.allocate_byte_string(&bytes).unwrap();
        let equal_root = vm.add_root(RootKind::Host, equal_owned).unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(equal_owned)),
            Ok(Value::Integer(27))
        );
        vm.raw_set(table, Value::Object(equal_owned), Value::Nil)
            .unwrap();
        vm.remove_root(equal_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(drops.get(), 1);
        vm.remove_root(table_root).unwrap();
    }
    assert!(
        allocation_deltas[1] < allocation_deltas[0] + 1024,
        "external content was charged as Lua payload: {allocation_deltas:?}"
    );
    assert!(
        deltas[1] < deltas[0] + 1024,
        "long key copied into canonical backing: {deltas:?}"
    );
}

#[test]
fn external_weak_mode_bytes_drive_gc_and_release_once_b9() {
    let drops = Rc::new(Cell::new(0));
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let weak = vm.allocate_table().unwrap();
    let weak_root = vm.add_root(RootKind::Host, weak).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mode = vm
        .allocate_external_byte_string(owner(b"kv", &drops))
        .unwrap();
    let mode_root = vm.add_root(RootKind::Host, mode).unwrap();
    vm.raw_set(metatable, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(weak, Some(metatable)).unwrap();
    vm.remove_root(mode_root).unwrap();
    let key = vm.allocate_table().unwrap();
    let value = vm.allocate_table().unwrap();
    vm.raw_set(weak, Value::Object(key), Value::Object(value))
        .unwrap();
    vm.collect().unwrap();
    assert!(vm.with_table(weak, |table| table.is_empty()).unwrap());
    assert_eq!(drops.get(), 0);
    vm.remove_root(weak_root).unwrap();
    vm.collect().unwrap();
    assert_eq!(drops.get(), 1);
}
