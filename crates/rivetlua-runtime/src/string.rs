//! P08-1 的不可變 byte string。

use crate::VmError;
use crate::alloc::{AllocationLedger, FailPoint, Reservation, reserve_vec};

/// Heap 內的不可變任意 bytes；相等與 hash 均涵蓋完整內容。
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct ByteString {
    bytes: Vec<u8>,
}

impl ByteString {
    pub(crate) fn try_from_bytes(
        ledger: &AllocationLedger,
        bytes: &[u8],
    ) -> Result<(Self, Reservation), VmError> {
        let mut stored = Vec::new();
        let ticket = reserve_vec(
            ledger,
            &mut stored,
            bytes.len(),
            FailPoint::StringBytesReserve,
        )?;
        stored.extend_from_slice(bytes);
        Ok((Self { bytes: stored }, ticket))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use rivetlua_core::{SlotId, Value};

    use crate::{FailPoint, RootKind, SlotState, Vm, VmError};

    fn hash(value: impl Hash) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn byte_string_keeps_all_bytes_length_equality_and_hash() {
        let mut vm = Vm::new().unwrap();
        let bytes = [0x00, 0x41, 0x80, 0xff];
        let first = vm.allocate_byte_string(&bytes).unwrap();
        let second = vm.clone_byte_string(first).unwrap();
        let third = vm.allocate_byte_string(&[0x00, 0x41, 0x80, 0xfe]).unwrap();
        let empty = vm.allocate_byte_string(&[]).unwrap();
        assert_ne!(first.identity(), second.identity());
        vm.with_byte_string(first, |a| {
            assert_eq!(a.as_bytes(), bytes);
            assert_eq!(a.len(), 4);
            vm.with_byte_string(second, |b| {
                assert_eq!(a, b);
                assert_eq!(hash(a), hash(b));
            })
            .unwrap();
            vm.with_byte_string(third, |b| assert_ne!(a, b)).unwrap();
            vm.with_byte_string(empty, |b| {
                assert!(b.is_empty());
                assert_eq!(b.len(), 0);
                assert_ne!(a, b);
            })
            .unwrap();
        })
        .unwrap();
        let value = vm.allocate(Value::Integer(7)).unwrap();
        assert_eq!(vm.read(value), Ok(Value::Integer(7)));
        assert_eq!(vm.with_value(value, |v| *v), Ok(Value::Integer(7)));
        assert_eq!(
            vm.with_byte_string(value, |s| s.len()),
            Err(VmError::WrongObjectType)
        );
        assert_eq!(vm.read(first), Err(VmError::WrongObjectType));
    }

    #[test]
    fn byte_string_failed_creation_and_copy_leave_no_object_root_or_reserved_bytes() {
        for point in [
            FailPoint::StringBytesReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
            FailPoint::MarkReserve,
            FailPoint::WorkReserve,
        ] {
            let mut vm = Vm::new().unwrap();
            vm.set_collect_every_allocation(true);
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate_byte_string(&[0, 0x80, 0xff]),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.slot_state(SlotId::new(0)), None);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        vm.set_allocation_limit(0);
        assert_eq!(
            vm.allocate_byte_string(&[0]),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.slot_state(SlotId::new(0)), None);

        let mut vm = Vm::new().unwrap();
        let source = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        vm.set_collect_every_allocation(true);
        let before = vm.ledger_snapshot();
        for point in [
            FailPoint::RootReserve,
            FailPoint::StringBytesReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
            FailPoint::MarkReserve,
            FailPoint::WorkReserve,
        ] {
            vm.inject_failure_once(point);
            assert_eq!(
                vm.clone_byte_string(source),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            assert_eq!(vm.slot_state(SlotId::new(1)), None);
            vm.with_byte_string(source, |s| assert_eq!(s.as_bytes(), [0, 0x80, 0xff]))
                .unwrap();
        }
        vm.set_allocation_limit(before.committed);
        assert_eq!(vm.clone_byte_string(source), Err(VmError::AllocationFailed));
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn byte_string_copy_source_survives_forced_collection_then_payload_is_refunded() {
        let mut vm = Vm::new().unwrap();
        let source = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        vm.set_collect_every_allocation(true);
        let copy = vm.clone_byte_string(source).unwrap();
        assert_eq!(vm.with_byte_string(source, |s| s.len()), Ok(3));
        assert_eq!(vm.with_byte_string(copy, |s| s.len()), Ok(3));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(
            vm.slot_state(source.identity().unwrap().slot),
            Some(SlotState::Free)
        );
        assert_eq!(
            vm.slot_state(copy.identity().unwrap().slot),
            Some(SlotState::Free)
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let reusable_slots_charge = vm.ledger_snapshot().committed;
        let replacement = vm.allocate_byte_string(&[0x80; 17]).unwrap();
        assert_eq!(vm.with_byte_string(replacement, |s| s.len()), Ok(17));
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(vm.ledger_snapshot().committed, reusable_slots_charge);
    }
}
