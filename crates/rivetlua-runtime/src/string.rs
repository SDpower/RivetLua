//! P08-1 的不可變 byte string。

use crate::VmError;
use crate::alloc::{AllocationLedger, FailPoint, PairedLuaCharges, Reservation, reserve_vec};
use core::mem::size_of;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

/// 外部不可變 byte string 的安全擁有者。bytes 在 owner 存活期間須保持不變；
/// 最後一個 owner 消失時由實作者釋放資源。
pub trait ExternalStringStorage {
    fn bytes(&self) -> &[u8];

    /// 可選的原位 NUL 結尾視圖；未提供時 C API 會建立自有 NUL 結尾 view。
    #[doc(hidden)]
    fn nul_terminated_bytes(&self) -> Option<&[u8]> {
        None
    }
}

enum StringBacking {
    Owned(Vec<u8>),
    ManagedShared(Rc<ManagedStringBacking>),
    External(Rc<dyn ExternalStringStorage>),
}

struct ManagedStringBacking {
    bytes: Vec<u8>,
    _charges: PairedLuaCharges,
    debt_bytes: usize,
}

/// Heap 內的不可變任意 bytes；相等與 hash 均涵蓋完整內容。
pub struct ByteString {
    backing: StringBacking,
}

impl fmt::Debug for ByteString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ByteString")
            .field(&self.as_bytes())
            .finish()
    }
}

impl PartialEq for ByteString {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ByteString {}

impl Hash for ByteString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl ByteString {
    /// 共用長字串須比保留第二份 bytes 便宜；Rc owner 的實際配置含控制區。
    pub(crate) const fn managed_sharing_metadata_bytes() -> usize {
        size_of::<ManagedStringBacking>() + 2 * size_of::<usize>()
    }

    pub(crate) const fn managed_sharing_is_cheaper(byte_len: usize) -> bool {
        byte_len > Self::managed_sharing_metadata_bytes()
    }

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
        Ok((
            Self {
                backing: StringBacking::Owned(stored),
            },
            ticket,
        ))
    }

    pub(crate) fn from_external(owner: Rc<dyn ExternalStringStorage>) -> Self {
        Self {
            backing: StringBacking::External(owner),
        }
    }

    /// 長字串的來源物件與 table key 共用不可變 backing；帳款隨最後一個 owner 退還。
    pub(crate) fn try_managed_shared_from_bytes(
        ledger: &AllocationLedger,
        bytes: &[u8],
    ) -> Result<Self, VmError> {
        let (owned, bytes_ticket) = Self::try_from_bytes(ledger, bytes)?;
        let metadata_bytes = Self::managed_sharing_metadata_bytes();
        let metadata_ticket =
            ledger.reserve_lua_backing_excess(metadata_bytes, FailPoint::StringBytesReserve)?;
        let bytes_charge = bytes_ticket.commit_charge()?;
        let metadata_charge = metadata_ticket.commit_charge()?;
        let debt_bytes = bytes_charge
            .bytes()
            .checked_add(metadata_charge.bytes())
            .ok_or(VmError::ArithmeticOverflow)?;
        let StringBacking::Owned(stored) = owned.backing else {
            unreachable!("新建的 byte string 必須持有自有 backing")
        };
        let mut charges = PairedLuaCharges::new(ledger.clone());
        charges.replace_first(bytes_charge);
        charges.replace_second(metadata_charge);
        Ok(Self {
            backing: StringBacking::ManagedShared(Rc::new(ManagedStringBacking {
                bytes: stored,
                _charges: charges,
                debt_bytes,
            })),
        })
    }

    pub(crate) fn shared_external(&self) -> Option<Self> {
        match &self.backing {
            StringBacking::External(owner) => Some(Self::from_external(Rc::clone(owner))),
            StringBacking::Owned(_) | StringBacking::ManagedShared(_) => None,
        }
    }

    pub(crate) fn shared_table_key(&self) -> Option<Self> {
        match &self.backing {
            StringBacking::ManagedShared(owner) => Some(Self {
                backing: StringBacking::ManagedShared(Rc::clone(owner)),
            }),
            StringBacking::External(owner) => Some(Self::from_external(Rc::clone(owner))),
            StringBacking::Owned(_) => None,
        }
    }

    /// 宿主借讀 external 原指標；呼叫端必須以此字串物件的 root 保活它。
    #[doc(hidden)]
    pub fn external_pointer(&self) -> Option<(*const u8, usize)> {
        match &self.backing {
            StringBacking::External(owner) => {
                let bytes = owner.bytes();
                let terminated = owner.nul_terminated_bytes()?;
                let required = bytes.len().checked_add(1)?;
                if terminated.len() != required
                    || terminated.as_ptr() != bytes.as_ptr()
                    || terminated[bytes.len()] != 0
                {
                    return None;
                }
                Some((bytes.as_ptr(), bytes.len()))
            }
            StringBacking::Owned(_) | StringBacking::ManagedShared(_) => None,
        }
    }

    pub(crate) fn managed_payload_len(&self) -> usize {
        match &self.backing {
            StringBacking::Owned(bytes) => bytes.len(),
            StringBacking::ManagedShared(owner) => owner.debt_bytes,
            StringBacking::External(_) => 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.backing {
            StringBacking::Owned(bytes) => bytes,
            StringBacking::ManagedShared(owner) => &owner.bytes,
            StringBacking::External(owner) => owner.bytes(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteString, StringBacking};
    use core::mem::size_of;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::rc::Rc;

    use rivetlua_core::{SlotId, Value};

    use crate::{AllocationLedger, FailPoint, RootKind, SlotState, Vm, VmError};

    fn hash(value: impl Hash) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn managed_long_string_table_key_last_owner_refunds_exact_charge() {
        let ledger = AllocationLedger::new(usize::MAX);
        let baseline = ledger.snapshot();
        let source = ByteString::try_managed_shared_from_bytes(&ledger, &[b'k'; 4096]).unwrap();
        let charged = ledger.snapshot();
        let key = source.shared_table_key().unwrap();
        let (StringBacking::ManagedShared(source_owner), StringBacking::ManagedShared(key_owner)) =
            (&source.backing, &key.backing)
        else {
            panic!("長字串 table key 應共用同一 backing");
        };
        assert!(Rc::ptr_eq(source_owner, key_owner));
        assert_eq!(
            charged.lua_heap_bytes,
            source_owner.bytes.capacity()
                + size_of::<super::ManagedStringBacking>()
                + 2 * size_of::<usize>()
        );
        assert_eq!(charged.lua_heap_bytes, source.managed_payload_len());
        assert_eq!(ledger.snapshot(), charged);
        drop(source);
        assert_eq!(ledger.snapshot(), charged);
        assert_eq!(key.as_bytes(), &[b'k'; 4096]);
        drop(key);
        assert_eq!(ledger.snapshot(), baseline);
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

    #[test]
    fn managed_long_string_clone_keeps_independent_bytes_and_refunds_after_collection() {
        let mut vm = Vm::new().unwrap();
        vm.stop_automatic_gc();
        let probe = vm.ledger_probe();
        let bytes = [0x80; 4096];
        let source = vm.allocate_byte_string(&bytes).unwrap();
        let source_root = vm.add_root(RootKind::Host, source).unwrap();
        let before_clone = vm.ledger_snapshot().lua_heap_bytes;
        let copy = vm.clone_byte_string(source).unwrap();
        let copy_root = vm.add_root(RootKind::Host, copy).unwrap();
        assert!(vm.ledger_snapshot().lua_heap_bytes >= before_clone + bytes.len());
        vm.remove_root(source_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(source), Err(VmError::StaleObject));
        vm.with_byte_string(copy, |stored| assert_eq!(stored.as_bytes(), bytes))
            .unwrap();
        vm.remove_root(copy_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(copy), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    #[test]
    fn managed_long_string_failure_rolls_back_bytes_metadata_and_roots() {
        let bytes = [b'x'; 4096];
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
                vm.allocate_byte_string(&bytes),
                Err(VmError::InjectedFailure(point)),
                "{point:?}"
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.slot_state(SlotId::new(0)), None);
        }

        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        vm.set_allocation_limit(before.committed + bytes.len());
        assert_eq!(vm.allocate_byte_string(&bytes), Err(VmError::AllocationFailed));
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.roots().total_count(), 0);
    }
}
