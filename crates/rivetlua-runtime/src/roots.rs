//! VM 集中持有的六類強參照來源。

use allocator_api2::vec::Vec as AllocVec;
use core::cell::{Cell, RefCell};
use core::mem::size_of;

use rivetlua_alloc::{SharedBlock, SharedUninitBlock, StateAllocator};
use rivetlua_core::{ObjectRef, VmId};

use crate::alloc::{AllocationCharge, AllocationLedger, FailPoint, Reservation};
use crate::heap::VmError;

/// 最小收集器必須逐類掃描的 root。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RootKind {
    Stack,
    Registry,
    Global,
    Temporary,
    Coroutine,
    Host,
}

impl RootKind {
    pub const ALL: [Self; 6] = [
        Self::Stack,
        Self::Registry,
        Self::Global,
        Self::Temporary,
        Self::Coroutine,
        Self::Host,
    ];
}

/// 與建立它的 VM 綁定，且不重用的 root 登錄識別。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RootId {
    vm: VmId,
    sequence: u64,
    slot: usize,
}

struct RootEntry {
    kind: RootKind,
    value: RootValue,
    charge: Option<AllocationCharge>,
}

enum RootValue {
    Direct {
        id: RootId,
        object: Option<ObjectRef>,
        lease: Option<RootLease>,
    },
    Stack(SharedBlock<StackRootData>),
}

impl RootEntry {
    fn id(&self) -> RootId {
        match &self.value {
            RootValue::Direct { id, .. } => *id,
            RootValue::Stack(data) => data.id.get(),
        }
    }

    fn object(&self) -> Option<ObjectRef> {
        match &self.value {
            RootValue::Direct { object, .. } => *object,
            RootValue::Stack(data) => data.object.get(),
        }
    }

    fn is_owned(&self) -> bool {
        match &self.value {
            RootValue::Direct { lease, .. } => lease.as_ref().is_none_or(RootLease::is_active),
            RootValue::Stack(data) => data.active.get(),
        }
    }

    fn is_active(&self) -> bool {
        self.is_owned() && self.object().is_some()
    }

    fn deactivate(&self) {
        match &self.value {
            RootValue::Direct { lease, .. } => {
                if let Some(lease) = lease {
                    lease.deactivate();
                }
            }
            RootValue::Stack(data) => data.deactivate(),
        }
    }
}

enum RootSlot {
    Occupied(RootEntry),
    Free { next: Option<usize> },
}

/// 只共享 root 存活與帳面費用，不持有 VM 或 Lua 物件配置。
#[derive(Clone)]
pub(crate) struct RootLease(SharedBlock<RootLeaseState>);

pub(crate) struct RootLeaseState {
    active: Cell<bool>,
    charge: RefCell<Option<AllocationCharge>>,
}

impl RootLease {
    fn new(storage: SharedUninitBlock<RootLeaseState>, charge: AllocationCharge) -> Self {
        Self(storage.write(RootLeaseState {
            active: Cell::new(true),
            charge: RefCell::new(Some(charge)),
        }))
    }

    pub(crate) fn is_active(&self) -> bool {
        self.0.active.get()
    }

    pub(crate) fn deactivate(&self) {
        if self.0.active.replace(false) {
            // VM 可已析構；此處只改共享帳本的 Cell，不借用 heap 或配置。
            self.0.charge.borrow_mut().take();
        }
    }
}

pub(crate) struct StackRoot(SharedBlock<StackRootData>);

pub(crate) struct StackRootData {
    id: Cell<RootId>,
    object: Cell<Option<ObjectRef>>,
    active: Cell<bool>,
    owners: Cell<usize>,
    pool: Option<(SharedBlock<CapiStackRoots>, usize)>,
    _charge: AllocationCharge,
}

pub(crate) struct CapiStackRoots {
    pub(crate) available: Cell<usize>,
    pub(crate) reserved: Cell<usize>,
    pub(crate) next: Cell<usize>,
    pub(crate) _charge: crate::heap::HostAllocationCharge,
}

impl StackRootData {
    fn deactivate(&self) {
        self.active.set(false);
        self.object.set(None);
    }
}

impl StackRoot {
    fn new(storage: SharedUninitBlock<StackRootData>, id: RootId, object: ObjectRef,
        charge: AllocationCharge, pool: Option<(SharedBlock<CapiStackRoots>, usize)>) -> Self {
        Self(storage.write(StackRootData {
            id: Cell::new(id),
            object: Cell::new(Some(object)),
            active: Cell::new(true),
            owners: Cell::new(1),
            pool,
            _charge: charge,
        }))
    }

    pub(crate) fn id(&self) -> RootId {
        self.0.id.get()
    }

    pub(crate) fn has_object(&self) -> bool {
        self.0.active.get() && self.0.object.get().is_some()
    }

    pub(crate) fn is_reserved_free(&self) -> bool {
        self.0.pool.is_some() && self.0.active.get()
            && self.0.owners.get() == 1 && self.0.object.get().is_none()
    }

    pub(crate) fn is_capi_reserved(&self) -> bool {
        self.0.pool.is_some()
    }

    pub(crate) fn is_unique_private(&self) -> bool {
        self.0.active.get() && self.0.pool.is_none() && self.0.owners.get() == 1
    }

    pub(crate) fn can_pass_from_capi_slot(&self) -> bool {
        self.0.active.get()
            && self.0.owners.get() == if self.0.pool.is_some() { 2 } else { 1 }
    }
}

impl Clone for StackRoot {
    fn clone(&self) -> Self {
        let data = self.0.clone();
        let owners = self.0.owners.get();
        // SharedBlock 已確認可增加強參照；只有 StackRoot handle 計入 owner。
        self.0.owners.set(owners.checked_add(1).expect("StackRoot owner 計數溢位"));
        Self(data)
    }
}

impl Drop for StackRoot {
    fn drop(&mut self) {
        let remaining = self.0.owners.get().checked_sub(1).expect("StackRoot owner 計數不足");
        self.0.owners.set(remaining);
        if remaining == 0 {
            self.0.deactivate();
        } else if remaining == 1 {
            if let Some((pool, index)) = &self.0.pool {
                self.0.object.set(None);
                pool.available.set(pool.available.get() + 1);
                pool.next.set(*index);
            }
        }
    }
}

/// root 表只由 VM 修改；公開介面供檢視類別與計數。
pub struct RootSet {
    vm: VmId,
    entries: AllocVec<RootSlot, StateAllocator>,
    free_head: Option<usize>,
    next_sequence: u64,
}

impl RootSet {
    pub(crate) fn new(vm: VmId, allocator: StateAllocator) -> Self {
        Self {
            vm,
            entries: AllocVec::new_in(allocator),
            free_head: None,
            next_sequence: 1,
        }
    }

    fn next_id(&self, slot: usize) -> Result<RootId, VmError> {
        self.next_sequence
            .checked_add(1)
            .ok_or(VmError::RootIdExhausted)?;
        Ok(RootId {
            vm: self.vm,
            sequence: self.next_sequence,
            slot,
        })
    }

    fn insert(&mut self, entry: RootEntry) -> Result<(), VmError> {
        if let Some(index) = self.free_head {
            let RootSlot::Free { next } = &self.entries[index] else {
                unreachable!("free list 只能指向空槽")
            };
            self.free_head = *next;
            self.entries[index] = RootSlot::Occupied(entry);
        } else {
            if self.entries.len() == self.entries.capacity() {
                return Err(VmError::LedgerInvariant);
            }
            self.entries.push(RootSlot::Occupied(entry));
        }
        Ok(())
    }

    fn prepare_slot_ticket(&mut self, ledger: &AllocationLedger, bytes: usize) -> Result<Reservation, VmError> {
        if self.free_head.is_none() {
            self.compact();
        }
        let slot = self.free_head.unwrap_or(self.entries.len());
        self.next_id(slot)?;
        if self.entries.allocator().is_lua() {
            ledger.reserve_userdata_vec(bytes, FailPoint::RootReserve, true)
        } else {
            let ticket = ledger.reserve(bytes)?;
            ledger.checkpoint(FailPoint::RootReserve)?;
            Ok(ticket)
        }
    }

    pub(crate) fn prepare_direct_slot(&mut self, ledger: &AllocationLedger) -> Result<Reservation, VmError> {
        self.prepare_slot_ticket(ledger, size_of::<RootSlot>())
    }

    pub(crate) fn prepare_host_slot(&mut self, ledger: &AllocationLedger) -> Result<Reservation, VmError> {
        let bytes = size_of::<RootSlot>()
            .checked_add(StateAllocator::shared_block_size::<RootLeaseState>())
            .ok_or(VmError::ArithmeticOverflow)?;
        self.prepare_slot_ticket(ledger, bytes)
    }

    pub(crate) fn prepare_stack_slot(&mut self, ledger: &AllocationLedger) -> Result<Reservation, VmError> {
        let bytes = size_of::<RootSlot>()
            .checked_add(StateAllocator::shared_block_size::<StackRootData>())
            .ok_or(VmError::ArithmeticOverflow)?;
        self.prepare_slot_ticket(ledger, bytes)
    }

    pub(crate) fn backing_identity(&self) -> (*const (), usize, usize) {
        (self.entries.as_ptr().cast(), self.entries.len(), self.entries.capacity())
    }

    pub(crate) fn reserve_slot_backing(&mut self, ticket: &Reservation, force: bool) -> Result<(), VmError> {
        if force || self.free_head.is_none() {
            let before = self.entries.allocator().refusal_count();
            self.entries.try_reserve_exact(1).map_err(|_| {
                if self.entries.allocator().is_lua()
                    && self.entries.allocator().refusal_count() != before {
                    ticket.physical_reserve_failure()
                } else {
                    ticket.rust_reserve_failure()
                }
            })?;
        }
        Ok(())
    }

    pub(crate) fn publish_direct(
        &mut self,
        kind: RootKind,
        object: ObjectRef,
        charge: AllocationCharge,
    ) -> Result<RootId, VmError> {
        let slot = self.free_head.unwrap_or(self.entries.len());
        let id = self.next_id(slot)?;
        self.insert(RootEntry {
            kind,
            value: RootValue::Direct {
                id,
                object: Some(object),
                lease: None,
            },
            charge: Some(charge),
        })?;
        self.next_sequence += 1;
        Ok(id)
    }

    pub(crate) fn publish_empty_registry(
        &mut self,
        charge: AllocationCharge,
    ) -> Result<RootId, VmError> {
        let slot = self.free_head.unwrap_or(self.entries.len());
        let id = self.next_id(slot)?;
        self.insert(RootEntry {
            kind: RootKind::Registry,
            value: RootValue::Direct { id, object: None, lease: None },
            charge: Some(charge),
        })?;
        self.next_sequence += 1;
        Ok(id)
    }

    pub(crate) fn publish_host(
        &mut self,
        object: ObjectRef,
        storage: SharedUninitBlock<RootLeaseState>,
        charge: AllocationCharge,
    ) -> Result<(RootId, RootLease), VmError> {
        let slot = self.free_head.unwrap_or(self.entries.len());
        let id = self.next_id(slot)?;
        let lease = RootLease::new(storage, charge);
        self.insert(RootEntry {
            kind: RootKind::Host,
            value: RootValue::Direct {
                id,
                object: Some(object),
                lease: Some(lease.clone()),
            },
            charge: None,
        })?;
        self.next_sequence += 1;
        Ok((id, lease))
    }

    pub(crate) fn publish_stack(
        &mut self,
        object: ObjectRef,
        storage: SharedUninitBlock<StackRootData>,
        charge: AllocationCharge,
    ) -> Result<StackRoot, VmError> {
        self.publish_stack_with_pool(object, storage, charge, None)
    }

    pub(crate) fn publish_capi_stack(
        &mut self, object: ObjectRef, storage: SharedUninitBlock<StackRootData>,
        charge: AllocationCharge, pool: SharedBlock<CapiStackRoots>, index: usize,
    ) -> Result<StackRoot, VmError> {
        self.publish_stack_with_pool(object, storage, charge, Some((pool, index)))
    }

    fn publish_stack_with_pool(
        &mut self, object: ObjectRef, storage: SharedUninitBlock<StackRootData>,
        charge: AllocationCharge, pool: Option<(SharedBlock<CapiStackRoots>, usize)>,
    ) -> Result<StackRoot, VmError> {
        let slot = self.free_head.unwrap_or(self.entries.len());
        let id = self.next_id(slot)?;
        let root = StackRoot::new(storage, id, object, charge, pool);
        self.insert(RootEntry {
            kind: RootKind::Stack,
            value: RootValue::Stack(root.0.clone()),
            charge: None,
        })?;
        self.next_sequence += 1;
        Ok(root)
    }

    #[inline(always)]
    pub(crate) fn prepare_stack_change(
        &self,
        root: &StackRoot,
        object: Option<ObjectRef>,
    ) -> Result<Option<RootId>, VmError> {
        let id = root.id();
        if id.vm != self.vm {
            return Err(VmError::WrongVm);
        }
        if !root.0.active.get() {
            return Err(VmError::StaleRoot);
        }
        // 私有 handle 的 active 狀態只在固定槽仍登記時為真。
        (root.0.object.get() != object && object.is_some())
            .then(|| self.next_id(id.slot))
            .transpose()
    }

    #[inline(always)]
    pub(crate) fn commit_stack_change(
        &mut self,
        root: &StackRoot,
        object: Option<ObjectRef>,
        next_id: Option<RootId>,
    ) {
        if let Some(next) = next_id {
            self.next_sequence += 1;
            root.0.id.set(next);
        }
        root.0.object.set(object);
    }

    pub(crate) fn set_registry(&mut self, id: RootId, value: Option<ObjectRef>) -> Result<(), VmError> {
        if id.vm != self.vm { return Err(VmError::WrongVm); }
        let Some(RootSlot::Occupied(entry)) = self.entries.get_mut(id.slot) else {
            return Err(VmError::StaleRoot);
        };
        if entry.kind != RootKind::Registry || entry.id() != id { return Err(VmError::StaleRoot); }
        let RootValue::Direct { object, lease: None, .. } = &mut entry.value else {
            return Err(VmError::StaleRoot);
        };
        *object = value;
        Ok(())
    }

    pub(crate) fn remove(
        &mut self,
        _ledger: &AllocationLedger,
        id: RootId,
    ) -> Result<ObjectRef, VmError> {
        if id.vm != self.vm {
            return Err(VmError::WrongVm);
        }
        let Some(RootSlot::Occupied(entry)) = self.entries.get(id.slot) else {
            return Err(VmError::StaleRoot);
        };
        if entry.id() != id {
            return Err(VmError::StaleRoot);
        }
        if entry.is_owned() && entry.object().is_none() {
            return Err(VmError::StaleRoot);
        }
        let was_active = entry.is_active();
        let object = entry.object();
        entry.deactivate();
        let RootSlot::Occupied(entry) = core::mem::replace(
            &mut self.entries[id.slot],
            RootSlot::Free { next: self.free_head },
        ) else {
            unreachable!()
        };
        self.free_head = Some(id.slot);
        drop(entry.charge);
        if was_active {
            object.ok_or(VmError::StaleRoot)
        } else {
            Err(VmError::StaleRoot)
        }
    }

    pub(crate) fn compact(&mut self) {
        // 已停用的 stack owner 先失去 Lua 物件，再於實體記錄移除時退還帳款。
        for index in 0..self.entries.len() {
            let stale = matches!(&self.entries[index], RootSlot::Occupied(entry) if !entry.is_owned());
            if stale {
                if let RootSlot::Occupied(entry) = &self.entries[index] {
                    entry.deactivate();
                }
                self.entries[index] = RootSlot::Free { next: self.free_head };
                self.free_head = Some(index);
            }
        }
    }

    pub(crate) fn release_all_on_vm_drop(&mut self, _ledger: &AllocationLedger) {
        for slot in self.entries.drain(..) {
            if let RootSlot::Occupied(entry) = slot {
                entry.deactivate();
                drop(entry.charge);
            }
        }
        self.free_head = None;
    }

    pub fn count(&self, kind: RootKind) -> usize {
        self.entries
            .iter()
            .filter(|slot| matches!(slot, RootSlot::Occupied(entry) if entry.kind == kind && entry.is_active()))
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|slot| matches!(slot, RootSlot::Occupied(entry) if entry.is_active()))
            .count()
    }

    pub fn visit(&self, kind: RootKind, mut f: impl FnMut(ObjectRef)) {
        for slot in &self.entries {
            if let RootSlot::Occupied(entry) = slot {
                if entry.kind == kind && entry.is_active() {
                    if let Some(object) = entry.object() {
                        f(object);
                    }
                }
            }
        }
    }

    pub fn visit_labeled(&self, mut f: impl FnMut(RootKind, RootId, ObjectRef)) {
        for slot in &self.entries {
            if let RootSlot::Occupied(entry) = slot {
                if entry.is_active() {
                    if let Some(object) = entry.object() {
                        f(entry.kind, entry.id(), object);
                    }
                }
            }
        }
    }

    pub(crate) fn active_object(&self, id: RootId) -> Option<ObjectRef> {
        if id.vm != self.vm {
            return None;
        }
        match self.entries.get(id.slot) {
            Some(RootSlot::Occupied(entry)) if entry.id() == id && entry.is_active() => entry.object(),
            _ => None,
        }
    }

    pub(crate) fn try_visit_all(
        &self,
        mut f: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.try_visit_labeled(|_, _, object| f(object))
    }

    pub(crate) fn try_visit_labeled(
        &self,
        mut f: impl FnMut(RootKind, RootId, ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for slot in &self.entries {
            if let RootSlot::Occupied(entry) = slot {
                if entry.is_active() {
                    if let Some(object) = entry.object() {
                        f(entry.kind, entry.id(), object)?;
                    }
                }
            }
        }
        Ok(())
    }
}
