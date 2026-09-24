//! VM 集中持有的六類強參照來源。

use std::cell::Cell;
use std::mem::size_of;
use std::rc::Rc;

use rivetlua_core::{ObjectRef, VmId};

use crate::alloc::{AllocationLedger, FailPoint};
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
}

struct RootEntry {
    id: RootId,
    kind: RootKind,
    object: ObjectRef,
    lease: Option<RootLease>,
    charge: usize,
}

impl RootEntry {
    fn is_active(&self) -> bool {
        self.lease.as_ref().is_none_or(RootLease::is_active)
    }
}

/// 只共享 root 存活與帳面費用，不持有 VM 或 Lua 物件配置。
#[derive(Clone)]
pub(crate) struct RootLease(Rc<RootLeaseState>);

struct RootLeaseState {
    active: Cell<bool>,
    ledger: AllocationLedger,
    charge: usize,
}

impl RootLease {
    fn new(ledger: &AllocationLedger, charge: usize) -> Self {
        Self(Rc::new(RootLeaseState {
            active: Cell::new(true),
            ledger: ledger.clone(),
            charge,
        }))
    }

    pub(crate) fn is_active(&self) -> bool {
        self.0.active.get()
    }

    pub(crate) fn deactivate(&self) {
        if self.0.active.replace(false) {
            // VM 可已析構；此處只改共享帳本的 Cell，不借用 heap 或配置。
            self.0.ledger.refund_on_drop(self.0.charge);
        }
    }
}

/// root 表只由 VM 修改；公開介面供檢視類別與計數。
pub struct RootSet {
    vm: VmId,
    entries: Vec<RootEntry>,
    next_sequence: u64,
}

impl RootSet {
    pub(crate) fn new(vm: VmId) -> Self {
        Self {
            vm,
            entries: Vec::new(),
            next_sequence: 1,
        }
    }

    fn next_id(&self) -> Result<RootId, VmError> {
        self.next_sequence
            .checked_add(1)
            .ok_or(VmError::RootIdExhausted)?;
        Ok(RootId {
            vm: self.vm,
            sequence: self.next_sequence,
        })
    }

    pub(crate) fn add(
        &mut self,
        ledger: &AllocationLedger,
        kind: RootKind,
        object: ObjectRef,
    ) -> Result<RootId, VmError> {
        self.compact();
        let id = self.next_id()?;
        let charge = size_of::<RootEntry>();
        let ticket = ledger.reserve(charge)?;
        ledger.checkpoint(FailPoint::RootReserve)?;
        self.entries
            .try_reserve_exact(1)
            .map_err(|_| VmError::AllocationFailed)?;
        ticket.commit()?;
        self.next_sequence += 1;
        self.entries.push(RootEntry {
            id,
            kind,
            object,
            lease: None,
            charge,
        });
        Ok(id)
    }

    pub(crate) fn add_host(
        &mut self,
        ledger: &AllocationLedger,
        object: ObjectRef,
    ) -> Result<(RootId, RootLease), VmError> {
        self.compact();
        let id = self.next_id()?;
        // Rc token 是宿主 root 元資料，不屬於 Lua 物件圖；額度仍預收其可預期成本。
        let host_cost = size_of::<usize>()
            .checked_mul(2)
            .and_then(|header| header.checked_add(size_of::<RootLeaseState>()))
            .ok_or(VmError::ArithmeticOverflow)?;
        let charge = size_of::<RootEntry>()
            .checked_add(host_cost)
            .ok_or(VmError::ArithmeticOverflow)?;
        let ticket = ledger.reserve(charge)?;
        ledger.checkpoint(FailPoint::RootReserve)?;
        self.entries
            .try_reserve_exact(1)
            .map_err(|_| VmError::AllocationFailed)?;
        ledger.checkpoint(FailPoint::HostLease)?;
        let lease = RootLease::new(ledger, charge);
        ticket.commit()?;
        self.next_sequence += 1;
        self.entries.push(RootEntry {
            id,
            kind: RootKind::Host,
            object,
            lease: Some(lease.clone()),
            charge,
        });
        Ok((id, lease))
    }

    pub(crate) fn remove(
        &mut self,
        ledger: &AllocationLedger,
        id: RootId,
    ) -> Result<ObjectRef, VmError> {
        if id.vm != self.vm {
            return Err(VmError::WrongVm);
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(VmError::StaleRoot)?;
        let was_active = self.entries[index].is_active();
        if let Some(lease) = &self.entries[index].lease {
            // 已釋放的 handle 已退還費用；移除墓碑不再重複退費。
            lease.deactivate();
        } else {
            ledger.refund(self.entries[index].charge)?;
        }
        let entry = self.entries.swap_remove(index);
        if was_active {
            Ok(entry.object)
        } else {
            Err(VmError::StaleRoot)
        }
    }

    pub(crate) fn compact(&mut self) {
        // 停用時已即時退還帳面費用；此處只回收尚留在 Vec 的實體記錄。
        self.entries.retain(RootEntry::is_active);
    }

    pub fn count(&self, kind: RootKind) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.kind == kind && entry.is_active())
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.is_active())
            .count()
    }

    pub fn visit(&self, kind: RootKind, mut f: impl FnMut(ObjectRef)) {
        for entry in &self.entries {
            if entry.kind == kind && entry.is_active() {
                f(entry.object);
            }
        }
    }

    pub(crate) fn try_visit_all(
        &self,
        mut f: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for entry in &self.entries {
            if entry.is_active() {
                f(entry.object)?;
            }
        }
        Ok(())
    }
}
