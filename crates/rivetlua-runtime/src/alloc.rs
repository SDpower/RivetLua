//! P06-4 的 VM 邏輯配置額度與可控失敗點。

use core::cell::Cell;
use core::mem::size_of;
use std::rc::Rc;

use crate::VmError;

/// 可控的配置、初始化與暫存容器失敗邊界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailPoint {
    SlotReserve,
    ObjectReserve,
    ObjectInitialize,
    RootReserve,
    HostLease,
    ChildReserve,
    MarkReserve,
    WorkReserve,
    FrameRegistersReserve,
    FrameRootsReserve,
    ReturnReserve,
}

/// 邏輯額度快照；不將 Rust allocator 呼叫次數或 RSS 當作額度依據。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub limit: usize,
    pub committed: usize,
    pub reserved: usize,
}

#[derive(Clone, Copy)]
struct LedgerState {
    snapshot: LedgerSnapshot,
    fail_once: Option<FailPoint>,
    poisoned: bool,
}

/// VM 的邏輯配置帳本；保留票據可跨短暫 heap 借用邊界。
#[derive(Clone)]
pub struct AllocationLedger {
    inner: Rc<Cell<LedgerState>>,
}

impl AllocationLedger {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Rc::new(Cell::new(LedgerState {
                snapshot: LedgerSnapshot {
                    limit,
                    committed: 0,
                    reserved: 0,
                },
                fail_once: None,
                poisoned: false,
            })),
        }
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        self.inner.get().snapshot
    }

    pub fn set_limit(&self, limit: usize) {
        let mut state = self.inner.get();
        state.snapshot.limit = limit;
        self.inner.set(state);
    }

    pub fn fail_once_at(&self, point: FailPoint) {
        let mut state = self.inner.get();
        state.fail_once = Some(point);
        self.inner.set(state);
    }

    pub(crate) fn checkpoint(&self, point: FailPoint) -> Result<(), VmError> {
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        if state.fail_once == Some(point) {
            state.fail_once = None;
            self.inner.set(state);
            return Err(VmError::InjectedFailure(point));
        }
        Ok(())
    }

    pub fn reserve(&self, bytes: usize) -> Result<Reservation, VmError> {
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        let outstanding = state
            .snapshot
            .committed
            .checked_add(state.snapshot.reserved)
            .ok_or(VmError::ArithmeticOverflow)?;
        let total = outstanding
            .checked_add(bytes)
            .ok_or(VmError::ArithmeticOverflow)?;
        if total > state.snapshot.limit {
            return Err(VmError::AllocationFailed);
        }
        state.snapshot.reserved = state
            .snapshot
            .reserved
            .checked_add(bytes)
            .ok_or(VmError::ArithmeticOverflow)?;
        self.inner.set(state);
        Ok(Reservation {
            ledger: self.clone(),
            bytes,
            active: true,
        })
    }

    pub fn refund(&self, bytes: usize) -> Result<(), VmError> {
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        state.snapshot.committed = state
            .snapshot
            .committed
            .checked_sub(bytes)
            .ok_or(VmError::LedgerInvariant)?;
        self.inner.set(state);
        Ok(())
    }

    /// Drop 不可回傳錯誤；若內部帳本已損壞，標記後續操作為可檢查失敗。
    pub(crate) fn refund_on_drop(&self, bytes: usize) {
        let mut state = self.inner.get();
        match state.snapshot.committed.checked_sub(bytes) {
            Some(committed) if !state.poisoned => state.snapshot.committed = committed,
            _ => state.poisoned = true,
        }
        self.inner.set(state);
    }
}

/// 尚未提交的費用在 Drop 時回復，不暴露半提交記帳。
pub struct Reservation {
    ledger: AllocationLedger,
    bytes: usize,
    active: bool,
}

impl Reservation {
    pub fn commit(mut self) -> Result<(), VmError> {
        let mut state = self.ledger.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        let reserved = state
            .snapshot
            .reserved
            .checked_sub(self.bytes)
            .ok_or(VmError::LedgerInvariant)?;
        let committed = state
            .snapshot
            .committed
            .checked_add(self.bytes)
            .ok_or(VmError::ArithmeticOverflow)?;
        state.snapshot.reserved = reserved;
        state.snapshot.committed = committed;
        self.ledger.inner.set(state);
        self.active = false;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.ledger.inner.get();
            if let Some(reserved) = state.snapshot.reserved.checked_sub(self.bytes) {
                state.snapshot.reserved = reserved;
            } else {
                state.poisoned = true;
            }
            self.ledger.inner.set(state);
        }
    }
}

pub(crate) fn checked_bytes(count: usize, size: usize) -> Result<usize, VmError> {
    count.checked_mul(size).ok_or(VmError::ArithmeticOverflow)
}

/// 受限的穩定 Rust 可失敗預留入口；票據由呼叫者於提交後 commit。
pub(crate) fn reserve_vec<T>(
    ledger: &AllocationLedger,
    values: &mut Vec<T>,
    additional: usize,
    point: FailPoint,
) -> Result<Reservation, VmError> {
    let bytes = checked_bytes(additional, size_of::<T>())?;
    let ticket = ledger.reserve(bytes)?;
    ledger.checkpoint(point)?;
    values
        .try_reserve_exact(additional)
        .map_err(|_| VmError::AllocationFailed)?;
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::{AllocationLedger, FailPoint, checked_bytes, reserve_vec};
    use crate::VmError;

    #[test]
    fn ledger_reserve_commit_rollback_and_refund_are_balanced() {
        let ledger = AllocationLedger::new(100);
        let first = ledger.reserve(40).unwrap();
        assert_eq!(ledger.snapshot().reserved, 40);
        assert_eq!(ledger.snapshot().committed, 0);
        drop(first);
        assert_eq!(ledger.snapshot().reserved, 0);
        let second = ledger.reserve(60).unwrap();
        second.commit().unwrap();
        assert_eq!(ledger.snapshot().committed, 60);
        assert_eq!(ledger.reserve(41).err(), Some(VmError::AllocationFailed));
        ledger.refund(60).unwrap();
        assert_eq!(ledger.snapshot().committed, 0);
    }

    #[test]
    fn ledger_rejects_arithmetic_overflow_and_actual_vec_reserve_failure() {
        assert_eq!(
            checked_bytes(usize::MAX, 2),
            Err(VmError::ArithmeticOverflow)
        );
        let ledger = AllocationLedger::new(usize::MAX);
        let held = ledger.reserve(usize::MAX).unwrap();
        assert_eq!(ledger.reserve(1).err(), Some(VmError::ArithmeticOverflow));
        drop(held);
        let mut values: Vec<u8> = Vec::new();
        assert_eq!(
            reserve_vec(&ledger, &mut values, usize::MAX, FailPoint::WorkReserve).err(),
            Some(VmError::AllocationFailed)
        );
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(ledger.snapshot().reserved, 0);
        assert!(values.is_empty());
    }
}
