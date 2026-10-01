//! P06-4 的 VM 邏輯配置額度與可控失敗點。

use core::cell::Cell;
use core::mem::size_of;
use core::panic::Location;
use std::rc::Rc;

use crate::VmError;

/// 可控的配置、初始化與暫存容器失敗邊界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailPoint {
    SlotReserve,
    ObjectReserve,
    ObjectInitialize,
    StringBytesReserve,
    TableArrayReserve,
    TableHashReserve,
    TableInsert,
    TableArrayGrow,
    TableHashGrow,
    TableRehash,
    RootReserve,
    HostLease,
    ChildReserve,
    MarkReserve,
    WorkReserve,
    RememberedReserve,
    FrameRegistersReserve,
    FrameRootsReserve,
    CallFrameReserve,
    ReturnReserve,
    ClosureCapturesReserve,
    OpenUpvaluesReserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationDomain {
    LuaHeap,
    Host,
}

impl FailPoint {
    const fn domain(self) -> AllocationDomain {
        match self {
            Self::SlotReserve
            | Self::ObjectReserve
            | Self::StringBytesReserve
            | Self::TableArrayReserve
            | Self::TableHashReserve
            | Self::TableArrayGrow
            | Self::TableHashGrow
            | Self::ChildReserve
            | Self::ClosureCapturesReserve => AllocationDomain::LuaHeap,
            _ => AllocationDomain::Host,
        }
    }

    fn domain_at(self, site: AllocationSite) -> AllocationDomain {
        // 執行器中的 captures 與 string_bytes 是短暫 staging Vec；同名
        // failpoint 在 closure/string payload 建構處則屬 Lua heap。
        if (matches!(self, Self::ClosureCapturesReserve) && !site.file.ends_with("closure.rs"))
            || (matches!(self, Self::StringBytesReserve) && !site.file.ends_with("string.rs"))
        {
            AllocationDomain::Host
        } else {
            self.domain()
        }
    }
}

/// 以來源位置辨識配置點；不配置字串或動態集合。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationSite {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}

impl AllocationSite {
    #[track_caller]
    const fn caller() -> Self {
        let location = Location::caller();
        Self {
            file: location.file(),
            line: location.line(),
            column: location.column(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationAttempt {
    pub site: AllocationSite,
    pub ordinal: u64,
    pub domain: AllocationDomain,
    pub bytes: usize,
    pub point: Option<FailPoint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationFailureKind {
    Arithmetic,
    Budget,
    Injection,
    RustReserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationFailure {
    pub attempt: AllocationAttempt,
    pub kind: AllocationFailureKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationTrace {
    pub next_ordinal: u64,
    pub last_attempt: Option<AllocationAttempt>,
    pub last_failure: Option<AllocationFailure>,
}

/// 邏輯額度快照；不將 Rust allocator 呼叫次數或 RSS 當作額度依據。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub limit: usize,
    pub committed: usize,
    pub reserved: usize,
    pub lua_heap_bytes: usize,
    pub host_allocation_bytes: usize,
    pub shared_rss_observation: Option<usize>,
}

#[derive(Clone, Copy)]
struct LedgerState {
    snapshot: LedgerSnapshot,
    fail_once: Option<FailPoint>,
    poisoned: bool,
    lua_reserved: usize,
    host_reserved: usize,
    trace: AllocationTrace,
    fail_at_ordinal: Option<u64>,
}

/// VM 的邏輯配置帳本；保留票據可跨短暫 heap 借用邊界。
#[derive(Clone)]
pub struct AllocationLedger {
    inner: Rc<Cell<LedgerState>>,
}

/// 只讀的 VM 帳本探針，可在 VM 析構後核對計帳基線。
#[derive(Clone)]
pub struct LedgerProbe(AllocationLedger);

impl LedgerProbe {
    pub fn snapshot(&self) -> LedgerSnapshot {
        self.0.snapshot()
    }

    pub fn trace(&self) -> AllocationTrace {
        self.0.trace()
    }
}

impl AllocationLedger {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Rc::new(Cell::new(LedgerState {
                snapshot: LedgerSnapshot {
                    limit,
                    committed: 0,
                    reserved: 0,
                    lua_heap_bytes: 0,
                    host_allocation_bytes: 0,
                    shared_rss_observation: None,
                },
                fail_once: None,
                poisoned: false,
                lua_reserved: 0,
                host_reserved: 0,
                trace: AllocationTrace {
                    next_ordinal: 1,
                    last_attempt: None,
                    last_failure: None,
                },
                fail_at_ordinal: None,
            })),
        }
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        self.inner.get().snapshot
    }

    pub(crate) fn probe(&self) -> LedgerProbe {
        LedgerProbe(self.clone())
    }

    pub fn trace(&self) -> AllocationTrace {
        self.inner.get().trace
    }

    /// 僅接受外部已量測 RSS；不把它用作 Lua 配置額度或 leak 判定。
    pub fn observe_shared_rss(&self, bytes: usize) {
        let mut state = self.inner.get();
        state.snapshot.shared_rss_observation = Some(bytes);
        self.inner.set(state);
    }

    pub fn fail_once_at_ordinal(&self, ordinal: u64) {
        let mut state = self.inner.get();
        state.fail_at_ordinal = Some(ordinal);
        self.inner.set(state);
    }

    #[track_caller]
    fn record_preflight_overflow(&self, domain: AllocationDomain, point: FailPoint) {
        let mut state = self.inner.get();
        let ordinal = state.trace.next_ordinal;
        if let Some(next) = ordinal.checked_add(1) {
            state.trace.next_ordinal = next;
        } else {
            state.poisoned = true;
        }
        let attempt = AllocationAttempt {
            site: AllocationSite::caller(),
            ordinal,
            domain,
            bytes: usize::MAX,
            point: Some(point),
        };
        state.trace.last_attempt = Some(attempt);
        state.trace.last_failure = Some(AllocationFailure {
            attempt,
            kind: AllocationFailureKind::Arithmetic,
        });
        self.inner.set(state);
    }

    fn record_failure(&self, attempt: AllocationAttempt, kind: AllocationFailureKind) {
        let mut state = self.inner.get();
        state.trace.last_failure = Some(AllocationFailure { attempt, kind });
        self.inner.set(state);
    }

    pub(crate) fn poison(&self) {
        let mut state = self.inner.get();
        state.poisoned = true;
        self.inner.set(state);
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

    #[track_caller]
    pub fn reserve(&self, bytes: usize) -> Result<Reservation, VmError> {
        self.reserve_at(bytes, AllocationDomain::Host, None)
    }

    #[track_caller]
    fn reserve_at(
        &self,
        bytes: usize,
        domain: AllocationDomain,
        point: Option<FailPoint>,
    ) -> Result<Reservation, VmError> {
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        let ordinal = state.trace.next_ordinal;
        state.trace.next_ordinal = ordinal.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
        let attempt = AllocationAttempt {
            site: AllocationSite::caller(),
            ordinal,
            domain,
            bytes,
            point,
        };
        state.trace.last_attempt = Some(attempt);
        let outstanding = state
            .snapshot
            .committed
            .checked_add(state.snapshot.reserved);
        let Some(outstanding) = outstanding else {
            state.trace.last_failure = Some(AllocationFailure {
                attempt,
                kind: AllocationFailureKind::Arithmetic,
            });
            self.inner.set(state);
            return Err(VmError::ArithmeticOverflow);
        };
        let total = outstanding.checked_add(bytes);
        let Some(total) = total else {
            state.trace.last_failure = Some(AllocationFailure {
                attempt,
                kind: AllocationFailureKind::Arithmetic,
            });
            self.inner.set(state);
            return Err(VmError::ArithmeticOverflow);
        };
        if total > state.snapshot.limit {
            state.trace.last_failure = Some(AllocationFailure {
                attempt,
                kind: AllocationFailureKind::Budget,
            });
            self.inner.set(state);
            return Err(VmError::AllocationFailed);
        }
        if state.fail_at_ordinal == Some(ordinal) {
            state.fail_at_ordinal = None;
            state.trace.last_failure = Some(AllocationFailure {
                attempt,
                kind: AllocationFailureKind::Injection,
            });
            self.inner.set(state);
            return Err(VmError::InjectedAllocation(attempt));
        }
        state.snapshot.reserved = state
            .snapshot
            .reserved
            .checked_add(bytes)
            .ok_or(VmError::ArithmeticOverflow)?;
        match domain {
            AllocationDomain::LuaHeap => {
                state.lua_reserved = state
                    .lua_reserved
                    .checked_add(bytes)
                    .ok_or(VmError::ArithmeticOverflow)?;
            }
            AllocationDomain::Host => {
                state.host_reserved = state
                    .host_reserved
                    .checked_add(bytes)
                    .ok_or(VmError::ArithmeticOverflow)?;
            }
        }
        self.inner.set(state);
        Ok(Reservation {
            ledger: self.clone(),
            bytes,
            domain,
            attempt,
            active: true,
        })
    }

    pub fn refund(&self, bytes: usize) -> Result<(), VmError> {
        self.refund_domain(bytes, AllocationDomain::Host)
    }

    pub(crate) fn refund_lua(&self, bytes: usize) -> Result<(), VmError> {
        self.refund_domain(bytes, AllocationDomain::LuaHeap)
    }

    fn refund_domain(&self, bytes: usize, domain: AllocationDomain) -> Result<(), VmError> {
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        let committed = state
            .snapshot
            .committed
            .checked_sub(bytes)
            .ok_or(VmError::LedgerInvariant)?;
        let domain_balance = match domain {
            AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes,
            AllocationDomain::Host => state.snapshot.host_allocation_bytes,
        }
        .checked_sub(bytes)
        .ok_or(VmError::LedgerInvariant)?;
        state.snapshot.committed = committed;
        match domain {
            AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes = domain_balance,
            AllocationDomain::Host => state.snapshot.host_allocation_bytes = domain_balance,
        }
        self.inner.set(state);
        Ok(())
    }

    /// Drop 不可回傳錯誤；若內部帳本已損壞，標記後續操作為可檢查失敗。
    pub(crate) fn refund_on_drop(&self, bytes: usize) {
        self.refund_on_drop_domain(bytes, AllocationDomain::Host);
    }

    pub(crate) fn refund_lua_on_drop(&self, bytes: usize) {
        self.refund_on_drop_domain(bytes, AllocationDomain::LuaHeap);
    }

    fn refund_on_drop_domain(&self, bytes: usize, domain: AllocationDomain) {
        let mut state = self.inner.get();
        let domain_balance = match domain {
            AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes,
            AllocationDomain::Host => state.snapshot.host_allocation_bytes,
        };
        match (
            state.snapshot.committed.checked_sub(bytes),
            domain_balance.checked_sub(bytes),
        ) {
            (Some(committed), Some(balance)) if !state.poisoned => {
                state.snapshot.committed = committed;
                match domain {
                    AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes = balance,
                    AllocationDomain::Host => state.snapshot.host_allocation_bytes = balance,
                }
            }
            _ => state.poisoned = true,
        }
        self.inner.set(state);
    }
}

/// 尚未提交的費用在 Drop 時回復，不暴露半提交記帳。
pub struct Reservation {
    ledger: AllocationLedger,
    bytes: usize,
    domain: AllocationDomain,
    attempt: AllocationAttempt,
    active: bool,
}

impl Reservation {
    pub(crate) fn rust_reserve_failure(&self) -> VmError {
        self.ledger
            .record_failure(self.attempt, AllocationFailureKind::RustReserve);
        VmError::AllocationFailed
    }

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
        let domain_reserved = match self.domain {
            AllocationDomain::LuaHeap => &mut state.lua_reserved,
            AllocationDomain::Host => &mut state.host_reserved,
        };
        *domain_reserved = domain_reserved
            .checked_sub(self.bytes)
            .ok_or(VmError::LedgerInvariant)?;
        let domain_committed = match self.domain {
            AllocationDomain::LuaHeap => &mut state.snapshot.lua_heap_bytes,
            AllocationDomain::Host => &mut state.snapshot.host_allocation_bytes,
        };
        *domain_committed = domain_committed
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
                let domain_reserved = match self.domain {
                    AllocationDomain::LuaHeap => &mut state.lua_reserved,
                    AllocationDomain::Host => &mut state.host_reserved,
                };
                if let Some(balance) = domain_reserved.checked_sub(self.bytes) {
                    *domain_reserved = balance;
                } else {
                    state.poisoned = true;
                }
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
#[track_caller]
pub(crate) fn reserve_vec<T>(
    ledger: &AllocationLedger,
    values: &mut Vec<T>,
    additional: usize,
    point: FailPoint,
) -> Result<Reservation, VmError> {
    let domain = point.domain_at(AllocationSite::caller());
    let bytes = match checked_bytes(additional, size_of::<T>()) {
        Ok(bytes) => bytes,
        Err(error) => {
            ledger.record_preflight_overflow(domain, point);
            return Err(error);
        }
    };
    let ticket = ledger.reserve_at(bytes, domain, Some(point))?;
    if let Err(error) = ledger.checkpoint(point) {
        ledger.record_failure(ticket.attempt, AllocationFailureKind::Injection);
        return Err(error);
    }
    values
        .try_reserve_exact(additional)
        .map_err(|_| ticket.rust_reserve_failure())?;
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

    #[test]
    fn p12_6_overflow_reports_caller_site_without_reserving_bytes() {
        let ledger = AllocationLedger::new(usize::MAX);
        let mut values: Vec<u16> = Vec::new();
        assert_eq!(
            reserve_vec(
                &ledger,
                &mut values,
                usize::MAX,
                FailPoint::TableArrayReserve
            )
            .err(),
            Some(VmError::ArithmeticOverflow)
        );
        let attempt = ledger.trace().last_attempt.expect("溢位配置須有 site 診斷");
        assert_eq!(attempt.domain, super::AllocationDomain::LuaHeap);
        assert_eq!(attempt.ordinal, 1);
        assert!(attempt.site.file.ends_with("src/alloc.rs"));
        assert_eq!(ledger.snapshot().reserved, 0);
        assert_eq!(ledger.snapshot().committed, 0);
    }

    #[test]
    fn p12_6_ordinal_injection_keeps_ticket_atomic_and_allows_retry() {
        use super::{AllocationDomain, AllocationFailureKind};

        let ledger = AllocationLedger::new(1024);
        let mut first = Vec::<u8>::new();
        let ticket = reserve_vec(&ledger, &mut first, 5, FailPoint::TableArrayReserve).unwrap();
        first.extend_from_slice(b"hello");
        ticket.commit().unwrap();
        assert_eq!(ledger.snapshot().lua_heap_bytes, 5);
        ledger.fail_once_at_ordinal(2);
        let mut second = Vec::<u8>::new();
        let error = reserve_vec(&ledger, &mut second, 7, FailPoint::TableArrayReserve)
            .err()
            .unwrap();
        let VmError::InjectedAllocation(attempt) = error else {
            panic!("需要含 site/ordinal 的錯誤: {error:?}");
        };
        assert_eq!(attempt.ordinal, 2);
        assert_eq!(attempt.domain, AllocationDomain::LuaHeap);
        assert!(attempt.site.file.ends_with("src/alloc.rs"));
        assert_eq!(
            ledger.trace().last_failure.unwrap().kind,
            AllocationFailureKind::Injection
        );
        assert!(second.is_empty());
        assert_eq!(ledger.snapshot().reserved, 0);
        assert_eq!(ledger.snapshot().lua_heap_bytes, 5);
        let retry = reserve_vec(&ledger, &mut second, 7, FailPoint::TableArrayReserve).unwrap();
        second.extend_from_slice(b"retry!!");
        retry.commit().unwrap();
        assert_eq!(ledger.trace().last_attempt.unwrap().ordinal, 3);
        assert_eq!(ledger.snapshot().lua_heap_bytes, 12);
        ledger.refund_lua(12).unwrap();
        assert_eq!(ledger.snapshot().committed, 0);
    }

    #[test]
    fn p12_6_budget_failure_reports_site_without_charging_either_domain() {
        use super::{AllocationDomain, AllocationFailureKind};

        let ledger = AllocationLedger::new(3);
        let mut bytes = Vec::<u8>::new();
        assert_eq!(
            reserve_vec(&ledger, &mut bytes, 4, FailPoint::TableArrayReserve).err(),
            Some(VmError::AllocationFailed)
        );
        let failure = ledger.trace().last_failure.unwrap();
        assert_eq!(failure.kind, AllocationFailureKind::Budget);
        assert_eq!(failure.attempt.ordinal, 1);
        assert_eq!(failure.attempt.domain, AllocationDomain::LuaHeap);
        assert!(failure.attempt.site.file.ends_with("src/alloc.rs"));
        assert_eq!(ledger.snapshot().lua_heap_bytes, 0);
        assert_eq!(ledger.snapshot().host_allocation_bytes, 0);
        assert_eq!(ledger.snapshot().reserved, 0);
        ledger.set_limit(4);
        let ticket = reserve_vec(&ledger, &mut bytes, 4, FailPoint::TableArrayReserve).unwrap();
        ticket.commit().unwrap();
        assert_eq!(ledger.trace().last_attempt.unwrap().ordinal, 2);
        assert_eq!(ledger.snapshot().lua_heap_bytes, 4);
    }

    #[test]
    fn p12_6_shared_rss_observation_does_not_change_vm_budget() {
        let ledger = AllocationLedger::new(8);
        ledger.observe_shared_rss(1_000_000);
        let ticket = ledger.reserve(8).unwrap();
        ticket.commit().unwrap();
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.shared_rss_observation, Some(1_000_000));
        assert_eq!(snapshot.host_allocation_bytes, 8);
        assert_eq!(snapshot.lua_heap_bytes, 0);
        assert_eq!(snapshot.committed, 8);
        ledger.refund(8).unwrap();
    }
}
