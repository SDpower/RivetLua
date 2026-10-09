//! P06-4 的 VM 邏輯配置額度與可控失敗點。

use core::cell::Cell;
use core::mem::size_of;
use core::num::NonZeroUsize;
use core::panic::Location;
use std::rc::Rc;

use crate::VmError;

/// 可控的配置、初始化與暫存容器失敗邊界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailPoint {
    SlotReserve,
    ObjectReserve,
    ObjectInitialize,
    ModuleConstantsReserve,
    StringBytesReserve,
    UserdataBytesReserve,
    UserdataUservaluesReserve,
    TableArrayReserve,
    TableHashReserve,
    TableKeyReserve,
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
            | Self::ModuleConstantsReserve
            | Self::StringBytesReserve
            | Self::UserdataBytesReserve
            | Self::UserdataUservaluesReserve
            | Self::TableArrayReserve
            | Self::TableHashReserve
            | Self::TableKeyReserve
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
    Admission,
    RustReserve,
}

/// 宿主對邏輯配置的安全 admission 介面。實際 FFI 指標只由 CAPI 層解讀。
pub trait AllocationAdmission {
    /// 非零要求成功時回傳唯一、非零且須以相同大小釋放的 token。
    fn admit(&self, bytes: usize) -> Option<NonZeroUsize>;

    /// 釋放先前成功 admission 的 token；呼叫者已先丟棄對應 backing。
    fn release(&self, token: NonZeroUsize, bytes: usize);
}

struct InternalAdmission;

impl AllocationAdmission for InternalAdmission {
    fn admit(&self, _bytes: usize) -> Option<NonZeroUsize> {
        NonZeroUsize::new(1)
    }

    fn release(&self, _token: NonZeroUsize, _bytes: usize) {}
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
    admission: Rc<dyn AllocationAdmission>,
    external_admission: bool,
}

struct PendingAdmission {
    admission: Rc<dyn AllocationAdmission>,
    token: Option<NonZeroUsize>,
    bytes: usize,
}

impl Drop for PendingAdmission {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.admission.release(token, self.bytes);
        }
    }
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
        Self::with_admission_kind(limit, Rc::new(InternalAdmission), false)
    }

    pub fn with_admission(limit: usize, admission: Rc<dyn AllocationAdmission>) -> Self {
        Self::with_admission_kind(limit, admission, true)
    }

    fn with_admission_kind(
        limit: usize,
        admission: Rc<dyn AllocationAdmission>,
        external_admission: bool,
    ) -> Self {
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
            admission,
            external_admission,
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

    /// Rust allocator 若把單元素 Vec 擴為較大容量，額外 backing 仍屬 Lua heap。
    #[track_caller]
    pub(crate) fn reserve_lua_backing_excess(
        &self,
        bytes: usize,
        point: FailPoint,
    ) -> Result<Reservation, VmError> {
        let ticket = self.reserve_at(bytes, AllocationDomain::LuaHeap, Some(point))?;
        if let Err(error) = self.checkpoint(point) {
            self.record_failure(ticket.attempt, AllocationFailureKind::Injection);
            return Err(error);
        }
        Ok(ticket)
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
        // callback 可在 CAPI 層 fail-closed；先發布 trace，再呼叫它，絕不在
        // admission 拒絕後預留 Rust backing 或修改 committed/reserved。
        self.inner.set(state);
        let token = if bytes == 0 {
            None
        } else {
            match self.admission.admit(bytes) {
                Some(token) => Some(token),
                None => {
                    self.record_failure(attempt, AllocationFailureKind::Admission);
                    return Err(VmError::AllocationFailed);
                }
            }
        };
        let mut admission = PendingAdmission {
            admission: Rc::clone(&self.admission),
            token,
            bytes,
        };
        let mut state = self.inner.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
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
            token: admission.token.take(),
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
    token: Option<NonZeroUsize>,
    active: bool,
}

/// 唯一持有一筆已提交邏輯配置與宿主 token；不得複製。
pub struct AllocationCharge {
    ledger: AllocationLedger,
    bytes: usize,
    domain: AllocationDomain,
    token: Option<NonZeroUsize>,
}

/// 同一 Lua 物件的兩塊 backing 共用帳本，各自保存 admission token 與費用。
#[derive(Default)]
struct LuaChargePart {
    bytes: usize,
    token: Option<NonZeroUsize>,
}

pub(crate) struct PairedLuaCharges {
    ledger: AllocationLedger,
    first: LuaChargePart,
    second: LuaChargePart,
}

impl PairedLuaCharges {
    pub(crate) fn new(ledger: AllocationLedger) -> Self {
        Self {
            ledger,
            first: LuaChargePart::default(),
            second: LuaChargePart::default(),
        }
    }

    fn take_part(&self, mut charge: AllocationCharge) -> LuaChargePart {
        debug_assert!(Rc::ptr_eq(&self.ledger.inner, &charge.ledger.inner));
        debug_assert!(Rc::ptr_eq(&self.ledger.admission, &charge.ledger.admission));
        debug_assert_eq!(charge.domain, AllocationDomain::LuaHeap);
        let part = LuaChargePart {
            bytes: core::mem::replace(&mut charge.bytes, 0),
            token: charge.token.take(),
        };
        part
    }

    fn release_part(&self, mut part: LuaChargePart) {
        if let Some(token) = part.token.take() {
            self.ledger.admission.release(token, part.bytes);
        }
        self.ledger
            .refund_on_drop_domain(part.bytes, AllocationDomain::LuaHeap);
    }

    pub(crate) fn replace_first(&mut self, charge: AllocationCharge) {
        let next = self.take_part(charge);
        let old = core::mem::replace(&mut self.first, next);
        self.release_part(old);
    }

    pub(crate) fn replace_second(&mut self, charge: AllocationCharge) {
        let next = self.take_part(charge);
        let old = core::mem::replace(&mut self.second, next);
        self.release_part(old);
    }

    pub(crate) fn clear_second(&mut self) {
        let old = core::mem::take(&mut self.second);
        self.release_part(old);
    }
}

impl Drop for PairedLuaCharges {
    fn drop(&mut self) {
        let first = core::mem::take(&mut self.first);
        let second = core::mem::take(&mut self.second);
        self.release_part(first);
        self.release_part(second);
    }
}

/// 同一 owner 的多筆原始 admission；每筆 token 在合計或移交前保持獨立。
#[derive(Default)]
pub struct AllocationCharges {
    entries: Vec<AllocationCharge>,
}

/// replacement backing 已備妥之後才使用的兩階段 charge 正規化。
pub(crate) enum PreparedNormalization {
    Equal,
    Zero,
    Partial(PreparedPartialNormalization),
}

pub(crate) struct PreparedPartialNormalization {
    actual: usize,
    ledger: AllocationLedger,
    domain: AllocationDomain,
    excess: usize,
    before: LedgerState,
    pending: PendingAdmission,
    next: AllocationCharges,
}

impl AllocationCharges {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_bytes(&self) -> Result<usize, VmError> {
        self.entries.iter().try_fold(0usize, |total, charge| {
            total
                .checked_add(charge.bytes)
                .ok_or(VmError::ArithmeticOverflow)
        })
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), VmError> {
        self.entries
            .try_reserve_exact(additional)
            .map_err(|_| VmError::AllocationFailed)
    }

    /// 呼叫者已在發布共享狀態前預留 metadata 容量，並確認帳本與 domain 相同。
    pub(crate) fn push_prepared(&mut self, charge: AllocationCharge) {
        debug_assert!(self.entries.len() < self.entries.capacity());
        self.entries.push(charge);
    }

    pub fn try_push(
        &mut self,
        charge: AllocationCharge,
    ) -> Result<(), (VmError, AllocationCharge)> {
        if let Some(first) = self.entries.first() {
            if !Rc::ptr_eq(&first.ledger.inner, &charge.ledger.inner)
                || first.domain != charge.domain
            {
                return Err((VmError::LedgerInvariant, charge));
            }
        }
        if self.entries.try_reserve_exact(1).is_err() {
            return Err((VmError::AllocationFailed, charge));
        }
        self.entries.push(charge);
        Ok(())
    }

    pub fn try_absorb(&mut self, other: &mut Self) -> Result<(), VmError> {
        if let (Some(first), Some(next)) = (self.entries.first(), other.entries.first()) {
            if !Rc::ptr_eq(&first.ledger.inner, &next.ledger.inner) || first.domain != next.domain {
                return Err(VmError::LedgerInvariant);
            }
        }
        self.entries
            .try_reserve_exact(other.entries.len())
            .map_err(|_| VmError::AllocationFailed)?;
        self.entries.append(&mut other.entries);
        Ok(())
    }

    /// prepare 只配置新 metadata 與 current-binding token；拒絕時原集合不變。
    pub(crate) fn prepare_normalize(
        &self,
        actual: usize,
    ) -> Result<PreparedNormalization, VmError> {
        let total = self.total_bytes()?;
        if actual > total {
            return Err(VmError::ArithmeticOverflow);
        }
        if actual == total || actual == 0 {
            return Ok(if actual == total {
                PreparedNormalization::Equal
            } else {
                PreparedNormalization::Zero
            });
        }
        let first = self.entries.first().ok_or(VmError::LedgerInvariant)?;
        let ledger = first.ledger.clone();
        let domain = first.domain;
        let before = ledger.inner.get();
        let domain_committed = match domain {
            AllocationDomain::LuaHeap => before.snapshot.lua_heap_bytes,
            AllocationDomain::Host => before.snapshot.host_allocation_bytes,
        };
        let excess = total - actual;
        if before.poisoned || before.snapshot.committed < excess || domain_committed < excess {
            return Err(VmError::LedgerInvariant);
        }
        let token = ledger
            .admission
            .admit(actual)
            .ok_or(VmError::AllocationFailed)?;
        let pending = PendingAdmission {
            admission: Rc::clone(&ledger.admission),
            token: Some(token),
            bytes: actual,
        };
        let mut next = Self::new();
        next.entries
            .try_reserve_exact(1)
            .map_err(|_| VmError::AllocationFailed)?;
        let state = ledger.inner.get();
        if state.poisoned
            || state.snapshot.committed != before.snapshot.committed
            || state.snapshot.reserved != before.snapshot.reserved
            || (match domain {
                AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes,
                AllocationDomain::Host => state.snapshot.host_allocation_bytes,
            }) != domain_committed
        {
            return Err(VmError::LedgerInvariant);
        }
        Ok(PreparedNormalization::Partial(
            PreparedPartialNormalization {
                actual,
                ledger,
                domain,
                excess,
                before,
                pending,
                next,
            },
        ))
    }

    /// 呼叫者先 drop 舊 backing，兩者之間不得執行其他 ledger 動作。
    pub(crate) fn commit_normalize(&mut self, prepared: PreparedNormalization) -> Self {
        let mut partial = match prepared {
            PreparedNormalization::Equal => return core::mem::take(self),
            PreparedNormalization::Zero => {
                self.entries.clear();
                return Self::new();
            }
            PreparedNormalization::Partial(partial) => partial,
        };
        let mut state = partial.before;
        // 此後不再有 fallible 動作；舊 backing 已由 caller 丟棄。
        for charge in &mut self.entries {
            if let Some(old) = charge.token.take() {
                partial.ledger.admission.release(old, charge.bytes);
            }
            charge.bytes = 0;
        }
        self.entries.clear();
        state.snapshot.committed -= partial.excess;
        match partial.domain {
            AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes -= partial.excess,
            AllocationDomain::Host => state.snapshot.host_allocation_bytes -= partial.excess,
        }
        partial.ledger.inner.set(state);
        partial.next.entries.push(AllocationCharge {
            ledger: partial.ledger,
            bytes: partial.actual,
            domain: partial.domain,
            token: partial.pending.token.take(),
        });
        partial.next
    }

    /// 同一 backing 仍由 caller 持有時只可用於 ledger-only 正規化。
    pub fn normalize(&mut self, actual: usize) -> Result<Self, VmError> {
        let prepared = self.prepare_normalize(actual)?;
        Ok(self.commit_normalize(prepared))
    }
}

impl AllocationCharge {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// 僅供舊帳本入口在未綁定宿主 allocator 時遞移使用。
    fn detach_internal(mut self) {
        self.token = None;
        self.bytes = 0;
    }
}

impl Drop for AllocationCharge {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.ledger.admission.release(token, self.bytes);
        }
        self.ledger.refund_on_drop_domain(self.bytes, self.domain);
    }
}

impl Reservation {
    pub(crate) fn rust_reserve_failure(&self) -> VmError {
        self.ledger
            .record_failure(self.attempt, AllocationFailureKind::RustReserve);
        VmError::AllocationFailed
    }

    pub fn commit(self) -> Result<(), VmError> {
        if self.ledger.external_admission {
            return Err(VmError::LedgerInvariant);
        }
        self.commit_charge()?.detach_internal();
        Ok(())
    }

    pub fn commit_charge(mut self) -> Result<AllocationCharge, VmError> {
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
        Ok(AllocationCharge {
            ledger: self.ledger.clone(),
            bytes: self.bytes,
            domain: self.domain,
            token: self.token.take(),
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            if let Some(token) = self.token.take() {
                self.ledger.admission.release(token, self.bytes);
            }
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

    #[test]
    fn p16_a50_admission_rejection_and_owned_charge_release() {
        use core::cell::Cell;
        use core::num::NonZeroUsize;
        use std::rc::Rc;

        use super::{AllocationAdmission, AllocationFailureKind};

        struct Admission {
            reject: Cell<bool>,
            calls: Cell<usize>,
            releases: Cell<usize>,
        }

        impl AllocationAdmission for Admission {
            fn admit(&self, _bytes: usize) -> Option<NonZeroUsize> {
                self.calls.set(self.calls.get() + 1);
                if self.reject.replace(false) {
                    None
                } else {
                    NonZeroUsize::new(self.calls.get())
                }
            }

            fn release(&self, _token: NonZeroUsize, _bytes: usize) {
                self.releases.set(self.releases.get() + 1);
            }
        }

        let admission = Rc::new(Admission {
            reject: Cell::new(true),
            calls: Cell::new(0),
            releases: Cell::new(0),
        });
        let ledger = AllocationLedger::with_admission(100, admission.clone());
        let mut values = Vec::<u8>::new();
        assert_eq!(
            reserve_vec(&ledger, &mut values, 8, FailPoint::WorkReserve).err(),
            Some(VmError::AllocationFailed),
        );
        assert_eq!(values.capacity(), 0);
        assert_eq!(ledger.snapshot().reserved, 0);
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(
            ledger.trace().last_failure.unwrap().kind,
            AllocationFailureKind::Admission,
        );

        let zero = ledger.reserve(0).unwrap().commit_charge().unwrap();
        assert_eq!(admission.calls.get(), 1);
        drop(zero);
        assert_eq!(admission.releases.get(), 0);

        let ticket = reserve_vec(&ledger, &mut values, 8, FailPoint::WorkReserve).unwrap();
        values.extend_from_slice(b"12345678");
        let charge = ticket.commit_charge().unwrap();
        assert_eq!(ledger.snapshot().committed, 8);
        drop(values);
        drop(charge);
        assert_eq!(admission.calls.get(), 2);
        assert_eq!(admission.releases.get(), 1);
        assert_eq!(ledger.snapshot().committed, 0);
    }

    #[test]
    fn p16_a50_charge_collection_normalizes_zero_equal_partial_and_rejection() {
        use core::cell::{Cell, RefCell};
        use core::num::NonZeroUsize;
        use std::rc::Rc;

        use super::{AllocationAdmission, AllocationCharges};

        struct Admission {
            next: Cell<usize>,
            reject: Cell<bool>,
            releases: RefCell<Vec<(usize, usize)>>,
        }

        impl AllocationAdmission for Admission {
            fn admit(&self, _bytes: usize) -> Option<NonZeroUsize> {
                if self.reject.replace(false) {
                    return None;
                }
                let next = self.next.get() + 1;
                self.next.set(next);
                NonZeroUsize::new(next)
            }

            fn release(&self, token: NonZeroUsize, bytes: usize) {
                self.releases.borrow_mut().push((token.get(), bytes));
            }
        }

        for actual in [0, 10, 7] {
            let admission = Rc::new(Admission {
                next: Cell::new(0),
                reject: Cell::new(false),
                releases: RefCell::new(Vec::new()),
            });
            let ledger = AllocationLedger::with_admission(100, admission.clone());
            let mut charges = AllocationCharges::new();
            charges
                .try_push(ledger.reserve(4).unwrap().commit_charge().unwrap())
                .unwrap_or_else(|_| panic!("charge collection 可預留第一筆"));
            charges
                .try_push(ledger.reserve(6).unwrap().commit_charge().unwrap())
                .unwrap_or_else(|_| panic!("charge collection 可預留第二筆"));
            assert_eq!(charges.total_bytes(), Ok(10));
            let normalized = charges.normalize(actual).unwrap();
            assert_eq!(charges.total_bytes(), Ok(0));
            assert_eq!(normalized.total_bytes(), Ok(actual));
            assert_eq!(ledger.snapshot().committed, actual);
            assert_eq!(admission.next.get(), if actual == 7 { 3 } else { 2 },);
            assert_eq!(
                admission.releases.borrow().len(),
                if actual == 10 { 0 } else { 2 },
            );
            drop(normalized);
            assert_eq!(ledger.snapshot().committed, 0);
            assert_eq!(
                admission.releases.borrow().len(),
                if actual == 7 { 3 } else { 2 }
            );
        }

        let admission = Rc::new(Admission {
            next: Cell::new(0),
            reject: Cell::new(false),
            releases: RefCell::new(Vec::new()),
        });
        let ledger = AllocationLedger::with_admission(100, admission.clone());
        let mut charges = AllocationCharges::new();
        charges
            .try_push(ledger.reserve(4).unwrap().commit_charge().unwrap())
            .unwrap_or_else(|_| panic!("charge collection 可預留第一筆"));
        charges
            .try_push(ledger.reserve(6).unwrap().commit_charge().unwrap())
            .unwrap_or_else(|_| panic!("charge collection 可預留第二筆"));
        admission.reject.set(true);
        assert_eq!(charges.normalize(7).err(), Some(VmError::AllocationFailed));
        assert_eq!(charges.total_bytes(), Ok(10));
        assert_eq!(ledger.snapshot().committed, 10);
        assert!(admission.releases.borrow().is_empty());
        drop(charges);
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(admission.releases.borrow().len(), 2);
    }
}
