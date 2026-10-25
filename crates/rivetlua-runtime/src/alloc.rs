//! P06-4 的 VM 邏輯配置額度與可控失敗點。

use crate::rust_alloc::vec::Vec;

use crate::rust_alloc::rc::Rc;
use core::cell::Cell;
use core::mem::size_of;
use core::num::NonZeroUsize;
use core::ops::Deref;
use core::panic::Location;
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{AdmissionToken, LuaBindingRef, SharedBlock, StateAllocator};

use crate::VmError;

/// 可控的配置、初始化與暫存容器失敗邊界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailPoint {
    SlotReserve,
    SlotChargeReserve,
    SlotSpareReserve,
    ObjectReserve,
    ObjectInitialize,
    ModuleConstantsReserve,
    StringBytesReserve,
    ShortStringIndexReserve,
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
            | Self::ShortStringIndexReserve
            | Self::UserdataBytesReserve
            | Self::UserdataUservaluesReserve
            | Self::TableArrayReserve
            | Self::TableHashReserve
            | Self::TableKeyReserve
            | Self::TableArrayGrow
            | Self::TableHashGrow
            | Self::ChildReserve => AllocationDomain::LuaHeap,
            _ => AllocationDomain::Host,
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

/// 宿主對邏輯配置的安全 admission 介面。callback 指標僅由 rivetlua-alloc 管理。
pub trait AllocationAdmission {
    /// 非零要求成功時回傳唯一擁有的 token。
    fn admit(&self, bytes: usize) -> Option<AdmissionToken>;

    /// 釋放先前成功 admission 的 token；呼叫者已先丟棄對應 backing。
    fn release(&self, token: AdmissionToken, bytes: usize);
}

struct InternalAdmission;

impl AllocationAdmission for InternalAdmission {
    fn admit(&self, _bytes: usize) -> Option<AdmissionToken> {
        Some(AdmissionToken::logical(NonZeroUsize::MIN))
    }

    fn release(&self, _token: AdmissionToken, _bytes: usize) {}
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

/// VM 邏輯配置的歷史高水位；不代表 Rust allocator、RSS 或實體 RAM。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationPeaks {
    pub committed: usize,
    pub outstanding: usize,
    pub lua_heap_bytes: usize,
    pub host_allocation_bytes: usize,
}

#[derive(Clone, Copy)]
struct LedgerState {
    snapshot: LedgerSnapshot,
    peaks: AllocationPeaks,
    poisoned: bool,
    lua_reserved: usize,
    host_reserved: usize,
    next_ordinal: u64,
    failure_stamp: Option<(u64, AllocationFailureKind)>,
    diagnostics_enabled: bool,
}

#[derive(Clone, Copy, Default)]
struct DiagnosticState {
    last_attempt: Option<AllocationAttempt>,
    last_failure: Option<AllocationFailure>,
    fail_once: Option<FailPoint>,
    fail_at_ordinal: Option<u64>,
}

struct LedgerInner {
    state: Cell<LedgerState>,
    diagnostics: Cell<DiagnosticState>,
    backing_allocator: StateAllocator,
}

#[derive(Clone)]
enum LedgerControl {
    Host(Rc<LedgerInner>),
    Lua(SharedBlock<LedgerInner>),
}

impl LedgerControl {
    fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Host(left), Self::Host(right)) => Rc::ptr_eq(left, right),
            (Self::Lua(left), Self::Lua(right)) => SharedBlock::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Deref for LedgerControl {
    type Target = LedgerInner;
    fn deref(&self) -> &Self::Target {
        match self { Self::Host(inner) => inner, Self::Lua(inner) => inner }
    }
}

#[derive(Clone)]
enum AdmissionOwner {
    Host(Rc<dyn AllocationAdmission>),
    Lua(LuaBindingRef),
}

impl AdmissionOwner {
    fn admit(&self, bytes: usize) -> Option<AdmissionToken> {
        match self { Self::Host(owner) => owner.admit(bytes), Self::Lua(binding) => binding.admit(bytes) }
    }

    fn release(&self, token: AdmissionToken, bytes: usize) {
        match self { Self::Host(owner) => owner.release(token, bytes), Self::Lua(_) => drop(token) }
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Host(left), Self::Host(right)) => Rc::ptr_eq(left, right),
            (Self::Lua(left), Self::Lua(right)) => left.same_binding(right),
            _ => false,
        }
    }
}

impl LedgerState {
    fn record_peaks(&mut self) -> Result<(), VmError> {
        let outstanding = self
            .snapshot
            .committed
            .checked_add(self.snapshot.reserved)
            .ok_or(VmError::ArithmeticOverflow)?;
        self.peaks.committed = self.peaks.committed.max(self.snapshot.committed);
        self.peaks.outstanding = self.peaks.outstanding.max(outstanding);
        self.peaks.lua_heap_bytes = self.peaks.lua_heap_bytes.max(self.snapshot.lua_heap_bytes);
        self.peaks.host_allocation_bytes = self
            .peaks
            .host_allocation_bytes
            .max(self.snapshot.host_allocation_bytes);
        Ok(())
    }
}

/// VM 的邏輯配置帳本；保留票據可跨短暫 heap 借用邊界。
#[derive(Clone)]
pub struct AllocationLedger {
    inner: LedgerControl,
    admission: AdmissionOwner,
    external_admission: bool,
}

struct PendingAdmission {
    admission: AdmissionOwner,
    token: Option<AdmissionToken>,
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

    pub fn peaks(&self) -> AllocationPeaks {
        self.0.peaks()
    }

    /// 首次請求才啟用詳細追蹤；此前的 last_attempt／last_failure 無歷史資料。
    pub fn trace(&self) -> AllocationTrace {
        self.0.trace()
    }
}

impl AllocationLedger {
    pub fn new(limit: usize) -> Self {
        Self::with_admission_kind(limit, Rc::new(InternalAdmission), false, StateAllocator::Global)
    }

    pub fn with_admission(limit: usize, admission: Rc<dyn AllocationAdmission>) -> Self {
        Self::with_admission_kind(limit, admission, true, StateAllocator::Global)
    }

    pub fn with_admission_and_allocator(
        limit: usize,
        admission: Rc<dyn AllocationAdmission>,
        allocator: StateAllocator,
    ) -> Self {
        Self::with_admission_kind(limit, admission, true, allocator)
    }

    fn with_admission_kind(
        limit: usize,
        admission: Rc<dyn AllocationAdmission>,
        external_admission: bool,
        backing_allocator: StateAllocator,
    ) -> Self {
        Self {
            inner: LedgerControl::Host(Rc::new(LedgerInner {
                state: Cell::new(LedgerState {
                    snapshot: LedgerSnapshot {
                        limit,
                        committed: 0,
                        reserved: 0,
                        lua_heap_bytes: 0,
                        host_allocation_bytes: 0,
                        shared_rss_observation: None,
                    },
                    peaks: AllocationPeaks {
                        committed: 0,
                        outstanding: 0,
                        lua_heap_bytes: 0,
                        host_allocation_bytes: 0,
                    },
                    poisoned: false,
                    lua_reserved: 0,
                    host_reserved: 0,
                    next_ordinal: 1,
                    failure_stamp: None,
                    diagnostics_enabled: false,
                }),
                diagnostics: Cell::new(DiagnosticState::default()),
                backing_allocator,
            })),
            admission: AdmissionOwner::Host(admission),
            external_admission,
        }
    }

    /// C-owned state 的唯一 ledger control backing；尚無 VM 可用時不重試配置。
    pub(crate) fn with_lua_binding(limit: usize, binding: LuaBindingRef)
        -> Result<Self, VmError>
    {
        let allocator = StateAllocator::Lua(binding.clone());
        let pending = allocator.clone().shared_uninit::<LedgerInner>(0)
            .map_err(|_| VmError::AllocationFailed)?;
        let inner = LedgerInner {
            state: Cell::new(LedgerState {
                snapshot: LedgerSnapshot {
                    limit, committed: 0, reserved: 0, lua_heap_bytes: 0,
                    host_allocation_bytes: 0, shared_rss_observation: None,
                },
                peaks: AllocationPeaks {
                    committed: 0, outstanding: 0, lua_heap_bytes: 0,
                    host_allocation_bytes: 0,
                },
                poisoned: false, lua_reserved: 0, host_reserved: 0,
                next_ordinal: 1, failure_stamp: None, diagnostics_enabled: false,
            }),
            diagnostics: Cell::new(DiagnosticState::default()),
            backing_allocator: allocator,
        };
        Ok(Self {
            inner: LedgerControl::Lua(pending.write(inner)),
            admission: AdmissionOwner::Lua(binding),
            external_admission: true,
        })
    }

    pub(crate) fn backing_allocator(&self) -> StateAllocator {
        self.inner.backing_allocator.clone()
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        self.inner.state.get().snapshot
    }

    pub fn peaks(&self) -> AllocationPeaks {
        self.inner.state.get().peaks
    }

    pub(crate) fn probe(&self) -> LedgerProbe {
        LedgerProbe(self.clone())
    }

    /// 從首次請求開始記錄詳細配置；此前的 last_attempt 與 last_failure 無歷史資料。
    pub fn trace(&self) -> AllocationTrace {
        let mut state = self.inner.state.get();
        if !state.diagnostics_enabled {
            state.diagnostics_enabled = true;
            self.inner.state.set(state);
        }
        let diagnostics = self.inner.diagnostics.get();
        AllocationTrace {
            next_ordinal: state.next_ordinal,
            last_attempt: diagnostics.last_attempt,
            last_failure: diagnostics.last_failure,
        }
    }

    /// 只在失敗時變更，供 C API 區分本次 close 是否遇到配置失敗。
    pub fn failure_stamp(&self) -> Option<(u64, AllocationFailureKind)> {
        self.inner.state.get().failure_stamp
    }

    /// 僅接受外部已量測 RSS；不把它用作 Lua 配置額度或 leak 判定。
    pub fn observe_shared_rss(&self, bytes: usize) {
        let mut state = self.inner.state.get();
        state.snapshot.shared_rss_observation = Some(bytes);
        self.inner.state.set(state);
    }

    pub fn fail_once_at_ordinal(&self, ordinal: u64) {
        self.enable_diagnostics();
        let mut diagnostics = self.inner.diagnostics.get();
        diagnostics.fail_at_ordinal = Some(ordinal);
        self.inner.diagnostics.set(diagnostics);
    }

    fn enable_diagnostics(&self) {
        let mut state = self.inner.state.get();
        if !state.diagnostics_enabled {
            state.diagnostics_enabled = true;
            self.inner.state.set(state);
        }
    }

    fn record_failure_in_state(
        &self,
        state: &mut LedgerState,
        ordinal: u64,
        attempt: Option<AllocationAttempt>,
        kind: AllocationFailureKind,
    ) {
        state.failure_stamp = Some((ordinal, kind));
        if let Some(attempt) = attempt {
            let mut diagnostics = self.inner.diagnostics.get();
            diagnostics.last_failure = Some(AllocationFailure { attempt, kind });
            self.inner.diagnostics.set(diagnostics);
        }
    }

    #[track_caller]
    fn record_preflight_overflow(&self, domain: AllocationDomain, point: FailPoint) {
        let mut state = self.inner.state.get();
        let ordinal = state.next_ordinal;
        if let Some(next) = ordinal.checked_add(1) {
            state.next_ordinal = next;
        } else {
            state.poisoned = true;
        }
        let attempt = if state.diagnostics_enabled {
            Some(AllocationAttempt {
                site: AllocationSite::caller(),
                ordinal,
                domain,
                bytes: usize::MAX,
                point: Some(point),
            })
        } else {
            None
        };
        if let Some(attempt) = attempt {
            let mut diagnostics = self.inner.diagnostics.get();
            diagnostics.last_attempt = Some(attempt);
            self.inner.diagnostics.set(diagnostics);
        }
        self.record_failure_in_state(
            &mut state,
            ordinal,
            attempt,
            AllocationFailureKind::Arithmetic,
        );
        self.inner.state.set(state);
    }

    fn record_failure(
        &self,
        ordinal: u64,
        attempt: Option<AllocationAttempt>,
        kind: AllocationFailureKind,
    ) {
        let mut state = self.inner.state.get();
        self.record_failure_in_state(&mut state, ordinal, attempt, kind);
        self.inner.state.set(state);
    }

    #[track_caller]
    fn attempt_enabled_during_admission(
        &self,
        ordinal: u64,
        domain: AllocationDomain,
        bytes: usize,
        point: Option<FailPoint>,
    ) -> AllocationAttempt {
        let attempt = AllocationAttempt {
            site: AllocationSite::caller(),
            ordinal,
            domain,
            bytes,
            point,
        };
        let mut diagnostics = self.inner.diagnostics.get();
        diagnostics.last_attempt = Some(attempt);
        self.inner.diagnostics.set(diagnostics);
        attempt
    }

    pub fn set_limit(&self, limit: usize) {
        let mut state = self.inner.state.get();
        state.snapshot.limit = limit;
        self.inner.state.set(state);
    }

    pub fn fail_once_at(&self, point: FailPoint) {
        self.enable_diagnostics();
        let mut diagnostics = self.inner.diagnostics.get();
        diagnostics.fail_once = Some(point);
        self.inner.diagnostics.set(diagnostics);
    }

    pub(crate) fn checkpoint(&self, point: FailPoint) -> Result<(), VmError> {
        let state = self.inner.state.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        if !state.diagnostics_enabled {
            return Ok(());
        }
        let mut diagnostics = self.inner.diagnostics.get();
        if diagnostics.fail_once == Some(point) {
            diagnostics.fail_once = None;
            self.inner.diagnostics.set(diagnostics);
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
        // Lua allocator 已持有較大的實體 Vec block；超額容量只補帳本，不再請求影子 block。
        let ticket = self.reserve_at_inner(
            bytes,
            AllocationDomain::LuaHeap,
            Some(point),
            !self.inner.backing_allocator.is_lua(),
        )?;
        if let Err(error) = self.checkpoint(point) {
            self.record_failure(ticket.ordinal, ticket.attempt, AllocationFailureKind::Injection);
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
        self.reserve_at_inner(bytes, domain, point, true)
    }

    #[track_caller]
    pub(crate) fn reserve_userdata_vec(
        &self,
        bytes: usize,
        point: FailPoint,
        physical: bool,
    ) -> Result<Reservation, VmError> {
        let ticket = self.reserve_at_inner(bytes, AllocationDomain::LuaHeap, Some(point), !physical)?;
        if let Err(error) = self.checkpoint(point) {
            self.record_failure(ticket.ordinal, ticket.attempt, AllocationFailureKind::Injection);
            return Err(error);
        }
        Ok(ticket)
    }

    #[track_caller]
    pub(crate) fn reserve_host_vec(
        &self,
        bytes: usize,
        point: FailPoint,
        physical: bool,
    ) -> Result<Reservation, VmError> {
        let ticket = self.reserve_at_inner(bytes, AllocationDomain::Host, Some(point), !physical)?;
        if let Err(error) = self.checkpoint(point) {
            self.record_failure(ticket.ordinal, ticket.attempt, AllocationFailureKind::Injection);
            return Err(error);
        }
        Ok(ticket)
    }

    #[track_caller]
    pub(crate) fn reserve_physical_host(&self, bytes: usize) -> Result<Reservation, VmError> {
        self.reserve_at_inner(bytes, AllocationDomain::Host, None, false)
    }

    #[track_caller]
    fn reserve_at_inner(
        &self,
        bytes: usize,
        domain: AllocationDomain,
        point: Option<FailPoint>,
        admit: bool,
    ) -> Result<Reservation, VmError> {
        let mut state = self.inner.state.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        let ordinal = state.next_ordinal;
        state.next_ordinal = ordinal.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
        let mut attempt = if state.diagnostics_enabled {
            Some(AllocationAttempt {
                site: AllocationSite::caller(),
                ordinal,
                domain,
                bytes,
                point,
            })
        } else {
            None
        };
        if let Some(attempt) = attempt {
            let mut diagnostics = self.inner.diagnostics.get();
            diagnostics.last_attempt = Some(attempt);
            self.inner.diagnostics.set(diagnostics);
        }
        let outstanding = state
            .snapshot
            .committed
            .checked_add(state.snapshot.reserved);
        let Some(outstanding) = outstanding else {
            self.record_failure_in_state(
                &mut state,
                ordinal,
                attempt,
                AllocationFailureKind::Arithmetic,
            );
            self.inner.state.set(state);
            return Err(VmError::ArithmeticOverflow);
        };
        let total = outstanding.checked_add(bytes);
        let Some(total) = total else {
            self.record_failure_in_state(
                &mut state,
                ordinal,
                attempt,
                AllocationFailureKind::Arithmetic,
            );
            self.inner.state.set(state);
            return Err(VmError::ArithmeticOverflow);
        };
        if total > state.snapshot.limit {
            self.record_failure_in_state(
                &mut state,
                ordinal,
                attempt,
                AllocationFailureKind::Budget,
            );
            self.inner.state.set(state);
            return Err(VmError::AllocationFailed);
        }
        if state.diagnostics_enabled {
            let mut diagnostics = self.inner.diagnostics.get();
            if diagnostics.fail_at_ordinal == Some(ordinal) {
                diagnostics.fail_at_ordinal = None;
                self.inner.diagnostics.set(diagnostics);
                self.record_failure_in_state(
                    &mut state,
                    ordinal,
                    attempt,
                    AllocationFailureKind::Injection,
                );
                self.inner.state.set(state);
                return Err(VmError::InjectedAllocation(
                    attempt.ok_or(VmError::LedgerInvariant)?,
                ));
            }
        }
        // callback 可在 CAPI 層 fail-closed；先發布狀態，再呼叫它，絕不在
        // admission 拒絕後預留 Rust backing 或修改 committed/reserved。
        self.inner.state.set(state);
        let token = if bytes == 0 || !admit {
            None
        } else {
            match self.admission.admit(bytes) {
                Some(token) => Some(token),
                None => {
                    if attempt.is_none() && self.inner.state.get().diagnostics_enabled {
                        attempt = Some(self.attempt_enabled_during_admission(
                            ordinal, domain, bytes, point,
                        ));
                    }
                    self.record_failure(ordinal, attempt, AllocationFailureKind::Admission);
                    return Err(VmError::AllocationFailed);
                }
            }
        };
        let mut admission = PendingAdmission {
            admission: self.admission.clone(),
            token,
            bytes,
        };
        let mut state = self.inner.state.get();
        if state.poisoned {
            return Err(VmError::LedgerInvariant);
        }
        if attempt.is_none() && state.diagnostics_enabled {
            attempt = Some(self.attempt_enabled_during_admission(ordinal, domain, bytes, point));
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
        state.record_peaks()?;
        self.inner.state.set(state);
        Ok(Reservation {
            ledger: self.clone(),
            bytes,
            domain,
            ordinal,
            attempt,
            token: admission.token.take(),
            active: true,
        })
    }

    pub fn refund(&self, bytes: usize) -> Result<(), VmError> {
        self.refund_domain(bytes, AllocationDomain::Host)
    }

    #[cfg(test)]
    pub(crate) fn refund_lua(&self, bytes: usize) -> Result<(), VmError> {
        self.refund_domain(bytes, AllocationDomain::LuaHeap)
    }

    fn refund_domain(&self, bytes: usize, domain: AllocationDomain) -> Result<(), VmError> {
        let mut state = self.inner.state.get();
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
        self.inner.state.set(state);
        Ok(())
    }

    /// Drop 不可回傳錯誤；若內部帳本已損壞，標記後續操作為可檢查失敗。
    fn refund_on_drop_domain(&self, bytes: usize, domain: AllocationDomain) {
        let mut state = self.inner.state.get();
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
        self.inner.state.set(state);
    }
}

/// 尚未提交的費用在 Drop 時回復，不暴露半提交記帳。
pub struct Reservation {
    ledger: AllocationLedger,
    bytes: usize,
    domain: AllocationDomain,
    ordinal: u64,
    attempt: Option<AllocationAttempt>,
    token: Option<AdmissionToken>,
    active: bool,
}

/// 唯一持有一筆已提交邏輯配置與宿主 token；不得複製。
pub struct AllocationCharge {
    ledger: AllocationLedger,
    bytes: usize,
    domain: AllocationDomain,
    token: Option<AdmissionToken>,
}

/// 同一 Lua 物件的兩塊 backing 共用帳本，各自保存 admission token 與費用。
#[derive(Default)]
struct LuaChargePart {
    bytes: usize,
    token: Option<AdmissionToken>,
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
        debug_assert!(self.ledger.inner.ptr_eq(&charge.ledger.inner));
        debug_assert!(self.ledger.admission.ptr_eq(&charge.ledger.admission));
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

    /// 將原字串 bytes 的 admission 與實體帳款原封移交給共享 owner。
    pub(crate) fn move_first_to(&mut self, owner: &mut Self) -> Result<usize, VmError> {
        if !self.ledger.inner.ptr_eq(&owner.ledger.inner)
            || !self.ledger.admission.ptr_eq(&owner.ledger.admission)
            || owner.first.bytes != 0
        {
            return Err(VmError::LedgerInvariant);
        }
        owner.first = core::mem::take(&mut self.first);
        Ok(owner.first.bytes)
    }

    pub(crate) fn first_bytes(&self) -> usize {
        self.first.bytes
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
/// entries 的實體 backing 使用指定配置器；其容量不另計為 ledger charge，避免自指計費。
pub struct AllocationCharges {
    entries: AllocVec<AllocationCharge, StateAllocator>,
}

impl Default for AllocationCharges {
    fn default() -> Self {
        Self::new()
    }
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
        Self::new_in(StateAllocator::Global)
    }

    #[doc(hidden)]
    pub fn new_in(allocator: StateAllocator) -> Self {
        Self { entries: AllocVec::new_in(allocator) }
    }

    pub(crate) fn allocator(&self) -> &StateAllocator {
        self.entries.allocator()
    }

    pub(crate) fn take_preserving_allocator(&mut self) -> Self {
        Self::replace_empty(self)
    }

    fn replace_empty(&mut self) -> Self {
        let empty = Self::new_in(self.entries.allocator().clone());
        core::mem::replace(self, empty)
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
            .try_reserve(additional)
            .map_err(|_| VmError::AllocationFailed)
    }

    /// 呼叫者已在發布共享狀態前預留 metadata 容量，並確認帳本與 domain 相同。
    pub(crate) fn push_prepared(&mut self, charge: AllocationCharge) {
        debug_assert!(self.entries.len() < self.entries.capacity());
        self.entries.push(charge);
    }

    pub(crate) fn first_bytes(&self) -> Option<usize> {
        self.entries.first().map(AllocationCharge::bytes)
    }

    pub(crate) fn swap_first(&mut self, charge: AllocationCharge) -> Result<AllocationCharge, VmError> {
        let first = self.entries.first_mut().ok_or(VmError::LedgerInvariant)?;
        if !first.ledger.inner.ptr_eq(&charge.ledger.inner)
            || first.domain != charge.domain
        {
            return Err(VmError::LedgerInvariant);
        }
        Ok(core::mem::replace(first, charge))
    }

    pub fn try_push(
        &mut self,
        charge: AllocationCharge,
    ) -> Result<(), (VmError, AllocationCharge)> {
        if !self.entries.allocator().same_binding(&charge.ledger.backing_allocator()) {
            return Err((VmError::LedgerInvariant, charge));
        }
        if let Some(first) = self.entries.first() {
            if !first.ledger.inner.ptr_eq(&charge.ledger.inner)
                || first.domain != charge.domain
            {
                return Err((VmError::LedgerInvariant, charge));
            }
        }
        if self.entries.try_reserve(1).is_err() {
            return Err((VmError::AllocationFailed, charge));
        }
        self.entries.push(charge);
        Ok(())
    }

    pub fn try_absorb(&mut self, other: &mut Self) -> Result<(), VmError> {
        if !self.entries.allocator().same_binding(other.entries.allocator()) {
            return Err(VmError::LedgerInvariant);
        }
        if let (Some(first), Some(next)) = (self.entries.first(), other.entries.first()) {
            if !first.ledger.inner.ptr_eq(&next.ledger.inner) || first.domain != next.domain {
                return Err(VmError::LedgerInvariant);
            }
        }
        self.entries
            .try_reserve(other.entries.len())
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
        let before = ledger.inner.state.get();
        let domain_committed = match domain {
            AllocationDomain::LuaHeap => before.snapshot.lua_heap_bytes,
            AllocationDomain::Host => before.snapshot.host_allocation_bytes,
        };
        let excess = total - actual;
        if before.poisoned || before.snapshot.committed < excess || domain_committed < excess {
            return Err(VmError::LedgerInvariant);
        }
        // 全部來源皆為已配置的實體 backing 時，縮減帳本不應重新呼叫宿主 allocator。
        let token = if self.entries.iter().all(|entry| entry.token.is_none()) {
            None
        } else {
            Some(ledger.admission.admit(actual).ok_or(VmError::AllocationFailed)?)
        };
        let pending = PendingAdmission {
            admission: ledger.admission.clone(),
            token,
            bytes: actual,
        };
        let mut next = Self::new_in(self.entries.allocator().clone());
        next.entries
            .try_reserve_exact(1)
            .map_err(|_| VmError::AllocationFailed)?;
        let state = ledger.inner.state.get();
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
            PreparedNormalization::Equal => return self.take_preserving_allocator(),
            PreparedNormalization::Zero => {
                self.entries.clear();
                return Self::new_in(self.entries.allocator().clone());
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
        let current = partial.ledger.inner.state.get();
        state.peaks = current.peaks;
        state.next_ordinal = current.next_ordinal;
        state.failure_stamp = current.failure_stamp;
        state.diagnostics_enabled = current.diagnostics_enabled;
        state.snapshot.committed -= partial.excess;
        match partial.domain {
            AllocationDomain::LuaHeap => state.snapshot.lua_heap_bytes -= partial.excess,
            AllocationDomain::Host => state.snapshot.host_allocation_bytes -= partial.excess,
        }
        partial.ledger.inner.state.set(state);
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
    pub(crate) fn physical_reserve_failure(&self) -> VmError {
        self.ledger
            .record_failure(self.ordinal, self.attempt, AllocationFailureKind::Admission);
        VmError::AllocationFailed
    }

    pub(crate) fn rust_reserve_failure(&self) -> VmError {
        self.ledger
            .record_failure(self.ordinal, self.attempt, AllocationFailureKind::RustReserve);
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
        self.commit_charge_in_place()
    }

    /// 配對 backing 尚未發布時，失敗者可先釋放實體 storage，再丟棄 reservation。
    pub(crate) fn commit_charge_in_place(&mut self) -> Result<AllocationCharge, VmError> {
        let mut state = self.ledger.inner.state.get();
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
        state.record_peaks()?;
        self.ledger.inner.state.set(state);
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
            let mut state = self.ledger.inner.state.get();
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
            self.ledger.inner.state.set(state);
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
    reserve_vec_in_domain(ledger, values, additional, point, point.domain())
}

/// 同名 failpoint 用於暫存與持久 backing 時，明確指定 Lua heap 計帳。
#[track_caller]
pub(crate) fn reserve_vec_lua<T>(
    ledger: &AllocationLedger,
    values: &mut Vec<T>,
    additional: usize,
    point: FailPoint,
) -> Result<Reservation, VmError> {
    reserve_vec_in_domain(ledger, values, additional, point, AllocationDomain::LuaHeap)
}

#[track_caller]
pub(crate) fn reserve_state_vec_lua<T>(
    ledger: &AllocationLedger,
    values: &mut AllocVec<T, StateAllocator>,
    additional: usize,
    point: FailPoint,
) -> Result<Reservation, VmError> {
    let bytes = match checked_bytes(additional, size_of::<T>()) {
        Ok(bytes) => bytes,
        Err(error) => {
            ledger.record_preflight_overflow(AllocationDomain::LuaHeap, point);
            return Err(error);
        }
    };
    let physical = ledger.inner.backing_allocator.is_lua();
    let ticket = ledger.reserve_userdata_vec(bytes, point, physical)?;
    let before = ledger.inner.backing_allocator.refusal_count();
    values.try_reserve_exact(additional).map_err(|_| {
        if physical && ledger.inner.backing_allocator.refusal_count() != before {
            ticket.physical_reserve_failure()
        } else {
            ticket.rust_reserve_failure()
        }
    })?;
    Ok(ticket)
}

#[track_caller]
pub(crate) fn reserve_state_vec_host<T>(
    ledger: &AllocationLedger,
    values: &mut AllocVec<T, StateAllocator>,
    additional: usize,
    point: FailPoint,
) -> Result<Reservation, VmError> {
    let bytes = match checked_bytes(additional, size_of::<T>()) {
        Ok(bytes) => bytes,
        Err(error) => {
            ledger.record_preflight_overflow(AllocationDomain::Host, point);
            return Err(error);
        }
    };
    let physical = ledger.inner.backing_allocator.is_lua();
    let ticket = ledger.reserve_host_vec(bytes, point, physical)?;
    let before = ledger.inner.backing_allocator.refusal_count();
    values.try_reserve_exact(additional).map_err(|_| {
        if physical && ledger.inner.backing_allocator.refusal_count() != before {
            ticket.physical_reserve_failure()
        } else {
            ticket.rust_reserve_failure()
        }
    })?;
    Ok(ticket)
}

#[track_caller]
fn reserve_vec_in_domain<T>(
    ledger: &AllocationLedger,
    values: &mut Vec<T>,
    additional: usize,
    point: FailPoint,
    domain: AllocationDomain,
) -> Result<Reservation, VmError> {
    let bytes = match checked_bytes(additional, size_of::<T>()) {
        Ok(bytes) => bytes,
        Err(error) => {
            ledger.record_preflight_overflow(domain, point);
            return Err(error);
        }
    };
    let ticket = ledger.reserve_at(bytes, domain, Some(point))?;
    if let Err(error) = ledger.checkpoint(point) {
        ledger.record_failure(ticket.ordinal, ticket.attempt, AllocationFailureKind::Injection);
        return Err(error);
    }
    values
        .try_reserve_exact(additional)
        .map_err(|_| ticket.rust_reserve_failure())?;
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::{
        AllocationDomain, AllocationLedger, AllocationPeaks, FailPoint, checked_bytes, reserve_vec,
    };
    use crate::VmError;

    #[test]
    fn p21_5_logical_peaks_track_only_published_charges() {
        let ledger = AllocationLedger::new(100);
        let zero = AllocationPeaks {
            committed: 0,
            outstanding: 0,
            lua_heap_bytes: 0,
            host_allocation_bytes: 0,
        };
        let probe = ledger.probe();
        assert_eq!(probe.peaks(), zero);
        let abandoned = ledger.reserve(40).unwrap();
        assert_eq!(ledger.peaks().outstanding, 40);
        drop(abandoned);
        assert_eq!(ledger.peaks().outstanding, 40);
        let host = ledger.reserve(60).unwrap().commit_charge().unwrap();
        assert_eq!(ledger.peaks().committed, 60);
        assert_eq!(ledger.peaks().host_allocation_bytes, 60);
        assert_eq!(ledger.peaks().outstanding, 60);
        let before_reject = ledger.peaks();
        assert_eq!(ledger.reserve(41).err(), Some(VmError::AllocationFailed));
        assert_eq!(ledger.peaks(), before_reject);
        drop(host);
        let lua = ledger
            .reserve_at(20, AllocationDomain::LuaHeap, None)
            .unwrap()
            .commit_charge()
            .unwrap();
        assert_eq!(ledger.peaks().lua_heap_bytes, 20);
        drop(lua);
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(ledger.peaks().outstanding, 60);
        assert_eq!(probe.peaks(), ledger.peaks());
    }

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
