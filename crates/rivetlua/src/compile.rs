//! SDK source compiler budget 與 runtime `load()` adapter。

use std::error::Error;
use std::sync::Arc;

use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileJob, CompileLimits, CompileProgress,
    CompileSource, compile_with_budget,
};
use rivetlua_core::{IrLimits, LuaProfile, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    AllocationLedger, AllocationTrace, HostLoadAdvance, HostLoadCompiler, HostLoadError,
    HostLoadErrorKind, HostLoadJob, HostLoadJobContext, HostLoadJobDriver, HostLoadProgress,
    HostLoadSource, LedgerSnapshot, LoadBudget, StateAllocator, VmError,
};

use crate::{CompileError, Engine, Module};

const DEFAULT_COMPILE_ALLOCATION_BYTES: usize = 768 * 1024 * 1024;
const ARC_CONTROL_OVERHEAD: usize = 128;

/// 單次 SDK 編譯的總 work 與峰值配置上限。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileBudgetLimits {
    pub max_work: u64,
    pub max_allocation_bytes: usize,
}

impl Default for CompileBudgetLimits {
    fn default() -> Self {
        Self {
            max_work: u64::MAX,
            max_allocation_bytes: DEFAULT_COMPILE_ALLOCATION_BYTES,
        }
    }
}

/// 可重用的 direct-compile 配置 context；每次 compile 會重設 work，並在結束時退回峰值 charge。
pub struct CompileBudget {
    limits: CompileBudgetLimits,
    ledger: AllocationLedger,
}

impl CompileBudget {
    /// 建立帳本；請在處理不可信來源前建立並重用此 context。
    pub fn new(limits: CompileBudgetLimits) -> Self {
        Self {
            limits,
            ledger: AllocationLedger::new(limits.max_allocation_bytes),
        }
    }

    pub const fn limits(&self) -> &CompileBudgetLimits {
        &self.limits
    }

    pub fn allocation_snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    /// 首次讀取會啟用後續配置的詳細診斷；此前不保留 last_attempt/site 歷史。
    pub fn allocation_trace(&self) -> AllocationTrace {
        self.ledger.trace()
    }

    /// 將下一次配置預約設為一次性失敗，供呼叫端驗證錯誤清理與重試。
    pub fn fail_once_at_ordinal(&self, ordinal: u64) {
        self.ledger.fail_once_at_ordinal(ordinal);
    }

    /// 更新後續編譯的配置上限。
    pub fn set_allocation_limit(&mut self, bytes: usize) {
        self.limits.max_allocation_bytes = bytes;
        self.ledger.set_limit(bytes);
    }
}

impl Default for CompileBudget {
    fn default() -> Self {
        Self::new(CompileBudgetLimits::default())
    }
}

/// 可供 `CompileError` 與呼叫端分辨的 budget failure。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileBudgetErrorKind {
    WorkLimitExceeded,
    AllocationLimitExceeded,
    AllocationFailed,
}

impl std::fmt::Display for CompileBudgetErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::WorkLimitExceeded => "編譯 work 額度不足",
            Self::AllocationLimitExceeded => "編譯 peak 配置額度不足",
            Self::AllocationFailed => "編譯配置預約失敗",
        })
    }
}

impl Error for CompileBudgetErrorKind {}

#[derive(Clone, Copy, Debug)]
enum SinkError {
    Budget(CompileBudgetErrorKind),
    Overflow,
}

struct DirectCompileSink<'a> {
    budget: &'a CompileBudget,
    work: u64,
    charged: usize,
}

impl DirectCompileSink<'_> {
    fn charge(&mut self, bytes: usize) -> Result<(), SinkError> {
        let next = self.charged.checked_add(bytes).ok_or(SinkError::Overflow)?;
        if next > self.budget.limits.max_allocation_bytes {
            return Err(SinkError::Budget(
                CompileBudgetErrorKind::AllocationLimitExceeded,
            ));
        }
        let reservation = self
            .budget
            .ledger
            .reserve(bytes)
            .map_err(|error| match error {
                VmError::ArithmeticOverflow => SinkError::Overflow,
                _ => SinkError::Budget(CompileBudgetErrorKind::AllocationFailed),
            })?;
        reservation.commit().map_err(|error| match error {
            VmError::ArithmeticOverflow => SinkError::Overflow,
            _ => SinkError::Budget(CompileBudgetErrorKind::AllocationFailed),
        })?;
        self.charged = next;
        Ok(())
    }
}

impl CompileBudgetSink for DirectCompileSink<'_> {
    type Error = SinkError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        let units = u64::try_from(units).map_err(|_| SinkError::Overflow)?;
        let next = self.work.checked_add(units).ok_or(SinkError::Overflow)?;
        if next > self.budget.limits.max_work {
            return Err(SinkError::Budget(CompileBudgetErrorKind::WorkLimitExceeded));
        }
        self.work = next;
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.charge(bytes)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.charge(bytes)
    }
}

impl Drop for DirectCompileSink<'_> {
    fn drop(&mut self) {
        if self.charged != 0 {
            let _ = self.budget.ledger.refund(self.charged);
        }
    }
}

fn map_direct_error(error: BudgetedCompileError<SinkError>) -> CompileError {
    match error {
        BudgetedCompileError::Budget(SinkError::Budget(kind)) => CompileError::Budget(kind),
        BudgetedCompileError::AllocationFailed => {
            CompileError::Budget(CompileBudgetErrorKind::AllocationFailed)
        }
        BudgetedCompileError::Budget(SinkError::Overflow)
        | BudgetedCompileError::AdmissionOverflow => CompileError::AdmissionOverflow,
        BudgetedCompileError::AdmissionUnderestimated => CompileError::AdmissionUnderestimated,
        BudgetedCompileError::Frontend(error) => CompileError::Diagnostic(error),
        BudgetedCompileError::Ir(error) => CompileError::Ir(error),
        BudgetedCompileError::Bytecode(error) => CompileError::Bytecode(error),
    }
}

impl Engine {
    /// 以可重用、明確限額的 budget 編譯並保留指定 source name。
    pub fn compile_named_with_budget(
        &self,
        source: &[u8],
        chunk_name: &[u8],
        budget: &CompileBudget,
    ) -> Result<Module, CompileError> {
        let mut sink = DirectCompileSink {
            budget,
            work: 0,
            charged: 0,
        };
        let verified = compile_with_budget(
            source,
            chunk_name,
            self.profile,
            &self.compile_limits,
            &self.ir_limits,
            &self.verify_limits,
            &mut sink,
        )
        .map_err(map_direct_error)?;
        sink.spend_work(1).map_err(|error| match error {
            SinkError::Budget(kind) => CompileError::Budget(kind),
            SinkError::Overflow => CompileError::AdmissionOverflow,
        })?;
        sink.claim_module_allocation(ARC_CONTROL_OVERHEAD)
            .map_err(|error| match error {
                SinkError::Budget(kind) => CompileError::Budget(kind),
                SinkError::Overflow => CompileError::AdmissionOverflow,
            })?;
        Ok(Module {
            verified: Arc::new(verified),
        })
    }
}

struct LoadCompileSink<'a, 'b> {
    budget: &'a mut LoadBudget<'b>,
}

struct ReaderCompileSink<'a, 'b, 'c> {
    budget: &'a mut LoadBudget<'b>,
    allocator: StateAllocator,
    recover: &'c mut dyn FnMut(u64) -> Result<bool, VmError>,
}

impl CompileBudgetSink for ReaderCompileSink<'_, '_, '_> {
    type Error = HostLoadError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.budget.spend_work(units)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_temporary(bytes)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_module_allocation(bytes)
    }

    fn state_allocator(&self) -> StateAllocator { self.allocator.clone() }

    fn recover_allocator_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        (self.recover)(before)
            .map_err(|error| self.budget.record_allocator_failure(error))
    }
}

struct ReaderCompileSource<'a> {
    source: &'a mut HostLoadSource,
    allocator: StateAllocator,
    max_source_bytes: usize,
    source_limit_failed: &'a mut bool,
}

impl CompileSource for ReaderCompileSource<'_> {
    type Source = HostLoadSource;

    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, sink: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        let next = self.source.as_ref().len().checked_add(1);
        if next.map_or(true, |next| next > self.max_source_bytes) {
            *self.source_limit_failed = true;
            return Err(BudgetedCompileError::AdmissionOverflow);
        }
        let work = self.source.copy_work(1).map_err(|_| {
            *self.source_limit_failed = true;
            BudgetedCompileError::AdmissionOverflow
        })?;
        sink.spend_work(work).map_err(BudgetedCompileError::Budget)?;
        if self.source.planned_growth(1)
            .map_err(|_| {
                *self.source_limit_failed = true;
                BudgetedCompileError::AdmissionOverflow
            })?.is_some() {
            let before = self.allocator.refusal_count();
            if self.source.reserve_for_append(1).is_err() {
                if !self.allocator.is_lua() || self.allocator.refusal_count() == before
                    || !sink.recover_allocator_refusal(before).map_err(BudgetedCompileError::Budget)?
                    || self.source.reserve_for_append(1).is_err() {
                    return Err(BudgetedCompileError::AllocationFailed);
                }
            }
        }
        self.source.append(&[byte], self.max_source_bytes).map_err(|error| {
            if matches!(error.kind, rivetlua_runtime::RuntimeErrorKind::HostLoadBudget
                | rivetlua_runtime::RuntimeErrorKind::Heap(VmError::ArithmeticOverflow)) {
                *self.source_limit_failed = true;
                BudgetedCompileError::AdmissionOverflow
            } else {
                BudgetedCompileError::AllocationFailed
            }
        })
    }

    fn take_source(&mut self) -> Self::Source { self.source.take_compile_source() }
}

struct EngineReaderJob { compiler: CompileJob }

impl HostLoadJobDriver for EngineReaderJob {
    fn advance(
        &mut self, available: &[u8], eof: bool, chunkname: &[u8],
        context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<HostLoadAdvance, HostLoadError> {
        if !context.source.uses_allocator(&context.allocator) {
            return Err(context.budget.record_allocator_failure(VmError::AllocationFailed));
        }
        let mut source_limit_failed = false;
        let result = {
            let mut source = ReaderCompileSource {
                source: &mut *context.source, allocator: context.allocator.clone(),
                max_source_bytes: context.max_source_bytes,
                source_limit_failed: &mut source_limit_failed,
            };
            let mut sink = ReaderCompileSink {
                budget: &mut *context.budget, allocator: context.allocator.clone(),
                recover: &mut *context.recover,
            };
            self.compiler.advance(available, eof, &mut source, chunkname, &mut sink)
        };
        if source_limit_failed {
            return Err(context.budget.record_source_limit_failure());
        }
        match result {
            Ok(result) => Ok(HostLoadAdvance {
                consumed: result.consumed,
                progress: match result.progress {
                    CompileProgress::NeedInput { minimum_total } => HostLoadProgress::NeedInput { minimum_total },
                    CompileProgress::Complete(module) => HostLoadProgress::Complete(module),
                },
            }),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(BudgetedCompileError::AllocationFailed) =>
                Err(context.budget.record_allocator_failure(
                    context.source.last_failure().unwrap_or(VmError::AllocationFailed))),
            Err(BudgetedCompileError::Frontend(error)) => Err(context.budget.compile_diagnostic(
                chunkname, error.start.line, error.message.as_bytes(),
            )?),
            Err(BudgetedCompileError::Ir(_) | BudgetedCompileError::Bytecode(_)) =>
                Err(host_diagnostic(context.budget, HostLoadErrorKind::Compile,
                    b"source compile failed")?),
            Err(BudgetedCompileError::AdmissionOverflow | BudgetedCompileError::AdmissionUnderestimated) =>
                Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new())),
        }
    }

    fn consumed_total(&self) -> usize { self.compiler.consumed_total() }
}

impl CompileBudgetSink for LoadCompileSink<'_, '_> {
    type Error = HostLoadError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.budget.spend_work(units)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_temporary(bytes)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_module_allocation(bytes)
    }
}

fn host_diagnostic(
    budget: &mut LoadBudget<'_>,
    kind: HostLoadErrorKind,
    message: &[u8],
) -> Result<HostLoadError, HostLoadError> {
    let work = message
        .len()
        .checked_add(1)
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    let capacity_upper = message
        .len()
        .checked_mul(2)
        .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
    budget.spend_work(work)?;
    budget.claim_temporary(capacity_upper)?;
    let mut diagnostic = Vec::new();
    diagnostic
        .try_reserve_exact(message.len())
        .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
    if diagnostic.capacity() > capacity_upper {
        return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
    }
    diagnostic.extend_from_slice(message);
    Ok(HostLoadError::new(kind, diagnostic))
}

impl HostLoadCompiler for Engine {
    fn begin_reader(
        &mut self, context: &mut HostLoadJobContext<'_, '_>,
    ) -> Result<Option<HostLoadJob>, HostLoadError> {
        if context.profile != self.profile {
            return Err(host_diagnostic(context.budget, HostLoadErrorKind::Compile,
                b"compiler profile mismatch")?);
        }
        let compiler = CompileJob::new(self.profile, self.compile_limits,
            self.ir_limits, self.verify_limits);
        HostLoadJob::new(EngineReaderJob { compiler }, context).map(Some)
    }

    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError> {
        if profile != self.profile {
            return Err(host_diagnostic(
                budget,
                HostLoadErrorKind::Compile,
                b"compiler profile mismatch",
            )?);
        }
        match compile_with_budget(
            source,
            chunkname,
            profile,
            &self.compile_limits,
            &self.ir_limits,
            &self.verify_limits,
            &mut LoadCompileSink { budget },
        ) {
            Ok(module) => Ok(module),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(BudgetedCompileError::AllocationFailed) => {
                Err(budget.record_allocator_failure(VmError::AllocationFailed))
            }
            Err(BudgetedCompileError::Frontend(error)) => Err(host_diagnostic(
                budget,
                HostLoadErrorKind::Compile,
                error.message.as_bytes(),
            )?),
            Err(BudgetedCompileError::Ir(_) | BudgetedCompileError::Bytecode(_)) => Err(
                host_diagnostic(budget, HostLoadErrorKind::Compile, b"source compile failed")?,
            ),
            Err(
                BudgetedCompileError::AdmissionOverflow
                | BudgetedCompileError::AdmissionUnderestimated,
            ) => Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new())),
        }
    }
}


