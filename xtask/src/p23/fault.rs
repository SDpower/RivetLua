//! P23 有界故障實驗；只使用 runtime 已公開的注入與宿主能力介面。

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rivetlua_compiler::{CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{
    AbortReason, AllocationFailureKind, CallbackResult, FileOperation, FileReadFormat,
    FileSeekOrigin, HostCloseResult, HostFileLease, HostHandle, HostIo, HostResourceError,
    HostResourceErrorKind, HostServices, LedgerProbe, ResourceBudget, ResourceCapability,
    ResourceLimits, RootKind, RunOutcome, RuntimeErrorKind, Vm, VmError,
};

use super::manifest::{ExperimentManifest, FaultPlan};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FaultPoint {
    pub id: &'static str,
    pub action: &'static str,
}

const POINTS: [FaultPoint; 6] = [
    FaultPoint { id: "FP-ALLOC", action: "fail" },
    FaultPoint { id: "FP-READ", action: "io-error" },
    FaultPoint { id: "FP-WRITE", action: "partial-write" },
    FaultPoint { id: "FP-CALLBACK", action: "throw" },
    FaultPoint { id: "FP-CANCEL", action: "cancel" },
    FaultPoint { id: "FP-ABORT", action: "fuel" },
];

pub(super) fn fault_points() -> &'static [FaultPoint] {
    &POINTS
}

pub(super) fn validate_plan(plan: &FaultPlan) -> Result<(), &'static str> {
    if plan.occurrence == 0 || plan.occurrence > 1_000_000 {
        return Err("E_FAULT_OCCURRENCE");
    }
    if fault_points().iter().any(|point| point.id == plan.point_id && point.action == plan.action) {
        Ok(())
    } else {
        Err("E_FAULT_PLAN")
    }
}

fn scenario_bytes(plan: &FaultPlan, profile: LuaProfile) -> Vec<u8> {
    match plan.point_id.as_str() {
        "FP-ALLOC" => b"p23-fault-v1:Vm::allocate_table".to_vec(),
        "FP-READ" | "FP-WRITE" => {
            let writing = plan.point_id == "FP-WRITE";
            let operation = if writing { "if not f:write('abcd') then return false end" }
                else { "if not f:read(1) then return false end" };
            let source = format!(
                "local f=assert(io.open('mem','{}')); for i=1,{} do {operation} end; return true",
                if writing { "w" } else { "r" }, plan.occurrence,
            );
            if profile == LuaProfile::Lua55 { format!("global io, assert; {source}").into_bytes() }
                else { source.into_bytes() }
        }
        "FP-CALLBACK" | "FP-CANCEL" => {
            let source = if plan.point_id == "FP-CANCEL" {
                format!("for i=1,{} do fault_callback() end; while true do end", plan.occurrence).into_bytes()
            } else {
                source_for(plan, "fault_callback()")
            };
            if profile == LuaProfile::Lua55 {
                [b"global fault_callback; ".as_slice(), source.as_slice()].concat()
            } else { source }
        }
        "FP-ABORT" => b"while true do end".to_vec(),
        _ => Vec::new(),
    }
}

pub(super) fn input_digests(plan: &FaultPlan, profile: &str) -> Result<(String, String), String> {
    validate_plan(plan).map_err(str::to_owned)?;
    let profile_name = profile;
    let profile = match profile {
        "lua55-i64f64" => LuaProfile::Lua55,
        "lua54-i64f64" => LuaProfile::Lua54,
        _ => return Err("E_FAULT_PROFILE".into()),
    };
    let input = format!("p23-fault-v1\0{}\0{}\0{}\0{}", profile_name, plan.point_id, plan.occurrence, plan.action);
    let input_sha = crate::p17::package_sha256_bytes(input.as_bytes()).map_err(|_| "E_FAULT_DIGEST")?;
    let scenario_sha = crate::p17::package_sha256_bytes(&scenario_bytes(plan, profile))
        .map_err(|_| "E_FAULT_DIGEST")?;
    Ok((input_sha, scenario_sha))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FaultCoverage {
    pub point_id: &'static str,
    pub reached: u64,
    pub injected: bool,
    pub cleanup_ok: bool,
    pub accounting_ok: bool,
    pub side_effects: u64,
    pub callbacks: u64,
    pub status: &'static str,
    pub code: &'static str,
}

impl FaultCoverage {
    fn new(point_id: &'static str) -> Self {
        Self {
            point_id,
            reached: 0,
            injected: false,
            cleanup_ok: false,
            accounting_ok: false,
            side_effects: 0,
            callbacks: 0,
            status: "UNREACHED",
            code: "E_FAULT_UNREACHED",
        }
    }

    fn finish(&mut self, expected: bool) {
        (self.status, self.code) = if !self.injected {
            ("UNREACHED", "E_FAULT_UNREACHED")
        } else if !self.cleanup_ok || !self.accounting_ok {
            ("FINDING", "E_FAULT_CLEANUP")
        } else if !expected {
            ("FINDING", "E_FAULT_OUTCOME")
        } else {
            ("PASS", "OK")
        };
    }
}

pub(super) fn run_fault(manifest: &ExperimentManifest) -> Result<FaultCoverage, String> {
    manifest.validate()?;
    if manifest.batch != "P23-B03" {
        return Err("E_FAULT_BATCH".into());
    }
    if super::host_triple() != Some(manifest.target.as_str()) {
        return Err("E_FAULT_HOST_UNSUPPORTED".into());
    }
    if manifest.worker_policy != "Compatibility" {
        return Err("E_FAULT_POLICY_UNSUPPORTED".into());
    }
    let plan = manifest.fault_plan.as_ref().ok_or("E_FAULT_PLAN")?;
    validate_plan(plan).map_err(str::to_owned)?;
    let profile = match manifest.profile.as_str() {
        "lua55-i64f64" => LuaProfile::Lua55,
        "lua54-i64f64" => LuaProfile::Lua54,
        _ => return Err("E_FAULT_PROFILE".into()),
    };
    let (input_sha, scenario_sha) = input_digests(plan, &manifest.profile)?;
    if !input_sha.eq_ignore_ascii_case(&manifest.input_sha256)
        || !scenario_sha.eq_ignore_ascii_case(&manifest.scenario_sha256)
    {
        return Err("E_FAULT_INPUT_DIGEST".into());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(manifest.budget.seconds))
        .ok_or("E_FAULT_BUDGET")?;
    let mut coverage = match plan.point_id.as_str() {
        "FP-ALLOC" => allocation_fault(manifest, profile, plan)?,
        "FP-READ" | "FP-WRITE" => io_fault(manifest, profile, plan)?,
        "FP-CALLBACK" | "FP-CANCEL" => callback_fault(manifest, profile, plan)?,
        "FP-ABORT" => fuel_fault(manifest, profile, plan)?,
        _ => return Err("E_FAULT_PLAN".into()),
    };
    if Instant::now() >= deadline && coverage.status != "FINDING" {
        coverage.status = "LIMIT";
        coverage.code = "E_FAULT_DEADLINE";
    }
    Ok(coverage)
}

fn finish_vm(mut vm: Vm, probe: LedgerProbe, coverage: &mut FaultCoverage, expected: bool) {
    coverage.cleanup_ok = vm.collect().is_ok() && vm.roots().total_count() == 0;
    coverage.accounting_ok = vm.ledger_snapshot().reserved == 0;
    drop(vm);
    let snapshot = probe.snapshot();
    coverage.accounting_ok &= snapshot.reserved == 0 && snapshot.committed == 0;
    coverage.finish(expected);
}

fn allocation_fault(
    manifest: &ExperimentManifest,
    profile: LuaProfile,
    plan: &FaultPlan,
) -> Result<FaultCoverage, String> {
    let mut coverage = FaultCoverage::new("FP-ALLOC");
    let mut vm = Vm::new_with_profile(profile).map_err(|_| "E_FAULT_VM")?;
    let probe = vm.ledger_probe();
    let limit = usize::try_from(manifest.budget.heap_bytes).map_err(|_| "E_FAULT_BUDGET")?;
    vm.set_allocation_limit(limit);
    let first = vm.allocation_trace().next_ordinal;
    let target = first.checked_add(plan.occurrence - 1).ok_or("E_FAULT_OCCURRENCE")?;
    vm.inject_allocation_failure_at(target);
    let mut expected = false;
    for _ in 0..manifest.budget.cases.min(manifest.budget.fuel) {
        let before = vm.ledger_snapshot();
        match vm.allocate_table() {
            Ok(_) => {},
            Err(VmError::InjectedAllocation(attempt)) if attempt.ordinal == target => {
                let after = vm.ledger_snapshot();
                // 自動 GC 可在配置期間回收舊物件；失敗不可淨增加已提交額度。
                expected = after.committed <= before.committed
                    && after.reserved == before.reserved
                    && vm.roots().total_count() == 0;
                break;
            }
            Err(_) => break,
        }
        if vm.allocation_trace().next_ordinal > target {
            break;
        }
    }
    let trace = vm.allocation_trace();
    coverage.reached = trace.next_ordinal.saturating_sub(first);
    coverage.injected = trace.last_failure.is_some_and(|failure| {
        failure.kind == AllocationFailureKind::Injection && failure.attempt.ordinal == target
    });
    finish_vm(vm, probe, &mut coverage, expected);
    Ok(coverage)
}

fn compile_source(profile: LuaProfile, source: &[u8]) -> Result<VerifiedModule, String> {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).map_err(|_| "E_FAULT_SOURCE")?;
    let parsed = parse(&chunk, language, &limits).map_err(|_| "E_FAULT_SOURCE")?;
    let resolved = resolve(&parsed, &chunk, language, &limits).map_err(|_| "E_FAULT_SOURCE")?;
    let ir = lower(&resolved, &IrLimits::default()).map_err(|_| "E_FAULT_SOURCE")?;
    Ok(emit(&ir, &VerifyLimits::default())
        .map_err(|_| "E_FAULT_SOURCE")?
        .verified()
        .clone())
}

fn source_for(plan: &FaultPlan, suffix: &str) -> Vec<u8> {
    format!("for i=1,{} do {suffix} end; return true", plan.occurrence).into_bytes()
}

fn check_source_limit(manifest: &ExperimentManifest, source: &[u8]) -> Result<(), String> {
    if source.len() as u64 > manifest.budget.max_input_bytes {
        Err("E_FAULT_SOURCE_LIMIT".into())
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct IoState {
    attempts: u64,
    injected: bool,
    side_effects: u64,
    active_leases: u64,
}

struct FaultIo {
    state: Rc<RefCell<IoState>>,
    occurrence: u64,
    writing: bool,
}

struct FaultFile {
    state: Rc<RefCell<IoState>>,
    occurrence: u64,
    writing: bool,
}

impl Drop for FaultFile {
    fn drop(&mut self) {
        self.state.borrow_mut().active_leases -= 1;
    }
}

fn io_unsupported() -> HostResourceError {
    HostResourceError::new(HostResourceErrorKind::Unsupported, Vec::new())
}

impl HostIo for FaultIo {
    fn authorize_path(&mut self, path: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if path == b"mem" && mode == if self.writing { b"w" } else { b"r" } {
            Ok(())
        } else {
            Err(HostResourceError::new(HostResourceErrorKind::PathDenied, Vec::new()))
        }
    }

    fn open(&mut self, path: &[u8], mode: &[u8], budget: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        self.authorize_path(path, mode, budget)?;
        budget.claim_retained(std::mem::size_of::<FaultFile>())?;
        self.state.borrow_mut().active_leases += 1;
        Ok(Box::new(FaultFile {
            state: Rc::clone(&self.state),
            occurrence: self.occurrence,
            writing: self.writing,
        }))
    }

    fn stdin(&mut self, _: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> { Err(io_unsupported()) }
    fn stdout(&mut self, _: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> { Err(io_unsupported()) }
    fn stderr(&mut self, _: &mut ResourceBudget<'_>) -> Result<Box<dyn HostFileLease>, HostResourceError> { Err(io_unsupported()) }
}

impl HostFileLease for FaultFile {
    fn authorize(&mut self, _: FileOperation, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }

    fn read(&mut self, format: FileReadFormat, budget: &mut ResourceBudget<'_>) -> Result<Option<Vec<u8>>, HostResourceError> {
        if self.writing || !matches!(format, FileReadFormat::Bytes(1)) { return Err(io_unsupported()); }
        budget.spend_work(1)?;
        let mut state = self.state.borrow_mut();
        state.attempts += 1;
        if state.attempts == self.occurrence {
            budget.claim_temporary(5)?;
            state.injected = true;
            return Err(HostResourceError::io_failure(b"fault".to_vec(), 5));
        }
        budget.claim_temporary(1)?;
        state.side_effects += 1;
        Ok(Some(vec![b'x']))
    }

    fn write(&mut self, bytes: &[u8], budget: &mut ResourceBudget<'_>) -> Result<usize, HostResourceError> {
        if !self.writing { return Err(io_unsupported()); }
        budget.spend_work(bytes.len())?;
        let mut state = self.state.borrow_mut();
        state.attempts += 1;
        if state.attempts == self.occurrence {
            let written = bytes.len().min(2);
            budget.claim_temporary(5)?;
            state.injected = true;
            state.side_effects += written as u64;
            return Err(HostResourceError::write_failure(b"fault".to_vec(), 5, written));
        }
        state.side_effects += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn seek(&mut self, _: FileSeekOrigin, _: i64, _: &mut ResourceBudget<'_>) -> Result<u64, HostResourceError> { Err(io_unsupported()) }
    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> { budget.spend_work(1) }
    fn close(self: Box<Self>, budget: &mut ResourceBudget<'_>) -> Result<HostCloseResult, HostResourceError> {
        budget.spend_work(1)?;
        Ok(HostCloseResult::File)
    }
}

fn io_fault(manifest: &ExperimentManifest, profile: LuaProfile, plan: &FaultPlan) -> Result<FaultCoverage, String> {
    let writing = plan.point_id == "FP-WRITE";
    let mut coverage = FaultCoverage::new(if writing { "FP-WRITE" } else { "FP-READ" });
    if plan.occurrence > manifest.budget.cases { return Ok(coverage); }
    let source = scenario_bytes(plan, profile);
    check_source_limit(manifest, &source)?;
    let module = compile_source(profile, &source)?;
    let state = Rc::new(RefCell::new(IoState::default()));
    let resource = ResourceCapability::deny_all()
        .and_io(FaultIo { state: Rc::clone(&state), occurrence: plan.occurrence, writing })
        .with_limits(ResourceLimits {
            max_work_units: usize::try_from(manifest.budget.fuel).map_err(|_| "E_FAULT_BUDGET")?,
            ..ResourceLimits::default()
        });
    let mut vm = Vm::new_with_services(profile, HostServices::deny_all().and_resource(resource))
        .map_err(|_| "E_FAULT_VM")?;
    let probe = vm.ledger_probe();
    vm.set_allocation_limit(usize::try_from(manifest.budget.heap_bytes).map_err(|_| "E_FAULT_BUDGET")?);
    let env = vm.allocate_table().map_err(|_| "E_FAULT_VM")?;
    let root = vm.add_root(RootKind::Host, env).map_err(|_| "E_FAULT_VM")?;
    vm.install_basic_builtins(env).map_err(|_| "E_FAULT_VM")?;
    vm.install_io_os_builtins(env).map_err(|_| "E_FAULT_VM")?;
    let mut execution = vm.load_with_environment(module, Value::Object(env)).map_err(|_| "E_FAULT_LOAD")?;
    execution.set_fuel(manifest.budget.fuel).map_err(|_| "E_FAULT_BUDGET")?;
    let outcome = execution.run();
    drop(execution);
    let expected = matches!(&outcome, Ok(RunOutcome::Returned(values)) if values.first() == Some(&Value::Boolean(false)));
    drop(outcome);
    vm.remove_root(root).map_err(|_| "E_FAULT_ROOT")?;
    {
        let observed = state.borrow();
        coverage.reached = observed.attempts;
        coverage.injected = observed.injected;
        coverage.side_effects = observed.side_effects;
    }
    let expected = expected && coverage.reached == plan.occurrence
        && coverage.side_effects == if writing { (plan.occurrence - 1) * 4 + 2 } else { plan.occurrence - 1 };
    finish_vm(vm, probe, &mut coverage, expected);
    coverage.cleanup_ok &= state.borrow().active_leases == 0;
    coverage.finish(expected);
    Ok(coverage)
}

fn install_callback(vm: &mut Vm, environment: rivetlua_core::ObjectRef, callback: HostHandle<Value>) -> Result<HostHandle<Value>, String> {
    let name = vm.allocate_byte_string(b"fault_callback").map_err(|_| "E_FAULT_VM")?;
    let key = HostHandle::<Value>::new(vm, name).map_err(|_| "E_FAULT_ROOT")?;
    let function = callback.as_value(vm).map_err(|_| "E_FAULT_ROOT")?;
    vm.raw_set(environment, Value::Object(name), function).map_err(|_| "E_FAULT_VM")?;
    drop(key);
    Ok(callback)
}

fn callback_fault(manifest: &ExperimentManifest, profile: LuaProfile, plan: &FaultPlan) -> Result<FaultCoverage, String> {
    let cancelling = plan.point_id == "FP-CANCEL";
    let mut coverage = FaultCoverage::new(if cancelling { "FP-CANCEL" } else { "FP-CALLBACK" });
    if plan.occurrence > manifest.budget.cases { return Ok(coverage); }
    let source = scenario_bytes(plan, profile);
    check_source_limit(manifest, &source)?;
    let module = compile_source(profile, &source)?;
    let mut vm = Vm::new_with_profile(profile).map_err(|_| "E_FAULT_VM")?;
    let probe = vm.ledger_probe();
    vm.set_allocation_limit(usize::try_from(manifest.budget.heap_bytes).map_err(|_| "E_FAULT_BUDGET")?);
    let env = vm.allocate_table().map_err(|_| "E_FAULT_VM")?;
    let root = vm.add_root(RootKind::Host, env).map_err(|_| "E_FAULT_VM")?;
    vm.install_basic_builtins(env).map_err(|_| "E_FAULT_VM")?;
    let calls = Rc::new(Cell::new(0u64));
    let flag = Arc::new(AtomicBool::new(false));
    let calls_in_callback = Rc::clone(&calls);
    let flag_in_callback = Arc::clone(&flag);
    let occurrence = plan.occurrence;
    let callback = vm.register_callback(&[], Rc::new(move |_, _| {
        let next = calls_in_callback.get() + 1;
        calls_in_callback.set(next);
        if next == occurrence {
            if cancelling {
                flag_in_callback.store(true, Ordering::Release);
                CallbackResult::Return(Vec::new())
            } else {
                CallbackResult::Throw(Value::Integer(1))
            }
        } else {
            CallbackResult::Return(Vec::new())
        }
    })).map_err(|_| "E_FAULT_CALLBACK")?;
    let callback = install_callback(&mut vm, env, callback)?;
    let mut execution = vm.load_with_environment(module, Value::Object(env)).map_err(|_| "E_FAULT_LOAD")?;
    execution.set_fuel(manifest.budget.fuel).map_err(|_| "E_FAULT_BUDGET")?;
    if cancelling {
        execution.set_interrupt_flag(Arc::clone(&flag)).map_err(|_| "E_FAULT_CANCEL")?;
    }
    let outcome = execution.run();
    drop(execution);
    let expected = if cancelling {
        matches!(&outcome, Ok(RunOutcome::LuaError(error)) if error.kind == RuntimeErrorKind::Heap(VmError::Interrupted))
            && !flag.load(Ordering::Acquire)
    } else {
        matches!(&outcome, Ok(RunOutcome::LuaError(_)))
    };
    drop(outcome);
    drop(callback);
    vm.remove_root(root).map_err(|_| "E_FAULT_ROOT")?;
    coverage.reached = calls.get();
    coverage.injected = coverage.reached >= occurrence;
    coverage.callbacks = coverage.reached;
    coverage.side_effects = coverage.reached;
    let expected = expected && coverage.reached == occurrence;
    finish_vm(vm, probe, &mut coverage, expected);
    Ok(coverage)
}

fn fuel_fault(manifest: &ExperimentManifest, profile: LuaProfile, plan: &FaultPlan) -> Result<FaultCoverage, String> {
    let mut coverage = FaultCoverage::new("FP-ABORT");
    if plan.occurrence > manifest.budget.fuel { return Ok(coverage); }
    let source = scenario_bytes(plan, profile);
    check_source_limit(manifest, &source)?;
    let module = compile_source(profile, &source)?;
    let mut vm = Vm::new_with_profile(profile).map_err(|_| "E_FAULT_VM")?;
    let probe = vm.ledger_probe();
    vm.set_allocation_limit(usize::try_from(manifest.budget.heap_bytes).map_err(|_| "E_FAULT_BUDGET")?);
    let mut execution = vm.load(module).map_err(|_| "E_FAULT_LOAD")?;
    execution.set_fuel(plan.occurrence).map_err(|_| "E_FAULT_BUDGET")?;
    let outcome = execution.run();
    let replay = execution.run();
    drop(execution);
    let expected = matches!(&outcome, Ok(RunOutcome::Aborted(AbortReason::FuelExhausted)))
        && matches!(&replay, Err(error) if error.kind == RuntimeErrorKind::TerminalExecution);
    drop(outcome);
    drop(replay);
    coverage.reached = if expected { plan.occurrence } else { 0 };
    coverage.injected = expected;
    finish_vm(vm, probe, &mut coverage, expected);
    Ok(coverage)
}
