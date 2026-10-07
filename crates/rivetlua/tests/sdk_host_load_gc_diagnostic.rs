use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rivetlua::{
    HostLoadError, HostLoadErrorKind, HostServices, HostSourceReader, LoadBudget, LoadCapability,
    LoadLimits, LuaProfile, RunOutcome,
};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{IrLimits, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostLoadCompiler, ObjectKind, RootKind, RuntimeErrorKind, Vm};

// RAW v13 固定 CLI 基線；下方 2Gi/256Mi/4b 是後續候選校準值，本檔不修改產品政策。
const RAW_V13_FUEL: u64 = 1_000_000_000;
const ISOLATION_FUEL: u64 = 4_000_000_000;
const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;

fn raw_v13_limits() -> LoadLimits {
    LoadLimits {
        max_source_bytes: 4 * MIB,
        max_encoded_bytes: 64 * MIB,
        max_module_allocation_bytes: 64 * MIB,
        max_temporary_bytes: 128 * MIB,
        max_work_units: 256 * MIB,
        max_reader_chunks: 512,
        max_path_candidates: 512,
    }
}

fn candidate_cli_limits() -> LoadLimits {
    LoadLimits {
        max_work_units: 2 * GIB,
        max_temporary_bytes: 256 * MIB,
        ..raw_v13_limits()
    }
}

struct Case {
    label: &'static str,
    profile: LuaProfile,
    path: PathBuf,
    guest_path: &'static [u8],
    expected_chunkname: &'static [u8],
    control: Option<LoadLimits>,
}

fn cases() -> Vec<Case> {
    let raw = PathBuf::from(
        std::env::var_os("RIVETLUA_RAW_V13_DIR")
            .expect("RIVETLUA_RAW_V13_DIR 須指向唯讀 RAW v13 目錄"),
    );
    let lua54 =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/lua54/lua-5.4.9-tests/gc.lua");
    vec![
        Case {
            label: "55-full-gc",
            profile: LuaProfile::Lua55,
            path: raw.join("lua-5.5.1-tests/gc.lua"),
            guest_path: b"gc.lua",
            expected_chunkname: b"@gc.lua",
            control: Some(LoadLimits {
                max_work_units: 2 * GIB,
                max_temporary_bytes: 512 * MIB,
                ..raw_v13_limits()
            }),
        },
        Case {
            label: "55-prefix-395",
            profile: LuaProfile::Lua55,
            path: raw.join("repro/gc_prefix_395.lua"),
            guest_path: b"gc_prefix_395.lua",
            expected_chunkname: b"@gc_prefix_395.lua",
            control: Some(LoadLimits {
                max_work_units: GIB,
                ..raw_v13_limits()
            }),
        },
        Case {
            label: "55-prefix-350",
            profile: LuaProfile::Lua55,
            path: raw.join("repro/gc_prefix_350.lua"),
            guest_path: b"gc_prefix_350.lua",
            expected_chunkname: b"@gc_prefix_350.lua",
            control: None,
        },
        Case {
            label: "54-full-gc",
            profile: LuaProfile::Lua54,
            path: lua54,
            guest_path: b"gc.lua",
            expected_chunkname: b"@gc.lua",
            control: Some(LoadLimits {
                max_work_units: 2 * GIB,
                ..raw_v13_limits()
            }),
        },
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dimension {
    Work,
    Temporary,
    Module,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    dimension: Dimension,
    request: usize,
    spent_before: usize,
    accepted: bool,
}

#[derive(Debug)]
struct CompileTrace {
    source: Vec<u8>,
    chunkname: Vec<u8>,
    profile: LuaProfile,
    spent: [usize; 3],
    claims: Vec<Claim>,
    outcome: &'static str,
}

impl CompileTrace {
    fn new(source: &[u8], chunkname: &[u8], profile: LuaProfile) -> Self {
        Self {
            source: source.to_vec(),
            chunkname: chunkname.to_vec(),
            profile,
            spent: [0; 3],
            claims: Vec::new(),
            outcome: "pending",
        }
    }
}

struct RecordingCompiler {
    traces: Arc<Mutex<Vec<CompileTrace>>>,
}

struct RecordingSink<'a, 'b, 'c> {
    budget: &'a mut LoadBudget<'b>,
    trace: &'c mut CompileTrace,
}

impl RecordingSink<'_, '_, '_> {
    fn claim(&mut self, dimension: Dimension, request: usize) -> Result<(), HostLoadError> {
        let slot = match dimension {
            Dimension::Work => 0,
            Dimension::Temporary => 1,
            Dimension::Module => 2,
        };
        let spent_before = self.trace.spent[slot];
        let result = match dimension {
            Dimension::Work => self.budget.spend_work(request),
            Dimension::Temporary => self.budget.claim_temporary(request),
            Dimension::Module => self.budget.claim_module_allocation(request),
        };
        self.trace.claims.push(Claim {
            dimension,
            request,
            spent_before,
            accepted: result.is_ok(),
        });
        if result.is_ok() {
            self.trace.spent[slot] += request;
        }
        result
    }
}

impl CompileBudgetSink for RecordingSink<'_, '_, '_> {
    type Error = HostLoadError;
    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Work, units)
    }
    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Temporary, bytes)
    }
    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Module, bytes)
    }
}

impl HostLoadCompiler for RecordingCompiler {
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError> {
        let mut trace = CompileTrace::new(source, chunkname, profile);
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let result = compile_with_budget(
            source,
            chunkname,
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut RecordingSink {
                budget,
                trace: &mut trace,
            },
        );
        let result = match result {
            Ok(module) => {
                trace.outcome = "compiled";
                Ok(module)
            }
            Err(BudgetedCompileError::Budget(error)) => {
                trace.outcome = "budget";
                Err(error)
            }
            Err(other) => {
                eprintln!("SDK compiler unexpected: {other:?}");
                trace.outcome = "unexpected-compile";
                Err(HostLoadError::new(HostLoadErrorKind::Compile, Vec::new()))
            }
        };
        self.traces.lock().unwrap().push(trace);
        result
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReadTrace {
    calls: usize,
    work: usize,
    temporary: usize,
    work_accepted: bool,
    temporary_accepted: bool,
}

struct Reader {
    source: Vec<u8>,
    guest_path: Vec<u8>,
    trace: Arc<Mutex<ReadTrace>>,
}

impl HostSourceReader for Reader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, self.guest_path);
        // 此測試 reader 的預付為 len+1 work / len temp；CLI FsSourceReader
        // 另含路徑、metadata、分段讀取與預處理，不能將此序列冒稱 RAW per-claim。
        let mut trace = self.trace.lock().unwrap();
        trace.calls += 1;
        trace.work = self.source.len() + 1;
        trace.temporary = self.source.len();
        let work = budget.spend_work(trace.work);
        trace.work_accepted = work.is_ok();
        work?;
        let temporary = budget.claim_temporary(trace.temporary);
        trace.temporary_accepted = temporary.is_ok();
        temporary?;
        drop(trace);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.source.len())
            .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
        if bytes.capacity() > self.source.len() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        bytes.extend_from_slice(&self.source);
        Ok(bytes)
    }

    fn read_stdin(&mut self, _: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        Err(HostLoadError::new(
            HostLoadErrorKind::PolicyDenied,
            Vec::new(),
        ))
    }
}

struct FiniteRunnerSink {
    spent: [usize; 3],
}

impl CompileBudgetSink for FiniteRunnerSink {
    type Error = ();

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        let next = self.spent[0].checked_add(units).ok_or(())?;
        if next > 256 * MIB {
            return Err(());
        }
        self.spent[0] = next;
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let next = self.spent[1].checked_add(bytes).ok_or(())?;
        if next > 128 * MIB {
            return Err(());
        }
        self.spent[1] = next;
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let next = self.spent[2].checked_add(bytes).ok_or(())?;
        if next > 64 * MIB {
            return Err(());
        }
        self.spent[2] = next;
        Ok(())
    }
}

fn runner(source: &[u8], profile: LuaProfile) -> VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    compile_with_budget(
        source,
        b"=sdk-gc-diagnostic-runner",
        language,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut FiniteRunnerSink { spent: [0; 3] },
    )
    .unwrap()
}

fn core_vm(profile: LuaProfile, services: HostServices) -> (Vm, rivetlua_core::ObjectRef) {
    let mut vm = Vm::new_with_services(profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_string_builtins(environment).unwrap();
    vm.install_table_builtins(environment).unwrap();
    vm.install_math_builtins(environment).unwrap();
    vm.install_utf8_builtins(environment).unwrap();
    vm.install_package_builtins(environment).unwrap();
    vm.install_io_os_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    (vm, environment)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observed {
    Function,
    HostLoadBudget,
    FuelExhausted,
    Other,
}

fn run(case: &Case, limits: LoadLimits, fuel: u64, scenario: &str) -> Observed {
    let source = std::fs::read(&case.path).unwrap();
    run_source(case, &source, limits, fuel, scenario).0
}

fn run_source(
    case: &Case,
    source: &[u8],
    limits: LoadLimits,
    fuel: u64,
    scenario: &str,
) -> (Observed, Option<Dimension>) {
    let traces = Arc::new(Mutex::new(Vec::new()));
    let reader_trace = Arc::new(Mutex::new(ReadTrace::default()));
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(Reader {
                source: source.to_vec(),
                guest_path: case.guest_path.to_vec(),
                trace: reader_trace.clone(),
            })
            .and_compiler(RecordingCompiler {
                traces: traces.clone(),
            })
            .with_limits(limits),
    );
    let (mut vm, environment) = core_vm(case.profile, services);
    let roots_before = vm.roots().total_count();
    let root_kinds_before: Vec<_> = RootKind::ALL
        .into_iter()
        .map(|kind| (kind, vm.roots().count(kind)))
        .collect();
    let mut command = b"return assert(loadfile('".to_vec();
    command.extend_from_slice(case.guest_path);
    command.extend_from_slice(b"'))");
    let (outcome, fuel_before, fuel_after) = {
        let mut execution = vm
            .load_with_environment(runner(&command, case.profile), Value::Object(environment))
            .unwrap();
        execution.set_fuel(fuel).unwrap();
        let before = execution.fuel_remaining();
        let result = execution.run().unwrap();
        let after = execution.fuel_remaining();
        (result, before, after)
    };
    let observed = match &outcome {
        RunOutcome::Returned(values) if matches!(values.as_slice(), [Value::Object(object)] if vm.object_kind(*object) == Ok(ObjectKind::Closure)) => {
            Observed::Function
        }
        RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget => {
            Observed::HostLoadBudget
        }
        RunOutcome::Aborted(rivetlua::AbortReason::FuelExhausted) => Observed::FuelExhausted,
        _ => Observed::Other,
    };
    let roots_with_outcome = vm.roots().total_count();
    let reserved_with_outcome = vm.ledger_snapshot().reserved;
    let recorded = traces.lock().unwrap();
    eprintln!(
        "SDK case={} scenario={scenario} profile={:?} source_bytes={} path={} caps={:?} fuel_before={fuel_before} fuel_after={fuel_after} outcome={outcome:?} observed={observed:?} roots_before={root_kinds_before:?} roots_with_outcome={roots_with_outcome} reserved={reserved_with_outcome} reader={:?}",
        case.label,
        case.profile,
        source.len(),
        case.path.display(),
        limits,
        *reader_trace.lock().unwrap()
    );
    let mut first_denial = None;
    for trace in recorded.iter() {
        eprintln!(
            "SDK case={} compile source_match={} chunkname={:?} expected_chunkname={:?} profile={:?} outcome={} accepted_work={} temporary_cumulative_claimed={} module_claimed={} claims={}",
            case.label,
            trace.source == source,
            String::from_utf8_lossy(&trace.chunkname),
            String::from_utf8_lossy(case.expected_chunkname),
            trace.profile,
            trace.outcome,
            trace.spent[0],
            trace.spent[1],
            trace.spent[2],
            trace.claims.len()
        );
        assert_eq!(trace.source, source);
        assert_eq!(trace.chunkname, case.expected_chunkname);
        assert_eq!(trace.profile, case.profile);
        for (index, claim) in trace.claims.iter().enumerate() {
            if !claim.accepted && first_denial.is_none() {
                first_denial = Some(claim.dimension);
            }
            eprintln!(
                "SDK case={} claim#{index} {:?} request={} spent_before={} accepted={}",
                case.label, claim.dimension, claim.request, claim.spent_before, claim.accepted
            );
        }
    }
    assert_eq!(recorded.len(), 1, "{}: compiler callback 次數", case.label);
    drop(recorded);
    let read = *reader_trace.lock().unwrap();
    assert_eq!(read.calls, 1);
    assert!(read.work_accepted && read.temporary_accepted);
    assert_eq!(reserved_with_outcome, 0);
    if observed == Observed::HostLoadBudget {
        assert_eq!(roots_with_outcome, roots_before + 1);
    }
    drop(outcome);
    assert_eq!(vm.roots().total_count(), roots_before);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let retry = runner(b"return assert(load('return 1'))()", case.profile);
    let retry_outcome = {
        let mut execution = vm
            .load_with_environment(retry, Value::Object(environment))
            .unwrap();
        execution.set_fuel(RAW_V13_FUEL).unwrap();
        execution.run().unwrap()
    };
    assert_eq!(retry_outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    assert_eq!(vm.roots().total_count(), roots_before);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    eprintln!(
        "SDK case={} scenario={scenario} same_vm_retry=Returned(1) roots={} reserved={}",
        case.label,
        roots_before,
        vm.ledger_snapshot().reserved
    );
    (observed, first_denial)
}

#[test]
#[ignore = "需明示 RAW v13 唯讀來源；Lua 5.5 真 VM loadfile 診斷"]
fn sdk_gc_loadfile_lua55() {
    for case in cases()
        .into_iter()
        .filter(|case| case.profile == LuaProfile::Lua55)
    {
        let baseline = run(&case, raw_v13_limits(), RAW_V13_FUEL, "raw-v13-baseline");
        match case.label {
            "55-prefix-350" => assert_eq!(baseline, Observed::Function),
            _ => assert_eq!(baseline, Observed::HostLoadBudget),
        }
        if let Some(control) = case.control {
            let observed = run(&case, control, RAW_V13_FUEL, "finite-control-raw-v13-fuel");
            if observed == Observed::FuelExhausted {
                assert_eq!(
                    run(
                        &case,
                        control,
                        ISOLATION_FUEL,
                        "finite-control-isolation-fuel"
                    ),
                    Observed::Function
                );
            } else {
                assert_eq!(observed, Observed::Function);
            }
        }
    }
}

#[test]
#[ignore = "需明示 Lua 5.4 官方 GC 唯讀來源；真 VM loadfile 診斷"]
fn sdk_gc_loadfile_lua54() {
    let case = cases()
        .into_iter()
        .find(|case| case.label == "54-full-gc")
        .unwrap();
    assert_eq!(
        run(&case, raw_v13_limits(), RAW_V13_FUEL, "raw-v13-baseline"),
        Observed::HostLoadBudget
    );
    let control = case.control.unwrap();
    let observed = run(&case, control, RAW_V13_FUEL, "finite-control-raw-v13-fuel");
    if observed == Observed::FuelExhausted {
        assert_eq!(
            run(
                &case,
                control,
                ISOLATION_FUEL,
                "finite-control-isolation-fuel"
            ),
            Observed::Function
        );
    } else {
        assert_eq!(observed, Observed::Function);
    }
}

#[test]
#[ignore = "校準 RAW v13 後候選 CLI 2Gi work units／256MiB temp／4b fuel；本檔不修改產品政策"]
fn sdk_gc_candidate_policy_lua55() {
    let case = cases()
        .into_iter()
        .find(|case| case.label == "55-full-gc")
        .unwrap();
    assert_eq!(
        run(
            &case,
            candidate_cli_limits(),
            ISOLATION_FUEL,
            "candidate-cli-policy"
        ),
        Observed::Function
    );
}

#[test]
#[ignore = "校準 RAW v13 後候選 CLI 2Gi work units／256MiB temp／4b fuel；本檔不修改產品政策"]
fn sdk_gc_candidate_policy_lua54() {
    let case = cases()
        .into_iter()
        .find(|case| case.label == "54-full-gc")
        .unwrap();
    assert_eq!(
        run(
            &case,
            candidate_cli_limits(),
            ISOLATION_FUEL,
            "candidate-cli-policy"
        ),
        Observed::Function
    );
}

fn candidate_work_negative(profile: LuaProfile) {
    let source = b"do local x=1 end\n".repeat(8_000);
    let case = Case {
        label: "synthetic-8000-blocks",
        profile,
        path: PathBuf::from("<memory:8000-independent-blocks>"),
        guest_path: b"gc_work_8000.lua",
        expected_chunkname: b"@gc_work_8000.lua",
        control: None,
    };
    let (observed, first_denial) = run_source(
        &case,
        &source,
        candidate_cli_limits(),
        ISOLATION_FUEL,
        "candidate-work-negative",
    );
    assert_eq!(observed, Observed::HostLoadBudget);
    assert_eq!(first_denial, Some(Dimension::Work));
}

#[test]
#[ignore = "僅校準候選 CLI Work-first 負向來源；不更動 CLI 原測試"]
fn sdk_gc_candidate_work_negative_lua55() {
    candidate_work_negative(LuaProfile::Lua55);
}

#[test]
#[ignore = "僅校準候選 CLI Work-first 負向來源；不更動 CLI 原測試"]
fn sdk_gc_candidate_work_negative_lua54() {
    candidate_work_negative(LuaProfile::Lua54);
}
