use std::sync::{Arc, Mutex};

use rivetlua::{
    Engine, HostLoadError, HostLoadErrorKind, HostServices, HostSourceReader, LoadBudget,
    LoadCapability, LoadLimits, LuaProfile, RunOutcome,
};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{IrLimits, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostLoadCompiler, RuntimeErrorKind, Vm};

const FINITE_WORK: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dimension {
    Work,
    Temporary,
    Module,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    dimension: Dimension,
    requested: usize,
    spent_before: usize,
    completed_temporary_admissions: usize,
    accepted: bool,
}

#[derive(Debug)]
struct CompileTrace {
    source: Vec<u8>,
    chunkname: Vec<u8>,
    profile: LuaProfile,
    work: usize,
    temporary: usize,
    module: usize,
    completed_temporary_admissions: usize,
    claims: Vec<Claim>,
    compiled: bool,
}

impl CompileTrace {
    fn new(source: &[u8], chunkname: &[u8], profile: LuaProfile) -> Self {
        Self {
            source: source.to_vec(),
            chunkname: chunkname.to_vec(),
            profile,
            work: 0,
            temporary: 0,
            module: 0,
            completed_temporary_admissions: 0,
            claims: Vec::new(),
            compiled: false,
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
    fn claim(&mut self, dimension: Dimension, requested: usize) -> Result<(), HostLoadError> {
        let spent_before = match dimension {
            Dimension::Work => self.trace.work,
            Dimension::Temporary => self.trace.temporary,
            Dimension::Module => self.trace.module,
        };
        let result = match dimension {
            Dimension::Work => self.budget.spend_work(requested),
            Dimension::Temporary => self.budget.claim_temporary(requested),
            Dimension::Module => self.budget.claim_module_allocation(requested),
        };
        self.trace.claims.push(Claim {
            dimension,
            requested,
            spent_before,
            completed_temporary_admissions: self.trace.completed_temporary_admissions,
            accepted: result.is_ok(),
        });
        if result.is_ok() {
            match dimension {
                Dimension::Work => self.trace.work += requested,
                Dimension::Temporary => {
                    self.trace.temporary += requested;
                    self.trace.completed_temporary_admissions += 1;
                }
                Dimension::Module => self.trace.module += requested,
            }
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
        trace.compiled = result.is_ok();
        self.traces.lock().unwrap().push(trace);
        match result {
            Ok(module) => Ok(module),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(other) => panic!("診斷來源意外語意或 verifier 失敗：{other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReaderTrace {
    work_request: usize,
    temporary_request: usize,
    work_accepted: bool,
    temporary_accepted: bool,
    calls: usize,
}

struct Reader {
    trace: Arc<Mutex<ReaderTrace>>,
}

impl Reader {
    fn read(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        let source = b"return 31, 32";
        let mut trace = self.trace.lock().unwrap();
        trace.calls += 1;
        trace.work_request = source.len() + 1;
        trace.temporary_request = source.len();
        let work = budget.spend_work(trace.work_request);
        trace.work_accepted = work.is_ok();
        work?;
        let temporary = budget.claim_temporary(trace.temporary_request);
        trace.temporary_accepted = temporary.is_ok();
        temporary?;
        drop(trace);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
        if bytes.capacity() > source.len() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        bytes.extend_from_slice(source);
        Ok(bytes)
    }
}

impl HostSourceReader for Reader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, b"code.lua");
        self.read(budget)
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        self.read(budget)
    }
}

struct Unlimited;

impl CompileBudgetSink for Unlimited {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
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
        b"=sdk-default-host-load-diagnostic",
        language,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn services(
    compiler: impl HostLoadCompiler + 'static,
    reader: bool,
    reader_trace: Arc<Mutex<ReaderTrace>>,
    limits: LoadLimits,
) -> HostServices {
    let load = LoadCapability::deny_all().and_compiler(compiler);
    let load = if reader {
        load.and_reader(Reader {
            trace: reader_trace,
        })
    } else {
        load
    };
    HostServices::deny_all().and_load(load.with_limits(limits))
}

fn core_vm(profile: LuaProfile, services: HostServices) -> (Vm, rivetlua_core::ObjectRef) {
    let mut vm = Vm::new_with_services(profile, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    // 此診斷保留 SDK 初始化的 A-E→F→G→H 順序，以 Host root 持有環境。
    vm.add_root(rivetlua_runtime::RootKind::Host, environment)
        .unwrap();
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

fn check_case(profile: LuaProfile, reader: bool) {
    let engine = Engine::new(profile);
    let source: &[u8] = if reader {
        b"local f=assert(loadfile('code.lua')); return f()"
    } else {
        b"local f=load('return 40+2'); return f()"
    };
    let expected_source: &[u8] = if reader {
        b"return 31, 32"
    } else {
        b"return 40+2"
    };
    let expected_chunkname: &[u8] = if reader {
        b"@code.lua"
    } else {
        expected_source
    };

    // 真正的 SDK Engine(default compiler) 與預設 Host LoadLimits。
    let sdk_reader = Arc::new(Mutex::new(ReaderTrace::default()));
    let mut sdk = engine
        .new_vm_with_services(services(
            engine.clone(),
            reader,
            sdk_reader.clone(),
            LoadLimits::default(),
        ))
        .unwrap();
    let sdk_runner = engine.compile(source).unwrap();
    let sdk_outcome = sdk.load_module(&sdk_runner).unwrap().run().unwrap();
    let expected = if reader {
        vec![Value::Integer(31), Value::Integer(32)]
    } else {
        vec![Value::Integer(42)]
    };
    assert_eq!(sdk_outcome, RunOutcome::Returned(expected.clone()));
    assert_eq!(sdk.allocation_snapshot().reserved, 0);
    if reader {
        let read = *sdk_reader.lock().unwrap();
        assert_eq!(read.calls, 1);
        assert!(read.work_accepted && read.temporary_accepted);
    }

    // 同等 VM 初始化與公開 HostLoadCompiler forwarding adapter，記錄完整申報。
    let traces = Arc::new(Mutex::new(Vec::new()));
    let reader_trace = Arc::new(Mutex::new(ReaderTrace::default()));
    let (mut vm, environment) = core_vm(
        profile,
        services(
            RecordingCompiler {
                traces: traces.clone(),
            },
            reader,
            reader_trace.clone(),
            LoadLimits::default(),
        ),
    );
    let roots = vm.roots().total_count();
    let root_kinds_before: Vec<_> = rivetlua_runtime::RootKind::ALL
        .into_iter()
        .map(|kind| (kind, vm.roots().count(kind)))
        .collect();
    let module = runner(source, profile);
    let (outcome, fuel_before, fuel_after) = {
        let mut execution = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap();
        let before = execution.fuel_remaining();
        let outcome = execution.run().unwrap();
        let after = execution.fuel_remaining();
        (outcome, before, after)
    };
    assert_eq!(outcome, RunOutcome::Returned(expected.clone()));
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    assert!(fuel_after > 0);
    let recorded = traces.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    let trace = &recorded[0];
    assert_eq!(trace.source, expected_source);
    assert_eq!(trace.chunkname, expected_chunkname);
    assert_eq!(trace.profile, profile);
    assert!(trace.compiled);
    assert!(trace.claims.iter().all(|claim| claim.accepted));
    assert!(trace.work < LoadLimits::default().max_work_units);
    let complete_work = trace.work;
    eprintln!(
        "SDK {profile:?} reader={reader} source={:?} chunkname={:?} default_outcome={outcome:?} compiled_work={} temporary={} module={} fuel_before={fuel_before} fuel_after={fuel_after} roots_before={root_kinds_before:?} roots_after={:?} reserved={} reader_prepay={:?}",
        String::from_utf8_lossy(&trace.source),
        String::from_utf8_lossy(&trace.chunkname),
        trace.work,
        trace.temporary,
        trace.module,
        rivetlua_runtime::RootKind::ALL
            .into_iter()
            .map(|kind| (kind, vm.roots().count(kind)))
            .collect::<Vec<_>>(),
        vm.ledger_snapshot().reserved,
        *reader_trace.lock().unwrap(),
    );
    drop(recorded);

    // compiler 前另付一單位 work；把 cap 設成剛完成的 compiler claim
    // 總和，便會在最後一筆 compiler work 真正被有限額度拒絕。
    let denied_traces = Arc::new(Mutex::new(Vec::new()));
    let denied_reader_trace = Arc::new(Mutex::new(ReaderTrace::default()));
    let limits = LoadLimits {
        max_work_units: complete_work,
        ..LoadLimits::default()
    };
    let (mut denied_vm, denied_environment) = core_vm(
        profile,
        services(
            RecordingCompiler {
                traces: denied_traces.clone(),
            },
            reader,
            denied_reader_trace.clone(),
            limits,
        ),
    );
    let denied_roots = denied_vm.roots().total_count();
    let (denied_outcome, denied_fuel_before, denied_fuel_after) = {
        let mut execution = denied_vm
            .load_with_environment(runner(source, profile), Value::Object(denied_environment))
            .unwrap();
        let before = execution.fuel_remaining();
        let outcome = execution.run().unwrap();
        let after = execution.fuel_remaining();
        (outcome, before, after)
    };
    assert!(
        matches!(&denied_outcome, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget)
    );
    // LuaError 持有一個 Host root，丟棄後須回到安裝完成的基線。
    assert_eq!(denied_vm.roots().total_count(), denied_roots + 1);
    assert_eq!(denied_vm.ledger_snapshot().reserved, 0);
    assert!(denied_fuel_after > 0);
    let denied_recorded = denied_traces.lock().unwrap();
    assert_eq!(denied_recorded.len(), 1);
    let denied_trace = &denied_recorded[0];
    assert_eq!(denied_trace.source, expected_source);
    assert_eq!(denied_trace.chunkname, expected_chunkname);
    assert_eq!(denied_trace.profile, profile);
    assert!(!denied_trace.compiled);
    let first_denial = denied_trace
        .claims
        .iter()
        .find(|claim| !claim.accepted)
        .unwrap();
    assert_eq!(first_denial.dimension, Dimension::Work);
    assert!(first_denial.spent_before + first_denial.requested + 1 > complete_work);
    assert!(first_denial.completed_temporary_admissions >= 3);
    eprintln!(
        "SDK {profile:?} reader={reader} insufficient_work_cap={complete_work} outcome={denied_outcome:?} first_denial={first_denial:?} accepted_work={} fuel_before={denied_fuel_before} fuel_after={denied_fuel_after} roots={} reserved={} reader_prepay={:?}",
        denied_trace.work,
        denied_roots,
        denied_vm.ledger_snapshot().reserved,
        *denied_reader_trace.lock().unwrap(),
    );
    drop(denied_recorded);
    drop(denied_outcome);
    assert_eq!(denied_vm.roots().total_count(), denied_roots);
    assert_eq!(denied_vm.ledger_snapshot().reserved, 0);

    let retry = runner(b"return assert(load('return 1'))()", profile);
    let retry_outcome = denied_vm
        .load_with_environment(retry, Value::Object(denied_environment))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(retry_outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
    assert_eq!(denied_vm.roots().total_count(), denied_roots);
    assert_eq!(denied_vm.ledger_snapshot().reserved, 0);

    let finite_reader_trace = Arc::new(Mutex::new(ReaderTrace::default()));
    let limits = LoadLimits {
        max_work_units: FINITE_WORK,
        ..LoadLimits::default()
    };
    let mut finite = engine
        .new_vm_with_services(services(
            engine.clone(),
            reader,
            finite_reader_trace.clone(),
            limits,
        ))
        .unwrap();
    let finite_outcome = finite.load_module(&sdk_runner).unwrap().run().unwrap();
    assert_eq!(finite_outcome, RunOutcome::Returned(expected));
    assert_eq!(finite.allocation_snapshot().reserved, 0);
    eprintln!("SDK {profile:?} reader={reader} finite_work={FINITE_WORK} success reserved=0");
}

#[test]
#[ignore = "需明示執行；診斷預設 HostLoad 成功、有限不足額拒絕及清理"]
fn sdk_default_host_load_diagnostic_lua54() {
    check_case(LuaProfile::Lua54, false);
    check_case(LuaProfile::Lua54, true);
}

#[test]
#[ignore = "需明示執行；診斷預設 HostLoad 成功、有限不足額拒絕及清理"]
fn sdk_default_host_load_diagnostic_lua55() {
    check_case(LuaProfile::Lua55, false);
    check_case(LuaProfile::Lua55, true);
}
