use rivetlua::{
    Engine, HostLoadError, HostLoadErrorKind, HostServices, HostSourceReader, LoadBudget,
    LoadCapability, LoadLimits, LuaProfile, RunOutcome,
};
use rivetlua_compiler::{CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget};
use rivetlua_core::{IrLimits, Value, VerifyLimits};
use rivetlua_runtime::{HostHandle, RuntimeErrorKind, Vm as CoreVm, VmError};

const MAX_READER_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANDIDATE_BYTES: usize = 4096;

fn cli_limits() -> LoadLimits {
    LoadLimits {
        max_source_bytes: MAX_READER_BYTES,
        max_encoded_bytes: 64 * 1024 * 1024,
        max_module_allocation_bytes: 64 * 1024 * 1024,
        max_temporary_bytes: MAX_READER_BYTES + MAX_CANDIDATE_BYTES * 3,
        max_work_units: 16 * 1024 * 1024,
        max_reader_chunks: 512,
        max_path_candidates: 512,
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

fn core_runner(source: &[u8]) -> rivetlua_core::VerifiedModule {
    let mut runner = b"return assert(load([=[".to_vec();
    runner.extend_from_slice(source);
    runner.extend_from_slice(b"]=]))");
    compile_with_budget(
        &runner,
        b"=host-load-budget-diagnostic",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

struct SourceReader {
    source: Vec<u8>,
    path: Vec<u8>,
}

impl SourceReader {
    fn read(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        let work = self.source.len() + 1;
        budget.spend_work(work)?;
        budget.claim_temporary(self.source.len())?;
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
}

impl HostSourceReader for SourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, self.path);
        self.read(budget)
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        self.read(budget)
    }
}

fn run_host_load(
    engine: &Engine,
    source: &[u8],
    file: bool,
    path: &[u8],
    limits: LoadLimits,
    fuel: Option<u64>,
    ledger_limit: Option<usize>,
) -> (String, usize, usize, usize) {
    let runner_source = if file {
        let mut runner = b"return assert(loadfile('".to_vec();
        runner.extend_from_slice(path);
        runner.extend_from_slice(b"'))");
        runner
    } else {
        let mut runner = b"return assert(load([=[".to_vec();
        runner.extend_from_slice(source);
        runner.extend_from_slice(b"]=]))");
        runner
    };
    let runner = engine.compile(&runner_source).unwrap();
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_reader(SourceReader {
                source: source.to_vec(),
                path: path.to_vec(),
            })
            .and_compiler(engine.clone())
            .with_limits(limits),
    );
    let mut vm = engine.new_vm_with_services(services).unwrap();
    if let Some(limit) = ledger_limit {
        vm.set_allocation_limit(limit);
    }
    let outcome = {
        let mut execution = vm.load_module(&runner).unwrap();
        if let Some(fuel) = fuel {
            execution.set_fuel(fuel).unwrap();
        }
        execution.run()
    };
    let described = match outcome {
        Ok(RunOutcome::Returned(values)) => format!("Returned({} values)", values.len()),
        Ok(RunOutcome::LuaError(error)) => {
            format!("LuaError({:?}, {})", error.kind, error.diagnostic_id)
        }
        Ok(other) => format!("{other:?}"),
        Err(error) => format!("RuntimeErr({error:?})"),
    };
    let snapshot = vm.allocation_snapshot();
    (
        described,
        snapshot.reserved,
        snapshot.committed,
        snapshot.limit,
    )
}

#[test]
fn public_engine_direct_and_host_load_baseline_for_five_and_twenty_one_blocks() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        for blocks in [5, 21] {
            let source = b"do local x=1 end\n".repeat(blocks);
            let direct = engine.compile_named(&source, b"@code.lua");
            eprintln!(
                "profile={profile:?} blocks={blocks} bytes={} direct={:?}",
                source.len(),
                direct.as_ref().map(|_| "Compiled")
            );
            assert!(direct.is_ok(), "direct compile 必須作為控制案例");
            for file in [false, true] {
                let (outcome, reserved, committed, limit) = run_host_load(
                    &engine,
                    &source,
                    file,
                    b"code.lua",
                    cli_limits(),
                    None,
                    None,
                );
                eprintln!(
                    "profile={profile:?} blocks={blocks} loadfile={file} host={outcome} reserved={reserved} committed={committed} ledger_limit={limit}"
                );
                assert_eq!(reserved, 0);
                if blocks == 5 {
                    assert_eq!(outcome, "Returned(1 values)");
                }
            }
        }
    }
}

#[test]
#[ignore = "需明示 RIVETLUA_HOSTLOAD_MAIN 指向 RAW v10 唯讀 fixture"]
fn isolate_host_load_work_temporary_fuel_and_ledger_limits() {
    let engine = Engine::new(LuaProfile::Lua55);
    let source = b"do local x=1 end\n".repeat(21);
    let base = cli_limits();
    for (label, limits, fuel) in [
        ("base", base, None),
        (
            "work-only-64m",
            LoadLimits {
                max_work_units: 64 * 1024 * 1024,
                ..base
            },
            None,
        ),
        (
            "temp-only-64m",
            LoadLimits {
                max_temporary_bytes: 64 * 1024 * 1024,
                ..base
            },
            None,
        ),
        (
            "module-only-128m",
            LoadLimits {
                max_module_allocation_bytes: 128 * 1024 * 1024,
                ..base
            },
            None,
        ),
        ("fuel-only-64m", base, Some(64 * 1024 * 1024)),
        (
            "temp-plus-fuel",
            LoadLimits {
                max_temporary_bytes: 64 * 1024 * 1024,
                ..base
            },
            Some(64 * 1024 * 1024),
        ),
        (
            "work-temp-fuel",
            LoadLimits {
                max_work_units: 64 * 1024 * 1024,
                max_temporary_bytes: 64 * 1024 * 1024,
                ..base
            },
            Some(64 * 1024 * 1024),
        ),
    ] {
        let (outcome, reserved, committed, ledger_limit) =
            run_host_load(&engine, &source, false, b"code.lua", limits, fuel, None);
        eprintln!(
            "case=21-blocks scenario={label} outcome={outcome} reserved={reserved} committed={committed} ledger_limit={ledger_limit}"
        );
        assert_eq!(reserved, 0);
    }

    let main_path = std::env::var_os("RIVETLUA_HOSTLOAD_MAIN")
        .expect("須以 RIVETLUA_HOSTLOAD_MAIN 指定本次唯讀官方 main.lua");
    let main_raw = std::fs::read(main_path).unwrap();
    assert_eq!(main_raw.len(), 16146);
    let end = main_raw.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut normalized = vec![b'\n'];
    normalized.extend_from_slice(&main_raw[end..]);
    let direct = engine.compile_named(&normalized, b"@main.lua");
    eprintln!(
        "case=official-main direct-default raw_bytes={} normalized_bytes={} outcome={:?}",
        main_raw.len(),
        normalized.len(),
        direct.as_ref().map(|_| "Compiled")
    );
    for (label, limits, fuel) in [
        ("base", base, None),
        (
            "work-only-120b",
            LoadLimits {
                max_work_units: 120_000_000_000,
                ..base
            },
            None,
        ),
        ("fuel-only-120b", base, Some(120_000_000_000)),
        (
            "work-plus-fuel",
            LoadLimits {
                max_work_units: 120_000_000_000,
                ..base
            },
            Some(120_000_000_000),
        ),
        (
            "temp-only-3gb",
            LoadLimits {
                max_temporary_bytes: 3_000_000_000,
                ..base
            },
            None,
        ),
        (
            "work-temp-fuel",
            LoadLimits {
                max_work_units: 120_000_000_000,
                max_temporary_bytes: 3_000_000_000,
                ..base
            },
            Some(120_000_000_000),
        ),
    ] {
        let (outcome, reserved, committed, ledger_limit) =
            run_host_load(&engine, &main_raw, true, b"main.lua", limits, fuel, None);
        eprintln!(
            "case=official-main scenario={label} outcome={outcome} reserved={reserved} committed={committed} ledger_limit={ledger_limit}"
        );
        assert_eq!(reserved, 0);
    }

    let (outcome, reserved, committed, ledger_limit) = run_host_load(
        &engine,
        &b"do local x=1 end\n".repeat(5),
        false,
        b"code.lua",
        base,
        None,
        Some(2 * 1024 * 1024),
    );
    eprintln!(
        "case=5-blocks scenario=ledger-only-2m outcome={outcome} reserved={reserved} committed={committed} ledger_limit={ledger_limit}"
    );
    assert_eq!(reserved, 0);
}

#[test]
fn failed_host_load_refunds_and_preserves_roots_for_same_vm_retry() {
    let engine = Engine::new(LuaProfile::Lua55);
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(engine)
            // 21 個區塊超過刻意設定的來源上限；5 個區塊仍可在同一 VM 重試。
            .with_limits(LoadLimits {
                max_source_bytes: 100,
                ..cli_limits()
            }),
    );
    let mut vm = CoreVm::new_with_services(LuaProfile::Lua55, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let roots = vm.roots().total_count();
    let twenty_one = core_runner(&b"do local x=1 end\n".repeat(21));
    let five = core_runner(&b"do local x=1 end\n".repeat(5));

    let budget_failure = vm
        .load_with_environment(twenty_one, Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    assert!(matches!(budget_failure, RunOutcome::LuaError(error)
        if error.kind == RuntimeErrorKind::HostLoadBudget));
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    // 以已用額度作為上限，確定下一次載入 frame 所需的配置遭拒；
    // 此檢查不依賴編譯器各階段預付額度的大小。
    vm.set_allocation_limit(vm.ledger_snapshot().committed);
    let allocation_failure = vm
        .load_with_environment(five.clone(), Value::Object(environment))
        .err()
        .unwrap();
    assert_eq!(
        allocation_failure.kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    vm.set_allocation_limit(usize::MAX);
    let outcome = vm
        .load_with_environment(five, Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Returned(values)
        if matches!(values.as_slice(), [Value::Object(_)])));
    assert_eq!(vm.roots().total_count(), roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}
