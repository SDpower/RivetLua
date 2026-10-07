use std::sync::{Arc, Mutex};

use rivetlua::{
    AbortReason, HostLoadError, HostServices, LoadCapability, LoadLimits, LuaProfile, RunOutcome,
};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{IrLimits, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostHandle, HostLoadCompiler, RuntimeErrorKind, Vm};

const HIGH_FUEL: u64 = 64 * 1024 * 1024;

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

#[derive(Clone, Debug, Default)]
struct StageTrace {
    work: [usize; 6],
    completed_admissions: usize,
    lower_work_claims: Vec<usize>,
}

struct RecordingCompiler {
    traces: Arc<Mutex<Vec<StageTrace>>>,
}

struct RecordingSink<'a, 'b> {
    budget: &'a mut rivetlua::LoadBudget<'b>,
    trace: &'a mut StageTrace,
}

impl CompileBudgetSink for RecordingSink<'_, '_> {
    type Error = HostLoadError;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        let stage = self.trace.completed_admissions.min(5);
        self.trace.work[stage] = self.trace.work[stage].checked_add(units).unwrap();
        if stage == 3 {
            self.trace.lower_work_claims.push(units);
        }
        self.budget.spend_work(units)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_temporary(bytes)?;
        self.trace.completed_admissions += 1;
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.budget.claim_module_allocation(bytes)
    }
}

impl HostLoadCompiler for RecordingCompiler {
    fn compile(
        &mut self,
        source: &[u8],
        chunkname: &[u8],
        profile: LuaProfile,
        budget: &mut rivetlua::LoadBudget<'_>,
    ) -> Result<VerifiedModule, HostLoadError> {
        let mut trace = StageTrace::default();
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
        self.traces.lock().unwrap().push(trace);
        match result {
            Ok(module) => Ok(module),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(other) => panic!("測試來源意外編譯失敗：{other:?}"),
        }
    }
}

fn runner(source: &[u8], profile: LuaProfile) -> VerifiedModule {
    let mut chunk = b"return assert(load([=[".to_vec();
    chunk.extend_from_slice(source);
    chunk.extend_from_slice(b"]=]))");
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    compile_with_budget(
        &chunk,
        b"=sdk-lower-budget-regression",
        language,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn vm_with_limits(
    profile: LuaProfile,
    limits: LoadLimits,
    traces: Arc<Mutex<Vec<StageTrace>>>,
) -> Vm {
    let services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_compiler(RecordingCompiler { traces })
            .with_limits(limits),
    );
    Vm::new_with_services(profile, services).unwrap()
}

#[test]
fn real_host_compiler_lower_denial_refunds_and_same_vm_retries() {
    let source = b"do local x=1 end\n".repeat(21);
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let traces = Arc::new(Mutex::new(Vec::new()));
        let limits = LoadLimits {
            max_source_bytes: 1024 * 1024,
            max_encoded_bytes: 64 * 1024 * 1024,
            max_module_allocation_bytes: 64 * 1024 * 1024,
            max_temporary_bytes: 64 * 1024 * 1024,
            max_work_units: 64 * 1024 * 1024,
            max_reader_chunks: 512,
            max_path_candidates: 512,
        };
        let mut vm = vm_with_limits(profile, limits, traces.clone());
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_error_builtins(environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let root_count = vm.roots().total_count();
        let module = runner(&source, profile);

        let (calibration, remaining) = {
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(HIGH_FUEL).unwrap();
            let outcome = execution.run().unwrap();
            (outcome, execution.fuel_remaining())
        };
        assert!(matches!(calibration, RunOutcome::Returned(_)));
        let successful = traces.lock().unwrap().last().cloned().unwrap();
        assert_eq!(successful.completed_admissions, 6);
        assert_eq!(successful.lower_work_claims.len(), 2);
        let compile_work: usize = successful.work.iter().sum();
        let overhead = usize::try_from(HIGH_FUEL - remaining)
            .unwrap()
            .checked_sub(compile_work)
            .unwrap();
        let lower_prepaid = successful.lower_work_claims[0];
        let lower_normal = successful.lower_work_claims[1];
        assert!(lower_normal > 100_000);
        let failure_fuel = overhead
            + successful.work[..3].iter().sum::<usize>()
            + lower_prepaid
            + lower_normal / 2;

        let failure = {
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(failure_fuel as u64).unwrap();
            execution.run().unwrap()
        };
        assert_eq!(failure, RunOutcome::Aborted(AbortReason::FuelExhausted));
        let denied = traces.lock().unwrap().last().cloned().unwrap();
        assert_eq!(denied.completed_admissions, 3, "{profile:?} {denied:?}");
        assert_eq!(denied.lower_work_claims.len(), 2, "{profile:?} {denied:?}");
        assert_eq!(vm.roots().total_count(), root_count);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let retry = {
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(HIGH_FUEL).unwrap();
            execution.run().unwrap()
        };
        assert!(matches!(retry, RunOutcome::Returned(values)
            if matches!(values.as_slice(), [Value::Object(_)])));
        assert_eq!(vm.roots().total_count(), root_count);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let budget_traces = Arc::new(Mutex::new(Vec::new()));
        let mut budget_vm = vm_with_limits(
            profile,
            LoadLimits {
                max_work_units: failure_fuel,
                ..limits
            },
            budget_traces.clone(),
        );
        let budget_env = budget_vm.allocate_table().unwrap();
        let _budget_root = HostHandle::<Value>::new(&mut budget_vm, budget_env).unwrap();
        budget_vm.install_error_builtins(budget_env).unwrap();
        budget_vm.install_basic_builtins(budget_env).unwrap();
        let budget_roots = budget_vm.roots().total_count();
        let limited = {
            let mut execution = budget_vm
                .load_with_environment(module, Value::Object(budget_env))
                .unwrap();
            execution.set_fuel(HIGH_FUEL).unwrap();
            execution.run().unwrap()
        };
        assert!(matches!(limited, RunOutcome::LuaError(error)
            if error.kind == RuntimeErrorKind::HostLoadBudget));
        let budget_denied = budget_traces.lock().unwrap().last().cloned().unwrap();
        assert_eq!(budget_denied.completed_admissions, 3);
        assert_eq!(budget_denied.lower_work_claims.len(), 2);
        assert_eq!(budget_vm.roots().total_count(), budget_roots);
        assert_eq!(budget_vm.ledger_snapshot().reserved, 0);

        let smaller = runner(b"return 1", profile);
        let budget_retry = {
            let mut execution = budget_vm
                .load_with_environment(smaller, Value::Object(budget_env))
                .unwrap();
            execution.set_fuel(HIGH_FUEL).unwrap();
            execution.run().unwrap()
        };
        assert!(matches!(budget_retry, RunOutcome::Returned(values)
            if matches!(values.as_slice(), [Value::Object(_)])));
        assert_eq!(budget_vm.roots().total_count(), budget_roots);
        assert_eq!(budget_vm.ledger_snapshot().reserved, 0);
    }
}
