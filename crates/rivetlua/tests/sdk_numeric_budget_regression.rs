use rivetlua::{Engine, HostServices, LoadCapability, LoadLimits, LuaProfile, RunOutcome};
use rivetlua_compiler::{CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget};
use rivetlua_core::{IrLimits, Value, VerifyLimits};
use rivetlua_runtime::{AbortReason, HostHandle, RuntimeErrorKind, Vm};

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

fn runner(source: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let mut code = b"return assert(load('".to_vec();
    code.extend_from_slice(source);
    code.extend_from_slice(b"'))()");
    compile_with_budget(
        &code,
        b"=numeric-budget-runner",
        match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        },
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn limits(max_work_units: usize) -> LoadLimits {
    LoadLimits {
        max_source_bytes: 4 * 1024 * 1024,
        max_encoded_bytes: 64 * 1024 * 1024,
        max_module_allocation_bytes: 64 * 1024 * 1024,
        max_temporary_bytes: 4 * 1024 * 1024 + 12 * 1024,
        max_work_units,
        max_reader_chunks: 512,
        max_path_candidates: 512,
    }
}

#[test]
fn numeric_host_load_distinguishes_fast_fuel_and_work_limit_with_same_vm_retry() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let fast = runner(b"return 1.25", profile);
        let slow = runner(b"return 9007199254740993e0", profile);
        let services = HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .and_compiler(engine.clone())
                .with_limits(limits(16 * 1024 * 1024)),
        );
        let mut vm = Vm::new_with_services(profile, services).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_error_builtins(environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let roots = vm.roots().total_count();

        let fast_outcome = vm
            .load_with_environment(fast, Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert!(
            matches!(fast_outcome, RunOutcome::Returned(values)
            if values.as_slice() == [Value::Float(1.25)]),
            "{profile:?}"
        );
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let low_fuel = {
            let mut execution = vm
                .load_with_environment(slow.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(100_000).unwrap();
            execution.run().unwrap()
        };
        assert!(
            matches!(low_fuel, RunOutcome::Aborted(AbortReason::FuelExhausted)),
            "{profile:?}: {low_fuel:?}"
        );
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let high_fuel = {
            let mut execution = vm
                .load_with_environment(slow.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(16 * 1024 * 1024).unwrap();
            execution.run().unwrap()
        };
        assert!(
            matches!(high_fuel, RunOutcome::Returned(ref values)
            if matches!(values.as_slice(), [Value::Float(value)] if value.to_bits() == 9_007_199_254_740_992.0_f64.to_bits())),
            "{profile:?}: {high_fuel:?}"
        );
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let services = HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .and_compiler(engine)
                .with_limits(limits(100_000)),
        );
        let mut limited = Vm::new_with_services(profile, services).unwrap();
        let environment = limited.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut limited, environment).unwrap();
        limited.install_error_builtins(environment).unwrap();
        limited.install_basic_builtins(environment).unwrap();
        let roots = limited.roots().total_count();
        let limited_outcome = {
            let mut execution = limited
                .load_with_environment(slow, Value::Object(environment))
                .unwrap();
            execution.set_fuel(16 * 1024 * 1024).unwrap();
            execution.run().unwrap()
        };
        assert!(
            matches!(limited_outcome, RunOutcome::LuaError(ref error)
            if error.kind == RuntimeErrorKind::HostLoadBudget),
            "{profile:?}: {limited_outcome:?}"
        );
        drop(limited_outcome);
        assert_eq!(limited.roots().total_count(), roots);
        assert_eq!(limited.ledger_snapshot().reserved, 0);
    }
}
