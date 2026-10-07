use rivetlua::{
    CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits, CompileError, Engine, LuaProfile,
    RunOutcome,
};

#[test]
fn sdk_budget_compiles_captured_implicit_return_and_releases_claims() {
    let source = b"local a=1\nlocal x=7\nlocal f=function() return x end\n";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let budget = CompileBudget::default();
        let module = engine
            .compile_named_with_budget(source, b"=sdk-implicit", &budget)
            .unwrap_or_else(|error| panic!("{profile:?}: {error:?}"));
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
        assert!(
            engine
                .compile_named_with_budget(
                    b"local a,b\nlocal f=function() b=1 end\nf()\nprint(b)\n",
                    b"=sdk-implicit-assignment",
                    &budget,
                )
                .is_ok(),
            "{profile:?}: observable assignment"
        );
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&module).unwrap().run().unwrap(),
            RunOutcome::Returned(Vec::new())
        );

        let mut limited = CompileBudget::new(CompileBudgetLimits {
            max_work: u64::MAX,
            max_allocation_bytes: 64,
        });
        assert!(matches!(
            engine.compile_named_with_budget(source, b"=sdk-implicit", &limited),
            Err(CompileError::Budget(
                CompileBudgetErrorKind::AllocationLimitExceeded
            ))
        ));
        assert_eq!(limited.allocation_snapshot().reserved, 0);
        assert_eq!(limited.allocation_snapshot().committed, 0);
        limited.set_allocation_limit(usize::MAX);
        assert!(
            engine
                .compile_named_with_budget(source, b"=sdk-implicit", &limited)
                .is_ok()
        );
        assert_eq!(limited.allocation_snapshot().reserved, 0);
        assert_eq!(limited.allocation_snapshot().committed, 0);
    }
}

#[test]
fn sdk_budget_faults_each_claim_then_retries_implicit_return() {
    let source = b"local a=1\nlocal x=7\nlocal f=function() return x end\n";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let measured = CompileBudget::default();
        let start = measured.allocation_trace().next_ordinal;
        assert!(
            engine
                .compile_named_with_budget(source, b"=sdk-implicit", &measured)
                .is_ok()
        );
        let end = measured.allocation_trace().next_ordinal;
        assert!(end > start);
        for ordinal in start..end {
            let faulted = CompileBudget::default();
            faulted.fail_once_at_ordinal(ordinal);
            assert!(matches!(
                engine.compile_named_with_budget(source, b"=sdk-implicit", &faulted),
                Err(CompileError::Budget(
                    CompileBudgetErrorKind::AllocationFailed
                ))
            ));
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);
            assert!(
                engine
                    .compile_named_with_budget(source, b"=sdk-implicit", &faulted)
                    .is_ok(),
                "{profile:?} ordinal={ordinal} retry"
            );
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);
        }
    }
}
