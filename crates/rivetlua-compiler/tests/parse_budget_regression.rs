use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    TemporaryLimit,
    ResolveReached,
}

#[derive(Default)]
struct StopAfterParse {
    work_calls: usize,
    temporary_calls: usize,
    temporary_total: usize,
}

impl CompileBudgetSink for StopAfterParse {
    type Error = Stop;

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        self.work_calls += 1;
        if self.work_calls == 3 {
            Err(Stop::ResolveReached)
        } else {
            Ok(())
        }
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary_calls += 1;
        self.temporary_total += bytes;
        if self.temporary_total > 4 * 1024 * 1024 + 12 * 1024 {
            Err(Stop::TemporaryLimit)
        } else {
            Ok(())
        }
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        panic!("此測試應在 RESOLVE admission 前停止")
    }
}

#[test]
fn twenty_one_short_blocks_reach_resolve_under_cli_temporary_cap() {
    let source = b"do local x=1 end\n".repeat(21);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = StopAfterParse::default();
        let result = compile_with_budget(
            &source,
            b"=parse-budget-regression",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            matches!(
                result,
                Err(BudgetedCompileError::Budget(Stop::ResolveReached))
            ),
            "{profile:?}: {result:?}; work_calls={} temp_calls={} temp_total={}",
            sink.work_calls,
            sink.temporary_calls,
            sink.temporary_total
        );
        assert_eq!((sink.work_calls, sink.temporary_calls), (3, 2));
    }
}
