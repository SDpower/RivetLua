use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    WorkLimit,
    TemporaryLimit,
    LowerReached,
}

struct StopAfterResolve {
    work: usize,
    temporary: usize,
    completed_admissions: usize,
}

impl CompileBudgetSink for StopAfterResolve {
    type Error = Stop;

    fn spend_work(&mut self, units: usize) -> Result<(), Stop> {
        // LEX、PARSE、RESOLVE 各在 work 後完成一次 temporary 申報。
        // 三段都完成後，下一筆 work 必然是 LOWER 的准入。
        if self.completed_admissions == 3 {
            return Err(Stop::LowerReached);
        }
        self.work = self.work.checked_add(units).ok_or(Stop::WorkLimit)?;
        if self.work > 4 * 1024 * 1024 {
            return Err(Stop::WorkLimit);
        }
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Stop> {
        self.temporary = self
            .temporary
            .checked_add(bytes)
            .ok_or(Stop::TemporaryLimit)?;
        if self.temporary > 64 * 1024 * 1024 {
            return Err(Stop::TemporaryLimit);
        }
        self.completed_admissions += 1;
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Stop> {
        panic!("此測試應在 LOWER admission 前停止")
    }
}

#[test]
fn twenty_one_short_blocks_reach_lower_under_bounded_resolve_work() {
    let source = b"do local x=1 end\n".repeat(21);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = StopAfterResolve {
            work: 0,
            temporary: 0,
            completed_admissions: 0,
        };
        let result = compile_with_budget(
            &source,
            b"=resolve-budget-regression",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            matches!(
                result,
                Err(BudgetedCompileError::Budget(Stop::LowerReached))
            ),
            "{profile:?}: {result:?}; work={} temporary={} completed_admissions={}",
            sink.work,
            sink.temporary,
            sink.completed_admissions
        );
        assert_eq!(sink.completed_admissions, 3);
    }
}
