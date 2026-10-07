use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    NumericWork,
    WrongStage,
}

#[derive(Default)]
struct StopAtNumeric {
    work_calls: Vec<usize>,
}

impl CompileBudgetSink for StopAtNumeric {
    type Error = Stop;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work_calls.push(units);
        if self.work_calls.len() == 1 {
            return Ok(());
        }
        Err(if units == 512 + 64 * 4 {
            Stop::NumericWork
        } else {
            Stop::WrongStage
        })
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        panic!("數字轉換額外 work 必須先於模組申報")
    }
}

#[test]
fn decimal_conversion_claims_extra_work_before_parse_admission() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = StopAtNumeric::default();
        let result = compile_with_budget(
            b"return 1.25",
            b"=numeric-budget-red",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            matches!(result, Err(BudgetedCompileError::Budget(Stop::NumericWork))),
            "{profile:?}: {result:?}; work={:?}",
            sink.work_calls
        );
        assert_eq!(sink.work_calls.len(), 2);
    }
}
