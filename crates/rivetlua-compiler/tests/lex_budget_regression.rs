use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    LexWorkLimit,
    ParseReached,
}

struct StopAfterLex {
    work_calls: usize,
    lex_work: usize,
    lex_temporary: usize,
}

impl CompileBudgetSink for StopAfterLex {
    type Error = Stop;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work_calls += 1;
        if self.work_calls > 1 {
            return Err(Stop::ParseReached);
        }
        self.lex_work = units;
        (units <= 16 * 1024 * 1024)
            .then_some(())
            .ok_or(Stop::LexWorkLimit)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.lex_temporary = bytes;
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        panic!("測試在 parse admission 必須停止")
    }
}

#[test]
fn valid_large_long_string_reaches_parse_under_bounded_lex_work() {
    let mut source = b"return [=====[".to_vec();
    source.extend_from_slice(&b"]====x".repeat(2700));
    source.extend_from_slice(b"]=====]");
    assert!(source.len() > 16 * 1024 - 256);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = StopAfterLex {
            work_calls: 0,
            lex_work: 0,
            lex_temporary: 0,
        };
        let result = compile_with_budget(
            &source,
            b"=lex-linear-work",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            matches!(
                &result,
                Err(BudgetedCompileError::Budget(Stop::ParseReached))
            ),
            "{profile:?}: {result:?}, lex_work={}",
            sink.lex_work
        );
        assert_eq!(sink.work_calls, 2);
        assert!(sink.lex_work > 0 && sink.lex_temporary > 0);
    }
}
