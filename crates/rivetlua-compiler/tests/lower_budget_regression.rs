use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    WorkLimit,
    TemporaryLimit,
    CandidateReached,
}

struct StopAfterLower {
    work: usize,
    temporary: usize,
    completed_admissions: usize,
    work_claims: Vec<usize>,
    temporary_claims: Vec<usize>,
}

impl CompileBudgetSink for StopAfterLower {
    type Error = Stop;

    fn spend_work(&mut self, units: usize) -> Result<(), Stop> {
        // LEX、PARSE、RESOLVE、LOWER 各以 temporary 申報完成階段。
        // 四段完成後，下一筆 work 是 CANDIDATE 的准入。
        if self.completed_admissions == 4 {
            return Err(Stop::CandidateReached);
        }
        self.work_claims.push(units);
        self.work = self.work.checked_add(units).ok_or(Stop::WorkLimit)?;
        if self.work > 4 * 1024 * 1024 {
            return Err(Stop::WorkLimit);
        }
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Stop> {
        self.temporary_claims.push(bytes);
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
        panic!("此測試應在 CANDIDATE admission 前停止")
    }
}

#[test]
fn twenty_one_short_blocks_reach_candidate_under_bounded_lower_work() {
    let source = b"do local x = 1 end\n".repeat(21);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = StopAfterLower {
            work: 0,
            temporary: 0,
            completed_admissions: 0,
            work_claims: Vec::new(),
            temporary_claims: Vec::new(),
        };
        let result = compile_with_budget(
            &source,
            b"=lower-budget-regression",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            matches!(
                result,
                Err(BudgetedCompileError::Budget(Stop::CandidateReached))
            ),
            "{profile:?}: {result:?}; work={} temporary={} admissions={} work_claims={:?} temporary_claims={:?}",
            sink.work,
            sink.temporary,
            sink.completed_admissions,
            sink.work_claims,
            sink.temporary_claims,
        );
        assert_eq!(sink.completed_admissions, 4);
    }
}

#[test]
fn small_literal_return_keeps_existing_host_budget() {
    #[derive(Debug)]
    struct Record {
        work: usize,
        temporary: usize,
        claims: Vec<usize>,
    }

    impl CompileBudgetSink for Record {
        type Error = ();

        fn spend_work(&mut self, units: usize) -> Result<(), ()> {
            self.claims.push(units);
            self.work += units;
            Ok(())
        }

        fn claim_temporary(&mut self, bytes: usize) -> Result<(), ()> {
            self.temporary += bytes;
            Ok(())
        }

        fn claim_module_allocation(&mut self, _: usize) -> Result<(), ()> {
            Ok(())
        }
    }

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut record = Record {
            work: 0,
            temporary: 0,
            claims: Vec::new(),
        };
        compile_with_budget(
            b"return 7",
            b"=small",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut record,
        )
        .unwrap();
        assert!(record.work <= 100_000, "{profile:?}: {record:?}");
        assert!(record.temporary <= 1024 * 1024);
    }
}
