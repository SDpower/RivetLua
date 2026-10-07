use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

const DEFAULT_WORK: usize = 100_000;
const DEFAULT_TEMPORARY: usize = 1024 * 1024;
const DEFAULT_MODULE: usize = 8 * 1024 * 1024;
const RAISED_WORK: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dimension {
    Work,
    Temporary,
    Module,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Denial {
    dimension: Dimension,
    requested: usize,
    spent_before: usize,
    limit: usize,
    completed_temporary_admissions: usize,
    claim_index: usize,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    dimension: Dimension,
    requested: usize,
    spent_before: usize,
    accepted: bool,
}

struct RecordingSink {
    work_limit: usize,
    temporary_limit: usize,
    module_limit: usize,
    work: usize,
    temporary: usize,
    module: usize,
    temporary_peak: usize,
    completed_temporary_admissions: usize,
    claims: Vec<Claim>,
}

impl RecordingSink {
    fn new(work_limit: usize, temporary_limit: usize) -> Self {
        Self {
            work_limit,
            temporary_limit,
            module_limit: DEFAULT_MODULE,
            work: 0,
            temporary: 0,
            module: 0,
            temporary_peak: 0,
            completed_temporary_admissions: 0,
            claims: Vec::new(),
        }
    }

    fn claim(&mut self, dimension: Dimension, requested: usize) -> Result<(), Denial> {
        let (spent_before, limit) = match dimension {
            Dimension::Work => (self.work, self.work_limit),
            Dimension::Temporary => (self.temporary, self.temporary_limit),
            Dimension::Module => (self.module, self.module_limit),
        };
        let accepted = spent_before
            .checked_add(requested)
            .is_some_and(|total| total <= limit);
        let claim_index = self.claims.len();
        self.claims.push(Claim {
            dimension,
            requested,
            spent_before,
            accepted,
        });
        if !accepted {
            return Err(Denial {
                dimension,
                requested,
                spent_before,
                limit,
                completed_temporary_admissions: self.completed_temporary_admissions,
                claim_index,
            });
        }
        match dimension {
            Dimension::Work => self.work += requested,
            Dimension::Temporary => {
                self.temporary += requested;
                self.temporary_peak = self.temporary_peak.max(self.temporary);
                self.completed_temporary_admissions += 1;
            }
            Dimension::Module => self.module += requested,
        }
        Ok(())
    }
}

impl CompileBudgetSink for RecordingSink {
    type Error = Denial;

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

struct Case {
    label: &'static str,
    source: &'static [u8],
    chunkname: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        label: "baseline-return-1",
        source: b"return 1",
        chunkname: b"return 1",
    },
    Case {
        label: "p13-load-return-x",
        source: b"return x",
        chunkname: b"return x",
    },
    Case {
        label: "p13-loadfile-path",
        source: b"return 3, 4",
        chunkname: b"@code.lua",
    },
    Case {
        label: "p13-dofile-stdin",
        source: b"return 5, 6",
        chunkname: b"=stdin",
    },
    Case {
        label: "p13-repository",
        source: b"return marker",
        chunkname: b"pkg/item/init.lua",
    },
    Case {
        label: "p13-rvl",
        source: b"RVL=7; return RVL",
        chunkname: b"RVL=7; return RVL",
    },
    Case {
        label: "p13-rvlu",
        source: b"RVLU=8; return RVLU",
        chunkname: b"RVLU=8; return RVLU",
    },
    Case {
        label: "p13-rvlu-newline",
        source: b"RVLU\n=9; return RVLU",
        chunkname: b"RVLU\n=9; return RVLU",
    },
    Case {
        label: "p13-rvlu-tab",
        source: b"RVLU\t=10; return RVLU",
        chunkname: b"RVLU\t=10; return RVLU",
    },
    Case {
        label: "sdk-load",
        source: b"return 40+2",
        chunkname: b"return 40+2",
    },
    Case {
        label: "sdk-reader",
        source: b"return 31, 32",
        chunkname: b"@code.lua",
    },
];

fn run_case(
    case: &Case,
    profile: LanguageProfile,
    work: usize,
    temporary: usize,
) -> Result<usize, Denial> {
    let mut sink = RecordingSink::new(work, temporary);
    let result = compile_with_budget(
        case.source,
        case.chunkname,
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut sink,
    );
    for (index, claim) in sink.claims.iter().enumerate() {
        eprintln!(
            "case={} profile={profile:?} caps={work}/{temporary}/{} claim#{index} {:?} request={} before={} accepted={}",
            case.label,
            DEFAULT_MODULE,
            claim.dimension,
            claim.requested,
            claim.spent_before,
            claim.accepted,
        );
    }
    match result {
        Ok(module) => {
            let actual = verified_module_allocation_bytes(&module).unwrap();
            assert!(actual <= sink.module);
            eprintln!(
                "case={} profile={profile:?} caps={work}/{temporary}/{} COMPLETE work={} temporary_cumulative_claimed={} temporary_cumulative_peak={} module_claimed={} module_actual={} claims={}",
                case.label,
                DEFAULT_MODULE,
                sink.work,
                sink.temporary,
                sink.temporary_peak,
                sink.module,
                actual,
                sink.claims.len(),
            );
            Ok(sink.work)
        }
        Err(BudgetedCompileError::Budget(denial)) => {
            eprintln!(
                "case={} profile={profile:?} caps={work}/{temporary}/{} DENIED {denial:?} accepted_work={} accepted_temporary={} temporary_cumulative_peak={} accepted_module={}",
                case.label,
                DEFAULT_MODULE,
                sink.work,
                sink.temporary,
                sink.temporary_peak,
                sink.module,
            );
            assert_eq!(sink.claims[denial.claim_index].accepted, false);
            Err(denial)
        }
        Err(other) => panic!(
            "case={} profile={profile:?} caps={work}/{temporary}/{} 意外語意或驗證拒絕：{other:?}",
            case.label, DEFAULT_MODULE,
        ),
    }
}

#[test]
#[ignore = "需明示執行；記錄 HostLoad 預設來源與不足額拒絕"]
fn record_default_host_load_cases() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for case in CASES {
            let default_complete = run_case(case, profile, DEFAULT_WORK, DEFAULT_TEMPORARY)
                .unwrap_or_else(|denial| panic!("{} {profile:?}: {denial:?}", case.label));
            let raised_complete = run_case(case, profile, RAISED_WORK, DEFAULT_TEMPORARY)
                .unwrap_or_else(|denial| panic!("{} {profile:?}: {denial:?}", case.label));
            assert_eq!(default_complete, raised_complete);
            let denial = run_case(case, profile, default_complete - 1, DEFAULT_TEMPORARY)
                .expect_err("低於實際完整 work 一單位應拒絕");
            assert_eq!(denial.dimension, Dimension::Work);
            assert!(denial.spent_before + denial.requested > denial.limit);
        }
    }
}
