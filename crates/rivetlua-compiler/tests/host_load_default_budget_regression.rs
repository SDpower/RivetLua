use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
    emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{VerifyLimits, encode_module, verified_module_allocation_bytes};

const WORK: usize = 100_000;
const TEMPORARY: usize = 1024 * 1024;
const MODULE: usize = 8 * 1024 * 1024;

struct DefaultHostSink {
    work: usize,
    temporary: usize,
    module: usize,
}

impl CompileBudgetSink for DefaultHostSink {
    type Error = &'static str;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work = self.work.checked_add(units).ok_or("work overflow")?;
        if self.work > WORK {
            return Err("work limit");
        }
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary = self
            .temporary
            .checked_add(bytes)
            .ok_or("temporary overflow")?;
        if self.temporary > TEMPORARY {
            return Err("temporary limit");
        }
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module = self.module.checked_add(bytes).ok_or("module overflow")?;
        if self.module > MODULE {
            return Err("module limit");
        }
        Ok(())
    }
}

struct Case {
    name: &'static str,
    source: &'static [u8],
    chunkname: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        name: "baseline",
        source: b"return 1",
        chunkname: b"return 1",
    },
    Case {
        name: "explicit-env",
        source: b"return x",
        chunkname: b"return x",
    },
    Case {
        name: "loadfile",
        source: b"return 3, 4",
        chunkname: b"@code.lua",
    },
    Case {
        name: "dofile-stdin",
        source: b"return 5, 6",
        chunkname: b"=stdin",
    },
    Case {
        name: "repository",
        source: b"return marker",
        chunkname: b"pkg/item/init.lua",
    },
    Case {
        name: "rvl",
        source: b"RVL=7; return RVL",
        chunkname: b"RVL=7; return RVL",
    },
    Case {
        name: "rvlu",
        source: b"RVLU=8; return RVLU",
        chunkname: b"RVLU=8; return RVLU",
    },
    Case {
        name: "rvlu-newline",
        source: b"RVLU\n=9; return RVLU",
        chunkname: b"RVLU\n=9; return RVLU",
    },
    Case {
        name: "rvlu-tab",
        source: b"RVLU\t=10; return RVLU",
        chunkname: b"RVLU\t=10; return RVLU",
    },
    Case {
        name: "sdk-load",
        source: b"return 40+2",
        chunkname: b"return 40+2",
    },
    Case {
        name: "sdk-reader",
        source: b"return 31, 32",
        chunkname: b"@code.lua",
    },
];

fn check_profile(profile: LanguageProfile) {
    let mut failures = Vec::new();
    for case in CASES {
        let mut sink = DefaultHostSink {
            work: 0,
            temporary: 0,
            module: 0,
        };
        let result = compile_with_budget(
            case.source,
            case.chunkname,
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        match result {
            Ok(module) => {
                let actual = verified_module_allocation_bytes(&module).unwrap();
                assert!(actual <= sink.module, "{} {profile:?}", case.name);
                assert!(sink.work <= WORK && sink.temporary <= TEMPORARY && sink.module <= MODULE);
                let compile_limits = CompileLimits::default();
                let verify_limits = VerifyLimits::default();
                let lexed = lex(case.source, profile, &compile_limits).unwrap();
                let parsed = parse(&lexed, profile, &compile_limits).unwrap();
                let resolved = resolve(&parsed, &lexed, profile, &compile_limits).unwrap();
                let ir = lower(&resolved, &IrLimits::default()).unwrap();
                let plain = emit_with_native_debug(
                    &ir,
                    &resolved,
                    case.source,
                    case.chunkname,
                    &verify_limits,
                )
                .unwrap();
                assert_eq!(&module, plain.verified(), "{} {profile:?}", case.name);
                let budgeted_bytes =
                    encode_module(module.module().clone(), module.profile(), &verify_limits)
                        .unwrap();
                assert_eq!(budgeted_bytes.bytes(), plain.bytes());
            }
            Err(error) => failures.push(format!(
                "{}: {error:?}; work={} temporary={} module={}",
                case.name, sink.work, sink.temporary, sink.module
            )),
        }
    }
    assert!(failures.is_empty(), "{profile:?}: {failures:#?}");
}

#[test]
fn default_host_budget_compiles_real_sources_lua54() {
    check_profile(LanguageProfile::Lua54);
}

#[test]
fn default_host_budget_compiles_real_sources_lua55() {
    check_profile(LanguageProfile::Lua55);
}
