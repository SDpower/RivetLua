use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

const DB_SOURCE: &[u8] = include_bytes!("../../../vendor/lua55/lua-5.5.1-tests/db.lua");
const MAX_WORK: usize = 2 * 1024 * 1024 * 1024;
const MAX_TEMPORARY: usize = 256 * 1024 * 1024;
const MAX_MODULE: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dimension {
    Work,
    Temporary,
    Module,
}

struct Meter {
    work: usize,
    temporary: usize,
    module: usize,
    work_limit: usize,
    temporary_limit: usize,
    module_limit: usize,
}

impl Meter {
    fn unlimited() -> Self {
        Self {
            work: 0,
            temporary: 0,
            module: 0,
            work_limit: usize::MAX,
            temporary_limit: usize::MAX,
            module_limit: usize::MAX,
        }
    }

    fn cli_limits() -> Self {
        Self {
            work_limit: MAX_WORK,
            temporary_limit: MAX_TEMPORARY,
            module_limit: MAX_MODULE,
            ..Self::unlimited()
        }
    }
}

impl CompileBudgetSink for Meter {
    type Error = Dimension;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work = self.work.checked_add(units).ok_or(Dimension::Work)?;
        if self.work > self.work_limit {
            return Err(Dimension::Work);
        }
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary = self
            .temporary
            .checked_add(bytes)
            .ok_or(Dimension::Temporary)?;
        if self.temporary > self.temporary_limit {
            return Err(Dimension::Temporary);
        }
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module = self.module.checked_add(bytes).ok_or(Dimension::Module)?;
        if self.module > self.module_limit {
            return Err(Dimension::Module);
        }
        Ok(())
    }
}

#[test]
fn official_db_load_budget_fits_existing_cli_limits() {
    assert_eq!(DB_SOURCE.len(), 26_598);
    let compile = |meter: &mut Meter| {
        compile_with_budget(
            DB_SOURCE,
            b"@db.lua",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            meter,
        )
    };
    let mut measured = Meter::unlimited();
    let verified = compile(&mut measured).expect("固定 db.lua 應可編譯並通過驗證");
    let actual = verified_module_allocation_bytes(&verified).unwrap();
    assert!(actual <= measured.module);
    assert!(
        measured.work <= MAX_WORK,
        "work={}，上限={MAX_WORK}；temporary={}，module={}",
        measured.work,
        measured.temporary,
        measured.module
    );
    assert!(measured.temporary <= MAX_TEMPORARY);
    assert!(measured.module <= MAX_MODULE);

    let mut bounded = Meter::cli_limits();
    let outcome = compile(&mut bounded);
    assert!(outcome.is_ok(), "既有限額不得拒絕固定 db.lua：{outcome:?}");
    assert_eq!(
        (bounded.work, bounded.temporary, bounded.module),
        (measured.work, measured.temporary, measured.module)
    );
    assert!(!matches!(outcome, Err(BudgetedCompileError::Budget(_))));
}

#[test]
fn initializer_dense_shapes_preserve_each_budget_dimension() {
    let mut source = b"local base=1\n".to_vec();
    for function in 0..8 {
        source.extend_from_slice(format!("local function f{function}()\n").as_bytes());
        for local in 0..16 {
            source.extend_from_slice(
                format!("local v{local}=function() return base end\n").as_bytes(),
            );
        }
        for local in 0..16 {
            source.extend_from_slice(format!("v{local}=v{local}\n").as_bytes());
        }
        source.extend_from_slice(b"return v0\nend\n");
    }
    source.extend_from_slice(b"return f0,f1,f2,f3,f4,f5,f6,f7\n");

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let compile = |meter: &mut Meter| {
            compile_with_budget(
                &source,
                b"@initializer-dense.lua",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                meter,
            )
        };
        let mut measured = Meter::unlimited();
        let verified = compile(&mut measured).unwrap();
        let module = verified.module();
        let debug = verified.native_debug().unwrap();
        let initializer_count = debug
            .prototypes()
            .iter()
            .map(|entry| {
                debug
                    .initializer_temporaries_for(entry.prototype)
                    .unwrap()
                    .len()
            })
            .sum::<usize>();
        let local_count = debug
            .prototypes()
            .iter()
            .map(|entry| entry.locals.len())
            .sum::<usize>();
        let pc_count = module
            .prototypes
            .iter()
            .map(|proto| proto.instructions.len())
            .sum::<usize>();
        assert!(module.prototypes.len() > 100, "{profile:?}");
        assert!(initializer_count > 100, "{profile:?}");
        assert!(local_count > 100, "{profile:?}");
        assert!(pc_count > 500, "{profile:?}");
        assert!(verified_module_allocation_bytes(&verified).unwrap() <= measured.module);

        let mut exact = Meter {
            work_limit: measured.work,
            temporary_limit: measured.temporary,
            module_limit: measured.module,
            ..Meter::unlimited()
        };
        assert!(compile(&mut exact).is_ok(), "{profile:?}");
        assert_eq!(
            (exact.work, exact.temporary, exact.module),
            (measured.work, measured.temporary, measured.module)
        );
        for dimension in [Dimension::Work, Dimension::Temporary, Dimension::Module] {
            let mut denied = Meter {
                work_limit: measured.work,
                temporary_limit: measured.temporary,
                module_limit: measured.module,
                ..Meter::unlimited()
            };
            match dimension {
                Dimension::Work => denied.work_limit -= 1,
                Dimension::Temporary => denied.temporary_limit -= 1,
                Dimension::Module => denied.module_limit -= 1,
            }
            assert!(
                matches!(compile(&mut denied), Err(BudgetedCompileError::Budget(actual)) if actual == dimension),
                "{profile:?} {dimension:?}"
            );
        }
    }
}
