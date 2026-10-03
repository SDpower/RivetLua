use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::VerifyLimits;

#[derive(Default)]
struct Probe {
    work: usize,
    temporary: usize,
    module: usize,
    work_limit: usize,
    temporary_limit: usize,
    module_limit: usize,
    calls: usize,
    fail_at: Option<usize>,
}

impl Probe {
    fn unlimited() -> Self {
        Self {
            work_limit: usize::MAX,
            temporary_limit: usize::MAX,
            module_limit: usize::MAX,
            ..Self::default()
        }
    }
}

impl CompileBudgetSink for Probe {
    type Error = ();

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            return Err(());
        }
        self.work = self.work.checked_add(units).ok_or(())?;
        (self.work <= self.work_limit).then_some(()).ok_or(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            return Err(());
        }
        self.temporary = self.temporary.checked_add(bytes).ok_or(())?;
        (self.temporary <= self.temporary_limit)
            .then_some(())
            .ok_or(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            return Err(());
        }
        self.module = self.module.checked_add(bytes).ok_or(())?;
        (self.module <= self.module_limit).then_some(()).ok_or(())
    }
}

fn compile(
    source: &[u8],
    chunk_name: &[u8],
    profile: LanguageProfile,
    sink: &mut Probe,
) -> Result<rivetlua_core::VerifiedModule, BudgetedCompileError<()>> {
    compile_with_budget(
        source,
        chunk_name,
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        sink,
    )
}

#[test]
fn compiler_budget_exact_and_one_below_each_dimension_both_profiles() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source = b"local x=7; local function f(y) return x+y end; return f(5)";
        let mut ample = Probe::unlimited();
        let module = compile(source, b"=budget", profile, &mut ample).unwrap();
        assert_eq!(module.module().prototypes.len(), 2);
        assert!(ample.work > 0 && ample.temporary > 0 && ample.module > 0);
        for dimension in 0..3 {
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            exact.module_limit = ample.module;
            assert!(compile(source, b"=budget", profile, &mut exact).is_ok());
            let mut one_below = Probe::unlimited();
            one_below.work_limit = ample.work - usize::from(dimension == 0);
            one_below.temporary_limit = ample.temporary - usize::from(dimension == 1);
            one_below.module_limit = ample.module - usize::from(dimension == 2);
            assert!(matches!(
                compile(source, b"=budget", profile, &mut one_below),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }
}

#[test]
fn compiler_budget_keeps_frontend_error_and_retry_separate() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = Probe::unlimited();
        assert!(matches!(
            compile(b"return +", b"=error", profile, &mut sink),
            Err(BudgetedCompileError::Frontend(_))
        ));
        let mut denied = Probe::unlimited();
        denied.work_limit = 0;
        assert!(matches!(
            compile(b"return 7", b"=retry", profile, &mut denied),
            Err(BudgetedCompileError::Budget(()))
        ));
        let mut retry = Probe::unlimited();
        assert!(compile(b"return 7", b"=retry", profile, &mut retry).is_ok());
    }
}

#[test]
fn compiler_budget_covers_long_names_labels_strings_chunkname_and_native_plan() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let name = vec![b'a'; 4096];
        let mut source = b"::".to_vec();
        source.extend(&name);
        source.extend(b":: local x = '");
        source.extend(vec![b'z'; 512]);
        source.extend(b"'; goto ");
        source.extend(&name);
        source.extend(b"; return x");
        let chunk_name = b"\xff\0budget-chunk";
        let mut ample = Probe::unlimited();
        let module = compile(&source, chunk_name, profile, &mut ample).unwrap();
        assert_eq!(module.native_debug().unwrap().source_name(), chunk_name);
        assert_eq!(module.module().prototypes.len(), 1);
        for source in [
            b"return {...}".as_slice(),
            b"local function f(x) return function(y) return x+y end end; return f(3)(4)".as_slice(),
            b"return 'a','b','c','d','e','f','g','h'".as_slice(),
            b"for i=1,3 do if i==2 then break end end; return 7".as_slice(),
            b"local x=1; while x<4 do x=x+1 end; return x".as_slice(),
        ] {
            let mut budget = Probe::unlimited();
            assert!(compile(source, b"=dense", profile, &mut budget).is_ok());
        }
        let mut captured = b"local ".to_vec();
        captured.extend(&name);
        captured.extend(b"=7; local function f() return ");
        captured.extend(&name);
        captured.extend(b" end; return f()");
        let mut budget = Probe::unlimited();
        assert!(compile(&captured, b"=long-capture", profile, &mut budget).is_ok());
    }
}

#[test]
fn compiler_budget_each_stage_fault_retries_without_partial_module() {
    let source = b"local function f(x) return x+1 end; return f(9)";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut successful = Probe::unlimited();
        assert!(compile(source, b"=fault", profile, &mut successful).is_ok());
        assert!(successful.calls >= 10);
        for ordinal in 0..successful.calls {
            let mut denied = Probe::unlimited();
            denied.fail_at = Some(ordinal);
            assert!(
                matches!(
                    compile(source, b"=fault", profile, &mut denied),
                    Err(BudgetedCompileError::Budget(()))
                ),
                "{profile:?} ordinal {ordinal}"
            );
            let mut retry = Probe::unlimited();
            assert!(compile(source, b"=fault", profile, &mut retry).is_ok());
        }
    }
}

#[test]
fn compiler_budget_preserves_ir_bytecode_and_overflow_errors() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = Probe::unlimited();
        let mut ir = IrLimits::default();
        ir.max_prototypes = 0;
        assert!(matches!(
            compile_with_budget(
                b"return 7",
                b"=ir",
                profile,
                &CompileLimits::default(),
                &ir,
                &VerifyLimits::default(),
                &mut sink
            ),
            Err(BudgetedCompileError::Ir(_))
        ));
        let mut sink = Probe::unlimited();
        let mut verify = VerifyLimits::default();
        verify.max_instructions = 0;
        assert!(matches!(
            compile_with_budget(
                b"return 7",
                b"=bytecode",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &verify,
                &mut sink
            ),
            Err(BudgetedCompileError::Bytecode(_))
        ));
        let mut sink = Probe::unlimited();
        let mut ir = IrLimits::default();
        ir.max_instructions = usize::MAX;
        assert!(matches!(
            compile_with_budget(
                b"local function f() return 7 end; return f()",
                b"=overflow",
                profile,
                &CompileLimits::default(),
                &ir,
                &VerifyLimits::default(),
                &mut sink
            ),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
    }
}

#[test]
fn compiler_budget_small_source_fits_host_load_defaults() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink = Probe::unlimited();
        sink.work_limit = 100_000;
        sink.temporary_limit = 1024 * 1024;
        sink.module_limit = 8 * 1024 * 1024;
        let module = compile(b"return 7", b"=small", profile, &mut sink).unwrap();
        assert_eq!(module.module().prototypes.len(), 1);
    }
}
