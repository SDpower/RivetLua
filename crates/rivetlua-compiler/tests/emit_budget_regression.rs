use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget,
};
use rivetlua_core::Instruction;
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Limit {
    Work,
    Temporary,
    Retained,
}

#[derive(Debug)]
struct BoundedSink {
    work: usize,
    temporary: usize,
    retained: usize,
    work_limit: usize,
    temporary_limit: usize,
    retained_limit: usize,
    completed_admissions: usize,
    module_claims: usize,
    work_claims: Vec<usize>,
    temporary_claims: Vec<usize>,
}

impl CompileBudgetSink for BoundedSink {
    type Error = Limit;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work_claims.push(units);
        self.work = self.work.checked_add(units).ok_or(Limit::Work)?;
        (self.work <= self.work_limit)
            .then_some(())
            .ok_or(Limit::Work)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary_claims.push(bytes);
        self.temporary = self.temporary.checked_add(bytes).ok_or(Limit::Temporary)?;
        if self.temporary > self.temporary_limit {
            return Err(Limit::Temporary);
        }
        self.completed_admissions += 1;
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module_claims += 1;
        self.retained = self.retained.checked_add(bytes).ok_or(Limit::Retained)?;
        (self.retained <= self.retained_limit)
            .then_some(())
            .ok_or(Limit::Retained)
    }
}

impl BoundedSink {
    fn with_limits(work_limit: usize, temporary_limit: usize, retained_limit: usize) -> Self {
        Self {
            work: 0,
            temporary: 0,
            retained: 0,
            work_limit,
            temporary_limit,
            retained_limit,
            completed_admissions: 0,
            module_claims: 0,
            work_claims: Vec::new(),
            temporary_claims: Vec::new(),
        }
    }
}

#[test]
fn twenty_one_short_blocks_emit_verified_module_under_bounded_budget() {
    let source = b"do local x = 1 end\n".repeat(21);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let mut sink =
            BoundedSink::with_limits(4 * 1024 * 1024, 64 * 1024 * 1024, 64 * 1024 * 1024);
        let result = compile_with_budget(
            &source,
            b"=emit-budget-regression",
            profile,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut sink,
        );
        let module = result.unwrap_or_else(|error| {
            panic!(
                "{profile:?}: {error:?}; work={} temporary={} admissions={} work_claims={:?} temporary_claims={:?}",
                sink.work, sink.temporary, sink.completed_admissions, sink.work_claims, sink.temporary_claims
            )
        });
        assert_eq!(sink.completed_admissions, 6, "{profile:?}");
        assert!(sink.retained > 0);
        assert!(module.native_debug().is_some());
        assert_eq!(module.module().prototypes.len(), 1);
        assert!(verified_module_allocation_bytes(&module).unwrap() <= sink.retained);
    }
}

#[test]
fn emit_verified_debug_and_plan_shapes_across_profiles() {
    let common: &[&[u8]] = &[
        b"return 7",
        b"local x=1; if x then x=x+1 else x=x-1 end; while x<4 do x=x+1 end; return x",
        b"for i=1,4 do local x=i end; return 1",
        b"goto done; ::done:: return 1",
        b"local x=1; local function outer(y) return function() return x+y end end; return outer(2)",
        b"local f; do local a <close> = f(); local b <close> = f() end; return 1",
        b"local f; do local a <close> = f(); goto done end ::done:: return 1",
        b"local f; return 1,f()",
        b"local f; return {1,f()}",
        b"local function f(...) return ... end; return f(1,2)",
        b"local t={v=0}; function t:m(x) self.v=self.v+x end; repeat t:m(1) until t.v>1; return t.v",
    ];
    let mut large_literal = b"return '".to_vec();
    large_literal.extend_from_slice(&[b'a'; 4096]);
    large_literal.push(b'\'');
    let mut long_name = b"local ".to_vec();
    long_name.extend_from_slice(&[b'n'; 1024]);
    long_name.extend_from_slice(b"=1; return ");
    long_name.extend_from_slice(&[b'n'; 1024]);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for source in common
            .iter()
            .copied()
            .chain([large_literal.as_slice(), long_name.as_slice()])
        {
            let mut sink = BoundedSink::with_limits(usize::MAX, usize::MAX, usize::MAX);
            let module = compile_with_budget(
                source,
                b"=emit-shapes",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut sink,
            )
            .unwrap_or_else(|error| panic!("{profile:?} {source:?}: {error:?}"));
            assert_eq!(sink.completed_admissions, 6);
            assert_eq!(sink.module_claims, 1);
            assert!(module.native_debug().is_some());
            assert!(verified_module_allocation_bytes(&module).unwrap() <= sink.retained);
            if source == common[2] {
                assert!(module.module().prototypes.iter().any(|proto| {
                    proto.instructions.iter().any(|entry| {
                        matches!(entry.instruction, Instruction::NumericForPrepare { .. })
                    })
                }));
            }
            if source == common[4] {
                assert!(module.module().prototypes.len() >= 3);
                assert!(module.module().prototypes.iter().any(|proto| {
                    proto.instructions.iter().any(|entry| {
                        matches!(entry.instruction, Instruction::Close { count: 0, .. })
                    })
                }));
            }
            if source == common[5] {
                let closes = module
                    .module()
                    .prototypes
                    .iter()
                    .flat_map(|proto| &proto.instructions)
                    .filter(|entry| {
                        matches!(entry.instruction, Instruction::Close { count: 1, .. })
                    })
                    .count();
                assert!(closes >= 2);
            }
            if source == common[8] {
                assert!(module.official_execution().is_some());
            }
        }
        if profile == LanguageProfile::Lua55 {
            let mut sink = BoundedSink::with_limits(usize::MAX, usize::MAX, usize::MAX);
            let module = compile_with_budget(
                b"local function f(... args) return args[1] end; return f(7)",
                b"=emit-named-vararg",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut sink,
            )
            .unwrap();
            assert!(module.native_debug().is_some());
            assert!(verified_module_allocation_bytes(&module).unwrap() <= sink.retained);
        }
    }
}

#[test]
fn emit_exact_and_one_below_limits_are_typed_before_emission() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source = b"local f; do local a <close> = f() end; return {1,f()}";
        let run = |sink: &mut BoundedSink| {
            compile_with_budget(
                source,
                b"=emit-exact",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                sink,
            )
        };
        let mut ample = BoundedSink::with_limits(usize::MAX, usize::MAX, usize::MAX);
        let module = run(&mut ample).unwrap();
        assert!(verified_module_allocation_bytes(&module).unwrap() <= ample.retained);
        assert_eq!(ample.module_claims, 1);
        assert!(ample.work_claims.len() >= 3);

        let mut exact = BoundedSink::with_limits(ample.work, ample.temporary, ample.retained);
        assert!(run(&mut exact).is_ok());
        let mut short_work = BoundedSink::with_limits(ample.work - 1, usize::MAX, usize::MAX);
        assert!(matches!(
            run(&mut short_work),
            Err(BudgetedCompileError::Budget(Limit::Work))
        ));
        assert_eq!(short_work.completed_admissions, 5);
        assert_eq!(short_work.module_claims, 0);
        let before_emit: usize = ample.work_claims[..ample.work_claims.len() - 3]
            .iter()
            .sum();
        let mut denied_metadata = BoundedSink::with_limits(before_emit, usize::MAX, usize::MAX);
        assert!(matches!(
            run(&mut denied_metadata),
            Err(BudgetedCompileError::Budget(Limit::Work))
        ));
        assert_eq!(denied_metadata.completed_admissions, 5);
        assert_eq!(denied_metadata.module_claims, 0);
        let after_shape_prepay = before_emit + ample.work_claims[ample.work_claims.len() - 3];
        let mut denied_name = BoundedSink::with_limits(after_shape_prepay, usize::MAX, usize::MAX);
        assert!(matches!(
            run(&mut denied_name),
            Err(BudgetedCompileError::Budget(Limit::Work))
        ));
        assert_eq!(denied_name.completed_admissions, 5);
        assert_eq!(denied_name.module_claims, 0);
        assert_eq!(denied_name.work_claims.len(), ample.work_claims.len() - 1);

        let mut short_temp = BoundedSink::with_limits(usize::MAX, ample.temporary - 1, usize::MAX);
        assert!(matches!(
            run(&mut short_temp),
            Err(BudgetedCompileError::Budget(Limit::Temporary))
        ));
        assert_eq!(short_temp.completed_admissions, 5);
        assert_eq!(short_temp.module_claims, 0);
        let mut short_retained =
            BoundedSink::with_limits(usize::MAX, usize::MAX, ample.retained - 1);
        assert!(matches!(
            run(&mut short_retained),
            Err(BudgetedCompileError::Budget(Limit::Retained))
        ));
        assert_eq!(short_retained.completed_admissions, 6);
        assert_eq!(short_retained.module_claims, 1);
    }
}
