use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget, emit,
    emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{Instruction, VerifyLimits};

struct Unlimited;

impl CompileBudgetSink for Unlimited {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn captured_root_implicit_return_closes_upvalue_before_storage_ends() {
    let source = b"local x=7\nlocal f=function() return x end\n";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let return_pc = root
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::Return { .. }))
            .unwrap();
        let close_pcs: Vec<_> = root.instructions[..return_pc]
            .iter()
            .enumerate()
            .filter_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::Close { count: 0, .. }).then_some(pc)
            })
            .collect();
        assert_eq!(resolved.root.error_close_path.exited_bindings.len(), 2);
        assert!(resolved.root.error_close_path.bindings.is_empty());
        assert_eq!(close_pcs, [return_pc - 1], "{profile:?}");
        let close_register = match root.instructions[close_pcs[0]].instruction {
            Instruction::Close { base, count: 0 } => base,
            ref other => panic!("預期捕獲 local 的 Close：{other:?}"),
        };
        let captured_local = root
            .native_debug
            .as_ref()
            .unwrap()
            .locals
            .iter()
            .find(|local| local.register == close_register)
            .unwrap();
        assert_eq!(captured_local.end_pc as usize, return_pc);
        let verify = VerifyLimits::default();
        assert!(emit(&ir, &verify).is_ok(), "{profile:?}: RVLU candidate");
        let unbudgeted = emit_with_native_debug(&ir, &resolved, source, b"=implicit", &verify);
        let budgeted = compile_with_budget(
            source,
            b"=implicit",
            profile,
            &limits,
            &IrLimits::default(),
            &verify,
            &mut Unlimited,
        );
        assert!(unbudgeted.is_ok(), "{profile:?}: {unbudgeted:?}");
        assert!(budgeted.is_ok(), "{profile:?}: {budgeted:?}");
    }
}

#[test]
fn uncaptured_implicit_return_adds_no_close_and_explicit_paths_stay_valid() {
    let cases: &[(&str, &[u8], bool)] = &[
        ("uncaptured", b"local x=7\nlocal f=8\n", false),
        (
            "explicit",
            b"local x=7; local f=function() return x end; return f()",
            true,
        ),
        ("tail", b"local function f() return 7 end; return f()", true),
    ];
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source, explicit) in cases {
            let limits = CompileLimits::default();
            let lexed = lex(source, profile, &limits).unwrap();
            let ast = parse(&lexed, profile, &limits).unwrap();
            let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            if !explicit {
                assert!(ir.prototypes[0].instructions.iter().all(|entry| {
                    !matches!(entry.instruction, Instruction::Close { count: 0, .. })
                }));
            }
            let verify = VerifyLimits::default();
            assert!(
                emit_with_native_debug(&ir, &resolved, source, name.as_bytes(), &verify).is_ok(),
                "{profile:?}/{name}: unbudgeted"
            );
            assert!(
                compile_with_budget(
                    source,
                    name.as_bytes(),
                    profile,
                    &limits,
                    &IrLimits::default(),
                    &verify,
                    &mut Unlimited,
                )
                .is_ok(),
                "{profile:?}/{name}: budgeted"
            );
        }
    }
}

#[test]
fn root_locals_end_in_slot_order_across_implicit_close_group() {
    let cases: &[(&str, &[u8], &[u8])] = &[
        (
            "uncaptured-before-capture",
            b"local a=1\nlocal x=7\nlocal f=function() return x end\n",
            b"local x=7\nlocal f=function() return x end\n",
        ),
        (
            "assignment-observable",
            b"local a,b\nlocal f=function() b=1 end\nf()\nprint(b)\n",
            b"local b\nlocal f=function() b=1 end\nf()\nprint(b)\n",
        ),
    ];
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source, control) in cases {
            let limits = CompileLimits::default();
            let lexed = lex(source, profile, &limits).unwrap();
            let ast = parse(&lexed, profile, &limits).unwrap();
            let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let root = &ir.prototypes[0];
            let return_pc = root
                .instructions
                .iter()
                .rposition(|entry| matches!(entry.instruction, Instruction::Return { .. }))
                .unwrap();
            let close_start = root.instructions[..return_pc]
                .iter()
                .rposition(|entry| !matches!(entry.instruction, Instruction::Close { .. }))
                .map_or(0, |pc| pc + 1);
            assert!(close_start < return_pc, "{profile:?}/{name}");
            assert!(emit(&ir, &VerifyLimits::default()).is_ok());
            let locals = &root.native_debug.as_ref().unwrap().locals;
            assert_eq!(locals.len(), 3, "{profile:?}/{name}");
            assert!(
                locals
                    .iter()
                    .all(|local| local.end_pc as usize == return_pc),
                "{profile:?}/{name}: {locals:?}"
            );
            let native = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                name.as_bytes(),
                &VerifyLimits::default(),
            );
            let budgeted = compile_with_budget(
                source,
                name.as_bytes(),
                profile,
                &limits,
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut Unlimited,
            );
            assert!(native.is_ok(), "{profile:?}/{name}: {native:?}");
            assert!(budgeted.is_ok(), "{profile:?}/{name}: {budgeted:?}");
            let control_native = {
                let lexed = lex(control, profile, &limits).unwrap();
                let ast = parse(&lexed, profile, &limits).unwrap();
                let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
                let ir = lower(&resolved, &IrLimits::default()).unwrap();
                emit_with_native_debug(
                    &ir,
                    &resolved,
                    control,
                    name.as_bytes(),
                    &VerifyLimits::default(),
                )
            };
            assert!(control_native.is_ok(), "{profile:?}/{name} control");
            assert!(
                compile_with_budget(
                    control,
                    name.as_bytes(),
                    profile,
                    &limits,
                    &IrLimits::default(),
                    &VerifyLimits::default(),
                    &mut Unlimited,
                )
                .is_ok(),
                "{profile:?}/{name} budgeted control"
            );
        }
    }
}

#[test]
fn completed_nested_scope_at_close_start_keeps_its_own_end_pc() {
    let source = b"local a=1\nlocal x=7\nlocal f=function() return x end\ndo local nested=2 end\n";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let return_pc = root.instructions.len() - 1;
        assert!(matches!(
            root.instructions[return_pc].instruction,
            Instruction::Return { .. }
        ));
        let close_start = root.instructions[..return_pc]
            .iter()
            .rposition(|entry| !matches!(entry.instruction, Instruction::Close { .. }))
            .map_or(0, |pc| pc + 1);
        assert!(close_start < return_pc);
        let locals = &root.native_debug.as_ref().unwrap().locals;
        assert_eq!(locals.len(), 4);
        let nested = locals
            .iter()
            .find(|local| {
                !resolved
                    .root
                    .error_close_path
                    .exited_bindings
                    .contains(&local.binding)
            })
            .unwrap();
        assert_eq!(nested.end_pc as usize, close_start, "{profile:?}");
        for local in locals
            .iter()
            .filter(|local| local.binding != nested.binding)
        {
            assert_eq!(local.end_pc as usize, return_pc, "{profile:?}");
        }
        assert!(
            emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"=nested-scope",
                &VerifyLimits::default(),
            )
            .is_ok(),
            "{profile:?}"
        );
    }
}
