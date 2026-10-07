use rivetlua_compiler::{
    CompileLimits, Instruction, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower,
    parse, resolve,
};
use rivetlua_core::{InstructionOffset, VerifyLimits};

fn inspect(
    source: &[u8],
    profile: LanguageProfile,
) -> (rivetlua_compiler::IrModule, rivetlua_core::VerifiedModule) {
    let limits = CompileLimits::default();
    let tokens = lex(source, profile, &limits).unwrap();
    let ast = parse(&tokens, profile, &limits).unwrap();
    let resolved = resolve(&ast, &tokens, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let verified = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@initializer.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone();
    (ir, verified)
}

#[test]
fn single_closure_initializer_has_one_future_slot_and_one_count_anchor() {
    let source = b"local A = function ()\n  return x\nend\nreturn A";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (ir, verified) = inspect(source, profile);
        let root = &ir.prototypes[0];
        let sidecar = root.native_debug.as_ref().unwrap();
        let initializer = &sidecar.initializer_temporaries;
        assert_eq!(initializer.len(), 1, "{profile:?}: {initializer:?}");
        assert_eq!((initializer[0].start_pc, initializer[0].end_pc), (0, 4));
        assert_eq!(initializer[0].slot, 0);
        assert!(matches!(
            root.instructions[0].instruction,
            Instruction::Closure { .. }
        ));
        assert!(root.instructions[1..4].iter().all(|entry| {
            matches!(
                entry.instruction,
                Instruction::Move { .. } | Instruction::LoadNil { .. }
            )
        }));
        assert!(!sidecar.non_counted_pcs.contains(&InstructionOffset(0)));
        for pc in 1..4 {
            assert!(
                sidecar.non_counted_pcs.contains(&InstructionOffset(pc)),
                "{profile:?}: PC {pc}"
            );
        }
        let native = verified.native_debug().unwrap();
        assert_eq!(
            &native.prototype(root.id).unwrap().lines[..4],
            &[3, 3, 3, 3]
        );
        assert_eq!(
            native.initializer_temporaries_for(root.id).unwrap().len(),
            1
        );
    }
}

#[test]
fn nested_multiple_missing_and_multivalue_initializers_keep_slot_order() {
    let source = b"local outer=1\ndo\n local a,b=2,3\n local c,d=a\n local e,f=(function() return 5,6 end)()\n return outer,a,b,c,d,e,f\nend";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (ir, verified) = inspect(source, profile);
        let root = &ir.prototypes[0];
        let native = verified.native_debug().unwrap();
        let entries = native.initializer_temporaries_for(root.id).unwrap();
        let locals = &native.prototype(root.id).unwrap().locals;
        for name in [b"outer".as_slice(), b"a", b"b", b"c", b"d", b"e", b"f"] {
            let local = locals.iter().find(|local| local.name == name).unwrap();
            let entry = entries
                .iter()
                .find(|entry| entry.binding == local.binding)
                .unwrap();
            assert_eq!(
                (entry.register, entry.slot, entry.end_pc),
                (local.register, local.slot, local.start_pc),
                "{profile:?}: {name:?}"
            );
        }
        assert!(entries.windows(2).all(|pair| {
            pair[0].start_pc < pair[1].start_pc
                || pair[0].start_pc == pair[1].start_pc && pair[0].slot < pair[1].slot
        }));
    }
}

#[test]
fn loop_reentry_does_not_expose_unproven_future_slot() {
    let source = b"for i=1,2 do local z=i end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (ir, verified) = inspect(source, profile);
        let root = &ir.prototypes[0];
        let native = verified.native_debug().unwrap();
        let z = native
            .prototype(root.id)
            .unwrap()
            .locals
            .iter()
            .find(|local| local.name == b"z")
            .unwrap();
        assert!(
            native
                .initializer_temporaries_for(root.id)
                .unwrap()
                .iter()
                .all(|entry| entry.binding != z.binding)
        );
    }
}

#[test]
fn captured_and_to_be_closed_locals_keep_their_verified_lifetimes() {
    let source = b"local captured=1; do local c <close> = nil; local f=function() return captured end; return f end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (ir, verified) = inspect(source, profile);
        let root = &ir.prototypes[0];
        let native = verified.native_debug().unwrap();
        let locals = &native.prototype(root.id).unwrap().locals;
        let intervals = native.initializer_temporaries_for(root.id).unwrap();
        for name in [b"captured".as_slice(), b"c", b"f"] {
            let local = locals.iter().find(|local| local.name == name).unwrap();
            let interval = intervals
                .iter()
                .find(|entry| entry.binding == local.binding)
                .unwrap();
            assert_eq!(interval.end_pc, local.start_pc);
            assert_eq!(interval.register, local.register);
            assert!(interval.end_pc <= local.end_pc);
        }
        let c = locals.iter().find(|local| local.name == b"c").unwrap();
        assert!(
            root.instructions[c.initialized_pc as usize]
                .close_path
                .is_some()
        );
    }
}
