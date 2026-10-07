use rivetlua_compiler::{
    CompileLimits, Instruction, IrLimits, LanguageProfile, Register, emit_with_native_debug, lex,
    lower, parse, resolve,
};
use rivetlua_core::{
    BytecodeErrorCode, InstructionOffset, NativeDebugCandidate, NativeTemporary,
    OfficialWorkBudget, VerifyLimits, verify_native_debug,
};

fn lowered(source: &[u8], profile: LanguageProfile) -> rivetlua_compiler::IrModule {
    let limits = CompileLimits::default();
    let tokens = lex(source, profile, &limits).unwrap();
    let ast = parse(&tokens, profile, &limits).unwrap();
    let resolved = resolve(&ast, &tokens, profile, &limits).unwrap();
    lower(&resolved, &IrLimits::default()).unwrap()
}

#[test]
fn native_debug_temporaries_follow_pending_expression_results_in_order() {
    let source =
        b"function f() return 20 end\nfunction g(a,b) return ((a+1)+(b+2))+f((a+3)+f()) end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let ir = lowered(source, profile);
        let g = &ir.prototypes[2];
        let temporary = &g.native_debug.as_ref().unwrap().temporaries;
        let call_pcs: Vec<_> = g
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::Call { .. }).then_some(pc)
            })
            .collect();
        assert_eq!(call_pcs.len(), 2, "{profile:?}");
        let inner: Vec<_> = temporary
            .iter()
            .filter(|entry| entry.call_pc.0 as usize == call_pcs[0])
            .collect();
        assert_eq!(inner.len(), 3, "{profile:?}: {temporary:?}");
        assert_eq!(
            inner.iter().map(|entry| entry.ordinal).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(
            inner
                .windows(2)
                .all(|pair| pair[0].register != pair[1].register)
        );
        let outer: Vec<_> = temporary
            .iter()
            .filter(|entry| entry.call_pc.0 as usize == call_pcs[1])
            .collect();
        assert_eq!(outer.len(), 1, "{profile:?}: {temporary:?}");
        assert_eq!(outer[0].ordinal, 1);
        assert_eq!(outer[0].register, inner[0].register);
    }
}

#[test]
fn native_debug_temporaries_exclude_active_locals_current_inputs_and_internal_helpers() {
    let source = b"function f(a,b) return a+b end\nfunction g(a,b) return a+f(a,b) end\nfunction h() return {f()} end\nfunction j() return {[1]=f()} end\nfunction k(a,b) return f(a,f(b,1)) end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let ir = lowered(source, profile);
        for proto in &ir.prototypes[..ir.prototypes.len() - 1] {
            assert!(
                proto.native_debug.as_ref().unwrap().temporaries.is_empty(),
                "{profile:?}: {:?}",
                proto.id,
            );
        }
        let nested = ir.prototypes.last().unwrap();
        let inner_call = nested
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::Call { .. }))
            .unwrap();
        let pending: Vec<_> = nested
            .native_debug
            .as_ref()
            .unwrap()
            .temporaries
            .iter()
            .filter(|entry| entry.call_pc.0 as usize == inner_call)
            .collect();
        assert_eq!(pending.len(), 2, "{profile:?}: {pending:?}");
        let outer_base = nested
            .instructions
            .iter()
            .find_map(|entry| match entry.instruction {
                Instruction::TailCall { base, .. } => Some(base),
                _ => None,
            })
            .unwrap();
        for (index, entry) in pending.iter().enumerate() {
            assert_eq!(entry.ordinal, (index + 1) as u16);
            assert_eq!(entry.register, Register(outer_base.0 + index as u16));
            assert!(
                nested
                    .native_debug
                    .as_ref()
                    .unwrap()
                    .locals
                    .iter()
                    .all(|local| local.register != entry.register)
            );
        }
        assert!(nested.instructions[inner_call + 1..].iter().any(|entry| {
            match entry.instruction {
                Instruction::Move { src, .. } => src == pending[0].register,
                Instruction::Call {
                    base, arg_count, ..
                }
                | Instruction::TailCall {
                    base, arg_count, ..
                } => pending[0].register.0 >= base.0 && pending[0].register.0 - base.0 <= arg_count,
                _ => false,
            }
        }));
    }
}

#[test]
fn native_debug_temporaries_include_nested_call_prefix_in_official_slot_order() {
    for (source, expected) in [
        (
            b"function f() return 19 end\nfunction g() local x={x=19}; return assert(x.x==f()) end"
                .as_slice(),
            2usize,
        ),
        (
            b"function f() return 5 end\nfunction outer(a,b,c) return a+b+c end\nfunction g() return outer(11,22,f()) end"
                .as_slice(),
            3usize,
        ),
        (
            b"function f() return 5 end\nobj={m=function(self,a,b) return a+b end}\nfunction g() return obj:m(11,f()) end"
                .as_slice(),
            3usize,
        ),
    ] {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let ir = lowered(source, profile);
            let g = ir.prototypes.last().unwrap();
            let inner_call = g
                .instructions
                .iter()
                .position(|entry| matches!(entry.instruction, Instruction::Call { .. }))
                .unwrap();
            let pending: Vec<_> = g
                .native_debug
                .as_ref()
                .unwrap()
                .temporaries
                .iter()
                .filter(|entry| entry.call_pc.0 as usize == inner_call)
                .collect();
            assert_eq!(pending.len(), expected, "{profile:?}: {pending:?}");
            assert_eq!(
                pending.iter().map(|entry| entry.ordinal).collect::<Vec<_>>(),
                (1..=expected as u16).collect::<Vec<_>>(),
                "{profile:?}: {pending:?}"
            );
            assert!(pending
                .windows(2)
                .all(|pair| pair[0].register != pair[1].register));
        }
    }
}

#[test]
fn native_debug_open_chain_retains_all_pending_prefixes() {
    let open_source = b"local func=load(string.dump(load('print(10)'), true)); return func";
    let selective_source = b"function probe() return 4 end\nfunction fixed(a,b) return a+b end\nfunction values() return 6,7 end\nfunction outer(...) return ... end\nfunction g() local x=outer(fixed(11,probe()+0), values()); local check=assert(1==probe()); return x,check end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let ir = lowered(open_source, profile);
        let root = &ir.prototypes[0];
        let open_calls: Vec<_> = root
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::Call { .. }).then_some(pc)
            })
            .collect();
        assert_eq!(open_calls.len(), 3, "{profile:?}");
        let open_counts: Vec<_> = open_calls
            .iter()
            .map(|pc| {
                root.native_debug
                    .as_ref()
                    .unwrap()
                    .temporaries
                    .iter()
                    .filter(|entry| entry.call_pc.0 as usize == *pc)
                    .count()
            })
            .collect();
        assert_eq!(open_counts, [2, 1, 0], "{profile:?}");

        let ir = lowered(selective_source, profile);
        let g = ir.prototypes.last().unwrap();
        let calls: Vec<_> = g
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::Call { .. }).then_some(pc)
            })
            .collect();
        assert_eq!(calls.len(), 6, "{profile:?}");
        let counts: Vec<_> = calls
            .iter()
            .map(|pc| {
                g.native_debug
                    .as_ref()
                    .unwrap()
                    .temporaries
                    .iter()
                    .filter(|entry| entry.call_pc.0 as usize == *pc)
                    .count()
            })
            .collect();
        assert_eq!(counts, [3, 1, 2, 0, 2, 0], "{profile:?}");
        for (pc, count) in calls.iter().zip(counts) {
            let ordinals: Vec<_> = g
                .native_debug
                .as_ref()
                .unwrap()
                .temporaries
                .iter()
                .filter(|entry| entry.call_pc.0 as usize == *pc)
                .map(|entry| entry.ordinal)
                .collect();
            assert_eq!(
                ordinals,
                (1..=count as u16).collect::<Vec<_>>(),
                "{profile:?} pc={pc}"
            );
        }
    }
}

#[test]
fn native_debug_open_last_uses_copied_active_local_prefix_once() {
    for (source, expected) in [
        (
            b"local function f(...) return ... end\nlocal function g() return 2,3 end\nreturn f(11,g())"
                .as_slice(),
            2usize,
        ),
        (
            b"local obj={}\nlocal n=11\nfunction obj:m(...) return ... end\nlocal function g() return 2,3 end\nreturn obj:m(n,g())"
                .as_slice(),
            3usize,
        ),
    ] {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let ir = lowered(source, profile);
            let root = &ir.prototypes[0];
            let nested_pc = root
                .instructions
                .iter()
                .position(|entry| matches!(entry.instruction, Instruction::Call { .. }))
                .unwrap();
            let outer_base = root
                .instructions
                .iter()
                .find_map(|entry| match entry.instruction {
                    Instruction::TailCall { base, .. } => Some(base),
                    _ => None,
                })
                .unwrap();
            let pending: Vec<_> = root
                .native_debug
                .as_ref()
                .unwrap()
                .temporaries
                .iter()
                .filter(|entry| entry.call_pc.0 as usize == nested_pc)
                .collect();
            assert_eq!(pending.len(), expected, "{profile:?}: {pending:?}");
            for (index, entry) in pending.iter().enumerate() {
                assert_eq!(entry.ordinal, (index + 1) as u16, "{profile:?}");
                assert_eq!(
                    entry.register,
                    Register(outer_base.0 + index as u16),
                    "{profile:?}"
                );
                assert!(
                    root.native_debug
                        .as_ref()
                        .unwrap()
                        .locals
                        .iter()
                        .all(|local| local.register != entry.register),
                    "{profile:?}: {pending:?}"
                );
            }
            let limits = CompileLimits::default();
            let tokens = lex(source, profile, &limits).unwrap();
            let ast = parse(&tokens, profile, &limits).unwrap();
            let resolved = resolve(&ast, &tokens, profile, &limits).unwrap();
            let encoded = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@open-last-active-copy.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            assert_eq!(
                encoded
                    .verified()
                    .native_debug()
                    .unwrap()
                    .temporaries_for(root.id)
                    .unwrap()
                    .iter()
                    .filter(|entry| entry.call_pc.0 as usize == nested_pc)
                    .count(),
                expected
            );
        }
    }
}

#[test]
fn native_debug_temporaries_include_nested_gettable_parent_value() {
    let source = b"function f() return 1 end\nfunction g(t) return (t[1])[f()] end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let ir = lowered(source, profile);
        let g = &ir.prototypes[2];
        let temporaries = &g.native_debug.as_ref().unwrap().temporaries;
        assert_eq!(temporaries.len(), 1, "{profile:?}: {temporaries:?}");
        let call_pc = temporaries[0].call_pc.0 as usize;
        assert!(matches!(
            g.instructions[call_pc].instruction,
            Instruction::Call { .. }
        ));
        assert_eq!(temporaries[0].ordinal, 1);
        assert!(g.instructions[call_pc + 1..].iter().any(|entry| {
            matches!(entry.instruction, Instruction::GetTable { table, .. }
                if table == temporaries[0].register)
        }));
    }
}

#[test]
fn native_debug_temporaries_survive_compiler_to_core_verification() {
    let source =
        b"function f() return 20 end\nfunction g(a,b) return ((a+1)+(b+2))+f((a+3)+f()) end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let tokens = lex(source, profile, &limits).unwrap();
        let ast = parse(&tokens, profile, &limits).unwrap();
        let resolved = resolve(&ast, &tokens, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"=temporaries",
            &VerifyLimits::default(),
        )
        .unwrap();
        let debug = encoded.verified().native_debug().unwrap();
        let g = &ir.prototypes[2];
        for temporary in &g.native_debug.as_ref().unwrap().temporaries {
            let mapped = debug
                .temporaries_at(g.id, InstructionOffset(temporary.call_pc.0))
                .unwrap();
            assert!(
                mapped.iter().any(|entry| {
                    entry.ordinal == temporary.ordinal && entry.register == temporary.register
                }),
                "{profile:?}: {temporary:?}"
            );
        }
    }
}

#[test]
fn native_debug_temporaries_reject_active_local_and_native_helper_call_aliases() {
    let source = b"function f() return 3 end\nfunction g(a) return (a+1)+{f()} end";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let tokens = lex(source, profile, &limits).unwrap();
        let ast = parse(&tokens, profile, &limits).unwrap();
        let resolved = resolve(&ast, &tokens, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"=temporary-helper",
            &VerifyLimits::default(),
        )
        .unwrap();
        let verified = encoded.verified();
        let debug = verified.native_debug().unwrap();
        let g = &ir.prototypes[2];
        let pending = debug.temporaries_for(g.id).unwrap();
        assert_eq!(pending.len(), 1, "{profile:?}: {pending:?}");
        let helper = verified
            .official_execution()
            .unwrap()
            .calls()
            .iter()
            .find(|call| call.prototype == g.id)
            .unwrap();
        let candidate = NativeDebugCandidate {
            source_name: debug.source_name().to_vec(),
            prototypes: debug.prototypes().to_vec(),
            temporaries: debug
                .prototypes()
                .iter()
                .flat_map(|proto| {
                    debug
                        .temporaries_for(proto.prototype)
                        .unwrap()
                        .iter()
                        .copied()
                })
                .collect(),
            initializer_temporaries: debug
                .prototypes()
                .iter()
                .flat_map(|proto| {
                    debug
                        .initializer_temporaries_for(proto.prototype)
                        .unwrap()
                        .iter()
                        .copied()
                })
                .collect(),
            non_counted_pcs: Vec::new(),
        };
        let local_register = candidate.prototypes[2]
            .locals
            .iter()
            .find(|local| local.name == b"a")
            .unwrap()
            .register;
        let mut local_alias = candidate.clone();
        local_alias.temporaries = vec![NativeTemporary {
            register: local_register,
            ..pending[0]
        }];
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        assert_eq!(
            verify_native_debug(verified, local_alias, &VerifyLimits::default(), &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::Verify,
            "{profile:?}",
        );
        let mut helper_alias = candidate;
        helper_alias.temporaries.push(NativeTemporary {
            call_pc: helper.call_pc,
            ..pending[0]
        });
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        assert_eq!(
            verify_native_debug(verified, helper_alias, &VerifyLimits::default(), &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::Verify,
            "{profile:?}",
        );
    }
}
