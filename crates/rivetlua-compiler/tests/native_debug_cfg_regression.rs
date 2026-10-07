use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{Instruction, InstructionOffset, VerifyLimits};

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
fn cfg_anchor_is_non_counted_but_source_loadnil_remains_counted() {
    let source = b"local x; for i = 1, 2 do end; return x";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let recorded = &root.native_debug.as_ref().unwrap().non_counted_pcs;
        assert!(!recorded.is_empty(), "{profile:?}");
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@cfg-anchor.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let debug = encoded.verified().native_debug().unwrap();
        let loadnil_pcs: Vec<_> = root
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(pc, entry)| {
                matches!(entry.instruction, Instruction::LoadNil { count: 1, .. })
                    .then_some(InstructionOffset(pc as u32))
            })
            .collect();
        assert!(
            recorded.iter().any(|pc| loadnil_pcs.contains(pc)),
            "{profile:?}"
        );
        assert!(
            recorded
                .iter()
                .all(|pc| debug.is_non_counted_pc(root.id, *pc)),
            "{profile:?}"
        );
        assert!(
            loadnil_pcs
                .iter()
                .any(|pc| !debug.is_non_counted_pc(root.id, *pc)),
            "{profile:?}: source LoadNil should still tick"
        );
    }
}

#[test]
fn native_count_groups_keep_one_anchor_for_for_values_and_named_lookups() {
    let source = b"local x=nil; for i=1,2 do end; return x, foo, t.bar, t['baz']";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let markers = &root.native_debug.as_ref().unwrap().non_counted_pcs;
        assert!(markers.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let marked = |pc: usize| markers.contains(&InstructionOffset(pc as u32));
        let prepare = root
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::NumericForPrepare { .. }))
            .unwrap();
        for pair in root.instructions[prepare - 6..prepare].chunks_exact(2) {
            assert!(
                matches!(pair[0].instruction, Instruction::LoadConst { .. }),
                "{profile:?}"
            );
            assert!(
                matches!(pair[1].instruction, Instruction::Move { .. }),
                "{profile:?}"
            );
        }
        for pc in [prepare - 6, prepare - 4, prepare - 2] {
            assert!(!marked(pc), "{profile:?}: source literal anchor PC={pc}");
            assert!(marked(pc + 1), "{profile:?}: for placement PC={}", pc + 1);
        }
        let named_gets: Vec<_> =
            root.instructions
                .windows(2)
                .enumerate()
                .filter_map(
                    |(pc, pair)| match (&pair[0].instruction, &pair[1].instruction) {
                        (
                            Instruction::LoadConst { dest, .. },
                            Instruction::GetTable { key, .. },
                        ) if dest == key => Some((pc, marked(pc), marked(pc + 1))),
                        _ => None,
                    },
                )
                .collect();
        assert_eq!(
            named_gets.iter().filter(|(_, helper, _)| *helper).count(),
            4,
            "{profile:?}: {named_gets:?}"
        );
        assert_eq!(
            named_gets.iter().filter(|(_, helper, _)| !*helper).count(),
            1,
            "{profile:?}: source index literal remains counted"
        );
        assert!(named_gets.iter().all(|(_, _, get)| !get), "{profile:?}");
        assert!(
            root.instructions.iter().enumerate().any(|(pc, entry)| {
                matches!(entry.instruction, Instruction::LoadNil { .. }) && !marked(pc)
            }),
            "{profile:?}: source nil must tick"
        );
        emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@count-groups.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
    }
}

#[test]
fn numeric_for_local_value_keeps_sole_move_anchor() {
    let source = b"local n=1; for i=n,2 do end; return n";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let prepare = root
            .instructions
            .iter()
            .position(|entry| matches!(entry.instruction, Instruction::NumericForPrepare { .. }))
            .unwrap();
        let markers = &root.native_debug.as_ref().unwrap().non_counted_pcs;
        assert!(matches!(
            root.instructions[prepare - 5].instruction,
            Instruction::Move { .. }
        ));
        assert!(
            !markers.contains(&InstructionOffset((prepare - 5) as u32)),
            "{profile:?}: local value 的 Move 是唯一 opcode"
        );
        assert!(
            markers.contains(&InstructionOffset((prepare - 3) as u32))
                && markers.contains(&InstructionOffset((prepare - 1) as u32)),
            "{profile:?}: literal placement 仍為展開"
        );
    }
}

#[test]
fn immediate_order_comparison_uses_binary_anchor() {
    let source = b"local n=1; return n<3, 3<n, n<1000";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = &ir.prototypes[0];
        let markers = &root.native_debug.as_ref().unwrap().non_counted_pcs;
        let mut small = 0;
        let mut large = 0;
        let mut comparisons = 0;
        for (pc, entry) in root.instructions.iter().enumerate() {
            let marked = markers.contains(&InstructionOffset(pc as u32));
            if matches!(entry.instruction, Instruction::LoadConst { .. }) {
                match &source[entry.span.start_byte..entry.span.end_byte] {
                    b"3" => {
                        small += 1;
                        assert!(marked, "{profile:?}: immediate helper PC={pc}");
                    }
                    b"1000" => {
                        large += 1;
                        assert!(!marked, "{profile:?}: 非 immediate literal PC={pc}");
                    }
                    _ => {}
                }
            }
            if matches!(entry.instruction, Instruction::BinaryOp { .. }) {
                comparisons += 1;
                assert!(!marked, "{profile:?}: comparison anchor PC={pc}");
            }
        }
        assert_eq!((small, large, comparisons), (2, 1, 3), "{profile:?}");
    }
}

#[test]
fn generic_for_fourth_value_keeps_native_debug_cfg_valid() {
    let cases: &[(&str, &[u8])] = &[
        ("minimal", b"for x in nil,nil,nil,{} do end"),
        ("closing-fourth-value", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter() return nil end; for x in iter,nil,nil,setmetatable({n=3},mt) do end; return log"),
        ("capture", b"local f; for x in nil,nil,nil,nil do f=function() return x end end"),
    ];
    let mut failures = Vec::new();
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source) in cases {
            let limits = CompileLimits::default();
            let lexed = lex(source, profile, &limits).unwrap();
            let ast = parse(&lexed, profile, &limits).unwrap();
            let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let verify = VerifyLimits::default();
            assert!(
                emit(&ir, &verify).is_ok(),
                "{profile:?}/{name}: RVLU candidate"
            );
            if *name == "minimal" {
                let root = &ir.prototypes[0];
                let visible = &root.native_debug.as_ref().unwrap().locals[0];
                let register = visible.register;
                let initialized = visible.initialized_pc as usize;
                let start = visible.start_pc as usize;
                let end = visible.end_pc as usize;
                assert!(matches!(
                    root.instructions[initialized].instruction,
                    Instruction::Move { dest, .. } if dest == register
                ));
                assert_eq!(start, initialized + 1);
                let (exit_jump, nil_exit) = root
                    .instructions
                    .iter()
                    .enumerate()
                    .find_map(|(pc, entry)| match entry.instruction {
                        Instruction::JumpIfFalse { target, .. } => Some((pc, target.0 as usize)),
                        _ => None,
                    })
                    .expect("generic-for nil exit 須有條件分支");
                let backedge = root
                    .instructions
                    .iter()
                    .enumerate()
                    .find_map(|(pc, entry)| match entry.instruction {
                        Instruction::Jump { target } if target.0 as usize <= exit_jump => Some(pc),
                        _ => None,
                    })
                    .expect("成功迭代路徑須返回 iterator");
                let cleanup = (start..backedge)
                    .find(|&pc| {
                        matches!(root.instructions[pc].instruction,
                        Instruction::LoadNil { start, count }
                        if u32::from(start.0) <= u32::from(register.0)
                            && u32::from(register.0) < u32::from(start.0) + u32::from(count))
                    })
                    .expect("可見 name 在回邊前須清除");
                assert!(
                    root.instructions[cleanup + 1..backedge]
                        .iter()
                        .all(|entry| !matches!(
                            entry.instruction,
                            Instruction::Close { count: 0, .. }
                        )),
                    "captured upvalue 必須先關閉，才能清除可見 name"
                );
                assert!(exit_jump < initialized && cleanup < backedge && backedge < end);
                assert!(end <= nil_exit && nil_exit < root.instructions.len());
            }
            let unbudgeted =
                emit_with_native_debug(&ir, &resolved, source, name.as_bytes(), &verify);
            let budgeted = compile_with_budget(
                source,
                name.as_bytes(),
                profile,
                &limits,
                &IrLimits::default(),
                &verify,
                &mut Unlimited,
            );
            if let Err(error) = &unbudgeted {
                failures.push(format!("{profile:?}/{name} unbudgeted: {error:?}"));
            }
            if let Err(error) = &budgeted {
                assert!(
                    matches!(error, BudgetedCompileError::Bytecode(_)),
                    "{profile:?}/{name}: {error:?}"
                );
                failures.push(format!("{profile:?}/{name} budgeted: {error:?}"));
            }
            assert_eq!(
                unbudgeted.is_ok(),
                budgeted.is_ok(),
                "{profile:?}/{name} classifier"
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
