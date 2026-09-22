use rivetlua_compiler::{
    BinaryOperation, CompileLimits, ExitKind, FunctionId, Instruction, IrLimits, LanguageProfile,
    LuaProfile, ResultMode, Span, UpvalueSource, lex, lower, parse, resolve,
};
use rivetlua_core::Register;

fn resolved(input: &[u8], profile: LanguageProfile) -> rivetlua_compiler::ResolvedModule {
    let limits = CompileLimits::default();
    let chunk = lex(input, profile, &limits).unwrap();
    let module = parse(&chunk, profile, &limits).unwrap();
    resolve(&module, &chunk, profile, &limits).unwrap()
}

#[test]
fn public_ir_lowers_binary_return_with_typed_operands_and_span() {
    for (profile, ir_profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let resolved = resolved(b"return 1+2", profile);
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        assert_eq!(ir.profile, ir_profile);
        let root = ir.prototype_for(FunctionId(0)).unwrap();
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::BinaryOp {
                op: BinaryOperation::Add,
                ..
            }
        )));
        assert!(matches!(
            root.instructions
                .last()
                .map(|instruction| &instruction.instruction),
            Some(Instruction::Return {
                result_mode: ResultMode::Fixed(1),
                ..
            })
        ));
        assert_eq!(
            root.span,
            Span {
                start_byte: 0,
                end_byte: 10
            }
        );
    }
}

#[test]
fn public_ir_keeps_function_ids_upvalues_and_close_path_metadata() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let resolved_functions = resolved(
            b"local x; local function f() local function g() return x end; return g end",
            profile,
        );
        let ir = lower(&resolved_functions, &IrLimits::default()).unwrap();
        let f = ir.prototype_for(FunctionId(1)).unwrap();
        let g = ir.prototype_for(FunctionId(2)).unwrap();
        assert_eq!(f.parent, Some(ir.proto_id_for(FunctionId(0)).unwrap()));
        assert_eq!(g.parent, Some(ir.proto_id_for(FunctionId(1)).unwrap()));
        assert_eq!(g.upvalues.len(), 1);
        assert!(matches!(
            f.upvalues.as_slice(),
            [upvalue] if matches!(upvalue.source, UpvalueSource::ParentLocal(_))
        ));
        assert!(matches!(
            g.upvalues.as_slice(),
            [upvalue] if matches!(upvalue.source, UpvalueSource::ParentUpvalue(_))
        ));

        let resolved_close = resolved(
            b"do local a <close>; do local b <close>; return b end end",
            profile,
        );
        let ir = lower(&resolved_close, &IrLimits::default()).unwrap();
        let root = ir.prototype_for(FunctionId(0)).unwrap();
        let path = root
            .close_paths
            .iter()
            .find(|path| path.bindings.len() == 2)
            .expect("P04 close path 必須保留兩個 bindings");
        assert_eq!(path.registers.len(), 2);
        let close_registers = root
            .instructions
            .iter()
            .filter_map(|instruction| match instruction.instruction {
                Instruction::Close { base, count: 1 } => Some(base),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            close_registers
                .windows(2)
                .any(|pair| pair == path.registers.as_slice())
        );
    }
}

#[test]
fn public_ir_lowers_resolved_control_and_table_shapes_without_source_input() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let resolved = resolved(
            b"local x=1; if x then x=x+1 else x=2 end; while x do break end; repeat x=x-1 until x; for i=1,2 do x=i end; for k in x do x=k end; return {a=x,[x]=x}",
            profile,
        );
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let root = ir.prototype_for(FunctionId(0)).unwrap();
        assert!(
            root.instructions.iter().any(|instruction| matches!(
                instruction.instruction,
                Instruction::JumpIfFalse { .. }
            ))
        );
        assert!(
            root.instructions
                .iter()
                .any(|instruction| matches!(instruction.instruction, Instruction::NewTable { .. }))
        );
        assert!(
            root.instructions
                .iter()
                .any(|instruction| matches!(instruction.instruction, Instruction::SetTable { .. }))
        );
    }
}

#[test]
fn public_ir_preserves_lua55_global_structure_as_typed_table_operations() {
    let resolved = resolved(
        b"global x=1; global function f() return x end; return f",
        LanguageProfile::Lua55,
    );
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let root = ir.prototype_for(FunctionId(0)).unwrap();
    assert!(
        root.instructions
            .iter()
            .any(|instruction| matches!(instruction.instruction, Instruction::SetTable { .. }))
    );
    assert!(
        root.instructions
            .iter()
            .any(|instruction| matches!(instruction.instruction, Instruction::Closure { .. }))
    );
}

#[test]
fn public_ir_is_deterministic_and_stops_before_limits() {
    let resolved_binary = resolved(b"return 1+2", LanguageProfile::Lua55);
    assert_eq!(
        lower(&resolved_binary, &IrLimits::default()).unwrap(),
        lower(&resolved_binary, &IrLimits::default()).unwrap()
    );
    let limits = IrLimits {
        max_instructions: 1,
        ..IrLimits::default()
    };
    assert!(lower(&resolved_binary, &limits).is_err());
    let register_limits = IrLimits {
        max_registers: 1,
        ..IrLimits::default()
    };
    assert!(lower(&resolved_binary, &register_limits).is_err());
    let nested = resolved(b"local function f() return 1 end", LanguageProfile::Lua55);
    let prototype_limits = IrLimits {
        max_prototypes: 1,
        ..IrLimits::default()
    };
    assert!(lower(&nested, &prototype_limits).is_err());
    let mut malformed = resolved_binary;
    malformed.functions.clear();
    assert!(lower(&malformed, &IrLimits::default()).is_err());
}

fn jump_target(instruction: &Instruction) -> Option<usize> {
    match instruction {
        Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
            Some(target.0 as usize)
        }
        _ => None,
    }
}

fn assert_real_jump_targets(root: &rivetlua_compiler::IrPrototype) {
    for (index, instruction) in root.instructions.iter().enumerate() {
        let target = match instruction.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => target,
            _ => continue,
        };
        assert!(
            (target.0 as usize) < root.instructions.len(),
            "jump at {index} points outside prototype: {:?}",
            target
        );
        assert_ne!(
            target.0 as usize, index,
            "jump at {index} must not use a self-jump placeholder"
        );
    }
}

#[test]
fn public_ir_builds_real_cfg_edges_for_control_flow_and_labels() {
    let cases: &[(&[u8], &str)] = &[
        (b"local x=true; if x then x=false else x=true end", "if"),
        (b"local x=true; while x do break end", "while"),
        (b"local x=false; repeat x=true until x", "repeat"),
        (b"local x; for i=1,2 do x=i end", "numeric-for"),
        (b"local x; for k in x do break end", "generic-for"),
        (
            b"goto after; ::back:: goto done; ::after:: goto back; ::done:: return 1",
            "goto",
        ),
        (
            b"::outer:: do ::outer:: goto outer end; goto outer",
            "label-shadow",
        ),
    ];
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        for (input, name) in cases {
            let resolved = resolved(input, profile);
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let root = ir.prototype_for(FunctionId(0)).unwrap();
            assert_real_jump_targets(root);
            assert!(
                root.instructions.iter().any(|instruction| matches!(
                    instruction.instruction,
                    Instruction::Jump { .. } | Instruction::JumpIfFalse { .. }
                )),
                "{name} 必須產生 CFG edge"
            );
        }
    }
}

#[test]
fn public_ir_cfg_keeps_conditional_skip_backedges_and_nearest_break_edges() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let if_ir = lower(
            &resolved(b"local x=true; if x then x=false else x=true end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let if_root = if_ir.prototype_for(FunctionId(0)).unwrap();
        assert!(
            if_root
                .instructions
                .iter()
                .enumerate()
                .any(|(index, instruction)| {
                    matches!(instruction.instruction, Instruction::JumpIfFalse { .. })
                        && jump_target(&instruction.instruction)
                            .is_some_and(|target| target > index)
                })
        );

        for input in [
            b"local x=true; while x do break end".as_slice(),
            b"local x=false; repeat x=true until x".as_slice(),
            b"local x; for i=1,2 do x=i end".as_slice(),
            b"local x; for k in x do break end".as_slice(),
        ] {
            let ir = lower(&resolved(input, profile), &IrLimits::default()).unwrap();
            let root = ir.prototype_for(FunctionId(0)).unwrap();
            assert_real_jump_targets(root);
            assert!(
                root.instructions
                    .iter()
                    .enumerate()
                    .any(|(index, instruction)| {
                        jump_target(&instruction.instruction).is_some_and(|target| target < index)
                    })
                    || input.starts_with(b"local x=true; while")
            );
        }

        let labels = lower(
            &resolved(
                b"goto after; ::back:: goto done; ::after:: goto back; ::done:: return 1",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        let root = labels.prototype_for(FunctionId(0)).unwrap();
        assert_real_jump_targets(root);
        assert!(
            root.instructions
                .iter()
                .enumerate()
                .any(|(index, instruction)| {
                    matches!(instruction.instruction, Instruction::Jump { .. })
                        && jump_target(&instruction.instruction)
                            .is_some_and(|target| target > index)
                })
        );
        assert!(
            root.instructions
                .iter()
                .enumerate()
                .any(|(index, instruction)| {
                    matches!(instruction.instruction, Instruction::Jump { .. })
                        && jump_target(&instruction.instruction)
                            .is_some_and(|target| target < index)
                })
        );

        let nested_break = lower(
            &resolved(
                b"local x=true; while x do while x do break end; break end",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        assert_real_jump_targets(nested_break.prototype_for(FunctionId(0)).unwrap());
    }
}

#[test]
fn public_ir_cfg_uses_the_nearest_label_and_loop_exit() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let labels = lower(
            &resolved(
                b"::outer:: do ::outer:: goto outer end; goto outer",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        let root = labels.prototype_for(FunctionId(0)).unwrap();
        let jump_targets = root
            .instructions
            .iter()
            .filter_map(|instruction| match instruction.instruction {
                Instruction::Jump { target } => Some(target.0 as usize),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(jump_targets, vec![1, 0]);

        let loops = lower(
            &resolved(
                b"local x=true; while x do while x do break end; break end",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        let root = loops.prototype_for(FunctionId(0)).unwrap();
        let forward_targets = root
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| match instruction.instruction {
                Instruction::Jump { target } if target.0 as usize > index => {
                    Some(target.0 as usize)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(forward_targets.len() >= 2);
        assert_ne!(forward_targets[0], forward_targets[1]);
    }
}

#[test]
fn public_ir_preserves_repeat_numeric_and_generic_for_lowering_semantics() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let repeat = lower(
            &resolved(b"repeat local x <close> = {}; until x == true", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let repeat_root = repeat.prototype_for(FunctionId(0)).unwrap();
        let condition = repeat_root
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction.instruction,
                    Instruction::BinaryOp {
                        op: BinaryOperation::Equal,
                        ..
                    }
                )
            })
            .expect("repeat condition binary operation");
        let close = repeat_root
            .instructions
            .iter()
            .position(|instruction| matches!(instruction.instruction, Instruction::Close { .. }))
            .expect("repeat scope close");
        assert!(
            repeat_root
                .close_paths
                .iter()
                .any(|path| path.kind == ExitKind::Normal)
        );
        let branch = repeat_root
            .instructions
            .iter()
            .position(|instruction| {
                matches!(instruction.instruction, Instruction::JumpIfFalse { .. })
            })
            .expect("repeat backedge branch");
        assert!(condition < close && close < branch);
        assert!(matches!(
            repeat_root.instructions[branch].instruction,
            Instruction::JumpIfFalse { target, .. } if (target.0 as usize) < branch
        ));

        let numeric = lower(
            &resolved(b"for i=5,1,-1 do end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let numeric_root = numeric.prototype_for(FunctionId(0)).unwrap();
        assert!(numeric_root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::BinaryOp {
                op: BinaryOperation::Less,
                ..
            }
        )));
        assert!(numeric_root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::BinaryOp {
                op: BinaryOperation::GreaterEqual,
                ..
            }
        )));
        assert!(numeric_root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::BinaryOp {
                op: BinaryOperation::LessEqual,
                ..
            }
        )));
        assert_eq!(
            numeric_root
                .instructions
                .iter()
                .filter(|instruction| instruction.span
                    == Span {
                        start_byte: 11,
                        end_byte: 12
                    })
                .count(),
            1,
            "negative step expression 只可在進入 loop 時求值一次"
        );

        let generic = lower(
            &resolved(
                b"local iter,state,control; for k,v in iter,state,control do end",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        let generic_root = generic.prototype_for(FunctionId(0)).unwrap();
        let call = generic_root
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction.instruction,
                    Instruction::Call {
                        arg_count: 2,
                        result_mode: ResultMode::Fixed(2),
                        ..
                    }
                )
            })
            .expect("generic for iterator call");
        let base = match generic_root.instructions[call].instruction {
            Instruction::Call { base, .. } => base,
            _ => unreachable!(),
        };
        assert!(matches!(
            generic_root.instructions[call - 3].instruction,
            Instruction::Move { dest, .. } if dest == base
        ));
        assert!(matches!(
            generic_root.instructions[call - 2].instruction,
            Instruction::Move { dest, .. } if dest == Register(base.0 + 1)
        ));
        assert!(matches!(
            generic_root.instructions[call - 1].instruction,
            Instruction::Move { dest, .. } if dest == Register(base.0 + 2)
        ));
        let nil = match generic_root.instructions[call + 1].instruction {
            Instruction::LoadNil { start, count: 1 } => start,
            _ => panic!("generic Call 後必須建立 nil comparator"),
        };
        let comparison = match generic_root.instructions[call + 2].instruction {
            Instruction::BinaryOp {
                dest,
                op: BinaryOperation::NotEqual,
                left,
                right,
            } => {
                assert_eq!(left, base);
                assert_eq!(right, nil);
                dest
            }
            _ => panic!("generic Call 首結果必須與 nil 比較"),
        };
        assert!(matches!(
            generic_root.instructions[call + 3].instruction,
            Instruction::JumpIfFalse { condition, .. } if condition == comparison
        ));
        assert!(matches!(
            generic_root.instructions[call + 4].instruction,
            Instruction::Move { src, .. } if src == base
        ));
    }
}

#[test]
fn public_ir_generic_for_terminates_only_on_nil_and_evaluates_extra_values() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let ir = lower(
            &resolved(
                b"local iter,state,control,side; for k in iter,state,control,side() do end",
                profile,
            ),
            &IrLimits::default(),
        )
        .unwrap();
        let root = ir.prototype_for(FunctionId(0)).unwrap();
        let generic_call = root
            .instructions
            .iter()
            .rposition(|instruction| {
                matches!(
                    instruction.instruction,
                    Instruction::Call {
                        arg_count: 2,
                        result_mode: ResultMode::Fixed(1),
                        ..
                    }
                )
            })
            .expect("generic iterator Call");
        assert!(
            root.instructions[..generic_call]
                .iter()
                .any(|instruction| matches!(
                    instruction.instruction,
                    Instruction::Call {
                        arg_count: 0,
                        result_mode: ResultMode::Fixed(1),
                        ..
                    }
                ))
        );
        let base = match root.instructions[generic_call].instruction {
            Instruction::Call { base, .. } => base,
            _ => unreachable!(),
        };
        let nil = match root.instructions[generic_call + 1].instruction {
            Instruction::LoadNil { start, count: 1 } => start,
            _ => panic!("generic Call 後必須建立 nil comparator"),
        };
        let comparison = match root.instructions[generic_call + 2].instruction {
            Instruction::BinaryOp {
                dest,
                op: BinaryOperation::NotEqual,
                left,
                right,
            } => {
                assert_eq!(left, base);
                assert_eq!(right, nil);
                dest
            }
            _ => panic!("generic Call 首結果必須與 nil 比較"),
        };
        assert!(matches!(
            root.instructions[generic_call + 3].instruction,
            Instruction::JumpIfFalse { condition, .. } if condition == comparison
        ));
    }
}

#[test]
fn public_ir_p05_2_uses_frames_contiguous_calls_results_close_and_environment() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let tail = lower(
            &resolved(b"local f,a,b; return f(a,b)", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = tail.prototype_for(FunctionId(0)).unwrap();
        let tail_index = root
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction.instruction,
                    Instruction::TailCall {
                        arg_count: 2,
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            })
            .expect("direct return call 必須為 tail call");
        let base = match root.instructions[tail_index].instruction {
            Instruction::TailCall { base, .. } => base,
            _ => unreachable!(),
        };
        assert!(
            matches!(root.instructions[tail_index - 3].instruction, Instruction::Move { dest, .. } if dest == base)
        );
        assert!(
            matches!(root.instructions[tail_index - 2].instruction, Instruction::Move { dest, .. } if dest == Register(base.0 + 1))
        );
        assert!(
            matches!(root.instructions[tail_index - 1].instruction, Instruction::Move { dest, .. } if dest == Register(base.0 + 2))
        );
        assert!(root.frame.registers_start_as_nil);
        assert_eq!(root.frame.environment, root.global_environment);

        let method = lower(
            &resolved(b"local object,a; return object:m(a)", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let method_root = method.prototype_for(FunctionId(0)).unwrap();
        let method_tail = method_root
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction.instruction,
                    Instruction::TailCall { arg_count: 2, .. }
                )
            })
            .expect("method return 必須為 tail call");
        let method_base = match method_root.instructions[method_tail].instruction {
            Instruction::TailCall { base, .. } => base,
            _ => unreachable!(),
        };
        assert!(
            matches!(method_root.instructions[method_tail - 3].instruction, Instruction::Move { dest, .. } if dest == method_base)
        );
        assert!(
            matches!(method_root.instructions[method_tail - 2].instruction, Instruction::Move { dest, .. } if dest == Register(method_base.0 + 1))
        );
        assert!(
            matches!(method_root.instructions[method_tail - 1].instruction, Instruction::Move { dest, .. } if dest == Register(method_base.0 + 2))
        );

        let paren = lower(
            &resolved(b"local f; return (f())", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = paren.prototype_for(FunctionId(0)).unwrap();
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Call {
                result_mode: ResultMode::Fixed(1),
                ..
            }
        )));
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Return {
                result_mode: ResultMode::Fixed(1),
                ..
            }
        )));
        assert!(
            !root
                .instructions
                .iter()
                .any(|instruction| matches!(instruction.instruction, Instruction::TailCall { .. }))
        );

        let open = lower(
            &resolved(b"local f; return 1,f()", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = open.prototype_for(FunctionId(0)).unwrap();
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Call {
                result_mode: ResultMode::All,
                ..
            }
        )));
        assert_ne!(root.frame.dynamic_top, root.frame.initial_top);
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Return {
                result_mode: ResultMode::All,
                ..
            }
        )));

        let fixed = lower(
            &resolved(b"local x,y=1; return x,y", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = fixed.prototype_for(FunctionId(0)).unwrap();
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::LoadNil { count: 1, .. }
        )));
        assert!(root.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Return {
                result_mode: ResultMode::Fixed(2),
                ..
            }
        )));

        let limits = IrLimits {
            max_registers: 3,
            ..IrLimits::default()
        };
        assert!(lower(&resolved(b"local f,a,b; return f(a,b)", profile), &limits).is_err());
    }

    for profile in [LanguageProfile::Lua54] {
        let local_env = lower(
            &resolved(b"local _ENV; return free", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = local_env.prototype_for(FunctionId(0)).unwrap();
        let local_table = root
            .instructions
            .iter()
            .find_map(|instruction| match instruction.instruction {
                Instruction::GetTable { table, .. } => Some(table),
                _ => None,
            })
            .unwrap();
        assert_ne!(local_table, root.global_environment);

        let parameter_env = lower(
            &resolved(b"local function f(_ENV) return free end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let child = parameter_env.prototype_for(FunctionId(1)).unwrap();
        assert!(child.instructions.iter().any(|instruction| matches!(instruction.instruction, Instruction::GetTable { table, .. } if table != child.global_environment)));

        let captured_env = lower(
            &resolved(b"local _ENV; local function f() return free end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let child = captured_env.prototype_for(FunctionId(1)).unwrap();
        let source = child
            .instructions
            .iter()
            .find_map(|instruction| match instruction.instruction {
                Instruction::GetUpvalue { dest, .. } => Some(dest),
                _ => None,
            })
            .expect("captured _ENV 必須由 upvalue 載入");
        assert!(child.instructions.iter().any(|instruction| matches!(instruction.instruction, Instruction::GetTable { table, .. } if table == source)));
    }

    let global = lower(
        &resolved(b"return free", LanguageProfile::Lua55),
        &IrLimits::default(),
    )
    .unwrap();
    let root = global.prototype_for(FunctionId(0)).unwrap();
    assert!(root.instructions.iter().any(|instruction| matches!(instruction.instruction, Instruction::GetTable { table, .. } if table == root.global_environment)));
}

#[test]
fn public_ir_p05_2_models_fixed_zero_vararg_and_open_result_boundaries() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let statement_call =
            lower(&resolved(b"local f; f()", profile), &IrLimits::default()).unwrap();
        assert!(
            statement_call
                .prototype_for(FunctionId(0))
                .unwrap()
                .instructions
                .iter()
                .any(|instruction| matches!(
                    instruction.instruction,
                    Instruction::Call {
                        result_mode: ResultMode::Fixed(0),
                        ..
                    }
                ))
        );

        let vararg = lower(
            &resolved(b"local function f(...) return ... end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let child = vararg.prototype_for(FunctionId(1)).unwrap();
        assert!(child.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Vararg {
                result_mode: ResultMode::All,
                ..
            }
        )));
        assert!(child.instructions.iter().any(|instruction| matches!(
            instruction.instruction,
            Instruction::Return {
                result_mode: ResultMode::All,
                ..
            }
        )));

        let truncate = lower(
            &resolved(b"local x=1,2; return x", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = truncate.prototype_for(FunctionId(0)).unwrap();
        assert!(
            root.instructions
                .iter()
                .filter(|instruction| matches!(
                    instruction.instruction,
                    Instruction::LoadConst { .. }
                ))
                .count()
                >= 2
        );
    }
}

#[test]
fn public_ir_frames_keep_verified_environment_source_chains() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let nested = lower(
            &resolved(b"local function f() return free end", profile),
            &IrLimits::default(),
        )
        .unwrap();
        let root = nested.prototype_for(FunctionId(0)).unwrap();
        assert!(matches!(
            root.frame.environment_source,
            rivetlua_compiler::EnvironmentSource::RootExternal
        ));
        let child = nested.prototype_for(FunctionId(1)).unwrap();
        match profile {
            LanguageProfile::Lua55 => assert!(matches!(
                child.frame.environment_source,
                rivetlua_compiler::EnvironmentSource::ParentFrame { parent, register }
                    if parent == root.id && register == root.global_environment
            )),
            LanguageProfile::Lua54 => assert!(matches!(
                child.frame.environment_source,
                rivetlua_compiler::EnvironmentSource::ParentLocal { upvalue }
                    if upvalue.0 == 0
            )),
        }
        assert!(
            child.instructions.iter().any(|instruction| matches!(
                instruction.instruction,
                Instruction::GetTable { table, .. } if table == child.global_environment
            )) || profile == LanguageProfile::Lua54
        );
    }

    let deep = lower(
        &resolved(
            b"local function f() local function g() return free end end",
            LanguageProfile::Lua55,
        ),
        &IrLimits::default(),
    )
    .unwrap();
    let middle = deep.prototype_for(FunctionId(1)).unwrap();
    let leaf = deep.prototype_for(FunctionId(2)).unwrap();
    assert!(matches!(
        middle.frame.environment_source,
        rivetlua_compiler::EnvironmentSource::ParentFrame { parent, register }
            if parent == deep.prototype_for(FunctionId(0)).unwrap().id
                && register == deep.prototype_for(FunctionId(0)).unwrap().global_environment
    ));
    assert!(matches!(
        leaf.frame.environment_source,
        rivetlua_compiler::EnvironmentSource::ParentFrame { parent, register }
            if parent == middle.id && register == middle.global_environment
    ));

    let shadow = lower(
        &resolved(
            b"local _ENV; local function f(_ENV) return free end",
            LanguageProfile::Lua54,
        ),
        &IrLimits::default(),
    )
    .unwrap();
    let child = shadow.prototype_for(FunctionId(1)).unwrap();
    assert!(child.instructions.iter().any(|instruction| matches!(
        instruction.instruction,
        Instruction::GetTable { table, .. } if table != child.global_environment
    )));
}

#[test]
fn public_rvlu_v1_roundtrips_two_profiles_through_verified_module() {
    for (profile, bytecode_profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let ir = lower(&resolved(b"return 1+2", profile), &IrLimits::default()).unwrap();
        let encoded = rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default())
            .expect("IR emission 必須先通過同一 structural validator");
        let decoded = rivetlua_compiler::decode_module(
            encoded.bytes(),
            bytecode_profile,
            &rivetlua_compiler::VerifyLimits::default(),
        )
        .expect("外部 bytes 必須經同一 validator 成為 VerifiedModule");
        assert_eq!(decoded.profile(), bytecode_profile);
        assert_eq!(decoded.module().prototypes.len(), ir.prototypes.len());
        assert_eq!(
            encoded.bytes(),
            rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default())
                .unwrap()
                .bytes()
        );
    }
}

#[test]
fn public_rvlu_rejects_untrusted_headers_lengths_and_profiles() {
    for (profile, bytecode_profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let ir = lower(&resolved(b"return 1+2", profile), &IrLimits::default()).unwrap();
        let encoded =
            rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default()).unwrap();
        for (offset, value) in [(0, 0xff), (4, 2), (7, 0)] {
            let mut bytes = encoded.bytes().to_vec();
            bytes[offset] = value;
            let error = rivetlua_compiler::decode_module(
                &bytes,
                bytecode_profile,
                &rivetlua_compiler::VerifyLimits::default(),
            )
            .expect_err("外部損壞 RVLU 必須拒絕");
            assert_eq!(error.code, rivetlua_compiler::BytecodeErrorCode::Verify);
            assert!(error.offset <= bytes.len());
        }
        let wrong_profile = if bytecode_profile == LuaProfile::Lua55 {
            LuaProfile::Lua54
        } else {
            LuaProfile::Lua55
        };
        assert_eq!(
            rivetlua_compiler::decode_module(
                encoded.bytes(),
                wrong_profile,
                &rivetlua_compiler::VerifyLimits::default(),
            )
            .expect_err("錯 profile 必須拒絕")
            .code,
            rivetlua_compiler::BytecodeErrorCode::Verify
        );
        let mut bad_section = encoded.bytes().to_vec();
        bad_section[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            rivetlua_compiler::decode_module(
                &bad_section,
                bytecode_profile,
                &rivetlua_compiler::VerifyLimits::default(),
            )
            .expect_err("section overflow 必須拒絕")
            .code,
            rivetlua_compiler::BytecodeErrorCode::Verify
        );
        let limits = rivetlua_compiler::VerifyLimits {
            max_module_bytes: encoded.bytes().len() - 1,
            ..rivetlua_compiler::VerifyLimits::default()
        };
        assert_eq!(
            rivetlua_compiler::decode_module(encoded.bytes(), bytecode_profile, &limits)
                .expect_err("module 上限必須先於配置拒絕")
                .code,
            rivetlua_compiler::BytecodeErrorCode::CompileLimit
        );
    }
}

#[test]
fn public_rvlu_verifies_two_profile_control_flow_closure_and_close_paths() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        for input in [
            b"local x=1; if x then x=2 else x=3 end; while x do break end; repeat x=x-1 until x; for i=1,2 do x=i end; for k in x do x=k end; return x".as_slice(),
            b"local x; local function f() return x end; return f".as_slice(),
            b"do local a <close>; do local b <close>; return b end end".as_slice(),
        ] {
            let ir = lower(&resolved(input, profile), &IrLimits::default()).unwrap();
            rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default())
                .expect("compiler IR 必須通過同一完整 verifier");
        }
    }
}

#[test]
fn public_rvlu_verifier_rejects_untrusted_candidate_operands_and_cfg() {
    let ir = lower(
        &resolved(b"return 1+2", LanguageProfile::Lua55),
        &IrLimits::default(),
    )
    .unwrap();
    let encoded =
        rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default()).unwrap();
    let mut bad_constant = encoded.verified().module().clone();
    bad_constant.prototypes[0].instructions[0].instruction = Instruction::LoadConst {
        dest: Register(0),
        constant: rivetlua_compiler::ConstId(u32::MAX),
    };
    assert_eq!(
        rivetlua_compiler::verify_module(
            bad_constant,
            LuaProfile::Lua55,
            &rivetlua_compiler::VerifyLimits::default(),
        )
        .expect_err("公開 verifier 必須拒絕 invalid constant")
        .code,
        rivetlua_compiler::BytecodeErrorCode::Verify
    );
    let mut fallthrough = encoded.verified().module().clone();
    fallthrough.prototypes[0].instructions.pop();
    assert!(
        rivetlua_compiler::verify_module(
            fallthrough,
            LuaProfile::Lua55,
            &rivetlua_compiler::VerifyLimits::default(),
        )
        .is_err()
    );
}

#[test]
fn public_rvlu_verifier_rejects_reordered_compiler_close_sequence() {
    let ir = lower(
        &resolved(
            b"do local a <close>; do local b <close>; return b end end",
            LanguageProfile::Lua55,
        ),
        &IrLimits::default(),
    )
    .unwrap();
    let encoded =
        rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default()).unwrap();
    let mut reordered = encoded.verified().module().clone();
    let root = &mut reordered.prototypes[0];
    let close_indices = root
        .instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            matches!(instruction.instruction, Instruction::Close { .. }).then_some(index)
        })
        .collect::<Vec<_>>();
    let pair = close_indices
        .windows(2)
        .find(|pair| {
            root.instructions[pair[0]].close_path == root.instructions[pair[1]].close_path
                && root.instructions[pair[0]].close_path.is_some()
        })
        .expect("compiler 必須輸出同一 ClosePath 的連續 Close 序列");
    root.instructions.swap(pair[0], pair[1]);
    assert_eq!(
        rivetlua_compiler::verify_module(
            reordered,
            LuaProfile::Lua55,
            &rivetlua_compiler::VerifyLimits::default(),
        )
        .expect_err("反序 Close sequence 必須拒絕")
        .code,
        rivetlua_compiler::BytecodeErrorCode::Verify
    );
}

#[test]
fn public_rvlu_verifier_uses_exact_call_argument_interval() {
    let ir = lower(
        &resolved(b"return 1+2", LanguageProfile::Lua55),
        &IrLimits::default(),
    )
    .unwrap();
    let encoded =
        rivetlua_compiler::emit(&ir, &rivetlua_compiler::VerifyLimits::default()).unwrap();
    let mut exact = encoded.verified().module().clone();
    let root = &mut exact.prototypes[0];
    let last = Register(root.register_count - 1);
    root.instructions[0].instruction = Instruction::Call {
        base: last,
        arg_count: 0,
        result_mode: ResultMode::Fixed(0),
    };
    rivetlua_compiler::verify_module(
        exact.clone(),
        LuaProfile::Lua55,
        &rivetlua_compiler::VerifyLimits::default(),
    )
    .expect("zero-argument Call 的最後有效 register 必須合法");
    exact.prototypes[0].instructions[0].instruction = Instruction::Call {
        base: last,
        arg_count: 1,
        result_mode: ResultMode::Fixed(0),
    };
    assert_eq!(
        rivetlua_compiler::verify_module(
            exact,
            LuaProfile::Lua55,
            &rivetlua_compiler::VerifyLimits::default(),
        )
        .expect_err("base + arg_count 超出 frame 必須拒絕")
        .code,
        rivetlua_compiler::BytecodeErrorCode::Verify
    );
}
