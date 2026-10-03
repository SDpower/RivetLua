use rivetlua_compiler::{
    BytecodeExitKind, Instruction, LuaProfile, OfficialFixedBuiltin, OfficialFrameInputSource,
    OfficialTranslation, ResultMode, VerifyLimits, translate_official_chunk,
};
use rivetlua_core::bytecode::official::{
    OfficialChunk, OfficialChunkLimits, OfficialConstant, OfficialDebug, OfficialPrototype,
    OfficialUpvalue, decode_official_chunk, encode_official_chunk,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeUpvalueSource,
    OfficialPlanBuiltin, OfficialPlanCall, OfficialPlanCandidate, OfficialWorkBudget, Register,
    preflight_official_chunk, translate_official_chunk_with_work, verify_module,
    verify_official_execution_plan,
};

fn abc(opcode: u32, a: u32, b: u32, c: u32) -> u32 {
    opcode | (a << 7) | (b << 16) | (c << 24)
}

fn abx(opcode: u32, a: u32, bx: u32) -> u32 {
    opcode | (a << 7) | (bx << 15)
}

fn chunk(profile: LuaProfile, code: Vec<u32>) -> OfficialChunk {
    OfficialChunk {
        profile,
        root_upvalues: 0,
        main: OfficialPrototype {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            flags: 0,
            max_stack_size: 2,
            code,
            constants: vec![OfficialConstant::Integer(7)],
            upvalues: vec![],
            children: vec![],
            debug: OfficialDebug::default(),
        },
    }
}

fn jump(offset: i32) -> u32 {
    56 | (((16_777_215 + offset) as u32) << 7)
}

fn open_list_chunk(profile: LuaProfile, call_producer: bool) -> OfficialChunk {
    let extra = if profile == LuaProfile::Lua54 { 82 } else { 84 };
    let mut code = vec![abc(19, 0, 0, 0), abc(extra, 0, 0, 0)];
    if call_producer {
        code.push(abc(8, 1, 0, 0));
        code.push(abc(68, 1, 1, 0));
    } else {
        code.insert(
            0,
            abc(if profile == LuaProfile::Lua54 { 81 } else { 83 }, 0, 0, 0),
        );
        code.push(abc(80, 1, 0, 0));
    }
    code.push(abc(78, 0, 0, 0));
    code.push(abc(71, 0, 0, 0));
    let mut source = chunk(profile, code);
    source.main.max_stack_size = 3;
    if !call_producer {
        source.main.flags = 1;
    }
    source
}

#[test]
fn both_profiles_translate_a_small_official_chunk_through_p05_verifier() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let source = chunk(profile, vec![abc(3, 0, 0, 0), abc(72, 0, 0, 0)]);
        let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        assert_eq!(translated.verified().profile(), profile);
        assert_eq!(translated.pc_mappings().len(), 1);
        assert_eq!(translated.pc_mappings()[0].official_to_rvlu().len(), 2);
        let instructions = &translated.verified().module().prototypes[0].instructions;
        assert!(
            instructions
                .iter()
                .any(|entry| matches!(entry.instruction, Instruction::LoadConst { .. }))
        );
        assert!(matches!(
            instructions.last().map(|entry| &entry.instruction),
            Some(Instruction::Return { .. })
        ));
    }
}

#[test]
fn rejects_unknown_opcode_and_invalid_constant_before_translation() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let unknown = chunk(profile, vec![abc(127, 0, 0, 0), abc(71, 0, 0, 0)]);
        assert!(translate_official_chunk(&unknown, &VerifyLimits::default()).is_err());
        let missing = chunk(profile, vec![abc(3, 0, 1, 0), abc(72, 0, 0, 0)]);
        assert!(translate_official_chunk(&missing, &VerifyLimits::default()).is_err());
    }
}

#[test]
fn translates_official_debug_strip_and_closure_fixtures_for_both_profiles() {
    for (profile, fixtures) in [
        (
            LuaProfile::Lua54,
            [
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac"
                )
                .as_slice(),
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-strip.luac"
                )
                .as_slice(),
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-closure.luac"
                )
                .as_slice(),
            ],
        ),
        (
            LuaProfile::Lua55,
            [
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac"
                )
                .as_slice(),
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-strip.luac"
                )
                .as_slice(),
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-closure.luac"
                )
                .as_slice(),
            ],
        ),
    ] {
        for fixture in fixtures {
            let source =
                decode_official_chunk(fixture, profile, &OfficialChunkLimits::default()).unwrap();
            let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
            assert_eq!(translated.verified().profile(), profile);
            assert_eq!(
                translated.pc_mappings().len(),
                translated.verified().module().prototypes.len()
            );
        }
    }
}

#[test]
fn rejects_unpaired_extraarg_and_cfg_target_to_data_word() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let extra = if profile == LuaProfile::Lua54 { 82 } else { 84 };
        let orphan = chunk(profile, vec![abc(extra, 0, 0, 0), abc(71, 0, 0, 0)]);
        assert!(translate_official_chunk(&orphan, &VerifyLimits::default()).is_err());
        let jump_to_data = chunk(
            profile,
            vec![
                56 | (((16_777_215 + 1) as u32) << 7),
                abc(4, 0, 0, 0),
                abc(extra, 0, 0, 0),
                abc(71, 0, 0, 0),
            ],
        );
        assert!(translate_official_chunk(&jump_to_data, &VerifyLimits::default()).is_err());
    }
}

#[test]
fn rejects_mismatched_mmbin_and_varargprep_for_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let arithmetic = chunk(
            profile,
            vec![abc(34, 0, 0, 1), abc(46, 0, 1, 7), abc(72, 0, 0, 0)],
        );
        assert!(translate_official_chunk(&arithmetic, &VerifyLimits::default()).is_err());
        let prep = if profile == LuaProfile::Lua54 { 81 } else { 83 };
        let non_variadic = chunk(profile, vec![abc(prep, 0, 0, 0), abc(71, 0, 0, 0)]);
        assert!(translate_official_chunk(&non_variadic, &VerifyLimits::default()).is_err());
    }
}

#[test]
fn mutable_chunk_cannot_bypass_translation_depth_or_total_quota() {
    let mut too_deep = chunk(LuaProfile::Lua55, vec![abc(71, 0, 0, 0)]);
    let mut cursor = &mut too_deep.main;
    for _ in 0..65 {
        cursor.children.push(OfficialPrototype {
            children: vec![],
            ..cursor.clone()
        });
        cursor = cursor.children.last_mut().unwrap();
    }
    assert!(translate_official_chunk(&too_deep, &VerifyLimits::default()).is_err());

    let mut limits = VerifyLimits::default();
    limits.max_instructions = 2;
    let over_total = chunk(
        LuaProfile::Lua55,
        vec![abc(71, 0, 0, 0), abc(71, 0, 0, 0), abc(71, 0, 0, 0)],
    );
    assert!(translate_official_chunk(&over_total, &limits).is_err());
}

#[test]
fn expanded_output_uses_one_instruction_and_constant_budget_across_prototypes() {
    let mut instruction_source = chunk(LuaProfile::Lua55, vec![abc(13, 0, 0, 0), abc(71, 0, 0, 0)]);
    instruction_source
        .main
        .children
        .push(chunk(LuaProfile::Lua55, vec![abc(13, 0, 0, 0), abc(71, 0, 0, 0)]).main);
    let instruction_output =
        translate_official_chunk(&instruction_source, &VerifyLimits::default()).unwrap();
    let bodies = &instruction_output.verified().module().prototypes;
    let instruction_total: usize = bodies.iter().map(|body| body.instructions.len()).sum();
    assert!(
        instruction_total
            > instruction_source.main.code.len() + instruction_source.main.children[0].code.len()
    );
    let mut limits = VerifyLimits::default();
    limits.max_instructions = instruction_total - 1;
    assert!(
        bodies
            .iter()
            .all(|body| body.instructions.len() <= limits.max_instructions)
    );
    let error = translate_official_chunk(&instruction_source, &limits).unwrap_err();
    assert_eq!(error.prototype.0, 1);
    assert!(error.detail.contains("轉譯指令超過 P05 限制"), "{error:?}");

    let mut constant_source = chunk(
        LuaProfile::Lua55,
        vec![
            abc(1, 0, 0, 0),
            abc(1, 0, 0, 0),
            abc(1, 0, 0, 0),
            abc(71, 0, 0, 0),
        ],
    );
    constant_source
        .main
        .children
        .push(chunk(LuaProfile::Lua55, constant_source.main.code.clone()).main);
    let constant_output =
        translate_official_chunk(&constant_source, &VerifyLimits::default()).unwrap();
    let bodies = &constant_output.verified().module().prototypes;
    let constant_total: usize = bodies.iter().map(|body| body.constants.len()).sum();
    assert!(
        constant_total
            > constant_source.main.constants.len()
                + constant_source.main.children[0].constants.len()
    );
    limits = VerifyLimits::default();
    limits.max_constants = constant_total - 1;
    assert!(
        bodies
            .iter()
            .all(|body| body.constants.len() <= limits.max_constants)
    );
    let error = translate_official_chunk(&constant_source, &limits).unwrap_err();
    assert_eq!(error.prototype.0, 1);
    assert!(error.detail.contains("轉譯常數超過 P05 限制"), "{error:?}");
}

#[test]
fn close_metadata_uses_one_byte_budget_across_prototypes() {
    let code = vec![abc(55, 0, 0, 0), abc(71, 0, 0, 0)];
    let mut source = chunk(LuaProfile::Lua55, code.clone());
    source
        .main
        .children
        .push(chunk(LuaProfile::Lua55, code).main);
    translate_official_chunk(&source, &VerifyLimits::default()).unwrap();

    let path_bytes = std::mem::size_of::<BytecodeClosePath>()
        + std::mem::size_of::<BytecodeBindingId>()
        + std::mem::size_of::<Register>();
    let mut limits = VerifyLimits::default();
    limits.max_module_bytes = path_bytes * 3 + 1;
    assert!(limits.max_module_bytes > 32);
    let error = translate_official_chunk(&source, &limits).unwrap_err();
    assert_eq!(error.prototype.0, 1);
    assert!(
        error.detail.contains("close metadata 超過 P05 bytes 限制"),
        "{error:?}"
    );
}

#[test]
fn translates_official_table_arithmetic_branches_and_loops_for_both_profiles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-flow.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-flow.luac").as_slice(),
        ),
    ] {
        let source =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        assert_eq!(translated.verified().profile(), profile);
        assert_eq!(
            translated.pc_mappings().len(),
            translated.verified().module().prototypes.len()
        );
        let body = &translated.verified().module().prototypes[1];
        let guest_start = body
            .binding_registers
            .iter()
            .find(|(binding, _)| binding.ordinal == 1)
            .unwrap()
            .1;
        let numeric_prepare = body
            .instructions
            .iter()
            .find_map(|entry| match entry.instruction {
                Instruction::NumericForPrepare {
                    control,
                    limit,
                    step,
                    visible,
                    ..
                } => Some((control, limit, step, visible)),
                _ => None,
            })
            .unwrap();
        assert!(numeric_prepare.0.0 < guest_start.0);
        assert!(numeric_prepare.1.0 < guest_start.0);
        assert!(numeric_prepare.2.0 < guest_start.0);
        assert!(numeric_prepare.3.0 >= guest_start.0);
        assert!(
            body.instructions
                .iter()
                .any(|entry| matches!(entry.instruction,
            Instruction::NumericForNext { control, limit, step, visible, .. }
                if (control, limit, step, visible) == numeric_prepare))
        );
        assert!(
            body.close_paths
                .iter()
                .any(|path| path.kind == BytecodeExitKind::Normal && !path.registers.is_empty())
        );
    }
}

#[test]
fn open_vararg_and_call_lists_preserve_producer_register_and_empty_tail() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for call_producer in [false, true] {
            let source = open_list_chunk(profile, call_producer);
            let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
            let prototype = &translated.verified().module().prototypes[0];
            let call = translated
                .internal_calls()
                .iter()
                .find(|call| call.open_tail().is_some())
                .unwrap();
            let producer = call.open_tail().unwrap();
            let call_index = call.call_pc().0 as usize;
            assert!(matches!(prototype.instructions[call_index - 1].instruction,
                Instruction::Vararg { base, result_mode: ResultMode::All }
                    | Instruction::Call { base, result_mode: ResultMode::All, .. } if base == producer));
            assert!(matches!(prototype.instructions[call_index].instruction,
                Instruction::Call { base, arg_count: u16::MAX, result_mode: ResultMode::Fixed(0) }
                    if base == call.function_register()));
            assert_eq!(call.inputs().last().unwrap().0 + 1, producer.0);
            assert!(call.function_register().0 < producer.0);
            let skip_slot = call.function_register().0 + 3;
            let skip = prototype
                .instructions
                .iter()
                .find_map(|entry| match entry.instruction {
                    Instruction::LoadConst { dest, constant } if dest.0 == skip_slot => {
                        prototype.constants.get(constant.0 as usize)
                    }
                    _ => None,
                });
            assert_eq!(skip, Some(&BytecodeConstant::Integer(1)));
        }
    }
}

#[test]
fn lua55_table_vararg_keeps_open_setlist_producer_adjacent_to_consumer() {
    let mut source = open_list_chunk(LuaProfile::Lua55, false);
    source.main.flags = 2;
    source.main.num_params = 1;
    source.main.code[3] = abc(80, 1, 1, 0) | (1 << 15);
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let prototype = &translated.verified().module().prototypes[0];
    let pack = translated
        .internal_calls()
        .iter()
        .find(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
        .unwrap();
    let list = translated
        .internal_calls()
        .iter()
        .find(|call| {
            call.builtin() == OfficialFixedBuiltin::RawListWrite && call.open_tail().is_some()
        })
        .unwrap();
    let list_pc = list.call_pc().0 as usize;
    assert!(pack.call_pc().0 as usize + 2 < list_pc);
    assert!(matches!(
        prototype.instructions[list_pc - 1].instruction,
        Instruction::Vararg {
            result_mode: ResultMode::All,
            ..
        }
    ));
    assert!(matches!(
        prototype.instructions[list_pc].instruction,
        Instruction::Call {
            arg_count: u16::MAX,
            result_mode: ResultMode::Fixed(0),
            ..
        }
    ));
}

#[test]
fn rejects_branches_into_open_list_consumer_or_nested_producer() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut direct = open_list_chunk(profile, false);
        let sink = direct.main.code.len() - 2;
        direct.main.code.insert(sink - 1, jump(1));
        assert!(translate_official_chunk(&direct, &VerifyLimits::default()).is_err());

        let extra = if profile == LuaProfile::Lua54 { 82 } else { 84 };
        let prep = if profile == LuaProfile::Lua54 { 81 } else { 83 };
        let mut nested = chunk(
            profile,
            vec![
                abc(prep, 0, 0, 0),
                abc(19, 0, 0, 0),
                abc(extra, 0, 0, 0),
                abc(8, 1, 0, 0),
                jump(1),
                abc(80, 2, 0, 0),
                abc(68, 1, 0, 0),
                abc(78, 0, 0, 0),
                abc(71, 0, 0, 0),
            ],
        );
        nested.main.flags = 1;
        nested.main.max_stack_size = 4;
        assert!(translate_official_chunk(&nested, &VerifyLimits::default()).is_err());
    }
}

#[test]
fn rejects_close_expansion_and_mutable_string_before_unbounded_allocation() {
    let mut closing = chunk(
        LuaProfile::Lua55,
        vec![abc(79, 0, 0, 0), abc(54, 0, 0, 0), abc(71, 0, 0, 0)],
    );
    closing.main.max_stack_size = 40;
    let mut child = chunk(LuaProfile::Lua55, vec![abc(71, 0, 0, 0)]).main;
    child.upvalues = (0..32)
        .map(|index| OfficialUpvalue {
            in_stack: true,
            index,
            kind: 0,
        })
        .collect();
    closing.main.children.push(child);
    let mut limits = VerifyLimits::default();
    limits.max_instructions = 12;
    let error = translate_official_chunk(&closing, &limits).unwrap_err();
    assert!(error.detail.contains("轉譯指令超過"), "{error:?}");

    let mut oversized = chunk(LuaProfile::Lua55, vec![abc(3, 0, 0, 0), abc(71, 0, 0, 0)]);
    oversized.main.constants = vec![OfficialConstant::String {
        bytes: vec![7; 65],
        long: false,
    }];
    limits.max_instructions = 100;
    limits.max_module_bytes = 64;
    let error = translate_official_chunk(&oversized, &limits).unwrap_err();
    assert!(error.detail.contains("bytes 超過"), "{error:?}");
}

#[test]
fn rejects_inconsistent_to_be_closed_state_at_cfg_join() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut source = chunk(
            profile,
            vec![
                abc(66, 0, 0, 0),
                jump(1),
                abc(55, 1, 0, 0),
                abc(71, 0, 0, 0),
            ],
        );
        source.main.max_stack_size = 2;
        let error = translate_official_chunk(&source, &VerifyLimits::default()).unwrap_err();
        assert!(
            error.detail.contains("CFG 匯合的 TBC 狀態不一致"),
            "{error:?}"
        );
    }
}

#[test]
fn lua55_named_vararg_table_uses_mapped_guest_binding() {
    let mut source = chunk(
        LuaProfile::Lua55,
        vec![
            abc(83, 0, 0, 0),
            abc(80, 2, 1, 2) | (1 << 15),
            abc(72, 2, 0, 0),
        ],
    );
    source.main.num_params = 1;
    source.main.max_stack_size = 3;
    source.main.flags = 2;
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let prototype = &translated.verified().module().prototypes[0];
    let guest_table = translated
        .frame_inputs()
        .iter()
        .find(|input| input.source() == OfficialFrameInputSource::GuestNamedVarargTable)
        .unwrap();
    let active = translated
        .frame_inputs()
        .iter()
        .find(|input| input.source() == OfficialFrameInputSource::ActiveVarargs)
        .unwrap();
    let (binding, register) = prototype.named_vararg.unwrap();
    assert_eq!(register, active.register());
    assert!(binding.ordinal > u32::from(source.main.max_stack_size));
    assert_ne!(guest_table.register(), active.register());
    assert_eq!(
        prototype
            .binding_registers
            .iter()
            .find(|(candidate, _)| candidate.ordinal == 2)
            .unwrap()
            .1,
        guest_table.register()
    );
    assert_eq!(
        translated
            .internal_calls()
            .iter()
            .filter(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
            .count(),
        1
    );
    assert!(
        matches!(prototype.instructions[0].instruction, Instruction::Move { dest, src } if dest.0 > src.0)
    );
    assert!(translated.pc_mappings()[0].official_to_rvlu()[0].unwrap().0 > 0);

    source.main.code[1] &= !(1 << 15);
    assert!(translate_official_chunk(&source, &VerifyLimits::default()).is_err());
}

#[test]
fn lua55_getvarg_reads_each_frames_original_varargs_without_guest_b() {
    let code = vec![abc(83, 0, 0, 0), abc(81, 0, 1, 2), abc(72, 0, 0, 0)];
    let mut source = chunk(LuaProfile::Lua55, code.clone());
    source.main.flags = 1;
    source.main.max_stack_size = 3;
    let mut child = chunk(LuaProfile::Lua55, code).main;
    child.flags = 1;
    child.max_stack_size = 3;
    source.main.children.push(child);
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    assert_eq!(translated.frame_inputs().len(), 2);
    for prototype in 0..2 {
        let input = &translated.frame_inputs()[prototype];
        assert_eq!(input.prototype().0 as usize, prototype);
        assert_eq!(input.source(), OfficialFrameInputSource::OriginalVarargs);
        let call = translated
            .internal_calls()
            .iter()
            .find(|call| {
                call.prototype().0 as usize == prototype
                    && call.builtin() == OfficialFixedBuiltin::RawVarargGet
            })
            .unwrap();
        let instructions = &translated.verified().module().prototypes[prototype].instructions;
        assert!(
            matches!(instructions[call.call_pc().0 as usize - 2].instruction,
            Instruction::Move { dest, src }
                if dest == call.inputs()[0] && src == input.register())
        );
        assert!(
            translated.verified().module().prototypes[prototype]
                .named_vararg
                .is_none()
        );
    }
    source.main.code[1] = abc(81, 0, 0, 2);
    let changed_b = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    assert_eq!(
        translated.verified().module().prototypes[0].instructions,
        changed_b.verified().module().prototypes[0].instructions
    );
}

#[test]
fn lua55_vararg_raw_and_table_modes_preserve_explicit_source_and_result_modes() {
    for (flags, k, b) in [
        (1_u8, false, 0_u32),
        (1, false, 4),
        (2, true, 0),
        (2, true, 1),
    ] {
        for (c, expected) in [
            (0_u32, ResultMode::All),
            (1, ResultMode::Fixed(0)),
            (3, ResultMode::Fixed(2)),
        ] {
            let vararg = abc(80, 2, b, c) | if k { 1 << 15 } else { 0 };
            let mut source = chunk(
                LuaProfile::Lua55,
                vec![
                    abc(83, 0, 0, 0),
                    vararg,
                    if c == 0 {
                        abc(70, 2, 0, 0)
                    } else {
                        abc(71, 0, 0, 0)
                    },
                ],
            );
            source.main.flags = flags;
            source.main.num_params = 1;
            source.main.max_stack_size = 5;
            let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
            let prototype = &translated.verified().module().prototypes[0];
            let active = translated
                .frame_inputs()
                .iter()
                .find(|input| input.source() == OfficialFrameInputSource::ActiveVarargs)
                .unwrap();
            assert_eq!(prototype.named_vararg.unwrap().1, active.register());
            let vararg_pc = prototype
                .instructions
                .iter()
                .position(|entry| {
                    matches!(entry.instruction, Instruction::Vararg { result_mode, .. }
                    if result_mode == expected)
                })
                .unwrap();
            if k {
                let guest_table = translated
                    .frame_inputs()
                    .iter()
                    .find(|input| input.source() == OfficialFrameInputSource::GuestNamedVarargTable)
                    .unwrap();
                assert_ne!(guest_table.register(), active.register());
                let call = translated
                    .internal_calls()
                    .iter()
                    .find(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
                    .unwrap();
                let call_pc = call.call_pc().0 as usize;
                assert_eq!(call_pc + 2, vararg_pc);
                assert!(matches!(prototype.instructions[call_pc - 2].instruction,
                    Instruction::Move { dest, src } if dest == call.inputs()[0]
                        && src == prototype.binding_registers.iter().find(|(binding, _)|
                            binding.ordinal == b + 1).unwrap().1));
                assert!(matches!(prototype.instructions[call_pc - 1].instruction,
                    Instruction::LoadConst { dest, constant } if dest == call.inputs()[1]
                        && prototype.constants[constant.0 as usize] == BytecodeConstant::Integer(
                            if c == 0 { -1 } else { i64::from(c - 1) })));
                assert!(matches!(
                    prototype.instructions[call_pc].instruction,
                    Instruction::Call {
                        result_mode: ResultMode::Fixed(1),
                        ..
                    }
                ));
                assert!(matches!(prototype.instructions[vararg_pc - 1].instruction,
                    Instruction::Move { dest, src } if dest == active.register()
                        && src == call.function_register()));
            } else {
                let raw = translated
                    .frame_inputs()
                    .iter()
                    .find(|input| input.source() == OfficialFrameInputSource::OriginalVarargs)
                    .unwrap();
                assert!(matches!(prototype.instructions[vararg_pc - 1].instruction,
                    Instruction::Move { dest, src } if dest == active.register()
                        && src == raw.register()));
                assert!(
                    translated
                        .internal_calls()
                        .iter()
                        .all(|call| call.builtin() != OfficialFixedBuiltin::PackUnpack)
                );
            }
        }
    }

    let mut bad_b = chunk(
        LuaProfile::Lua55,
        vec![
            abc(83, 0, 0, 0),
            abc(80, 0, 5, 1) | (1 << 15),
            abc(71, 0, 0, 0),
        ],
    );
    bad_b.main.flags = 2;
    bad_b.main.max_stack_size = 5;
    assert!(translate_official_chunk(&bad_b, &VerifyLimits::default()).is_err());
    bad_b.main.flags = 1;
    bad_b.main.code[1] = abc(80, 0, 0, 1) | (1 << 15);
    assert!(translate_official_chunk(&bad_b, &VerifyLimits::default()).is_err());
}

#[test]
fn lua55_table_vararg_prepares_a_fresh_snapshot_after_guest_table_write() {
    let table_vararg = abc(80, 2, 1, 2) | (1 << 15);
    let mut source = chunk(
        LuaProfile::Lua55,
        vec![
            abc(83, 0, 0, 0),
            table_vararg,
            abc(1, 3, 0, 0),
            abc(17, 1, 1, 3),
            table_vararg,
            abc(72, 2, 0, 0),
        ],
    );
    source.main.flags = 2;
    source.main.num_params = 1;
    source.main.max_stack_size = 4;
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let prototype = &translated.verified().module().prototypes[0];
    let guest_table = translated
        .frame_inputs()
        .iter()
        .find(|input| input.source() == OfficialFrameInputSource::GuestNamedVarargTable)
        .unwrap()
        .register();
    let calls: Vec<_> = translated
        .internal_calls()
        .iter()
        .filter(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
        .collect();
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert!(
            matches!(prototype.instructions[call.call_pc().0 as usize - 2].instruction,
            Instruction::Move { dest, src } if dest == call.inputs()[0] && src == guest_table)
        );
    }
    let first = calls[0].call_pc().0 as usize;
    let second = calls[1].call_pc().0 as usize;
    assert!(prototype.instructions[first..second].iter().any(|entry|
        matches!(entry.instruction, Instruction::SetTable { table, .. } if table == guest_table)));
}

fn opcode_case(profile: LuaProfile, opcode: u32) -> OfficialChunk {
    let prep = if profile == LuaProfile::Lua54 { 81 } else { 83 };
    let extra = if profile == LuaProfile::Lua54 { 82 } else { 84 };
    let mut code = vec![abc(prep, 0, 0, 0)];
    let sequence = match opcode {
        4 | 19 => vec![abc(opcode, 0, 0, 0), abc(extra, 0, 0, 0)],
        6 => vec![abc(6, 0, 0, 0), abc(0, 0, 0, 0)],
        21 => vec![abc(21, 0, 0, 127), abc(47, 0, 127, 6)],
        22..=31 => vec![abc(opcode, 0, 0, 1), abc(48, 0, 1, opcode - 16)],
        32 | 33 => {
            let left = opcode == if profile == LuaProfile::Lua55 { 32 } else { 33 };
            vec![
                abc(opcode, 0, 0, 128),
                abc(47, 0, 128, if left { 16 } else { 17 }) | if left { 1 << 15 } else { 0 },
            ]
        }
        34..=45 => vec![abc(opcode, 0, 0, 0), abc(46, 0, 0, opcode - 28)],
        46 => vec![abc(34, 0, 0, 0), abc(46, 0, 0, 6)],
        47 => vec![abc(21, 0, 0, 127), abc(47, 0, 127, 6)],
        48 => vec![abc(22, 0, 0, 1), abc(48, 0, 1, 6)],
        53 => vec![abc(53, 0, 2, 0)],
        56 => vec![jump(0)],
        57..=67 => vec![
            abc(
                opcode,
                0,
                if (61..=65).contains(&opcode) { 127 } else { 0 },
                0,
            ),
            jump(1),
            abc(0, 0, 0, 0),
        ],
        73 | 74 => vec![abx(74, 0, 1), abc(0, 7, 7, 0), abx(73, 0, 2)],
        75..=77 => vec![
            abx(75, 0, 1),
            abc(0, 7, 7, 0),
            abc(76, 0, 0, 1),
            abx(77, 0, 3),
        ],
        81 if profile == LuaProfile::Lua54 => Vec::new(),
        83 if profile == LuaProfile::Lua55 => Vec::new(),
        value if value == extra as u32 => vec![abc(4, 0, 0, 0), abc(extra, 0, 0, 0)],
        79 => vec![abc(79, 0, 0, 0)],
        80 => vec![abc(80, 0, 0, 2)],
        70 => vec![abc(70, 0, 1, 0)],
        68 | 69 => vec![abc(opcode, 0, 1, 1)],
        78 => vec![abc(78, 0, 1, 0)],
        82 if profile == LuaProfile::Lua55 => vec![abc(82, 0, 0, 0)],
        _ => vec![abc(opcode, 0, 0, 0)],
    };
    code.extend(sequence);
    code.push(abc(71, 0, 0, 0));
    let mut source = chunk(profile, code);
    source.main.flags = 1;
    source.main.max_stack_size = 16;
    source.main.constants = vec![
        OfficialConstant::String {
            bytes: b"x".to_vec(),
            long: false,
        },
        OfficialConstant::Integer(1),
        OfficialConstant::Number(1.5),
    ];
    source.main.upvalues.push(OfficialUpvalue {
        in_stack: false,
        index: 0,
        kind: 0,
    });
    source.root_upvalues = 1;
    source
        .main
        .children
        .push(chunk(profile, vec![abc(71, 0, 0, 0)]).main);
    source
}

#[test]
fn every_profile_opcode_has_a_verified_structural_translation_or_paired_data_role() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let count = if profile == LuaProfile::Lua54 { 83 } else { 85 };
        for opcode in 0..count {
            let source = opcode_case(profile, opcode);
            assert!(source.main.code.iter().any(|word| word & 0x7f == opcode));
            let bytes = encode_official_chunk(&source, false, &OfficialChunkLimits::default())
                .unwrap_or_else(|error| panic!("{profile:?} opcode {opcode}: {error}"));
            let preflight = preflight_official_chunk(
                &bytes,
                profile,
                &OfficialChunkLimits::default(),
                &VerifyLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{profile:?} opcode {opcode}: {error}"));
            let mut work = OfficialWorkBudget::new(u64::MAX);
            let translated =
                translate_official_chunk_with_work(&source, &VerifyLimits::default(), &mut work)
                    .unwrap_or_else(|error| panic!("{profile:?} opcode {opcode}: {error}"));
            assert_eq!(translated.verified().profile(), profile);
            assert!(
                translated
                    .verified()
                    .module()
                    .prototypes
                    .iter()
                    .map(|proto| proto.instructions.len())
                    .sum::<usize>()
                    <= preflight.expanded_instructions,
                "{profile:?} opcode {opcode}: E 上界不足"
            );
            assert!(
                work.consumed() <= preflight.subsequent_work,
                "{profile:?} opcode {opcode}: work 上界不足"
            );
            if (46..=48).contains(&opcode)
                || opcode == if profile == LuaProfile::Lua54 { 82 } else { 84 }
            {
                let data_pc = source
                    .main
                    .code
                    .iter()
                    .position(|word| word & 0x7f == opcode)
                    .unwrap();
                assert_eq!(
                    translated.pc_mappings()[0].official_to_rvlu()[data_pc],
                    None
                );
            }
        }
    }
}

fn plan_builtin_for_test(kind: OfficialFixedBuiltin) -> OfficialPlanBuiltin {
    match kind {
        OfficialFixedBuiltin::RawListWrite => OfficialPlanBuiltin::RawListWrite,
        OfficialFixedBuiltin::RawVarargGet => OfficialPlanBuiltin::RawVarargGet,
        OfficialFixedBuiltin::PackUnpack => OfficialPlanBuiltin::PackUnpack,
        OfficialFixedBuiltin::GlobalNilCheck => OfficialPlanBuiltin::GlobalNilCheck,
    }
}

fn candidate_from_translation(translation: &OfficialTranslation) -> OfficialPlanCandidate {
    let plan = translation.verified().official_execution().unwrap();
    let prototypes = &translation.verified().module().prototypes;
    OfficialPlanCandidate {
        root_bindings: plan.root_bindings().to_vec(),
        upvalue_maps: prototypes
            .iter()
            .map(|proto| plan.upvalue_map(proto.id).unwrap().clone())
            .collect(),
        frame_inputs: prototypes
            .iter()
            .flat_map(|proto| plan.frame_inputs(proto.id).copied())
            .collect(),
        calls: translation
            .internal_calls()
            .iter()
            .map(|call| OfficialPlanCall {
                prototype: call.prototype(),
                call_pc: call.call_pc(),
                function_register: call.function_register(),
                source_upvalue: call.source_upvalue(),
                inputs: call.inputs().to_vec(),
                open_tail: call.open_tail(),
                builtin: plan_builtin_for_test(call.builtin()),
            })
            .collect(),
    }
}

#[test]
fn p05_rejects_forged_private_call_result_leak_and_cfg_entry() {
    let source = open_list_chunk(LuaProfile::Lua55, true);
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let call = translation
        .internal_calls()
        .iter()
        .find(|call| call.builtin() == OfficialFixedBuiltin::RawListWrite)
        .unwrap();
    let pc = call.call_pc().0 as usize;
    let guest = translation
        .verified()
        .official_execution()
        .unwrap()
        .upvalue_map(translation.verified().module().prototypes[0].id)
        .unwrap()
        .guest_start;

    let mut leaked = translation.verified().module().clone();
    leaked.prototypes[0].instructions[pc + 1].instruction = Instruction::Move {
        dest: guest,
        src: call.function_register(),
    };
    let verified = verify_module(leaked, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let error = verify_official_execution_plan(
        verified,
        candidate_from_translation(&translation),
        &VerifyLimits::default(),
    )
    .unwrap_err();
    assert!(error.message.contains("清除 private slot"), "{error:?}");

    let mut jumped = translation.verified().module().clone();
    let body = &mut jumped.prototypes[0];
    let load_pc = (0..pc)
        .rev()
        .find(|&index| {
            matches!(body.instructions[index].instruction,
            Instruction::GetUpvalue { dest, .. } if dest == call.function_register())
        })
        .unwrap();
    let target = rivetlua_core::InstructionOffset((load_pc + 1) as u32);
    let outside = (0..load_pc)
        .find(|&index| {
            matches!(
                body.instructions[index].instruction,
                Instruction::LoadNil { .. } | Instruction::Move { .. }
            )
        })
        .unwrap();
    body.instructions[outside].instruction = Instruction::Jump { target };
    let verified = verify_module(jumped, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let error = verify_official_execution_plan(
        verified,
        candidate_from_translation(&translation),
        &VerifyLimits::default(),
    )
    .unwrap_err();
    assert!(error.message.contains("CFG 不可跳入 private"), "{error:?}");
}

#[test]
fn p05_rejects_forged_frame_input_overlap_and_private_parent_capture() {
    let mut source = chunk(
        LuaProfile::Lua55,
        vec![
            abc(83, 0, 0, 0),
            abc(80, 0, 0, 2) | (1 << 15),
            abc(71, 0, 0, 0),
        ],
    );
    source.main.flags = 2;
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let mut candidate = candidate_from_translation(&translation);
    let guest_start = candidate.upvalue_maps[0].guest_start;
    candidate
        .frame_inputs
        .iter_mut()
        .find(|input| input.source == rivetlua_core::OfficialPlanFrameInputSource::ActiveVarargs)
        .unwrap()
        .register = guest_start;
    let verified = verify_module(
        translation.verified().module().clone(),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let error =
        verify_official_execution_plan(verified, candidate, &VerifyLimits::default()).unwrap_err();
    assert!(error.message.contains("frame input 重複"), "{error:?}");

    let mut source = chunk(LuaProfile::Lua55, vec![abc(79, 0, 0, 0), abc(71, 0, 0, 0)]);
    let mut child_source = chunk(LuaProfile::Lua55, vec![abc(71, 0, 0, 0)]).main;
    child_source.upvalues.push(OfficialUpvalue {
        in_stack: true,
        index: 0,
        kind: 0,
    });
    source.main.children.push(child_source);
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let mut forged = translation.verified().module().clone();
    let child = forged
        .prototypes
        .iter()
        .position(|proto| proto.parent.is_some() && !proto.upvalues.is_empty())
        .unwrap();
    let parent = forged.prototypes[child].parent.unwrap();
    let parent_index = forged
        .prototypes
        .iter()
        .position(|proto| proto.id == parent)
        .unwrap();
    let parent_start =
        candidate_from_translation(&translation).upvalue_maps[parent_index].guest_start;
    let private_binding = forged.prototypes[parent_index]
        .binding_registers
        .iter()
        .find(|(_, register)| register.0 < parent_start.0)
        .unwrap()
        .0;
    let private_register = forged.prototypes[parent_index]
        .binding_registers
        .iter()
        .find(|(binding, _)| *binding == private_binding)
        .unwrap()
        .1;
    let BytecodeUpvalueSource::ParentLocal(original_binding) =
        forged.prototypes[child].upvalues[0].source
    else {
        panic!("原始 child capture 須為 ParentLocal");
    };
    let original_register = forged.prototypes[parent_index]
        .binding_registers
        .iter()
        .find(|(binding, _)| *binding == original_binding)
        .unwrap()
        .1;
    forged.prototypes[child].upvalues[0].source =
        BytecodeUpvalueSource::ParentLocal(private_binding);
    let parent_body = &mut forged.prototypes[parent_index];
    for entry in &mut parent_body.instructions {
        if let Instruction::Close { base, count: 0 } = &mut entry.instruction {
            if *base == original_register {
                *base = private_register;
            }
        }
        if let Some(path) = &mut entry.close_path {
            for binding in &mut path.bindings {
                if *binding == original_binding {
                    *binding = private_binding;
                }
            }
            for register in &mut path.registers {
                if *register == original_register {
                    *register = private_register;
                }
            }
        }
    }
    for path in &mut parent_body.close_paths {
        for binding in &mut path.bindings {
            if *binding == original_binding {
                *binding = private_binding;
            }
        }
        for register in &mut path.registers {
            if *register == original_register {
                *register = private_register;
            }
        }
    }
    let verified = verify_module(forged, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let error = verify_official_execution_plan(
        verified,
        candidate_from_translation(&translation),
        &VerifyLimits::default(),
    )
    .unwrap_err();
    assert!(error.message.contains("private register"), "{error:?}");
}

#[test]
fn p05_rejects_raw_vararg_pack_argument_moved_into_guest_registers() {
    let mut source = chunk(
        LuaProfile::Lua55,
        vec![abc(83, 0, 0, 0), abc(81, 0, 1, 2), abc(72, 0, 0, 0)],
    );
    source.main.flags = 1;
    source.main.max_stack_size = 3;
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let mut candidate = candidate_from_translation(&translation);
    let guest_start = candidate.upvalue_maps[0].guest_start;
    let raw = candidate.frame_inputs[0].register;
    let call = candidate
        .calls
        .iter_mut()
        .find(|call| call.builtin == OfficialPlanBuiltin::RawVarargGet)
        .unwrap();
    let forged_base = Register(guest_start.0 - 1);
    let pc = call.call_pc.0 as usize;
    let mut forged = translation.verified().module().clone();
    let body = &mut forged.prototypes[0];
    let load = (0..pc)
        .rev()
        .find(|&index| {
            matches!(body.instructions[index].instruction,
        Instruction::GetUpvalue { dest, .. } if dest == call.function_register)
        })
        .unwrap();
    body.instructions[load].instruction = Instruction::GetUpvalue {
        dest: forged_base,
        upvalue: call.source_upvalue,
    };
    body.instructions[pc - 2].instruction = Instruction::Move {
        dest: guest_start,
        src: raw,
    };
    body.instructions[pc - 1].instruction = Instruction::Move {
        dest: Register(guest_start.0 + 1),
        src: Register(guest_start.0 + 2),
    };
    body.instructions[pc].instruction = Instruction::Call {
        base: forged_base,
        arg_count: 2,
        result_mode: ResultMode::Fixed(1),
    };
    body.instructions[pc + 1].instruction = Instruction::Move {
        dest: Register(guest_start.0 + 1),
        src: forged_base,
    };
    call.function_register = forged_base;
    call.inputs = vec![guest_start, Register(guest_start.0 + 1)];
    let verified = verify_module(forged, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let error =
        verify_official_execution_plan(verified, candidate, &VerifyLimits::default()).unwrap_err();
    assert!(error.message.contains("private 輸入與 guest"), "{error:?}");
}

#[test]
fn p05_rejects_nested_pack_snapshot_used_as_raw_list_table() {
    let mut source = open_list_chunk(LuaProfile::Lua55, false);
    source.main.flags = 2;
    source.main.num_params = 1;
    source.main.code[3] = abc(80, 1, 1, 0) | (1 << 15);
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let mut candidate = candidate_from_translation(&translation);
    let list_table_input = candidate
        .calls
        .iter()
        .find(|call| call.builtin == OfficialPlanBuiltin::RawListWrite && call.open_tail.is_some())
        .unwrap()
        .inputs[0];
    let pack = candidate
        .calls
        .iter()
        .find(|call| call.builtin == OfficialPlanBuiltin::PackUnpack)
        .unwrap();
    let pack_pc = pack.call_pc.0 as usize;
    let pack_result = pack.function_register;
    let mut forged = translation.verified().module().clone();
    let body = &mut forged.prototypes[0];
    let (binding, _) = body.named_vararg.unwrap();
    body.named_vararg = Some((binding, list_table_input));
    body.binding_registers
        .iter_mut()
        .find(|(candidate, _)| *candidate == binding)
        .unwrap()
        .1 = list_table_input;
    body.instructions[pack_pc + 1].instruction = Instruction::Move {
        dest: list_table_input,
        src: pack_result,
    };
    candidate
        .frame_inputs
        .iter_mut()
        .find(|input| input.source == rivetlua_core::OfficialPlanFrameInputSource::ActiveVarargs)
        .unwrap()
        .register = list_table_input;
    let verified = verify_module(forged, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let error =
        verify_official_execution_plan(verified, candidate, &VerifyLimits::default()).unwrap_err();
    assert!(
        error
            .message
            .contains("private 輸入與 guest/frame/builtin 重疊"),
        "{error:?}"
    );
}
