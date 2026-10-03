use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_translation::{OfficialWorkBudget, translate_official_chunk};
use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction, InstructionOffset,
    LuaProfile, ModuleOrigin, NativeDebugCandidate, NativePrototypeDebug, OfficialConstant,
    OfficialPlanCandidate, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode,
    TransportLimits, VerifyLimits, decode_transport_module, encode_module, encode_transport_module,
    preflight_transport_decode, preflight_transport_encode, transport_encode_scan_admission,
    transport_scan_admission, verify_module, verify_native_builtin_plan,
    verify_official_execution_plan,
};

fn work(limits: &TransportLimits) -> OfficialWorkBudget {
    OfficialWorkBudget::for_limits(&limits.verify).unwrap()
}

fn set_total_len(sidecar: &mut [u8]) {
    let len = sidecar.len() as u64;
    sidecar[8..16].copy_from_slice(&len.to_le_bytes());
}

fn imported(profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let bytes: &[u8] = match profile {
        LuaProfile::Lua54 => include_bytes!("official_chunk_fixtures/lua54-debug.luac"),
        LuaProfile::Lua55 => include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
    };
    imported_bytes(profile, bytes)
}

fn imported_bytes(profile: LuaProfile, bytes: &[u8]) -> rivetlua_core::VerifiedModule {
    let chunk = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&chunk, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn official_transport_preserves_strip_closure_helpers_and_source_maps() {
    let fixtures: &[(LuaProfile, &[u8])] = &[
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-strip.luac"),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-strip.luac"),
        ),
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-closure.luac"),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-closure.luac"),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-many-helpers.luac"),
        ),
    ];
    for (profile, bytes) in fixtures {
        let verified = imported_bytes(*profile, bytes);
        let limits = TransportLimits::default();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(&verified, &limits, &mut work).unwrap();
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            *profile,
            &limits,
            &mut work,
        )
        .unwrap();
        assert_eq!(reloaded.origin(), ModuleOrigin::OfficialImport);
        assert_eq!(reloaded.official_execution(), verified.official_execution());
        assert_eq!(
            reloaded.official_artifact().unwrap().pc_mappings(),
            verified.official_artifact().unwrap().pc_mappings()
        );
        for prototype in &verified.module().prototypes {
            assert_eq!(
                reloaded
                    .official_artifact()
                    .unwrap()
                    .effective_source(prototype.id),
                verified
                    .official_artifact()
                    .unwrap()
                    .effective_source(prototype.id),
            );
        }
    }
}

fn simple_native_module(profile: LuaProfile) -> BytecodeModule {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 10,
    };
    let binding = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    BytecodeModule {
        format_version: RVLU_V2,
        profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        span,
        function_prototypes: vec![(0, ProtoId(0))],
        prototypes: vec![BytecodePrototype {
            id: ProtoId(0),
            function: 0,
            parent: None,
            span,
            register_count: 2,
            parameter_count: 0,
            is_variadic: false,
            named_vararg: None,
            frame: FrameLayout {
                register_limit: 2,
                initial_top: Register(2),
                dynamic_top: Register(2),
                return_base: Register(0),
                environment: Register(1),
                environment_source: EnvironmentSource::RootExternal,
                registers_start_as_nil: true,
            },
            global_environment: Register(1),
            global_environment_binding: binding,
            binding_registers: vec![(binding, Register(1))],
            constants: vec![BytecodeConstant::Integer(42)],
            upvalues: vec![],
            instructions: vec![
                BytecodeInstruction {
                    instruction: Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    span,
                    close_path: None,
                },
                BytecodeInstruction {
                    instruction: Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                    span,
                    close_path: None,
                },
            ],
            close_paths: vec![],
        }],
    }
}

fn native_debugged(profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let module = simple_native_module(profile);
    let candidate = NativeDebugCandidate {
        source_name: b"@transport-native.lua".to_vec(),
        prototypes: module
            .prototypes
            .iter()
            .map(|prototype| NativePrototypeDebug {
                prototype: prototype.id,
                line_defined: 1,
                last_line_defined: 1,
                lines: vec![1; prototype.instructions.len()],
                locals: Vec::new(),
                upvalue_names: vec![None; prototype.upvalues.len()],
                max_active_locals: 0,
            })
            .collect(),
    };
    let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
    encode_module(module, profile, &VerifyLimits::default())
        .unwrap()
        .with_native_debug(candidate, &VerifyLimits::default(), &mut work)
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn official_transport_rebuilds_plan_artifact_and_exact_rvlu_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let verified = imported(profile);
        let limits = TransportLimits::default();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(&verified, &limits, &mut work).unwrap();
        assert_eq!(&encoded.sidecar()[..4], b"RVAS");
        assert_eq!(encoded.sidecar()[6], 1);
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work,
        )
        .unwrap();
        assert_eq!(reloaded.origin(), ModuleOrigin::OfficialImport);
        assert!(reloaded.official_execution().is_some());
        assert_eq!(
            reloaded.official_artifact().unwrap().pc_mappings(),
            verified.official_artifact().unwrap().pc_mappings()
        );
        let reencoded = encode_transport_module(&reloaded, &limits, &mut work).unwrap();
        assert_eq!(reencoded.rvlu(), encoded.rvlu());
        assert_eq!(reencoded.sidecar(), encoded.sidecar());
    }
}

#[test]
fn native_without_debug_uses_empty_sidecar_and_roundtrips() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let official = imported(profile);
        let native =
            verify_module(official.module().clone(), profile, &VerifyLimits::default()).unwrap();
        assert_eq!(native.origin(), ModuleOrigin::NativeRvlu);
        let limits = TransportLimits::default();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(&native, &limits, &mut work).unwrap();
        assert_eq!(encoded.sidecar().len(), 16);
        assert_eq!(encoded.sidecar()[6], 0);
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work,
        )
        .unwrap();
        assert_eq!(reloaded.origin(), ModuleOrigin::NativeRvlu);
        assert!(reloaded.native_debug().is_none());
        assert!(reloaded.official_execution().is_none());
    }
}

#[test]
fn native_debug_rebuilds_validated_source_and_lines_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let verified = native_debugged(profile);
        let limits = TransportLimits::default();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(&verified, &limits, &mut work).unwrap();
        assert_eq!(encoded.sidecar()[6], 2);
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work,
        )
        .unwrap();
        assert_eq!(reloaded.origin(), ModuleOrigin::NativeRvlu);
        assert_eq!(
            reloaded.native_debug().unwrap().source_name(),
            b"@transport-native.lua"
        );
        for prototype in &verified.module().prototypes {
            let recovered = reloaded
                .native_debug()
                .unwrap()
                .prototype(prototype.id)
                .unwrap();
            assert_eq!(recovered.lines.len(), prototype.instructions.len());
            assert_eq!(recovered.upvalue_names.len(), prototype.upvalues.len());
        }
        let reencoded = encode_transport_module(&reloaded, &limits, &mut work).unwrap();
        assert_eq!(reencoded.rvlu(), encoded.rvlu());
        assert_eq!(reencoded.sidecar(), encoded.sidecar());
    }
}

#[test]
fn transport_rejects_header_and_body_corruption_without_partial_result() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let original =
        encode_transport_module(&imported(profile), &limits, &mut work(&limits)).unwrap();
    let mut cases = Vec::new();
    let mut broken = original.sidecar().to_vec();
    broken[0] = b'X';
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken[4] = 2;
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken[6] = 3;
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken[7] = 1;
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken.truncate(15);
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken.pop();
    set_total_len(&mut broken);
    cases.push(broken);
    let mut broken = original.sidecar().to_vec();
    broken.push(0);
    set_total_len(&mut broken);
    cases.push(broken);
    for sidecar in cases {
        assert!(
            decode_transport_module(
                original.rvlu(),
                &sidecar,
                profile,
                &limits,
                &mut work(&limits)
            )
            .is_err()
        );
    }
    let clean = decode_transport_module(
        original.rvlu(),
        original.sidecar(),
        profile,
        &limits,
        &mut work(&limits),
    )
    .unwrap();
    assert_eq!(clean.origin(), ModuleOrigin::OfficialImport);
}

#[test]
fn official_sidecar_rejects_valid_same_count_rvlu_splice_and_wrong_profile() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let imported = imported(profile);
    let encoded = encode_transport_module(&imported, &limits, &mut work(&limits)).unwrap();
    let mut altered = imported.module().clone();
    altered.span.end_byte += 1;
    let alien = encode_module(altered, profile, &limits.verify).unwrap();
    assert_eq!(
        alien.verified().module().prototypes.len(),
        imported.module().prototypes.len()
    );
    assert!(
        decode_transport_module(
            alien.bytes(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut constant_splice = imported.module().clone();
    let mut changed = false;
    for proto in &mut constant_splice.prototypes {
        for constant in &mut proto.constants {
            if let BytecodeConstant::Integer(value) = constant {
                *value = value.wrapping_add(1);
                changed = true;
                break;
            }
        }
        if changed {
            break;
        }
    }
    assert!(changed, "fixture 必須含整數常數以驗證同 count splice");
    let constant_splice = encode_module(constant_splice, profile, &limits.verify).unwrap();
    assert!(
        decode_transport_module(
            constant_splice.bytes(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut instruction_splice = imported.module().clone();
    let mut changed = false;
    for proto in &mut instruction_splice.prototypes {
        for code in &mut proto.instructions {
            if let Instruction::LoadConst { dest, .. } = code.instruction {
                code.instruction = Instruction::Move { dest, src: dest };
                changed = true;
                break;
            }
        }
        if changed {
            break;
        }
    }
    assert!(
        changed,
        "fixture 必須含 LoadConst 以驗證同 count opcode splice"
    );
    let instruction_splice = encode_module(instruction_splice, profile, &limits.verify).unwrap();
    assert!(
        decode_transport_module(
            instruction_splice.bytes(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            LuaProfile::Lua54,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let other = encode_transport_module(
        &imported_bytes(
            profile,
            include_bytes!("official_chunk_fixtures/lua55-closure.luac"),
        ),
        &limits,
        &mut work(&limits),
    )
    .unwrap();
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            other.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
}

#[test]
fn official_sidecar_rejects_forged_close_binding_bytes() {
    let profile = LuaProfile::Lua55;
    let input = include_bytes!(
        "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-interop-error-close.luac"
    );
    let verified = imported_bytes(profile, input);
    let binding = verified
        .module()
        .prototypes
        .iter()
        .flat_map(|proto| &proto.close_paths)
        .flat_map(|path| &path.bindings)
        .last()
        .copied()
        .expect("錯誤退出 fixture 應有 close binding");
    let limits = TransportLimits::default();
    let encoded = encode_transport_module(&verified, &limits, &mut work(&limits)).unwrap();
    let mut needle = [0u8; 8];
    needle[..4].copy_from_slice(&binding.function.to_le_bytes());
    needle[4..].copy_from_slice(&binding.ordinal.to_le_bytes());
    let offset = encoded
        .rvlu()
        .windows(8)
        .rposition(|window| window == needle)
        .expect("序列化 RVLU 應含 close binding");
    let mut forged = encoded.rvlu().to_vec();
    forged[offset + 4..offset + 8].copy_from_slice(&binding.ordinal.wrapping_add(1).to_le_bytes());
    assert!(
        decode_transport_module(
            &forged,
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
}

#[test]
fn native_sidecar_rejects_forged_identity_lines_counts_and_missing_fields() {
    let profile = LuaProfile::Lua54;
    let limits = TransportLimits::default();
    let verified = native_debugged(profile);
    let encoded = encode_transport_module(&verified, &limits, &mut work(&limits)).unwrap();
    let proto_count_at = 16 + 4 + b"@transport-native.lua".len();
    let proto_id_at = proto_count_at + 4;
    let first_line_at = proto_id_at + 4 + 4 + 4 + 1 + 4;
    let mut forged = encoded.sidecar().to_vec();
    forged[proto_id_at..proto_id_at + 4].copy_from_slice(&99u32.to_le_bytes());
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &forged,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut forged = encoded.sidecar().to_vec();
    forged[first_line_at..first_line_at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &forged,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut forged = encoded.sidecar().to_vec();
    forged[proto_count_at..proto_count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &forged,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut forged = encoded.sidecar().to_vec();
    let local_count_at = first_line_at + 2 * 4;
    forged[local_count_at..local_count_at + 4].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &forged,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut forged = encoded.sidecar().to_vec();
    forged.pop();
    set_total_len(&mut forged);
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &forged,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
}

#[test]
fn preflight_rejects_small_rvlu_with_forged_large_declared_counts_before_allocation() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let verified = verify_module(simple_native_module(profile), profile, &limits.verify).unwrap();
    let encoded = encode_transport_module(&verified, &limits, &mut work(&limits)).unwrap();
    let first_record = 36usize;
    let constants_len_at = first_record + 53;
    let constants_count_at = constants_len_at + 4;
    assert_eq!(
        u32::from_le_bytes(
            encoded.rvlu()[constants_count_at..constants_count_at + 4]
                .try_into()
                .unwrap()
        ),
        1
    );
    let constants_len = u32::from_le_bytes(
        encoded.rvlu()[constants_len_at..constants_len_at + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let instructions_len_at = constants_count_at + constants_len;
    let instructions_count_at = instructions_len_at + 4;
    let instructions_len = u32::from_le_bytes(
        encoded.rvlu()[instructions_len_at..instructions_len_at + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let metadata_count_at = instructions_count_at + instructions_len + 4;
    for offset in [constants_count_at, instructions_count_at, metadata_count_at] {
        let mut forged = encoded.rvlu().to_vec();
        forged[offset..offset + 4].copy_from_slice(&100_000u32.to_le_bytes());
        assert!(
            rivetlua_core::preflight_transport_decode(&forged, encoded.sidecar(), profile, &limits)
                .is_err()
        );
        assert!(
            decode_transport_module(
                &forged,
                encoded.sidecar(),
                profile,
                &limits,
                &mut work(&limits)
            )
            .is_err()
        );
    }
}

#[test]
fn metadata_lookup_work_grows_quadratically_with_bindings_even_for_two_instructions() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let mut work_by_count = Vec::new();
    for count in [128u32, 256u32] {
        let mut raw = simple_native_module(profile);
        for ordinal in 1..count {
            raw.prototypes[0].binding_registers.push((
                BytecodeBindingId {
                    function: 0,
                    ordinal,
                },
                Register(1),
            ));
        }
        let verified = verify_module(raw, profile, &limits.verify).unwrap();
        assert_eq!(verified.module().prototypes[0].instructions.len(), 2);
        let encoded = encode_transport_module(&verified, &limits, &mut work(&limits)).unwrap();
        let scan = transport_scan_admission(encoded.rvlu().len(), encoded.sidecar().len()).unwrap();
        let admission =
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &limits)
                .unwrap();
        let total = scan.work + admission.subsequent_work;
        assert!(
            decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut OfficialWorkBudget::new(total - 1)
            )
            .is_err()
        );
        assert!(
            decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut OfficialWorkBudget::new(total)
            )
            .is_ok()
        );
        work_by_count.push(admission.subsequent_work);
    }
    assert!(work_by_count[1] > work_by_count[0] * 3);
}

#[test]
fn transport_admission_work_sidecar_temporary_and_retained_boundaries_retry() {
    let profile = LuaProfile::Lua54;
    let verified = verify_module(
        simple_native_module(profile),
        profile,
        &VerifyLimits::default(),
    )
    .unwrap();
    let limits = TransportLimits::default();
    let scan = transport_encode_scan_admission(&verified, &limits).unwrap();
    let admission = preflight_transport_encode(&verified, &limits).unwrap();
    let total = scan.work + admission.subsequent_work;
    assert!(total > 1);
    let mut low = limits;
    low.max_work = total - 1;
    assert!(preflight_transport_encode(&verified, &low).is_err());
    assert!(encode_transport_module(&verified, &limits, &mut OfficialWorkBudget::new(0)).is_err());
    assert!(
        encode_transport_module(&verified, &limits, &mut OfficialWorkBudget::new(total - 1))
            .is_err()
    );
    let encoded =
        encode_transport_module(&verified, &limits, &mut OfficialWorkBudget::new(total)).unwrap();
    assert_eq!(&encoded.sidecar()[..4], b"RVAS");
    assert_eq!(&encoded.sidecar()[4..6], &1u16.to_le_bytes());
    assert_eq!(encoded.sidecar()[7], 0);
    assert_eq!(
        u64::from_le_bytes(encoded.sidecar()[8..16].try_into().unwrap()),
        16
    );

    let scan = transport_scan_admission(encoded.rvlu().len(), encoded.sidecar().len()).unwrap();
    let admission =
        preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &limits).unwrap();
    let total = scan.work + admission.subsequent_work;
    let mut low = limits;
    low.max_work = total - 1;
    assert!(preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err());
    let mut low = limits;
    low.max_sidecar_bytes = encoded.sidecar().len() - 1;
    assert!(preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err());
    let mut low = limits;
    low.max_temporary_bytes = admission.temporary_bytes - 1;
    assert!(preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err());
    let mut low = limits;
    low.max_retained_bytes = admission.retained_bytes - 1;
    assert!(preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err());
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut OfficialWorkBudget::new(0)
        )
        .is_err()
    );
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut OfficialWorkBudget::new(total - 1)
        )
        .is_err()
    );
    let mut exact = limits;
    exact.max_work = total;
    exact.max_sidecar_bytes = encoded.sidecar().len();
    exact.max_temporary_bytes = admission.temporary_bytes;
    exact.max_retained_bytes = admission.retained_bytes;
    let reloaded = decode_transport_module(
        encoded.rvlu(),
        encoded.sidecar(),
        profile,
        &exact,
        &mut OfficialWorkBudget::new(total),
    )
    .unwrap();
    assert_eq!(reloaded.module(), verified.module());
}

#[test]
fn official_depth_limit_and_nan_negative_zero_native_bits_retry() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let official =
        encode_transport_module(&imported(profile), &limits, &mut work(&limits)).unwrap();
    let mut shallow = limits;
    shallow.official.max_depth = 0;
    assert!(
        decode_transport_module(
            official.rvlu(),
            official.sidecar(),
            profile,
            &shallow,
            &mut work(&limits)
        )
        .is_err()
    );
    assert!(
        decode_transport_module(
            official.rvlu(),
            official.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_ok()
    );

    let mut raw = simple_native_module(profile);
    raw.prototypes[0].constants = vec![
        BytecodeConstant::FloatBits(0x7ff8_0000_0000_0001),
        BytecodeConstant::FloatBits((-0.0f64).to_bits()),
    ];
    let native = verify_module(raw, profile, &limits.verify).unwrap();
    let encoded = encode_transport_module(&native, &limits, &mut work(&limits)).unwrap();
    let loaded = decode_transport_module(
        encoded.rvlu(),
        encoded.sidecar(),
        profile,
        &limits,
        &mut work(&limits),
    )
    .unwrap();
    let reencoded = encode_transport_module(&loaded, &limits, &mut work(&limits)).unwrap();
    assert_eq!(reencoded.rvlu(), encoded.rvlu());
    assert_eq!(
        loaded.module().prototypes[0].constants,
        native.module().prototypes[0].constants
    );
}

#[test]
fn official_nan_payload_and_negative_zero_survive_canonical_identity_both_profiles() {
    for (profile, input) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-debug.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-debug.luac").as_slice(),
        ),
    ] {
        let mut chunk =
            decode_official_chunk(input, profile, &OfficialChunkLimits::default()).unwrap();
        chunk
            .main
            .constants
            .push(OfficialConstant::Number(f64::from_bits(
                0x7ff8_0000_0000_00ab,
            )));
        chunk.main.constants.push(OfficialConstant::Number(-0.0));
        let limits = TransportLimits::default();
        let source = translate_official_chunk(&chunk, &limits.verify)
            .unwrap()
            .into_verified();
        let encoded = encode_transport_module(&source, &limits, &mut work(&limits)).unwrap();
        let recovered = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits),
        )
        .unwrap();
        let actual = &recovered.module().prototypes[0].constants;
        assert!(actual.iter().any(|constant| matches!(
            constant,
            BytecodeConstant::FloatBits(0x7ff8_0000_0000_00ab)
        )));
        assert!(actual.iter().any(|constant| matches!(
            constant,
            BytecodeConstant::FloatBits(0x8000_0000_0000_0000)
        )));
        let again = encode_transport_module(&recovered, &limits, &mut work(&limits)).unwrap();
        assert_eq!(again.rvlu(), encoded.rvlu());
    }
}

#[test]
fn official_and_native_debug_metadata_have_exact_and_one_below_resource_admission() {
    for module in [
        imported(LuaProfile::Lua55),
        native_debugged(LuaProfile::Lua55),
    ] {
        let profile = module.profile();
        let limits = TransportLimits::default();
        let encode_scan = transport_encode_scan_admission(&module, &limits).unwrap();
        let encode_admission = preflight_transport_encode(&module, &limits).unwrap();
        let encode_work = encode_scan.work + encode_admission.subsequent_work;
        assert!(
            encode_transport_module(
                &module,
                &limits,
                &mut OfficialWorkBudget::new(encode_work - 1)
            )
            .is_err()
        );
        let encoded =
            encode_transport_module(&module, &limits, &mut OfficialWorkBudget::new(encode_work))
                .unwrap();
        let decode_scan =
            transport_scan_admission(encoded.rvlu().len(), encoded.sidecar().len()).unwrap();
        let decode_admission =
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &limits)
                .unwrap();
        let decode_work = decode_scan.work + decode_admission.subsequent_work;
        assert!(
            decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut OfficialWorkBudget::new(decode_work - 1)
            )
            .is_err()
        );
        let mut low = limits;
        low.max_temporary_bytes = decode_admission.temporary_bytes - 1;
        assert!(
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err()
        );
        let mut low = limits;
        low.max_retained_bytes = decode_admission.retained_bytes - 1;
        assert!(
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &low).is_err()
        );
        let mut exact = limits;
        exact.max_work = decode_work;
        exact.max_temporary_bytes = decode_admission.temporary_bytes;
        exact.max_retained_bytes = decode_admission.retained_bytes;
        let recovered = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &exact,
            &mut OfficialWorkBudget::new(decode_work),
        )
        .unwrap();
        assert_eq!(recovered.origin(), module.origin());
    }
}

#[test]
fn transport_rejects_rvlu_version_numeric_and_none_sidecar_body() {
    let profile = LuaProfile::Lua55;
    let limits = TransportLimits::default();
    let native = verify_module(simple_native_module(profile), profile, &limits.verify).unwrap();
    let encoded = encode_transport_module(&native, &limits, &mut work(&limits)).unwrap();
    let mut rvlu = encoded.rvlu().to_vec();
    rvlu[4..6].copy_from_slice(&3u16.to_le_bytes());
    assert!(
        decode_transport_module(
            &rvlu,
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut rvlu = encoded.rvlu().to_vec();
    rvlu[7] = 2;
    assert!(
        decode_transport_module(
            &rvlu,
            encoded.sidecar(),
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
    let mut sidecar = encoded.sidecar().to_vec();
    sidecar.push(1);
    set_total_len(&mut sidecar);
    assert!(
        decode_transport_module(
            encoded.rvlu(),
            &sidecar,
            profile,
            &limits,
            &mut work(&limits)
        )
        .is_err()
    );
}

#[test]
fn plan_without_official_artifact_cannot_be_transported() {
    let profile = LuaProfile::Lua55;
    let source = imported(profile);
    let plan = source.official_execution().unwrap();
    let candidate = OfficialPlanCandidate {
        root_bindings: plan.root_bindings().to_vec(),
        upvalue_maps: source
            .module()
            .prototypes
            .iter()
            .map(|proto| plan.upvalue_map(proto.id).unwrap().clone())
            .collect(),
        frame_inputs: source
            .module()
            .prototypes
            .iter()
            .flat_map(|proto| plan.frame_inputs(proto.id).copied())
            .collect(),
        calls: source
            .module()
            .prototypes
            .iter()
            .flat_map(|proto| {
                (0..proto.instructions.len()).filter_map(move |pc| {
                    plan.call(proto.id, InstructionOffset(pc as u32)).cloned()
                })
            })
            .collect(),
    };
    let native = verify_module(source.module().clone(), profile, &VerifyLimits::default()).unwrap();
    let plan_only =
        verify_official_execution_plan(native, candidate, &VerifyLimits::default()).unwrap();
    let limits = TransportLimits::default();
    assert!(preflight_transport_encode(&plan_only, &limits).is_err());
    assert!(encode_transport_module(&plan_only, &limits, &mut work(&limits)).is_err());
}

#[test]
fn native_builtin_declaration_cannot_attach_to_official_import() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let official = imported(profile);
        let candidate = OfficialPlanCandidate {
            root_bindings: Vec::new(),
            upvalue_maps: Vec::new(),
            frame_inputs: Vec::new(),
            calls: Vec::new(),
        };
        assert!(verify_native_builtin_plan(official, candidate, &VerifyLimits::default()).is_err());
    }
}
