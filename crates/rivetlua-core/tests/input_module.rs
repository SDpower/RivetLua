use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, InputErrorKind, InputFormat,
    Instruction, LuaProfile, ModuleOrigin, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register,
    ResultMode, TransportLimits, VerifyLimits, classify_input, decode_input_module, encode_module,
    input_scan_admission, preflight_input_module,
};

fn official(profile: LuaProfile) -> &'static [u8] {
    match profile {
        LuaProfile::Lua54 => include_bytes!("official_chunk_fixtures/lua54-debug.luac"),
        LuaProfile::Lua55 => include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
    }
}

#[test]
fn input_classifier_keeps_source_and_unknown_escape_distinct() {
    assert_eq!(classify_input(b"return 1"), InputFormat::Source);
    assert_eq!(classify_input(b"RVLU = 1"), InputFormat::Source);
    assert_eq!(classify_input(b"RVLU()"), InputFormat::Source);
    assert_eq!(classify_input(b"\x1b"), InputFormat::UnsupportedBinary);
    assert_eq!(classify_input(b"\x1bBad"), InputFormat::UnsupportedBinary);
    assert_eq!(classify_input(b"\x1bLua"), InputFormat::Official);
    assert_eq!(classify_input(b"RVLU\x02\x00"), InputFormat::RawRvlu);
    assert_eq!(classify_input(b"RVLU\x02"), InputFormat::RawRvlu);
    assert_eq!(classify_input(b"RVLU\x03\x00"), InputFormat::RawRvlu);
    assert_eq!(
        input_scan_admission(usize::MAX, InputFormat::RawRvlu)
            .unwrap_err()
            .kind,
        InputErrorKind::LimitExceeded
    );
    assert_eq!(
        input_scan_admission(usize::MAX, InputFormat::Official)
            .unwrap_err()
            .kind,
        InputErrorKind::LimitExceeded
    );
}

#[test]
fn official_input_facade_preserves_artifact_and_checked_admission() {
    let fixtures: &[(LuaProfile, &[u8])] = &[
        (LuaProfile::Lua54, official(LuaProfile::Lua54)),
        (LuaProfile::Lua55, official(LuaProfile::Lua55)),
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
    for &(profile, bytes) in fixtures {
        let limits = TransportLimits::default();
        let scan = input_scan_admission(bytes.len(), InputFormat::Official).unwrap();
        assert_eq!(scan.work, (bytes.len() as u64) * 2 + 1);
        let preflight = preflight_input_module(bytes, profile, &limits).unwrap();
        let admission = preflight.admission();
        assert!(admission.subsequent_work > 0);
        let module = decode_input_module(preflight).unwrap();
        assert_eq!(module.origin(), ModuleOrigin::OfficialImport);
        assert!(module.official_artifact().is_some());
        assert!(module.official_execution().is_some());

        let mut one_below = limits;
        one_below.max_work = scan.work + admission.subsequent_work - 1;
        assert_eq!(
            preflight_input_module(bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );
        let mut one_below = limits;
        one_below.max_temporary_bytes = admission.temporary_bytes - 1;
        assert_eq!(
            preflight_input_module(bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );
        let mut one_below = limits;
        one_below.max_retained_bytes = admission.retained_bytes - 1;
        assert_eq!(
            preflight_input_module(bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );

        assert_eq!(
            preflight_input_module(
                bytes,
                if profile == LuaProfile::Lua54 {
                    LuaProfile::Lua55
                } else {
                    LuaProfile::Lua54
                },
                &limits
            )
            .unwrap_err()
            .kind,
            InputErrorKind::InvalidFormat
        );
        assert_eq!(
            preflight_input_module(&bytes[..8], profile, &limits)
                .unwrap_err()
                .kind,
            InputErrorKind::InvalidFormat
        );
    }
}

fn native(profile: LuaProfile) -> Vec<u8> {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 8,
    };
    let binding = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let module = BytecodeModule {
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
    };
    encode_module(module, profile, &VerifyLimits::default())
        .unwrap()
        .bytes()
        .to_vec()
}

#[test]
fn raw_input_facade_checks_both_profiles_without_promoting_sidecar_metadata() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let bytes = native(profile);
        assert_eq!(classify_input(&bytes), InputFormat::RawRvlu);
        let limits = TransportLimits::default();
        let scan = input_scan_admission(bytes.len(), InputFormat::RawRvlu).unwrap();
        assert_eq!(scan.work, (bytes.len() as u64 + 16) * 2 + 1);
        let admission = preflight_input_module(&bytes, profile, &limits).unwrap();
        let numbers = admission.admission();
        assert!(numbers.subsequent_work > 0);
        let module = decode_input_module(admission).unwrap();
        assert_eq!(module.origin(), ModuleOrigin::NativeRvlu);
        assert!(module.official_artifact().is_none());
        assert!(module.official_execution().is_none());
        assert!(module.native_debug().is_none());

        let mut one_below = limits;
        one_below.max_work = scan.work + numbers.subsequent_work - 1;
        assert_eq!(
            preflight_input_module(&bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );
        let mut one_below = limits;
        one_below.max_temporary_bytes = numbers.temporary_bytes - 1;
        assert_eq!(
            preflight_input_module(&bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );
        let mut one_below = limits;
        one_below.max_retained_bytes = numbers.retained_bytes - 1;
        assert_eq!(
            preflight_input_module(&bytes, profile, &one_below)
                .unwrap_err()
                .kind,
            InputErrorKind::LimitExceeded
        );

        let mut wrong = bytes.clone();
        wrong[6] ^= 1;
        assert_eq!(
            preflight_input_module(&wrong, profile, &limits)
                .unwrap_err()
                .kind,
            InputErrorKind::InvalidFormat
        );
        let mut version = bytes.clone();
        version[4] = 3;
        assert_eq!(
            preflight_input_module(&version, profile, &limits)
                .unwrap_err()
                .kind,
            InputErrorKind::InvalidFormat
        );
        let mut numeric = bytes.clone();
        numeric[7] = 0;
        assert_eq!(
            preflight_input_module(&numeric, profile, &limits)
                .unwrap_err()
                .kind,
            InputErrorKind::InvalidFormat
        );
        assert_eq!(
            preflight_input_module(&bytes[..8], profile, &limits)
                .unwrap_err()
                .kind,
            InputErrorKind::InvalidFormat
        );
    }
}
