#![cfg(feature = "compiler")]

use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, Endian, EnvironmentSource, ExecMemoryPolicy, FrameLayout, Instruction,
    LuaProfile, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, TargetDescriptor,
    VerifiedModule, VerifyLimits, VmId, decode_module, encode_module,
};
use rivetlua_native::{AotBuildInput, AotError, TrustedAotBuild, build_aot, inspect_aot, load_aot};
use std::collections::BTreeSet;

fn integer_module(profile: LuaProfile, value: i64) -> BytecodeModule {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 10,
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
            register_count: 3,
            parameter_count: 0,
            is_variadic: false,
            named_vararg: None,
            frame: FrameLayout {
                register_limit: 4096,
                initial_top: Register(3),
                dynamic_top: Register(3),
                return_base: Register(0),
                environment: Register(2),
                environment_source: EnvironmentSource::RootExternal,
                registers_start_as_nil: true,
            },
            global_environment: Register(2),
            global_environment_binding: BytecodeBindingId {
                function: 0,
                ordinal: 0,
            },
            binding_registers: vec![(
                BytecodeBindingId {
                    function: 0,
                    ordinal: 0,
                },
                Register(2),
            )],
            constants: vec![BytecodeConstant::Integer(value)],
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

fn verified_integer_module(profile: LuaProfile, value: i64) -> VerifiedModule {
    let limits = VerifyLimits::default();
    let encoded = encode_module(integer_module(profile, value), profile, &limits).unwrap();
    decode_module(encoded.bytes(), profile, &limits).unwrap()
}

fn target_descriptor(profile: LuaProfile) -> TargetDescriptor {
    TargetDescriptor {
        target_triple: "aarch64-apple-darwin".into(),
        isa: "aarch64".into(),
        os: "macos".into(),
        abi: "apple-aarch64".into(),
        cpu_features: BTreeSet::new(),
        endian: Endian::Little,
        lua_profile: profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        flash_cap: None,
        ram_cap: 64 * 1024 * 1024,
        code_cap: 16 * 1024 * 1024,
        exec_memory_policy: ExecMemoryPolicy::MapJit,
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_provenance: "synthetic-fixture".into(),
    }
}

fn assert_load_rejected(
    bytes: &[u8],
    module: &VerifiedModule,
    target: &TargetDescriptor,
    trust: &TrustedAotBuild,
) {
    assert!(matches!(
        load_aot(bytes, module, target, trust, VmId::new_unique().unwrap()),
        Err(AotError::Malformed
            | AotError::Mismatch(_)
            | AotError::Untrusted
            | AotError::Unsupported(_))
    ));
}

#[test]
fn p21_aot_manifest_roundtrips_and_trust_rejects_mismatches() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let module = verified_integer_module(profile, 41);
        let target = target_descriptor(profile);
        let artifact = build_aot(AotBuildInput {
            module: &module,
            prototype_index: 0,
            entry_pc: 0,
            target: &target,
        })
        .unwrap();
        let manifest = artifact.manifest();
        let inspected = inspect_aot(artifact.bytes()).unwrap();

        assert_eq!(&inspected, manifest);
        assert_eq!(inspected.profile, profile);
        assert_eq!(inspected.target, target.clone());
        assert_eq!(inspected.prototype_index, 0);
        assert_eq!(inspected.entry_pc, 0);

        let trust = artifact.trusted_build();
        let mut unknown_magic = artifact.bytes().to_vec();
        assert!(unknown_magic.len() >= 4);
        unknown_magic[..4].copy_from_slice(b"NOPE");
        assert!(inspect_aot(&unknown_magic).is_err());
        assert_load_rejected(&unknown_magic, &module, &target, &trust);

        let mut truncated = artifact.bytes().to_vec();
        truncated.pop();
        assert!(inspect_aot(&truncated).is_err());
        assert_load_rejected(&truncated, &module, &target, &trust);

        let mut changed_bytes = artifact.bytes().to_vec();
        let last_byte = changed_bytes.len() - 1;
        changed_bytes[last_byte] ^= 1;
        assert_load_rejected(&changed_bytes, &module, &target, &trust);

        let different_module = verified_integer_module(profile, 42);
        assert_load_rejected(artifact.bytes(), &different_module, &target, &trust);

        let other_profile = match profile {
            LuaProfile::Lua54 => LuaProfile::Lua55,
            LuaProfile::Lua55 => LuaProfile::Lua54,
        };
        let profile_mismatch = verified_integer_module(other_profile, 41);
        assert_load_rejected(artifact.bytes(), &profile_mismatch, &target, &trust);

        let mut abi_mismatch = target.clone();
        abi_mismatch.abi = "apple-aarch64-mismatch".into();
        assert_load_rejected(artifact.bytes(), &module, &abi_mismatch, &trust);

        let mut unknown_numeric = target.clone();
        unknown_numeric.numeric_config = 0;
        assert_load_rejected(artifact.bytes(), &module, &unknown_numeric, &trust);

        let mut isa_mismatch = target.clone();
        isa_mismatch.isa = "x86_64".into();
        assert_load_rejected(artifact.bytes(), &module, &isa_mismatch, &trust);

        let mut codecap_mismatch = target.clone();
        codecap_mismatch.code_cap = 0;
        assert_load_rejected(artifact.bytes(), &module, &codecap_mismatch, &trust);
    }
}
