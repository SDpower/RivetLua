use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction, LuaProfile, ProtoId,
    RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, Value, VerifyLimits, decode_module,
    encode_module,
};
use rivetlua_runtime::{RunOutcome, Vm};

fn integer_module(profile: LuaProfile) -> BytecodeModule {
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
            constants: vec![BytecodeConstant::Integer(41)],
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

#[test]
fn p21_runtime_executes_core_encoded_rvlu_for_both_profiles() {
    let limits = VerifyLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let encoded = encode_module(integer_module(profile), profile, &limits).unwrap();
        let bytes = encoded.bytes().to_vec();
        let verified = decode_module(&bytes, profile, &limits).unwrap();
        let mut vm = Vm::new_with_profile(profile).unwrap();
        assert_eq!(
            vm.load(verified).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(41)])
        );

        let wrong_profile = match profile {
            LuaProfile::Lua54 => LuaProfile::Lua55,
            LuaProfile::Lua55 => LuaProfile::Lua54,
        };
        assert!(decode_module(&bytes, wrong_profile, &limits).is_err());
        let mut corrupted = bytes;
        corrupted[0] ^= 0xff;
        assert!(decode_module(&corrupted, profile, &limits).is_err());
    }
}
