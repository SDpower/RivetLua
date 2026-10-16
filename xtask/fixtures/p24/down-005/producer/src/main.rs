use std::ffi::OsStr;

use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction, LuaProfile, ProtoId,
    Register, ResultMode, RVLU_NUMERIC_I64_F64, RVLU_V2, VerifyLimits, encode_module,
};

fn parse_profile(argument: &OsStr) -> LuaProfile {
    match argument.to_str() {
        Some("54") => LuaProfile::Lua54,
        Some("55") => LuaProfile::Lua55,
        _ => panic!("profile 必須為 54 或 55"),
    }
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let profile = parse_profile(&arguments.next().expect("請提供 Lua profile：54 或 55"));
    let output = arguments.next().expect("請提供 RVLU artifact 輸出路徑");
    assert!(arguments.next().is_none(), "只接受 profile 與 artifact 路徑");
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 10,
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
            global_environment_binding: binding,
            binding_registers: vec![(binding, Register(2))],
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
    };
    let encoded = encode_module(module, profile, &VerifyLimits::default())
        .expect("RVLU producer module 驗證失敗");
    std::fs::write(output, encoded.bytes()).expect("無法寫入 RVLU artifact");
}
