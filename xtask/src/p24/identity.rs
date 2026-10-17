//! DA-31：發布身分欄位分離；bytecode 版本與 profile 只投影已驗證 P05 module。

use rivetlua_core::{BytecodeVersion, LuaProfile, VerifiedModule, VerifyLimits, decode_module};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIdentity {
    pub crate_semver: String,
    pub lua_profile: LuaProfile,
    pub bytecode_format_version: BytecodeVersion,
    pub c_abi_version: Option<String>,
    pub native_artifact_version: Option<String>,
    pub platform_version: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    CrateVersion,
    Module,
}

impl ReleaseIdentity {
    pub fn from_verified(
        module: &VerifiedModule,
        crate_semver: &str,
    ) -> Result<Self, IdentityError> {
        let numbers = crate_semver.split('.').collect::<Vec<_>>();
        if numbers.len() != 3
            || numbers.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
        {
            return Err(IdentityError::CrateVersion);
        }
        Ok(Self {
            crate_semver: crate_semver.to_owned(),
            lua_profile: module.profile(),
            bytecode_format_version: module.format_version(),
            c_abi_version: None,
            native_artifact_version: None,
            platform_version: None,
        })
    }

    pub fn from_rvlu_bytes(
        bytes: &[u8],
        expected_profile: LuaProfile,
        crate_semver: &str,
    ) -> Result<Self, IdentityError> {
        let module = decode_module(bytes, expected_profile, &VerifyLimits::default())
            .map_err(|_| IdentityError::Module)?;
        Self::from_verified(&module, crate_semver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivetlua_core::{
        BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule,
        BytecodePrototype, BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction,
        ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, encode_module,
    };

    fn encoded(profile: LuaProfile) -> Vec<u8> {
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
    fn release_identity_uses_verified_profile_and_version_only() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let bytes = encoded(profile);
            let module = decode_module(&bytes, profile, &VerifyLimits::default()).unwrap();
            let identity = ReleaseIdentity::from_verified(&module, "1.2.3").unwrap();
            assert_eq!(identity.lua_profile, module.profile());
            assert_eq!(identity.bytecode_format_version, module.format_version());
            assert_eq!(
                ReleaseIdentity::from_rvlu_bytes(&bytes, profile, "1.2.3"),
                Ok(identity.clone())
            );
            assert_eq!(identity.c_abi_version, None);
            assert_eq!(identity.native_artifact_version, None);
            assert_eq!(identity.platform_version, None);
            for bad in ["", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.x"] {
                assert_eq!(
                    ReleaseIdentity::from_verified(&module, bad),
                    Err(IdentityError::CrateVersion)
                );
            }
            let other = if profile == LuaProfile::Lua54 {
                LuaProfile::Lua55
            } else {
                LuaProfile::Lua54
            };
            assert_eq!(
                ReleaseIdentity::from_rvlu_bytes(&bytes, other, "1.2.3"),
                Err(IdentityError::Module)
            );
            assert_eq!(
                ReleaseIdentity::from_rvlu_bytes(b"invalid", profile, "1.2.3"),
                Err(IdentityError::Module)
            );
        }
    }
}
