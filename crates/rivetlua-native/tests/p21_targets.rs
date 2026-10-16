use rivetlua_core::{
    BoardConfig, DeploymentStatus, Endian, ExecMemoryPolicy, LuaProfile, RVLU_NUMERIC_I64_F64,
    TargetDescriptor,
};
use rivetlua_native::{platform_target, platform_targets, validate_board_target};

const RAM_CAP: u64 = 64 * 1024 * 1024;
const CODE_CAP: u64 = 16 * 1024 * 1024;
const PROVENANCE: &str = "synthetic-fixture";

fn assert_descriptor(
    descriptor: &TargetDescriptor,
    target_triple: &str,
    isa: &str,
    os: &str,
    abi: &str,
    profile: LuaProfile,
    policy: &ExecMemoryPolicy,
) {
    assert_eq!(descriptor.target_triple, target_triple);
    assert_eq!(descriptor.isa, isa);
    assert_eq!(descriptor.os, os);
    assert_eq!(descriptor.abi, abi);
    assert!(descriptor.cpu_features.is_empty());
    assert_eq!(descriptor.endian, Endian::Little);
    assert_eq!(descriptor.lua_profile, profile);
    assert_eq!(descriptor.numeric_config, RVLU_NUMERIC_I64_F64);
    assert_eq!(descriptor.flash_cap, None);
    assert_eq!(descriptor.ram_cap, RAM_CAP);
    assert_eq!(descriptor.code_cap, CODE_CAP);
    assert_eq!(&descriptor.exec_memory_policy, policy);
    assert_eq!(descriptor.runtime_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(descriptor.compiler_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(descriptor.build_provenance, PROVENANCE);
}

fn synthetic_board(float_abi: &str) -> BoardConfig {
    BoardConfig {
        schema_version: 1,
        board_id: "synthetic-cortex-m4".into(),
        cpu: "cortex-m4".into(),
        thumb: true,
        fpu: None,
        float_abi: float_abi.into(),
        linker_map_digest: [1; 32],
        allocator: "static".into(),
        panic_strategy: "abort".into(),
        entry: "Reset".into(),
        clock: "synthetic-clock".into(),
        timer: "synthetic-timer".into(),
    }
}

#[test]
fn p21_platform_targets_expose_local_deployment_contracts() {
    let targets = platform_targets();
    assert!(targets.iter().all(|target| {
        !matches!(
            &target.status,
            DeploymentStatus::Supported { .. }
        )
    }));

    let expected_desktop = [
        (
            "x86_64-pc-windows-msvc",
            "x86_64",
            "windows",
            "win64",
            ExecMemoryPolicy::WriteThenExecute,
        ),
        (
            "x86_64-unknown-linux-gnu",
            "x86_64",
            "linux",
            "sysv64",
            ExecMemoryPolicy::WriteThenExecute,
        ),
        (
            "aarch64-apple-darwin",
            "aarch64",
            "macos",
            "apple-aarch64",
            ExecMemoryPolicy::MapJit,
        ),
        (
            "aarch64-unknown-linux-gnu",
            "aarch64",
            "linux",
            "aapcs64",
            ExecMemoryPolicy::WriteThenExecute,
        ),
    ];

    for (triple, isa, os, abi, policy) in &expected_desktop {
        assert!(targets.iter().any(|target| target.target_triple == *triple));
        let target = platform_target(triple).expect("required desktop target must be present");
        assert!(target.aot_codegen);
        assert!(matches!(
            &target.status,
            DeploymentStatus::Experimental { .. }
        ));

        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let descriptor = target
                .descriptor(profile, RAM_CAP, CODE_CAP, None, PROVENANCE)
                .unwrap();
            assert_descriptor(
                &descriptor,
                triple,
                isa,
                os,
                abi,
                profile,
                policy,
            );
        }
    }

    let thumb = platform_target("thumbv7em-none-eabi").expect("Thumb target must be present");
    assert_eq!(thumb.isa, "thumbv7em");
    assert_eq!(thumb.os, "none");
    assert_eq!(thumb.abi, "eabi");
    assert!(!thumb.aot_codegen);
    assert_eq!(thumb.exec_memory_policy, ExecMemoryPolicy::Forbidden);
    assert!(matches!(&thumb.status, DeploymentStatus::BuildOnly));

    let rv32 = platform_target("riscv32-unknown-none-elf").expect("RV32 target must be present");
    assert_eq!(rv32.isa, "unspecified");
    assert_eq!(rv32.abi, "unspecified");
    assert!(!rv32.aot_codegen);
    assert_eq!(rv32.exec_memory_policy, ExecMemoryPolicy::Forbidden);
    assert!(matches!(
        &rv32.status,
        DeploymentStatus::Unsupported { .. }
    ));

    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let thumb_descriptor = thumb
            .descriptor(profile, RAM_CAP, CODE_CAP, None, PROVENANCE)
            .unwrap();
        assert_descriptor(
            &thumb_descriptor,
            "thumbv7em-none-eabi",
            "thumbv7em",
            "none",
            "eabi",
            profile,
            &ExecMemoryPolicy::Forbidden,
        );

        let board = synthetic_board("soft");
        assert!(validate_board_target(&board, &thumb_descriptor).is_ok());

        let hardfloat_board = synthetic_board("hardfloat");
        assert!(validate_board_target(&hardfloat_board, &thumb_descriptor).is_err());

        let arm64 = platform_target("aarch64-apple-darwin").unwrap();
        let arm64_descriptor = arm64
            .descriptor(profile, RAM_CAP, CODE_CAP, None, PROVENANCE)
            .unwrap();
        assert!(validate_board_target(&board, &arm64_descriptor).is_err());

        assert!(rv32
            .descriptor(profile, RAM_CAP, CODE_CAP, None, PROVENANCE)
            .is_err());
    }

    assert!(platform_target("unknown-target-triple").is_none());
}
