use rivetlua_core::{
    BoardConfig, DeploymentStatus, Endian, ExecMemoryPolicy, TargetDescriptor, TargetError,
};

pub(super) fn entries() -> Vec<super::PlatformTarget> {
    vec![
        super::PlatformTarget {
            target_triple: "aarch64-apple-darwin",
            isa: "aarch64",
            os: "macos",
            abi: "apple-aarch64",
            exec_memory_policy: ExecMemoryPolicy::MapJit,
            aot_codegen: true,
            status: DeploymentStatus::Experimental {
                limits: "尚無可確認的 allow-jit entitlement 與原生執行證據。".into(),
            },
        },
        super::PlatformTarget {
            target_triple: "aarch64-unknown-linux-gnu",
            isa: "aarch64",
            os: "linux",
            abi: "aapcs64",
            exec_memory_policy: ExecMemoryPolicy::WriteThenExecute,
            aot_codegen: true,
            status: DeploymentStatus::Experimental {
                limits: "指令快取同步能力尚未確認，現有執行頁面路徑拒絕原生執行。".into(),
            },
        },
        super::PlatformTarget {
            target_triple: "thumbv7em-none-eabi",
            isa: "thumbv7em",
            os: "none",
            abi: "eabi",
            exec_memory_policy: ExecMemoryPolicy::Forbidden,
            aot_codegen: false,
            status: DeploymentStatus::BuildOnly,
        },
        super::PlatformTarget {
            target_triple: "riscv32-unknown-none-elf",
            isa: "unspecified",
            os: "none",
            abi: "unspecified",
            exec_memory_policy: ExecMemoryPolicy::Forbidden,
            aot_codegen: false,
            status: DeploymentStatus::Unsupported {
                reason: "尚未指定 ISA extensions、ILP32 ABI 或可信原生 backend。".into(),
            },
        },
    ]
}

pub fn validate_board_target(
    board: &BoardConfig,
    target: &TargetDescriptor,
) -> Result<(), TargetError> {
    board.validate()?;
    target.validate()?;

    if target.target_triple == "riscv32-unknown-none-elf" {
        return Err(TargetError::InvalidField("isa/abi"));
    }
    if target.target_triple != "thumbv7em-none-eabi"
        || target.isa != "thumbv7em"
        || target.os != "none"
        || target.abi != "eabi"
        || target.endian != Endian::Little
        || target.exec_memory_policy != ExecMemoryPolicy::Forbidden
        || !target.cpu_features.is_empty()
    {
        return Err(TargetError::Mismatch("board target descriptor"));
    }
    if !board.thumb
        || !(board.cpu.eq_ignore_ascii_case("cortex-m4")
            || board.cpu.eq_ignore_ascii_case("cortex-m7"))
    {
        return Err(TargetError::Mismatch("board cpu"));
    }
    if board.float_abi != "soft" || board.fpu.is_some() {
        return Err(TargetError::Mismatch("board float ABI/FPU"));
    }
    if board.panic_strategy != "abort" {
        return Err(TargetError::Mismatch("board panic strategy"));
    }
    Ok(())
}
