use rivetlua_core::{DeploymentStatus, ExecMemoryPolicy};

pub(super) fn entries() -> Vec<super::PlatformTarget> {
    vec![
        super::PlatformTarget {
            target_triple: "x86_64-unknown-linux-gnu",
            isa: "x86_64",
            os: "linux",
            abi: "sysv64",
            exec_memory_policy: ExecMemoryPolicy::WriteThenExecute,
            aot_codegen: true,
            status: DeploymentStatus::Experimental {
                limits: "僅有 runtime-only 交叉建置路徑與受限數值 AOT 產碼；Linux x86_64 已有 W→RX 頁面發布路徑，但尚無此目標的執行驗證及完整 runtime/native 證據。".into(),
            },
        },
        super::PlatformTarget {
            target_triple: "x86_64-pc-windows-msvc",
            isa: "x86_64",
            os: "windows",
            abi: "win64",
            exec_memory_policy: ExecMemoryPolicy::WriteThenExecute,
            aot_codegen: true,
            status: DeploymentStatus::Experimental {
                limits: "僅有 runtime-only 交叉建置路徑與受限數值 AOT 產碼；現有 execmem 對 Windows 原生載入回報 Unsupported，尚無完整目標 runtime/native 證據。".into(),
            },
        },
        super::PlatformTarget {
            target_triple: "x86_64-apple-darwin",
            isa: "x86_64",
            os: "macos",
            abi: "apple-x86_64",
            exec_memory_policy: ExecMemoryPolicy::MapJit,
            aot_codegen: true,
            status: DeploymentStatus::Experimental {
                limits: "僅有 runtime-only 交叉建置路徑與受限數值 AOT 產碼；x86_64 macOS 缺實機與 MAP_JIT entitlement 執行證據，尚無完整目標 runtime/native 證據。".into(),
            },
        },
    ]
}
