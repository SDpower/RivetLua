use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;

use rivetlua_core::{DeploymentStatus, ExecMemoryPolicy};
use rivetlua_core::LuaProfile;
use rivetlua_native::platform_target;
use p24_down_007_cortex_m_runtime::{
    CORTEX_M_TRIPLE, MAX_RVLU_BYTES, verify_host_contract,
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
    let path = arguments.next().expect("請提供外部 RVLU artifact 路徑");
    assert!(arguments.next().is_none(), "只接受 profile 與 artifact 路徑");

    let mut input = File::open(path)
        .expect("無法開啟 RVLU artifact")
        .take(MAX_RVLU_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .expect("無法讀取 RVLU artifact");
    assert!(bytes.len() <= MAX_RVLU_BYTES, "RVLU artifact 超過 1 MiB");
    verify_host_contract(&bytes, profile).expect("DOWN-007 host-side source assertion 失敗");

    let target = platform_target(CORTEX_M_TRIPLE).expect("P21 Cortex-M target metadata 缺失");
    assert_eq!(target.target_triple, CORTEX_M_TRIPLE);
    assert_eq!(target.isa, "thumbv7em");
    assert_eq!(target.os, "none");
    assert_eq!(target.abi, "eabi");
    assert_eq!(target.exec_memory_policy, ExecMemoryPolicy::Forbidden);
    assert!(!target.aot_codegen);
    assert_eq!(target.status, DeploymentStatus::BuildOnly);
}
