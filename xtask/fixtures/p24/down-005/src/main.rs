use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;

use rivetlua_core::{LuaProfile, Value, VerifyLimits, decode_module};
use rivetlua_runtime::{AbortReason, RunOutcome, Vm};

const MAX_RVLU_BYTES: u64 = 1024 * 1024;
const VM_HEAP_LIMIT: usize = 8 * 1024 * 1024;
const FIRST_RUN_FUEL: u64 = 1024;

fn parse_profile(argument: &OsStr) -> LuaProfile {
    match argument.to_str() {
        Some("54") => LuaProfile::Lua54,
        Some("55") => LuaProfile::Lua55,
        _ => panic!("profile 必須為 54 或 55"),
    }
}

fn opposite_profile(profile: LuaProfile) -> LuaProfile {
    match profile {
        LuaProfile::Lua54 => LuaProfile::Lua55,
        LuaProfile::Lua55 => LuaProfile::Lua54,
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
        .take(MAX_RVLU_BYTES + 1);
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .expect("無法讀取 RVLU artifact");
    assert!(bytes.len() as u64 <= MAX_RVLU_BYTES, "RVLU artifact 超過 1 MiB");

    let limits = VerifyLimits::default();
    let verified = decode_module(&bytes, profile, &limits).expect("RVLU 驗證失敗");

    assert!(decode_module(&bytes, opposite_profile(profile), &limits).is_err());
    let mut wrong_format = bytes.clone();
    *wrong_format
        .get_mut(4)
        .expect("已驗證 RVLU 應包含 format version") ^= 0xff;
    assert!(decode_module(&wrong_format, profile, &limits).is_err());

    let mut vm = Vm::new_with_profile(profile).expect("無法建立 VM");
    vm.set_allocation_limit(VM_HEAP_LIMIT);
    let mut execution = vm.load(verified).expect("無法載入 VerifiedModule");
    execution
        .set_fuel(FIRST_RUN_FUEL)
        .expect("無法設定首次執行 fuel");
    assert_eq!(
        execution.run().expect("VM 執行失敗"),
        RunOutcome::Returned(vec![Value::Integer(41)])
    );
    println!("41");
    drop(execution);

    let verified = decode_module(&bytes, profile, &limits).expect("RVLU 驗證失敗");
    let mut execution = vm.load(verified).expect("無法載入 VerifiedModule");
    execution.set_fuel(0).expect("無法設定 fuel");
    assert_eq!(
        execution.run().expect("fuel abort 應為受控結果"),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
}
