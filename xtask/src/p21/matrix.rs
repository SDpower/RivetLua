//! P21 平台 metadata 模板；不宣稱建置、執行或實板量測結果。

use rivetlua::{DeploymentStatus, Endian, ExecMemoryPolicy, LuaProfile, TargetDescriptor};
use rivetlua_native::{PlatformTarget, platform_targets};

const RAM_CAP: u64 = 64 * 1024 * 1024;
const CODE_CAP: u64 = 16 * 1024 * 1024;
const PROVENANCE: &str = "metadata-only";

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let profiles = match args {
        [] => vec![LuaProfile::Lua54, LuaProfile::Lua55],
        [name] if name == "lua54" => vec![LuaProfile::Lua54],
        [name] if name == "lua55" => vec![LuaProfile::Lua55],
        _ => return Err("用法：platform matrix [lua54|lua55]".into()),
    };
    let targets = platform_targets();
    let mut cells = Vec::with_capacity(targets.len() * profiles.len());
    for profile in profiles {
        for target in &targets {
            cells.push(cell(target, profile)?);
        }
    }
    println!("{{\"version\":1,\"data_kind\":\"metadata-only\",\"capacity_template\":{{\"ram_cap\":{RAM_CAP},\"code_cap\":{CODE_CAP},\"flash_cap\":null,\"build_provenance\":{}}},\"cells\":[{}]}}",
        quoted(PROVENANCE), cells.join(","));
    Ok(())
}

fn cell(target: &PlatformTarget, profile: LuaProfile) -> Result<String, String> {
    let (descriptor, descriptor_reason) = match target.descriptor(
        profile, RAM_CAP, CODE_CAP, None, PROVENANCE,
    ) {
        Ok(value) => (descriptor_json(&value), String::from("null")),
        Err(_) if target.isa == "unspecified" || target.abi == "unspecified" =>
            (String::from("null"), quoted("ISA／ABI 與可信 AOT backend 尚未指定")),
        Err(error) => return Err(format!("{} metadata 不合法：{error:?}", target.target_triple)),
    };
    let (status, reason) = match &target.status {
        DeploymentStatus::Supported { evidence_id } => ("Supported", evidence_id.as_str()),
        DeploymentStatus::BuildOnly => ("BuildOnly", "僅可建置，未有目標執行證據"),
        DeploymentStatus::Experimental { limits } => ("Experimental", limits.as_str()),
        DeploymentStatus::Unsupported { reason } => ("Unsupported", reason.as_str()),
    };
    Ok(format!("{{\"lua_profile\":{},\"target_triple\":{},\"isa\":{},\"os\":{},\"abi\":{},\"exec_memory_policy\":{},\"aot_codegen\":{},\"deployment_status\":{{\"kind\":{},\"reason\":{}}},\"descriptor\":{},\"descriptor_reason\":{}}}",
        quoted(profile_name(profile)), quoted(target.target_triple), quoted(target.isa),
        quoted(target.os), quoted(target.abi), quoted(policy_name(target.exec_memory_policy)),
        target.aot_codegen, quoted(status), quoted(reason), descriptor, descriptor_reason))
}

fn descriptor_json(value: &TargetDescriptor) -> String {
    let features = value.cpu_features.iter().map(|feature| quoted(feature))
        .collect::<Vec<_>>().join(",");
    let flash = value.flash_cap.map_or(String::from("null"), |cap| cap.to_string());
    let endian = match value.endian { Endian::Little => "Little", Endian::Big => "Big" };
    format!("{{\"target_triple\":{},\"isa\":{},\"cpu_features\":[{}],\"os\":{},\"abi\":{},\"endian\":{},\"lua_profile\":{},\"numeric_config\":{},\"flash_cap\":{},\"ram_cap\":{},\"code_cap\":{},\"exec_memory_policy\":{},\"runtime_version\":{},\"compiler_version\":{},\"build_provenance\":{}}}",
        quoted(&value.target_triple), quoted(&value.isa), features, quoted(&value.os),
        quoted(&value.abi), quoted(endian), quoted(profile_name(value.lua_profile)),
        value.numeric_config, flash, value.ram_cap, value.code_cap,
        quoted(policy_name(value.exec_memory_policy)), quoted(&value.runtime_version),
        quoted(&value.compiler_version), quoted(&value.build_provenance))
}

fn profile_name(profile: LuaProfile) -> &'static str {
    match profile { LuaProfile::Lua54 => "lua54", LuaProfile::Lua55 => "lua55" }
}

fn policy_name(policy: ExecMemoryPolicy) -> &'static str {
    match policy {
        ExecMemoryPolicy::Forbidden => "Forbidden",
        ExecMemoryPolicy::WriteThenExecute => "WriteThenExecute",
        ExecMemoryPolicy::MapJit => "MapJit",
    }
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}
