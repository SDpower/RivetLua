pub mod identity;

use std::fs::{self, File};
use std::io::Read;

use identity::ReleaseIdentity;
use rivetlua_core::LuaProfile;

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let [command, path_flag, path, profile_flag, profile, version_flag, version] = args else {
        return Err("E_RELEASE_IDENTITY_USAGE".into());
    };
    if command != "identity" || path_flag != "--rvlu" || profile_flag != "--profile"
        || version_flag != "--crate-version"
    {
        return Err("E_RELEASE_IDENTITY_USAGE".into());
    }
    let profile = match profile.as_str() {
        "lua55" => LuaProfile::Lua55,
        "lua54" => LuaProfile::Lua54,
        _ => return Err("E_RELEASE_IDENTITY_PROFILE".into()),
    };
    let metadata = fs::symlink_metadata(path).map_err(|_| "E_RELEASE_IDENTITY_INPUT")?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err("E_RELEASE_IDENTITY_INPUT".into());
    }
    let file = File::open(path).map_err(|_| "E_RELEASE_IDENTITY_INPUT")?;
    if !file.metadata().map_err(|_| "E_RELEASE_IDENTITY_INPUT")?.is_file() {
        return Err("E_RELEASE_IDENTITY_INPUT".into());
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)
        .map_err(|_| "E_RELEASE_IDENTITY_INPUT")?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("E_RELEASE_IDENTITY_INPUT".into());
    }
    let identity = ReleaseIdentity::from_rvlu_bytes(&bytes, profile, version)
        .map_err(|_| "E_RELEASE_IDENTITY_INVALID")?;
    let profile = match identity.lua_profile {
        LuaProfile::Lua55 => "lua55",
        LuaProfile::Lua54 => "lua54",
    };
    println!(
        "{{\"version\":1,\"crate_semver\":\"{}\",\"lua_profile\":\"{profile}\",\"bytecode_format_version\":{},\"c_abi_version\":null,\"native_artifact_version\":null,\"platform_version\":null,\"release_ready\":false}}",
        crate::json_escape(&identity.crate_semver), identity.bytecode_format_version.0,
    );
    Ok(())
}
