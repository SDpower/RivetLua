use std::path::Path;

use rivetlua::LuaProfile;

use super::{Profile, installer, tree};

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let [
        root,
        profile_name,
        target,
        abi,
        framework,
        script,
        rest @ ..,
    ] = args
    else {
        return Err("用法：package run <root> <profile> <target> <abi> <lua|luaunit|busted> <script> [args...]".into());
    };
    if !["lua", "luaunit", "busted"].contains(&framework.as_str()) {
        return Err("framework 不支援".into());
    }
    let profile = Profile::parse(profile_name)?;
    let tree = tree::existing(Path::new(root), profile, target, abi)?;
    if framework != "lua" && !installer::is_installed(&tree, framework)? {
        return Err("framework package 尚未安裝於指定 tree".into());
    }
    let lua_profile = match profile {
        Profile::Lua54 => LuaProfile::Lua54,
        Profile::Lua55 => LuaProfile::Lua55,
    };
    rivetlua_cli::package_runner::run(lua_profile, &tree, framework, Path::new(script), rest)
}
