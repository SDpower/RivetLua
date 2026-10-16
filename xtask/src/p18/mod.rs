mod closure;
mod installer;
mod moonrocks;
mod native;
mod patch;
mod rockspec;
mod runner;
mod tree;

#[derive(Clone, Copy)]
pub(super) enum Profile { Lua54, Lua55 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub lua_profile: String,
    pub target: String,
    pub abi: String,
}

impl Profile {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "lua54-i64f64" => Ok(Self::Lua54),
            "lua55-i64f64" => Ok(Self::Lua55),
            _ => Err("不支援的 package Lua profile".into()),
        }
    }
    pub(super) fn name(self) -> &'static str {
        match self { Self::Lua54 => "lua54-i64f64", Self::Lua55 => "lua55-i64f64" }
    }
    pub(super) fn lua_version(self) -> &'static str {
        match self { Self::Lua54 => "5.4", Self::Lua55 => "5.5" }
    }
    pub(super) fn release(self) -> &'static str {
        match self { Self::Lua54 => "5.4.9", Self::Lua55 => "5.5.1" }
    }
}

pub(super) fn segment(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value == "." || value == ".." || value.len() > 128
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("{label} 含有不合法路徑字元"));
    }
    Ok(())
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    match args.split_first() {
        Some((command, args)) if command == "tree-init" => tree::init(args),
        Some((command, args)) if command == "rockspec" => rockspec::read(args),
        Some((command, args)) if command == "lock" => closure::lock(args),
        Some((command, args)) if command == "install" => installer::install(args),
        Some((command, args)) if command == "remove" => installer::remove(args),
        Some((command, args)) if command == "run" => runner::run(args),
        Some((command, args)) if command == "moonrocks" => moonrocks::run(args),
        _ => Err("用法：package tree-init <root> <profile> <target> <abi> | package rockspec <file> <profile> <target> <abi> | package lock <index.json> <root-name> <profile> <target> <abi> | package install <lock.json> <root> | package remove <root> <profile> <target> <abi> <name> | package run <root> <profile> <target> <abi> <lua|luaunit|busted> <script> [args...] | package moonrocks <root> <profile> <target> <abi> <endpoint> <namespace> <token-env> <version|outdated|login|upload> [input]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::segment;
    #[test]
    fn path_segment_rejects_traversal() {
        for value in ["", ".", "..", "../other", "x/y", "x:y"] {
            assert!(segment(value, "target").is_err());
        }
        assert!(segment("aarch64-apple-darwin", "target").is_ok());
    }
}
