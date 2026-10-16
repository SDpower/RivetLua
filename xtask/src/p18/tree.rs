use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use super::{Profile, segment};
use crate::{StrictJsonParser, StrictJsonValue, json_escape};

pub(super) fn init(args: &[String]) -> Result<(), String> {
    let [root_arg, profile_arg, target, abi] = args else {
        return Err("用法：package tree-init <root> <profile> <target> <abi>".into());
    };
    let profile = Profile::parse(profile_arg)?;
    segment(target, "target")?;
    if abi.len() != 64 || !abi.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ABI 必須是 64 位十六進位字串".into());
    }
    let abi = abi.to_ascii_lowercase();
    let root_arg = Path::new(root_arg);
    if root_arg.as_os_str().is_empty() || root_arg.components().any(|part| matches!(part, Component::ParentDir)) {
        return Err("package root 不可為空或含上層目錄".into());
    }
    let root = if root_arg.is_absolute() {
        root_arg.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| "無法取得目前目錄")?.join(root_arg)
    };
    let tree = root.join(profile.name()).join(target).join(&abi);
    ensure_directory(&root)?;
    ensure_directory(&root.join(profile.name()))?;
    ensure_directory(&root.join(profile.name()).join(target))?;
    let existing = fs::symlink_metadata(&tree).ok();
    if existing.as_ref().is_some_and(|meta| !meta.is_dir() || meta.file_type().is_symlink()) {
        return Err("package tree 路徑不是一般目錄".into());
    }
    let manifest = tree.join("manifest.json");
    if existing.is_some() && !manifest.exists() && fs::read_dir(&tree).map_err(|_| "無法讀取 package tree")?.next().is_some() {
        return Err("既有 package tree 缺少 manifest，拒絕接管使用者資料".into());
    }
    ensure_directory(&tree)?;
    let contents = format!("{{\"lua_profile\":\"{}\",\"target\":\"{}\",\"abi\":\"{}\",\"layout_version\":1}}\n", profile.name(), json_escape(target), abi);
    match fs::symlink_metadata(&manifest) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            let old = fs::read_to_string(&manifest).map_err(|_| "無法讀取 package manifest")?;
            let parsed = StrictJsonParser::parse(&old).map_err(|_| "package manifest 格式無效")?;
            if parsed.get("lua_profile").and_then(StrictJsonValue::as_str) != Some(profile.name())
                || parsed.get("target").and_then(StrictJsonValue::as_str) != Some(target)
                || parsed.get("abi").and_then(StrictJsonValue::as_str) != Some(abi.as_str())
                || parsed.get("layout_version").and_then(StrictJsonValue::as_i32) != Some(1)
            {
                return Err("package manifest 的 profile／target／ABI 不相容".into());
            }
        }
        Ok(_) => return Err("package manifest 不是一般檔案".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&manifest)
                .map_err(|_| "無法建立 package manifest")?;
            file.write_all(contents.as_bytes()).map_err(|_| "無法寫入 package manifest")?;
        }
        Err(_) => return Err("無法檢查 package manifest".into()),
    }
    let bin = tree.join("bin");
    let lua = tree.join("share/lua").join(profile.lua_version());
    let lib = tree.join("lib/lua").join(profile.lua_version());
    for dir in [&bin, &lua, &lib] { ensure_directory(dir)?; }
    let path = bin.display().to_string();
    let lua_path = format!("{}/?.lua;{}/?/init.lua", lua.display(), lua.display());
    let lua_cpath = format!("{}/?.so", lib.display());
    println!("{{\"profile\":\"{}\",\"target\":\"{}\",\"abi\":\"{}\",\"root\":\"{}\",\"path\":\"{}\",\"environment\":{{\"PATH\":\"{}\",\"LUA_PATH\":\"{}\",\"LUA_CPATH\":\"{}\"}}}}", profile.name(), json_escape(target), abi, json_escape(&root.display().to_string()), json_escape(&tree.display().to_string()), json_escape(&path), json_escape(&lua_path), json_escape(&lua_cpath));
    Ok(())
}

pub(super) fn ensure_directory(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir) { return Err("package 路徑不可含上層目錄".into()); }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err("package 路徑包含 symlink 或非目錄".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| "無法建立 package 目錄")?;
            }
            Err(_) => return Err("無法檢查 package 目錄".into()),
        }
    }
    Ok(())
}

pub(super) fn existing(root: &Path, profile: Profile, target: &str, abi: &str) -> Result<PathBuf, String> {
    segment(target, "target")?;
    if abi.len() != 64 || !abi.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ABI 必須是 64 位十六進位字串".into());
    }
    if root.as_os_str().is_empty() || root.components().any(|part| matches!(part, Component::ParentDir)) {
        return Err("package root 含不安全路徑".into());
    }
    let root = if root.is_absolute() { root.to_path_buf() } else {
        std::env::current_dir().map_err(|_| "無法取得目前目錄")?.join(root)
    };
    let tree = root.join(profile.name()).join(target).join(abi.to_ascii_lowercase());
    let mut current = PathBuf::new();
    for part in tree.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|_| "package tree 尚未初始化")?;
        if !meta.is_dir() || meta.file_type().is_symlink() { return Err("package tree 包含 symlink 或非目錄".into()); }
    }
    let manifest = tree.join("manifest.json");
    let meta = fs::symlink_metadata(&manifest).map_err(|_| "package manifest 缺失")?;
    if !meta.is_file() || meta.file_type().is_symlink() { return Err("package manifest 不是一般檔案".into()); }
    let contents = fs::read_to_string(manifest).map_err(|_| "無法讀取 package manifest")?;
    let parsed = StrictJsonParser::parse(&contents).map_err(|_| "package manifest 格式無效")?;
    if parsed.get("lua_profile").and_then(StrictJsonValue::as_str) != Some(profile.name())
        || parsed.get("target").and_then(StrictJsonValue::as_str) != Some(target)
        || parsed.get("abi").and_then(StrictJsonValue::as_str) != Some(abi.to_ascii_lowercase().as_str())
        || parsed.get("layout_version").and_then(StrictJsonValue::as_i32) != Some(1)
    { return Err("package manifest 的 profile／target／ABI 不相容".into()); }
    fs::canonicalize(tree).map_err(|_| "package tree 不可讀".into())
}
