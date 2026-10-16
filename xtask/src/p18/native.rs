use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use super::{Profile, closure, installer::safe_relative, segment};
use crate::StrictJsonValue;

const MAX_SOURCE_FILES: usize = 8192;
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_NATIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOOL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;

const ABI_HEADER: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/rivetlua_abi.h"));
const LUA54_HEADERS: [&[u8]; 3] = [
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua54/lua.h")),
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua54/lauxlib.h")),
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua54/luaconf.h")),
];
const LUA55_HEADERS: [&[u8]; 3] = [
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua55/lua.h")),
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua55/lauxlib.h")),
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/rivetlua/lua55/luaconf.h")),
];

fn sha(bytes: &[u8]) -> Result<String, String> { crate::p17::package_sha256_bytes(bytes) }

fn plain_path(path: &Path, directory: bool) -> Result<(), String> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::CurDir | Component::ParentDir)) {
        return Err("native 路徑必須是正規絕對路徑".into());
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|_| "native 路徑不可讀")?;
        if meta.file_type().is_symlink() { return Err("native 路徑不可含 symlink".into()); }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "native 路徑不可讀")?;
    if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        return Err("native 路徑型別不符".into());
    }
    Ok(())
}

fn file_digest(path: &Path, limit: u64) -> Result<String, String> {
    plain_path(path, false)?;
    let meta = fs::symlink_metadata(path).map_err(|_| "native 檔案不可讀")?;
    if meta.len() > limit { return Err("native 檔案超過限制".into()); }
    let bytes = fs::read(path).map_err(|_| "native 檔案不可讀")?;
    if bytes.len() as u64 > limit { return Err("native 檔案超過限制".into()); }
    sha(&bytes)
}

fn native_target(target: &str) -> Result<(), String> {
    let host = if cfg!(all(target_os = "macos", target_arch = "aarch64")) { "aarch64-apple-darwin" }
        else if cfg!(all(target_os = "macos", target_arch = "x86_64")) { "x86_64-apple-darwin" }
        else if cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) { "x86_64-unknown-linux-gnu" }
        else if cfg!(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu")) { "aarch64-unknown-linux-gnu" }
        else { return Err("native builder 不支援此宿主平台".into()); };
    if target != host { return Err("native builder 只支援當前宿主 target".into()); }
    Ok(())
}

fn executable(path: PathBuf) -> Result<(PathBuf, String), String> {
    plain_path(&path, false)?;
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
    if matches!(name.as_str(), "xcrun" | "cc" | "clang" | "ar" | "nm" | "otool" | "git" | "lldb" | "debugserver" | "gdb" | "instruments")
        && path.starts_with("/usr/bin") {
        return Err("native toolchain 指向禁止的啟動器".into());
    }
    if matches!(name.as_str(), "xcrun" | "lldb" | "debugserver" | "gdb" | "instruments") {
        return Err("native toolchain 指向禁止的工具".into());
    }
    let meta = fs::symlink_metadata(&path).map_err(|_| "native toolchain 不可讀")?;
    if meta.len() > MAX_TOOL_BYTES { return Err("native toolchain 超過大小限制".into()); }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 { return Err("native toolchain 不是可執行檔".into()); }
    }
    let mut file = File::open(&path).map_err(|_| "native toolchain 不可讀")?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|_| "native toolchain 檔頭無效")?;
    let host_binary = if cfg!(target_os = "macos") { matches!(magic, [0xcf, 0xfa, 0xed, 0xfe]) }
        else { matches!(magic, [0x7f, b'E', b'L', b'F']) };
    if !host_binary {
        return Err("native toolchain 必須是宿主實體 MachO／ELF binary".into());
    }
    Ok((path.clone(), file_digest(&path, MAX_TOOL_BYTES)?))
}

fn sdk_root() -> Result<PathBuf, String> {
    let path = if let Some(value) = env::var_os("RIVETLUA_SDK_INCLUDE") { PathBuf::from(value) }
        else { Path::new(env!("CARGO_MANIFEST_DIR")).parent().ok_or("SDK 路徑無效")?.join("include/rivetlua") };
    plain_path(&path, true)?;
    Ok(path)
}

fn sdk_digest(root: &Path, profile: Profile) -> Result<String, String> {
    let (folder, expected) = match profile { Profile::Lua54 => ("lua54", LUA54_HEADERS), Profile::Lua55 => ("lua55", LUA55_HEADERS) };
    match fs::symlink_metadata(root.join(folder).join("lualib.h")) {
        Ok(_) => return Err("SDK lualib.h 尚未是 RivetLua 產品 header，不能使用".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err("SDK lualib.h 路徑不可檢查".into()),
    }
    let mut joined = Vec::new();
    for (name, expected) in [
        ("lua.h", expected[0]), ("lauxlib.h", expected[1]), ("luaconf.h", expected[2]), ("rivetlua_abi.h", ABI_HEADER),
    ] {
        let path = if name == "rivetlua_abi.h" { root.join(name) } else { root.join(folder).join(name) };
        plain_path(&path, false)?;
        if fs::symlink_metadata(&path).map_err(|_| "SDK header 不可讀")?.len() != expected.len() as u64 {
            return Err("SDK header 與工具內建產品版本不符".into());
        }
        let actual = fs::read(&path).map_err(|_| "SDK header 不可讀")?;
        if actual != expected { return Err("SDK header 與工具內建產品版本不符".into()); }
        joined.extend_from_slice(name.as_bytes()); joined.push(0);
        joined.extend_from_slice(&actual); joined.push(b'\n');
    }
    sha(&joined)
}

pub(super) fn build_flags(values: &[StrictJsonValue]) -> Result<Vec<String>, String> {
    if values.len() > 16 { return Err("native build_flags 數量超過限制".into()); }
    values.iter().map(|value| {
        let flag = value.as_str().ok_or("native build_flags 必須是字串")?;
        if !["-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-fPIC", "-fpic", "-g0"].contains(&flag) {
            return Err("native build_flags 包含未允許選項".into());
        }
        Ok(flag.to_owned())
    }).collect()
}

pub(super) fn external(value: &StrictJsonValue) -> Result<(), String> {
    if matches!(value, StrictJsonValue::Null) { return Ok(()); }
    let StrictJsonValue::Object(entries) = value else { return Err("external_dependencies 必須是 table".into()); };
    for (name, value) in entries {
        if name != "RIVETLUA" { return Err("native external dependency 缺少可驗明的 backend".into()); }
        let StrictJsonValue::Object(fields) = value else { return Err("RIVETLUA external dependency 型別無效".into()); };
        if fields.len() != 1 || value.get("header").and_then(StrictJsonValue::as_str) != Some("lua.h") {
            return Err("RIVETLUA external dependency 只支援 header-only lua.h".into());
        }
    }
    Ok(())
}

pub(super) struct HostBuild {
    cc: PathBuf, cc_digest: String,
    ld: PathBuf, ld_digest: String,
    sdk: PathBuf, header_sha256: String,
    sdkroot: Option<PathBuf>, profile: Profile, target: String,
}

impl HostBuild {
    pub(super) fn new(profile: Profile, target: &str) -> Result<Self, String> {
        native_target(target)?;
        let cc = env::var_os("CC").ok_or("native builder 缺少 CC 絕對路徑配置")?;
        let ld = env::var_os("LD").ok_or("native builder 缺少 LD 絕對路徑配置")?;
        let (cc, cc_digest) = executable(PathBuf::from(cc))?;
        let (ld, ld_digest) = executable(PathBuf::from(ld))?;
        let sdk = sdk_root()?;
        let header_sha256 = sdk_digest(&sdk, profile)?;
        let sdkroot = if cfg!(target_os = "macos") {
            let path = PathBuf::from(env::var_os("SDKROOT").ok_or("Darwin native builder 缺少 SDKROOT")?);
            plain_path(&path, true)?;
            Some(path)
        } else { None };
        Ok(Self { cc, cc_digest, ld, ld_digest, sdk, header_sha256, sdkroot, profile, target: target.to_owned() })
    }

    pub(super) fn verify_unchanged(&self) -> Result<(), String> {
        if file_digest(&self.cc, MAX_TOOL_BYTES)? != self.cc_digest || file_digest(&self.ld, MAX_TOOL_BYTES)? != self.ld_digest
            || sdk_digest(&self.sdk, self.profile)? != self.header_sha256 {
            return Err("native toolchain 或 SDK header 在建置期間變更".into());
        }
        if let Some(path) = &self.sdkroot { plain_path(path, true)?; }
        Ok(())
    }

    pub(super) fn build(&self, copy: &NativeSource, name: &str, value: &StrictJsonValue, build_flags: &[String], index: usize) -> Result<BuiltModule, String> {
        let spec = module_spec(value)?;
        let destination = destination(name, self.profile)?;
        let output = copy.root.join(format!("module-{index}.so"));
        let stdout = copy.root.join(format!("module-{index}.stdout"));
        let stderr = copy.root.join(format!("module-{index}.stderr"));
        match fs::symlink_metadata(&output) {
            Ok(_) => return Err("native 產物暫存路徑與來源衝突".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => return Err("native 產物暫存路徑不可檢查".into()),
        }
        let folder = match self.profile { Profile::Lua54 => "lua54", Profile::Lua55 => "lua55" };
        let include = self.sdk.join(folder);
        let mut argv = vec!["-std=c11".to_owned(), "-fPIC".to_owned()];
        if cfg!(target_os = "macos") {
            argv.extend(["-dynamiclib".into(), "-undefined".into(), "dynamic_lookup".into(), "-isysroot".into(), self.sdkroot.as_ref().ok_or("SDKROOT 缺失")?.to_string_lossy().into_owned()]);
        } else { argv.push("-shared".into()); }
        argv.push(format!("--ld-path={}", self.ld.display()));
        argv.extend(["-I".into(), include.to_string_lossy().into_owned(), "-I".into(), self.sdk.to_string_lossy().into_owned()]);
        for header in [include.join("lua.h"), include.join("lauxlib.h"), self.sdk.join("rivetlua_abi.h")] {
            argv.push("-include".into()); argv.push(header.to_string_lossy().into_owned());
        }
        for path in &spec.incdirs {
            let path = if path == "$(RIVETLUA_INCDIR)" { include.clone() } else { copy.directory(path)? };
            argv.push("-I".into()); argv.push(path.to_string_lossy().into_owned());
        }
        for path in &spec.libdirs {
            argv.push("-L".into()); argv.push(copy.directory(path)?.to_string_lossy().into_owned());
        }
        for define in &spec.defines { argv.push(format!("-D{define}")); }
        argv.extend(build_flags.iter().cloned());
        for source in &spec.sources {
            argv.push(copy.file(source, "c")?.to_string_lossy().into_owned());
        }
        for library in &spec.libraries { argv.push(format!("-l{library}")); }
        argv.push("-o".into()); argv.push(output.to_string_lossy().into_owned());
        let stdout_file = OpenOptions::new().write(true).create_new(true).open(&stdout).map_err(|_| "native stdout 暫存建立失敗")?;
        let stderr_file = OpenOptions::new().write(true).create_new(true).open(&stderr).map_err(|_| "native stderr 暫存建立失敗")?;
        let mut command = Command::new(&self.cc);
        command.args(&argv).env_clear().env("LLVM_DISABLE_SYMBOLIZATION", "1")
            .env("TMPDIR", &copy.root).current_dir(&copy.root)
            .stdin(Stdio::null()).stdout(Stdio::from(stdout_file)).stderr(Stdio::from(stderr_file));
        if let Some(path) = &self.sdkroot { command.env("SDKROOT", path); }
        let status = command.status().map_err(|_| "native compiler 啟動失敗；需由宿主預先核對完整啟動鏈")?;
        for path in [&stdout, &stderr] {
            let meta = fs::symlink_metadata(path).map_err(|_| "native 診斷檔不可讀")?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_DIAGNOSTIC_BYTES {
                return Err("native compiler 診斷超過限制".into());
            }
            let mut text = Vec::new();
            File::open(path).map_err(|_| "native 診斷檔不可讀")?.take(4096).read_to_end(&mut text).map_err(|_| "native 診斷檔不可讀")?;
        }
        if !status.success() { return Err(format!("native compiler 失敗（exit {:?}）", status.code())); }
        plain_path(&output, false)?;
        let meta = fs::symlink_metadata(&output).map_err(|_| "native 產物缺失")?;
        if meta.len() > MAX_NATIVE_BYTES { return Err("native 產物超過 64 MiB".into()); }
        let bytes = fs::read(&output).map_err(|_| "native 產物不可讀")?;
        if bytes.len() as u64 > MAX_NATIVE_BYTES { return Err("native 產物超過 64 MiB".into()); }
        binary_header(&bytes, &self.target)?;
        Ok(BuiltModule { module: name.to_owned(), path: destination, sha256: sha(&bytes)?, bytes,
            opener: opener(name)?, header_sha256: self.header_sha256.clone() })
    }
}

pub(super) struct NativeSource { root: PathBuf }

impl NativeSource {
    pub(super) fn new(source: &Path, expected: &str, patched: &BTreeMap<PathBuf, Vec<u8>>, stage: &Path) -> Result<Self, String> {
        fs::create_dir(stage).map_err(|_| "native source 暫存建立失敗")?;
        let copy = Self { root: stage.to_path_buf() };
        let mut files = 0;
        let mut total_bytes = 0;
        copy_tree(source, &copy.root, 0, &mut files, &mut total_bytes)?;
        if closure::verified_source_digest(&copy.root)? != expected { return Err("native source 副本與 lock SHA-256 不符".into()); }
        for (path, bytes) in patched {
            let target = copy.root.join(path);
            plain_path(&target, false)?;
            if bytes.len() as u64 > MAX_FILE_BYTES { return Err("native patch 檔案過大".into()); }
            let prior = fs::symlink_metadata(&target).map_err(|_| "native patch 目標不可讀")?.len();
            total_bytes = total_bytes.checked_sub(prior).and_then(|size| size.checked_add(bytes.len() as u64))
                .ok_or("native patch 大小溢位")?;
            if total_bytes > MAX_SOURCE_BYTES { return Err("native patch 後來源超過限制".into()); }
            fs::write(&target, bytes).map_err(|_| "native patch 寫入暫存失敗")?;
        }
        reject_shadow_headers(&copy.root)?;
        Ok(copy)
    }

    fn file(&self, value: &str, extension: &str) -> Result<PathBuf, String> {
        let relative = safe_relative(value)?;
        if relative.extension().and_then(|value| value.to_str()) != Some(extension) { return Err("native source 必須是 .c 一般檔案".into()); }
        let path = self.root.join(relative);
        plain_path(&path, false)?;
        Ok(path)
    }

    fn directory(&self, value: &str) -> Result<PathBuf, String> {
        let path = self.root.join(safe_relative(value)?);
        plain_path(&path, true)?;
        Ok(path)
    }
}

impl Drop for NativeSource {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
}

fn copy_tree(source: &Path, target: &Path, depth: usize, files: &mut usize, bytes: &mut u64) -> Result<(), String> {
    if depth > 32 { return Err("native source 目錄過深".into()); }
    for entry in fs::read_dir(source).map_err(|_| "native source 目錄不可讀")? {
        let entry = entry.map_err(|_| "native source 項目不可讀")?;
        let origin = entry.path();
        let dest = target.join(entry.file_name());
        let meta = fs::symlink_metadata(&origin).map_err(|_| "native source 項目不可讀")?;
        if meta.file_type().is_symlink() { return Err("native source 不可含 symlink".into()); }
        if meta.is_dir() {
            fs::create_dir(&dest).map_err(|_| "native source 副本目錄建立失敗")?;
            copy_tree(&origin, &dest, depth + 1, files, bytes)?;
        } else if meta.is_file() {
            *files += 1;
            *bytes = bytes.checked_add(meta.len()).ok_or("native source 大小溢位")?;
            if *files > MAX_SOURCE_FILES || *bytes > MAX_SOURCE_BYTES || meta.len() > MAX_FILE_BYTES { return Err("native source 數量或大小超限".into()); }
            let contents = fs::read(&origin).map_err(|_| "native source 檔案不可讀")?;
            if contents.len() as u64 > MAX_FILE_BYTES { return Err("native source 檔案過大".into()); }
            if contents.len() as u64 > meta.len() {
                *bytes = bytes.checked_add(contents.len() as u64 - meta.len()).ok_or("native source 大小溢位")?;
                if *bytes > MAX_SOURCE_BYTES { return Err("native source 大小超限".into()); }
            }
            let mut output = OpenOptions::new().write(true).create_new(true).open(&dest).map_err(|_| "native source 副本檔案建立失敗")?;
            output.write_all(&contents).map_err(|_| "native source 副本寫入失敗")?;
        } else { return Err("native source 只允許一般檔案與目錄".into()); }
    }
    Ok(())
}

fn reject_shadow_headers(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|_| "native source 副本不可讀")? {
        let entry = entry.map_err(|_| "native source 副本不可讀")?;
        let path = entry.path();
        if path.is_dir() { reject_shadow_headers(&path)?; }
        else if matches!(path.file_name().and_then(|name| name.to_str()), Some("lua.h" | "lauxlib.h" | "luaconf.h" | "lualib.h" | "rivetlua_abi.h")) {
            return Err("native source 不可遮蔽 RivetLua SDK header".into());
        }
    }
    Ok(())
}

struct ModuleSpec { sources: Vec<String>, defines: Vec<String>, incdirs: Vec<String>, libdirs: Vec<String>, libraries: Vec<String> }

fn strings(value: &StrictJsonValue, label: &str) -> Result<Vec<String>, String> {
    let values = match value { StrictJsonValue::String(value) => vec![value.to_owned()],
        StrictJsonValue::Array(items) => items.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(|| format!("{label} 必須是字串"))).collect::<Result<Vec<_>, _>>()?,
        _ => return Err(format!("{label} 必須是字串或字串清單")), };
    if values.len() > 128 { return Err(format!("{label} 數量超過限制")); }
    Ok(values)
}

fn identifier(value: &str) -> bool {
    let mut chars = value.bytes();
    chars.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn module_spec(value: &StrictJsonValue) -> Result<ModuleSpec, String> {
    let StrictJsonValue::Object(fields) = value else { return Err("native module 必須是 table".into()); };
    if fields.iter().any(|(name, _)| !["sources", "defines", "incdirs", "libdirs", "libraries"].contains(&name.as_str())) {
        return Err("native module 含尚未支援的建置欄位".into());
    }
    let sources = strings(value.get("sources").ok_or("native module 缺少 sources")?, "native sources")?;
    if sources.is_empty() { return Err("native module sources 不可為空".into()); }
    for source in &sources {
        if safe_relative(source)?.extension().and_then(|value| value.to_str()) != Some("c") { return Err("native sources 只接受 .c 檔案".into()); }
    }
    let mut defines = Vec::new();
    if let Some(value) = value.get("defines") {
        match value {
            StrictJsonValue::Object(entries) => {
                for (key, value) in entries {
                    let text = value.as_str().ok_or("native define value 必須是字串")?;
                    defines.push(format!("{key}={text}"));
                }
            }
            _ => defines = strings(value, "native defines")?,
        }
    }
    for define in &defines {
        let (name, value) = define.split_once('=').unwrap_or((define, ""));
        if !identifier(name) || define.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.,+-".contains(&byte)) {
            return Err("native define 格式不安全".into());
        }
    }
    let incdirs = value.get("incdirs").map(|value| strings(value, "native incdirs")).transpose()?.unwrap_or_default();
    let libdirs = value.get("libdirs").map(|value| strings(value, "native libdirs")).transpose()?.unwrap_or_default();
    let libraries = value.get("libraries").map(|value| strings(value, "native libraries")).transpose()?.unwrap_or_default();
    for directory in &incdirs { if directory != "$(RIVETLUA_INCDIR)" { safe_relative(directory)?; } }
    for directory in &libdirs { safe_relative(directory)?; }
    for library in &libraries {
        if library.is_empty() || library.len() > 64 || !library.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
            || library.starts_with('-') || library.contains("..") { return Err("native library 名稱不安全".into()); }
        let lower = library.to_ascii_lowercase();
        if lower == "lua" || lower.starts_with("lua5") || lower.starts_with("lua-") || lower.starts_with("lua_")
            || lower.starts_with("luajit") || lower.starts_with("liblua") {
            return Err("native module 不可連結系統 Lua／LuaJIT".into());
        }
        if lower == "rivetlua" || lower == "librivetlua" { return Err("native module 要求 SDK static library；目前不支援".into()); }
    }
    Ok(ModuleSpec { sources, defines, incdirs, libdirs, libraries })
}

pub(super) fn describe(name: &str, profile: Profile, value: &StrictJsonValue) -> Result<(PathBuf, String), String> {
    module_spec(value)?;
    Ok((destination(name, profile)?, opener(name)?))
}

pub(super) struct BuiltModule { pub(super) module: String, pub(super) path: PathBuf, pub(super) bytes: Vec<u8>, pub(super) sha256: String,
    pub(super) opener: String, pub(super) header_sha256: String }

fn destination(name: &str, profile: Profile) -> Result<PathBuf, String> {
    if name.is_empty() || name.split('.').any(|part| segment(part, "native module").is_err()) { return Err("native module 名稱無效".into()); }
    Ok(PathBuf::from("lib/lua").join(profile.lua_version()).join(format!("{}.so", name.replace('.', "/"))))
}

fn opener(name: &str) -> Result<String, String> {
    let name = name.split_once('-').map(|(_, suffix)| suffix).unwrap_or(name);
    let symbol = name.replace('.', "_");
    if symbol.is_empty() || !identifier(&symbol) { return Err("native opener 名稱無效".into()); }
    Ok(format!("luaopen_{symbol}"))
}

fn binary_header(bytes: &[u8], target: &str) -> Result<(), String> {
    if target.ends_with("apple-darwin") {
        if bytes.len() < 16 || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe] { return Err("native 產物不是 64-bit MachO".into()); }
        let cpu = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| "MachO header 無效")?);
        let kind = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| "MachO header 無效")?);
        let expected = if target.starts_with("aarch64-") { 0x0100000c } else { 0x01000007 };
        if cpu != expected || kind != 6 { return Err("native MachO 架構或檔案型別不符".into()); }
    } else {
        if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return Err("native 產物不是 64-bit little-endian ELF".into());
        }
        let kind = u16::from_le_bytes(bytes[16..18].try_into().map_err(|_| "ELF header 無效")?);
        let machine = u16::from_le_bytes(bytes[18..20].try_into().map_err(|_| "ELF header 無效")?);
        let expected = if target.starts_with("aarch64-") { 183 } else { 62 };
        if kind != 3 || machine != expected { return Err("native ELF 架構或檔案型別不符".into()); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::module_spec;
    use crate::{StrictJsonParser, StrictJsonValue};

    #[test]
    fn native_module_rejects_system_lua_library() {
        let value = StrictJsonParser::parse(r#"{"sources":"src/mod.c","libraries":["lua"]}"#).unwrap();
        assert!(module_spec(&value).is_err());
        let value = StrictJsonValue::String("src/mod.c".into());
        assert!(module_spec(&value).is_err());
    }
}
