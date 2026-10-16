use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rivetlua::{CompileBudget, CompileBudgetLimits, Engine, LuaProfile};

use super::{PackageIdentity, Profile, closure, native, patch, rockspec, segment, tree};
use crate::{StrictJsonParser, StrictJsonValue, json_escape};

const MAX_LOCK_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_STAGE_BYTES: usize = 256 * 1024 * 1024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(name).ok_or_else(|| format!("package 缺少 {name}"))
}

fn string<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    field(value, name)?.as_str().ok_or_else(|| format!("package {name} 必須是字串"))
}

fn digest(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("package SHA-256 必須是 64 位 hex".into());
    }
    Ok(value.to_ascii_lowercase())
}

pub(super) fn read_json(path: &Path, limit: u64) -> Result<StrictJsonValue, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "package JSON 不可讀")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        return Err("package JSON 必須是有限大小的一般檔案".into());
    }
    let bytes = fs::read(path).map_err(|_| "package JSON 不可讀")?;
    if bytes.len() as u64 > limit { return Err("package JSON 超過限制".into()); }
    let text = std::str::from_utf8(&bytes).map_err(|_| "package JSON 不是 UTF-8")?;
    StrictJsonParser::parse(text).map_err(|_| "package JSON 格式無效".into())
}

pub(super) fn identity(value: &StrictJsonValue) -> Result<PackageIdentity, String> {
    let id = PackageIdentity {
        name: string(value, "name")?.to_owned(),
        version: string(value, "version")?.to_owned(),
        lua_profile: string(value, "lua_profile")?.to_owned(),
        target: string(value, "target")?.to_owned(),
        abi: digest(string(value, "abi")?)?,
    };
    segment(&id.name, "package")?;
    segment(&id.version, "version")?;
    Profile::parse(&id.lua_profile)?;
    segment(&id.target, "target")?;
    Ok(id)
}

pub(super) fn safe_relative(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() || path.is_absolute()
        || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err("package 路徑含目錄穿越或不安全字元".into());
    }
    Ok(path.to_path_buf())
}

pub(super) fn source_file(source: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let relative = safe_relative(relative)?;
    let mut current = source.to_path_buf();
    for part in relative.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|_| "package source 檔案缺失")?;
        if meta.file_type().is_symlink() { return Err("package source 含 symlink".into()); }
    }
    let meta = fs::symlink_metadata(&current).map_err(|_| "package source 檔案缺失")?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES { return Err("package source 檔案型別或大小無效".into()); }
    let bytes = fs::read(current).map_err(|_| "package source 檔案不可讀")?;
    if bytes.len() as u64 > MAX_FILE_BYTES { return Err("package source 檔案超過限制".into()); }
    Ok(bytes)
}

struct PreparedFile { path: PathBuf, bytes: Vec<u8>, sha256: String }
#[derive(Eq, PartialEq)]
struct NativeRecord { module: String, path: PathBuf, sha256: String, opener: String, header_sha256: String }
struct PreparedPackage { identity: PackageIdentity, rockspec_sha256: String, source_sha256: String,
    runtime: Vec<(String, String)>, files: Vec<PreparedFile>, native_modules: Vec<NativeRecord> }

fn module_destination(name: &str, profile: Profile) -> Result<PathBuf, String> {
    if name.is_empty() || name.split('.').any(|part| segment(part, "module").is_err()) {
        return Err("package module 名稱無效".into());
    }
    Ok(PathBuf::from("share/lua").join(profile.lua_version()).join(format!("{}.lua", name.replace('.', "/"))))
}

fn prepare_file(source: &Path, source_name: &str, destination: PathBuf, engine: &Engine, patched: &BTreeMap<PathBuf, Vec<u8>>) -> Result<PreparedFile, String> {
    let relative = safe_relative(source_name)?;
    let bytes = if let Some(bytes) = patched.get(&relative) { bytes.clone() } else { source_file(source, source_name)? };
    if destination.extension().is_some_and(|ext| ext == "lua") || source_name.ends_with(".lua") {
        let budget = CompileBudget::new(CompileBudgetLimits {
            max_work: 1_000_000, max_allocation_bytes: 16 * 1024 * 1024,
        });
        engine.compile_named_with_budget(&bytes, destination.to_string_lossy().as_bytes(), &budget)
            .map_err(|_| "package Lua source 編譯失敗或超過額度")?;
    }
    Ok(PreparedFile { path: destination, sha256: crate::p17::package_sha256_bytes(&bytes)?, bytes })
}

fn prepare_package(spec: &rockspec::Parsed, source: &Path, source_hash: &str, flags: &[StrictJsonValue], profile: Profile,
    engine: &Engine, scratch: &Path, native_host: &mut Option<native::HostBuild>, existing: Option<&StrictJsonValue>) -> Result<PreparedPackage, String> {
    let parsed = StrictJsonParser::parse(&spec.json).map_err(|_| "rockspec 內部 JSON 無效")?;
    let mut build = field(&parsed, "build")?;
    if let Some(platforms) = parsed.get("platforms") {
        for key in rockspec::platform_keys(&spec.identity.target) {
            if let Some(selected) = platforms.get(key).and_then(|override_fields| override_fields.get("build")) {
                build = selected;
            }
        }
    }
    let build_type = string(build, "type")?;
    if build_type != "builtin" && build_type != "none" {
        return Err("此 package 需要尚未提供的 build backend".into());
    }
    if build_type == "none" && (build.get("modules").is_some() || build.get("command").is_some()) {
        return Err("build.type=none 不可包含 modules 或 command".into());
    }
    if field(&parsed, "source")?.get("patches").is_some() {
        return Err("source.patches 格式尚未支援".into());
    }
    if let StrictJsonValue::Object(fields) = build {
        let supported = if build_type == "none" { &["type", "install", "patches"][..] }
            else { &["type", "modules", "install", "patches"][..] };
        if fields.iter().any(|(name, _)| !supported.contains(&name.as_str())) {
            return Err("build 含尚未支援的步驟".into());
        }
    }
    let external = field(&parsed, "external_dependencies")?;
    let patched = if let Some(patches) = build.get("patches") { patch::apply(source, patches)? } else { BTreeMap::new() };
    let mut files = Vec::new();
    let mut native_modules = Vec::new();
    let mut native_source = None;
    let mut checked_flags = None;
    if let Some(modules) = build.get("modules") {
        let StrictJsonValue::Object(entries) = modules else { return Err("build.modules 必須是 table".into()); };
        for (name, value) in entries {
            if let Some(source_name) = value.as_str() {
                let dest = module_destination(name, profile)?;
                files.push(prepare_file(source, source_name, dest, engine, &patched)?);
            } else {
                native::external(external)?;
                if let Some(record) = existing {
                    if string(record, "rockspec_sha256")? != spec.sha256.as_str() || string(record, "source_sha256")? != source_hash {
                        return Err("已安裝 native package 的來源與 rockspec 已變更".into());
                    }
                    native::build_flags(flags)?;
                    let (path, opener) = native::describe(name, profile, value)?;
                    let entries = field(record, "native_modules")?.as_array().ok_or("package native_modules 必須是陣列")?;
                    let item = entries.iter().find(|item| item.get("module").and_then(StrictJsonValue::as_str) == Some(name))
                        .ok_or("已安裝 native module metadata 缺失")?;
                    if safe_relative(string(item, "path")?)? != path || string(item, "opener")? != opener.as_str()
                        || string(item, "unwind")? != "unknown" { return Err("已安裝 native module metadata 不符".into()); }
                    let sha256 = digest(string(item, "sha256")?)?;
                    native_modules.push(NativeRecord { module: name.to_owned(), path: path.clone(), sha256: sha256.clone(),
                        opener, header_sha256: digest(string(item, "header_sha256")?)? });
                    files.push(PreparedFile { path, bytes: Vec::new(), sha256 });
                    continue;
                }
                if checked_flags.is_none() { checked_flags = Some(native::build_flags(flags)?); }
                native::describe(name, profile, value)?;
                if native_host.is_none() { *native_host = Some(native::HostBuild::new(profile, &spec.identity.target)?); }
                if native_source.is_none() {
                    native_source = Some(native::NativeSource::new(source, source_hash, &patched, scratch)?);
                }
                let built = native_host.as_ref().ok_or("native builder 缺失")?.build(
                    native_source.as_ref().ok_or("native source 副本缺失")?, name, value,
                    checked_flags.as_deref().ok_or("native build_flags 缺失")?, native_modules.len())?;
                native_modules.push(NativeRecord { module: built.module, path: built.path.clone(), sha256: built.sha256.clone(),
                    opener: built.opener, header_sha256: built.header_sha256 });
                files.push(PreparedFile { path: built.path, bytes: built.bytes, sha256: built.sha256 });
            }
        }
    }
    if native_modules.is_empty() {
        if !flags.is_empty() { return Err("此 package build_flags 需要 native module".into()); }
        if matches!(external, StrictJsonValue::Object(items) if !items.is_empty()) {
            return Err("此 package external dependencies 需要 native builder".into());
        }
    }
    if let Some(install) = build.get("install") {
        let StrictJsonValue::Object(_) = install else { return Err("build.install 必須是 table".into()); };
        for (kind, prefix) in [
            ("lua", PathBuf::from("share/lua").join(profile.lua_version())),
            ("conf", PathBuf::from("etc")),
            ("bin", PathBuf::from("bin")),
        ] {
            if let Some(entries) = install.get(kind) {
                let entries = match entries {
                    StrictJsonValue::Object(entries) => entries.iter().map(|(name, value)| Ok((name.to_owned(), value))).collect::<Result<Vec<_>, String>>()?,
                    StrictJsonValue::Array(items) => items.iter().map(|value| {
                        let src = value.as_str().ok_or("build.install 清單項目必須是字串")?;
                        let path = safe_relative(src)?;
                        let name = path.file_name().and_then(|name| name.to_str()).ok_or("build.install 檔名無效")?;
                        Ok((name.to_owned(), value))
                    }).collect::<Result<Vec<_>, String>>()?,
                    _ => return Err(format!("build.install.{kind} 必須是 table")),
                };
                for (name, value) in entries {
                    let src = value.as_str().ok_or("build.install 項目必須是字串")?;
                    let relative = if kind == "lua" && !name.ends_with(".lua") && !name.contains('/') {
                        PathBuf::from(format!("{}.lua", name.replace('.', "/")))
                    } else { safe_relative(&name)? };
                    files.push(prepare_file(source, src, prefix.join(relative), engine, &patched)?);
                }
            }
        }
        if let StrictJsonValue::Object(entries) = install {
            if entries.iter().any(|(kind, _)| !["lua", "conf", "bin"].contains(&kind.as_str())) {
                return Err("build.install 含尚未支援的目標".into());
            }
        }
    }
    if files.is_empty() { return Err("package 沒有可安裝的檔案".into()); }
    let mut seen = BTreeSet::new();
    for file in &files {
        if !seen.insert(file.path.clone()) { return Err("package 安裝目的路徑重複".into()); }
    }
    Ok(PreparedPackage { identity: spec.identity.clone(), rockspec_sha256: spec.sha256.clone(),
        source_sha256: source_hash.to_owned(), runtime: Vec::new(), files, native_modules })
}

fn metadata(package: &PreparedPackage) -> Result<Vec<u8>, String> {
    let id = &package.identity;
    let mut files = Vec::new();
    for file in &package.files {
        let path = file.path.to_str().ok_or("package 目的路徑不是 UTF-8")?;
        files.push(format!("{{\"path\":\"{}\",\"sha256\":\"{}\"}}", json_escape(path), file.sha256));
    }
    let runtime = package.runtime.iter().map(|(name, version)|
        format!("{{\"name\":\"{}\",\"version\":\"{}\"}}", json_escape(name), json_escape(version)))
        .collect::<Vec<_>>().join(",");
    let native_modules = package.native_modules.iter().map(|item| format!(
        "{{\"module\":\"{}\",\"path\":\"{}\",\"sha256\":\"{}\",\"opener\":\"{}\",\"header_sha256\":\"{}\",\"unwind\":\"unknown\"}}",
        json_escape(&item.module), json_escape(&item.path.to_string_lossy()), item.sha256, json_escape(&item.opener), item.header_sha256))
        .collect::<Vec<_>>().join(",");
    Ok(format!("{{\"name\":\"{}\",\"version\":\"{}\",\"lua_profile\":\"{}\",\"target\":\"{}\",\"abi\":\"{}\",\"rockspec_sha256\":\"{}\",\"source_sha256\":\"{}\",\"dependencies\":{{\"runtime\":[{}]}},\"files\":[{}],\"native_modules\":[{}]}}\n",
        json_escape(&id.name), json_escape(&id.version), id.lua_profile, json_escape(&id.target), id.abi,
        package.rockspec_sha256, package.source_sha256, runtime, files.join(","), native_modules).into_bytes())
}

fn packages_dir(tree: &Path) -> Result<PathBuf, String> {
    let path = tree.join(".packages");
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(path),
        Ok(_) => Err("package metadata 目錄型別無效".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(_) => Err("package metadata 目錄不可讀".into()),
    }
}

pub(super) fn installed(tree: &Path) -> Result<BTreeMap<String, StrictJsonValue>, String> {
    let dir = packages_dir(tree)?;
    if !dir.exists() { return Ok(BTreeMap::new()); }
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(dir).map_err(|_| "package metadata 目錄不可讀")? {
        let entry = entry.map_err(|_| "package metadata 項目不可讀")?;
        let path = entry.path();
        let name = path.file_stem().and_then(|value| value.to_str()).ok_or("package metadata 名稱無效")?;
        segment(name, "package metadata")?;
        if path.extension().and_then(|value| value.to_str()) != Some("json") { return Err("package metadata 檔名無效".into()); }
        let value = read_json(&path, 1024 * 1024)?;
        if string(&value, "name")? != name { return Err("package metadata 名稱不符".into()); }
        result.insert(name.to_owned(), value);
    }
    Ok(result)
}

pub(super) fn dependency_pairs(value: &StrictJsonValue) -> Result<BTreeMap<String, String>, String> {
    let entries = value.as_array().ok_or("package dependencies 必須是陣列")?;
    let mut pairs = BTreeMap::new();
    for item in entries {
        let name = string(item, "name")?.to_ascii_lowercase();
        let version = string(item, "version")?.to_owned();
        segment(&name, "dependency")?; segment(&version, "dependency version")?;
        if pairs.insert(name, version.clone()).is_some_and(|old| old != version) {
            return Err("package dependency 版本衝突".into());
        }
    }
    Ok(pairs)
}

fn verify_dependencies(spec: &rockspec::Parsed, entry: &StrictJsonValue, profile: Profile, available: &BTreeMap<String, String>) -> Result<Vec<(String, String)>, String> {
    let groups = field(entry, "dependencies")?;
    let mut runtime = Vec::new();
    for (index, key) in ["runtime", "build", "test"].into_iter().enumerate() {
        let actual = dependency_pairs(field(groups, key)?)?;
        let mut expected = BTreeMap::new();
        for raw in &spec.dependencies[index] {
            let requirement = closure::parse_requirement(raw)?;
            if requirement.name == "luajit" { return Err("LuaJIT-only dependency 不支援".into()); }
            if requirement.name == "lua" {
                if !closure::requirement_matches(&requirement, profile.release()) { return Err("Lua profile 不符合 dependency".into()); }
                continue;
            }
            let version = available.get(&requirement.name).ok_or("dependency 尚未安裝或順序錯誤")?;
            if !closure::requirement_matches(&requirement, version) { return Err("dependency 版本衝突".into()); }
            expected.insert(requirement.name, version.clone());
        }
        if actual != expected { return Err(format!("lock {key} dependency 與 rockspec 不符")); }
        if index == 0 { runtime = expected.into_iter().collect(); }
    }
    Ok(runtime)
}

fn verify_existing(tree: &Path, record: &StrictJsonValue, package: &PreparedPackage) -> Result<(), String> {
    if identity(record)? != package.identity { return Err("已安裝 package identity 與 lock 衝突".into()); }
    let runtime = dependency_pairs(field(field(record, "dependencies")?, "runtime")?)?;
    if runtime != package.runtime.iter().cloned().collect() { return Err("已安裝 package runtime dependency 已變更".into()); }
    let records = field(record, "files")?.as_array().ok_or("package files 必須是陣列")?;
    let mut actual = BTreeMap::new();
    for item in records {
        let path = safe_relative(string(item, "path")?)?;
        let expected = digest(string(item, "sha256")?)?;
        if actual.insert(path.clone(), expected.clone()).is_some() { return Err("package metadata 檔案重複".into()); }
        let file = tree.join(path);
        closure::checked_existing(&file, false)?;
        let bytes = fs::read(file).map_err(|_| "已安裝 package 檔案不可讀")?;
        if crate::p17::package_sha256_bytes(&bytes)? != expected { return Err("已安裝 package 檔案已變更".into()); }
    }
    let wanted = package.files.iter().map(|file| (file.path.clone(), file.sha256.clone())).collect::<BTreeMap<_, _>>();
    if actual != wanted { return Err("已安裝 package 檔案集合與 rockspec 不符".into()); }
    let records = record.get("native_modules").map(|value| value.as_array().ok_or("package native_modules 必須是陣列"))
        .transpose()?.unwrap_or(&[]);
    let mut actual_native = BTreeMap::new();
    for item in records {
        if string(item, "unwind")? != "unknown" { return Err("package native unwind metadata 無效".into()); }
        let entry = NativeRecord { module: string(item, "module")?.to_owned(), path: safe_relative(string(item, "path")?)?,
            sha256: digest(string(item, "sha256")?)?, opener: string(item, "opener")?.to_owned(),
            header_sha256: digest(string(item, "header_sha256")?)? };
        if actual_native.insert(entry.module.clone(), entry).is_some() { return Err("package native module metadata 重複".into()); }
    }
    let wanted_native = package.native_modules.iter().map(|item| (item.module.clone(), NativeRecord {
        module: item.module.clone(), path: item.path.clone(), sha256: item.sha256.clone(),
        opener: item.opener.clone(), header_sha256: item.header_sha256.clone(),
    })).collect::<BTreeMap<_, _>>();
    if actual_native != wanted_native { return Err("已安裝 native metadata 與 lock 產物不符".into()); }
    Ok(())
}

struct Transaction { stage: PathBuf, published: Vec<(PathBuf, String)>, dirs: Vec<PathBuf>, committed: bool, preserve_stage: bool }

impl Transaction {
    fn new(tree: &Path) -> Result<Self, String> {
        for _ in 0..100 {
            let nonce = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let path = tree.join(format!(".stage-{}-{nonce}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { stage: path, published: Vec::new(), dirs: Vec::new(), committed: false, preserve_stage: false }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("package stage 無法建立".into()),
            }
        }
        Err("package stage 名稱耗盡".into())
    }

    fn parent_dirs(&mut self, tree: &Path, relative: &Path) -> Result<(), String> {
        let parent = relative.parent().ok_or("package 目的路徑無父目錄")?;
        let mut current = tree.to_path_buf();
        for part in parent.components() {
            if !matches!(part, Component::Normal(_)) { return Err("package 目的路徑不安全".into()); }
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {},
                Ok(_) => return Err("package 目的目錄含 symlink 或非目錄".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current).map_err(|_| "package 目的目錄無法建立")?;
                    self.dirs.push(current.clone());
                }
                Err(_) => return Err("package 目的目錄不可檢查".into()),
            }
        }
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            for (path, expected) in self.published.iter().rev() {
                if fs::read(path).ok().and_then(|bytes| crate::p17::package_sha256_bytes(&bytes).ok()).as_deref() == Some(expected.as_str()) {
                    let _ = fs::remove_file(path);
                }
            }
            for path in self.dirs.iter().rev() { let _ = fs::remove_dir(path); }
        }
        if !self.preserve_stage { let _ = fs::remove_dir_all(&self.stage); }
    }
}

pub(super) fn install(args: &[String]) -> Result<(), String> {
    let [lock_path, root] = args else { return Err("用法：package install <lock.json> <root>".into()); };
    let lock = read_json(Path::new(lock_path), MAX_LOCK_BYTES)?;
    if field(&lock, "format_version")?.as_i32() != Some(1) { return Err("ClosureLock 版本無效".into()); }
    let root_id = identity(field(&lock, "root")?)?;
    let profile = Profile::parse(&root_id.lua_profile)?;
    let tree = tree::existing(Path::new(root), profile, &root_id.target, &root_id.abi)?;
    let existing = installed(&tree)?;
    let entries = field(&lock, "packages")?.as_array().ok_or("lock packages 必須是陣列")?;
    if entries.is_empty() || entries.len() > 256 { return Err("lock packages 數量無效".into()); }
    let engine = Engine::new(match profile { Profile::Lua54 => LuaProfile::Lua54, Profile::Lua55 => LuaProfile::Lua55 });
    let mut existing_names = BTreeSet::new();
    for (name, record) in &existing {
        let id = identity(record)?;
        if id.name != name.as_str() || id.lua_profile != root_id.lua_profile || id.target != root_id.target || id.abi != root_id.abi {
            return Err("既有 package metadata identity 與 tree 不符".into());
        }
        if !existing_names.insert(name.to_ascii_lowercase()) { return Err("既有 package 名稱大小寫衝突".into()); }
    }
    let mut locked = BTreeMap::new();
    let mut edges = BTreeMap::new();
    let mut prepared = Vec::new();
    let mut all_paths = BTreeSet::new();
    let mut staged_bytes = 0usize;
    let mut root_found = false;
    let mut transaction = Transaction::new(&tree)?;
    let mut native_host = None;
    for (entry_index, entry) in entries.iter().enumerate() {
        let id = identity(entry)?;
        if id.lua_profile != root_id.lua_profile || id.target != root_id.target || id.abi != root_id.abi {
            return Err("lock package profile／target／ABI 混用".into());
        }
        if id == root_id { root_found = true; }
        if locked.contains_key(&id.name.to_ascii_lowercase()) { return Err("lock 重複 package 名稱".into()); }
        let rockspec_path = Path::new(string(entry, "rockspec")?);
        let source_path = Path::new(string(entry, "source")?);
        if transaction.stage.starts_with(source_path) { return Err("package source 不可包含交易 stage".into()); }
        closure::checked_existing(rockspec_path, false)?;
        closure::checked_existing(source_path, true)?;
        let spec = rockspec::evaluate(rockspec_path, profile, &root_id.target, &root_id.abi)?;
        if spec.identity != id || spec.sha256 != digest(string(entry, "rockspec_sha256")?)? {
            return Err("lock rockspec identity 或 SHA-256 不符".into());
        }
        let source_hash = digest(string(entry, "source_sha256")?)?;
        if closure::verified_source_digest(source_path)? != source_hash {
            return Err("lock source SHA-256 不符".into());
        }
        let runtime = verify_dependencies(&spec, entry, profile, &locked)?;
        let mut dependencies = BTreeSet::new();
        for raw in spec.dependencies.iter().flatten() {
            let requirement = closure::parse_requirement(raw)?;
            if requirement.name != "lua" { dependencies.insert(requirement.name); }
        }
        edges.insert(id.name.to_ascii_lowercase(), dependencies);
        let flags = field(entry, "build_flags")?.as_array().ok_or("build_flags 必須是陣列")?;
        let mut package = prepare_package(&spec, source_path, &source_hash, flags, profile, &engine,
            &transaction.stage.join(format!("native-{entry_index}")), &mut native_host, existing.get(&id.name))?;
        if closure::verified_source_digest(source_path)? != source_hash {
            return Err("package source 在準備安裝期間已變更".into());
        }
        package.runtime = runtime;
        if let Some(record) = existing.get(&id.name) {
            verify_existing(&tree, record, &package)?;
            locked.insert(id.name.to_ascii_lowercase(), id.version);
            continue;
        }
        if existing_names.contains(&id.name.to_ascii_lowercase()) { return Err("已安裝 package 名稱大小寫衝突".into()); }
        for file in &package.files {
            staged_bytes = staged_bytes.checked_add(file.bytes.len()).ok_or("package stage 大小溢位")?;
            if staged_bytes > MAX_STAGE_BYTES { return Err("package stage 超過限制".into()); }
            if !all_paths.insert(file.path.clone()) { return Err("closure package 檔案目的路徑衝突".into()); }
            if fs::symlink_metadata(tree.join(&file.path)).is_ok() { return Err("package 目的路徑已有使用者或其他套件檔案".into()); }
        }
        locked.insert(id.name.to_ascii_lowercase(), id.version.clone());
        prepared.push(package);
    }
    if !root_found { return Err("ClosureLock 缺 root package".into()); }
    let mut reachable = BTreeSet::new();
    let mut todo = vec![root_id.name.to_ascii_lowercase()];
    while let Some(name) = todo.pop() {
        if reachable.insert(name.clone()) {
            todo.extend(edges.get(&name).ok_or("lock dependency 缺失")?.iter().cloned());
        }
    }
    if reachable.len() != locked.len() { return Err("lock 含 root 不可達 package".into()); }
    if let Some(host) = &native_host { host.verify_unchanged()?; }
    if prepared.is_empty() {
        println!("{{\"installed\":0,\"root\":\"{}\"}}", json_escape(&tree.display().to_string()));
        return Ok(());
    }
    let mut publish = Vec::new();
    for package in &prepared {
        for file in &package.files {
            let staged = transaction.stage.join(format!("{}", publish.len()));
            let mut output = OpenOptions::new().write(true).create_new(true).open(&staged).map_err(|_| "package stage 檔案無法建立")?;
            output.write_all(&file.bytes).map_err(|_| "package stage 檔案無法寫入")?;
            #[cfg(unix)]
            if file.path.starts_with("bin") {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).map_err(|_| "package bin 權限設定失敗")?;
            }
            publish.push((staged, file.path.clone(), file.sha256.clone()));
        }
        let relative = PathBuf::from(".packages").join(format!("{}.json", package.identity.name));
        let staged = transaction.stage.join(format!("{}", publish.len()));
        let bytes = metadata(package)?;
        let mut output = OpenOptions::new().write(true).create_new(true).open(&staged).map_err(|_| "package metadata stage 無法建立")?;
        output.write_all(&bytes).map_err(|_| "package metadata stage 無法寫入")?;
        publish.push((staged, relative, crate::p17::package_sha256_bytes(&bytes)?));
    }
    for (staged, relative, expected) in &publish {
        transaction.parent_dirs(&tree, relative)?;
        let destination = tree.join(relative);
        fs::hard_link(staged, &destination).map_err(|_| "package 發布失敗或目的檔案已存在")?;
        transaction.published.push((destination, expected.clone()));
    }
    transaction.committed = true;
    println!("{{\"installed\":{},\"root\":\"{}\"}}", prepared.len(), json_escape(&tree.display().to_string()));
    Ok(())
}

pub(super) fn remove(args: &[String]) -> Result<(), String> {
    let [root, profile, target, abi, name] = args else {
        return Err("用法：package remove <root> <profile> <target> <abi> <name>".into());
    };
    let profile = Profile::parse(profile)?;
    segment(name, "package")?;
    let tree = tree::existing(Path::new(root), profile, target, abi)?;
    let records = installed(&tree)?;
    let record = records.get(name).ok_or("package 未安裝")?;
    let id = identity(record)?;
    if id.name != name.as_str() || id.lua_profile != profile.name() || id.target != target.as_str() || id.abi != abi.to_ascii_lowercase() {
        return Err("package metadata identity 不符".into());
    }
    for (other, value) in &records {
        if other == name { continue; }
        let dependencies = field(field(value, "dependencies")?, "runtime")?;
        if dependency_pairs(dependencies)?.contains_key(&name.to_ascii_lowercase()) {
            return Err("package 仍被 runtime dependency 使用".into());
        }
    }
    let entries = field(record, "files")?.as_array().ok_or("package files 必須是陣列")?;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for item in entries {
        let relative = safe_relative(string(item, "path")?)?;
        if !seen.insert(relative.clone()) { return Err("package metadata 檔案重複".into()); }
        let path = tree.join(relative);
        closure::checked_existing(&path, false)?;
        let bytes = fs::read(&path).map_err(|_| "package 檔案不可讀")?;
        if crate::p17::package_sha256_bytes(&bytes)? != digest(string(item, "sha256")?)? {
            return Err("package 檔案已被修改，拒絕移除".into());
        }
        files.push(path);
    }
    for (other, value) in &records {
        if other == name { continue; }
        let other_files = field(value, "files")?.as_array().ok_or("package files 必須是陣列")?;
        for item in other_files {
            let path = tree.join(safe_relative(string(item, "path")?)?);
            if files.contains(&path) { return Err("package 檔案所有權與其他套件衝突".into()); }
        }
    }
    let metadata_path = tree.join(".packages").join(format!("{name}.json"));
    let mut transaction = Transaction::new(&tree)?;
    for (index, path) in files.iter().chain(std::iter::once(&metadata_path)).enumerate() {
        fs::hard_link(path, transaction.stage.join(format!("backup-{index}"))).map_err(|_| "package 移除備份失敗")?;
    }
    let mut deleted = Vec::new();
    for path in files.iter().chain(std::iter::once(&metadata_path)) {
        if fs::remove_file(path).is_err() {
            let mut missing = BTreeSet::new();
            for (index, destination) in deleted.iter().enumerate() {
                if fs::hard_link(transaction.stage.join(format!("backup-{index}")), destination).is_err() {
                    missing.insert(index);
                }
            }
            if !missing.is_empty() {
                for index in 0..files.len() + 1 {
                    if !missing.contains(&index) { let _ = fs::remove_file(transaction.stage.join(format!("backup-{index}"))); }
                }
                transaction.preserve_stage = true;
                return Err(format!("package 移除失敗且回復未完成；必要備份保留於 {}", transaction.stage.display()));
            }
            return Err("package 移除失敗，原檔已回復".into());
        }
        deleted.push(path.clone());
    }
    transaction.committed = true;
    for path in &files {
        let mut parent = path.parent();
        while let Some(dir) = parent {
            if dir == tree || dir == tree.join("share/lua").join(profile.lua_version()) || dir == tree.join("bin") { break; }
            if fs::remove_dir(dir).is_err() { break; }
            parent = dir.parent();
        }
    }
    println!("{{\"removed\":\"{}\",\"version\":\"{}\"}}", json_escape(name), json_escape(&id.version));
    Ok(())
}

pub(super) fn is_installed(tree: &Path, name: &str) -> Result<bool, String> {
    Ok(installed(tree)?.contains_key(name))
}
