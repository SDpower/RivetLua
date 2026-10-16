use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{Profile, rockspec, segment};
use crate::{StrictJsonParser, StrictJsonValue, json_escape};

const MAX_INDEX: u64 = 1024 * 1024;
const MAX_PACKAGES: usize = 256;
const MAX_FILES: usize = 8192;
const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone)]
struct Bound {
    op: &'static str,
    version: String,
}

#[derive(Clone)]
pub(super) struct Requirement {
    pub name: String,
    bounds: Vec<Bound>,
}

struct Candidate {
    spec: rockspec::Parsed,
    rockspec: PathBuf,
    source: PathBuf,
    source_sha256: String,
    build_flags: Vec<String>,
    dependencies: [Vec<Requirement>; 3],
}

fn field<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(key).ok_or_else(|| format!("index 缺少 {key}"))
}
fn string<'a>(value: &'a StrictJsonValue, key: &str) -> Result<&'a str, String> {
    field(value, key)?.as_str().ok_or_else(|| format!("index {key} 必須是字串"))
}
fn digest(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("index SHA-256 必須是 64 位 hex".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn checked_path(base: &Path, input: &str, directory: bool) -> Result<PathBuf, String> {
    let relative = Path::new(input);
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err("index 路徑必須是安全相對路徑".into());
    }
    let mut current = base.to_path_buf();
    let parts = relative.components().collect::<Vec<_>>();
    if !parts.iter().any(|part| matches!(part, Component::Normal(_))) {
        return Err("index 路徑缺少檔名".into());
    }
    for (index, part) in parts.iter().enumerate() {
        match part {
            Component::CurDir => continue,
            Component::ParentDir => {
                if !current.pop() { return Err("index 相對路徑越過根目錄".into()); }
            }
            Component::Normal(name) => {
                current.push(*name);
                let metadata = fs::symlink_metadata(&current).map_err(|_| "index 指定路徑不存在")?;
                if metadata.file_type().is_symlink() || (index + 1 < parts.len() && !metadata.is_dir()) {
                    return Err("index 路徑包含 symlink 或非目錄".into());
                }
            }
            _ => return Err("index 路徑不是相對路徑".into()),
        }
    }
    let metadata = fs::symlink_metadata(&current).map_err(|_| "index 指定路徑不存在")?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err("index 路徑型別不符".into());
    }
    Ok(current)
}

struct SourceBudget { files: usize, bytes: u64 }

fn source_rows(root: &Path, directory: &Path, depth: usize, budget: &mut SourceBudget, rows: &mut Vec<(String, String)>) -> Result<(), String> {
    if depth > 32 { return Err("source 目錄過深".into()); }
    for entry in fs::read_dir(directory).map_err(|_| "source 目錄不可讀")? {
        let entry = entry.map_err(|_| "source 目錄不可讀")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| "source 項目不可讀")?;
        if metadata.file_type().is_symlink() { return Err("source 不可含 symlink".into()); }
        if metadata.is_dir() {
            source_rows(root, &path, depth + 1, budget, rows)?;
        } else if metadata.is_file() {
            budget.files += 1;
            budget.bytes = budget.bytes.checked_add(metadata.len()).ok_or("source 大小溢位")?;
            if budget.files > MAX_FILES || budget.bytes > MAX_SOURCE_BYTES || metadata.len() > MAX_FILE_BYTES {
                return Err("source 檔案數或大小超過限制".into());
            }
            let bytes = fs::read(&path).map_err(|_| "source 檔案不可讀")?;
            if bytes.len() as u64 > MAX_FILE_BYTES { return Err("source 檔案超過限制".into()); }
            if bytes.len() as u64 > metadata.len() {
                budget.bytes = budget.bytes.checked_add(bytes.len() as u64 - metadata.len()).ok_or("source 大小溢位")?;
                if budget.bytes > MAX_SOURCE_BYTES { return Err("source 大小超過限制".into()); }
            }
            let relative = path.strip_prefix(root).map_err(|_| "source 路徑無效")?;
            let name = relative.components().map(|part| part.as_os_str().to_str().ok_or("source 路徑不是 UTF-8"))
                .collect::<Result<Vec<_>, _>>()?.join("/");
            if name.contains('\0') || name.contains('\n') { return Err("source 路徑含控制字元".into()); }
            rows.push((name, crate::p17::package_sha256_bytes(&bytes)?));
        } else {
            return Err("source 只允許一般檔案與目錄".into());
        }
    }
    Ok(())
}

fn source_digest(root: &Path, budget: &mut SourceBudget) -> Result<String, String> {
    let mut rows = Vec::new();
    source_rows(root, root, 0, budget, &mut rows)?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let mut joined = Vec::new();
    for (name, digest) in rows {
        joined.extend_from_slice(name.as_bytes());
        joined.push(0);
        joined.extend_from_slice(digest.as_bytes());
        joined.push(b'\n');
    }
    crate::p17::package_sha256_bytes(&joined)
}

pub(super) fn verified_source_digest(root: &Path) -> Result<String, String> {
    source_digest(root, &mut SourceBudget { files: 0, bytes: 0 })
}

pub(super) fn checked_existing(path: &Path, directory: bool) -> Result<(), String> {
    if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return Err("lock 路徑必須是正規絕對路徑".into());
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|_| "lock 路徑不存在")?;
        if meta.file_type().is_symlink() { return Err("lock 路徑包含 symlink".into()); }
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "lock 路徑不存在")?;
    if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) { return Err("lock 路徑型別不符".into()); }
    Ok(())
}

fn version_parts(input: &str) -> (Vec<VersionPart>, u64) {
    let (main, revision) = input.rsplit_once('-')
        .and_then(|(main, revision)| revision.parse::<u64>().ok().map(|number| (main, number)))
        .unwrap_or((input, 0));
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut numeric = false;
    for character in main.chars().chain(std::iter::once('.')) {
        if character.is_ascii_alphanumeric() {
            if !current.is_empty() && character.is_ascii_digit() != numeric {
                parts.push(if numeric { VersionPart::Number(current.parse().unwrap_or(u64::MAX)) } else { VersionPart::Text(current.to_ascii_lowercase()) });
                current.clear();
            }
            numeric = character.is_ascii_digit();
            current.push(character);
        } else if !current.is_empty() {
            parts.push(if numeric { VersionPart::Number(current.parse().unwrap_or(u64::MAX)) } else { VersionPart::Text(current.to_ascii_lowercase()) });
            current.clear();
        }
    }
    (parts, revision)
}

#[derive(Clone)]
enum VersionPart { Number(u64), Text(String) }

pub(super) fn compare_version(left: &str, right: &str) -> Ordering {
    let (a, a_revision) = version_parts(left);
    let (b, b_revision) = version_parts(right);
    for index in 0..a.len().max(b.len()) {
        let cmp = match (a.get(index), b.get(index)) {
            (Some(VersionPart::Number(a)), Some(VersionPart::Number(b))) => a.cmp(b),
            (Some(VersionPart::Text(a)), Some(VersionPart::Text(b))) => a.cmp(b),
            (Some(VersionPart::Number(_)), Some(VersionPart::Text(_))) => Ordering::Greater,
            (Some(VersionPart::Text(_)), Some(VersionPart::Number(_))) => Ordering::Less,
            (Some(VersionPart::Number(a)), None) => a.cmp(&0),
            (None, Some(VersionPart::Number(b))) => 0.cmp(b),
            (Some(VersionPart::Text(_)), None) => Ordering::Less,
            (None, Some(VersionPart::Text(_))) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if cmp != Ordering::Equal { return cmp; }
    }
    a_revision.cmp(&b_revision)
}

pub(super) fn parse_requirement(raw: &str) -> Result<Requirement, String> {
    let raw = raw.trim();
    let end = raw.find(char::is_whitespace).unwrap_or(raw.len());
    let name = raw[..end].to_ascii_lowercase();
    segment(&name, "dependency name")?;
    let mut bounds = Vec::new();
    for part in raw[end..].split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let (op, version) = [">=", "<=", "==", "!=", "~=", "~>", ">", "<", "="].into_iter()
            .find_map(|op| part.strip_prefix(op).map(|version| (op, version.trim())))
            .ok_or("dependency 版本限制格式無效")?;
        if version.is_empty() || version.len() > 128 || version.chars().any(char::is_whitespace) {
            return Err("dependency 版本限制無效".into());
        }
        bounds.push(Bound { op, version: version.to_owned() });
    }
    if !raw[end..].trim().is_empty() && bounds.is_empty() { return Err("dependency 版本限制缺失".into()); }
    Ok(Requirement { name, bounds })
}

fn matches_bounds(version: &str, bounds: &[Bound]) -> bool {
    bounds.iter().all(|bound| {
        let cmp = compare_version(version, &bound.version);
        match bound.op {
            ">=" => cmp != Ordering::Less,
            ">" => cmp == Ordering::Greater,
            "<=" => cmp != Ordering::Greater,
            "<" => cmp == Ordering::Less,
            "=" | "==" => cmp == Ordering::Equal,
            "!=" | "~=" => cmp != Ordering::Equal,
            "~>" => {
                let fields = bound.version.split('.').collect::<Vec<_>>();
                let bump = if fields.len() > 1 { fields.len() - 2 } else { 0 };
                let upper = fields[bump].parse::<u64>().ok().and_then(|value| value.checked_add(1))
                    .map(|value| format!("{}{}", fields[..bump].join("."), if bump == 0 { value.to_string() } else { format!(".{value}") }));
                cmp != Ordering::Less && upper.is_some_and(|upper| compare_version(version, &upper) == Ordering::Less)
            }
            _ => false,
        }
    })
}

pub(super) fn requirement_matches(requirement: &Requirement, version: &str) -> bool {
    matches_bounds(version, &requirement.bounds)
}

fn resolve(candidates: &[Candidate], by_name: &BTreeMap<String, Vec<usize>>, profile: Profile, chosen: BTreeMap<String, usize>, needs: BTreeMap<String, Vec<Bound>>, work: &mut usize) -> Result<(BTreeMap<String, usize>, Vec<usize>), String> {
    *work += 1;
    if *work > 100_000 { return Err("dependency 候選組合超過限制".into()); }
    for (name, bounds) in &needs {
        if let Some(&index) = chosen.get(name) {
            if !matches_bounds(&candidates[index].spec.identity.version, bounds) { return Err(format!("{name} 版本衝突")); }
        }
    }
    let Some((name, bounds)) = needs.iter().find(|(name, _)| !chosen.contains_key(*name)) else {
        let mut visiting = BTreeSet::new();
        let mut finished = BTreeSet::new();
        let mut order = Vec::new();
        for name in chosen.keys() { visit(name, &chosen, candidates, &mut visiting, &mut finished, &mut order)?; }
        return Ok((chosen, order));
    };
    let options = by_name.get(name).ok_or_else(|| format!("缺少 dependency {name}"))?;
    let mut last = format!("{name} 版本衝突");
    for &index in options {
        if !matches_bounds(&candidates[index].spec.identity.version, bounds) { continue; }
        let mut next_chosen = chosen.clone();
        let mut next_needs = needs.clone();
        next_chosen.insert(name.clone(), index);
        let mut failed = None;
        for dependency in candidates[index].dependencies.iter().flatten() {
            if dependency.name == "luajit" {
                failed = Some("LuaJIT-only dependency 不支援".into());
                break;
            }
            if dependency.name == "lua" {
                if !matches_bounds(profile.release(), &dependency.bounds) {
                    failed = Some("Lua profile 不符合 dependency 版本".into());
                }
                if failed.is_some() { break; }
            } else {
                next_needs.entry(dependency.name.clone()).or_default().extend(dependency.bounds.clone());
            }
        }
        if let Some(error) = failed { last = error; continue; }
        match resolve(candidates, by_name, profile, next_chosen, next_needs, work) {
            Ok(result) => return Ok(result),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn visit(name: &str, chosen: &BTreeMap<String, usize>, candidates: &[Candidate], visiting: &mut BTreeSet<String>, finished: &mut BTreeSet<String>, order: &mut Vec<usize>) -> Result<(), String> {
    if finished.contains(name) { return Ok(()); }
    if !visiting.insert(name.to_owned()) { return Err(format!("dependency cycle: {name}")); }
    let index = *chosen.get(name).ok_or("dependency 缺少選定版本")?;
    for dependency in candidates[index].dependencies.iter().flatten() {
        if dependency.name != "lua" { visit(&dependency.name, chosen, candidates, visiting, finished, order)?; }
    }
    visiting.remove(name);
    finished.insert(name.to_owned());
    order.push(index);
    Ok(())
}

fn json_text(value: &str) -> String { format!("\"{}\"", json_escape(value)) }

fn lock_json(candidates: &[Candidate], chosen: &BTreeMap<String, usize>, order: &[usize], root: &str) -> Result<String, String> {
    let root = chosen.get(root).ok_or("root package 缺失")?;
    let identity = &candidates[*root].spec.identity;
    let mut packages = Vec::new();
    for &index in order {
        let candidate = &candidates[index];
        let item = &candidate.spec.identity;
        let mut groups = Vec::new();
        for group in &candidate.dependencies {
            let mut resolved = Vec::new();
            for dependency in group {
                let version = if dependency.name == "lua" { continue; }
                    else { &candidates[*chosen.get(&dependency.name).ok_or("dependency 未解決")?].spec.identity.version };
                resolved.push(format!("{{\"name\":{},\"version\":{}}}", json_text(&dependency.name), json_text(version)));
            }
            groups.push(format!("[{}]", resolved.join(",")));
        }
        let flags = candidate.build_flags.iter().map(|flag| json_text(flag)).collect::<Vec<_>>().join(",");
        packages.push(format!("{{\"name\":{},\"version\":{},\"lua_profile\":{},\"target\":{},\"abi\":{},\"rockspec\":{},\"rockspec_sha256\":{},\"source\":{},\"source_sha256\":{},\"build_flags\":[{}],\"dependencies\":{{\"runtime\":{},\"build\":{},\"test\":{}}}}}",
            json_text(&item.name), json_text(&item.version), json_text(&item.lua_profile), json_text(&item.target), json_text(&item.abi),
            json_text(candidate.rockspec.to_str().ok_or("rockspec 路徑不是 UTF-8")?), json_text(&candidate.spec.sha256),
            json_text(candidate.source.to_str().ok_or("source 路徑不是 UTF-8")?), json_text(&candidate.source_sha256), flags,
            groups[0], groups[1], groups[2]));
    }
    let output = format!("{{\"format_version\":1,\"root\":{{\"name\":{},\"version\":{},\"lua_profile\":{},\"target\":{},\"abi\":{}}},\"packages\":[{}]}}",
        json_text(&identity.name), json_text(&identity.version), json_text(&identity.lua_profile), json_text(&identity.target), json_text(&identity.abi), packages.join(","));
    if output.len() > 8 * 1024 * 1024 { return Err("ClosureLock 輸出超過限制".into()); }
    Ok(output)
}

pub(super) fn lock(args: &[String]) -> Result<(), String> {
    let [index, root_name, profile, target, abi] = args else {
        return Err("用法：package lock <index.json> <root-name> <profile> <target> <abi>".into());
    };
    let profile = Profile::parse(profile)?;
    segment(root_name, "root-name")?;
    if root_name.eq_ignore_ascii_case("luajit") { return Err("LuaJIT-only package 不支援".into()); }
    segment(target, "target")?;
    let abi = digest(abi)?;
    let index = Path::new(index);
    let metadata = fs::symlink_metadata(index).map_err(|_| "index 檔案不可讀")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_INDEX {
        return Err("index 必須是不超過 1MiB 的一般檔案".into());
    }
    let contents = fs::read_to_string(index).map_err(|_| "index 檔案不可讀")?;
    if contents.len() as u64 > MAX_INDEX { return Err("index 超過大小限制".into()); }
    let parsed = StrictJsonParser::parse(&contents).map_err(|_| "index JSON 無效")?;
    let entries = field(&parsed, "packages")?.as_array().ok_or("index packages 必須是陣列")?;
    if entries.is_empty() || entries.len() > MAX_PACKAGES { return Err("index packages 數量無效".into()); }
    let parent = index.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let base = fs::canonicalize(parent).map_err(|_| "index 目錄不可讀")?;
    let mut candidates = Vec::new();
    let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut budget = SourceBudget { files: 0, bytes: 0 };
    let mut source_cache: BTreeMap<PathBuf, String> = BTreeMap::new();
    for entry in entries {
        let spec_path = checked_path(&base, string(entry, "rockspec")?, false)?;
        let source_path = checked_path(&base, string(entry, "source")?, true)?;
        let expected_spec = digest(string(entry, "rockspec_sha256")?)?;
        let expected_source = digest(string(entry, "source_sha256")?)?;
        let mut spec = rockspec::evaluate(&spec_path, profile, target, &abi)?;
        if spec.sha256 != expected_spec { return Err("rockspec SHA-256 不符".into()); }
        spec.json.clear();
        spec.json.shrink_to_fit();
        let actual_source = if let Some(prior) = source_cache.get(&source_path) {
            prior.clone()
        } else {
            let computed = source_digest(&source_path, &mut budget)?;
            source_cache.insert(source_path.clone(), computed.clone());
            computed
        };
        if actual_source != expected_source { return Err("source SHA-256 不符".into()); }
        let flags = field(entry, "build_flags")?.as_array().ok_or("build_flags 必須是陣列")?;
        if flags.len() > 32 { return Err("build_flags 數量超過限制".into()); }
        let build_flags = flags.iter().map(|flag| {
            let flag = flag.as_str().ok_or("build_flags 項目必須是字串")?;
            if flag.len() > 256 || flag.chars().any(char::is_control) { return Err("build_flags 項目無效".into()); }
            if rockspec::system_lua_flag(flag) { return Err("build_flags 要求系統 Lua linkage".into()); }
            Ok(flag.to_owned())
        }).collect::<Result<Vec<_>, String>>()?;
        if build_flags.windows(2).any(|pair| pair[0] == "-l"
            && (pair[1] == "lua" || pair[1] == "luajit" || pair[1].starts_with("lua5."))) {
            return Err("build_flags 要求系統 Lua linkage".into());
        }
        let dependencies = [
            spec.dependencies[0].iter().map(|raw| parse_requirement(raw)).collect::<Result<Vec<_>, _>>()?,
            spec.dependencies[1].iter().map(|raw| parse_requirement(raw)).collect::<Result<Vec<_>, _>>()?,
            spec.dependencies[2].iter().map(|raw| parse_requirement(raw)).collect::<Result<Vec<_>, _>>()?,
        ];
        let name = spec.identity.name.to_ascii_lowercase();
        if by_name.get(&name).is_some_and(|indices| indices.iter().any(|&index| candidates.get(index)
            .is_some_and(|other: &Candidate| other.spec.identity.version == spec.identity.version))) {
            return Err("index 同名同版本 package 重複".into());
        }
        let index = candidates.len();
        candidates.push(Candidate { spec, rockspec: spec_path, source: source_path, source_sha256: actual_source, build_flags, dependencies });
        by_name.entry(name).or_default().push(index);
    }
    for indices in by_name.values_mut() {
        indices.sort_by(|&a, &b| compare_version(&candidates[b].spec.identity.version, &candidates[a].spec.identity.version)
            .then_with(|| candidates[a].rockspec.cmp(&candidates[b].rockspec)));
    }
    let root = root_name.to_ascii_lowercase();
    let needs = BTreeMap::from([(root.clone(), Vec::new())]);
    let mut work = 0;
    let (chosen, order) = resolve(&candidates, &by_name, profile, BTreeMap::new(), needs, &mut work)?;
    println!("{}", lock_json(&candidates, &chosen, &order, &root)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Bound, compare_version, matches_bounds, parse_requirement};
    use std::cmp::Ordering;

    #[test]
    fn compound_constraints_and_versions() {
        let need = parse_requirement("foo >= 1.2-1, < 2.0").unwrap();
        assert!(matches_bounds("1.3-2", &need.bounds));
        assert!(!matches_bounds("2.0", &need.bounds));
        assert_eq!(compare_version("1.2-2", "1.2-1"), Ordering::Greater);
        assert!(matches_bounds("1.2.9", &[Bound { op: "~>", version: "1.2.3".into() }]));
        assert!(!matches_bounds("1.3", &[Bound { op: "~>", version: "1.2.3".into() }]));
    }
}
