use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use super::{PackageIdentity, Profile, closure, installer, rockspec, segment, tree};
use crate::{StrictJsonParser, StrictJsonValue, json_escape};

const CURRENT: &str = "1.3.0";
const MAX_HTTP_BODY: usize = 1024 * 1024;
const MAX_HTTP_HEADER: usize = 16 * 1024;
const MAX_LOCK: u64 = 8 * 1024 * 1024;
const MAX_ROCKSPEC: usize = 256 * 1024;

struct Endpoint { address: SocketAddr, authority: String }

impl Endpoint {
    fn parse(raw: &str) -> Result<Self, String> {
        let (ip, port, host) = if let Some(port) = raw.strip_prefix("http://127.0.0.1:") {
            (IpAddr::V4(Ipv4Addr::LOCALHOST), port, "127.0.0.1")
        } else if let Some(port) = raw.strip_prefix("http://[::1]:") {
            (IpAddr::V6(Ipv6Addr::LOCALHOST), port, "[::1]")
        } else { return Err("Moonrocks 只接受 literal loopback HTTP endpoint".into()); };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Moonrocks endpoint port 無效".into());
        }
        let port: u16 = port.parse().map_err(|_| "Moonrocks endpoint port 無效")?;
        if port == 0 { return Err("Moonrocks endpoint port 不可為零".into()); }
        Ok(Self { address: SocketAddr::new(ip, port), authority: format!("{host}:{port}") })
    }

    fn request(&self, method: &str, path: &str, content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>, String> {
        if body.len() > MAX_HTTP_BODY || !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_control() || byte == b' ') {
            return Err("Moonrocks request 無效或超過限制".into());
        }
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(5))
            .map_err(|_| "Moonrocks localtest 連線失敗")?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|_| "Moonrocks localtest timeout 設定失敗")?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|_| "Moonrocks localtest timeout 設定失敗")?;
        let accept = if path == "/manifest" { "text/plain" } else { "application/json" };
        let mut header = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: {accept}\r\nContent-Length: {}\r\n", self.authority, body.len());
        if let Some(value) = content_type { header.push_str(&format!("Content-Type: {value}\r\n")); }
        header.push_str("\r\n");
        stream.write_all(header.as_bytes()).map_err(|_| "Moonrocks localtest request 失敗")?;
        if !body.is_empty() { stream.write_all(body).map_err(|_| "Moonrocks localtest request 失敗")?; }
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk).map_err(|_| "Moonrocks localtest response 失敗")?;
            if count == 0 { return Err("Moonrocks localtest response 缺少 header".into()); }
            received.extend_from_slice(&chunk[..count]);
            if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") { break index + 4; }
            if received.len() > MAX_HTTP_HEADER { return Err("Moonrocks localtest header 超過限制".into()); }
        };
        if header_end > MAX_HTTP_HEADER { return Err("Moonrocks localtest header 超過限制".into()); }
        let head = std::str::from_utf8(&received[..header_end]).map_err(|_| "Moonrocks localtest header 無效")?;
        let mut lines = head.trim_end_matches("\r\n").split("\r\n");
        let status = lines.next().ok_or("Moonrocks localtest status 缺失")?;
        let mut parts = status.split_ascii_whitespace();
        let protocol = parts.next().ok_or("Moonrocks localtest status 無效")?;
        let code = parts.next().ok_or("Moonrocks localtest status 無效")?;
        if !matches!(protocol, "HTTP/1.0" | "HTTP/1.1") || code != "200" {
            return Err("Moonrocks localtest 回應非 200 或 redirect".into());
        }
        let mut length = None;
        for line in lines {
            if line.is_empty() { continue; }
            let (name, value) = line.split_once(':').ok_or("Moonrocks localtest header 無效")?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("Moonrocks localtest Content-Length 無效".into());
                }
                let size: usize = value.parse().map_err(|_| "Moonrocks localtest Content-Length 無效")?;
                if size > MAX_HTTP_BODY { return Err("Moonrocks localtest body 超過限制".into()); }
                length = Some(size);
            } else if name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-encoding") {
                return Err("Moonrocks localtest 不支援轉碼回應".into());
            }
        }
        let mut body = received.split_off(header_end);
        if body.len() > MAX_HTTP_BODY { return Err("Moonrocks localtest body 超過限制".into()); }
        if let Some(size) = length {
            if body.len() > size { return Err("Moonrocks localtest body 長度不符".into()); }
            let have = body.len();
            body.resize(size, 0);
            stream.read_exact(&mut body[have..])
                .map_err(|_| "Moonrocks localtest body 不完整")?;
        } else {
            stream.take((MAX_HTTP_BODY + 1 - body.len()) as u64).read_to_end(&mut body)
                .map_err(|_| "Moonrocks localtest body 讀取失敗")?;
            if body.len() > MAX_HTTP_BODY { return Err("Moonrocks localtest body 超過限制".into()); }
        }
        Ok(body)
    }
}

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(name).ok_or_else(|| format!("Moonrocks 回應缺少 {name}"))
}

fn text_field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    field(value, name)?.as_str().ok_or_else(|| format!("Moonrocks {name} 型別無效"))
}

fn response(body: &[u8]) -> Result<StrictJsonValue, String> {
    let text = std::str::from_utf8(body).map_err(|_| "Moonrocks JSON 不是 UTF-8")?;
    let value = StrictJsonParser::parse(text).map_err(|_| "Moonrocks JSON 格式無效")?;
    if !matches!(&value, StrictJsonValue::Object(_)) { return Err("Moonrocks JSON 必須是 object".into()); }
    for name in ["error", "errors"] {
        if let Some(item) = value.get(name) {
            let empty = match item {
                StrictJsonValue::Null | StrictJsonValue::Bool(false) => true,
                StrictJsonValue::String(text) => text.is_empty(),
                StrictJsonValue::Array(items) => items.is_empty(),
                StrictJsonValue::Object(items) => items.is_empty(),
                _ => false,
            };
            if !empty { return Err("Moonrocks 服務回報錯誤".into()); }
        }
    }
    for name in ["two_factor_required", "two_factor"] {
        if !matches!(value.get(name), None | Some(StrictJsonValue::Bool(false))) {
            return Err("Moonrocks two_factor 需要額外授權，未支援".into());
        }
    }
    Ok(value)
}

fn json_get(endpoint: &Endpoint, path: &str) -> Result<StrictJsonValue, String> {
    response(&endpoint.request("GET", path, None, &[])?)
}

fn safe_text(value: &str, token: Option<&str>) -> Result<(), String> {
    if value.len() > 128 || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || token.is_some_and(|secret| value.contains(secret)) {
        return Err("Moonrocks 回應欄位無效或包含機密".into());
    }
    Ok(())
}

fn tool_version(endpoint: &Endpoint, token: Option<&str>) -> Result<String, String> {
    let answer = json_get(endpoint, &format!("/api/tool_version?current={CURRENT}"))?;
    if matches!(answer.get("force_update"), Some(StrictJsonValue::Bool(true))) {
        return Err("Moonrocks localtest 要求不相容的強制更新".into());
    }
    if !matches!(answer.get("force_update"), None | Some(StrictJsonValue::Bool(false))) {
        return Err("Moonrocks force_update 型別無效".into());
    }
    let version = text_field(&answer, "version")?;
    safe_text(version, token)?;
    Ok(version.to_owned())
}

fn token(name: &str) -> Result<String, String> {
    let mut bytes = name.bytes();
    if name.len() > 128 || !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err("Moonrocks token-env 名稱無效".into());
    }
    let secret = env::var(name).map_err(|_| "Moonrocks secret store 環境變數缺失")?;
    if secret.len() < 16 || secret.len() > 1024 || secret.chars().any(char::is_control) {
        return Err("Moonrocks secret 長度或內容無效".into());
    }
    Ok(secret)
}

fn percent(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { result.push(char::from(byte)); }
        else { result.push_str(&format!("%{byte:02X}")); }
    }
    result
}

fn status(endpoint: &Endpoint, secret: &str, namespace: &str) -> Result<(), String> {
    let answer = json_get(endpoint, &format!("/api/1/{}/status", percent(secret)))?;
    let authorized = answer.get("namespace").and_then(StrictJsonValue::as_str)
        .ok_or("Moonrocks localtest adapter status 必須提供 namespace")?;
    if authorized != namespace {
        return Err("Moonrocks localtest token 與 namespace 不符".into());
    }
    if matches!(answer.get("logged_in"), Some(StrictJsonValue::Bool(false)))
        || matches!(answer.get("authenticated"), Some(StrictJsonValue::Bool(false))) {
        return Err("Moonrocks localtest 登入狀態無效".into());
    }
    if let Some(value) = answer.get("status") {
        if !matches!(value.as_str(), Some("ok" | "valid" | "success")) {
            return Err("Moonrocks localtest 登入狀態無效".into());
        }
    }
    Ok(())
}

fn local_namespace(name: &str) -> Result<(), String> {
    segment(name, "Moonrocks namespace")?;
    if !name.starts_with("localtest-") || name.len() <= "localtest-".len() {
        return Err("Moonrocks namespace 必須是 localtest- 前綴".into());
    }
    Ok(())
}

fn lock_packages(path: &Path, tree_path: &Path, profile: Profile, target: &str, abi: &str) -> Result<Vec<PackageIdentity>, String> {
    let lock = installer::read_json(path, MAX_LOCK)?;
    if field(&lock, "format_version")?.as_i32() != Some(1) { return Err("Moonrocks ClosureLock 版本無效".into()); }
    let root = installer::identity(field(&lock, "root")?)?;
    if root.lua_profile != profile.name() || root.target != target || root.abi != abi.to_ascii_lowercase() {
        return Err("Moonrocks ClosureLock tree identity 不符".into());
    }
    let entries = field(&lock, "packages")?.as_array().ok_or("Moonrocks ClosureLock packages 型別無效")?;
    if entries.is_empty() || entries.len() > 256 { return Err("Moonrocks ClosureLock package 數量無效".into()); }
    let installed = installer::installed(tree_path)?;
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();
    let mut root_found = false;
    for entry in entries {
        let identity = installer::identity(entry)?;
        if identity.lua_profile != root.lua_profile || identity.target != root.target || identity.abi != root.abi
            || !seen.insert(identity.name.to_ascii_lowercase()) {
            return Err("Moonrocks ClosureLock package identity 混用或重複".into());
        }
        if identity.name.eq_ignore_ascii_case("luajit") { return Err("Moonrocks LuaJIT-only dependency 未支援".into()); }
        if identity == root { root_found = true; }
        let record = installed.get(&identity.name).ok_or("Moonrocks ClosureLock package 尚未安裝")?;
        if installer::identity(record)? != identity { return Err("Moonrocks ClosureLock 與已安裝版本不符".into()); }
        packages.push(identity);
    }
    if !root_found { return Err("Moonrocks ClosureLock 缺少 root package".into()); }
    let locked = packages.iter().map(|item| (item.name.to_ascii_lowercase(), item.version.as_str())).collect::<BTreeMap<_, _>>();
    let mut edges = BTreeMap::new();
    for entry in entries {
        let name = text_field(entry, "name")?.to_ascii_lowercase();
        let groups = field(entry, "dependencies")?;
        let mut dependencies = BTreeSet::new();
        for group in ["runtime", "build", "test"] {
            let raw = field(groups, group)?;
            let count = raw.as_array().ok_or("Moonrocks lock dependency 型別無效")?.len();
            let pairs = installer::dependency_pairs(raw)?;
            if pairs.len() != count { return Err("Moonrocks lock dependency 重複".into()); }
            for (dependency, version) in pairs {
                if dependency == "luajit" { return Err("Moonrocks LuaJIT-only dependency 未支援".into()); }
                if locked.get(&dependency).copied() != Some(version.as_str()) {
                    return Err("Moonrocks ClosureLock 缺少依賴或版本不符".into());
                }
                dependencies.insert(dependency);
            }
        }
        edges.insert(name, dependencies);
    }
    let mut reachable = BTreeSet::new();
    let mut todo = vec![root.name.to_ascii_lowercase()];
    while let Some(name) = todo.pop() {
        if reachable.insert(name.clone()) {
            todo.extend(edges.get(&name).ok_or("Moonrocks ClosureLock 缺少依賴")?.iter().cloned());
        }
    }
    if reachable.len() != locked.len() { return Err("Moonrocks ClosureLock 含 root 不可達 package".into()); }
    Ok(packages)
}

fn outdated(endpoint: &Endpoint, namespace: &str, path: &Path, tree_path: &Path, profile: Profile, target: &str, abi: &str) -> Result<(), String> {
    let packages = lock_packages(path, tree_path, profile, target, abi)?;
    let manifest = endpoint.request("GET", "/manifest", None, &[])?;
    let versions = rockspec::manifest_versions(&manifest, profile)?;
    let mut rows = Vec::new();
    for item in packages {
        let latest = versions.get(&item.name.to_ascii_lowercase()).and_then(|items| items.iter().max_by(|a, b| closure::compare_version(a, b)));
        let latest_json = if let Some(latest) = latest { format!("\"{}\"", json_escape(latest)) } else { "null".to_owned() };
        let old = latest.is_some_and(|latest| closure::compare_version(&item.version, latest).is_lt());
        rows.push(format!("{{\"name\":\"{}\",\"current\":\"{}\",\"wanted\":\"{}\",\"latest\":{},\"outdated\":{}}}",
            json_escape(&item.name), json_escape(&item.version), json_escape(&item.version), latest_json, old));
    }
    println!("{{\"operation\":\"outdated\",\"namespace\":\"{}\",\"packages\":[{}]}}", json_escape(namespace), rows.join(","));
    Ok(())
}

fn boundary(bytes: &[u8]) -> Result<String, String> {
    for index in 0..1024 {
        let value = format!("rivetlua-localtest-{index}");
        if !bytes.windows(value.len()).any(|window| window == value.as_bytes()) { return Ok(value); }
    }
    Err("Moonrocks multipart boundary 無法選定".into())
}

fn upload(endpoint: &Endpoint, namespace: &str, secret: &str, path: &Path, tree_path: &Path,
    profile: Profile, target: &str, abi: &str) -> Result<(), String> {
    let spec = rockspec::evaluate(path, profile, target, abi)?;
    let id = &spec.identity;
    if !id.name.starts_with(&format!("{namespace}-")) || id.name.len() <= namespace.len() + 1 {
        return Err("Moonrocks upload package 不屬於授權 localtest namespace".into());
    }
    for raw in spec.dependencies.iter().flatten() {
        if closure::parse_requirement(raw).map_err(|_| "Moonrocks dependency 無效")?.name == "luajit" {
            return Err("Moonrocks LuaJIT-only dependency 未支援".into());
        }
    }
    let records = installer::installed(tree_path)?;
    let installed = records.get(&id.name).ok_or("Moonrocks upload package 尚未安裝")?;
    if installer::identity(installed)? != *id { return Err("Moonrocks upload package identity 與 tree 不符".into()); }
    for value in [&id.name, &id.version, &id.lua_profile, &id.target, &id.abi, namespace, &spec.sha256] {
        if value.contains(secret) { return Err("Moonrocks 輸出欄位包含機密".into()); }
    }
    let mut bytes = Vec::new();
    File::open(path).map_err(|_| "Moonrocks rockspec 不可讀")?.take((MAX_ROCKSPEC + 1) as u64)
        .read_to_end(&mut bytes).map_err(|_| "Moonrocks rockspec 不可讀")?;
    if bytes.len() > MAX_ROCKSPEC || crate::p17::package_sha256_bytes(&bytes)? != spec.sha256 {
        return Err("Moonrocks rockspec 在準備上傳期間已變更".into());
    }
    let key = percent(secret);
    let check = json_get(endpoint, &format!("/api/1/{key}/check_rockspec?package={}&version={}", percent(&id.name), percent(&id.version)))?;
    if !matches!(check.get("version"), None | Some(StrictJsonValue::Null | StrictJsonValue::Bool(false))) {
        return Err("Moonrocks localtest 已存在此版本，拒絕覆寫".into());
    }
    let marker = boundary(&bytes)?;
    let mut body = format!("--{marker}\r\nContent-Disposition: form-data; name=\"rockspec_file\"; filename=\"package.rockspec\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(&bytes);
    body.extend_from_slice(format!("\r\n--{marker}--\r\n").as_bytes());
    let answer = response(&endpoint.request("POST", &format!("/api/1/{key}/upload"),
        Some(&format!("multipart/form-data; boundary={marker}")), &body)?)?;
    let version = field(&answer, "version")?;
    let number = match field(version, "id")? {
        StrictJsonValue::Number(value) if value.bytes().all(|byte| byte.is_ascii_digit()) => value.parse::<u64>().ok().filter(|id| *id > 0),
        _ => None,
    };
    if number.is_none() || !matches!(field(version, "development")?, StrictJsonValue::Bool(false))
        || !matches!(field(&answer, "is_new")?, StrictJsonValue::Bool(true)) {
        return Err("Moonrocks upload 回應版本狀態無效".into());
    }
    let manifests = field(&answer, "manifests")?.as_array().ok_or("Moonrocks manifests 型別無效")?;
    if manifests.is_empty() || manifests.len() > 128 || manifests.iter().any(|item| item.as_str().is_none_or(|text| text.is_empty() || text.len() > 1024)) {
        return Err("Moonrocks manifests 無效".into());
    }
    let module_url = text_field(&answer, "module_url")?;
    if module_url.is_empty() || module_url.len() > 1024 { return Err("Moonrocks module_url 無效".into()); }
    println!("{{\"status\":\"localtest-uploaded\",\"package\":\"{}\",\"version\":\"{}\",\"lua_profile\":\"{}\",\"target\":\"{}\",\"abi\":\"{}\",\"namespace\":\"{}\",\"rockspec_sha256\":\"{}\"}}",
        json_escape(&id.name), json_escape(&id.version), id.lua_profile, json_escape(&id.target), id.abi,
        json_escape(namespace), spec.sha256);
    Ok(())
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let [root, profile, target, abi, raw_endpoint, namespace, token_env, command, rest @ ..] = args else {
        return Err("用法：package moonrocks <root> <profile> <target> <abi> <endpoint> <namespace> <token-env> <version|outdated|login|upload> [input]".into());
    };
    let profile = Profile::parse(profile)?;
    let tree_path = tree::existing(Path::new(root), profile, target, abi)?;
    local_namespace(namespace)?;
    let endpoint = Endpoint::parse(raw_endpoint)?;
    match command.as_str() {
        "version" if rest.is_empty() && token_env == "-" => {
            let version = tool_version(&endpoint, None)?;
            println!("{{\"operation\":\"version\",\"version\":\"{}\",\"force_update\":false}}", json_escape(&version));
            Ok(())
        }
        "outdated" if rest.len() == 1 && token_env == "-" =>
            outdated(&endpoint, namespace, Path::new(&rest[0]), &tree_path, profile, target, abi),
        "login" if rest.is_empty() => {
            let secret = token(token_env)?;
            if namespace.contains(&secret) { return Err("Moonrocks 輸出欄位包含機密".into()); }
            tool_version(&endpoint, Some(&secret))?;
            status(&endpoint, &secret, namespace)?;
            println!("{{\"logged_in\":true,\"namespace\":\"{}\"}}", json_escape(namespace));
            Ok(())
        }
        "upload" if rest.len() == 1 => {
            let secret = token(token_env)?;
            tool_version(&endpoint, Some(&secret))?;
            status(&endpoint, &secret, namespace)?;
            upload(&endpoint, namespace, &secret, Path::new(&rest[0]), &tree_path, profile, target, abi)
        }
        _ => Err("Moonrocks command 或參數未支援".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoint;

    #[test]
    fn endpoint_rejects_non_loopback_and_extra_path() {
        assert!(Endpoint::parse("http://127.0.0.1:8080").is_ok());
        assert!(Endpoint::parse("http://[::1]:8080").is_ok());
        assert!(Endpoint::parse("https://127.0.0.1:8080").is_err());
        assert!(Endpoint::parse("http://127.0.0.1:8080/api").is_err());
    }
}
