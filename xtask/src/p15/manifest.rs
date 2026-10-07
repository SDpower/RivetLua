use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const COMMITTED: &str = include_str!("../../../tests/p15/runner-manifest.toml");

fn validate_committed(contents: &str) -> Result<(), String> {
    let mut actual = BTreeMap::new();
    let mut section = "";
    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("P15 source manifest 格式錯誤")?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or("P15 source manifest 僅接受固定字串值")?;
        if actual
            .insert(
                (section.to_owned(), key.trim().to_owned()),
                value.to_owned(),
            )
            .is_some()
        {
            return Err("P15 source manifest 重複欄位".into());
        }
    }
    let expected = [
        ("", "schema", "rivetlua-p15-source-v1"),
        ("", "source_recorded_date", "2026-09-21"),
        ("", "runner_version", "p15-basic-v2"),
        ("lua55-i64f64", "release", "5.5.1"),
        (
            "lua55-i64f64",
            "url",
            "https://www.lua.org/tests/lua-5.5.1-tests.tar.gz",
        ),
        ("lua55-i64f64", "tarball", "vendor/lua55/tests.tar.gz"),
        (
            "lua55-i64f64",
            "tarball_sha256",
            "da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31",
        ),
        ("lua55-i64f64", "suite", "vendor/lua55/lua-5.5.1-tests"),
        (
            "lua55-i64f64",
            "all_lua_sha256",
            "f1b8b8075a71e7abc40260f6b9112e8d2a1057772f26374df4bc800d10296309",
        ),
        (
            "lua55-i64f64",
            "binary_recipe",
            "cargo build --locked -p rivetlua-cli --bin rivetlua",
        ),
        ("lua55-i64f64", "binary_features", "default"),
        ("lua55-i64f64", "version", "RivetLua 0.0.0 (Lua 5.5.1)"),
        ("lua54-i64f64", "release", "5.4.9"),
        (
            "lua54-i64f64",
            "url",
            "https://www.lua.org/tests/lua-5.4.9-tests.tar.gz",
        ),
        ("lua54-i64f64", "tarball", "vendor/lua54/tests.tar.gz"),
        (
            "lua54-i64f64",
            "tarball_sha256",
            "7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca",
        ),
        ("lua54-i64f64", "suite", "vendor/lua54/lua-5.4.9-tests"),
        (
            "lua54-i64f64",
            "all_lua_sha256",
            "3e296dd2b26ac6891ccba1ebaa62d40f1816ac93c7efdeaddc05aaa064e7311c",
        ),
        (
            "lua54-i64f64",
            "binary_recipe",
            "cargo build --locked -p rivetlua-cli --bin rivetlua --features default-lua54",
        ),
        ("lua54-i64f64", "binary_features", "default-lua54"),
        ("lua54-i64f64", "version", "RivetLua 0.0.0 (Lua 5.4.9)"),
    ];
    if actual.len() != expected.len()
        || expected.iter().any(|(section, key, value)| {
            actual
                .get(&(section.to_string(), key.to_string()))
                .map(String::as_str)
                != Some(*value)
        })
    {
        return Err("P15 source manifest 固定來源、版本或 binary recipe 不符".into());
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct Source {
    pub profile: &'static str,
    pub release: &'static str,
    pub url: &'static str,
    pub tarball: &'static str,
    pub tarball_sha256: &'static str,
    pub suite: &'static str,
    pub all_lua_sha256: &'static str,
    pub version: &'static str,
    pub feature: &'static str,
}

pub(super) fn source(root: &Path, profile: &str) -> Result<Source, String> {
    let actual = fs::read_to_string(root.join("tests/p15/runner-manifest.toml"))
        .map_err(|error| format!("讀取 P15 source manifest 失敗：{error}"))?;
    if actual != COMMITTED {
        return Err("P15 source manifest 與 runner 編譯時內容不符".into());
    }
    validate_committed(&actual)?;
    match profile {
        "lua55-i64f64" => Ok(Source {
            profile: "lua55-i64f64",
            release: "5.5.1",
            url: "https://www.lua.org/tests/lua-5.5.1-tests.tar.gz",
            tarball: "vendor/lua55/tests.tar.gz",
            tarball_sha256: "da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31",
            suite: "vendor/lua55/lua-5.5.1-tests",
            all_lua_sha256: "f1b8b8075a71e7abc40260f6b9112e8d2a1057772f26374df4bc800d10296309",
            version: "RivetLua 0.0.0 (Lua 5.5.1)",
            feature: "default",
        }),
        "lua54-i64f64" => Ok(Source {
            profile: "lua54-i64f64",
            release: "5.4.9",
            url: "https://www.lua.org/tests/lua-5.4.9-tests.tar.gz",
            tarball: "vendor/lua54/tests.tar.gz",
            tarball_sha256: "7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca",
            suite: "vendor/lua54/lua-5.4.9-tests",
            all_lua_sha256: "3e296dd2b26ac6891ccba1ebaa62d40f1816ac93c7efdeaddc05aaa064e7311c",
            version: "RivetLua 0.0.0 (Lua 5.4.9)",
            feature: "default-lua54",
        }),
        _ => Err(format!("P15 不支援的 profile：{profile}")),
    }
}

pub(super) fn sha256(path: &Path) -> Result<String, String> {
    let (program, prefix) = super::super::sha256_tool(std::env::consts::OS)?;
    let output = Command::new(program)
        .args(prefix)
        .arg(path)
        .output()
        .map_err(|error| format!("SHA-256 啟動失敗 {}：{error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "SHA-256 失敗 {}：{}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("SHA-256 輸出錯誤：{}", path.display()));
    }
    Ok(value)
}

pub(super) fn verify_archive(root: &Path, source: &Source) -> Result<(), String> {
    let tarball = root.join(source.tarball);
    if sha256(&tarball)? != source.tarball_sha256 {
        return Err(format!(
            "官方 tests tarball SHA-256 不符：{}",
            tarball.display()
        ));
    }
    let all_lua = root.join(source.suite).join("all.lua");
    if sha256(&all_lua)? != source.all_lua_sha256 {
        return Err(format!("官方 all.lua SHA-256 不符：{}", all_lua.display()));
    }
    Ok(())
}

fn files(root: &Path, path: &Path, found: &mut BTreeMap<PathBuf, String>) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|error| format!("讀取 suite 失敗：{error}"))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        if relative == Path::new("libs/P1/.gitkeep") {
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if !metadata.file_type().is_file()
                || fs::read(&path).map_err(|error| error.to_string())? != b"\n"
            {
                return Err("P00 空目錄標記內容變更".into());
            }
            continue;
        }
        let kind = fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            files(root, &path, found)?;
        } else if kind.is_file() {
            found.insert(relative.to_path_buf(), sha256(&path)?);
        } else {
            return Err(format!("suite 含非一般檔案：{}", path.display()));
        }
    }
    Ok(())
}

pub(super) fn file_map(root: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let mut found = BTreeMap::new();
    files(root, root, &mut found)?;
    if found.is_empty() {
        return Err("suite 沒有任何官方檔案".into());
    }
    Ok(found)
}

pub(super) fn tree_sha(map: &BTreeMap<PathBuf, String>) -> Result<String, String> {
    let (program, prefix) = super::super::sha256_tool(std::env::consts::OS)?;
    let mut child = Command::new(program)
        .args(prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    {
        let input = child.stdin.as_mut().ok_or("tree SHA 缺少 stdin")?;
        input
            .write_all(b"RivetLua-P15-tree-v1\0")
            .map_err(|error| error.to_string())?;
        for (path, sha) in map {
            input
                .write_all(path.to_string_lossy().as_bytes())
                .map_err(|error| error.to_string())?;
            input.write_all(b"\0").map_err(|error| error.to_string())?;
            input
                .write_all(sha.as_bytes())
                .map_err(|error| error.to_string())?;
            input.write_all(b"\n").map_err(|error| error.to_string())?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("計算 suite tree SHA 失敗".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .into())
}

pub(super) fn prepare(
    root: &Path,
    source: &Source,
    work: &Path,
) -> Result<(PathBuf, BTreeMap<PathBuf, String>, String), String> {
    verify_archive(root, source)?;
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let output = Command::new("tar")
        .arg("-xzf")
        .arg(root.join(source.tarball))
        .arg("-C")
        .arg(work)
        .output()
        .map_err(|error| format!("解壓官方 tests 失敗：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "解壓官方 tests 失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let suite_name = Path::new(source.suite)
        .file_name()
        .ok_or("suite 名稱缺失")?;
    let extracted = work.join(suite_name);
    let expected = file_map(&extracted)?;
    let canonical = file_map(&root.join(source.suite))?;
    if expected != canonical {
        return Err("官方 canonical suite 與已驗 tarball 全檔案內容不符".into());
    }
    if expected.get(Path::new("all.lua")).map(String::as_str) != Some(source.all_lua_sha256) {
        return Err("解壓後 all.lua SHA-256 不符".into());
    }
    let tree_sha = tree_sha(&expected)?;
    for path in expected.keys() {
        let file = extracted.join(path);
        let mut permissions = fs::metadata(&file)
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&file, permissions).map_err(|error| error.to_string())?;
    }
    Ok((extracted, expected, tree_sha))
}
