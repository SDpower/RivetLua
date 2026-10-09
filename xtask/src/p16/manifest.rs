use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub(super) struct Row {
    pub id: String,
    pub profile: String,
    pub kind: String,
    pub name: String,
    pub definition: String,
    pub condition: String,
    pub status: String,
    pub evidence: String,
    pub mapping: String,
    pub p17_use: String,
}

#[derive(Debug)]
pub(super) struct Manifest {
    pub rows: Vec<Row>,
    pub header_sets: HashMap<String, String>,
    pub header_files: HashMap<String, HashMap<String, String>>,
}

fn value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

fn string(value: &str) -> Result<&str, String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| "P16 ABI manifest 欄位不是字串".into())
}

pub(super) fn load(root: &Path) -> Result<Manifest, String> {
    let source = fs::read_to_string(root.join("tests/p16/abi-manifest.toml"))
        .map_err(|error| format!("P16 ABI manifest 不可讀：{error}"))?;
    let mut schema = false;
    let mut revision = false;
    let mut targets = false;
    let mut section = "root";
    let mut rows = Vec::new();
    let mut row: HashMap<String, String> = HashMap::new();
    let mut profile: HashMap<String, String> = HashMap::new();
    let mut header_sets = HashMap::new();
    let mut header_files = HashMap::new();
    let finish_row =
        |row: &mut HashMap<String, String>, rows: &mut Vec<Row>| -> Result<(), String> {
            if row.is_empty() {
                return Ok(());
            }
            let take = |key: &str| {
                row.get(key)
                    .cloned()
                    .ok_or_else(|| format!("P16 ABI manifest item 缺 {key}"))
            };
            rows.push(Row {
                id: take("id")?,
                profile: take("profile")?,
                kind: take("kind")?,
                name: take("name")?,
                definition: take("definition")?,
                condition: take("condition")?,
                status: take("implementation_status")?,
                evidence: take("evidence")?,
                mapping: take("implementation_mapping")?,
                p17_use: take("p17_use")?,
            });
            row.clear();
            Ok(())
        };
    let finish_profile = |profile: &mut HashMap<String, String>,
                          sets: &mut HashMap<String, String>,
                          files: &mut HashMap<String, HashMap<String, String>>|
     -> Result<(), String> {
        if profile.is_empty() {
            return Ok(());
        }
        let id = profile.get("id").ok_or("P16 profile 缺 ID")?;
        let (release, case_profile) = if id == "lua55" {
            ("5.5.1", "lua55-i64f64")
        } else {
            ("5.4.9", "lua54-i64f64")
        };
        if profile.get("release").map(String::as_str) != Some(release)
            || profile.get("case_profile").map(String::as_str) != Some(case_profile)
            || profile.get("numeric_config").map(String::as_str) != Some("i64f64")
        {
            return Err(format!("P16 profile {id} version/numeric 不符"));
        }
        let hash = profile
            .get("header_set_sha256")
            .ok_or("P16 profile 缺 header set SHA")?;
        if !matches!(id.as_str(), "lua54" | "lua55")
            || !super::is_sha(hash)
            || sets.insert(id.clone(), hash.clone()).is_some()
        {
            return Err("P16 profile 身分、header SHA 或重複項無效".into());
        }
        let mut hashes = HashMap::new();
        for (key, name) in [
            ("lua_h_sha256", "lua.h"),
            ("lauxlib_h_sha256", "lauxlib.h"),
            ("luaconf_h_sha256", "luaconf.h"),
        ] {
            let hash = profile
                .get(key)
                .ok_or_else(|| format!("P16 profile 缺 {key}"))?;
            if !super::is_sha(hash) {
                return Err(format!("P16 profile {key} SHA 無效"));
            }
            hashes.insert(name.into(), hash.clone());
        }
        files.insert(id.clone(), hashes);
        profile.clear();
        Ok(())
    };
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[profile]]" || line == "[[item]]" {
            match section {
                "profile" => finish_profile(&mut profile, &mut header_sets, &mut header_files)?,
                "item" => finish_row(&mut row, &mut rows)?,
                _ => {}
            }
            section = if line == "[[profile]]" {
                "profile"
            } else {
                "item"
            };
            continue;
        }
        let Some((key, raw)) = value(line) else {
            return Err("P16 ABI manifest 語法錯誤".into());
        };
        match section {
            "root" if key == "schema" => schema = string(raw)? == "rivetlua-p16-abi-manifest-v1",
            "root" if key == "abi_revision" => revision = raw == "1",
            "root" if key == "target_matrix" => {
                targets = raw
                    == "[\"aarch64-apple-darwin\", \"x86_64-unknown-linux-gnu\", \"aarch64-unknown-linux-gnu\"]"
            }
            "profile"
                if matches!(
                    key,
                    "id" | "release"
                        | "case_profile"
                        | "numeric_config"
                        | "header_set_sha256"
                        | "lua_h_sha256"
                        | "lauxlib_h_sha256"
                        | "luaconf_h_sha256"
                ) =>
            {
                if profile.insert(key.into(), string(raw)?.into()).is_some() {
                    return Err("P16 profile 重複欄位".into());
                }
            }
            "item"
                if matches!(
                    key,
                    "id" | "profile"
                        | "kind"
                        | "name"
                        | "definition"
                        | "condition"
                        | "implementation_status"
                        | "evidence"
                        | "implementation_mapping"
                        | "p17_use"
                ) =>
            {
                if row.insert(key.into(), string(raw)?.into()).is_some() {
                    return Err("P16 item 重複欄位".into());
                }
            }
            _ => {}
        }
    }
    match section {
        "profile" => finish_profile(&mut profile, &mut header_sets, &mut header_files)?,
        "item" => finish_row(&mut row, &mut rows)?,
        _ => {}
    }
    if !schema || !revision || !targets || header_sets.len() != 2 || rows.len() != 951 {
        return Err(format!(
            "P16 ABI manifest schema/revision/profile/951 列不符：{}",
            rows.len()
        ));
    }
    let mut ids = HashSet::new();
    let mut header_only = 0;
    for row in &rows {
        if !ids.insert(&row.id)
            || !row.id.starts_with(&format!("{}:", row.profile))
            || !matches!(row.profile.as_str(), "lua54" | "lua55")
            || !matches!(
                row.status.as_str(),
                "HEADER_ONLY" | "IMPLEMENTED" | "NOT_IMPLEMENTED"
            )
        {
            return Err(format!("P16 ABI manifest item 身分／狀態無效：{}", row.id));
        }
        match row.kind.as_str() {
            "function" if row.status == "HEADER_ONLY" => {
                return Err(format!("P16 function 被標為 HEADER_ONLY：{}", row.id));
            }
            "constant" | "type" | "layout" | "layout_field" | "alignment" | "size"
                if row.status != "HEADER_ONLY" =>
            {
                return Err(format!("P16 header ABI item 分類不符：{}", row.id));
            }
            "function" | "macro" | "constant" | "type" | "opaque_type" | "layout"
            | "layout_field" | "alignment" | "size" => {}
            _ => return Err(format!("P16 ABI manifest item kind 無效：{}", row.id)),
        }
        if row.status == "HEADER_ONLY" {
            header_only += 1;
        }
        if row.evidence.is_empty() || row.mapping.is_empty() || row.p17_use.is_empty() {
            return Err(format!("P16 ABI manifest item 缺對應／證據：{}", row.id));
        }
    }
    if header_only != 538 {
        return Err(format!("P16 HEADER_ONLY 列數非 538：{header_only}"));
    }
    Ok(Manifest {
        rows,
        header_sets,
        header_files,
    })
}
