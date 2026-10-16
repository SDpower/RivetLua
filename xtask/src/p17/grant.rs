use super::manifest::{self, Profile};
use super::report::q;
use crate::{StrictJsonParser, StrictJsonValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const LUA55_LAYOUT: [i32; 37] = [
    8, 8, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 144, 8, 1056, 8, 16, 8, 16,
    8, 76, 136, 32, 8, 8, 60, 1024,
];
const LUA54_LAYOUT: [i32; 37] = [
    8, 8, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 136, 8, 1056, 8, 16, 8, 16,
    8, 68, 128, 32, 8, 8, 60, 1024,
];

pub(super) struct ValidatedAbi {
    pub json: String,
    pub header_set_sha256: String,
}

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value
        .get(name)
        .ok_or_else(|| format!("P17 C ABI JSON 缺 {name}"))
}

fn string<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("P17 C ABI JSON {name} 非字串"))
}

fn number(value: &StrictJsonValue, name: &str) -> Result<i32, String> {
    field(value, name)?
        .as_i32()
        .ok_or_else(|| format!("P17 C ABI JSON {name} 非整數"))
}

fn lowercase_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn manifest_headers(root: &Path, profile: Profile) -> Result<BTreeMap<String, String>, String> {
    let text = fs::read_to_string(root.join("tests/p16/abi-manifest.toml"))
        .map_err(|error| format!("P17 ABI manifest 不可讀：{error}"))?;
    let mut profiles = Vec::new();
    let mut active = None::<BTreeMap<String, String>>;
    for line in text.lines().map(str::trim) {
        if line == "[[profile]]" {
            if let Some(fields) = active.take() {
                profiles.push(fields);
            }
            active = Some(BTreeMap::new());
        } else if line.starts_with("[[") {
            if let Some(fields) = active.take() {
                profiles.push(fields);
            }
            break;
        } else if let Some(fields) = active.as_mut() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, quoted) = line
                .split_once('=')
                .ok_or("P17 ABI manifest profile 欄位格式錯誤")?;
            let value = quoted
                .trim()
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or("P17 ABI manifest profile 欄位須為字串")?;
            if fields
                .insert(key.trim().to_owned(), value.to_owned())
                .is_some()
            {
                return Err("P17 ABI manifest profile 重複欄位".into());
            }
        }
    }
    if let Some(fields) = active {
        profiles.push(fields);
    }
    if profiles.len() != 2 {
        return Err("P17 ABI manifest 必須有固定雙 profile".into());
    }
    profiles
        .into_iter()
        .find(|fields| fields.get("case_profile").map(String::as_str) == Some(profile.name))
        .ok_or_else(|| format!("P17 ABI manifest 缺 {}", profile.name))
}

pub(super) fn validate_abi_json(
    root: &Path,
    profile: Profile,
    body: &str,
) -> Result<ValidatedAbi, String> {
    if !body.ends_with('\n') || body.lines().count() != 1 {
        return Err("P17 C ABI JSON 必須是一行完整輸出".into());
    }
    let json = body.trim_end_matches('\n');
    let value = StrictJsonParser::parse(json)?;
    let StrictJsonValue::Object(ref entries) = value else {
        return Err("P17 C ABI JSON 根值非物件".into());
    };
    let fixed_keys = [
        "revision",
        "profile_id",
        "numeric_config",
        "pointer_width_bits",
        "endianness",
        "reserved_zero",
        "target",
        "header_set_sha256",
        "lua_h_sha256",
        "lauxlib_h_sha256",
        "luaconf_h_sha256",
        "layout",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if entries.len() != fixed_keys.len()
        || entries
            .iter()
            .any(|(name, _)| !fixed_keys.contains(name.as_str()))
    {
        return Err("P17 C ABI JSON 欄位集合不符".into());
    }
    let profile_id = if profile.name == "lua55-i64f64" {
        55
    } else {
        54
    };
    for (name, expected) in [
        ("revision", 1),
        ("profile_id", profile_id),
        ("numeric_config", 1),
        ("pointer_width_bits", 64),
        ("endianness", 1),
        ("reserved_zero", 0),
    ] {
        if number(&value, name)? != expected {
            return Err(format!("P17 C ABI JSON {name} 與固定身分不符"));
        }
    }
    if string(&value, "target")? != "aarch64-apple-darwin" {
        return Err("P17 C ABI JSON target 不符".into());
    }
    let metadata = manifest_headers(root, profile)?;
    let mut header_set = String::new();
    for (json_name, manifest_name, file_name) in [
        ("header_set_sha256", "header_set_sha256", None),
        ("lua_h_sha256", "lua_h_sha256", Some("lua.h")),
        ("lauxlib_h_sha256", "lauxlib_h_sha256", Some("lauxlib.h")),
        ("luaconf_h_sha256", "luaconf_h_sha256", Some("luaconf.h")),
    ] {
        let observed = string(&value, json_name)?;
        let pinned = metadata
            .get(manifest_name)
            .ok_or_else(|| format!("P17 ABI manifest 缺 {manifest_name}"))?;
        if !lowercase_sha(observed) || observed != pinned {
            return Err(format!("P17 C ABI JSON {json_name} 與固定 manifest 不符"));
        }
        if let Some(file_name) = file_name {
            if manifest::sha256(&root.join(profile.header_dir).join(file_name))? != observed {
                return Err(format!("P17 C ABI JSON {json_name} 與 header bytes 不符"));
            }
        } else {
            header_set = observed.to_owned();
        }
    }
    let layout = field(&value, "layout")?
        .as_array()
        .ok_or("P17 C ABI JSON layout 非陣列")?;
    let expected = if profile_id == 55 {
        &LUA55_LAYOUT
    } else {
        &LUA54_LAYOUT
    };
    if layout.len() != expected.len()
        || layout.iter().zip(expected).any(|(entry, expected)| {
            entry.as_i32() != Some(*expected) || !(0..=u16::MAX as i32).contains(expected)
        })
    {
        return Err("P17 C ABI JSON 37 個 u16 layout 不符".into());
    }
    Ok(ValidatedAbi {
        json: json.to_owned(),
        header_set_sha256: header_set,
    })
}

pub(super) fn render(
    root: &Path,
    profile: Profile,
    abi: &ValidatedAbi,
    suite: &Path,
    modules: &[PathBuf; 5],
) -> Result<String, String> {
    let suite = fs::canonicalize(suite).map_err(|error| error.to_string())?;
    let mut canonical = Vec::new();
    for (index, &(name, _)) in manifest::MODULES.iter().enumerate() {
        let expected = suite.join("libs").join(name);
        if modules[index] != expected {
            return Err(format!("P17 grant module 路徑不符：{name}"));
        }
        canonical.push(fs::canonicalize(&expected).map_err(|error| error.to_string())?);
        if canonical[index] != expected {
            return Err(format!("P17 grant module 不是獨立檔案：{name}"));
        }
    }
    let mut entries = Vec::new();
    for (index, &(_, source)) in manifest::MODULES.iter().enumerate() {
        let exports: &[&str] = match index {
            0 => &[
                "luaopen_lib1_sub",
                "lib1_export",
                "onefunction",
                "anotherfunc",
            ],
            1 => &["luaopen_lib11"],
            2 => &["luaopen_lib2"],
            3 => &["luaopen_lib21"],
            4 => &["luaopen_lib2"],
            _ => unreachable!(),
        };
        let dependencies: Vec<String> = match index {
            1 => vec![q(&canonical[0].display().to_string())],
            3 => vec![q(&canonical[2].display().to_string())],
            _ => Vec::new(),
        };
        let source = root.join(profile.suite).join("libs").join(source);
        entries.push(format!(
            "{{\"canonical_path\":{},\"sha256\":{},\"source_sha256\":{},\"header_binding\":{},\"abi_identity\":{},\"unwind\":\"CNoUnwind\",\"exports\":[{}],\"visibility\":{},\"dependencies\":[{}]}}",
            q(&canonical[index].display().to_string()),
            q(&manifest::sha256(&canonical[index])?),
            q(&manifest::sha256(&source)?),
            q(&abi.header_set_sha256),
            abi.json,
            exports.iter().map(|export| q(export)).collect::<Vec<_>>().join(","),
            q(if index == 0 || index == 2 { "global" } else { "local" }),
            dependencies.join(",")
        ));
    }
    let cpath = suite.join("libs/?.so");
    Ok(format!(
        "{{\"schema\":\"rivetlua-native-grant-v1\",\"profile\":{},\"target\":\"aarch64-apple-darwin\",\"abi_manifest_sha256\":{},\"capability\":\"trusted-host-process-permissions-v1\",\"cpath\":[{}],\"modules\":[{}]}}\n",
        q(profile.name),
        q(&manifest::sha256(
            &root.join("tests/p16/abi-manifest.toml")
        )?),
        q(&cpath.display().to_string()),
        entries.join(",")
    ))
}

pub(super) fn write(
    root: &Path,
    profile: Profile,
    abi: &ValidatedAbi,
    suite: &Path,
    modules: &[PathBuf; 5],
    path: &Path,
) -> Result<(), String> {
    let text = render(root, profile, abi, suite, modules)?;
    fs::write(path, text).map_err(|error| format!("P17 grant 寫入失敗：{error}"))?;
    validate_file(root, profile, abi, suite, modules, path)
}

pub(super) fn validate_file(
    root: &Path,
    profile: Profile,
    abi: &ValidatedAbi,
    suite: &Path,
    modules: &[PathBuf; 5],
    path: &Path,
) -> Result<(), String> {
    if path.file_name().and_then(|name| name.to_str()) != Some("p17-native-grant.json")
        || !path.is_absolute()
    {
        return Err("P17 grant 絕對檔名不符".into());
    }
    let actual = fs::read_to_string(path).map_err(|error| error.to_string())?;
    if actual.len() > 1024 * 1024 || actual != render(root, profile, abi, suite, modules)? {
        return Err("P17 grant schema、模組、SHA 或 ABI 身分不符".into());
    }
    StrictJsonParser::parse(&actual)?;
    Ok(())
}

pub(super) fn rejected_variant(
    original: &str,
    profile: Profile,
    label: &str,
    first_module: &Path,
    first_sha256: &str,
    abi_manifest_sha256: &str,
) -> Result<String, String> {
    let zeros = "0".repeat(64);
    let (before, after) = match label {
        "wrong-profile" => (
            format!("\"profile\":{},\"target\":", q(profile.name)),
            format!(
                "\"profile\":{},\"target\":",
                q(if profile.name == "lua55-i64f64" {
                    "lua54-i64f64"
                } else {
                    "lua55-i64f64"
                })
            ),
        ),
        "wrong-target" => (
            "\"target\":\"aarch64-apple-darwin\",\"abi_manifest_sha256\":".into(),
            "\"target\":\"wrong-target\",\"abi_manifest_sha256\":".into(),
        ),
        "wrong-abi" => (
            format!("\"abi_manifest_sha256\":{}", q(abi_manifest_sha256)),
            format!("\"abi_manifest_sha256\":{}", q(&zeros)),
        ),
        "wrong-hash" => (
            format!(
                "\"canonical_path\":{},\"sha256\":{}",
                q(&first_module.display().to_string()),
                q(first_sha256)
            ),
            format!(
                "\"canonical_path\":{},\"sha256\":{}",
                q(&first_module.display().to_string()),
                q(&zeros)
            ),
        ),
        _ => return Err("P17 native negative label 不在固定清單".into()),
    };
    if before == after || original.matches(before.as_str()).count() != 1 {
        return Err(format!("P17 {label} grant 唯一 mutation 錨點不符"));
    }
    Ok(original.replacen(before.as_str(), after.as_str(), 1))
}

#[cfg(test)]
mod tests {
    use super::{LUA54_LAYOUT, LUA55_LAYOUT, manifest_headers, validate_abi_json};
    use crate::p17::manifest::{self, Profile};
    use std::path::Path;

    fn example(root: &Path, profile: Profile) -> String {
        let fields = manifest_headers(root, profile).unwrap();
        let layout = if profile.name == "lua55-i64f64" {
            &LUA55_LAYOUT
        } else {
            &LUA54_LAYOUT
        };
        format!(
            "{{\"revision\":1,\"profile_id\":{},\"numeric_config\":1,\"pointer_width_bits\":64,\"endianness\":1,\"reserved_zero\":0,\"target\":\"aarch64-apple-darwin\",\"header_set_sha256\":\"{}\",\"lua_h_sha256\":\"{}\",\"lauxlib_h_sha256\":\"{}\",\"luaconf_h_sha256\":\"{}\",\"layout\":[{}]}}\n",
            if profile.name == "lua55-i64f64" {
                55
            } else {
                54
            },
            fields["header_set_sha256"],
            fields["lua_h_sha256"],
            fields["lauxlib_h_sha256"],
            fields["luaconf_h_sha256"],
            layout
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    #[test]
    fn p17_c_abi_json_checks_all_fields_headers_and_37_layout_entries() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for profile in manifest::PROFILES {
            let valid = example(root, profile);
            validate_abi_json(root, profile, &valid).unwrap();
            let bad_profile = valid.replacen(
                &format!(
                    "\"profile_id\":{}",
                    if profile.name == "lua55-i64f64" {
                        55
                    } else {
                        54
                    }
                ),
                "\"profile_id\":99",
                1,
            );
            assert!(validate_abi_json(root, profile, &bad_profile).is_err());
            let bad_sha = valid.replacen("\"lua_h_sha256\":\"", "\"lua_h_sha256\":\"0", 1);
            assert!(validate_abi_json(root, profile, &bad_sha).is_err());
            let bad_layout = valid.replacen("\"layout\":[8,", "\"layout\":[9,", 1);
            assert!(validate_abi_json(root, profile, &bad_layout).is_err());
            assert!(validate_abi_json(root, profile, &format!("{valid}\n")).is_err());
        }
    }
}
