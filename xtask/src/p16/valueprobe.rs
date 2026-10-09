use super::manifest::{Manifest, Row};
use super::rowproof::needs_value;
use super::selection::{self, Applicability, Snapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(super) fn source(root: &Path) -> PathBuf {
    root.join("tests/p16/acceptance/header_values.c")
}

pub(super) fn vendor_dir(root: &Path, profile: &str) -> Result<PathBuf, String> {
    let release = match profile {
        "lua54" => "5.4.9",
        "lua55" => "5.5.1",
        _ => return Err("P16 value probe profile 無效".into()),
    };
    Ok(root.join(format!("vendor/{profile}/lua-{release}/src")))
}

pub(super) fn verify_vendor(root: &Path, manifest: &Manifest, profile: &str) -> Result<(), String> {
    let dir = vendor_dir(root, profile)?;
    let files = manifest
        .header_files
        .get(profile)
        .ok_or("P16 official header hashes 缺失")?;
    for name in ["lua.h", "lauxlib.h", "luaconf.h"] {
        let expected = files
            .get(name)
            .ok_or("P16 official header file hash 缺失")?;
        if super::sha_file(&dir.join(name))? != *expected {
            return Err(format!("P16 official {profile}/{name} source SHA-256 不符"));
        }
    }
    Ok(())
}

pub(super) fn command(
    root: &Path,
    profile: &str,
    official: bool,
    binary: &Path,
) -> Result<Vec<String>, String> {
    let include = if official {
        vendor_dir(root, profile)?
    } else {
        root.join(format!("include/rivetlua/{profile}"))
    };
    let mut argv = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        format!("-I{}", include.display()),
        format!("-I{}", root.join("include/rivetlua").display()),
    ];
    argv.push(
        if profile == "lua54" {
            "-DLUA_COMPAT_5_3"
        } else {
            "-DLUA_COMPAT_APIINTCASTS"
        }
        .into(),
    );
    argv.extend([
        source(root).display().to_string(),
        "-o".into(),
        binary.display().to_string(),
    ]);
    Ok(argv)
}

pub(super) fn expected(
    manifest: &Manifest,
    profile: &str,
    snapshot: &Snapshot,
) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for row in &manifest.rows {
        if row.profile == profile
            && row.status == "HEADER_ONLY"
            && needs_value(row)
            && (row.kind == "layout_field"
                || matches!(
                    selection::classify(snapshot, row)?,
                    Applicability::Selected(_)
                ))
        {
            names.insert(row.name.clone());
        }
    }
    Ok(names)
}

pub(super) fn observations(log: &str) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for line in log.lines().filter(|line| line.starts_with("P16_VALUE ")) {
        let mut parts = line.splitn(4, ' ');
        if parts.next() != Some("P16_VALUE") {
            return Err("P16 value probe marker 格式無效".into());
        }
        let name = parts.next().ok_or("P16 value probe 名稱缺失")?;
        let kind = parts.next().ok_or("P16 value probe 類型缺失")?;
        let value = parts.next().ok_or("P16 value probe 值缺失")?;
        let numbers = value.split(' ').collect::<Vec<_>>();
        let valid = match kind {
            "NUM" => value.parse::<i128>().is_ok(),
            "STR" => {
                value.len().is_multiple_of(2) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }
            "TYPE" => {
                numbers.len() == 3 && numbers.iter().all(|part| part.parse::<usize>().is_ok())
            }
            "LAYOUT" => {
                numbers.len() == 2 && numbers.iter().all(|part| part.parse::<usize>().is_ok())
            }
            "OFFSET" => {
                numbers.len() == 3
                    && numbers[0].parse::<usize>().is_ok()
                    && numbers[1] == "SIZE"
                    && numbers[2].parse::<usize>().is_ok()
            }
            _ => false,
        };
        if !valid
            || name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
            || values
                .insert(name.to_owned(), format!("{kind} {value}"))
                .is_some()
        {
            return Err("P16 value probe 重複或格式無效".into());
        }
    }
    Ok(values)
}

pub(super) fn row_value(row: &Row, log: &str) -> Result<String, String> {
    observations(log)?
        .remove(&row.name)
        .ok_or_else(|| format!("P16 value probe {} 缺逐值觀察", row.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_value_probe_preserves_string_bytes_and_rejects_duplicates() {
        let log = "P16_VALUE LUA_COPYRIGHT STR 2061\nP16_VALUE LUA_NUMBER_FRMLEN STR \nP16_VALUE LUA_OK NUM 0\n";
        let values = observations(log).unwrap();
        assert_eq!(values.get("LUA_COPYRIGHT").unwrap(), "STR 2061");
        assert_eq!(values.get("LUA_NUMBER_FRMLEN").unwrap(), "STR ");
        assert_ne!(values.get("LUA_COPYRIGHT").unwrap(), "STR 61");
        assert!(observations(&format!("{log}P16_VALUE LUA_OK NUM 0\n")).is_err());
        assert!(observations("P16_VALUE LUA_OK BAD 0\n").is_err());
        assert!(observations("P16_VALUE LUA_COPYRIGHT STR 2\n").is_err());
        assert!(observations("P16_VALUE  STR 20\n").is_err());
        assert!(observations("P16_VALUE LUA_COPYRIGHT STR\n").is_err());
        assert!(observations("P16_VALUE LUA_COPYRIGHT STR 206\n").is_err());
        assert!(observations("P16_VALUE LUA_COPYRIGHT STR 20zz\n").is_err());
        assert!(observations("P16_VALUE LUA_OK NUM \n").is_err());
        assert!(observations("P16_VALUE luaL_Reg.name OFFSET 0 BAD 8\n").is_err());
        assert!(observations("P16_VALUE LUA_NUMBER TYPE 8 8\n").is_err());
    }
}
