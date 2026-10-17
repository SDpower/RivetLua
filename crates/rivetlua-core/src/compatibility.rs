//! P19 固定版本的語言相容差異表。

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::LuaProfile;

pub const COMPATIBILITY_VERSION: u32 = 1;

const TABLE: &str = include_str!("../../../spec/p19-compatibility.csv");
const HEADER: &str = "area,lua55_rule,lua54_rule,source,case_id,status";
const AREAS: [&str; 8] = [
    "keywords",
    "declarations",
    "vararg",
    "loop",
    "stdlib",
    "c_api",
    "chunk",
    "cli",
];
const CASES: [(&str, &str); 9] = [
    ("PROF-001-KEYWORD-GLOBAL", "keywords"),
    ("PROF-002-DECL-GLOBAL", "declarations"),
    ("PROF-002-VARARG-NAMED", "vararg"),
    ("PROF-002-LOOP-READONLY", "loop"),
    ("PROF-002-STDLIB-TABLECREATE", "stdlib"),
    ("PROF-002-CAPI-OPENSELECTEDLIBS", "c_api"),
    ("PROF-002-CAPI-MAKESEED", "c_api"),
    ("PROF-006-CHUNK-PROFILE", "chunk"),
    ("PROF-006-CLI-PROFILE", "cli"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityEntry<'a> {
    pub area: &'a str,
    pub lua55_rule: &'a str,
    pub lua54_rule: &'a str,
    pub source: &'a str,
    pub case_id: &'a str,
    pub status: &'a str,
}

impl CompatibilityEntry<'_> {
    pub fn selected_rule(&self, profile: LuaProfile) -> &str {
        match profile {
            LuaProfile::Lua55 => self.lua55_rule,
            LuaProfile::Lua54 => self.lua54_rule,
        }
    }

    pub fn is_gap(&self) -> bool {
        self.status != "implemented"
    }
}

pub fn compatibility_entries() -> Result<Vec<CompatibilityEntry<'static>>, String> {
    parse_table(TABLE)
}

fn parse_table(contents: &str) -> Result<Vec<CompatibilityEntry<'_>>, String> {
    let mut lines = contents.lines();
    if lines.next() != Some(HEADER) {
        return Err("P19 compatibility table header 不符".into());
    }

    let mut ids = BTreeSet::new();
    let mut entries = Vec::new();
    for (index, line) in lines.enumerate() {
        let columns: Vec<_> = line.split(',').collect();
        if columns.len() != 6 || columns.iter().any(|field| field.trim().is_empty()) {
            return Err(format!(
                "P19 compatibility table 第 {} 列欄位不正確",
                index + 2
            ));
        }
        if !AREAS.contains(&columns[0]) {
            return Err(format!(
                "P19 compatibility table 第 {} 列 area 不合法",
                index + 2
            ));
        }
        if !matches!(columns[5], "specified" | "pending" | "implemented") {
            return Err(format!(
                "P19 compatibility table 第 {} 列 status 不合法",
                index + 2
            ));
        }
        let sources: Vec<_> = columns[3].split('|').collect();
        if sources.len() != 2
            || sources
                .iter()
                .any(|source| !source.starts_with("https://www.lua.org/"))
        {
            return Err(format!(
                "P19 compatibility table 第 {} 列 source 不合法",
                index + 2
            ));
        }
        if !ids.insert(columns[4]) {
            return Err(format!(
                "P19 compatibility table 有重複 case_id：{}",
                columns[4]
            ));
        }
        entries.push(CompatibilityEntry {
            area: columns[0],
            lua55_rule: columns[1],
            lua54_rule: columns[2],
            source: columns[3],
            case_id: columns[4],
            status: columns[5],
        });
    }
    if entries.len() != CASES.len()
        || CASES.iter().any(|(case_id, area)| {
            !entries
                .iter()
                .any(|entry| entry.case_id == *case_id && entry.area == *area)
        })
    {
        return Err("P19 compatibility table 未完整符合固定案例清單".into());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{TABLE, parse_table};

    #[test]
    fn compatibility_table_has_fixed_cases_and_rejects_bad_rows() {
        assert_eq!(parse_table(TABLE).unwrap().len(), 9);
        let duplicate = TABLE.replace("PROF-002-DECL-GLOBAL", "PROF-001-KEYWORD-GLOBAL");
        assert!(parse_table(&duplicate).is_err());
        let unknown_area = TABLE.replacen("keywords,", "unknown,", 1);
        assert!(parse_table(&unknown_area).is_err());
        let unknown_status = TABLE.replacen(",implemented\n", ",unknown\n", 1);
        assert!(parse_table(&unknown_status).is_err());
    }
}
