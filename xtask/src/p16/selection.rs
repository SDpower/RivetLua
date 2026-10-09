use super::manifest::Row;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Definition {
    pub header: String,
    pub line: usize,
    pub text: String,
}

pub(super) struct Snapshot {
    pub command: Vec<String>,
    pub output: String,
    active: HashMap<String, Definition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Applicability {
    Selected(Definition),
    Excluded(Definition),
    Undefined,
}

pub(super) fn verify_macro_output(profile: &str, log: &str) -> Result<(), String> {
    if profile != "lua54" {
        return Ok(());
    }
    let expected =
        "P16_WRITE_STRING\nP16_MACRO lua_writestring PASS\n\nP16_MACRO lua_writeline PASS\n";
    if log.matches(expected).count() != 1
        || log
            .lines()
            .filter(|line| *line == "P16_WRITE_STRING")
            .count()
            != 1
        || log
            .lines()
            .filter(|line| *line == "P16_WRITE_ERROR:42")
            .count()
            != 1
    {
        return Err("P16 lua54 輸出巨集缺固定字串、空行或錯誤輸出效果".into());
    }
    Ok(())
}

impl Applicability {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Selected(_) => "selected-effect",
            Self::Excluded(_) => "excluded-guard",
            Self::Undefined => "undefined-internal",
        }
    }

    pub(super) fn active(&self) -> Option<&Definition> {
        match self {
            Self::Selected(definition) | Self::Excluded(definition) => Some(definition),
            Self::Undefined => None,
        }
    }
}

pub(super) fn source(root: &Path) -> PathBuf {
    root.join("tests/p16/acceptance/header_selection.c")
}

pub(super) fn command(root: &Path, profile: &str) -> Result<Vec<String>, String> {
    if !matches!(profile, "lua54" | "lua55") {
        return Err("P16 HeaderSelection profile 無效".into());
    }
    let mut argv = vec![
        "cc".into(),
        "-std=c11".into(),
        "-E".into(),
        "-dD".into(),
        "-x".into(),
        "c".into(),
        format!(
            "-I{}",
            root.join(format!("include/rivetlua/{profile}")).display()
        ),
        format!("-I{}", root.join("include/rivetlua").display()),
    ];
    if profile == "lua54" {
        argv.push("-DLUA_COMPAT_5_3".into());
    } else {
        argv.push("-DLUA_COMPAT_APIINTCASTS".into());
    }
    argv.push(source(root).display().to_string());
    Ok(argv)
}

fn marker(line: &str) -> Option<(usize, &str)> {
    let rest = line.strip_prefix("# ")?;
    let (number, tail) = rest.split_once(' ')?;
    let number = number.parse().ok()?;
    let tail = tail.strip_prefix('"')?;
    let (path, _) = tail.split_once('"')?;
    Some((number, path))
}

fn macro_name(line: &str, directive: &str) -> Option<String> {
    let body = line.strip_prefix(directive)?;
    let name = body
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if name == 0 {
        return None;
    }
    Some(body[..name].to_owned())
}

pub(super) fn parse(root: &Path, profile: &str, output: &str) -> Result<Snapshot, String> {
    let header_dir = root.join(format!("include/rivetlua/{profile}"));
    let canonical = fs::canonicalize(&header_dir)
        .map_err(|error| format!("P16 HeaderSelection include 不可讀：{error}"))?;
    let mut active = HashMap::new();
    let mut file = String::new();
    let mut line_number = 0usize;
    for line in output.lines() {
        if let Some((number, path)) = marker(line) {
            file = path.to_owned();
            line_number = number;
            continue;
        }
        let header = fs::canonicalize(&file).ok().and_then(|path| {
            path.strip_prefix(&canonical)
                .ok()
                .and_then(|name| name.to_str().map(str::to_owned))
        });
        if let Some(name) = macro_name(line, "#define ") {
            if let Some(header) = header {
                active.insert(
                    name,
                    Definition {
                        header,
                        line: line_number,
                        text: line.to_owned(),
                    },
                );
            } else {
                active.remove(&name);
            }
        } else if let Some(name) = macro_name(line, "#undef ") {
            active.remove(&name);
        }
        line_number = line_number.saturating_add(1);
    }
    Ok(Snapshot {
        command: command(root, profile)?,
        output: output.into(),
        active,
    })
}

pub(super) fn capture(root: &Path, profile: &str) -> Result<Snapshot, String> {
    let argv = command(root, profile)?;
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(root)
        .output()
        .map_err(|error| format!("P16 HeaderSelection 預處理無法啟動：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "P16 HeaderSelection 預處理 exit={:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "P16 HeaderSelection 輸出非 UTF-8")?;
    parse(root, profile, &text)
}

pub(super) fn classify(snapshot: &Snapshot, row: &Row) -> Result<Applicability, String> {
    if row.status != "HEADER_ONLY" || !matches!(row.kind.as_str(), "macro" | "constant") {
        return Err("P16 HeaderSelection 僅適用 header 定義列".into());
    }
    let fields = row.id.split(':').collect::<Vec<_>>();
    if fields.len() != 5
        || fields[0] != row.profile
        || fields[2] != row.kind
        || fields[3] != row.name
    {
        return Err("P16 HeaderSelection row ID 不符".into());
    }
    let expected_line = fields[4]
        .parse::<usize>()
        .map_err(|_| "P16 HeaderSelection row line 無效")?;
    let Some(active) = snapshot.active.get(&row.name) else {
        return Ok(Applicability::Undefined);
    };
    if active.header == fields[1] && active.line == expected_line {
        Ok(Applicability::Selected(active.clone()))
    } else {
        Ok(Applicability::Excluded(active.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_selection_preprocessor_uses_fixed_c11_for_both_profiles() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for profile in ["lua54", "lua55"] {
            let argv = command(root, profile).unwrap();
            assert_eq!(&argv[..5], ["cc", "-std=c11", "-E", "-dD", "-x"]);
            assert_eq!(
                argv.iter().filter(|arg| arg.as_str() == "-std=c11").count(),
                1
            );
            assert_eq!(argv.last().unwrap(), &source(root).display().to_string());
        }
    }

    #[test]
    fn p16_lua54_output_macros_require_bytes_and_blank_line() {
        let good = "P16_WRITE_STRING\nP16_MACRO lua_writestring PASS\n\nP16_MACRO lua_writeline PASS\nP16_MACRO lua_writestringerror PASS\nP16_WRITE_ERROR:42\n";
        assert!(verify_macro_output("lua54", good).is_ok());
        for bad in [
            good.replace("P16_WRITE_STRING\n", ""),
            good.replace(
                "PASS\n\nP16_MACRO lua_writeline",
                "PASS\nP16_MACRO lua_writeline",
            ),
            good.replace("P16_WRITE_ERROR:42", "P16_WRITE_ERROR:24"),
            format!("{good}P16_WRITE_ERROR:42\n"),
        ] {
            assert!(verify_macro_output("lua54", &bad).is_err());
        }
    }

    #[test]
    fn p16_header_selection_tracks_final_source_line_and_undef() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let header = root.join("include/rivetlua/lua54/lauxlib.h");
        let output = format!(
            "# 176 \"{}\"\n#define lua_assert(c) assert(c)\n# 178 \"{}\"\n#define lua_assert(c) ((void)0)\n#undef absent\n",
            header.display(),
            header.display()
        );
        let snapshot = parse(root, "lua54", &output).unwrap();
        let row = Row {
            id: "lua54:lauxlib.h:macro:lua_assert:176".into(),
            profile: "lua54".into(),
            kind: "macro".into(),
            name: "lua_assert".into(),
            definition: "#define lua_assert(c) assert(c)".into(),
            status: "HEADER_ONLY".into(),
            condition: "#if LUAI_ASSERT".into(),
            evidence: String::new(),
            mapping: String::new(),
            p17_use: String::new(),
        };
        assert_eq!(
            classify(&snapshot, &row).unwrap().as_str(),
            "excluded-guard"
        );
        let mut selected = row.clone();
        selected.id = "lua54:lauxlib.h:macro:lua_assert:178".into();
        assert_eq!(
            classify(&snapshot, &selected).unwrap().as_str(),
            "selected-effect"
        );
        let mut undefined = row;
        undefined.name = "absent".into();
        undefined.id = "lua54:lauxlib.h:macro:absent:180".into();
        assert_eq!(
            classify(&snapshot, &undefined).unwrap().as_str(),
            "undefined-internal"
        );
    }
}
