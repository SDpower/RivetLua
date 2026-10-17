//! P21 runtime-only 產品稽核：只讀取呼叫者提供的檔案，不啟動工具鏈。

mod matrix;
mod resources;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_ARTIFACT: u64 = 256 * 1024 * 1024;
const MAX_GRAPH: u64 = 1024 * 1024;
const MAX_MEMBERS: usize = 16_384;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_SYMBOL_NAME: usize = 4096;

#[derive(Default)]
struct Sections {
    text: u64,
    readonly: u64,
    writable: u64,
    zerofill: u64,
}

struct Audit {
    sections: Sections,
    symbols: usize,
    forbidden_symbols: BTreeSet<String>,
    no_std: bool,
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("matrix") {
        return matrix::run(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("resources") {
        return resources::run(&args[1..]);
    }
    let [
        command,
        artifact_flag,
        artifact,
        dependencies_flag,
        dependencies,
        target_flag,
        target,
    ] = args
    else {
        return Err("用法：platform runtime-audit --artifact <rlib> --dependencies <cargo-tree-text> --target <triple>".into());
    };
    if command != "runtime-audit"
        || artifact_flag != "--artifact"
        || dependencies_flag != "--dependencies"
        || target_flag != "--target"
    {
        return Err("runtime-audit 參數順序或名稱不符".into());
    }
    let no_std = match target.as_str() {
        "aarch64-apple-darwin" => false,
        "thumbv7em-none-eabi" => true,
        _ => return Err(format!("不支援的 runtime-audit target：{target}")),
    };
    let graph = read_bounded(Path::new(dependencies), MAX_GRAPH)?;
    let packages = parse_packages(&graph)?;
    let forbidden_dependencies: Vec<_> = packages
        .iter()
        .filter(|package| forbidden_package(package.split_once(' ').unwrap().0))
        .cloned()
        .collect();
    let bytes = read_bounded(Path::new(artifact), MAX_ARTIFACT)?;
    let mut audit = Audit {
        sections: Sections::default(),
        symbols: 0,
        forbidden_symbols: BTreeSet::new(),
        no_std,
    };
    scan_archive(&bytes, target, &mut audit)?;
    let package_json = json_array(packages.iter().map(String::as_str));
    let dependency_json = json_array(forbidden_dependencies.iter().map(String::as_str));
    let symbol_json = json_array(audit.forbidden_symbols.iter().map(String::as_str));
    let object_validation = if no_std {
        "ELF32 LE ARM REL"
    } else {
        "Mach-O64 AArch64 MH_OBJECT"
    };
    println!(
        "{{\"version\":1,\"target\":\"{}\",\"object_validation\":\"{}\",\"artifact_bytes\":{},\"dependency_source\":\"supplied normal graph\",\"dependency_packages\":{},\"symbols_scanned\":{},\"forbidden_dependencies\":{},\"forbidden_symbols\":{},\"object_sections\":{{\"text\":{},\"readonly\":{},\"writable\":{},\"zerofill\":{}}}}}",
        super::json_escape(target),
        object_validation,
        bytes.len(),
        package_json,
        audit.symbols,
        dependency_json,
        symbol_json,
        audit.sections.text,
        audit.sections.readonly,
        audit.sections.writable,
        audit.sections.zerofill
    );
    if !forbidden_dependencies.is_empty() || !audit.forbidden_symbols.is_empty() {
        return Err("runtime-only 稽核發現禁止依賴或符號".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("無法讀取 {}：{error}", path.display()))?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(format!(
            "輸入路徑必須是一般檔案且不得為 symlink：{}",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|error| format!("無法讀取 {}：{error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("無法讀取 {}：{error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(format!("輸入檔不是有界一般檔案：{}", path.display()));
    }
    let mut bytes = Vec::new();
    let mut reader = file.take(limit + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("無法讀取 {}：{error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("輸入檔在讀取期間變為空或超過上限".into());
    }
    Ok(bytes)
}

fn parse_packages(bytes: &[u8]) -> Result<BTreeSet<String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "normal dependency graph 不是 UTF-8")?;
    let mut packages = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let name = fields
            .next()
            .ok_or("normal dependency graph 缺 package 名稱")?;
        let version = fields.next().ok_or("normal dependency graph 缺版本")?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || !version.starts_with('v')
            || version.len() < 2
            || !version[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
        {
            return Err(format!("normal dependency graph 格式不符：{line}"));
        }
        packages.insert(format!("{name} {version}"));
        if packages.len() > 4096 {
            return Err("normal dependency graph package 數量超限".into());
        }
    }
    if packages.is_empty()
        || !packages
            .iter()
            .any(|item| item.starts_with("rivetlua-runtime v"))
        || !packages
            .iter()
            .any(|item| item.starts_with("rivetlua-core v"))
    {
        return Err("normal dependency graph 缺 rivetlua-runtime/core 或為空".into());
    }
    Ok(packages)
}

fn forbidden_package(name: &str) -> bool {
    name == "rivetlua-compiler"
        || name == "cranelift"
        || name.starts_with("cranelift-")
        || name == "wasmtime"
        || name.starts_with("wasmtime-")
        || matches!(
            name,
            "reqwest"
                | "hyper"
                | "ureq"
                | "curl"
                | "tokio"
                | "mio"
                | "socket2"
                | "rustls"
                | "quinn"
                | "tonic"
                | "axum"
                | "warp"
                | "tungstenite"
                | "ort"
                | "onnxruntime"
                | "tch"
                | "burn"
                | "tokenizers"
                | "hf-hub"
        )
        || name.starts_with("candle-")
        || name.starts_with("llama-cpp-")
        || name.starts_with("rivetlua-model")
}

fn json_array<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut result = String::from("[");
    for (index, value) in values.enumerate() {
        if index > 0 {
            result.push(',');
        }
        result.push('"');
        result.push_str(&super::json_escape(value));
        result.push('"');
    }
    result.push(']');
    result
}

fn scan_archive(bytes: &[u8], target: &str, audit: &mut Audit) -> Result<(), String> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err("artifact 不是標準 ar archive".into());
    }
    let mut cursor = 8usize;
    let mut members = 0usize;
    let mut objects = 0usize;
    let mut long_names: &[u8] = &[];
    while cursor < bytes.len() {
        members += 1;
        if members > MAX_MEMBERS {
            return Err("ar member 數量超限".into());
        }
        let header = slice(bytes, cursor, 60)?;
        if &header[58..60] != b"`\n" {
            return Err("ar header 尾碼錯誤".into());
        }
        let raw_name = std::str::from_utf8(&header[..16])
            .map_err(|_| "ar name 不是 ASCII")?
            .trim();
        let size_text = std::str::from_utf8(&header[48..58])
            .map_err(|_| "ar size 不是 ASCII")?
            .trim();
        let size = size_text
            .parse::<usize>()
            .map_err(|_| "ar member size 不合法")?;
        let start = cursor.checked_add(60).ok_or("ar offset 溢位")?;
        let mut body = slice(bytes, start, size)?;
        let name = if let Some(length) = raw_name.strip_prefix("#1/") {
            let length = length
                .parse::<usize>()
                .map_err(|_| "BSD ar name 長度錯誤")?;
            let name = std::str::from_utf8(body.get(..length).ok_or("BSD ar name 截斷")?)
                .map_err(|_| "BSD ar name 不是 UTF-8")?
                .trim_end_matches('\0')
                .to_owned();
            body = &body[length..];
            name
        } else if raw_name == "//" {
            long_names = body;
            String::new()
        } else if raw_name.starts_with('/') && raw_name != "/" && raw_name != "/SYM64/" {
            let offset = raw_name[1..]
                .parse::<usize>()
                .map_err(|_| "GNU ar name offset 錯誤")?;
            let rest = long_names.get(offset..).ok_or("GNU ar name 缺長名表")?;
            let end = rest
                .iter()
                .position(|&byte| byte == b'\n')
                .ok_or("GNU ar name 未結束")?;
            std::str::from_utf8(&rest[..end])
                .map_err(|_| "GNU ar name 非 UTF-8")?
                .trim_end_matches('/')
                .to_owned()
        } else {
            raw_name.trim_end_matches('/').to_owned()
        };
        if raw_name != "//"
            && raw_name != "/"
            && raw_name != "/SYM64/"
            && !name.starts_with("__.SYMDEF")
            && !name.ends_with(".rmeta")
        {
            if name.is_empty() {
                return Err("ar object name 為空".into());
            }
            match target {
                "aarch64-apple-darwin" => scan_mach_object(body, audit)?,
                "thumbv7em-none-eabi" => scan_elf32_object(body, audit)?,
                _ => return Err("不支援的 object target".into()),
            }
            objects += 1;
        }
        cursor = start
            .checked_add(size)
            .and_then(|end| end.checked_add(size & 1))
            .ok_or("ar offset 溢位")?;
        if cursor > bytes.len() || (size & 1 == 1 && bytes[cursor - 1] != b'\n') {
            return Err("ar padding 錯誤".into());
        }
    }
    if cursor != bytes.len() || objects == 0 || audit.symbols == 0 {
        return Err("ar 無 object、非 debug symbols 或尾端不完整".into());
    }
    Ok(())
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    let end = offset.checked_add(length).ok_or("檔案範圍溢位")?;
    bytes.get(offset..end).ok_or_else(|| "檔案範圍截斷".into())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = slice(bytes, offset, 8)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| "u64 截斷")?,
    ))
}

fn add_size(total: &mut u64, size: u64) -> Result<(), String> {
    *total = total.checked_add(size).ok_or("section 容量溢位")?;
    Ok(())
}

fn scan_symbol(name: &str, audit: &mut Audit) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_SYMBOL_NAME {
        return Err("object symbol name 不合法".into());
    }
    audit.symbols = audit.symbols.checked_add(1).ok_or("symbol count 溢位")?;
    if audit.symbols > MAX_SYMBOLS {
        return Err("symbol count 超限".into());
    }
    let lower = name.to_ascii_lowercase();
    let forbidden = lower.contains("rivetlua_compiler")
        || lower.contains("cranelift")
        || lower.contains("wasmtime")
        || lower.contains("rivetlua_model")
        || [
            "reqwest",
            "hyper",
            "ureq",
            "curl",
            "tokio",
            "socket2",
            "rustls",
            "quinn",
            "tonic",
            "axum",
            "tungstenite",
            "candle",
            "onnxruntime",
            "tokenizers",
            "hf_hub",
        ]
        .iter()
        .any(|token| lower.contains(token))
        || (audit.no_std
            && (lower.contains("_zn3std") || lower.contains("::std::") || lower.contains("3std")));
    if forbidden {
        audit.forbidden_symbols.insert(name.to_owned());
        if audit.forbidden_symbols.len() > 256 {
            return Err("禁止符號數量超限".into());
        }
    }
    Ok(())
}

fn symbol_name(table: &[u8], offset: usize) -> Result<&str, String> {
    let rest = table.get(offset..).ok_or("symbol string offset 超界")?;
    let end = rest
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("symbol string 未終止")?;
    if end > MAX_SYMBOL_NAME {
        return Err("symbol name 過長".into());
    }
    std::str::from_utf8(&rest[..end]).map_err(|_| "symbol name 不是 UTF-8".into())
}

fn scan_mach_object(object: &[u8], audit: &mut Audit) -> Result<(), String> {
    if slice(object, 0, 4)? != [0xcf, 0xfa, 0xed, 0xfe].as_slice()
        || u32_at(object, 4)? != 0x0100_000c
        || u32_at(object, 12)? != 1
    {
        return Err("object 不是 AArch64 Mach-O64 MH_OBJECT".into());
    }
    slice(object, 0, 32)?;
    let commands = u32_at(object, 16)? as usize;
    let command_bytes = u32_at(object, 20)? as usize;
    if commands == 0 || commands > 4096 {
        return Err("Mach-O load command 數量不合法".into());
    }
    let command_end = 32usize
        .checked_add(command_bytes)
        .ok_or("Mach-O command 長度溢位")?;
    slice(object, 32, command_bytes)?;
    let mut cursor = 32usize;
    let mut symtab = None;
    let mut section_count = 0usize;
    for _ in 0..commands {
        let command = u32_at(object, cursor)?;
        let size = u32_at(object, cursor + 4)? as usize;
        if size < 8 || cursor.checked_add(size).is_none_or(|end| end > command_end) {
            return Err("Mach-O load command 截斷".into());
        }
        if command == 2 {
            if size < 24 || symtab.is_some() {
                return Err("Mach-O SYMTAB 不完整或重複".into());
            }
            symtab = Some((
                u32_at(object, cursor + 8)? as usize,
                u32_at(object, cursor + 12)? as usize,
                u32_at(object, cursor + 16)? as usize,
                u32_at(object, cursor + 20)? as usize,
            ));
        } else if command == 0x19 {
            if size < 72 {
                return Err("Mach-O segment command 截斷".into());
            }
            let sections = u32_at(object, cursor + 64)? as usize;
            let section_bytes = sections.checked_mul(80).ok_or("Mach-O section 數量溢位")?;
            if sections > 4096
                || 72usize
                    .checked_add(section_bytes)
                    .is_none_or(|need| need > size)
            {
                return Err("Mach-O section table 截斷".into());
            }
            for index in 0..sections {
                let start = cursor + 72 + index * 80;
                let section = slice(object, start, 80)?;
                let segment_name = c_name(&section[16..32])?;
                let length = u64_at(section, 40)?;
                let file_offset = u32_at(section, 48)? as usize;
                let flags = u32_at(section, 64)?;
                let zero_fill = matches!(flags & 0xff, 1 | 0x0c | 0x12);
                if !zero_fill {
                    let length = usize::try_from(length).map_err(|_| "Mach-O section size 超界")?;
                    slice(object, file_offset, length)?;
                }
                section_count = section_count
                    .checked_add(1)
                    .ok_or("Mach-O section count 溢位")?;
                if segment_name == "__DWARF" {
                    continue;
                }
                let destination = if zero_fill {
                    &mut audit.sections.zerofill
                } else if flags & 0x8000_0400 != 0 || c_name(&section[..16])? == "__text" {
                    &mut audit.sections.text
                } else if segment_name == "__TEXT" {
                    &mut audit.sections.readonly
                } else {
                    &mut audit.sections.writable
                };
                add_size(destination, length)?;
            }
        }
        cursor += size;
    }
    if cursor != command_end || section_count == 0 {
        return Err("Mach-O section/command 不完整".into());
    }
    let (symbol_offset, symbol_count, string_offset, string_size) =
        symtab.ok_or("Mach-O 缺 SYMTAB")?;
    if symbol_count > MAX_SYMBOLS {
        return Err("Mach-O symbol count 不合法".into());
    }
    let symbol_bytes = symbol_count
        .checked_mul(16)
        .ok_or("Mach-O symbol table 溢位")?;
    let symbols = slice(object, symbol_offset, symbol_bytes)?;
    let strings = slice(object, string_offset, string_size)?;
    for index in 0..symbol_count {
        let symbol = &symbols[index * 16..(index + 1) * 16];
        if symbol[4] & 0xe0 != 0 {
            continue;
        }
        let name_offset = u32_at(symbol, 0)? as usize;
        if name_offset == 0 {
            continue;
        }
        let name = symbol_name(strings, name_offset)?;
        if !name.is_empty() {
            scan_symbol(name, audit)?;
        }
    }
    Ok(())
}

fn c_name(bytes: &[u8]) -> Result<&str, String> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).map_err(|_| "Mach-O section name 不是 UTF-8".into())
}

fn scan_elf32_object(object: &[u8], audit: &mut Audit) -> Result<(), String> {
    // shortcut: 尚未解析 .ARM.attributes；若要證明 Thumb v7EM CPU，須另行比對該屬性。
    let ident = slice(object, 0, 16)?;
    if &ident[..4] != b"\x7fELF".as_slice()
        || ident[4] != 1
        || ident[5] != 1
        || ident[6] != 1
        || u16_at(object, 16)? != 1
        || u16_at(object, 18)? != 40
        || u32_at(object, 20)? != 1
    {
        return Err("object 不是 ARM ELF32 LE REL".into());
    }
    slice(object, 0, 52)?;
    let section_offset = u32_at(object, 32)? as usize;
    let section_size = u16_at(object, 46)? as usize;
    let section_count = u16_at(object, 48)? as usize;
    if section_size != 40 || section_count == 0 || section_count > 8192 {
        return Err("ELF32 section table 規格不符".into());
    }
    let table_bytes = section_count
        .checked_mul(section_size)
        .ok_or("ELF section table 溢位")?;
    let table = slice(object, section_offset, table_bytes)?;
    let mut found_symtab = false;
    for index in 0..section_count {
        let section = &table[index * 40..(index + 1) * 40];
        let kind = u32_at(section, 4)?;
        let flags = u32_at(section, 8)?;
        let offset = u32_at(section, 16)? as usize;
        let size = u32_at(section, 20)? as usize;
        if kind != 8 {
            slice(object, offset, size)?;
        }
        if flags & 2 != 0 {
            let destination = if kind == 8 {
                &mut audit.sections.zerofill
            } else if flags & 4 != 0 {
                &mut audit.sections.text
            } else if flags & 1 != 0 {
                &mut audit.sections.writable
            } else {
                &mut audit.sections.readonly
            };
            add_size(destination, size as u64)?;
        }
        if kind != 2 {
            continue;
        }
        if found_symtab {
            return Err("ELF32 重複 SYMTAB".into());
        }
        found_symtab = true;
        let link = u32_at(section, 24)? as usize;
        let entry_size = u32_at(section, 36)? as usize;
        if link >= section_count || entry_size != 16 || size % 16 != 0 || size / 16 > MAX_SYMBOLS {
            return Err("ELF32 SYMTAB 長度或 strtab link 錯誤".into());
        }
        let string_section = &table[link * 40..(link + 1) * 40];
        if u32_at(string_section, 4)? != 3 {
            return Err("ELF32 SYMTAB 未連到 STRTAB".into());
        }
        let strings = slice(
            object,
            u32_at(string_section, 16)? as usize,
            u32_at(string_section, 20)? as usize,
        )?;
        let symbols = slice(object, offset, size)?;
        for symbol in symbols.chunks_exact(16) {
            let symbol_kind = symbol[12] & 0x0f;
            if matches!(symbol_kind, 3 | 4) {
                continue;
            }
            let name_offset = u32_at(symbol, 0)? as usize;
            if name_offset == 0 {
                continue;
            }
            let name = symbol_name(strings, name_offset)?;
            if !name.is_empty() {
                scan_symbol(name, audit)?;
            }
        }
    }
    if !found_symtab {
        return Err("ELF32 缺 SYMTAB".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn truncated_archive_member_is_rejected() {
        let mut audit = super::Audit {
            sections: super::Sections::default(),
            symbols: 0,
            forbidden_symbols: Default::default(),
            no_std: false,
        };
        assert!(
            super::scan_archive(b"!<arch>\nshort", "aarch64-apple-darwin", &mut audit).is_err()
        );
    }
}
