use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::installer::{safe_relative, source_file};
use crate::StrictJsonValue;

const MAX_PATCHES: usize = 64;
const MAX_PATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_PATCH_LINES: usize = 65_536;
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

fn patch_path(header: &str, prefix: &str) -> Result<PathBuf, String> {
    let header = header.strip_suffix('\n').unwrap_or(header);
    let header = header.strip_suffix('\r').unwrap_or(header);
    let path = header.split_once('\t').map_or(header, |(path, _)| path);
    if path.is_empty() || path.contains('"') || path.contains('\\') {
        return Err("patch 不支援引號或跳脫檔名".into());
    }
    let path = path.strip_prefix(prefix).unwrap_or(path);
    if path.contains("//") || path == "/dev/null" {
        return Err("patch 檔案路徑不安全或格式不支援".into());
    }
    safe_relative(path)
}

fn hunk_header(line: &str) -> Result<(usize, usize, usize, usize), String> {
    let body = line.strip_prefix("@@ -").ok_or("patch hunk header 無效")?;
    let (old, body) = body.split_once(" +").ok_or("patch hunk header 無效")?;
    let (new, _) = body.split_once(" @@").ok_or("patch hunk header 無效")?;
    fn range(value: &str) -> Result<(usize, usize), String> {
        let (start, count) = value.split_once(',').unwrap_or((value, "1"));
        let start = start.parse::<usize>().map_err(|_| "patch hunk 行號無效")?;
        let count = count.parse::<usize>().map_err(|_| "patch hunk 行數無效")?;
        if count > MAX_PATCH_LINES || (start == 0 && count != 0) { return Err("patch hunk 範圍無效".into()); }
        Ok((start, count))
    }
    let (old_start, old_count) = range(old)?;
    let (new_start, new_count) = range(new)?;
    Ok((old_start, old_count, new_start, new_count))
}

fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split_inclusive(|byte| *byte == b'\n').collect()
}

fn patch_line<'a>(all: &[&'a [u8]], index: &mut usize) -> Result<(u8, &'a [u8]), String> {
    let line = *all.get(*index).ok_or("patch hunk 未完整")?;
    let (&kind, body) = line.split_first().ok_or("patch hunk 空行無標記")?;
    if !matches!(kind, b' ' | b'-' | b'+') { return Err("patch hunk 行標記無效".into()); }
    *index += 1;
    let no_newline = all.get(*index).is_some_and(|line| line.starts_with(b"\\ No newline at end of file"));
    if no_newline {
        let marker = all[*index];
        if marker != b"\\ No newline at end of file\n" && marker != b"\\ No newline at end of file" {
            return Err("patch newline 標記無效".into());
        }
        *index += 1;
        let body = body.strip_suffix(b"\n").ok_or("patch newline 標記位置無效")?;
        Ok((kind, body))
    } else {
        Ok((kind, body))
    }
}

fn apply_file(original: &[u8], all: &[&[u8]], index: &mut usize) -> Result<Vec<u8>, String> {
    let source = lines(original);
    if source.len() > MAX_PATCH_LINES { return Err("patch source 行數超過限制".into()); }
    let mut result: Vec<Vec<u8>> = Vec::new();
    let mut consumed = 0usize;
    let mut hunks = 0usize;
    while all.get(*index).is_some_and(|line| line.starts_with(b"@@ ")) {
        hunks += 1;
        if hunks > MAX_PATCH_LINES { return Err("patch hunk 數超過限制".into()); }
        let header = std::str::from_utf8(all[*index]).map_err(|_| "patch hunk header 不是文字")?.trim_end_matches('\n');
        let (old_start, old_count, new_start, new_count) = hunk_header(header)?;
        *index += 1;
        let old_index = if old_count == 0 { old_start } else { old_start - 1 };
        let new_index = if new_count == 0 { new_start } else { new_start - 1 };
        if old_index < consumed || old_index > source.len() { return Err("patch hunk 舊行號越界或重疊".into()); }
        result.extend(source[consumed..old_index].iter().map(|line| line.to_vec()));
        if result.len() != new_index { return Err("patch hunk 新行號不符".into()); }
        let mut source_index = old_index;
        let mut seen_old = 0usize;
        let mut seen_new = 0usize;
        while seen_old < old_count || seen_new < new_count {
            let (kind, body) = patch_line(all, index)?;
            match kind {
                b' ' | b'-' => {
                    if source.get(source_index).copied() != Some(body) { return Err("patch context 或刪除行不符".into()); }
                    source_index += 1;
                    seen_old += 1;
                    if kind == b' ' { result.push(body.to_vec()); seen_new += 1; }
                }
                b'+' => { result.push(body.to_vec()); seen_new += 1; }
                _ => unreachable!(),
            }
            if seen_old > old_count || seen_new > new_count { return Err("patch hunk 行數不符".into()); }
        }
        consumed = source_index;
        if all.get(*index).is_some_and(|line| line.starts_with(b" ") || line.starts_with(b"+") || line.starts_with(b"-"))
            && !all[*index].starts_with(b"--- ") {
            return Err("patch hunk 含超出宣告行數的資料".into());
        }
    }
    if hunks == 0 { return Err("patch 沒有 hunk".into()); }
    result.extend(source[consumed..].iter().map(|line| line.to_vec()));
    if result.iter().take(result.len().saturating_sub(1)).any(|line| !line.ends_with(b"\n")) {
        return Err("patch 非最後一行缺少換行".into());
    }
    let size = result.iter().try_fold(0usize, |total, line| total.checked_add(line.len())).ok_or("patch 輸出大小溢位")?;
    if size > MAX_FILE_BYTES { return Err("patch 輸出檔案過大".into()); }
    let mut output = Vec::with_capacity(size);
    for line in result { output.extend_from_slice(&line); }
    Ok(output)
}

fn apply_text(source: &Path, text: &str, updated: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<(), String> {
    if text.len() > MAX_PATCH_BYTES || text.as_bytes().contains(&0) { return Err("patch 不是有限大小的文字".into()); }
    let all = lines(text.as_bytes());
    if all.len() > MAX_PATCH_LINES { return Err("patch 行數超過限制".into()); }
    let mut index = 0;
    let mut files = 0;
    while index < all.len() {
        while all.get(index).is_some_and(|line| line.starts_with(b"diff --git ") || line.starts_with(b"index ")) {
            index += 1;
        }
        let old = all.get(index).ok_or("patch 缺少 --- header")?;
        let old = std::str::from_utf8(old).map_err(|_| "patch header 不是文字")?
            .strip_prefix("--- ").ok_or("patch 缺少 --- header")?;
        index += 1;
        let new = all.get(index).ok_or("patch 缺少 +++ header")?;
        let new = std::str::from_utf8(new).map_err(|_| "patch header 不是文字")?
            .strip_prefix("+++ ").ok_or("patch 缺少 +++ header")?;
        index += 1;
        let old = patch_path(old, "a/")?;
        let new = patch_path(new, "b/")?;
        if old != new { return Err("patch 不支援改名或新增/刪除檔案".into()); }
        let original = if let Some(previous) = updated.get(&old) { previous.clone() }
            else { source_file(source, old.to_str().ok_or("patch 路徑不是 UTF-8")?)? };
        if original.contains(&0) || std::str::from_utf8(&original).is_err() {
            return Err("patch 不支援 binary source".into());
        }
        let output = apply_file(&original, &all, &mut index)?;
        updated.insert(old, output);
        let size = updated.values().try_fold(0usize, |total, bytes| total.checked_add(bytes.len())).ok_or("patch 總大小溢位")?;
        if size > MAX_TOTAL_BYTES { return Err("patch 總大小超過限制".into()); }
        files += 1;
        if files > MAX_PATCHES { return Err("patch 檔案數超過限制".into()); }
    }
    if files == 0 { return Err("patch 沒有檔案".into()); }
    Ok(())
}

pub(super) fn apply(source: &Path, patches: &StrictJsonValue) -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let StrictJsonValue::Object(entries) = patches else { return Err("build.patches 必須是 table".into()); };
    if entries.len() > MAX_PATCHES { return Err("build.patches 數量超過限制".into()); }
    let mut updated = BTreeMap::new();
    for (name, value) in entries {
        safe_relative(name)?;
        let text = value.as_str().ok_or("build.patches 項目必須是 inline diff 字串")?;
        apply_text(source, text, &mut updated)?;
        let size = updated.values().try_fold(0usize, |total, bytes: &Vec<u8>| total.checked_add(bytes.len())).ok_or("patch 總大小溢位")?;
        if size > MAX_TOTAL_BYTES { return Err("patch 總大小超過限制".into()); }
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::{apply_file, lines, patch_path};

    #[test]
    fn unified_hunk_requires_exact_context_and_counts() {
        let patch = b"@@ -1,2 +1,2 @@\n a\n-b\n+c\n";
        let chunks = lines(patch);
        assert_eq!(apply_file(b"a\nb\n", &chunks, &mut 0).unwrap(), b"a\nc\n");
        assert!(apply_file(b"x\nb\n", &chunks, &mut 0).is_err());
        assert!(patch_path("a/../escape.lua", "a/").is_err());
        assert_eq!(patch_path("a/my file.lua\t2026\n", "a/").unwrap().as_path(), std::path::Path::new("my file.lua"));
        assert!(patch_path("\"a/my\\040file.lua\"\n", "a/").is_err());
    }
}
