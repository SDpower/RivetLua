use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const COMMITTED: &str = include_str!("../../../tests/p17/runner-manifest.toml");
pub(super) const MODULES: [(&str, &str); 5] = [
    ("lib1.so", "lib1.c"),
    ("lib11.so", "lib11.c"),
    ("lib2.so", "lib2.c"),
    ("lib21.so", "lib21.c"),
    ("lib2-v2.so", "lib22.c"),
];

#[derive(Clone, Copy)]
pub(super) struct Profile {
    pub name: &'static str,
    pub release: &'static str,
    pub tarball: &'static str,
    pub tarball_sha256: &'static str,
    pub suite: &'static str,
    pub all_lua_sha256: &'static str,
    pub libs_makefile: &'static str,
    pub version: &'static str,
    pub header_dir: &'static str,
}

pub(super) const PROFILES: [Profile; 2] = [
    Profile {
        name: "lua55-i64f64",
        release: "5.5.1",
        tarball: "vendor/lua55/tests.tar.gz",
        tarball_sha256: "da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31",
        suite: "vendor/lua55/lua-5.5.1-tests",
        all_lua_sha256: "f1b8b8075a71e7abc40260f6b9112e8d2a1057772f26374df4bc800d10296309",
        libs_makefile: "vendor/lua55/lua-5.5.1-tests/libs/makefile",
        version: "RivetLua 0.0.0 (Lua 5.5.1)",
        header_dir: "include/rivetlua/lua55",
    },
    Profile {
        name: "lua54-i64f64",
        release: "5.4.9",
        tarball: "vendor/lua54/tests.tar.gz",
        tarball_sha256: "7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca",
        suite: "vendor/lua54/lua-5.4.9-tests",
        all_lua_sha256: "3e296dd2b26ac6891ccba1ebaa62d40f1816ac93c7efdeaddc05aaa064e7311c",
        libs_makefile: "vendor/lua54/lua-5.4.9-tests/libs/makefile",
        version: "RivetLua 0.0.0 (Lua 5.4.9)",
        header_dir: "include/rivetlua/lua54",
    },
];

pub(super) fn sha256_bytes(bytes: &[u8]) -> Option<[u8; 32]> {
    rivetlua::sha256_bytes(bytes)
}

pub(super) fn sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("P17 SHA-256 讀取失敗：{}：{error}", path.display()))?;
    let digest = sha256_bytes(&bytes)
        .ok_or_else(|| format!("P17 SHA-256 長度溢位：{}", path.display()))?;
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{sha256, sha256_bytes};
    use std::fs;
    use std::path::PathBuf;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rivetlua-p17-sha256-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn known_vectors_and_padding_boundaries() {
        assert_eq!(
            hex(&sha256_bytes(b"").unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256_bytes(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        for (length, expected) in [
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
            (128, "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"),
        ] {
            assert_eq!(
                hex(&sha256_bytes(&vec![b'a'; length]).unwrap()),
                expected,
                "長度 {length}"
            );
        }
    }

    #[test]
    fn binary_input_spans_multiple_blocks() {
        let bytes = (0..1025)
            .map(|index| ((index * 131 + 17) % 256) as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            hex(&sha256_bytes(&bytes).unwrap()),
            "b49a266849885c837e4295d53d91dc873fbd77f76fd0c06b12ff4da04fe3e3c9"
        );
    }

    #[test]
    fn reads_and_hashes_a_file() {
        let path = temporary_path("file");
        let payload = b"RivetLua P17 manifest SHA file\0\xff\x80\x01";
        fs::write(&path, payload).expect("寫入測試檔");
        let result = sha256(&path);
        let cleanup = fs::remove_file(&path);
        assert_eq!(
            result.unwrap(),
            "124aebcbb76380c357488ea8364f96ee56442198e8480f82641a0cb537135501"
        );
        cleanup.expect("移除測試檔");
    }

    #[test]
    fn missing_file_returns_an_error() {
        let path = temporary_path("missing");
        let _ = fs::remove_file(&path);
        let error = sha256(&path).expect_err("不存在的檔案必須回報錯誤");
        assert!(error.contains("P17 SHA-256 讀取失敗"));
    }
}

pub(super) fn validate(root: &Path) -> Result<(), String> {
    let actual = fs::read_to_string(root.join("tests/p17/runner-manifest.toml"))
        .map_err(|error| format!("P17 runner manifest 不可讀：{error}"))?;
    if actual != COMMITTED {
        return Err("P17 runner manifest 與編譯時固定內容不符".into());
    }
    let mut observed = BTreeMap::new();
    let mut section = "";
    for line in actual
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("P17 runner manifest 格式錯誤")?;
        let value = value.trim();
        let normalized;
        let value = if let Some(array) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            let entries = array
                .split(',')
                .map(str::trim)
                .map(|v| {
                    v.strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .ok_or("P17 runner manifest 陣列元素須為字串")
                })
                .collect::<Result<Vec<_>, _>>()?;
            if entries.is_empty() || entries.iter().any(|v| v.is_empty()) {
                return Err("P17 runner manifest 陣列不得空白".into());
            }
            normalized = entries.join(",");
            normalized.as_str()
        } else {
            value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .ok_or("P17 runner manifest 只接受固定字串或字串陣列")?
        };
        if observed
            .insert(
                (section.to_owned(), key.trim().to_owned()),
                value.to_owned(),
            )
            .is_some()
        {
            return Err("P17 runner manifest 重複欄位".into());
        }
    }
    let modules = MODULES
        .iter()
        .map(|(name, source)| format!("{name}:{source}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut expected = BTreeMap::new();
    expected.insert(
        ("".into(), "schema".into()),
        "rivetlua-p17-runner-v1".into(),
    );
    expected.insert(("".into(), "batch".into()), "P17-B01".into());
    expected.insert(
        ("".into(), "profiles".into()),
        "lua55-i64f64,lua54-i64f64".into(),
    );
    for profile in PROFILES {
        for (key, value) in [
            ("release", profile.release),
            ("tarball", profile.tarball),
            ("tarball_sha256", profile.tarball_sha256),
            ("suite", profile.suite),
            ("all_lua_sha256", profile.all_lua_sha256),
            ("libs_makefile", profile.libs_makefile),
            ("modules", &modules),
            ("p1_init", "libs/P1/init.lua"),
            ("p1_xuxu", "libs/P1/xuxu.lua"),
        ] {
            expected.insert((profile.name.into(), key.into()), value.into());
        }
    }
    if observed != expected {
        return Err("P17 runner manifest 固定來源、release 或 module 清單不符".into());
    }
    Ok(())
}

fn files(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("P17 suite 讀取失敗：{error}"))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(base).map_err(|error| error.to_string())?;
        if relative == Path::new("libs/P1/.gitkeep") {
            if fs::read(&path).map_err(|error| error.to_string())? != b"\n" {
                return Err("P17 P1 空目錄標記變更".into());
            }
            continue;
        }
        let kind = fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .file_type();
        if kind.is_dir() {
            files(base, &path, out)?;
        } else if kind.is_file() {
            out.insert(relative.to_path_buf(), sha256(&path)?);
        } else {
            return Err(format!("P17 suite 含非一般檔案：{}", path.display()));
        }
    }
    Ok(())
}

pub(super) fn verify_fixture(
    root: &Path,
    profile: Profile,
    work: &Path,
) -> Result<PathBuf, String> {
    if sha256(&root.join(profile.tarball))? != profile.tarball_sha256 {
        return Err(format!("P17 {} tarball SHA 不符", profile.name));
    }
    let canonical = root.join(profile.suite);
    if sha256(&canonical.join("all.lua"))? != profile.all_lua_sha256 {
        return Err(format!("P17 {} all.lua SHA 不符", profile.name));
    }
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let output = Command::new("tar")
        .arg("-xzf")
        .arg(root.join(profile.tarball))
        .arg("-C")
        .arg(work)
        .output()
        .map_err(|error| format!("P17 tar 啟動失敗：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "P17 tar 失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let suite = work.join(
        Path::new(profile.suite)
            .file_name()
            .ok_or("P17 suite 名稱缺失")?,
    );
    let mut expected = BTreeMap::new();
    let mut actual = BTreeMap::new();
    files(&suite, &suite, &mut expected)?;
    files(&canonical, &canonical, &mut actual)?;
    if expected.is_empty() || expected != actual {
        return Err(format!(
            "P17 {} canonical suite 與 tarball 全樹不符",
            profile.name
        ));
    }
    if expected.get(Path::new("all.lua")).map(String::as_str) != Some(profile.all_lua_sha256) {
        return Err(format!("P17 {} tarball all.lua SHA 不符", profile.name));
    }
    Ok(suite)
}
