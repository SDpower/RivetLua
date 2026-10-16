use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rivetlua-p17-binary-prefix-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("建立獨立測試目錄");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn current_profile() -> (&'static str, rivetlua::LuaProfile, u8) {
    if cfg!(feature = "native-lua54") {
        ("lua54", rivetlua::LuaProfile::Lua54, 0x54)
    } else {
        ("lua55", rivetlua::LuaProfile::Lua55, 0x55)
    }
}

fn other_profile() -> rivetlua::LuaProfile {
    match current_profile().1 {
        rivetlua::LuaProfile::Lua54 => rivetlua::LuaProfile::Lua55,
        rivetlua::LuaProfile::Lua55 => rivetlua::LuaProfile::Lua54,
    }
}

fn run_lua(profile: &str, args: &[&OsStr], cwd: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rivetlua"));
    command
        .current_dir(cwd)
        .env_remove("LUA_INIT")
        .env_remove("LUA_INIT_5_4")
        .env_remove("LUA_INIT_5_5")
        .env_remove("LUA_PATH")
        .env_remove("LUA_PATH_5_4")
        .env_remove("LUA_PATH_5_5")
        .env_remove("LUA_CPATH")
        .env_remove("LUA_CPATH_5_4")
        .env_remove("LUA_CPATH_5_5")
        .arg("--profile")
        .arg(profile)
        .args(args)
        .output()
        .expect("啟動 RivetLua CLI")
}

fn dump_official_chunk(directory: &Path, profile: &str) -> Vec<u8> {
    let source = r#"local chunk, err = load("print('official-file-ok')", "=p17-dump")
assert(chunk, err)
assert(io.stdout:write(string.dump(chunk)))"#;
    let output = run_lua(profile, &[OsStr::new("-e"), OsStr::new(source)], directory);
    assert!(
        output.status.success(),
        "profile={profile}; stdout={:?}; stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let bytes = output.stdout;
    let (_, _, expected_version) = current_profile();
    assert!(bytes.starts_with(b"\x1bLua"));
    assert_eq!(bytes.get(4), Some(&expected_version));
    bytes
}

fn sdk_rvlu(profile: rivetlua::LuaProfile, source: &[u8]) -> Vec<u8> {
    let engine = rivetlua::Engine::new(profile);
    let module = engine
        .compile_named(source, b"=p17-rvlu")
        .expect("SDK 編譯 RVLU fixture");
    let transport = engine
        .save_module(
            &module,
            &rivetlua::TransportBudget::new(rivetlua::ContainerLimits::default()),
        )
        .expect("SDK 建立 RVCT transport fixture");
    let length = u64::from_le_bytes(
        transport[16..24]
            .try_into()
            .expect("RVCT fixture 包含 module 長度欄位"),
    ) as usize;
    let end = 40usize
        .checked_add(length)
        .expect("RVCT fixture 長度不溢位");
    transport
        .get(40..end)
        .expect("RVCT fixture 包含完整 RVLU module")
        .to_vec()
}

fn with_source_prefix(binary: &[u8]) -> Vec<u8> {
    let mut bytes = b"\xef\xbb\xbf# P17 binary prefix\n".to_vec();
    bytes.extend_from_slice(binary);
    bytes
}

fn assert_success(output: &Output, expected_stdout: &[u8], label: &str) {
    assert!(
        output.status.success(),
        "{label}; exit={:?}; stdout={:?}; stderr={}",
        output.status.code(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected_stdout, "{label}");
    assert!(output.stderr.is_empty(), "{label}: {:?}", output.stderr);
}

fn assert_binary_rejected(output: &Output, label: &str) {
    let marker = "binary 載入失敗".as_bytes();
    assert!(
        !output.status.success(),
        "{label}: binary input unexpectedly succeeded"
    );
    assert!(output.stdout.is_empty(), "{label}: {:?}", output.stdout);
    assert!(
        output
            .stderr
            .windows(marker.len())
            .any(|part| part == marker),
        "{label}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn p17_binary_file_prefix_loads_dumped_chunk() {
    let scratch = ScratchDir::new();
    let (profile, sdk_profile, _) = current_profile();

    let official = dump_official_chunk(&scratch.path, profile);
    let official_path = scratch.path.join("official.luac");
    fs::write(&official_path, &official).expect("寫入官方 chunk fixture");
    let direct_official = run_lua(profile, &[official_path.as_os_str()], &scratch.path);
    assert_success(&direct_official, b"official-file-ok\n", "官方 chunk 檔案輸入");

    let official_prefixed_path = scratch.path.join("official-prefixed.luac");
    fs::write(&official_prefixed_path, with_source_prefix(&official))
        .expect("寫入前綴官方 chunk fixture");
    let prefixed_official = run_lua(
        profile,
        &[official_prefixed_path.as_os_str()],
        &scratch.path,
    );
    assert_success(
        &prefixed_official,
        b"official-file-ok\n",
        "BOM 與首行 comment 後的官方 chunk",
    );

    let rvlu = sdk_rvlu(sdk_profile, b"print('rvlu-file-ok')\n");
    let rvlu_path = scratch.path.join("module.rvlu");
    fs::write(&rvlu_path, &rvlu).expect("寫入 SDK RVLU fixture");
    let direct_rvlu = run_lua(profile, &[rvlu_path.as_os_str()], &scratch.path);
    assert_success(&direct_rvlu, b"rvlu-file-ok\n", "RVLU 檔案輸入");

    let rvlu_prefixed_path = scratch.path.join("module-prefixed.rvlu");
    fs::write(&rvlu_prefixed_path, with_source_prefix(&rvlu))
        .expect("寫入前綴 RVLU fixture");
    let prefixed_rvlu = run_lua(
        profile,
        &[rvlu_prefixed_path.as_os_str()],
        &scratch.path,
    );
    assert_success(
        &prefixed_rvlu,
        b"rvlu-file-ok\n",
        "BOM 與首行 comment 後的 RVLU module",
    );

    let main = scratch.path.join("main.lua");
    fs::write(
        &main,
        b"local f, e = loadfile('official-prefixed.luac'); assert(f, e); f()\n\
          local g, ge = loadfile('module-prefixed.rvlu'); assert(g, ge); g()\n\
          dofile('official-prefixed.luac')\n\
          dofile('module-prefixed.rvlu')\n",
    )
    .expect("寫入 loadfile/dofile fixture");
    let reader_output = run_lua(profile, &[main.as_os_str()], &scratch.path);
    assert_success(
        &reader_output,
        b"official-file-ok\nrvlu-file-ok\nofficial-file-ok\nrvlu-file-ok\n",
        "FsSourceReader 的 loadfile/dofile 官方 chunk 與 RVLU 路徑",
    );
}

#[test]
fn p17_binary_file_prefix_keeps_source_and_binary_errors() {
    let scratch = ScratchDir::new();
    let (profile, sdk_profile, version) = current_profile();

    let source_line_path = scratch.path.join("source-line.lua");
    fs::write(
        &source_line_path,
        b"\xef\xbb\xbf# source comment\nlocal harmless=true\nerror('source-line-check')\n",
    )
    .expect("寫入保留 runtime 行號的 source fixture");
    let source_error = run_lua(profile, &[source_line_path.as_os_str()], &scratch.path);
    assert!(!source_error.status.success(), "source runtime error 須保留");
    assert!(source_error.stdout.is_empty(), "source runtime error 不應輸出 stdout");
    assert!(
        source_error
            .stderr
            .windows(b":3:".len())
            .any(|part| part == b":3:"),
        "comment 前綴不應改變錯誤行號：{}",
        String::from_utf8_lossy(&source_error.stderr)
    );
    assert!(
        source_error
            .stderr
            .windows(b"source-line-check".len())
            .any(|part| part == b"source-line-check"),
        "source runtime diagnostic 應保留 marker：{}",
        String::from_utf8_lossy(&source_error.stderr)
    );

    let no_newline_path = scratch.path.join("comment-without-newline.lua");
    fs::write(&no_newline_path, b"# source comment without newline")
        .expect("寫入無換行 source comment");
    let no_newline = run_lua(profile, &[no_newline_path.as_os_str()], &scratch.path);
    assert_success(&no_newline, b"", "無換行 source comment 舊行為");

    let official = dump_official_chunk(&scratch.path, profile);
    let truncated = official
        .get(..5)
        .expect("string.dump official chunk 含 signature 與 version");
    let truncated_path = scratch.path.join("truncated-prefixed.luac");
    fs::write(&truncated_path, with_source_prefix(truncated))
        .expect("寫入前綴 truncated official chunk");
    let truncated_output = run_lua(profile, &[truncated_path.as_os_str()], &scratch.path);
    assert_binary_rejected(&truncated_output, "截斷官方 chunk 須由 binary loader 拒絕");

    let mut wrong_version = official;
    wrong_version[4] = if version == 0x54 { 0x55 } else { 0x54 };
    let wrong_version_path = scratch.path.join("wrong-version-prefixed.luac");
    fs::write(&wrong_version_path, with_source_prefix(&wrong_version))
        .expect("寫入前綴 wrong-version official chunk");
    let wrong_version_output = run_lua(profile, &[wrong_version_path.as_os_str()], &scratch.path);
    assert_binary_rejected(&wrong_version_output, "不匹配版本的官方 chunk 須拒絕");

    let wrong_profile = sdk_rvlu(other_profile(), b"print('wrong-profile')\n");
    let wrong_profile_path = scratch.path.join("wrong-profile-prefixed.rvlu");
    fs::write(&wrong_profile_path, with_source_prefix(&wrong_profile))
        .expect("寫入前綴 wrong-profile RVLU fixture");
    let wrong_profile_output = run_lua(profile, &[wrong_profile_path.as_os_str()], &scratch.path);
    assert_binary_rejected(&wrong_profile_output, "不匹配 profile 的 RVLU module 須拒絕");
}
