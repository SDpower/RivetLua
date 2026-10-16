use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

const USAGE: &str =
    "用法：rivetlua [--profile lua55|lua54] [-E] [-v] [-i] [-e 程式] [-l 模組] [--] [檔案 [參數...]]";

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rivetlua-p17-cli-diagnostics-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("建立獨立缺檔測試目錄");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn run_lua(profile: &str, args: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rivetlua"));
    command
        .env_remove("LUA_INIT")
        .env_remove("LUA_INIT_5_4")
        .env_remove("LUA_INIT_5_5")
        .env_remove("LUA_PATH")
        .env_remove("LUA_PATH_5_4")
        .env_remove("LUA_PATH_5_5")
        .env_remove("LUA_CPATH")
        .env_remove("LUA_CPATH_5_4")
        .env_remove("LUA_CPATH_5_5")
        .env_remove("RIVETLUA_NATIVE_MANIFEST");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .arg("--profile")
        .arg(profile)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("啟動 RivetLua 命令列程式")
}

fn assert_cli_error<'a>(output: &'a Output, exit_code: i32, label: &str) -> &'a str {
    assert_eq!(output.status.code(), Some(exit_code), "{label}: {output:?}");
    assert!(output.stdout.is_empty(), "{label}: stdout={:?}", output.stdout);
    std::str::from_utf8(&output.stderr).expect("命令列診斷應為 UTF-8")
}

fn assert_option_diagnostic(stderr: &str, message: &str, label: &str) {
    let expected = format!("{message}\n{USAGE}\n");
    assert_eq!(
        stderr,
        expected.as_str(),
        "{label}: 命令列診斷與用法不符"
    );
}

#[test]
fn p17_cli_unknown_options_report_lua_compatible_diagnostics() {
    let unknown_options: [(&str, &[&str]); 5] = [
        ("-h", &["-h"]),
        ("---", &["---"]),
        ("-Ex", &["-Ex", "--"]),
        ("-vv", &["-vv"]),
        ("-iv", &["-iv"]),
    ];

    for profile in ["lua55", "lua54"] {
        for (flag, args) in unknown_options {
            let output = run_lua(profile, args, None);
            let stderr = assert_cli_error(&output, 2, &format!("{profile} {flag}"));
            let message = format!(
                "rivetlua: 不支援的選項：{flag} (unrecognized option '{flag}')"
            );
            assert_option_diagnostic(stderr, &message, &format!("{profile} {flag}"));
        }
    }
}

#[test]
fn p17_cli_missing_option_arguments_report_lua_compatible_diagnostics() {
    let missing_arguments: [(&str, &[&str], &str); 2] = [
        (
            "-e",
            &["-e"],
            "rivetlua: -e 需要程式文字 ('-e' needs argument)",
        ),
        (
            "-l",
            &["-l"],
            "rivetlua: -l 需要模組名稱 ('-l' needs argument)",
        ),
    ];

    for profile in ["lua55", "lua54"] {
        for (option, args, message) in missing_arguments {
            let output = run_lua(profile, args, None);
            let stderr = assert_cli_error(&output, 2, &format!("{profile} {option}"));
            assert_option_diagnostic(stderr, message, &format!("{profile} {option}"));
        }

        for (option, args, message) in [
            (
                "-e",
                &["-e", "-v"][..],
                "rivetlua: -e 需要程式文字 ('-e' needs argument)",
            ),
            (
                "-l",
                &["-l", "-v"][..],
                "rivetlua: -l 需要模組名稱 ('-l' needs argument)",
            ),
        ] {
            let output = run_lua(profile, args, None);
            let stderr = assert_cli_error(&output, 2, &format!("{profile} {option} -v"));
            assert!(
                !stderr.contains("RivetLua 0.0.0"),
                "{profile} {option}: 選項參數 -v 不應輸出版本列"
            );
            assert_option_diagnostic(stderr, message, &format!("{profile} {option} -v"));
        }
    }
}

#[test]
fn p17_cli_syntax_and_missing_file_diagnostics_identify_failure() {
    for profile in ["lua55", "lua54"] {
        let syntax = run_lua(profile, &["-e", "a"], None);
        let stderr = assert_cli_error(&syntax, 1, &format!("{profile} -e 語法錯誤"));
        assert!(
            stderr.contains("rivetlua: 編譯失敗："),
            "{profile}: 缺少精確繁中編譯錯誤前綴：{stderr:?}"
        );
        assert!(
            stderr.contains("syntax error"),
            "{profile}: 缺少 Lua 語法錯誤診斷：{stderr:?}"
        );

        let scratch = ScratchDir::new();
        let missing_file = run_lua(profile, &["--", "-i"], Some(&scratch.path));
        let stderr = assert_cli_error(&missing_file, 1, &format!("{profile} -- -i 缺檔"));
        assert!(
            stderr.contains("讀取檔案資訊失敗") && stderr.contains("-i"),
            "{profile}: 缺檔診斷須指出 -i 檔案及讀取檔案資訊失敗：{stderr:?}"
        );
    }
}
