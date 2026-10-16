use std::io::Write;
use std::process::{Command, Output, Stdio};

fn expected_banner(profile: &str) -> &'static [u8] {
    match profile {
        "lua54" => {
            b"RivetLua 0.0.0 (Lua 5.4.9); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n"
        }
        "lua55" => {
            b"RivetLua 0.0.0 (Lua 5.5.1); Lua language: Copyright (C) 1994-2026 Lua.org, PUC-Rio\n"
        }
        _ => unreachable!("測試只使用明確的 Lua profile"),
    }
}

fn run_lua(profile: &str, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rivetlua"))
        .env_remove("LUA_INIT")
        .env_remove("LUA_INIT_5_4")
        .env_remove("LUA_INIT_5_5")
        .env_remove("LUA_PATH")
        .env_remove("LUA_PATH_5_4")
        .env_remove("LUA_PATH_5_5")
        .env_remove("LUA_CPATH")
        .env_remove("LUA_CPATH_5_4")
        .env_remove("LUA_CPATH_5_5")
        .env_remove("RIVETLUA_NATIVE_MANIFEST")
        .arg("--profile")
        .arg(profile)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("啟動 RivetLua CLI");
    if let Err(error) = child
        .stdin
        .take()
        .expect("RivetLua CLI stdin")
        .write_all(input)
    {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "寫入 RivetLua CLI stdin"
        );
    }
    child.wait_with_output().expect("等待 RivetLua CLI")
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

#[test]
fn p17_version_flag_with_execute_prints_full_banner_then_program_output() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, &["-v", "-e", "print'hello'"], b"");
        let expected = [expected_banner(profile), b"hello\n"].concat();
        assert_success(&output, &expected, profile);
        assert!(!output.stdout.contains(&0), "{profile}: stdout 不應包含 NUL");
    }
}

#[test]
fn p17_version_flag_does_not_execute_stdin() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, &["-v"], b"print('must-not-run')\n");
        assert_success(&output, expected_banner(profile), profile);
    }
}

#[test]
fn p17_repl_eof_prints_full_banner_and_exact_prompt_termination() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, &["-i"], b"");
        let expected = [expected_banner(profile), b"> \n"].concat();
        assert_success(&output, &expected, profile);
    }
}
