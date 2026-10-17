use std::process::{Command, Output, Stdio};

const MISSING_ARGUMENT_SOURCE: &str = "local ok,msg=pcall(warn); assert(ok == false and type(msg) == 'string'); assert(string.find(msg,'string expected',1,true)); print('missing-argument-ok')";
const INVALID_ARGUMENT_SOURCE: &str = "warn('@on'); local ok,msg=pcall(warn,'SHOULD NOT APPEAR',{}); assert(ok == false and type(msg) == 'string'); assert(string.find(msg,'string expected',1,true)); warn('AFTER'); warn('@off'); print('invalid-argument-ok')";
const NUMERIC_ARGUMENT_SOURCE: &str = "warn('@on'); assert(warn('number:',42,3.5)==nil); warn('@off'); warn('SUPPRESSED'); print('numeric-control-ok')";

fn run_lua(profile: &str, source: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rivetlua"))
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
        .arg("-e")
        .arg(source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("啟動 RivetLua 命令列程式")
}

fn assert_output(output: &Output, expected_stdout: &[u8], expected_stderr: &[u8], profile: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{profile}: 命令列程式應成功結束；stderr={:?}",
        output.stderr
    );
    assert_eq!(
        output.stdout.as_slice(),
        expected_stdout,
        "{profile}: stdout 不符"
    );
    assert_eq!(
        output.stderr.as_slice(),
        expected_stderr,
        "{profile}: stderr 不符"
    );
}

#[test]
fn p17_warn_missing_argument_reports_string_expected() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, MISSING_ARGUMENT_SOURCE);
        assert_output(&output, b"missing-argument-ok\n", b"", profile);
    }
}

#[test]
fn p17_warn_invalid_argument_does_not_leak_pending_warning() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, INVALID_ARGUMENT_SOURCE);
        assert_output(
            &output,
            b"invalid-argument-ok\n",
            b"Lua warning: AFTER\n",
            profile,
        );
    }
}

#[test]
fn p17_warn_numeric_arguments_and_controls_remain_supported() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, NUMERIC_ARGUMENT_SOURCE);
        assert_output(
            &output,
            b"numeric-control-ok\n",
            b"Lua warning: number:423.5\n",
            profile,
        );
    }
}
