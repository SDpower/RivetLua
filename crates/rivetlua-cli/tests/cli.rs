use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

fn lua(profile: &str, args: &[&str]) -> Output {
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
        .arg("--profile")
        .arg(profile)
        .args(args)
        .output()
        .unwrap()
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rivetlua-cli-test-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run_lua(
    args: &[&OsStr],
    input: &[u8],
    cwd: Option<&std::path::Path>,
    env: &[(&str, &str)],
) -> Output {
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
        .env_remove("LUA_CPATH_5_5");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn run_luac(args: &[&OsStr], input: &[u8], cwd: Option<&std::path::Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rivetluac"));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn save_transport(profile: rivetlua::LuaProfile, source: &[u8]) -> Vec<u8> {
    let engine = rivetlua::Engine::new(profile);
    let module = engine.compile_named(source, b"cli-test.lua").unwrap();
    engine
        .save_module(
            &module,
            &rivetlua::TransportBudget::new(rivetlua::ContainerLimits::default()),
        )
        .unwrap()
}

fn raw_rvlu_from_transport(transport: &[u8]) -> Vec<u8> {
    let rvlu_len = u64::from_le_bytes(transport[16..24].try_into().unwrap()) as usize;
    transport[40..40 + rvlu_len].to_vec()
}

#[test]
fn cli_executes_command_string_for_both_profiles() {
    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", "print('cli-ok')"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"cli-ok\n");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn cli_passes_script_arguments_and_builds_aligned_arg_table() {
    let path = std::env::temp_dir().join(format!("rivetlua-cli-{}.lua", std::process::id()));
    std::fs::write(&path, b"print(arg[-2], arg[-1], arg[0], arg[1], ...)\n").unwrap();
    let path_text = path.to_string_lossy().into_owned();
    let output = lua("lua54", &[path_text.as_str(), "first", "second"]);
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        format!("--profile\tlua54\t{path_text}\tfirst\tfirst\tsecond\n").as_bytes()
    );
}

#[test]
fn cli_rejects_unknown_options_with_nonzero_status() {
    let output = lua("lua55", &["-Z"]);
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
}

#[test]
fn cli_rejects_missing_option_values_and_version_does_not_consume_stdin() {
    let missing_e = lua("lua55", &["-e"]);
    assert_eq!(missing_e.status.code(), Some(2));
    let missing_l = lua("lua55", &["-l"]);
    assert_eq!(missing_l.status.code(), Some(2));

    let version = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-v"),
        ],
        b"print('must-not-run')\n",
        None,
        &[],
    );
    assert!(version.status.success());
    assert!(version.stdout.starts_with(b"RivetLua 0.0.0 (Lua 5.4.9)\n"));
    assert!(
        !version
            .stdout
            .windows(b"must-not-run".len())
            .any(|part| part == b"must-not-run")
    );
}

#[test]
fn cli_runs_stdin_and_dash_script_inputs() {
    let default_stdin = run_lua(
        &[OsStr::new("--profile"), OsStr::new("lua55")],
        b"print('pipe')\n",
        None,
        &[],
    );
    assert!(
        default_stdin.status.success(),
        "{}",
        String::from_utf8_lossy(&default_stdin.stderr)
    );
    assert_eq!(default_stdin.stdout, b"pipe\n");

    let dash_stdin = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-"),
        ],
        b"print('dash')\n",
        None,
        &[],
    );
    assert!(
        dash_stdin.status.success(),
        "{}",
        String::from_utf8_lossy(&dash_stdin.stderr)
    );
    assert_eq!(dash_stdin.stdout, b"dash\n");
}

#[test]
fn cli_runs_init_before_command_and_versioned_init_wins() {
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-eprint('action')"),
        ],
        b"",
        None,
        &[
            ("LUA_INIT", "print('fallback')"),
            ("LUA_INIT_5_5", "print('versioned')"),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"versioned\naction\n");
}

#[test]
fn cli_uses_unversioned_init_and_paths_only_as_fallbacks() {
    let init = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-eprint('action')"),
        ],
        b"",
        None,
        &[("LUA_INIT", "print('fallback-init')")],
    );
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert_eq!(init.stdout, b"fallback-init\naction\n");

    let paths = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-eprint(package.path);print(package.cpath)"),
        ],
        b"",
        None,
        &[
            ("LUA_PATH", "prefix/?.lua;;suffix/?.lua"),
            ("LUA_CPATH", "prefix/?.so"),
        ],
    );
    assert!(
        paths.status.success(),
        "{}",
        String::from_utf8_lossy(&paths.stderr)
    );
    assert_eq!(
        paths.stdout,
        b"prefix/?.lua;./?.lua;./?/init.lua;suffix/?.lua\nprefix/?.so\n"
    );

    let precedence = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-eprint(package.path)"),
        ],
        b"",
        None,
        &[
            ("LUA_PATH", "fallback/?.lua"),
            ("LUA_PATH_5_5", "versioned/?.lua"),
        ],
    );
    assert!(precedence.status.success());
    assert_eq!(precedence.stdout, b"versioned/?.lua\n");
}

#[test]
fn cli_ignore_environment_only_skips_init_and_path_overrides() {
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-E"),
            OsStr::new("-eprint('action')"),
        ],
        b"",
        None,
        &[
            ("LUA_INIT", "print('fallback')"),
            ("LUA_INIT_5_5", "print('versioned')"),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"action\n");

    let paths = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-E"),
            OsStr::new("-eprint(package.path);print(package.cpath)"),
        ],
        b"",
        None,
        &[
            ("LUA_PATH_5_5", "ignored/?.lua"),
            ("LUA_CPATH_5_5", "ignored/?.so"),
        ],
    );
    assert!(paths.status.success());
    assert_eq!(paths.stdout, b"./?.lua;./?/init.lua\n\n");
}

#[test]
fn cli_runs_at_file_init_source() {
    let directory = temp_dir();
    let init = directory.join("init.lua");
    std::fs::write(&init, b"print('from-init-file')\n").unwrap();
    let value = format!("@{}", init.display());
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-eprint('after-init')"),
        ],
        b"",
        Some(&directory),
        &[("LUA_INIT_5_4", value.as_str())],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"from-init-file\nafter-init\n");
}

#[test]
fn cli_loads_library_into_requested_global_before_script() {
    let directory = temp_dir();
    std::fs::write(directory.join("answer.lua"), b"return { value = 42 }\n").unwrap();
    let script = directory.join("main.lua");
    std::fs::write(&script, b"print(alias.value)\n").unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-l"),
            OsStr::new("alias=answer"),
            OsStr::new(script_text.as_str()),
        ],
        b"",
        Some(&directory),
        &[("LUA_PATH_5_5", "?.lua")],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"42\n");
}

#[test]
fn cli_loads_module_with_utf8_name() {
    let directory = temp_dir();
    std::fs::write(directory.join("módulo.lua"), b"return 37\n").unwrap();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-eprint(require('módulo'))"),
        ],
        b"",
        Some(&directory),
        &[("LUA_PATH_5_5", "?.lua")],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, "37\tmódulo.lua\n".as_bytes());
}

#[test]
fn cli_require_passes_and_returns_the_exact_module_candidate_path() {
    for profile in ["lua54", "lua55"] {
        let directory = temp_dir();
        std::fs::write(
            directory.join("sample.lua"),
            b"local name, path = ...; return name, path\n",
        )
        .unwrap();
        let script = directory.join("main.lua");
        std::fs::write(
            &script,
            b"local name, path = require('sample'); print(name, path)\n",
        )
        .unwrap();
        let script_text = script.to_string_lossy().into_owned();
        let path_variable = if profile == "lua54" {
            "LUA_PATH_5_4"
        } else {
            "LUA_PATH_5_5"
        };
        let output = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new(script_text.as_str()),
            ],
            b"",
            Some(&directory),
            &[(path_variable, "?.lua")],
        );
        let _ = std::fs::remove_dir_all(directory);
        assert!(
            output.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"sample\tsample.lua\n", "profile={profile}");
    }
}

#[test]
fn cli_dynamic_loadfile_uses_metered_host_reader() {
    let directory = temp_dir();
    std::fs::write(directory.join("child.lua"), b"return 23\n").unwrap();
    let script = directory.join("main.lua");
    std::fs::write(
        &script,
        b"local f = assert(loadfile('child.lua')); print(f())\n",
    )
    .unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new(script_text.as_str()),
        ],
        b"",
        Some(&directory),
        &[],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"23\n");
}

#[test]
fn cli_dynamic_loadfile_reads_stdin_with_metered_host_reader_for_both_profiles() {
    for profile in ["lua54", "lua55"] {
        let output = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new("local f = assert(loadfile()); print(f())"),
            ],
            b"return 31\n",
            None,
            &[],
        );
        assert!(
            output.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"31\n", "profile={profile}");
    }
}

#[test]
fn cli_reports_fuel_exhaustion_as_nonzero_aborted_execution() {
    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-ewhile true do end"]);
        assert!(!output.status.success(), "profile={profile}");
        assert!(
            output
                .stderr
                .windows("執行額度耗盡".len())
                .any(|part| part == "執行額度耗盡".as_bytes()),
            "profile={profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_runs_mixed_actions_in_order_and_treats_post_script_options_as_arguments() {
    let directory = temp_dir();
    std::fs::write(directory.join("math.lua"), b"return { value = 4 }\n").unwrap();
    let script = directory.join("main.lua");
    std::fs::write(&script, b"print(result, arg[1])\n").unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-eresult = 1"),
            OsStr::new("-lmathlib=math"),
            OsStr::new("-eresult = result + mathlib.value"),
            OsStr::new(script_text.as_str()),
            OsStr::new("--profile"),
            OsStr::new("lua55"),
        ],
        b"",
        Some(&directory),
        &[("LUA_PATH_5_4", "?.lua")],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"5\t--profile\n");
}

#[test]
fn cli_handles_bom_shebang_and_lua_magic_source_lines() {
    let directory = temp_dir();
    let script = directory.join("shebang.lua");
    std::fs::write(
        &script,
        b"\xef\xbb\xbf#!/usr/bin/env rivetlua\nprint('after-shebang')\n",
    )
    .unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let output = lua("lua55", &[script_text.as_str()]);
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"after-shebang\n");
}

#[test]
fn cli_keeps_rvct_whitespace_source_and_routes_unknown_binary_version_to_sdk() {
    for profile in ["lua54", "lua55"] {
        for (index, source) in [
            b"RVCT\t=1\nprint(RVCT)\n".as_slice(),
            b"RVCT\n=1\nprint(RVCT)\n".as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = temp_dir();
            let script = directory.join(format!("source-{index}.lua"));
            std::fs::write(&script, source).unwrap();
            let script_text = script.to_string_lossy().into_owned();
            let output = lua(profile, &[script_text.as_str()]);
            let _ = std::fs::remove_dir_all(directory);
            assert!(
                output.status.success(),
                "profile={profile}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"1\n", "profile={profile}");
        }

        let directory = temp_dir();
        let binary = directory.join("unknown.rvct");
        std::fs::write(&binary, b"RVCT\xff\x7fgarbage").unwrap();
        let binary_text = binary.to_string_lossy().into_owned();
        let output = lua(profile, &[binary_text.as_str()]);
        let _ = std::fs::remove_dir_all(directory);
        assert!(!output.status.success(), "profile={profile}");
        assert!(
            output
                .stderr
                .windows("binary 載入失敗".len())
                .any(|part| part == "binary 載入失敗".as_bytes()),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output
                .stderr
                .windows("編譯失敗".len())
                .any(|part| part == "編譯失敗".as_bytes())
        );
    }
}

#[test]
fn cli_reports_lua_error_bytes_and_keeps_repl_error_status() {
    let error = lua("lua54", &["-eerror('cli-sentinel')"]);
    assert!(!error.status.success());
    assert!(
        error
            .stderr
            .windows(b"cli-sentinel".len())
            .any(|part| part == b"cli-sentinel")
    );

    let repl = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-i"),
        ],
        b"error('repl-sentinel')\nprint('after-error')\n",
        None,
        &[],
    );
    assert!(!repl.status.success());
    assert!(
        repl.stdout
            .windows(b"after-error\n".len())
            .any(|part| part == b"after-error\n")
    );
    assert!(
        repl.stderr
            .windows(b"repl-sentinel".len())
            .any(|part| part == b"repl-sentinel")
    );
}

#[test]
fn cli_repl_accepts_multiline_blocks_and_continues() {
    let repl = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-i"),
        ],
        b"if true then\nprint('multiline')\nend\nprint('after-block')\n",
        None,
        &[],
    );
    assert!(
        repl.status.success(),
        "{}",
        String::from_utf8_lossy(&repl.stderr)
    );
    assert!(
        repl.stdout
            .windows(b"multiline\n".len())
            .any(|part| part == b"multiline\n")
    );
    assert!(
        repl.stdout
            .windows(b"after-block\n".len())
            .any(|part| part == b"after-block\n")
    );

    let expression = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-i"),
        ],
        b"1 + 2\n",
        None,
        &[],
    );
    assert!(
        expression.status.success(),
        "{}",
        String::from_utf8_lossy(&expression.stderr)
    );
    assert!(
        expression
            .stdout
            .windows(b"3\n".len())
            .any(|part| part == b"3\n")
    );
}

#[test]
fn cli_repl_tries_expressions_before_statements_and_matches_profile_equals_syntax() {
    let expression = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-i"),
        ],
        b"type({})\ntonumber('12')\n",
        None,
        &[],
    );
    assert!(
        expression.status.success(),
        "{}",
        String::from_utf8_lossy(&expression.stderr)
    );
    assert_eq!(
        expression.stdout,
        b"RivetLua 0.0.0 (Lua 5.5.1)\ntable\n12\n"
    );

    let lua54_equals = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-i"),
        ],
        b"=1+2\n",
        None,
        &[],
    );
    assert!(
        lua54_equals.status.success(),
        "{}",
        String::from_utf8_lossy(&lua54_equals.stderr)
    );
    assert_eq!(lua54_equals.stdout, b"RivetLua 0.0.0 (Lua 5.4.9)\n3\n");

    let lua55_equals = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-i"),
        ],
        b"=1+2\n",
        None,
        &[],
    );
    assert!(!lua55_equals.status.success());
    assert_eq!(lua55_equals.stdout, b"RivetLua 0.0.0 (Lua 5.5.1)\n");
    assert!(!lua55_equals.stderr.is_empty());
}

#[test]
fn cli_repl_prints_returned_values_through_vm_local_print_for_both_profiles() {
    for profile in ["lua54", "lua55"] {
        let version = match profile {
            "lua54" => b"RivetLua 0.0.0 (Lua 5.4.9)\n".as_slice(),
            _ => b"RivetLua 0.0.0 (Lua 5.5.1)\n".as_slice(),
        };

        let normal_print = lua(profile, &["-e", "print(1/0); print(0/0)"]);
        assert!(
            normal_print.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&normal_print.stderr)
        );
        let evaluated = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-i"),
            ],
            b"1/0\n0/0\n",
            None,
            &[],
        );
        assert!(
            evaluated.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&evaluated.stderr)
        );
        let mut expected = version.to_vec();
        expected.extend_from_slice(&normal_print.stdout);
        assert_eq!(evaluated.stdout, expected, "profile={profile}");

        let tostring = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new("t = setmetatable({}, { __tostring = function() return 'seen' end })"),
                OsStr::new("-i"),
            ],
            b"t\n",
            None,
            &[],
        );
        assert!(
            tostring.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&tostring.stderr)
        );
        let mut expected = version.to_vec();
        expected.extend_from_slice(b"seen\n");
        assert_eq!(tostring.stdout, expected, "profile={profile}");

        let overridden_print = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new(
                    "host_print = print; print = function(...) host_print('replacement', select('#', ...), ...) end",
                ),
                OsStr::new("-i"),
            ],
            b"select(1, 1, nil, 3)\n",
            None,
            &[],
        );
        assert!(
            overridden_print.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&overridden_print.stderr)
        );
        let mut expected = version.to_vec();
        expected.extend_from_slice(b"replacement\t3\t1\tnil\t3\n");
        assert_eq!(overridden_print.stdout, expected, "profile={profile}");

        let print_error = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new("print = function() error('print-failure') end"),
                OsStr::new("-i"),
            ],
            b"1\n",
            None,
            &[],
        );
        assert!(!print_error.status.success(), "profile={profile}");
        assert!(
            print_error
                .stderr
                .windows(b"print-failure".len())
                .any(|part| part == b"print-failure"),
            "profile={profile}: {}",
            String::from_utf8_lossy(&print_error.stderr)
        );

        let print_aborted = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new("print = function() while true do end end"),
                OsStr::new("-i"),
            ],
            b"1\n",
            None,
            &[],
        );
        assert!(!print_aborted.status.success(), "profile={profile}");
        assert!(
            print_aborted
                .stderr
                .windows("REPL print 執行額度耗盡".len())
                .any(|part| part == "REPL print 執行額度耗盡".as_bytes()),
            "profile={profile}: {}",
            String::from_utf8_lossy(&print_aborted.stderr)
        );
    }
}

#[test]
fn cli_rivetluac_compiles_explicit_and_default_outputs_that_rivetlua_loads() {
    for profile in ["lua54", "lua55"] {
        let directory = temp_dir();
        let source = directory.join("module.lua");
        let output_path = directory.join("module.rvct");
        std::fs::write(&source, b"print('compiled-cli')\n").unwrap();
        let source_text = source.to_string_lossy().into_owned();
        let output_text = output_path.to_string_lossy().into_owned();
        let output = run_luac(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-o"),
                OsStr::new(output_text.as_str()),
                OsStr::new(source_text.as_str()),
            ],
            b"",
            Some(&directory),
        );
        assert!(
            output.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&output_path).unwrap();
        assert!(bytes.starts_with(b"RVCT"));
        let loaded = lua(profile, &[output_text.as_str()]);
        assert!(
            loaded.status.success(),
            "profile={profile}: {}",
            String::from_utf8_lossy(&loaded.stderr)
        );
        assert_eq!(loaded.stdout, b"compiled-cli\n");
        let _ = std::fs::remove_dir_all(&directory);
    }

    let directory = temp_dir();
    std::fs::write(directory.join("stdin.lua"), b"print('default-output')\n").unwrap();
    let output = run_luac(&[OsStr::new("stdin.lua")], b"", Some(&directory));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let artifact = directory.join("rivetluac.out");
    assert!(std::fs::read(&artifact).unwrap().starts_with(b"RVCT"));
    let artifact_text = artifact.to_string_lossy().into_owned();
    let loaded = lua("lua55", &[artifact_text.as_str()]);
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    assert_eq!(loaded.stdout, b"default-output\n");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn cli_rivetluac_supports_stdin_syntax_check_public_listing_and_version() {
    let directory = temp_dir();
    let artifact = directory.join("stdin.rvct");
    let artifact_text = artifact.to_string_lossy().into_owned();
    let compiled = run_luac(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-o"),
            OsStr::new(artifact_text.as_str()),
            OsStr::new("-"),
        ],
        b"return 42\n",
        Some(&directory),
    );
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let loaded = lua("lua54", &[artifact_text.as_str()]);
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );

    let source = directory.join("listed.lua");
    std::fs::write(&source, b"local function f() return 1 end\n").unwrap();
    let source_text = source.to_string_lossy().into_owned();
    let checked = run_luac(
        &[OsStr::new("-p"), OsStr::new(source_text.as_str())],
        b"",
        Some(&directory),
    );
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(checked.stdout.is_empty());
    assert!(!directory.join("rivetluac.out").exists());

    let listed = run_luac(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-l"),
            OsStr::new(source_text.as_str()),
        ],
        b"",
        Some(&directory),
    );
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    for field in [
        b"profile=".as_slice(),
        b"format=".as_slice(),
        b"origin=".as_slice(),
        b"source_name=".as_slice(),
        b"main_line=".as_slice(),
    ] {
        assert!(
            listed.stdout.windows(field.len()).any(|part| part == field),
            "missing {field:?}: {}",
            String::from_utf8_lossy(&listed.stdout)
        );
    }
    assert!(
        listed
            .stdout
            .windows(b"profile=Lua54".len())
            .any(|part| part == b"profile=Lua54")
    );

    let version = run_luac(&[OsStr::new("-v")], b"", Some(&directory));
    assert!(version.status.success());
    assert_eq!(version.stdout, b"RivetLua luac (Lua 5.5.1)\n");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn cli_rivetluac_rejects_bad_inputs_multiple_files_and_keeps_existing_output() {
    let directory = temp_dir();
    let bad = directory.join("bad.lua");
    let good = directory.join("good.lua");
    let output_path = directory.join("existing.rvct");
    std::fs::write(&bad, b"local =\n").unwrap();
    std::fs::write(&good, b"return 1\n").unwrap();
    std::fs::write(&output_path, b"sentinel").unwrap();
    let bad_text = bad.to_string_lossy().into_owned();
    let good_text = good.to_string_lossy().into_owned();
    let output_text = output_path.to_string_lossy().into_owned();
    let syntax = run_luac(
        &[OsStr::new("-p"), OsStr::new(bad_text.as_str())],
        b"",
        Some(&directory),
    );
    assert!(!syntax.status.success());
    assert!(!syntax.stderr.is_empty());
    let write = run_luac(
        &[
            OsStr::new("-o"),
            OsStr::new(output_text.as_str()),
            OsStr::new(bad_text.as_str()),
        ],
        b"",
        Some(&directory),
    );
    assert!(!write.status.success());
    assert_eq!(std::fs::read(&output_path).unwrap(), b"sentinel");

    let multiple = run_luac(
        &[
            OsStr::new(good_text.as_str()),
            OsStr::new(bad_text.as_str()),
        ],
        b"",
        Some(&directory),
    );
    assert!(!multiple.status.success());
    assert!(!multiple.stderr.is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn cli_rivetluac_imports_rvct_raw_and_official_through_the_sdk() {
    for (profile, profile_value, official) in [
        (
            "lua54",
            rivetlua::LuaProfile::Lua54,
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-small-return.luac"
            )
            .as_slice(),
        ),
        (
            "lua55",
            rivetlua::LuaProfile::Lua55,
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-small-return.luac"
            )
            .as_slice(),
        ),
    ] {
        let transport = save_transport(profile_value, b"print('sdk-binary')\n");
        let raw = raw_rvlu_from_transport(&transport);
        for (input_name, bytes, expected_stdout) in [
            (
                "input.rvct",
                transport.as_slice(),
                b"sdk-binary\n".as_slice(),
            ),
            ("input.rvlu", raw.as_slice(), b"sdk-binary\n".as_slice()),
            ("input.luac", official, b"".as_slice()),
        ] {
            let directory = temp_dir();
            let input = directory.join(input_name);
            let output_path = directory.join("converted.rvct");
            std::fs::write(&input, bytes).unwrap();
            let input_text = input.to_string_lossy().into_owned();
            let output_text = output_path.to_string_lossy().into_owned();
            let compiled = run_luac(
                &[
                    OsStr::new("--profile"),
                    OsStr::new(profile),
                    OsStr::new("-o"),
                    OsStr::new(output_text.as_str()),
                    OsStr::new(input_text.as_str()),
                ],
                b"",
                Some(&directory),
            );
            assert!(
                compiled.status.success(),
                "profile={profile} input={input_name}: {}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let loaded = lua(profile, &[output_text.as_str()]);
            assert!(
                loaded.status.success(),
                "profile={profile} input={input_name}: {}",
                String::from_utf8_lossy(&loaded.stderr)
            );
            assert_eq!(
                loaded.stdout, expected_stdout,
                "profile={profile} input={input_name}"
            );
            let _ = std::fs::remove_dir_all(directory);
        }

        let directory = temp_dir();
        let corrupt = directory.join("corrupt.rvct");
        let output_path = directory.join("preserved.rvct");
        let mut bytes = transport.clone();
        bytes[32] ^= 0x80;
        std::fs::write(&corrupt, bytes).unwrap();
        std::fs::write(&output_path, b"preserved").unwrap();
        let corrupt_text = corrupt.to_string_lossy().into_owned();
        let output_text = output_path.to_string_lossy().into_owned();
        let rejected = run_luac(
            &[
                OsStr::new("-o"),
                OsStr::new(output_text.as_str()),
                OsStr::new(corrupt_text.as_str()),
            ],
            b"",
            Some(&directory),
        );
        assert!(!rejected.status.success());
        assert!(
            rejected
                .stderr
                .windows("binary 載入失敗".len())
                .any(|part| part == "binary 載入失敗".as_bytes())
        );
        assert_eq!(std::fs::read(&output_path).unwrap(), b"preserved");
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[test]
fn cli_rivetluac_defaults_to_stdin_and_atomic_output_io_failure_leaves_no_temp_file() {
    let directory = temp_dir();
    let output_path = directory.join("stdin-default.rvct");
    let output_text = output_path.to_string_lossy().into_owned();
    let compiled = run_luac(
        &[
            OsStr::new("--profile=lua54"),
            OsStr::new("-o"),
            OsStr::new(output_text.as_str()),
        ],
        b"print('no-input-stdin')\n",
        Some(&directory),
    );
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let loaded = lua("lua54", &[output_text.as_str()]);
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    assert_eq!(loaded.stdout, b"no-input-stdin\n");

    let source = directory.join("valid.lua");
    std::fs::write(&source, b"return 9\n").unwrap();
    let source_text = source.to_string_lossy().into_owned();
    let existing_directory = directory.join("destination-directory");
    std::fs::create_dir_all(&existing_directory).unwrap();
    let sentinel = existing_directory.join("sentinel");
    std::fs::write(&sentinel, b"keep").unwrap();
    let destination_text = existing_directory.to_string_lossy().into_owned();
    let failed = run_luac(
        &[
            OsStr::new("-o"),
            OsStr::new(destination_text.as_str()),
            OsStr::new(source_text.as_str()),
        ],
        b"",
        Some(&directory),
    );
    assert!(!failed.status.success());
    assert!(!failed.stderr.is_empty());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    for entry in std::fs::read_dir(&directory).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(!name.to_string_lossy().starts_with(".rivetluac-"));
    }
    let _ = std::fs::remove_dir_all(directory);
}

#[cfg(unix)]
#[test]
fn cli_preserves_non_utf8_and_empty_script_arguments() {
    use std::os::unix::ffi::OsStringExt;

    let directory = temp_dir();
    let script = directory.join("bytes.lua");
    std::fs::write(&script, b"print(arg[1], arg[2])\n").unwrap();
    let bad = std::ffi::OsString::from_vec(vec![0xff, b'x']);
    let script = script.into_os_string();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            script.as_os_str(),
            bad.as_os_str(),
            OsStr::new(""),
        ],
        b"",
        Some(&directory),
        &[],
    );
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, [vec![0xff, b'x'], b"\t\n".to_vec()].concat());
}

#[test]
fn cli_treats_lua_magic_lookalikes_as_source() {
    let output = lua("lua55", &["-e", "RVLU = 1; RVCT = 1; print(RVLU, RVCT)"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"1\t1\n");

    let call = lua("lua54", &["-e", "RVLU()"]);
    assert!(!call.status.success());
    assert!(
        !call
            .stderr
            .windows(b"binary ".len())
            .any(|part| part == b"binary ")
    );
}

#[test]
fn cli_loads_transport_and_rejects_corrupt_or_wrong_profile_binary() {
    let directory = temp_dir();
    let path = directory.join("module.rvct");
    let transport = save_transport(rivetlua::LuaProfile::Lua55, b"print('rvct-ok')\n");
    std::fs::write(&path, &transport).unwrap();
    let path_text = path.to_string_lossy().into_owned();
    let valid = lua("lua55", &[path_text.as_str()]);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(valid.stdout, b"rvct-ok\n");

    let wrong_profile = lua("lua54", &[path_text.as_str()]);
    assert!(!wrong_profile.status.success());
    let mut corrupt = transport.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&path, corrupt).unwrap();
    let bad = lua("lua55", &[path_text.as_str()]);
    let _ = std::fs::remove_dir_all(directory);
    assert!(!bad.status.success());
    assert!(
        bad.stderr
            .windows(b"RVCT".len())
            .any(|part| part == b"RVCT")
    );
}

#[test]
fn cli_loads_native_transport_with_vararg_sidecar_and_raw_rvlu() {
    for profile in [rivetlua::LuaProfile::Lua54, rivetlua::LuaProfile::Lua55] {
        let source = b"local function make(seed) return function(...) local t = {...}; print(seed, t[1], t[2]) end end; make(7)('left', 'right')\n";
        let transport = save_transport(profile, source);
        let directory = temp_dir();
        let path = directory.join("nested.rvct");
        std::fs::write(&path, &transport).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let selected = match profile {
            rivetlua::LuaProfile::Lua54 => "lua54",
            rivetlua::LuaProfile::Lua55 => "lua55",
        };
        let output = lua(selected, &[path_text.as_str()]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"7\tleft\tright\n");

        let raw = raw_rvlu_from_transport(&save_transport(profile, b"assert(40 + 2 == 42)\n"));
        std::fs::write(&path, raw).unwrap();
        let raw_output = lua(selected, &[path_text.as_str()]);
        assert!(
            raw_output.status.success(),
            "{}",
            String::from_utf8_lossy(&raw_output.stderr)
        );
        let _ = std::fs::remove_dir_all(directory);
    }
}

#[test]
fn cli_rejects_unknown_and_truncated_binary_inputs() {
    let directory = temp_dir();
    let path = directory.join("bad.bin");
    std::fs::write(&path, b"\x1bNotLua").unwrap();
    let path_text = path.to_string_lossy().into_owned();
    let unknown = lua("lua55", &[path_text.as_str()]);
    assert!(!unknown.status.success());

    std::fs::write(&path, b"RVCT").unwrap();
    let truncated = lua("lua55", &[path_text.as_str()]);
    let _ = std::fs::remove_dir_all(directory);
    assert!(!truncated.status.success());
    assert!(
        truncated
            .stderr
            .windows(b"RVCT".len())
            .any(|part| part == b"RVCT")
    );
}

#[test]
fn cli_loads_official_chunks_in_both_profiles() {
    for (profile, fixture) in [
        (
            "lua54",
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-small-return.luac"
            )
            .as_slice(),
        ),
        (
            "lua55",
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-small-return.luac"
            )
            .as_slice(),
        ),
    ] {
        let directory = temp_dir();
        let path = directory.join("official.luac");
        std::fs::write(&path, fixture).unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let output = lua(profile, &[path_text.as_str()]);
        let _ = std::fs::remove_dir_all(directory);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
