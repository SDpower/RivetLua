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

fn run_gc_loadfile_fixture(
    environment_variable: &str,
    profile: &str,
    expected_source_bytes: usize,
) -> Output {
    let path = std::env::var_os(environment_variable)
        .unwrap_or_else(|| panic!("需明確指定 {environment_variable} 官方 GC fixture 路徑"));
    let path = PathBuf::from(path);
    assert!(path.is_absolute(), "{environment_variable} 必須是絕對路徑");
    assert_eq!(path.file_name(), Some(OsStr::new("gc.lua")));
    assert!(path.is_file(), "{environment_variable} 必須指向 gc.lua");
    assert_eq!(
        usize::try_from(std::fs::metadata(&path).unwrap().len()).unwrap(),
        expected_source_bytes,
        "fixture 大小不符：{}",
        path.display()
    );
    let parent = path.parent().expect("GC fixture 必須有父目錄");

    run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new(profile),
            OsStr::new("-e"),
            OsStr::new(
                "local f,e=loadfile('gc.lua'); assert(type(f)=='function',e); print('gc-compiled')",
            ),
        ],
        b"",
        Some(parent),
        &[],
    )
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
#[cfg(unix)]
fn cli_randomseed_without_arguments_uses_host_entropy_for_both_profiles() {
    const ENTROPY_SOURCE: &str = "local x,y=math.randomseed(); assert(type(x)=='number' and type(y)=='number'); assert(math.type(x)=='integer' and math.type(y)=='integer'); assert(type(math.random())=='number'); print(type(x),type(y),math.type(x),math.type(y))";
    for profile in ["lua54", "lua55"] {
        let randomseed = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new(ENTROPY_SOURCE),
            ],
            b"",
            None,
            &[],
        );
        assert!(
            randomseed.status.success(),
            "profile={profile}; status={:?}; stdout={:?}; stderr={:?}",
            randomseed.status.code(),
            randomseed.stdout,
            randomseed.stderr
        );
        assert_eq!(randomseed.stdout, b"number\tnumber\tinteger\tinteger\n");

        let explicit = [
            OsStr::new("--profile"),
            OsStr::new(profile),
            OsStr::new("-e"),
            OsStr::new(
                "math.randomseed(123,456); print(math.random(1,1000000), math.random(1,1000000))",
            ),
        ];
        let first = run_lua(&explicit, b"", None, &[]);
        let second = run_lua(&explicit, b"", None, &[]);
        assert!(first.status.success());
        assert!(second.status.success());
        assert_eq!(first.stdout, second.stdout, "profile={profile}");
        assert!(!first.stdout.is_empty());
    }

    let default_profile = run_lua(
        &[OsStr::new("-e"), OsStr::new(ENTROPY_SOURCE)],
        b"",
        None,
        &[],
    );
    assert!(
        default_profile.status.success(),
        "default profile; stderr={:?}",
        default_profile.stderr
    );
    assert_eq!(
        default_profile.stdout,
        b"number\tnumber\tinteger\tinteger\n"
    );
}

#[cfg(not(unix))]
#[test]
fn cli_randomseed_without_arguments_reports_entropy_failure_on_unsupported_platforms() {
    for profile in ["lua54", "lua55"] {
        let output = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new("math.randomseed()"),
            ],
            b"",
            None,
            &[],
        );
        assert!(!output.status.success(), "profile={profile}");
        assert!(
            output
                .stderr
                .windows(b"E_HOST_ENTROPY_FAILED".len())
                .any(|window| window == b"E_HOST_ENTROPY_FAILED"),
            "profile={profile}; stderr={:?}",
            output.stderr
        );
    }
}

#[cfg(any(unix, windows))]
#[test]
fn cli_os_clock_and_time_use_real_host_values_for_profiles_and_build_default() {
    const SOURCE: &str = "local before=os.clock(); local sum=0; for i=1,10000 do sum=sum+i end; local after=os.clock(); local epoch=os.time(); assert(type(before)=='number' and before>=0 and before<math.huge); assert(type(after)=='number' and after>before and after<math.huge); assert(math.type(epoch)=='integer'); print(before,after,epoch)";

    for profile in ["lua54", "lua55"] {
        let before = std::time::SystemTime::now();
        let output = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new(SOURCE),
            ],
            b"",
            None,
            &[],
        );
        let after = std::time::SystemTime::now();
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={:?}",
            output.stdout,
            output.stderr
        );
        let values = String::from_utf8(output.stdout).unwrap();
        let mut values = values.split_whitespace();
        let start_clock: f64 = values.next().unwrap().parse().unwrap();
        let finish_clock: f64 = values.next().unwrap().parse().unwrap();
        let epoch: i64 = values.next().unwrap().parse().unwrap();
        assert!(start_clock.is_finite() && start_clock >= 0.0);
        assert!(finish_clock.is_finite() && finish_clock > start_clock);
        let before_epoch: i64 = before
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
        let after_epoch: i64 = after
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
        assert!(
            epoch >= before_epoch && epoch <= after_epoch,
            "profile={profile}"
        );
        assert!(values.next().is_none());
    }

    let before = std::time::SystemTime::now();
    let default_output = run_lua(&[OsStr::new("-e"), OsStr::new(SOURCE)], b"", None, &[]);
    let after = std::time::SystemTime::now();
    assert!(
        default_output.status.success(),
        "default profile; stdout={:?}; stderr={:?}",
        default_output.stdout,
        default_output.stderr
    );
    let values = String::from_utf8(default_output.stdout).unwrap();
    let mut values = values.split_whitespace();
    let start_clock: f64 = values.next().unwrap().parse().unwrap();
    let finish_clock: f64 = values.next().unwrap().parse().unwrap();
    let epoch: i64 = values.next().unwrap().parse().unwrap();
    assert!(start_clock.is_finite() && start_clock >= 0.0);
    assert!(finish_clock.is_finite() && finish_clock > start_clock);
    let before_epoch: i64 = before
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    let after_epoch: i64 = after
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    assert!(epoch >= before_epoch && epoch <= after_epoch);
    assert!(values.next().is_none());
}

#[cfg(not(any(unix, windows)))]
#[test]
fn cli_os_clock_is_unsupported_without_a_native_process_clock() {
    let output = run_lua(
        &[
            OsStr::new("-e"),
            OsStr::new(
                "local ok, err=pcall(os.clock); assert(not ok and err=='E_HOST_UNSUPPORTED'); assert(math.type(os.time())=='integer'); print('unsupported')",
            ),
        ],
        b"",
        None,
        &[],
    );
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert_eq!(output.stdout, b"unsupported\n");
}

#[test]
fn cli_os_resource_policy_keeps_unconfigured_operations_denied() {
    let source = "local a,b=pcall(os.getenv,'PATH'); local c,d=pcall(os.execute); local e,f=pcall(os.date,'*t'); local g,h=pcall(os.time,{year=2020,month=1,day=2}); local i,j=pcall(os.remove,'x'); assert(not a and b=='E_HOST_POLICY_OS'); assert(not c and d=='E_HOST_POLICY_OS'); assert(not e and f=='E_HOST_POLICY_OS'); assert(not g and h=='E_HOST_POLICY_OS'); assert(not i and j=='E_HOST_POLICY_OS'); print('denied')";
    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", source]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert_eq!(output.stdout, b"denied\n");
    }
}

#[test]
fn cli_os_setlocale_uses_only_fixed_c_locale_for_profiles_and_build_default() {
    const SOURCE: &str = r#"
local categories = {'all', 'collate', 'ctype', 'monetary', 'numeric', 'time'}
assert(os.setlocale() == 'C')
assert(os.setlocale(nil) == 'C')
for i=1,#categories do
    local category = categories[i]
    assert(os.setlocale(nil, category) == 'C')
    assert(os.setlocale('C', category) == 'C')
end
assert(os.setlocale('C') == 'C')
assert(os.setlocale('') == nil)
assert(os.setlocale('POSIX') == nil)
assert(os.setlocale('en_US.UTF-8') == nil)
assert(os.setlocale() == 'C')
local ok = pcall(os.setlocale, 'C', 'invalid')
assert(not ok)
assert(string.lower(string.char(65, 195, 128)) == string.char(97, 195, 128))
assert(string.upper(string.char(97, 195, 128)) == string.char(65, 195, 128))
assert(string.find(string.char(233), '%a') == nil)
assert(string.format('%.1f', 1.5) == '1.5')
print('locale-ok')
"#;

    for profile in [Some("lua54"), Some("lua55"), None] {
        let mut args = Vec::new();
        if let Some(profile) = profile {
            args.extend([OsStr::new("--profile"), OsStr::new(profile)]);
        }
        args.extend([OsStr::new("-e"), OsStr::new(SOURCE)]);
        let output = run_lua(&args, b"", None, &[]);
        assert!(
            output.status.success(),
            "profile={profile:?}; stdout={:?}; stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert_eq!(output.stdout, b"locale-ok\n");
    }
}

#[test]
fn cli_default_profile_identity_and_compiler_roundtrip_match_build_feature() {
    let (default_version, default_lua_version) = if cfg!(feature = "default-lua54") {
        (b"5.4.9".as_slice(), b"Lua 5.4".as_slice())
    } else {
        (b"5.5.1".as_slice(), b"Lua 5.5".as_slice())
    };
    let interpreter_version = run_lua(&[OsStr::new("-v")], b"", None, &[]);
    assert!(interpreter_version.status.success());
    assert_eq!(
        interpreter_version.stdout,
        format!(
            "RivetLua 0.0.0 (Lua {})\n",
            String::from_utf8_lossy(default_version)
        )
        .as_bytes()
    );

    let compiler_version = run_luac(&[OsStr::new("-v")], b"", None);
    assert!(compiler_version.status.success());
    assert_eq!(
        compiler_version.stdout,
        format!(
            "RivetLua luac (Lua {})\n",
            String::from_utf8_lossy(default_version)
        )
        .as_bytes()
    );

    for explicit_profile in ["lua54", "lua55"] {
        let explicit_version = match explicit_profile {
            "lua54" => b"5.4.9".as_slice(),
            _ => b"5.5.1".as_slice(),
        };
        let interpreter_override = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(explicit_profile),
                OsStr::new("-v"),
            ],
            b"",
            None,
            &[],
        );
        assert!(
            interpreter_override.status.success(),
            "profile={explicit_profile}: {}",
            String::from_utf8_lossy(&interpreter_override.stderr)
        );
        assert_eq!(
            interpreter_override.stdout,
            format!(
                "RivetLua 0.0.0 (Lua {})\n",
                String::from_utf8_lossy(explicit_version)
            )
            .as_bytes()
        );

        let compiler_override = run_luac(
            &[
                OsStr::new("--profile"),
                OsStr::new(explicit_profile),
                OsStr::new("-v"),
            ],
            b"",
            None,
        );
        assert!(compiler_override.status.success());
        assert_eq!(
            compiler_override.stdout,
            format!(
                "RivetLua luac (Lua {})\n",
                String::from_utf8_lossy(explicit_version)
            )
            .as_bytes()
        );
    }

    let directory = temp_dir();
    let source = directory.join("all.lua");
    let encoded = directory.join("all.rvct");
    std::fs::write(
        &source,
        b"print(_VERSION); print(arg[-2], arg[-1], arg[0], arg[1], ...)\n",
    )
    .unwrap();
    let source_text = source.to_string_lossy().into_owned();
    let encoded_text = encoded.to_string_lossy().into_owned();
    let compiled = run_luac(
        &[
            OsStr::new("-o"),
            OsStr::new(encoded_text.as_str()),
            OsStr::new(source_text.as_str()),
        ],
        b"",
        None,
    );
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let loaded = run_lua(
        &[
            OsStr::new("-e_U=true"),
            OsStr::new(encoded_text.as_str()),
            OsStr::new("first"),
            OsStr::new("second"),
        ],
        b"",
        None,
        &[],
    );
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    let expected_args = format!(
        "{}\t-e_U=true\t{}\tfirst\tfirst\tsecond\n",
        env!("CARGO_BIN_EXE_rivetlua"),
        encoded_text,
    );
    assert!(loaded.stdout.ends_with(expected_args.as_bytes()));

    let interpreter_execution = run_lua(
        &[OsStr::new("-e"), OsStr::new("print(_VERSION)")],
        b"",
        None,
        &[],
    );
    assert!(interpreter_execution.status.success());
    let mut expected_lua_version = default_lua_version.to_vec();
    expected_lua_version.push(b'\n');
    assert_eq!(interpreter_execution.stdout, expected_lua_version);
    let _ = std::fs::remove_dir_all(directory);
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
fn cli_host_load_handles_21_short_blocks_through_load_loadfile_and_require_for_both_profiles() {
    const LOAD_SOURCE: &str = r#"local f,e=load(string.rep('do local x=1 end\n',21)); assert(type(f)=='function',e); print('loaded')"#;
    const LOADFILE_SOURCE: &str =
        "local f,e=loadfile('short.lua'); assert(type(f)=='function',e); print('loaded')";
    let short_source = b"do local x=1 end\n".repeat(21);
    assert_eq!(short_source.len(), 357);

    for profile in ["lua54", "lua55"] {
        let loaded = lua(profile, &["-e", LOAD_SOURCE]);
        assert!(
            loaded.status.success(),
            "load profile={profile}; stdout={:?}; stderr={:?}",
            loaded.stdout,
            loaded.stderr
        );
        assert_eq!(loaded.stdout, b"loaded\n", "load profile={profile}");

        let directory = temp_dir();
        std::fs::write(directory.join("short.lua"), &short_source).unwrap();
        let loadfile = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-e"),
                OsStr::new(LOADFILE_SOURCE),
            ],
            b"",
            Some(&directory),
            &[],
        );
        let _ = std::fs::remove_dir_all(directory);
        assert!(
            loadfile.status.success(),
            "loadfile profile={profile}; stdout={:?}; stderr={:?}",
            loadfile.stdout,
            loadfile.stderr
        );
        assert_eq!(loadfile.stdout, b"loaded\n", "loadfile profile={profile}");

        let directory = temp_dir();
        std::fs::write(directory.join("short.lua"), &short_source).unwrap();
        let path_variable = if profile == "lua54" {
            "LUA_PATH_5_4"
        } else {
            "LUA_PATH_5_5"
        };
        let required = run_lua(
            &[
                OsStr::new("--profile"),
                OsStr::new(profile),
                OsStr::new("-lshort"),
                OsStr::new("-eprint(short)"),
            ],
            b"",
            Some(&directory),
            &[(path_variable, "?.lua")],
        );
        let _ = std::fs::remove_dir_all(directory);
        assert!(
            required.status.success(),
            "require profile={profile}; stdout={:?}; stderr={:?}",
            required.stdout,
            required.stderr
        );
        assert_eq!(required.stdout, b"true\n", "require profile={profile}");
    }
}

#[test]
fn cli_host_load_keeps_finite_work_limit_and_allows_same_vm_retry() {
    const SOURCE: &str = "local source = string.rep('do local x=1 end\\n', 8000); assert(#source == 136000); local ok, err = pcall(function() load(source) end); assert(not ok); assert(err == 'E_HOST_LOAD_BUDGET', tostring(err)); local f = assert(load('return 42')); print(f())";

    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", SOURCE]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert_eq!(output.stdout, b"42\n", "profile={profile}");
    }
}

#[test]
#[ignore = "需明確指定 RIVETLUA_HOSTLOAD_GC55 Lua 5.5 官方 gc.lua"]
fn cli_host_loads_lua55_gc_fixture_when_explicitly_enabled() {
    let output = run_gc_loadfile_fixture("RIVETLUA_HOSTLOAD_GC55", "lua55", 19_650);
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"gc-compiled\n");
}

#[test]
#[ignore = "需明確指定 RIVETLUA_HOSTLOAD_GC54 Lua 5.4 官方 gc.lua"]
fn cli_host_loads_lua54_gc_fixture_when_explicitly_enabled() {
    let output = run_gc_loadfile_fixture("RIVETLUA_HOSTLOAD_GC54", "lua54", 18_442);
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"gc-compiled\n");
}

#[test]
#[ignore = "需要透過 RIVETLUA_HOSTLOAD_MAIN 明確指定官方 Lua 5.5 main.lua"]
fn cli_host_load_compiles_official_lua55_main_when_explicitly_enabled() {
    let main = std::env::var_os("RIVETLUA_HOSTLOAD_MAIN")
        .expect("需明確指定 RIVETLUA_HOSTLOAD_MAIN 官方 fixture 路徑");
    let main = PathBuf::from(main);
    let parent = main.parent().expect("官方 main.lua 必須有父目錄");
    assert_eq!(main.file_name(), Some(OsStr::new("main.lua")));

    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-e"),
            OsStr::new(
                "local f,e=loadfile('main.lua'); assert(type(f)=='function',e); print('main-compiled')",
            ),
        ],
        b"",
        Some(parent),
        &[],
    );
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert_eq!(output.stdout, b"main-compiled\n");
}

#[test]
#[ignore = "需明示 RIVETLUA_HOSTLOAD_DB 指向 Lua 5.5 官方 db.lua"]
fn cli_string_dump_round_trips_official_lua55_db_when_explicitly_enabled() {
    let db = std::env::var_os("RIVETLUA_HOSTLOAD_DB")
        .expect("需明確指定 RIVETLUA_HOSTLOAD_DB 官方 fixture 路徑");
    let db = PathBuf::from(db);
    assert!(db.is_absolute(), "RIVETLUA_HOSTLOAD_DB 必須是絕對路徑");
    assert_eq!(db.file_name(), Some(OsStr::new("db.lua")));
    assert!(db.is_file(), "RIVETLUA_HOSTLOAD_DB 必須指向 db.lua");
    assert_eq!(
        std::fs::metadata(&db).unwrap().len(),
        26_598,
        "官方 db.lua 大小不符：{}",
        db.display()
    );
    let parent = db.parent().expect("官方 db.lua 必須有父目錄");

    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-e"),
            OsStr::new(
                "local f,e=loadfile('db.lua'); assert(type(f)=='function',e); local b=string.dump(f); local g,de=load(b,'@db.lua','b'); assert(type(g)=='function',de); print('db-dump-roundtrip-ok')",
            ),
        ],
        b"",
        Some(parent),
        &[],
    );
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"db-dump-roundtrip-ok\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_reports_fuel_exhaustion_as_nonzero_aborted_execution() {
    for profile in ["lua54", "lua55"] {
        let output = lua(
            profile,
            &["-ewhile true do assert(load('return 9007199254740993e0')) end"],
        );
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
    std::fs::write(
        directory.join("cli_action_fixture.lua"),
        b"return { value = 4 }\n",
    )
    .unwrap();
    let script = directory.join("main.lua");
    std::fs::write(&script, b"print(result, arg[1])\n").unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua54"),
            OsStr::new("-eresult = 1"),
            OsStr::new("-lmathlib=cli_action_fixture"),
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
                OsStr::new(
                    "print = function() while true do assert(load('return 9007199254740993e0')) end end",
                ),
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
    let loaded = run_lua(
        &[OsStr::new(artifact_text.as_str())],
        b"",
        Some(&directory),
        &[],
    );
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
    let default_version = if cfg!(feature = "default-lua54") {
        b"5.4.9".as_slice()
    } else {
        b"5.5.1".as_slice()
    };
    assert_eq!(
        version.stdout,
        format!(
            "RivetLua luac (Lua {})\n",
            String::from_utf8_lossy(default_version)
        )
        .as_bytes()
    );
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

#[test]
fn cli_string_dump_round_trips_ordinary_and_stripped_closures_for_both_profiles() {
    let mut outputs = Vec::new();
    for (profile, bytecode_version) in [("lua54", 0x54), ("lua55", 0x55)] {
        let source = format!(
            r#"local function original(value) return value + 2 end
for _, strip in ipairs({{false, true}}) do
  local bytes = string.dump(original, strip)
  assert(bytes:sub(1, 4) == '\27Lua')
  assert(bytes:byte(5) == {bytecode_version})
  local restored, err = load(bytes, '@roundtrip', 'b')
  assert(type(restored) == 'function', tostring(err))
  assert(restored(40) == 42)
end
print('dump-roundtrip-ok')"#
        );
        let output = lua(profile, &["-e", source.as_str()]);
        outputs.push((profile, output));
    }
    let failures = outputs
        .iter()
        .filter(|(_, output)| !output.status.success())
        .map(|(profile, output)| {
            format!(
                "profile={profile}; stdout={:?}; stderr={}",
                output.stdout,
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .collect::<Vec<_>>();
    assert!(failures.is_empty(), "{}", failures.join("; "));
    for (profile, output) in outputs {
        assert_eq!(output.stdout, b"dump-roundtrip-ok\n", "profile={profile}");
    }
}

#[test]
fn cli_string_dump_argument_modes_profile_and_retry_for_both_profiles() {
    for (profile, bytecode_version, wrong_version) in [("lua54", 0x54, 0x55), ("lua55", 0x55, 0x54)]
    {
        let source = format!(
            r#"local function check_bad_argument(value)
  local ok, err = pcall(string.dump, value)
  assert(not ok and err == 'E_STRING_ARGUMENT', tostring(err))
end
check_bad_argument(42)
check_bad_argument(print)

local binary = string.dump(function(value) return value + 2 end)
assert(binary:sub(1, 4) == '\27Lua')
assert(binary:byte(5) == {bytecode_version})
local binary_fn, binary_error = load(binary, '@binary', 'b')
assert(type(binary_fn) == 'function', tostring(binary_error))
assert(binary_fn(40) == 42)
local rejected_binary, binary_mode_error = load(binary, '@binary', 't')
assert(rejected_binary == nil and type(binary_mode_error) == 'string')

local source_fn, source_error = load('return 40 + 2', '@text', 't')
assert(type(source_fn) == 'function', tostring(source_error))
assert(source_fn() == 42)
local rejected_source, source_mode_error = load('return 40 + 2', '@text', 'b')
assert(rejected_source == nil and type(source_mode_error) == 'string')

local wrong_header = binary:sub(1, 4) .. string.char({wrong_version}) .. binary:sub(6)
local rejected_profile, profile_error = load(wrong_header, '@wrong-profile', 'b')
assert(rejected_profile == nil and type(profile_error) == 'string')

local retry_bytes = string.dump(function(value) return value + 1 end)
local retry_fn, retry_error = load(retry_bytes, '@retry', 'b')
assert(type(retry_fn) == 'function', tostring(retry_error))
assert(retry_fn(41) == 42)
print('dump-contracts-ok')"#
        );
        let output = lua(profile, &["-e", source.as_str()]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={}",
            output.stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"dump-contracts-ok\n", "profile={profile}");
    }
}

#[test]
#[ignore = "需要透過 RIVETLUA_HOSTLOAD_MAIN 明確指定官方 Lua 5.5 main.lua"]
fn cli_string_dump_round_trips_official_lua55_main_when_explicitly_enabled() {
    let main = std::env::var_os("RIVETLUA_HOSTLOAD_MAIN")
        .expect("需明確指定 RIVETLUA_HOSTLOAD_MAIN 官方 fixture 路徑");
    let main = PathBuf::from(main);
    let parent = main.parent().expect("官方 main.lua 必須有父目錄");
    assert_eq!(main.file_name(), Some(OsStr::new("main.lua")));

    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-e"),
            OsStr::new(
                "local f,e=loadfile('main.lua'); assert(type(f)=='function',e); local ordinary=string.dump(f); local g,de=load(ordinary,'@main.lua','b'); assert(type(g)=='function',de); local stripped=string.dump(f,true); local h,se=load(stripped,'@main.lua','b'); assert(type(h)=='function',se); print('main-dump-ok')",
            ),
        ],
        b"",
        Some(parent),
        &[],
    );
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert_eq!(output.stdout, b"main-dump-ok\n");
}

#[test]
fn cli_debug_table_metatable_write_preserves_registry_identity_for_both_profiles() {
    const SOURCE: &str = r#"local debug = require('debug')
assert(debug == require('debug'))
assert(package.loaded.debug == debug)
local math_module = require('math')
assert(math_module == math and package.loaded.math == math)
print('registry-ok')

local value = {}
local initial = {__index = {marker = 'initial'}}
assert(debug.setmetatable(value, initial) == value)
assert(value.marker == 'initial')

local locked = {__index = {marker = 'replacement'}, __metatable = 'locked'}
assert(debug.setmetatable(value, locked) == value)
assert(value.marker == 'replacement')
assert(getmetatable(value) == 'locked')
assert(not pcall(setmetatable, value, {}))

local bypass = {__index = {marker = 'bypassed'}}
assert(debug.setmetatable(value, bypass) == value)
assert(value.marker == 'bypassed')
assert(debug.setmetatable(value, nil) == value)
assert(getmetatable(value) == nil and value.marker == nil)
print('metatable-ok')"#;

    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", SOURCE]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={}",
            output.stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout, b"registry-ok\nmetatable-ok\n",
            "profile={profile}"
        );
    }
}

#[test]
fn cli_debug_gethook_is_allowed_for_both_profiles() {
    const SOURCE: &str = "assert(debug.gethook() == nil); print('debug-gethook-ok')";

    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", SOURCE]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={}",
            output.stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"debug-gethook-ok\n", "profile={profile}");
    }
}

#[test]
fn cli_debug_policy_rejects_unimplemented_ops_and_restricts_table_metatable_write() {
    const SOURCE: &str = r#"local debug = require('debug')
local function target() return 42 end
local unsupported = {
  function() return debug.debug() end
}
for _, operation in ipairs(unsupported) do
  local ok, err = pcall(operation)
  assert(not ok and err == 'E_HOST_POLICY_DEBUG', tostring(err))
end

local function check_error(expected, ...)
  local ok, err = pcall(debug.setmetatable, ...)
  assert(not ok and err == expected, tostring(err))
end
check_error('E_DEBUG_ARGUMENT', 42, {})
check_error('E_DEBUG_ARGUMENT', false, {})
check_error('E_DEBUG_ARGUMENT', nil, {})
check_error('E_HOST_POLICY_DEBUG', 'text', {})
check_error('E_HOST_POLICY_DEBUG', target, {})
check_error('E_HOST_POLICY_DEBUG', coroutine.create(function() end), {})
check_error('E_DEBUG_ARGUMENT', {}, false)
check_error('E_DEBUG_ARGUMENT')

local value = {}
assert(debug.setmetatable(value, {__index = {answer = 42}}) == value)
assert(value.answer == 42)
print('retry-ok')"#;

    for profile in ["lua54", "lua55"] {
        let output = lua(profile, &["-e", SOURCE]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={}",
            output.stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"retry-ok\n", "profile={profile}");

        let setcstack_source = match profile {
            "lua54" => {
                "assert(type(debug.setcstacklimit) == 'function'); local ok, err = pcall(debug.setcstacklimit, 1024); assert(not ok and err == 'E_HOST_POLICY_DEBUG')"
            }
            "lua55" => {
                "assert(debug.setcstacklimit == nil); local ok, err = pcall(debug.setcstacklimit, 1024); assert(not ok and err == 'E_CALL_NON_FUNCTION')"
            }
            _ => unreachable!(),
        };
        let output = lua(profile, &["-e", setcstack_source]);
        assert!(
            output.status.success(),
            "profile={profile}; stdout={:?}; stderr={}",
            output.stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "需透過 RIVETLUA_TRACEGC_DIR 明確指定 Lua 5.5 官方 fixture 目錄"]
fn cli_debug_table_metatable_write_starts_lua55_tracegc_fixture_when_explicitly_enabled() {
    let directory = std::env::var_os("RIVETLUA_TRACEGC_DIR")
        .expect("需明確指定 RIVETLUA_TRACEGC_DIR 官方 fixture 目錄");
    let directory = PathBuf::from(directory);
    assert!(directory.join("tracegc.lua").is_file());

    let output = run_lua(
        &[
            OsStr::new("--profile"),
            OsStr::new("lua55"),
            OsStr::new("-e"),
            OsStr::new(
                "local tracegc = require('tracegc'); tracegc.start(); print('tracegc-started')",
            ),
        ],
        b"",
        Some(&directory),
        &[],
    );
    assert!(
        output.status.success(),
        "stdout={:?}; stderr={}",
        output.stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"tracegc-started\n");
}
