use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rivetlua::{ContainerLimits, Engine, LuaProfile, TransportBudget};

fn profiles() -> Vec<(&'static str, LuaProfile, &'static str)> {
    match std::env::var("RIVETLUA_P14_PROFILE").ok().as_deref() {
        Some("lua55-i64f64") => vec![("lua55", LuaProfile::Lua55, "lua55-i64f64")],
        Some("lua54-i64f64") => vec![("lua54", LuaProfile::Lua54, "lua54-i64f64")],
        None => vec![
            ("lua55", LuaProfile::Lua55, "lua55-i64f64"),
            ("lua54", LuaProfile::Lua54, "lua54-i64f64"),
        ],
        Some(other) => panic!("未知 P14 profile：{other}"),
    }
}

fn emit(id: &str, profile: &str, actual: &str, trace: &str) {
    assert!(!trace.is_empty());
    println!(
        "P14_CASE\t{id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted\tallocation=not-applicable\tresource=temporary-files-scoped\tvm={profile}\tcli={trace}"
    );
}

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rivetlua-p14-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

struct TempCleanup(PathBuf);

impl Drop for TempCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn lua(profile: &str, args: &[&str]) -> std::process::Output {
    clean_lua_env(&mut Command::new(env!("CARGO_BIN_EXE_rivetlua")))
        .arg("--profile")
        .arg(profile)
        .args(args)
        .output()
        .unwrap()
}

fn clean_lua_env(command: &mut Command) -> &mut Command {
    for key in [
        "LUA_INIT",
        "LUA_INIT_5_4",
        "LUA_INIT_5_5",
        "LUA_PATH",
        "LUA_PATH_5_4",
        "LUA_PATH_5_5",
        "LUA_CPATH",
        "LUA_CPATH_5_4",
        "LUA_CPATH_5_5",
    ] {
        command.env_remove(key);
    }
    command
}

fn saved(profile: LuaProfile) -> Vec<u8> {
    let engine = Engine::new(profile);
    let module = engine.compile(b"print(42)").unwrap();
    engine
        .save_module(&module, &TransportBudget::new(ContainerLimits::default()))
        .unwrap()
}

#[test]
fn cli_case_006() {
    for (profile, lua_profile, label) in profiles() {
        let bad_lua = lua(profile, &["-e", "error('p14-lua-error')"]);
        assert!(!bad_lua.status.success());
        let lua_exit = bad_lua
            .status
            .code()
            .expect("CLI LuaError 不應被 signal 終止");
        assert_ne!(lua_exit, 0);
        assert!(
            bad_lua
                .stderr
                .windows(13)
                .any(|part| part == b"p14-lua-error")
        );
        let dir = temp_dir("error");
        let _cleanup = TempCleanup(dir.clone());
        let binary = dir.join("bad.rvct");
        let mut bytes = saved(lua_profile);
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&binary, bytes).unwrap();
        let bad_codec = lua(profile, &[binary.to_str().unwrap()]);
        assert!(!bad_codec.status.success());
        let codec_exit = bad_codec
            .status
            .code()
            .expect("CLI codec error 不應被 signal 終止");
        assert_ne!(codec_exit, 0);
        assert!(bad_codec.stderr.windows(4).any(|part| part == b"RVCT"));
        emit(
            "SDK-006",
            label,
            "lua+codec:nonzero",
            &format!("lua-exit={lua_exit},codec-exit={codec_exit}"),
        );
    }
}

fn installed_bin(root: &Path, name: &str) -> PathBuf {
    root.join("bin")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

#[test]
fn cli_case_007() {
    for (profile, _, label) in profiles() {
        let prefix = temp_dir("install");
        let _cleanup = TempCleanup(prefix.clone());
        let bin = prefix.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let lua_sentinel = installed_bin(&prefix, "lua");
        let luac_sentinel = installed_bin(&prefix, "luac");
        fs::write(&lua_sentinel, b"P14_SYSTEM_LUA_SENTINEL\n").unwrap();
        fs::write(&luac_sentinel, b"P14_SYSTEM_LUAC_SENTINEL\n").unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut install = Command::new("cargo");
        install
            .args([
                "install",
                "--force",
                "--debug",
                "--locked",
                "--offline",
                "--path",
                "crates/rivetlua-cli",
                "--root",
            ])
            .arg(&prefix)
            .current_dir(&workspace);
        if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
            install.env("CARGO_TARGET_DIR", target);
        }
        let output = install.output().unwrap();
        assert!(
            output.status.success(),
            "cargo install 失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(&lua_sentinel).unwrap(),
            b"P14_SYSTEM_LUA_SENTINEL\n"
        );
        assert_eq!(
            fs::read(&luac_sentinel).unwrap(),
            b"P14_SYSTEM_LUAC_SENTINEL\n"
        );
        let mut names: Vec<_> = fs::read_dir(&bin)
            .unwrap()
            .map(|item| item.unwrap().file_name())
            .collect();
        names.sort();
        let mut expected = vec![
            OsString::from(format!("lua{}", std::env::consts::EXE_SUFFIX)),
            OsString::from(format!("luac{}", std::env::consts::EXE_SUFFIX)),
            OsString::from(format!("rivetlua{}", std::env::consts::EXE_SUFFIX)),
            OsString::from(format!("rivetluac{}", std::env::consts::EXE_SUFFIX)),
        ];
        expected.sort();
        assert_eq!(names, expected);
        let interpreter = clean_lua_env(&mut Command::new(installed_bin(&prefix, "rivetlua")))
            .args(["--profile", profile, "-e", "print(42)"])
            .output()
            .unwrap();
        assert!(interpreter.status.success());
        assert_eq!(interpreter.stdout, b"42\n");
        let compiler = clean_lua_env(&mut Command::new(installed_bin(&prefix, "rivetluac")))
            .args(["--profile", profile, "-v"])
            .output()
            .unwrap();
        assert!(compiler.status.success());
        let source = prefix.join("install-smoke.lua");
        let output_path = prefix.join("install-smoke.rvct");
        fs::write(&source, b"print(42)\n").unwrap();
        let compile = clean_lua_env(&mut Command::new(installed_bin(&prefix, "rivetluac")))
            .args([
                "--profile",
                profile,
                "-o",
                output_path.to_str().unwrap(),
                source.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "安裝的 compiler 失敗：{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        assert!(fs::read(&output_path).unwrap().starts_with(b"RVCT"));
        let compiled_run = clean_lua_env(&mut Command::new(installed_bin(&prefix, "rivetlua")))
            .args(["--profile", profile, output_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(compiled_run.status.success());
        assert_eq!(compiled_run.stdout, b"42\n");
        let trace = format!(
            "cmd=cargo install --force --debug --locked --offline --path crates/rivetlua-cli --root {};cwd={};exit=0;bin=lua,luac,rivetlua,rivetluac;sentinels=P14_SYSTEM_LUA_SENTINEL,P14_SYSTEM_LUAC_SENTINEL;rvct-run=42",
            prefix.display(),
            workspace.display()
        );
        emit("SDK-007", label, "install:rivet-only", &trace);
    }
}

#[test]
fn cli_case_neg_005() {
    for (profile, lua_profile, label) in profiles() {
        let dir = temp_dir("decoy");
        let _cleanup = TempCleanup(dir.clone());
        let source_file = dir.join("probe.rs");
        let marker = dir.join("decoy-was-run");
        fs::write(&source_file, "fn main() { std::fs::write(std::env::var_os(\"P14_DECOY_MARKER\").unwrap(), b\"executed\").unwrap(); std::process::exit(77); }\n").unwrap();
        let decoy_lua = installed_bin(&dir, "lua");
        let decoy_luac = installed_bin(&dir, "luac");
        fs::create_dir_all(dir.join("bin")).unwrap();
        let build = Command::new("rustc")
            .args([
                "--edition=2021",
                source_file.to_str().unwrap(),
                "-o",
                decoy_lua.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "decoy rustc 失敗：{}",
            String::from_utf8_lossy(&build.stderr)
        );
        fs::copy(&decoy_lua, &decoy_luac).unwrap();
        let mut paths = vec![dir.join("bin")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let path = std::env::join_paths(paths).unwrap();
        let source = dir.join("source.lua");
        let raw = dir.join("raw.rvlu");
        let rvct = dir.join("container.rvct");
        let official = dir.join("official.luac");
        fs::write(&source, b"print(42)\n").unwrap();
        let transport = saved(lua_profile);
        let rvlu_len = u64::from_le_bytes(transport[16..24].try_into().unwrap()) as usize;
        fs::write(&raw, &transport[40..40 + rvlu_len]).unwrap();
        fs::write(&rvct, transport).unwrap();
        let official_bytes: &[u8] = match lua_profile {
            LuaProfile::Lua54 => include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-small-return.luac"
            ),
            LuaProfile::Lua55 => include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-small-return.luac"
            ),
        };
        fs::write(&official, official_bytes).unwrap();
        for (input, expected) in [
            (&source, b"42\n".as_slice()),
            (&raw, b"42\n"),
            (&rvct, b"42\n"),
            (&official, b"".as_slice()),
        ] {
            let output = clean_lua_env(&mut Command::new(env!("CARGO_BIN_EXE_rivetlua")))
                .env("PATH", &path)
                .env("P14_DECOY_MARKER", &marker)
                .args(["--profile", profile, input.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "輸入 {} 失敗：{}",
                input.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, expected);
            assert!(!marker.exists(), "系統 Lua decoy 被啟動");
        }
        let syntax = clean_lua_env(&mut Command::new(env!("CARGO_BIN_EXE_rivetluac")))
            .env("PATH", path)
            .env("P14_DECOY_MARKER", &marker)
            .args(["--profile", profile, "-p", source.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(syntax.status.success());
        assert!(!marker.exists(), "系統 luac decoy 被啟動");
        emit(
            "SDK-NEG-005",
            label,
            "decoy:untouched",
            "rustc-executable-decoys;source+raw+official+rvct+compiler;marker=absent",
        );
    }
}

#[test]
fn cli_case_neg_006() {
    for (profile, _, label) in profiles() {
        let output = lua(profile, &["-e", "error('must fail')"]);
        assert!(!output.status.success());
        let code = output.status.code().expect("錯誤腳本不應被 signal 終止");
        assert_ne!(code, 0);
        assert!(!output.stderr.is_empty());
        emit(
            "SDK-NEG-006",
            label,
            "failure:nonzero",
            &format!("lua-error-exit={code}"),
        );
    }
}
