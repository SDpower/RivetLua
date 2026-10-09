//! P00 階段驗證工具。

mod p15;
mod p16;

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MSRV: &str = "1.94.1";

fn supported_rustc(actual: &str) -> bool {
    fn version_parts(version: &str) -> Option<[u64; 3]> {
        let parts = version
            .split('.')
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
            .ok()?;
        <[u64; 3]>::try_from(parts).ok()
    }
    let Some(actual_version) = actual.split_whitespace().nth(1).and_then(version_parts) else {
        return false;
    };
    version_parts(MSRV).is_some_and(|minimum| actual_version >= minimum)
}
static VERIFY_COUNTER: AtomicUsize = AtomicUsize::new(0);
static GATE_REPORT_WRITTEN: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct GateResult {
    name: String,
    command: String,
    exit_code: i32,
    status: &'static str,
    diagnostic: String,
    report_path: String,
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn write_gate_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P00.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let entries = results.iter().map(|item| format!("{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}", json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status, json_escape(&item.diagnostic), json_escape(&item.report_path))).collect::<Vec<_>>().join(",");
    if fs::write(
        path,
        format!("{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{entries}]}}\n"),
    )
    .is_ok()
    {
        GATE_REPORT_WRITTEN.store(true, Ordering::Relaxed);
    }
}

fn write_early_gate_failure(root: &Path, diagnostic: &str) {
    write_gate_results(
        root,
        &[GateResult {
            name: "gate".into(),
            command: "cargo run --locked -p rivetlua-xtask -- gate P00".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: diagnostic.into(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        }],
    );
}

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    version: &'static str,
    source_sha: &'static str,
    tests_sha: &'static str,
    source: &'static str,
    tests: &'static str,
    source_dir: &'static str,
    tests_dir: &'static str,
}

const LUA55: Profile = Profile {
    name: "lua55",
    version: "5.5.1",
    source_sha: "1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce",
    tests_sha: "da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31",
    source: "vendor/lua55/source.tar.gz",
    tests: "vendor/lua55/tests.tar.gz",
    source_dir: "lua-5.5.1",
    tests_dir: "lua-5.5.1-tests",
};
const LUA54: Profile = Profile {
    name: "lua54",
    version: "5.4.9",
    source_sha: "2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6",
    tests_sha: "7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca",
    source: "vendor/lua54/source.tar.gz",
    tests: "vendor/lua54/tests.tar.gz",
    source_dir: "lua-5.4.9",
    tests_dir: "lua-5.4.9-tests",
};

fn profile(name: &str) -> Result<Profile, String> {
    match name {
        "lua55" => Ok(LUA55),
        "lua54" => Ok(LUA54),
        _ => Err(format!("不支援的 lua_profile：{name}")),
    }
}
fn root() -> Result<PathBuf, String> {
    let root = env::current_dir().map_err(|e| e.to_string())?;
    root.join("Cargo.toml")
        .is_file()
        .then_some(root)
        .ok_or_else(|| "必須在 workspace 根目錄執行 xtask".into())
}
fn run(program: &str, args: &[&str], cwd: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("無法執行 {program}：{e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "{program} {:?} 退出 {:?}：{text}",
            args,
            output.status.code()
        ))
    }
}

fn sha256_tool(os: &str) -> Result<(&'static str, &'static [&'static str]), String> {
    match os {
        "macos" => Ok(("shasum", &["-a", "256"])),
        "linux" => Ok(("sha256sum", &[])),
        _ => Err(format!("不支援的 SHA-256 平台：{os}")),
    }
}

fn source_digest(root: &Path) -> Result<String, String> {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::process::Stdio;

    let listed = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("列出來源檔失敗：{error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "列出來源檔失敗：git exit={:?}",
            listed.status.code()
        ));
    }
    let mut paths = listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();

    let (program, prefix) = sha256_tool(env::consts::OS)?;
    let mut process = Command::new(program)
        .args(prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("啟動來源 SHA-256 失敗：{error}"))?;
    {
        let mut input = process.stdin.take().ok_or("來源 SHA-256 缺少 stdin")?;
        input
            .write_all(b"RivetLua-source-digest-v1\0")
            .map_err(|error| error.to_string())?;
        for path in paths {
            let relative = std::ffi::OsString::from_vec(path.to_vec());
            let absolute = root.join(relative);
            input
                .write_all(&(path.len() as u64).to_be_bytes())
                .map_err(|error| error.to_string())?;
            input.write_all(path).map_err(|error| error.to_string())?;
            match fs::symlink_metadata(&absolute) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    input.write_all(b"M").map_err(|error| error.to_string())?;
                }
                Err(error) => {
                    return Err(format!(
                        "讀取來源檔型別失敗 {}：{error}",
                        absolute.display()
                    ));
                }
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let target = fs::read_link(&absolute).map_err(|error| {
                        format!("讀取 symlink 失敗 {}：{error}", absolute.display())
                    })?;
                    let bytes = target.as_os_str().as_bytes();
                    input.write_all(b"L").map_err(|error| error.to_string())?;
                    input
                        .write_all(&(bytes.len() as u64).to_be_bytes())
                        .map_err(|error| error.to_string())?;
                    input.write_all(bytes).map_err(|error| error.to_string())?;
                }
                Ok(metadata) if metadata.is_file() => {
                    let bytes = fs::read(&absolute).map_err(|error| {
                        format!("讀取來源檔失敗 {}：{error}", absolute.display())
                    })?;
                    input.write_all(b"F").map_err(|error| error.to_string())?;
                    input
                        .write_all(&(bytes.len() as u64).to_be_bytes())
                        .map_err(|error| error.to_string())?;
                    input.write_all(&bytes).map_err(|error| error.to_string())?;
                }
                Ok(metadata) if metadata.is_dir() => {
                    input.write_all(b"D").map_err(|error| error.to_string())?;
                }
                Ok(_) => {
                    input.write_all(b"O").map_err(|error| error.to_string())?;
                }
            }
        }
    }
    let output = process
        .wait_with_output()
        .map_err(|error| format!("等待來源 SHA-256 失敗：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "來源 SHA-256 失敗：{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("來源 SHA-256 輸出不是 64 位 hex".into());
    }
    Ok(digest)
}

fn validate_report_source_digest(
    phase: &str,
    parsed: &StrictJsonValue,
    current: &str,
) -> Result<(), String> {
    let reported = parsed
        .get("source_digest")
        .and_then(StrictJsonValue::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            format!("{phase} 前置 gate 報告缺少合法 source_digest；請重跑 gate {phase}")
        })?;
    if reported != current {
        return Err(format!(
            "{phase} 前置 gate 報告 source_digest 已過期；請重跑 gate {phase}"
        ));
    }
    Ok(())
}

fn reference_make_target(os: &str) -> Result<&'static str, String> {
    match os {
        "macos" => Ok("macosx"),
        "linux" => Ok("linux"),
        _ => Err(format!("不支援的參考程式建置平台：{os}")),
    }
}

fn hash(root: &Path, relative: &str, expected: &str) -> Result<(), String> {
    if !root.join(relative).is_file() {
        return Err(format!("缺少離線快照：{relative}"));
    }
    let (program, prefix) = sha256_tool(env::consts::OS)?;
    let mut args = prefix.to_vec();
    args.push(relative);
    let output = run(program, &args, root)?;
    (output.split_whitespace().next() == Some(expected))
        .then_some(())
        .ok_or_else(|| format!("SHA-256 不符：{relative}"))
}
fn verify(root: &Path, profile: Profile) -> Result<(), String> {
    hash(root, profile.source, profile.source_sha)?;
    hash(root, profile.tests, profile.tests_sha)?;
    let nonce = VERIFY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let verify_root = root.join("target/rivetlua-verify").join(format!(
        "{}-{}-{nonce}",
        profile.name,
        std::process::id()
    ));
    fs::create_dir_all(&verify_root).map_err(|error| error.to_string())?;
    let archive = root.join(profile.source);
    run(
        "tar",
        &[
            "-xzf",
            archive.to_str().ok_or("無法表示 source archive")?,
            "-C",
            verify_root.to_str().ok_or("無法表示 verify path")?,
        ],
        root,
    )?;
    run(
        "diff",
        &[
            "-qr",
            "-x",
            ".gitkeep",
            root.join("vendor")
                .join(profile.name)
                .join(profile.source_dir)
                .to_str()
                .ok_or("無法表示 vendor source")?,
            verify_root
                .join(profile.source_dir)
                .to_str()
                .ok_or("無法表示 extracted source")?,
        ],
        root,
    )?;
    let tests_archive = root.join(profile.tests);
    run(
        "tar",
        &[
            "-xzf",
            tests_archive.to_str().ok_or("無法表示 tests archive")?,
            "-C",
            verify_root.to_str().ok_or("無法表示 verify path")?,
        ],
        root,
    )?;
    run(
        "diff",
        &[
            "-qr",
            "-x",
            ".gitkeep",
            root.join("vendor")
                .join(profile.name)
                .join(profile.tests_dir)
                .to_str()
                .ok_or("無法表示 vendor tests")?,
            verify_root
                .join(profile.tests_dir)
                .to_str()
                .ok_or("無法表示 extracted tests")?,
        ],
        root,
    )?;
    let vendor = root.join("vendor").join(profile.name);
    if !vendor.join(profile.source_dir).join("README").is_file()
        || !vendor.join(profile.tests_dir).is_dir()
    {
        return Err(format!("{} 的解壓快照或授權不完整", profile.name));
    }
    Ok(())
}
fn build(root: &Path, profile: Profile) -> Result<PathBuf, String> {
    verify(root, profile)?;
    let nonce = VERIFY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let destination = root.join("target/rivetlua-reference").join(format!(
        "{}-{}-{nonce}",
        profile.name,
        std::process::id()
    ));
    fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
    let archive = root.join(profile.source);
    run(
        "tar",
        &[
            "-xzf",
            archive.to_str().ok_or("無法表示來源路徑")?,
            "-C",
            destination.to_str().ok_or("無法表示目標路徑")?,
        ],
        root,
    )?;
    let source = destination.join(profile.source_dir);
    run("make", &[reference_make_target(env::consts::OS)?], &source)?;
    let version = run("./src/lua", &["-v"], &source)?;
    if !version.contains(&format!("Lua {}", profile.version)) {
        return Err(format!("{} 參考程式版本不符：{version}", profile.name));
    }
    Ok(source.join("src/lua"))
}
fn reference(arguments: &[String]) -> Result<(), String> {
    let name = arguments
        .windows(2)
        .find_map(|pair| (pair[0] == "--profile").then(|| pair[1].as_str()))
        .ok_or("reference 必須指定 --profile lua55|lua54")?;
    let root = root()?;
    let selected = profile(name)?;
    let interpreter = build(&root, selected)?;
    println!(
        "profile={} version={} interpreter={}",
        selected.name,
        selected.version,
        interpreter.display()
    );
    Ok(())
}

fn argument<'a>(arguments: &'a [String], flag: &str) -> Result<&'a str, String> {
    arguments
        .windows(2)
        .find_map(|pair| (pair[0] == flag).then(|| pair[1].as_str()))
        .ok_or_else(|| format!("runner 必須指定 {flag}"))
}

fn write_report(
    root: &Path,
    case_id: &str,
    profile: Profile,
    status: &str,
    exit_code: i32,
    reference_version: &str,
    diagnostic: &str,
) -> Result<PathBuf, String> {
    let directory = root.join("target/rivetlua-reports");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let path = directory.join(format!("{case_id}-{}.json", profile.name));
    let command = format!(
        "rivetlua-xtask runner --profile {} --case {case_id}",
        profile.name
    );
    let source = format!("{};{}", profile.source_sha, profile.tests_sha);
    let json = format!(
        "{{\n  \"case_id\": \"{}\",\n  \"lua_profile\": \"{}\",\n  \"mode\": \"reference\",\n  \"status\": \"{}\",\n  \"command\": \"{}\",\n  \"exit_code\": {},\n  \"reference_version\": \"{}\",\n  \"source_sha256\": \"{}\",\n  \"report_path\": \"{}\",\n  \"diagnostic\": \"{}\"\n}}\n",
        json_escape(case_id),
        json_escape(profile.name),
        json_escape(status),
        json_escape(&command),
        exit_code,
        json_escape(reference_version),
        json_escape(&source),
        json_escape(&path.display().to_string()),
        json_escape(diagnostic),
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn fixture_path(case_id: &str) -> Result<&'static str, String> {
    match case_id {
        "P00-RUN-001" | "P00-RUN-002" => Ok("tests/p00/fixtures/normal.fixture"),
        "P00-SUP-001" => Ok("tests/p00/fixtures/missing-sha.fixture"),
        "P00-REF-003" => Ok("tests/p00/fixtures/wrong-version.fixture"),
        "P00-RUN-003" => Ok("tests/p00/fixtures/wrong-output.fixture"),
        "P00-RUN-004" => Ok("tests/p00/fixtures/early-exit.fixture"),
        _ => Err(format!("未知 P00 runner case：{case_id}")),
    }
}

fn fixture_value(contents: &str, name: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.split_once('=')
            .and_then(|(key, value)| (key == name).then(|| value.to_owned()))
    })
}

fn runner(arguments: &[String]) -> Result<(), String> {
    let selected = profile(argument(arguments, "--profile")?)?;
    let case_id = argument(arguments, "--case")?;
    let root = root()?;
    let result = (|| -> Result<String, String> {
        let fixture = fs::read_to_string(root.join(fixture_path(case_id)?))
            .map_err(|error| error.to_string())?;
        if fixture_value(&fixture, "complete").as_deref() != Some("true") {
            return Err("fixture 宣告 runner 未完整執行".into());
        }
        let expected_sha = fixture_value(&fixture, "source_sha256")
            .ok_or("fixture 缺少必要 source_sha256")?
            .replace(
                "PROFILE",
                &format!("{};{}", selected.source_sha, selected.tests_sha),
            );
        if expected_sha != format!("{};{}", selected.source_sha, selected.tests_sha) {
            return Err("fixture 的來源雜湊不符".into());
        }
        let interpreter = build(&root, selected)?;
        let version = run(
            interpreter.to_str().ok_or("無法表示 interpreter")?,
            &["-v"],
            &root,
        )?;
        let expected_version = fixture_value(&fixture, "expected_version")
            .ok_or("fixture 缺 expected_version")?
            .replace("PROFILE", selected.version);
        let actual_version = version
            .strip_prefix("Lua ")
            .and_then(|value| value.split_whitespace().next())
            .ok_or_else(|| format!("無法解析參考程式版本：{version}"))?;
        if actual_version != expected_version {
            return Err(format!("參考程式版本不符：實際 {version}"));
        }
        let output = run(
            interpreter.to_str().ok_or("無法表示 interpreter")?,
            &["tests/p00/cases/reference-output.lua"],
            &root,
        )?;
        if output.trim()
            != fixture_value(&fixture, "expected_output")
                .as_deref()
                .ok_or("fixture 缺 expected_output")?
        {
            return Err(format!("預期與實際輸出不符：{output}"));
        }
        Ok(version.trim().to_owned())
    })();
    match result {
        Ok(reference_version) => {
            let path = write_report(
                &root,
                case_id,
                selected,
                "PASS",
                0,
                &reference_version,
                "完整執行且預期相符",
            )?;
            println!("PASS report={}", path.display());
            Ok(())
        }
        Err(error) => {
            let path = write_report(
                &root,
                case_id,
                selected,
                "FAIL",
                1,
                "未取得；驗證失敗",
                &error,
            )?;
            eprintln!("FAIL report={}", path.display());
            Err(error)
        }
    }
}

fn required_file(root: &Path, path: &str) -> Result<(), String> {
    root.join(path)
        .is_file()
        .then_some(())
        .ok_or_else(|| format!("缺少必要檔案：{path}"))
}

fn scan_dependency_tree(root: &Path) -> Result<(), String> {
    let tree = run("cargo", &["tree", "--locked", "--workspace"], root)?;
    if tree.contains(" mlua ") || tree.contains(" lua-sys ") {
        return Err("正式依賴樹含 Lua runtime crate".into());
    }
    Ok(())
}

fn scan_lua_symbols(root: &Path) -> Result<(), String> {
    let binary = root.join("target/debug/rivetlua-xtask");
    if !binary.is_file() {
        return Err("缺少正式 xtask binary".into());
    }
    let output = run(
        "nm",
        &["-g", binary.to_str().ok_or("無法表示 binary 路徑")?],
        root,
    )?;
    if contains_lua_engine_symbol(&output) {
        return Err("正式 Rust binary 定義官方 Lua engine 符號".into());
    }
    Ok(())
}

fn contains_lua_engine_symbol(output: &str) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split_whitespace().rev();
        let symbol = fields.next();
        let kind = fields.next();
        kind == Some("T")
            && matches!(
                symbol,
                Some("_lua_newstate" | "_luaL_newstate" | "lua_newstate" | "luaL_newstate")
            )
    })
}

fn validate_csv(contents: &str) -> Result<(), String> {
    let mut identities = std::collections::HashSet::new();
    let header = "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference";
    if contents.lines().next() != Some(header) {
        return Err("compatibility.csv header 不符".into());
    }
    for (index, line) in contents.lines().skip(1).enumerate() {
        let columns: Vec<_> = line.split(',').collect();
        if columns.len() != 7
            || columns[0].is_empty()
            || columns[1].is_empty()
            || columns[2].is_empty()
            || columns[3].is_empty()
            || columns[5].is_empty()
        {
            return Err(format!("compatibility.csv 第 {} 列欄位不正確", index + 2));
        }
        if !matches!(columns[1], "lua55" | "lua54" | "common") {
            return Err(format!(
                "compatibility.csv 第 {} 列 profile 不合法",
                index + 2
            ));
        }
        if !identities.insert((columns[0], columns[1])) {
            return Err(format!(
                "compatibility.csv 第 {} 列 feature_id/profile 重複",
                index + 2
            ));
        }
        if !matches!(
            columns[5],
            "PASS"
                | "FAIL"
                | "EXPECTED_SKIP"
                | "UNEXPECTED_SKIP"
                | "UPSTREAM_FAILURE"
                | "POLICY_DENIED"
                | "NOT_IMPLEMENTED"
        ) {
            return Err(format!(
                "compatibility.csv 第 {} 列 status 不合法",
                index + 2
            ));
        }
        if columns[5] == "PASS" && columns[4].is_empty() {
            return Err(format!(
                "compatibility.csv 第 {} 列 PASS 缺 case",
                index + 2
            ));
        }
        if columns[5] == "PASS" {
            if columns[0].starts_with("p01.")
                || columns[0].starts_with("p02.")
                || columns[0].starts_with("p03.")
                || columns[0].starts_with("p04.")
                || columns[0].starts_with("p05.")
                || columns[0].starts_with("p06.")
                || columns[0].starts_with("p07.")
                || columns[0].starts_with("p08.")
                || columns[0].starts_with("p09.")
                || columns[0].starts_with("p10.")
                || columns[0].starts_with("p11.")
                || columns[0].starts_with("p12.")
                || columns[0].starts_with("p13.")
                || columns[0].starts_with("p14.")
            {
                continue;
            }
            for case in columns[4].split(';') {
                if !matches!(
                    case,
                    "P00-IND-001" | "P00-REF-001" | "P00-REF-002" | "P00-RUN-001" | "P00-RUN-002"
                ) {
                    return Err(format!(
                        "compatibility.csv 第 {} 列 PASS 使用未知 case：{case}",
                        index + 2
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_pass_evidence(csv: &str, results: &[GateResult]) -> Result<(), String> {
    for line in csv.lines().skip(1) {
        let columns: Vec<_> = line.split(',').collect();
        if columns.len() != 7 || columns[5] != "PASS" {
            continue;
        }
        if columns[0].starts_with("p01.")
            || columns[0].starts_with("p02.")
            || columns[0].starts_with("p03.")
            || columns[0].starts_with("p04.")
            || columns[0].starts_with("p05.")
            || columns[0].starts_with("p06.")
            || columns[0].starts_with("p07.")
            || columns[0].starts_with("p08.")
            || columns[0].starts_with("p09.")
            || columns[0].starts_with("p10.")
            || columns[0].starts_with("p11.")
            || columns[0].starts_with("p12.")
            || columns[0].starts_with("p13.")
            || columns[0].starts_with("p14.")
        {
            continue;
        }
        for case in columns[4].split(';') {
            if matches!(case, "P00-RUN-001" | "P00-RUN-002") {
                let expected = format!("{case}-{}", columns[1]);
                if !results
                    .iter()
                    .any(|result| result.name == expected && result.status == "PASS")
                {
                    return Err(format!("CSV PASS 缺本次執行證據：{expected}"));
                }
            }
            if case == "P00-REF-001" {
                for expected in ["sources-lua55", "P00-RUN-001-lua55"] {
                    if !results
                        .iter()
                        .any(|result| result.name == expected && result.status == "PASS")
                    {
                        return Err(format!("CSV PASS 缺本次執行證據：{expected}"));
                    }
                }
            }
            if case == "P00-REF-002" {
                for expected in ["sources-lua54", "P00-RUN-001-lua54"] {
                    if !results
                        .iter()
                        .any(|result| result.name == expected && result.status == "PASS")
                    {
                        return Err(format!("CSV PASS 缺本次執行證據：{expected}"));
                    }
                }
            }
            if case == "P00-IND-001" {
                for expected in ["governance", "toolchain", "rustc"] {
                    if !results
                        .iter()
                        .any(|result| result.name == expected && result.status == "PASS")
                    {
                        return Err(format!("CSV PASS 缺本次執行證據：{expected}"));
                    }
                }
            }
            if !matches!(
                case,
                "P00-IND-001" | "P00-REF-001" | "P00-REF-002" | "P00-RUN-001" | "P00-RUN-002"
            ) {
                return Err(format!("CSV PASS 無法追溯未知 case：{case}"));
            }
        }
    }
    Ok(())
}

fn abi_evidence_check(root: &Path, report_path: &str, evidence_path: &str) -> Result<(), String> {
    let report = fs::read_to_string(root.join(report_path)).map_err(|error| error.to_string())?;
    let evidence =
        fs::read_to_string(root.join(evidence_path)).map_err(|error| error.to_string())?;
    if !report.contains("拒絕設計")
        || !report.contains("不建立、編譯或執行")
        || !evidence.contains("\"rust_toolchain\": \"1.94.1\"")
        || !evidence.contains("\"unsafe_path_executed\": false")
    {
        return Err("ABI 拒絕證據不完整或接受不安全路徑".into());
    }
    Ok(())
}

fn abi_check(root: &Path) -> Result<(), String> {
    for source in ["tests/abi/nested_callback.c", "tests/abi/c_only_longjmp.c"] {
        required_file(root, source)?;
        let binary = root.join("target/rivetlua-abi").join(
            source
                .rsplit('/')
                .next()
                .ok_or("無效 ABI 路徑")?
                .replace(".c", ""),
        );
        fs::create_dir_all(binary.parent().ok_or("無效 ABI 目標")?)
            .map_err(|error| error.to_string())?;
        run(
            "cc",
            &[source, "-o", binary.to_str().ok_or("無法表示 ABI 路徑")?],
            root,
        )?;
        run(binary.to_str().ok_or("無法表示 ABI binary")?, &[], root)?;
    }
    abi_evidence_check(root, "tests/abi/REPORT.md", "tests/abi/evidence.json")
}

fn p00_direct_opt_in(value: Option<&str>) -> Result<bool, String> {
    match value {
        None => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err("P00 direct opt-in 僅允許精確值 1".into()),
    }
}

fn p00_full_test_count(output: &str) -> Result<usize, String> {
    let summaries = output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    if summaries.len() != 1
        || output
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(str::trim)
            != summaries.first().copied()
    {
        return Err("P00 direct 完整測試摘要缺失、重複或不是輸出結尾".into());
    }
    let parts = summaries[0].split(';').map(str::trim).collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err("P00 direct 測試摘要欄位數不符".into());
    }
    let first = parts[0]
        .strip_prefix("test result: ok. ")
        .and_then(|text| text.strip_suffix(" passed"))
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .ok_or("P00 direct 測試通過數必須大於零")?;
    for (field, expected) in
        parts[1..5]
            .iter()
            .zip(["0 failed", "0 ignored", "0 measured", "0 filtered out"])
    {
        if *field != expected {
            return Err(format!("P00 direct 測試摘要不是 {expected}：{field}"));
        }
    }
    if !parts[5].starts_with("finished in ") {
        return Err("P00 direct 測試摘要缺少完成時間".into());
    }
    let running = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("running "))
        .filter_map(|line| line.strip_suffix(" tests"))
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("P00 direct 測試啟動數無效：{error}"))?;
    if running.as_slice() != [first] {
        return Err("P00 direct 測試啟動數與完整 PASS 摘要不符".into());
    }
    Ok(first)
}

fn p00_direct_metadata_package(root: &Path, text: &str) -> Result<String, String> {
    let parsed = StrictJsonParser::parse(text)?;
    let packages = parsed
        .get("packages")
        .and_then(StrictJsonValue::as_array)
        .ok_or("P00 Cargo metadata 缺 packages")?;
    let selected = packages
        .iter()
        .filter(|package| {
            package.get("name").and_then(StrictJsonValue::as_str) == Some("rivetlua-xtask")
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err("P00 Cargo metadata xtask package 必須唯一".into());
    }
    let package = selected[0];
    let manifest = root.join("xtask/Cargo.toml");
    if package
        .get("manifest_path")
        .and_then(StrictJsonValue::as_str)
        != Some(manifest.to_string_lossy().as_ref())
        || package.get("edition").and_then(StrictJsonValue::as_str) != Some("2024")
        || !matches!(package.get("features"), Some(StrictJsonValue::Object(entries)) if entries.is_empty())
        || !matches!(package.get("dependencies"), Some(StrictJsonValue::Array(entries)) if entries.is_empty())
    {
        return Err(
            "P00 Cargo metadata 的 xtask manifest、edition、feature 或 dependency 不符".into(),
        );
    }
    let targets = package
        .get("targets")
        .and_then(StrictJsonValue::as_array)
        .ok_or("P00 Cargo metadata 缺 xtask targets")?;
    let mut bins = 0usize;
    for target in targets {
        let kind = target
            .get("kind")
            .and_then(StrictJsonValue::as_array)
            .ok_or("P00 Cargo target 缺 kind")?;
        let kind = match kind {
            [StrictJsonValue::String(kind)] => kind.as_str(),
            _ => return Err("P00 Cargo target kind 必須唯一".into()),
        };
        match kind {
            "bin" => {
                bins += 1;
                if target.get("name").and_then(StrictJsonValue::as_str) != Some("rivetlua-xtask")
                    || target.get("src_path").and_then(StrictJsonValue::as_str)
                        != Some(root.join("xtask/src/main.rs").to_string_lossy().as_ref())
                {
                    return Err("P00 Cargo bin 必須是固定 xtask main".into());
                }
            }
            "test" => {}
            _ => return Err(format!("P00 Cargo target kind 不允許 {kind}")),
        }
    }
    if bins != 1 {
        return Err("P00 Cargo bin 必須唯一".into());
    }
    package
        .get("id")
        .and_then(StrictJsonValue::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or("P00 Cargo metadata 缺 xtask package id".into())
}

fn p00_direct_artifact(
    root: &Path,
    target_root: &Path,
    package_id: &str,
    text: &str,
) -> Result<PathBuf, String> {
    let mut artifact = None;
    let mut finished = false;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let parsed = StrictJsonParser::parse(line)?;
        match parsed.get("reason").and_then(StrictJsonValue::as_str) {
            Some("compiler-artifact") => {
                if artifact.is_some()
                    || parsed.get("package_id").and_then(StrictJsonValue::as_str)
                        != Some(package_id)
                {
                    return Err("P00 Cargo artifact 非唯一或 package 不符".into());
                }
                let target = parsed.get("target").ok_or("P00 Cargo artifact 缺 target")?;
                let source = root.join("xtask/src/main.rs");
                if target.get("name").and_then(StrictJsonValue::as_str) != Some("rivetlua-xtask")
                    || target.get("src_path").and_then(StrictJsonValue::as_str)
                        != Some(source.to_string_lossy().as_ref())
                    || target.get("edition").and_then(StrictJsonValue::as_str) != Some("2024")
                    || !matches!(target.get("test"), Some(StrictJsonValue::Bool(true)))
                    || !matches!(target.get("kind"), Some(StrictJsonValue::Array(kinds)) if matches!(kinds.as_slice(), [StrictJsonValue::String(kind)] if kind == "bin"))
                    || !matches!(parsed.get("features"), Some(StrictJsonValue::Array(features)) if features.is_empty())
                {
                    return Err("P00 Cargo artifact target、source 或 feature 不符".into());
                }
                let profile = parsed
                    .get("profile")
                    .ok_or("P00 Cargo artifact 缺 profile")?;
                if profile.get("opt_level").and_then(StrictJsonValue::as_str) != Some("0")
                    || !matches!(
                        profile.get("debug_assertions"),
                        Some(StrictJsonValue::Bool(true))
                    )
                    || !matches!(
                        profile.get("overflow_checks"),
                        Some(StrictJsonValue::Bool(true))
                    )
                    || !matches!(profile.get("test"), Some(StrictJsonValue::Bool(true)))
                {
                    return Err("P00 Cargo artifact test profile 不符".into());
                }
                let executable = parsed
                    .get("executable")
                    .and_then(StrictJsonValue::as_str)
                    .map(PathBuf::from)
                    .ok_or("P00 Cargo artifact 缺 executable")?;
                if !executable.is_absolute() || !executable.starts_with(target_root) {
                    return Err("P00 Cargo artifact 不在共享 target".into());
                }
                artifact = Some(executable);
            }
            Some("build-finished") => {
                if finished || !matches!(parsed.get("success"), Some(StrictJsonValue::Bool(true))) {
                    return Err("P00 Cargo build-finished 非唯一或非 PASS".into());
                }
                finished = true;
            }
            Some("compiler-message") => {}
            _ => return Err("P00 Cargo --no-run 回傳未知 JSON 訊息".into()),
        }
    }
    if !finished {
        return Err("P00 Cargo --no-run 缺 build-finished".into());
    }
    artifact.ok_or("P00 Cargo --no-run 缺 compiler-artifact".into())
}

fn p00_sha_file(path: &Path) -> Result<String, String> {
    let (program, prefix) = sha256_tool(env::consts::OS)?;
    let output = Command::new(program)
        .args(prefix)
        .arg(path)
        .output()
        .map_err(|error| format!("P00 SHA-256 啟動失敗：{error}"))?;
    let sha = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    if !output.status.success()
        || sha.len() != 64
        || !sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("P00 SHA-256 失敗：{}", path.display()));
    }
    Ok(sha)
}

fn p00_argv(program: &str, args: &[&str]) -> String {
    format!(
        "{} {}",
        program,
        args.iter()
            .map(|arg| format!("{arg:?}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn p00_record_output(
    dir: &Path,
    stem: &str,
    output: &std::process::Output,
) -> Result<(PathBuf, String, PathBuf, String), String> {
    let stdout = dir.join(format!("{stem}.stdout.log"));
    let stderr = dir.join(format!("{stem}.stderr.log"));
    fs::write(&stdout, &output.stdout).map_err(|error| error.to_string())?;
    fs::write(&stderr, &output.stderr).map_err(|error| error.to_string())?;
    let stdout_sha = p00_sha_file(&stdout)?;
    let stderr_sha = p00_sha_file(&stderr)?;
    Ok((stdout, stdout_sha, stderr, stderr_sha))
}

fn p00_build_override_name(name: &str) -> bool {
    matches!(
        name,
        "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "CARGO_BUILD_TARGET"
            | "CARGO_BUILD_RUSTFLAGS"
            | "CARGO_BUILD_RUSTC"
            | "CARGO_BUILD_RUSTC_WRAPPER"
            | "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
    ) || name.starts_with("CARGO_PROFILE_TEST_")
        || name.starts_with("CARGO_TARGET_") && name.ends_with("_RUSTFLAGS")
}

fn p00_direct_xtask_full_tests(root: &Path) -> Result<(String, String), (String, String)> {
    let mut commands = Vec::new();
    let outcome = (|| -> Result<String, String> {
        for (name, value) in env::vars_os() {
            let name = name.to_string_lossy();
            if !value.is_empty() && p00_build_override_name(&name) {
                return Err(format!("P00 direct 不接受 {name} 建置覆寫"));
            }
        }
        if root.join("xtask/build.rs").exists() {
            return Err("P00 direct 不接受 xtask build.rs".into());
        }
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        let target = env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .ok_or("P00 direct 必須設定共享 CARGO_TARGET_DIR")?;
        let temp = env::var_os("TMPDIR")
            .map(PathBuf::from)
            .ok_or("P00 direct 必須設定共享 TMPDIR")?;
        if !target.is_absolute() || !temp.is_absolute() {
            return Err("P00 direct target/tmp 必須為絕對路徑".into());
        }
        let target = fs::canonicalize(&target).map_err(|error| error.to_string())?;
        let temp = fs::canonicalize(&temp).map_err(|error| error.to_string())?;
        if target.starts_with(&root)
            || temp != fs::canonicalize(target.join("tmp")).map_err(|error| error.to_string())?
        {
            return Err("P00 direct target/tmp 必須位於受控外接 cache".into());
        }
        let dir = temp.join(format!("p00-direct-full-{}", std::process::id()));
        fs::create_dir(&dir)
            .map_err(|error| format!("P00 direct 建立唯一執行目錄失敗：{error}"))?;
        let digest = source_digest(&root)?;

        let metadata_args = ["metadata", "--locked", "--no-deps", "--format-version", "1"];
        commands.push(p00_argv("cargo", &metadata_args));
        let metadata_output = Command::new("cargo")
            .args(metadata_args)
            .current_dir(&root)
            .output()
            .map_err(|error| format!("P00 Cargo metadata 啟動失敗：{error}"))?;
        let (metadata_log, metadata_sha, metadata_stderr, metadata_stderr_sha) =
            p00_record_output(&dir, "metadata", &metadata_output)?;
        if !metadata_output.status.success() {
            return Err("P00 Cargo metadata 非零退出".into());
        }
        let package_id = p00_direct_metadata_package(
            &root,
            std::str::from_utf8(&metadata_output.stdout).map_err(|error| error.to_string())?,
        )?;

        let no_run_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-xtask",
            "--bin",
            "rivetlua-xtask",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ];
        commands.push(p00_argv("cargo", &no_run_args));
        let no_run_output = Command::new("cargo")
            .args(no_run_args)
            .current_dir(&root)
            .output()
            .map_err(|error| format!("P00 Cargo --no-run 啟動失敗：{error}"))?;
        let (no_run_log, no_run_sha, no_run_stderr, no_run_stderr_sha) =
            p00_record_output(&dir, "cargo-no-run", &no_run_output)?;
        if !no_run_output.status.success() {
            return Err("P00 Cargo --no-run 非零退出".into());
        }
        let artifact = p00_direct_artifact(
            &root,
            &target,
            &package_id,
            std::str::from_utf8(&no_run_output.stdout).map_err(|error| error.to_string())?,
        )?;
        let artifact = fs::canonicalize(&artifact).map_err(|error| error.to_string())?;
        if !artifact.is_file() || !artifact.starts_with(&target) {
            return Err("P00 Cargo unit artifact 無效或不在共享 target".into());
        }
        let artifact_sha = p00_sha_file(&artifact)?;

        let binary = dir.join("xtask-full-unit");
        let binary_text = binary.to_string_lossy().into_owned();
        let rustc_args = [
            "--edition=2024",
            "--crate-name",
            "rivetlua_xtask",
            "--test",
            "-C",
            "opt-level=0",
            "-C",
            "debug-assertions=yes",
            "-C",
            "overflow-checks=yes",
            "-C",
            "debuginfo=2",
            "xtask/src/main.rs",
            "-o",
            binary_text.as_str(),
        ];
        commands.push(format!(
            "CARGO_MANIFEST_DIR={} {}",
            root.join("xtask").display(),
            p00_argv("rustc", &rustc_args)
        ));
        let rustc_output = Command::new("rustc")
            .args(rustc_args)
            .env("CARGO_MANIFEST_DIR", root.join("xtask"))
            .current_dir(&root)
            .output()
            .map_err(|error| format!("P00 direct rustc 啟動失敗：{error}"))?;
        let (rustc_log, rustc_sha, rustc_stderr, rustc_stderr_sha) =
            p00_record_output(&dir, "rustc", &rustc_output)?;
        if !rustc_output.status.success() {
            return Err("P00 direct rustc 非零退出".into());
        }
        let binary_sha = p00_sha_file(&binary)?;

        commands.push(format!(
            "CARGO_MANIFEST_DIR={} {}",
            root.join("xtask").display(),
            p00_argv(&binary_text, &["--nocapture"])
        ));
        let unit_output = Command::new(&binary)
            .arg("--nocapture")
            .env("CARGO_MANIFEST_DIR", root.join("xtask"))
            .current_dir(&root)
            .output()
            .map_err(|error| format!("P00 direct full unit 啟動失敗：{error}"))?;
        let (unit_log, unit_sha, unit_stderr, unit_stderr_sha) =
            p00_record_output(&dir, "full-unit", &unit_output)?;
        if !unit_output.status.success() {
            return Err(format!(
                "P00 direct full unit 非零退出：{:?}",
                unit_output.status.code()
            ));
        }
        let count = p00_full_test_count(
            std::str::from_utf8(&unit_output.stdout).map_err(|error| error.to_string())?,
        )?;
        if source_digest(&root)? != digest {
            return Err("P00 direct full unit 前後來源摘要不同".into());
        }
        Ok(format!(
            "direct-full opt-in=1；matched={count} passed={count} failed=0 ignored=0 filtered=0；Cargo --no-run PASS artifact={} sha256={artifact_sha}；metadata={} sha256={metadata_sha}；metadata-stderr={} sha256={metadata_stderr_sha}；no-run={} sha256={no_run_sha}；no-run-stderr={} sha256={no_run_stderr_sha}；rustc={} sha256={rustc_sha}；rustc-stderr={} sha256={rustc_stderr_sha}；binary={} sha256={binary_sha}；unit={} sha256={unit_sha}；unit-stderr={} sha256={unit_stderr_sha}；source_digest={digest}",
            artifact.display(),
            metadata_log.display(),
            metadata_stderr.display(),
            no_run_log.display(),
            no_run_stderr.display(),
            rustc_log.display(),
            rustc_stderr.display(),
            binary.display(),
            unit_log.display(),
            unit_stderr.display(),
        ))
    })();
    let command = commands.join(" && ");
    outcome
        .map(|diagnostic| (command.clone(), diagnostic))
        .map_err(|error| (command, error))
}

fn gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let checks = [
        "Cargo.lock",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "README.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "GOVERNANCE.md",
        "THIRD_PARTY_NOTICES.md",
        "CHANGELOG.md",
        "spec/upstream-sources.md",
        "spec/compatibility.csv",
    ];
    for check in checks {
        required_file(&root, check)?;
    }
    results.push(GateResult {
        name: "governance".into(),
        command: "required files".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "complete".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let cargo = fs::read_to_string(root.join("Cargo.toml")).map_err(|e| e.to_string())?;
    if root.join("rust-toolchain.toml").exists()
        || root.join("rust-toolchain").exists()
        || !cargo.contains("rust-version = \"1.94.1\"")
    {
        results.push(GateResult {
            name: "toolchain".into(),
            command: "Cargo.toml; no rust-toolchain override".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: "專案工具鏈覆寫或 MSRV 宣告不符".into(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err("專案工具鏈覆寫或 MSRV 宣告不符".into());
    }
    results.push(GateResult {
        name: "toolchain".into(),
        command: "Cargo.toml; no rust-toolchain override".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "使用預設 stable；MSRV 為 1.94.1".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let actual_rustc = match run("rustc", &["--version"], &root) {
        Ok(output) => output,
        Err(error) => {
            results.push(GateResult {
                name: "rustc".into(),
                command: "rustc --version".into(),
                exit_code: 1,
                status: "FAIL",
                diagnostic: error.clone(),
                report_path: "target/rivetlua-reports/gate-P00.json".into(),
            });
            write_gate_results(&root, &results);
            return Err(error);
        }
    };
    if !supported_rustc(&actual_rustc) {
        results.push(GateResult {
            name: "rustc".into(),
            command: "rustc --version".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: actual_rustc.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(format!("實際 rustc 低於 MSRV {MSRV} 或版本無法辨識"));
    }
    results.push(GateResult {
        name: "rustc".into(),
        command: "rustc --version".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: actual_rustc.trim().into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let csv = fs::read_to_string(root.join("spec/compatibility.csv")).map_err(|e| e.to_string())?;
    if let Err(error) = validate_csv(&csv) {
        results.push(GateResult {
            name: "compatibility".into(),
            command: "validate spec/compatibility.csv".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "compatibility".into(),
        command: "validate spec/compatibility.csv".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "header、profile 與 status 有效".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let (test_command, test_result) = match env::var("RIVETLUA_P00_DIRECT_XTASK_FULL") {
        Err(env::VarError::NotPresent) => (
            "cargo test --locked -p rivetlua-xtask --bin rivetlua-xtask".to_owned(),
            run(
                "cargo",
                &[
                    "test",
                    "--locked",
                    "-p",
                    "rivetlua-xtask",
                    "--bin",
                    "rivetlua-xtask",
                ],
                &root,
            )
            .map(|_| "xtask binary 單元測試通過".to_owned()),
        ),
        Ok(value) => match p00_direct_opt_in(Some(&value)) {
            Ok(true) => match p00_direct_xtask_full_tests(&root) {
                Ok((command, diagnostic)) => (command, Ok(diagnostic)),
                Err((command, error)) => (command, Err(error)),
            },
            Ok(false) => unreachable!(),
            Err(error) => ("RIVETLUA_P00_DIRECT_XTASK_FULL".into(), Err(error)),
        },
        Err(env::VarError::NotUnicode(_)) => (
            "RIVETLUA_P00_DIRECT_XTASK_FULL".into(),
            Err("P00 direct opt-in 不是 UTF-8".into()),
        ),
    };
    let test_diagnostic = match test_result {
        Ok(diagnostic) => diagnostic,
        Err(error) => {
            results.push(GateResult {
                name: "xtask-tests".into(),
                command: test_command,
                exit_code: 1,
                status: "FAIL",
                diagnostic: error.clone(),
                report_path: "target/rivetlua-reports/gate-P00.json".into(),
            });
            write_gate_results(&root, &results);
            return Err(error);
        }
    };
    results.push(GateResult {
        name: "xtask-tests".into(),
        command: test_command,
        exit_code: 0,
        status: "PASS",
        diagnostic: test_diagnostic,
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let (sha_program, sha_prefix) = sha256_tool(env::consts::OS)?;
    for selected in [LUA55, LUA54] {
        let mut sha_parts = vec![sha_program];
        sha_parts.extend_from_slice(sha_prefix);
        sha_parts.extend([selected.source, selected.tests]);
        let sha_command = sha_parts.join(" ");
        if let Err(error) = verify(&root, selected) {
            results.push(GateResult {
                name: format!("sources-{}", selected.name),
                command: sha_command.clone(),
                exit_code: 1,
                status: "FAIL",
                diagnostic: error.clone(),
                report_path: "target/rivetlua-reports/gate-P00.json".into(),
            });
            write_gate_results(&root, &results);
            return Err(error);
        }
        results.push(GateResult {
            name: format!("sources-{}", selected.name),
            command: sha_command,
            exit_code: 0,
            status: "PASS",
            diagnostic: "SHA-256、解壓 source/tests 與授權資料完整".into(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        if let Err(error) = runner(&[
            "--profile".into(),
            selected.name.into(),
            "--case".into(),
            "P00-RUN-001".into(),
        ]) {
            results.push(GateResult {
                name: format!("P00-RUN-001-{}", selected.name),
                command: format!(
                    "rivetlua-xtask runner --profile {} --case P00-RUN-001",
                    selected.name
                ),
                exit_code: 1,
                status: "FAIL",
                diagnostic: error.clone(),
                report_path: format!("target/rivetlua-reports/P00-RUN-001-{}.json", selected.name),
            });
            write_gate_results(&root, &results);
            return Err(error);
        }
        results.push(GateResult {
            name: format!("P00-RUN-001-{}", selected.name),
            command: format!(
                "rivetlua-xtask runner --profile {} --case P00-RUN-001",
                selected.name
            ),
            exit_code: 0,
            status: "PASS",
            diagnostic: "完整執行且預期相符".into(),
            report_path: format!("target/rivetlua-reports/P00-RUN-001-{}.json", selected.name),
        });
        if let Err(error) = runner(&[
            "--profile".into(),
            selected.name.into(),
            "--case".into(),
            "P00-RUN-002".into(),
        ]) {
            results.push(GateResult {
                name: format!("P00-RUN-002-{}", selected.name),
                command: format!(
                    "rivetlua-xtask runner --profile {} --case P00-RUN-002",
                    selected.name
                ),
                exit_code: 1,
                status: "FAIL",
                diagnostic: error.clone(),
                report_path: format!("target/rivetlua-reports/P00-RUN-002-{}.json", selected.name),
            });
            write_gate_results(&root, &results);
            return Err(error);
        }
        results.push(GateResult {
            name: format!("P00-RUN-002-{}", selected.name),
            command: format!(
                "rivetlua-xtask runner --profile {} --case P00-RUN-002",
                selected.name
            ),
            exit_code: 0,
            status: "PASS",
            diagnostic: "完整執行且預期相符".into(),
            report_path: format!("target/rivetlua-reports/P00-RUN-002-{}.json", selected.name),
        });
    }
    for case in ["P00-SUP-001", "P00-REF-003", "P00-RUN-003", "P00-RUN-004"] {
        if runner(&[
            "--profile".into(),
            "lua55".into(),
            "--case".into(),
            case.into(),
        ])
        .is_ok()
        {
            results.push(GateResult {
                name: case.into(),
                command: format!("rivetlua-xtask runner --profile lua55 --case {case}"),
                exit_code: 0,
                status: "FAIL",
                diagnostic: "故意失敗 fixture 意外通過".into(),
                report_path: format!("target/rivetlua-reports/{case}-lua55.json"),
            });
            write_gate_results(&root, &results);
            return Err(format!("故意失敗 case 意外通過：{case}"));
        }
        results.push(GateResult {
            name: case.into(),
            command: format!("rivetlua-xtask runner --profile lua55 --case {case}"),
            exit_code: 1,
            status: "PASS",
            diagnostic: "已確認 fixture 非零退出".into(),
            report_path: format!("target/rivetlua-reports/{case}-lua55.json"),
        });
    }
    if let Err(error) = abi_check(&root) {
        results.push(GateResult {
            name: "abi-safe-controls".into(),
            command: "cc nested_callback; cc c_only_longjmp; evidence check".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "abi-safe-controls".into(),
        command: "cc nested_callback; cc c_only_longjmp; evidence check".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "C-only controls passed; unsafe route rejected".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    if abi_evidence_check(
        &root,
        "tests/abi/REPORT.md",
        "tests/abi/fixtures/incomplete-evidence.json",
    )
    .is_ok()
    {
        results.push(GateResult {
            name: "P00-ABI-004".into(),
            command: "abi_evidence_check tests/abi/fixtures/incomplete-evidence.json".into(),
            exit_code: 0,
            status: "FAIL",
            diagnostic: "不完整 evidence fixture 意外通過".into(),
            report_path: "tests/abi/fixtures/incomplete-evidence.json".into(),
        });
        write_gate_results(&root, &results);
        return Err("P00-ABI-004 fixture 意外通過".into());
    }
    results.push(GateResult {
        name: "P00-ABI-004".into(),
        command: "abi_evidence_check tests/abi/fixtures/incomplete-evidence.json".into(),
        exit_code: 1,
        status: "PASS",
        diagnostic: "已拒絕不完整 evidence fixture".into(),
        report_path: "tests/abi/fixtures/incomplete-evidence.json".into(),
    });
    if abi_evidence_check(
        &root,
        "tests/abi/fixtures/unsafe-accepted.md",
        "tests/abi/evidence.json",
    )
    .is_ok()
    {
        results.push(GateResult {
            name: "P00-ABI-005".into(),
            command: "abi_evidence_check tests/abi/fixtures/unsafe-accepted.md".into(),
            exit_code: 0,
            status: "FAIL",
            diagnostic: "unsafe accepted fixture 意外通過".into(),
            report_path: "tests/abi/fixtures/unsafe-accepted.md".into(),
        });
        write_gate_results(&root, &results);
        return Err("P00-ABI-005 fixture 意外通過".into());
    }
    results.push(GateResult {
        name: "P00-ABI-005".into(),
        command: "abi_evidence_check tests/abi/fixtures/unsafe-accepted.md".into(),
        exit_code: 1,
        status: "PASS",
        diagnostic: "已拒絕接受不安全路徑的 fixture".into(),
        report_path: "tests/abi/fixtures/unsafe-accepted.md".into(),
    });
    if let Err(error) = scan_dependency_tree(&root) {
        results.push(GateResult {
            name: "dependency-scan".into(),
            command: "cargo tree --locked --workspace".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "dependency-scan".into(),
        command: "cargo tree --locked --workspace".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "未發現 Lua runtime crate".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    if let Err(error) = scan_lua_symbols(&root) {
        results.push(GateResult {
            name: "symbol-scan".into(),
            command: "nm -g target/debug/rivetlua-xtask".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "symbol-scan".into(),
        command: "nm -g target/debug/rivetlua-xtask".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "未定義 Lua engine 符號".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    let debug = root.join("target/debug");
    if debug.exists()
        && fs::read_dir(&debug)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with("liblua"))
    {
        results.push(GateResult {
            name: "artifact-scan".into(),
            command: "scan target/debug for liblua".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: "正式 Rust 產物含 Lua library".into(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err("正式 Rust 產物含 Lua library".into());
    }
    results.push(GateResult {
        name: "artifact-scan".into(),
        command: "scan target/debug for liblua".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "未發現 Lua library".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    if let Err(error) = validate_pass_evidence(&csv, &results) {
        results.push(GateResult {
            name: "compatibility-evidence".into(),
            command: "validate PASS case evidence".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "compatibility-evidence".into(),
        command: "validate PASS case evidence".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "所有 CSV PASS case 均有本次證據".into(),
        report_path: "target/rivetlua-reports/gate-P00.json".into(),
    });
    write_gate_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P00.json").display()
    );
    Ok(())
}

const P01_CASES: [(&str, &str); 15] = [
    ("NUM-001", "num_001_floor_division"),
    ("NUM-002", "num_002_negative_modulo"),
    ("NUM-003", "num_003_negative_divisor_modulo"),
    ("NUM-004", "num_004_integer_addition_wraps"),
    ("NUM-005", "num_005_large_integer_float_comparison_is_exact"),
    ("NUM-006", "num_006_minimum_integer_boundaries_do_not_panic"),
    ("NUM-007", "num_007_bit_conversion_and_shift_boundaries"),
    (
        "NUM-008",
        "num_008_power_is_float_and_preserves_ieee_boundaries",
    ),
    ("VAL-001", "val_001_and_keeps_selected_operand"),
    ("VAL-002", "val_002_or_keeps_truthy_object_operand"),
    ("VAL-003", "val_003_only_nil_and_false_are_falsey"),
    ("ERR-001", "err_001_integer_division_by_zero_is_checkable"),
    ("ERR-002", "err_002_integer_modulo_by_zero_is_checkable"),
    (
        "ERR-003",
        "err_003_inexact_or_nonfinite_float_is_not_integer",
    ),
    ("ERR-004", "err_004_non_numeric_value_is_checkable"),
];

fn write_p01_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P01.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let entries = results.iter().map(|item| format!("{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}", json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status, json_escape(&item.diagnostic), json_escape(&item.report_path))).collect::<Vec<_>>().join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{entries}]}}\n"
        ),
    );
}

fn write_p01_case_report(
    root: &Path,
    case_id: &str,
    profile: &str,
    lua_profile: &str,
    records: &[(String, String, String, String)],
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P01-{case_id}-{lua_profile}.json"
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P01 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let selected: Vec<_> = records
        .iter()
        .filter(|record| record.0 == case_id)
        .collect();
    if selected.is_empty() {
        return Err(format!("缺少 {case_id} 記錄"));
    }
    let array = |index: usize| {
        selected
            .iter()
            .map(|record| {
                let value = match index {
                    1 => &record.1,
                    2 => &record.2,
                    3 => &record.3,
                    _ => unreachable!(),
                };
                format!("\"{}\"", json_escape(value))
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-core\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"unit\",\"operands\":[{}],\"expected\":[{}],\"actual\":[{}],\"status\":\"PASS\",\"command\":\"cargo test --locked -p rivetlua-core --test p01_contracts -- --nocapture --test-threads=1\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"完整執行且 expected 等於 actual\"}}\n",
        json_escape(case_id),
        json_escape(profile),
        json_escape(lua_profile),
        array(1),
        array(2),
        array(3),
        json_escape(&path.display().to_string())
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn p01_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P01.json".into(),
    }
}

fn p01_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p01_result(name, command, 1, "FAIL", error.clone()));
    write_p01_results(root, results);
    Err(error)
}

fn validate_p01_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P01_CASES.iter().map(|(id, _)| *id).collect();
    for profile in ["lua55", "lua54"] {
        let rows: Vec<_> = csv
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with(&format!("p01.core,{profile},")) && line.contains(",PASS,")
            })
            .collect();
        if rows.len() != 1 {
            return Err(format!("{profile} P01 PASS 列數不正確"));
        }
        let columns: Vec<_> = rows[0].split(',').collect();
        if columns.len() != 7 {
            return Err(format!("{profile} P01 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty()) || actual.len() != ids.len() || actual != expected {
            return Err(format!("{profile} P01 test_ids 不完整、重複或未知"));
        }
    }
    Ok(())
}

fn p01_contracts(
    root: &Path,
    profile: &str,
) -> Result<Vec<(String, String, String, String)>, String> {
    let fixture = fs::read_to_string(root.join("tests/p01/fixtures/wrong-num-001.fixture"))
        .map_err(|error| error.to_string())?;
    let expected = fixture
        .lines()
        .find_map(|line| line.strip_prefix("expected="))
        .ok_or("P01 fixture 缺 expected")?;
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-core",
            "--test",
            "p01_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P01_PROFILE", profile)
        .env("RIVETLUA_P01_NUM001_EXPECTED", expected)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let status = output.status;
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    validate_p01_contract_status(profile, &status, &output)?;
    let expected_summary = format!(
        "test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
        P01_CASES.len() + 1
    );
    if !output.contains(&expected_summary) {
        return Err(format!("{profile} P01 contracts 失敗：{output}"));
    }
    for (_, test_name) in P01_CASES {
        if !output.contains(test_name) {
            return Err(format!("{profile} 未完整執行 P01 case：{test_name}"));
        }
    }
    let records = output
        .lines()
        .filter_map(|line| {
            line.find("P01_CASE\t")
                .map(|index| &line[index + "P01_CASE\t".len()..])
        })
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("{profile} P01_CASE 欄位不完整：{line}"));
            }
            if fields[2] != fields[3] {
                return Err(format!("{profile} P01_CASE expected/actual 不符：{line}"));
            }
            Ok((
                fields[0].into(),
                fields[1].into(),
                fields[2].into(),
                fields[3].into(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (case, _) in P01_CASES {
        if !records.iter().any(|record| record.0 == case) {
            return Err(format!("{profile} 缺少 P01_CASE 記錄：{case}"));
        }
    }
    Ok(records)
}

fn validate_p01_contract_status(
    profile: &str,
    status: &ExitStatus,
    output: &str,
) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{profile} P01 contracts 子行程失敗（實際退出碼 {status}）：{output}"
        ))
    }
}

fn p01_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let p00_command = "cargo run --locked -p rivetlua-xtask -- gate P00";
    if let Err(error) = run(
        "cargo",
        &[
            "run",
            "--locked",
            "-p",
            "rivetlua-xtask",
            "--",
            "gate",
            "P00",
        ],
        &root,
    ) {
        return p01_fail(&root, &mut results, "p00-before", p00_command, error);
    }
    results.push(p01_result(
        "p00-before",
        p00_command,
        0,
        "PASS",
        "P00 回歸通過",
    ));
    let csv = fs::read_to_string(root.join("spec/compatibility.csv"))
        .map_err(|error| error.to_string())?;
    if let Err(error) = validate_p01_csv_cases(&csv) {
        return p01_fail(
            &root,
            &mut results,
            "p01-csv",
            "validate spec/compatibility.csv",
            error,
        );
    }
    results.push(p01_result(
        "p01-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "兩個 profile 的 15 個 P01 case 均完整追溯",
    ));
    let fmt_command = "cargo fmt --all -- --check";
    if let Err(error) = run("cargo", &["fmt", "--all", "--", "--check"], &root) {
        return p01_fail(&root, &mut results, "p01-fmt", fmt_command, error);
    }
    results.push(p01_result(
        "p01-fmt",
        fmt_command,
        0,
        "PASS",
        "格式檢查通過",
    ));
    let core_unit_command = "cargo test --locked -p rivetlua-core --lib";
    if let Err(error) = run(
        "cargo",
        &["test", "--locked", "-p", "rivetlua-core", "--lib"],
        &root,
    ) {
        return p01_fail(
            &root,
            &mut results,
            "p01-core-unit",
            core_unit_command,
            error,
        );
    }
    results.push(p01_result(
        "p01-core-unit",
        core_unit_command,
        0,
        "PASS",
        "core 單元測試通過",
    ));
    for (name, test_name) in [
        ("p01-integration-value", "p01_value"),
        ("p01-integration-number", "p01_number"),
    ] {
        let command = format!("cargo test --locked -p rivetlua-core --test {test_name}");
        if let Err(error) = run(
            "cargo",
            &[
                "test",
                "--locked",
                "-p",
                "rivetlua-core",
                "--test",
                test_name,
            ],
            &root,
        ) {
            return p01_fail(&root, &mut results, name, &command, error);
        }
        results.push(p01_result(
            name,
            command,
            0,
            "PASS",
            "crate 外 integration test 通過",
        ));
    }
    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = "cargo test --locked -p rivetlua-core --test p01_contracts";
        let records = match p01_contracts(&root, profile) {
            Ok(records) => records,
            Err(error) => {
                let name =
                    if fs::read_to_string(root.join("tests/p01/fixtures/wrong-num-001.fixture"))
                        .map(|fixture| fixture.contains("expected=-1"))
                        .unwrap_or(false)
                    {
                        "P01-NUM-NEG-001".to_owned()
                    } else {
                        format!("p01-contracts-{lua_profile}")
                    };
                return p01_fail(&root, &mut results, &name, command, error);
            }
        };
        for (case, _) in P01_CASES {
            let path = match write_p01_case_report(&root, case, profile, lua_profile, &records) {
                Ok(path) => path,
                Err(error) => {
                    return p01_fail(
                        &root,
                        &mut results,
                        &format!("{case}-{lua_profile}"),
                        command,
                        error,
                    );
                }
            };
            let mut result = p01_result(
                format!("{case}-{lua_profile}"),
                command,
                0,
                "PASS",
                format!("profile={profile}; mode=unit; case 已由 core 外部 integration 執行"),
            );
            result.report_path = path.display().to_string();
            results.push(result);
        }
    }
    if let Err(error) = run(
        "cargo",
        &[
            "run",
            "--locked",
            "-p",
            "rivetlua-xtask",
            "--",
            "gate",
            "P00",
        ],
        &root,
    ) {
        return p01_fail(&root, &mut results, "p00-after", p00_command, error);
    }
    results.push(p01_result(
        "p00-after",
        p00_command,
        0,
        "PASS",
        "P00 回歸通過",
    ));
    write_p01_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P01.json").display()
    );
    Ok(())
}

const P02_CASES: [&str; 11] = [
    "LEX-001",
    "LEX-002",
    "LEX-003",
    "LEX-004",
    "LEX-005",
    "LEX-006",
    "LEX-LONG-001",
    "LEX-ERR-001",
    "LEX-ERR-002",
    "LEX-ERR-003",
    "LEX-ERR-004",
];
const P03_CASES: [&str; 10] = [
    "PARSE-001",
    "PARSE-002",
    "PARSE-003",
    "PARSE-004",
    "PARSE-005",
    "PARSE-006",
    "PARSE-ERR-001",
    "PARSE-ERR-002",
    "PARSE-ERR-003",
    "PARSE-ERR-004",
];
const P04_CASES: [&str; 10] = [
    "RES-001",
    "RES-002",
    "RES-003",
    "RES-004",
    "RES-005",
    "RES-006",
    "RES-007",
    "RES-008",
    "RES-ERR-001",
    "RES-ERR-002",
];
const P05_CASES: [&str; 12] = [
    "BC-001",
    "BC-002",
    "BC-003",
    "BC-004",
    "BC-005",
    "BC-006",
    "BC-007",
    "BC-008",
    "BC-009",
    "BC-010",
    "BC-ERR-001",
    "BC-ERR-002",
];
const P05_CONTRACT_TEST_COUNT: usize = 7;
const P06_CASES: [&str; 8] = [
    "HEAP-001", "HEAP-002", "HEAP-003", "HEAP-004", "HEAP-005", "HEAP-006", "HEAP-007", "HEAP-008",
];
const P06_FIXTURE: &str = "tests/p06/heap-cases.fixture";
const P07_CASES: [&str; 10] = [
    "VM-001", "VM-002", "VM-003", "VM-004", "VM-005", "VM-006", "VM-007", "VM-008", "VM-009",
    "VM-010",
];
const P07_FIXTURE: &str = "tests/p07/vm-cases.fixture";
const P08_CASES: [&str; 12] = [
    "TAB-001", "TAB-002", "TAB-003", "TAB-004", "TAB-005", "TAB-006", "TAB-007", "TAB-008",
    "TAB-009", "TAB-010", "TAB-011", "TAB-012",
];
const P08_FIXTURE: &str = "tests/p08/table-cases.fixture";
const P09_LUA55_CASES: [&str; 12] = [
    "CALL-001", "CALL-002", "CALL-003", "CALL-004", "CALL-005", "CALL-006", "CALL-007", "CALL-008",
    "CALL-009", "CALL-010", "CALL-011", "CALL-013",
];
const P09_LUA54_CASES: [&str; 12] = [
    "CALL-001", "CALL-002", "CALL-003", "CALL-004", "CALL-005", "CALL-006", "CALL-007", "CALL-008",
    "CALL-009", "CALL-010", "CALL-012", "CALL-013",
];
const P09_FIXTURE: &str = "tests/p09/call-cases.fixture";
const P10_CASES: [&str; 10] = [
    "META-001", "META-002", "META-003", "META-004", "META-005", "META-006", "META-007", "META-008",
    "META-009", "META-010",
];
const P10_FIXTURE: &str = "tests/p10/metamethod-cases.fixture";
const P11_CASE_IDS: [&str; 16] = [
    "ERR-001",
    "ERR-002",
    "ERR-003",
    "ERR-004",
    "ERR-005",
    "COR-001",
    "COR-002",
    "COR-003",
    "COR-004",
    "COR-005",
    "COR-006",
    "CLOSE-001",
    "CLOSE-002",
    "CLOSE-003",
    "CLOSE-004",
    "CLOSE-005",
];
const P11_FIXTURE: &str = "tests/p11/error-coroutine-close-cases.fixture";
const P12_CASE_IDS: [&str; 10] = [
    "GC-001", "GC-002", "GC-003", "GC-004", "GC-005", "GC-006", "GC-007", "GC-008", "GC-009",
    "GC-010",
];
const P12_FIXTURE: &str = "tests/p12/gc-cases.fixture";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P12CaseSpec {
    id: &'static str,
    mode: &'static str,
    test_name: &'static str,
    expected: &'static str,
}

const P12_CASE_SPECS: [P12CaseSpec; 10] = [
    P12CaseSpec {
        id: "GC-001",
        mode: "cycle",
        test_name: "gc_case_001",
        expected: "cycle=reclaimed;roots=0;generation=stale-handle-rejected",
    },
    P12CaseSpec {
        id: "GC-002",
        mode: "incremental-barrier",
        test_name: "gc_case_002",
        expected: "barrier=marked;child=retained;cycle=complete",
    },
    P12CaseSpec {
        id: "GC-003",
        mode: "ephemeron",
        test_name: "gc_case_003",
        expected: "ephemeron=converged;reverse-key=not-root;pair=cleared",
    },
    P12CaseSpec {
        id: "GC-004",
        mode: "finalizer-revival",
        test_name: "gc_case_004",
        expected: "finalizer=once;revival=observed;reclaimed=after-root-drop",
    },
    P12CaseSpec {
        id: "GC-005",
        mode: "allocation-failure",
        test_name: "gc_case_005",
        expected: "allocation=atomic;lua-sites=covered;ordinals=failed-and-retried",
    },
    P12CaseSpec {
        id: "GC-006",
        mode: "vm-lifecycle",
        test_name: "gc_case_006",
        expected: "vms=10000;domains=balanced;coroutines=collected",
    },
    P12CaseSpec {
        id: "GC-007",
        mode: "generational",
        test_name: "gc_case_007",
        expected: "minor=retained;major=reclaimed;remembered-set=cleared",
    },
    P12CaseSpec {
        id: "GC-008",
        mode: "weak-finalizer-boundary",
        test_name: "gc_case_008",
        expected: "weak-v=cleared-before-finalizer;weak-k=visible-to-finalizer;weak-kv=cleared-before-finalizer;revival=collected",
    },
    P12CaseSpec {
        id: "GC-009",
        mode: "finalizer-error",
        test_name: "gc_case_009",
        expected: "yield=warning;error=diagnostic;gc-reentry=unit-asserted",
    },
    P12CaseSpec {
        id: "GC-010",
        mode: "finalizer-remark",
        test_name: "gc_case_010",
        expected: "explicit-remark=next-eligible-only;unmarked=not-repeated",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P11CaseSpec {
    id: &'static str,
    category: &'static str,
    mode: &'static str,
    test_name: &'static str,
    marker: &'static str,
    expected: &'static str,
}

const P11_CASE_SPECS: [P11CaseSpec; 16] = [
    P11CaseSpec {
        id: "ERR-001",
        category: "ERR",
        mode: "protected-error",
        test_name: "err_case_001_original_table_and_nested_boundary",
        marker: "P11_STAGE:err_case_001",
        expected: "identity=preserved;nested=nearest;host_root=owned",
    },
    P11CaseSpec {
        id: "ERR-002",
        category: "ERR",
        mode: "protected-error",
        test_name: "err_case_002_xpcall_handler_reentry_and_abort",
        marker: "P11_STAGE:err_case_002",
        expected: "handler_reentry=3;handler_limit=32;abort=bypassed",
    },
    P11CaseSpec {
        id: "ERR-003",
        category: "ERR",
        mode: "abort",
        test_name: "err_case_003_pcall_fuel_abort_remains_host_terminal",
        marker: "P11_STAGE:err_case_003",
        expected: "abort=host;terminal=true",
    },
    P11CaseSpec {
        id: "ERR-004",
        category: "ERR",
        mode: "protected-close",
        test_name: "err_case_004_protected_close_receives_original_error",
        marker: "P11_STAGE:err_case_004_close",
        expected: "error=original;order=LIFO",
    },
    P11CaseSpec {
        id: "ERR-005",
        category: "ERR",
        mode: "close-error",
        test_name: "err_case_005_close_failure_continues_and_replaces_error",
        marker: "P11_STAGE:err_case_005",
        expected: "continued=LIFO;error=identity",
    },
    P11CaseSpec {
        id: "COR-001",
        category: "COR",
        mode: "yield-resume",
        test_name: "cor_case_001_yield_resumes_without_replaying_side_effect",
        marker: "P11_STAGE:cor_case_001",
        expected: "side_effect=1",
    },
    P11CaseSpec {
        id: "COR-002",
        category: "COR",
        mode: "nested-state",
        test_name: "cor_case_002_nested_resume_reports_normal_parent",
        marker: "P11_STAGE:cor_case_002",
        expected: "parent=normal",
    },
    P11CaseSpec {
        id: "COR-003",
        category: "COR",
        mode: "dead-resume",
        test_name: "cor_case_003_dead_resume_is_lua_failure_without_replay",
        marker: "P11_STAGE:cor_case_003",
        expected: "dead_replay=0",
    },
    P11CaseSpec {
        id: "COR-004",
        category: "COR",
        mode: "yield-error",
        test_name: "cor_case_004_main_yield_is_catchable_lua_error",
        marker: "P11_STAGE:cor_case_004",
        expected: "main_yield=LuaError",
    },
    P11CaseSpec {
        id: "COR-005",
        category: "COR",
        mode: "coroutine-close",
        test_name: "cor_case_005_close_suspended_error_and_invalid_state",
        marker: "P11_STAGE:cor_case_005",
        expected: "suspended+error=closed",
    },
    P11CaseSpec {
        id: "COR-006",
        category: "COR",
        mode: "coroutine-wrap",
        test_name: "cor_case_006_wrap_unwraps_results_and_closes_on_error",
        marker: "P11_STAGE:cor_case_006",
        expected: "wrap=unboxed+close_error",
    },
    P11CaseSpec {
        id: "CLOSE-001",
        category: "CLOSE",
        mode: "generic-for",
        test_name: "close_case_001_generic_for_normal_and_break_close_once",
        marker: "P11_CASE:CLOSE-001",
        expected: "normal:close-once,break:close-once",
    },
    P11CaseSpec {
        id: "CLOSE-002",
        category: "CLOSE",
        mode: "generic-for-error",
        test_name: "close_case_002_generic_for_protected_error_passes_original_value",
        marker: "P11_CASE:CLOSE-002",
        expected: "protected-false;error-identity=preserved;close-count=1",
    },
    P11CaseSpec {
        id: "CLOSE-003",
        category: "CLOSE",
        mode: "scope-exit",
        test_name: "close_case_003_return_and_goto_close_before_transfer",
        marker: "P11_CASE:CLOSE-003",
        expected: "return:closed-once,goto:closed-once",
    },
    P11CaseSpec {
        id: "CLOSE-004",
        category: "CLOSE",
        mode: "close-gc-reentry",
        test_name: "close_case_004_reentrant_close_and_xpcall_handler_survive_gc",
        marker: "P11_STAGE:close_case_004",
        expected: "reentry=once;gc=forced",
    },
    P11CaseSpec {
        id: "CLOSE-005",
        category: "CLOSE",
        mode: "close-abort",
        test_name: "close_case_005_coroutine_hard_abort_is_not_close_or_resume_tuple",
        marker: "P11_STAGE:close_case_005",
        expected: "abort=host;close=unpromised",
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct P08FixtureCase {
    id: String,
    mode: String,
    input: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P08Record {
    id: String,
    profile: String,
    input: String,
    expected: String,
    actual: String,
    diagnostic: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P09FixtureCase {
    profile: String,
    id: String,
    mode: String,
    input: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P09Record {
    id: String,
    profile: String,
    actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P10FixtureCase {
    profile: String,
    id: String,
    mode: String,
    input: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P10Record {
    id: String,
    profile: String,
    actual: String,
    diagnostic: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P11FixtureCase {
    profile: String,
    id: String,
    mode: String,
    input: String,
    marker: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P11Record {
    id: String,
    profile: String,
    actual: String,
    diagnostic: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P12FixtureCase {
    profile: String,
    id: String,
    mode: String,
    input: String,
    marker: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P12Record {
    id: String,
    profile: String,
    actual: String,
    diagnostic: String,
}

fn p09_expected_shape(id: &str) -> Option<(&'static str, &'static str)> {
    Some(match id {
        "CALL-001" => ("runtime", "Returned([1,2,1])"),
        "CALL-002" => ("runtime", "Returned([1])"),
        "CALL-003" => ("runtime", "Returned([1,9])"),
        "CALL-004" => ("runtime", "Returned([9,1,2,3])"),
        "CALL-005" => ("runtime", "Returned([nil,1,nil])"),
        "CALL-006" => ("runtime", "Returned([3,9])"),
        "CALL-007" => ("runtime", "Returned([7])"),
        "CALL-008" => ("runtime-error", "E_STACK_LIMIT"),
        "CALL-009" => ("runtime", "Returned([9,7,9])"),
        "CALL-010" => (
            "runtime-suite",
            "fixed missing values are nil; excess fixed arguments are discarded; vararg count preserves trailing nil",
        ),
        "CALL-011" => ("runtime-environment", "Returned([9])"),
        "CALL-012" => (
            "compile-reject",
            "ParseError(named vararg table lua55 only)",
        ),
        "CALL-013" => (
            "runtime-close",
            "Returned([nil,1,nil]);peak_frames=2;path_pc=numeric;tail_reuse=false;result_count=3;close_order=LIFO",
        ),
        _ => return None,
    })
}

fn parse_p09_fixture(contents: &str) -> Result<Vec<P09FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P09 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, expected, note]
                if !profile.is_empty()
                    && !id.is_empty()
                    && !mode.is_empty()
                    && !input.is_empty()
                    && !expected.is_empty()
                    && !note.is_empty()
                    && !input.contains('\t')
                    && !note.contains('\t') =>
            {
                if !matches!(*profile, "lua55-i64f64" | "lua54-i64f64") {
                    return Err(format!(
                        "P09 fixture 第 {} 行案例 profile 無效",
                        line_index + 1
                    ));
                }
                if !seen_cases.insert((*profile, *id)) {
                    return Err(format!("P09 fixture 案例重複：{profile}/{id}"));
                }
                cases.push(P09FixtureCase {
                    profile: (*profile).to_owned(),
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P09 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P09 fixture 缺少正確的兩個 profile 映射".into());
    }
    if cases.len() != 24 {
        return Err(format!(
            "P09 fixture 案例數錯誤：預期 24，實際 {}",
            cases.len()
        ));
    }
    for (profile, expected_ids) in [
        ("lua55-i64f64", &P09_LUA55_CASES[..]),
        ("lua54-i64f64", &P09_LUA54_CASES[..]),
    ] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let actual_ids: std::collections::HashSet<_> =
            selected.iter().map(|case| case.id.as_str()).collect();
        let expected_ids: std::collections::HashSet<_> = expected_ids.iter().copied().collect();
        if selected.len() != 12 || actual_ids != expected_ids {
            return Err(format!(
                "{profile} P09 fixture 缺少、重複或含錯誤 profile 的案例"
            ));
        }
        for case in selected {
            let (mode, expected) = p09_expected_shape(&case.id)
                .ok_or_else(|| format!("P09 fixture 含未知案例：{}", case.id))?;
            if case.mode != mode || case.expected != expected {
                return Err(format!(
                    "{} {} fixture mode／expected 對照錯誤",
                    profile, case.id
                ));
            }
        }
    }
    Ok(cases)
}

fn validate_p09_csv_cases(csv: &str) -> Result<(), String> {
    let p09_rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| {
            line.split(',')
                .next()
                .is_some_and(|feature| feature.starts_with("p09."))
        })
        .collect();
    if p09_rows.len() != 2
        || p09_rows
            .iter()
            .any(|row| !row.starts_with("p09.function-closure,"))
    {
        return Err(format!("P09 CSV 列數錯誤：預期 2，實際 {}", p09_rows.len()));
    }
    let rows = p09_rows;
    for (profile, expected_ids) in [
        ("lua55", &P09_LUA55_CASES[..]),
        ("lua54", &P09_LUA54_CASES[..]),
    ] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P09 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p09.function-closure"
            || columns[1] != profile
            || columns[2] != "docs/plane/P09.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("{profile} P09 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual_ids: std::collections::HashSet<_> = ids.iter().copied().collect();
        let expected_ids: std::collections::HashSet<_> = expected_ids.iter().copied().collect();
        if ids.len() != 12
            || ids.iter().any(|id| id.is_empty())
            || actual_ids.len() != ids.len()
            || actual_ids != expected_ids
        {
            return Err(format!("{profile} P09 test_ids 不完整、重複或未知"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P09 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn p09_records_from_output(profile: &str, output: &str) -> Result<Vec<P09Record>, String> {
    output
        .lines()
        .filter_map(|line| line.find("P09_CASE\t").map(|index| &line[index..]))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() < 4
                || fields[0] != "P09_CASE"
                || fields.iter().any(|field| field.is_empty())
            {
                return Err(format!("{profile} P09_CASE 欄位不完整：{line}"));
            }
            Ok(P09Record {
                id: fields[1].to_owned(),
                profile: fields[2].to_owned(),
                actual: fields[3..].join(";"),
            })
        })
        .collect()
}

fn p09_formal_case_id(marker: &str) -> Option<&str> {
    let bytes = marker.as_bytes();
    if bytes.len() < 8
        || &bytes[..5] != b"CALL-"
        || !bytes[5..8].iter().all(u8::is_ascii_digit)
        || (bytes.len() > 8 && bytes[8] != b'-')
    {
        return None;
    }
    Some(&marker[..8])
}

fn p09_call_013_path_pc(actual: &str) -> Option<usize> {
    let mut fields = std::collections::HashMap::new();
    for field in actual.split(';') {
        let (name, value) = field.split_once('=')?;
        if fields.insert(name, value).is_some() {
            return None;
        }
    }
    if fields.len() != 5
        || fields.get("peak") != Some(&"2")
        || fields.get("count") != Some(&"3")
        || fields.get("actual") != Some(&"Returned")
        || fields.get("close_order") != Some(&"LIFO")
    {
        return None;
    }
    fields.get("path_pc")?.parse().ok()
}

fn validate_p09_records(
    profile: &str,
    cases: &[P09FixtureCase],
    records: &[P09Record],
) -> Result<std::collections::HashMap<String, String>, String> {
    if records.iter().any(|record| record.profile != profile) {
        return Err(format!("{profile} P09_CASE 含錯誤 profile"));
    }
    let selected_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.profile == profile)
        .collect();
    let all_case_ids: std::collections::HashSet<_> =
        cases.iter().map(|case| case.id.as_str()).collect();
    let selected_case_ids: std::collections::HashSet<_> =
        selected_cases.iter().map(|case| case.id.as_str()).collect();
    for record in records {
        let Some(case_id) = p09_formal_case_id(&record.id) else {
            continue;
        };
        if !all_case_ids.contains(case_id) {
            return Err(format!("{profile} 含未知正式 CALL marker：{case_id}"));
        }
        if !selected_case_ids.contains(case_id) {
            return Err(format!(
                "{profile} 含不屬於此 profile 的正式 CALL marker：{case_id}"
            ));
        }
    }
    let mut actuals = std::collections::HashMap::new();
    for case in selected_cases {
        if case.id == "CALL-010" {
            let expected_markers = [
                "CALL-010-fixed-fewer",
                "CALL-010-vararg-tail-nil",
                "CALL-010-fixed-zero",
                "CALL-010-fixed-exact",
                "CALL-010-fixed-excess",
                "CALL-010-vararg-fixed",
                "CALL-010-setter-argument",
                "CALL-010-vararg-GC",
            ];
            let selected: Vec<_> = records
                .iter()
                .filter(|record| expected_markers.contains(&record.id.as_str()))
                .collect();
            let actual_ids: std::collections::HashSet<_> =
                selected.iter().map(|record| record.id.as_str()).collect();
            let expected_ids: std::collections::HashSet<_> = expected_markers.into_iter().collect();
            if selected.len() != expected_markers.len() || actual_ids != expected_ids {
                return Err(format!("{profile} CALL-010 subcase marker 缺少或重複"));
            }
            if selected.iter().any(|record| record.actual != "status=PASS") {
                return Err(format!("{profile} CALL-010 子案例沒有 PASS assertion"));
            }
            actuals.insert(
                case.id.clone(),
                selected
                    .iter()
                    .map(|record| format!("{}={}", record.id, record.actual))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            continue;
        }
        let found: Vec<_> = records
            .iter()
            .filter(|record| record.id == case.id)
            .collect();
        if found.len() != 1 {
            return Err(format!(
                "{profile} {} marker 數錯誤：預期 1，實際 {}",
                case.id,
                found.len()
            ));
        }
        let record = found[0];
        let valid = match case.id.as_str() {
            "CALL-001" => record.actual == "actual=Returned([1,2,1])",
            "CALL-002" | "CALL-003" | "CALL-004" | "CALL-005" => record.actual == "status=PASS",
            "CALL-006" => record.actual == "actual=Returned([3,9])",
            "CALL-007" => record.actual == "peak=1;value=7",
            "CALL-008" => record.actual == "peak=1025;error=E_STACK_LIMIT",
            "CALL-009" => record.actual == "actual=Returned([9,7,9])",
            "CALL-011" => record.actual == "count=1;value=9",
            "CALL-012" => record.actual == "status=REJECTED",
            "CALL-013" => p09_call_013_path_pc(&record.actual).is_some(),
            _ => false,
        };
        if !valid {
            return Err(format!(
                "{profile} {} 實際 marker 不符：{}",
                case.id, record.actual
            ));
        }
        let actual = if case.id == "CALL-013" {
            let path_pc =
                p09_call_013_path_pc(&record.actual).expect("CALL-013 實際 marker 已在上方驗證");
            format!(
                "Returned([nil,1,nil]);peak_frames=2;path_pc={path_pc};tail_reuse=false;result_count=3;close_order=LIFO"
            )
        } else {
            record.actual.clone()
        };
        actuals.insert(case.id.clone(), actual);
    }
    Ok(actuals)
}

fn p10_expected_shape(id: &str) -> Option<(&'static str, &'static str)> {
    Some(match id {
        "META-001" => ("runtime", "Returned([Boolean(false)])"),
        "META-002" => ("runtime", "Returned([Integer(7)])"),
        "META-003" => ("raw-runtime", "Returned([Integer(7)])"),
        "META-004" => ("runtime", "Returned([Integer(7), Integer(7)])"),
        "META-005" => ("runtime-error", "LuaError(E_METATABLE_CHAIN_LIMIT)"),
        "META-006" => ("runtime-gc", "Returned([Integer(8)])"),
        "META-007" => ("runtime-error", "LuaError(E_WRONG_OBJECT_TYPE)"),
        "META-008" => (
            "runtime",
            "Returned([Integer(41),Integer(41),Integer(41),Integer(41),Boolean(true),Boolean(true),Boolean(true)])",
        ),
        "META-009" => ("runtime-nested", "Returned([Integer(5)])"),
        "META-010" => (
            "runtime-cleanup",
            "Terminated(return=clean;error=clean;aborted=clean;chain=clean)",
        ),
        _ => return None,
    })
}

fn parse_p10_fixture(contents: &str) -> Result<Vec<P10FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P10 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, expected, note]
                if !profile.is_empty()
                    && !id.is_empty()
                    && !mode.is_empty()
                    && !input.is_empty()
                    && !expected.is_empty()
                    && !note.is_empty()
                    && !input.contains(['\t', '\n', '\r'])
                    && !note.contains(['\t', '\n', '\r']) =>
            {
                if !matches!(*profile, "lua55-i64f64" | "lua54-i64f64") {
                    return Err(format!(
                        "P10 fixture 第 {} 行案例 profile 無效",
                        line_index + 1
                    ));
                }
                if !seen_cases.insert((*profile, *id)) {
                    return Err(format!("P10 fixture 案例重複：{profile}/{id}"));
                }
                cases.push(P10FixtureCase {
                    profile: (*profile).to_owned(),
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P10 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P10 fixture 缺少正確的兩個 profile 映射".into());
    }
    if cases.len() != P10_CASES.len() * 2 {
        return Err(format!(
            "P10 fixture 案例數錯誤：預期 20，實際 {}",
            cases.len()
        ));
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let actual_ids: std::collections::HashSet<_> =
            selected.iter().map(|case| case.id.as_str()).collect();
        let expected_ids: std::collections::HashSet<_> = P10_CASES.into_iter().collect();
        if selected.len() != P10_CASES.len() || actual_ids != expected_ids {
            return Err(format!(
                "{profile} P10 fixture 缺少、重複或含錯誤 profile 的案例"
            ));
        }
        for case in selected {
            let (mode, expected) = p10_expected_shape(&case.id)
                .ok_or_else(|| format!("P10 fixture 含未知案例：{}", case.id))?;
            if case.mode != mode || case.expected != expected {
                return Err(format!(
                    "{profile} {} fixture mode／expected 對照錯誤",
                    case.id
                ));
            }
        }
    }
    Ok(cases)
}

fn validate_p10_csv_cases(csv: &str) -> Result<(), String> {
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| {
            line.split(',')
                .next()
                .is_some_and(|feature| feature.starts_with("p10."))
        })
        .collect();
    if rows.len() != 2 || rows.iter().any(|row| !row.starts_with("p10.metatable,")) {
        return Err(format!("P10 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    let expected_ids = P10_CASES.join(";");
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P10 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p10.metatable"
            || columns[1] != profile
            || columns[2] != "docs/plane/P10.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[4] != expected_ids
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("{profile} P10 CSV 欄位或 test_ids 不完整"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P10 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn p10_formal_case_id(marker: &str) -> Option<&str> {
    let bytes = marker.as_bytes();
    if bytes.len() < 8
        || &bytes[..5] != b"META-"
        || !bytes[5..8].iter().all(u8::is_ascii_digit)
        || (bytes.len() > 8 && bytes[8] != b'-')
    {
        return None;
    }
    Some(&marker[..8])
}

fn p10_records_from_output(profile: &str, output: &str) -> Result<Vec<P10Record>, String> {
    output
        .lines()
        .filter_map(|line| line.find("P10_CASE\t").map(|index| &line[index..]))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 5
                || fields[0] != "P10_CASE"
                || fields[1].is_empty()
                || fields[2].is_empty()
                || fields[2] != profile
            {
                return Err(format!("{profile} P10_CASE 欄位或 profile 錯誤：{line}"));
            }
            let actual = fields[3]
                .strip_prefix("actual=")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{profile} P10_CASE 缺 actual：{line}"))?;
            let diagnostic = fields[4]
                .strip_prefix("diagnostic=")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{profile} P10_CASE 缺 diagnostic：{line}"))?;
            Ok(P10Record {
                id: fields[1].to_owned(),
                profile: fields[2].to_owned(),
                actual: actual.to_owned(),
                diagnostic: diagnostic.to_owned(),
            })
        })
        .collect()
}

fn p10_diagnostic_is_complete(diagnostic: &str) -> bool {
    let required = [
        "event",
        "operands",
        "pending",
        "frame_pc",
        "resume",
        "fuel",
        "roots",
        "error",
        "aborted",
        "protected_boundary",
        "internal_unit",
    ];
    let mut values = std::collections::HashMap::new();
    for field in diagnostic.split(';') {
        let Some((key, value)) = field.split_once('=') else {
            return false;
        };
        if key.is_empty() || value.is_empty() || values.insert(key, value).is_some() {
            return false;
        }
    }
    values.len() == required.len() && required.iter().all(|key| values.contains_key(key))
}

fn validate_p10_records(
    profile: &str,
    cases: &[P10FixtureCase],
    records: &[P10Record],
) -> Result<std::collections::HashMap<String, P10Record>, String> {
    let selected_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.profile == profile)
        .collect();
    let all_case_ids: std::collections::HashSet<_> =
        cases.iter().map(|case| case.id.as_str()).collect();
    let selected_case_ids: std::collections::HashSet<_> =
        selected_cases.iter().map(|case| case.id.as_str()).collect();
    for record in records {
        if record.profile != profile {
            return Err(format!(
                "{profile} P10_CASE 含錯誤 profile marker：{}",
                record.profile
            ));
        }
        let Some(case_id) = p10_formal_case_id(&record.id) else {
            return Err(format!(
                "{profile} 含格式錯誤正式 META marker：{}",
                record.id
            ));
        };
        if !all_case_ids.contains(case_id) || record.id != case_id {
            return Err(format!("{profile} 含未知正式 META marker：{}", record.id));
        }
        if !selected_case_ids.contains(case_id) {
            return Err(format!(
                "{profile} 含不屬於此 profile 的正式 META marker：{case_id}"
            ));
        }
        if !p10_diagnostic_is_complete(&record.diagnostic) {
            return Err(format!(
                "{profile} {case_id} diagnostic 缺 event／operands／PendingOp／frame-pc／resume／fuel／roots／error／Aborted／protected-boundary 證據"
            ));
        }
    }
    let mut actuals = std::collections::HashMap::new();
    for case in selected_cases {
        let found: Vec<_> = records
            .iter()
            .filter(|record| record.id == case.id)
            .collect();
        if found.len() != 1 {
            return Err(format!(
                "{profile} {} marker 數錯誤：預期 1，實際 {}",
                case.id,
                found.len()
            ));
        }
        let record = found[0];
        if record.actual != case.expected {
            return Err(format!(
                "{profile} {} 實際結果不符：expected={} actual={}",
                case.id, case.expected, record.actual
            ));
        }
        actuals.insert(case.id.clone(), record.clone());
    }
    if records.len() != P10_CASES.len() {
        return Err(format!(
            "{profile} P10_CASE marker 數錯誤：預期 10，實際 {}",
            records.len()
        ));
    }
    Ok(actuals)
}

fn p10_case_command(profile: &str) -> String {
    format!(
        "RIVETLUA_P10_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p10_contracts meta_case_ -- --nocapture --test-threads=1"
    )
}

fn p10_check_test_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P10 contracts 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P10 contracts 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    if passed == Some(P10_CASES.len()) && failed == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "P10 meta_case_ 必須精確通過 10 個測試；摘要={line}"
        ))
    }
}

fn p10_unit_command() -> &'static str {
    "cargo test --locked -p rivetlua-runtime --lib p10_ -- --test-threads=1"
}

fn p10_check_unit_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P10 runtime unit 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P10 runtime unit 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    if passed == Some(7) && failed == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "P10 runtime unit 必須精確通過 7 個 p10_ 測試；摘要={line}"
        ))
    }
}

fn p10_capture_unit(root: &Path) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "p10_",
            "--",
            "--test-threads=1",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P10 runtime unit 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p11_case_spec(id: &str) -> Option<&'static P11CaseSpec> {
    P11_CASE_SPECS.iter().find(|spec| spec.id == id)
}

fn parse_p11_fixture(contents: &str) -> Result<Vec<P11FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    let mut seen_inputs = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P11 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, marker, expected, note]
                if !profile.is_empty()
                    && !id.is_empty()
                    && !mode.is_empty()
                    && !input.is_empty()
                    && !marker.is_empty()
                    && !expected.is_empty()
                    && !note.is_empty()
                    && ![input, marker, expected, note]
                        .iter()
                        .any(|value| value.contains(['\t', '\r', '\n'])) =>
            {
                if !matches!(*profile, "lua55-i64f64" | "lua54-i64f64") {
                    return Err(format!(
                        "P11 fixture 第 {} 行案例 profile 無效",
                        line_index + 1
                    ));
                }
                if !seen_cases.insert((*profile, *id)) {
                    return Err(format!("P11 fixture 案例重複：{profile}/{id}"));
                }
                if !seen_inputs.insert((*profile, *input)) {
                    return Err(format!("P11 fixture test input 重複：{profile}/{input}"));
                }
                cases.push(P11FixtureCase {
                    profile: (*profile).to_owned(),
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    marker: (*marker).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P11 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P11 fixture 缺少正確的兩個 profile 映射".into());
    }
    if cases.len() != P11_CASE_IDS.len() * 2 {
        return Err(format!(
            "P11 fixture 案例數錯誤：預期 32，實際 {}",
            cases.len()
        ));
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let actual_ids: std::collections::HashSet<_> =
            selected.iter().map(|case| case.id.as_str()).collect();
        let expected_ids: std::collections::HashSet<_> = P11_CASE_IDS.into_iter().collect();
        if selected.len() != P11_CASE_IDS.len() || actual_ids != expected_ids {
            return Err(format!(
                "{profile} P11 fixture 缺少、重複或含錯誤 profile 的案例"
            ));
        }
        for case in selected {
            let spec = p11_case_spec(&case.id)
                .ok_or_else(|| format!("P11 fixture 含未知案例：{}", case.id))?;
            if case.mode != spec.mode
                || case.input != spec.test_name
                || case.marker != spec.marker
                || case.expected != spec.expected
            {
                return Err(format!(
                    "{profile} {} fixture 的 mode/test/marker/expected 對照錯誤",
                    case.id
                ));
            }
        }
    }
    Ok(cases)
}

fn validate_p11_csv_cases(csv: &str) -> Result<(), String> {
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| {
            line.split(',')
                .next()
                .is_some_and(|feature| feature.starts_with("p11."))
        })
        .collect();
    if rows.len() != 2
        || rows
            .iter()
            .any(|row| !row.starts_with("p11.errors-coroutines-close,"))
    {
        return Err(format!("P11 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    let expected_ids = P11_CASE_IDS.join(";");
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P11 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p11.errors-coroutines-close"
            || columns[1] != profile
            || columns[2] != "docs/plane/P11.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[4] != expected_ids
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("{profile} P11 CSV 欄位或 test_ids 不完整"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P11 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn p11_records_from_output(profile: &str, output: &str) -> Result<Vec<P11Record>, String> {
    let mut records = Vec::new();
    for output_line in output.lines() {
        if let Some(index) = output_line.find("P11_CASE\t") {
            let line = &output_line[index..];
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4 || fields[0] != "P11_CASE" || fields[2] != profile {
                return Err(format!("{profile} P11_CASE 欄位或 profile 錯誤：{line}"));
            }
            let spec = p11_case_spec(fields[1])
                .ok_or_else(|| format!("{profile} P11_CASE 含未知 formal marker：{}", fields[1]))?;
            if spec.marker != format!("P11_CASE:{}", fields[1]) {
                return Err(format!("{profile} {} marker 類型錯誤", fields[1]));
            }
            let payload = fields[3]
                .strip_prefix("status=PASS;actual=")
                .ok_or_else(|| format!("{profile} {} marker 缺 PASS/actual", fields[1]))?;
            let (actual, diagnostic) = payload
                .split_once(";diagnostic=")
                .filter(|(actual, diagnostic)| !actual.is_empty() && !diagnostic.is_empty())
                .ok_or_else(|| format!("{profile} {} marker 缺 diagnostic", fields[1]))?;
            records.push(P11Record {
                id: fields[1].to_owned(),
                profile: profile.to_owned(),
                actual: actual.to_owned(),
                diagnostic: format!("source=P11_CASE;{}", diagnostic),
            });
            continue;
        }
        if let Some(index) = output_line.find("P11_STAGE\t") {
            let line = &output_line[index..];
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 4 || fields[0] != "P11_STAGE" || fields[2] != profile {
                return Err(format!("{profile} P11_STAGE 欄位或 profile 錯誤：{line}"));
            }
            let marker = format!("P11_STAGE:{}", fields[1]);
            let spec = P11_CASE_SPECS
                .iter()
                .find(|spec| spec.marker == marker)
                .ok_or_else(|| {
                    format!("{profile} P11_STAGE 含未知 formal marker：{}", fields[1])
                })?;
            let actual = fields[3]
                .strip_prefix("status=PASS;")
                .filter(|actual| !actual.is_empty())
                .ok_or_else(|| format!("{profile} {} marker 沒有 PASS payload", spec.id))?;
            records.push(P11Record {
                id: spec.id.to_owned(),
                profile: profile.to_owned(),
                actual: actual.to_owned(),
                diagnostic: format!("source=P11_STAGE;marker={};payload={actual}", fields[1]),
            });
        }
    }
    Ok(records)
}

fn validate_p11_records(
    profile: &str,
    cases: &[P11FixtureCase],
    records: &[P11Record],
) -> Result<std::collections::HashMap<String, P11Record>, String> {
    let selected_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.profile == profile)
        .collect();
    let selected_ids: std::collections::HashSet<_> =
        selected_cases.iter().map(|case| case.id.as_str()).collect();
    for record in records {
        if record.profile != profile {
            return Err(format!(
                "{profile} P11 marker 含跨 profile 記錄：{}",
                record.profile
            ));
        }
        if !selected_ids.contains(record.id.as_str()) {
            return Err(format!(
                "{profile} P11 marker 不屬於此 profile：{}",
                record.id
            ));
        }
        if record.diagnostic.is_empty() {
            return Err(format!("{profile} {} marker diagnostic 為空", record.id));
        }
    }
    let mut actuals = std::collections::HashMap::new();
    for case in &selected_cases {
        let found: Vec<_> = records
            .iter()
            .filter(|record| record.id == case.id)
            .collect();
        if found.len() != 1 {
            return Err(format!(
                "{profile} {} marker 數錯誤：預期 1，實際 {}",
                case.id,
                found.len()
            ));
        }
        let record = found[0];
        if record.actual != case.expected {
            return Err(format!(
                "{profile} {} 實際 marker 不符：expected={} actual={}",
                case.id, case.expected, record.actual
            ));
        }
        actuals.insert(case.id.clone(), record.clone());
    }
    if records.len() != selected_cases.len() {
        return Err(format!(
            "{profile} formal P11 marker 數錯誤：預期 {}，實際 {}",
            selected_cases.len(),
            records.len()
        ));
    }
    Ok(actuals)
}

fn p11_case_command(profile: &str, test_name: &str) -> String {
    format!(
        "RIVETLUA_P11_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p11_contracts {test_name} -- --nocapture --exact --test-threads=1"
    )
}

fn p11_check_case_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P11 crate 外 case 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P11 crate 外 case 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    if passed == Some(1) && failed == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "P11 exact formal case 必須精確通過 1 個測試；摘要={line}"
        ))
    }
}

fn p11_unit_command() -> &'static str {
    "cargo test --locked -p rivetlua-runtime --lib p11_ -- --test-threads=1"
}

fn p11_check_unit_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P11 runtime unit 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P11 runtime unit 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    if passed == Some(23) && failed == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "P11 runtime unit 必須精確通過 23 個 p11_ 測試；摘要={line}"
        ))
    }
}

fn p11_capture_case(
    root: &Path,
    profile: &str,
    test_name: &str,
) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p11_contracts",
            test_name,
            "--",
            "--nocapture",
            "--exact",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P11_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P11 formal case {test_name} 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p11_capture_unit(root: &Path) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "p11_",
            "--",
            "--test-threads=1",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P11 runtime unit 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p11_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P11.json".into(),
    }
}

fn validate_p11_prior_reports(root: &Path) -> Result<Vec<GateResult>, String> {
    let current_digest = source_digest(root)?;
    let mut results = Vec::new();
    for phase in [
        "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10",
    ] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS JSON"));
        }
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 gate 報告缺少非空 checks 陣列"))?;
        let mut name_counts = std::collections::HashMap::new();
        for check in checks {
            let name = check
                .get("name")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查缺少名稱"))?;
            *name_counts.entry(name).or_insert(0usize) += 1;
            let command = check
                .get("command")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 command"))?;
            let diagnostic = check
                .get("diagnostic")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 diagnostic 或為空"))?;
            let report_path = check
                .get("report_path")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 report_path"))?;
            let exit_code = check
                .get("exit_code")
                .and_then(StrictJsonValue::as_i32)
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少整數 exit_code"))?;
            if check.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
                return Err(format!("{phase} 前置 gate 檢查 {name} 不是 PASS 狀態"));
            }
            results.push(GateResult {
                name: format!("{phase}-{name}"),
                command: command.to_owned(),
                exit_code,
                status: "PASS",
                diagnostic: format!("前置檢查通過：{diagnostic}"),
                report_path: report_path.to_owned(),
            });
        }
        if phase == "P07" {
            for name in ["p01-before", "p05-before", "p06-before", "p00-p06-before"] {
                if name_counts.get(name) != Some(&1) {
                    return Err(format!("P07 checks 陣列中回歸檢查 {name} 應恰有一筆"));
                }
            }
        }
        validate_report_source_digest(phase, &parsed, &current_digest)?;
        results.push(GateResult {
            name: format!("{phase}-aggregate"),
            command: format!("validate target/rivetlua-reports/gate-{phase}.json"),
            exit_code: 0,
            status: "PASS",
            diagnostic: format!("{phase} aggregate 與 {} 個 checks 均為 PASS", checks.len()),
            report_path: format!("target/rivetlua-reports/gate-{phase}.json"),
        });
    }
    Ok(results)
}

fn p11_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = root.join("target/rivetlua-reports");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P11 報告目錄失敗：{error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P11 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P11-") {
            fs::remove_file(entry.path())
                .map_err(|error| format!("清除舊 P11 案例報告失敗：{error}"))?;
        }
    }
    Ok(())
}

fn write_p11_results(root: &Path, results: &[GateResult], diagnostic: &str) -> Result<(), String> {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P11.json");
    fs::create_dir_all(path.parent().ok_or("無效 P11 gate 報告路徑")?)
        .map_err(|error| format!("建立 P11 報告目錄失敗：{error}"))?;
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"diagnostic\":\"{}\",\"checks\":[{checks}]}}\n",
        json_escape(diagnostic)
    );
    fs::write(path, json).map_err(|error| format!("寫入 P11 gate 報告失敗：{error}"))
}

fn p11_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    p11_fail_with_exit(root, results, name, command, 1, error)
}

fn p11_fail_with_exit(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    exit_code: i32,
    error: String,
) -> Result<(), String> {
    let _ = p11_clear_case_reports(root);
    results.push(p11_result(name, command, exit_code, "FAIL", error.clone()));
    write_p11_results(root, results, &error)?;
    Err(error)
}

fn write_p11_case_report(
    root: &Path,
    case: &P11FixtureCase,
    lua_profile: &str,
    record: &P11Record,
    command: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P11-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P11 case report 路徑")?)
        .map_err(|error| format!("建立 P11 case report 目錄失敗：{error}"))?;
    let diagnostic = format!("{}；{}", case.note, record.diagnostic);
    let json = format!(
        "{{\"case_id\":\"{}\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(&case.profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(&record.actual),
        json_escape(command),
        json_escape(&path.display().to_string()),
        json_escape(&diagnostic),
    );
    fs::write(&path, json).map_err(|error| format!("寫入 P11 case report 失敗：{error}"))?;
    Ok(path)
}

fn p11_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    if let Err(error) = p11_clear_case_reports(&root) {
        return p11_fail(
            &root,
            &mut results,
            "p11-clear-cases",
            "clear old P11 case reports",
            error,
        );
    }
    let gate_report = root.join("target/rivetlua-reports/gate-P11.json");
    if gate_report.exists() {
        if let Err(error) = fs::remove_file(&gate_report) {
            return p11_fail(
                &root,
                &mut results,
                "p11-clear-aggregate",
                "remove old gate-P11.json",
                error.to_string(),
            );
        }
    }

    let prior_command = "validate target/rivetlua-reports/gate-P00.json..gate-P10.json";
    match validate_p11_prior_reports(&root) {
        Ok(prior_results) => results.extend(prior_results),
        Err(error) => return p11_fail(&root, &mut results, "p00-p10-before", prior_command, error),
    }

    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p11_fail(
                &root,
                &mut results,
                "p11-csv",
                "read spec/compatibility.csv",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p11_csv_cases(&csv)) {
        return p11_fail(
            &root,
            &mut results,
            "p11-csv",
            "validate P11 compatibility rows",
            error,
        );
    }
    results.push(p11_result(
        "p11-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各自映射完整 16 個 ERR/COR/CLOSE 案例",
    ));

    let fixture_contents = match fs::read_to_string(root.join(P11_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p11_fail(
                &root,
                &mut results,
                "p11-fixture",
                P11_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p11_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p11_fail(&root, &mut results, "p11-fixture", P11_FIXTURE, error),
    };
    results.push(p11_result(
        "p11-fixture",
        P11_FIXTURE,
        0,
        "PASS",
        "兩個 profile 各有 ERR-001..005、COR-001..006、CLOSE-001..005 共 16 個唯一案例",
    ));

    let unit_command = p11_unit_command();
    let (unit_success, unit_exit_code, unit_output) = match p11_capture_unit(&root) {
        Ok(result) => result,
        Err(error) => {
            return p11_fail(&root, &mut results, "p11-runtime-unit", unit_command, error);
        }
    };
    if !unit_success {
        return p11_fail_with_exit(
            &root,
            &mut results,
            "p11-runtime-unit",
            unit_command,
            unit_exit_code,
            format!("實際 exit={unit_exit_code}；P11 runtime unit 失敗：{unit_output}"),
        );
    }
    if let Err(error) = p11_check_unit_summary(&unit_output) {
        return p11_fail(
            &root,
            &mut results,
            "p11-runtime-unit",
            unit_command,
            format!("{error}；輸出：{unit_output}"),
        );
    }
    results.push(p11_result(
        "p11-runtime-unit",
        unit_command,
        unit_exit_code,
        "PASS",
        "P11 runtime p11_ unit 精確執行 23/23",
    ));

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let selected: Vec<_> = fixture
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let mut profile_records = Vec::new();
        for case in selected {
            let command = p11_case_command(profile, &case.input);
            let (success, exit_code, output) = match p11_capture_case(&root, profile, &case.input) {
                Ok(result) => result,
                Err(error) => return p11_fail(&root, &mut results, &case.id, &command, error),
            };
            let check_name = format!("{}-{lua_profile}", case.id);
            if !success {
                return p11_fail_with_exit(
                    &root,
                    &mut results,
                    &check_name,
                    &command,
                    exit_code,
                    format!("實際 exit={exit_code}；P11 exact case 子行程失敗：{output}"),
                );
            }
            if let Err(error) = p11_check_case_summary(&output) {
                return p11_fail(
                    &root,
                    &mut results,
                    &check_name,
                    &command,
                    format!("{error}；輸出：{output}"),
                );
            }
            let records = match p11_records_from_output(profile, &output) {
                Ok(records) => records,
                Err(error) => return p11_fail(&root, &mut results, &check_name, &command, error),
            };
            if records.len() != 1 {
                return p11_fail(
                    &root,
                    &mut results,
                    &check_name,
                    &command,
                    format!(
                        "{profile} {} exact child marker 數錯誤：預期 1，實際 {}",
                        case.id,
                        records.len()
                    ),
                );
            }
            let case_only = vec![(*case).clone()];
            let actuals = match validate_p11_records(profile, &case_only, &records) {
                Ok(actuals) => actuals,
                Err(error) => return p11_fail(&root, &mut results, &check_name, &command, error),
            };
            let record = actuals
                .get(&case.id)
                .expect("validated P11 case record exists");
            let report_path =
                match write_p11_case_report(&root, case, lua_profile, record, &command) {
                    Ok(path) => path,
                    Err(error) => {
                        return p11_fail(
                            &root,
                            &mut results,
                            &check_name,
                            "write P11 case report",
                            error,
                        );
                    }
                };
            profile_records.extend(records);
            results.push(GateResult {
                name: check_name,
                command: command.clone(),
                exit_code,
                status: "PASS",
                diagnostic: format!(
                    "profile={profile};expected/actual/marker validated; report={}",
                    report_path.display()
                ),
                report_path: report_path.display().to_string(),
            });
        }
        if let Err(error) = validate_p11_records(profile, &fixture, &profile_records) {
            return p11_fail(
                &root,
                &mut results,
                &format!("p11-markers-{lua_profile}"),
                "validate unique P11 formal markers",
                error,
            );
        }
        let counts = ["ERR", "COR", "CLOSE"].map(|category| {
            fixture
                .iter()
                .filter(|case| case.profile == profile && case.id.starts_with(category))
                .count()
        });
        if counts != [5, 6, 5] {
            return p11_fail(
                &root,
                &mut results,
                &format!("p11-case-count-{lua_profile}"),
                "validate P11 per-profile formal case counts",
                format!(
                    "{profile} case 數錯誤：ERR/COR/CLOSE={}/{}/{}",
                    counts[0], counts[1], counts[2]
                ),
            );
        }
        results.push(p11_result(
            format!("p11-profile-{lua_profile}"),
            format!("16 exact formal tests for {profile}"),
            0,
            "PASS",
            format!("{profile} 真正執行 16/16 unique cases：ERR=5 COR=6 CLOSE=5"),
        ));
    }

    let case_names: std::collections::HashSet<_> = results
        .iter()
        .filter(|item| {
            P11_CASE_IDS
                .iter()
                .any(|id| item.name.starts_with(&format!("{id}-")))
        })
        .map(|item| item.name.clone())
        .collect();
    if case_names.len() != 32
        || results
            .iter()
            .filter(|item| {
                P11_CASE_IDS
                    .iter()
                    .any(|id| item.name.starts_with(&format!("{id}-")))
            })
            .count()
            != 32
    {
        return p11_fail(
            &root,
            &mut results,
            "p11-case-count",
            "validate unique P11 case reports",
            format!(
                "P11 唯一 case 報告數錯誤：預期 32，實際 {}",
                case_names.len()
            ),
        );
    }
    write_p11_results(
        &root,
        &results,
        "ERR-001..005、COR-001..006、CLOSE-001..005 依 lua55/lua54 各自逐項 exact 執行，產生 32 份唯一 PASS case JSON",
    )?;
    println!("PASS report={}", gate_report.display());
    Ok(())
}

fn p12_case_spec(id: &str) -> Option<&'static P12CaseSpec> {
    P12_CASE_SPECS.iter().find(|spec| spec.id == id)
}

fn parse_p12_fixture(contents: &str) -> Result<Vec<P12FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    let mut seen_inputs = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P12 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, marker, expected, note]
                if ![profile, id, mode, input, marker, expected, note]
                    .iter()
                    .any(|value| value.is_empty() || value.contains(['\t', '\r', '\n'])) =>
            {
                if !matches!(*profile, "lua55-i64f64" | "lua54-i64f64") {
                    return Err(format!(
                        "P12 fixture 第 {} 行案例 profile 無效",
                        line_index + 1
                    ));
                }
                if !seen_cases.insert((*profile, *id)) {
                    return Err(format!("P12 fixture 案例重複：{profile}/{id}"));
                }
                if !seen_inputs.insert((*profile, *input)) {
                    return Err(format!("P12 fixture test input 重複：{profile}/{input}"));
                }
                cases.push(P12FixtureCase {
                    profile: (*profile).to_owned(),
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    marker: (*marker).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P12 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P12 fixture 缺少正確的兩個 profile 映射".into());
    }
    if cases.len() != P12_CASE_IDS.len() * 2 {
        return Err(format!(
            "P12 fixture 案例數錯誤：預期 20，實際 {}",
            cases.len()
        ));
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let actual_ids: std::collections::HashSet<_> =
            selected.iter().map(|case| case.id.as_str()).collect();
        let expected_ids: std::collections::HashSet<_> = P12_CASE_IDS.into_iter().collect();
        if selected.len() != P12_CASE_IDS.len() || actual_ids != expected_ids {
            return Err(format!(
                "{profile} P12 fixture 缺少、重複或含錯誤 profile 的案例"
            ));
        }
        for case in selected {
            let spec = p12_case_spec(&case.id)
                .ok_or_else(|| format!("P12 fixture 含未知案例：{}", case.id))?;
            if case.mode != spec.mode
                || case.input != spec.test_name
                || case.marker != format!("P12_CASE:{}", spec.id)
                || case.expected != spec.expected
            {
                return Err(format!(
                    "{profile} {} fixture 的 mode/test/marker/expected 對照錯誤",
                    case.id
                ));
            }
        }
    }
    Ok(cases)
}

fn validate_p12_csv_cases(csv: &str) -> Result<(), String> {
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| {
            line.split(',')
                .next()
                .is_some_and(|feature| feature.starts_with("p12."))
        })
        .collect();
    if rows.len() != 2 || rows.iter().any(|row| !row.starts_with("p12.gc-complete,")) {
        return Err(format!("P12 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    let expected_ids = P12_CASE_IDS.join(";");
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P12 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p12.gc-complete"
            || columns[1] != profile
            || columns[2] != "docs/plane/P12.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[4] != expected_ids
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("{profile} P12 CSV 欄位或 test_ids 不完整"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P12 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn p12_records_from_output(profile: &str, output: &str) -> Result<Vec<P12Record>, String> {
    let mut records = Vec::new();
    for output_line in output.lines() {
        if let Some(index) = output_line.find("P12_CASE") {
            let line = output_line[index..]
                .strip_prefix("P12_CASE\t")
                .ok_or_else(|| format!("{profile} P12_CASE marker 格式錯誤：{output_line}"))?;
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields[1] != profile {
                return Err(format!("{profile} P12_CASE 欄位或 profile 錯誤：{line}"));
            }
            let spec = p12_case_spec(fields[0])
                .ok_or_else(|| format!("{profile} P12_CASE 含未知 formal marker：{}", fields[0]))?;
            let payload = fields[2]
                .strip_prefix("status=PASS;actual=")
                .ok_or_else(|| format!("{profile} {} marker 缺 PASS/actual", fields[0]))?;
            let (actual, diagnostic) = payload
                .split_once(";diagnostic=")
                .filter(|(actual, diagnostic)| !actual.is_empty() && !diagnostic.is_empty())
                .ok_or_else(|| format!("{profile} {} marker 缺 diagnostic", fields[0]))?;
            if spec.id != fields[0] {
                return Err(format!("{profile} P12 marker id 不符：{}", fields[0]));
            }
            records.push(P12Record {
                id: fields[0].to_owned(),
                profile: fields[1].to_owned(),
                actual: actual.to_owned(),
                diagnostic: diagnostic.to_owned(),
            });
        }
    }
    Ok(records)
}

fn validate_p12_records(
    profile: &str,
    cases: &[P12FixtureCase],
    records: &[P12Record],
) -> Result<std::collections::HashMap<String, P12Record>, String> {
    let selected_cases: Vec<_> = cases
        .iter()
        .filter(|case| case.profile == profile)
        .collect();
    let selected_ids: std::collections::HashSet<_> =
        selected_cases.iter().map(|case| case.id.as_str()).collect();
    for record in records {
        if record.profile != profile || !selected_ids.contains(record.id.as_str()) {
            return Err(format!(
                "{profile} P12 marker 跨 profile 或不屬於此 profile：{}/{}",
                record.profile, record.id
            ));
        }
        if record.diagnostic.trim().is_empty() {
            return Err(format!("{profile} {} marker diagnostic 為空", record.id));
        }
    }
    let mut actuals = std::collections::HashMap::new();
    for case in selected_cases {
        let found: Vec<_> = records
            .iter()
            .filter(|record| record.id == case.id)
            .collect();
        if found.len() != 1 {
            return Err(format!(
                "{profile} {} marker 數錯誤：預期 1，實際 {}",
                case.id,
                found.len()
            ));
        }
        let record = found[0];
        if record.actual != case.expected {
            return Err(format!(
                "{profile} {} 實際結果不符：expected={} actual={}",
                case.id, case.expected, record.actual
            ));
        }
        actuals.insert(case.id.clone(), record.clone());
    }
    if records.len() != selected_ids.len() {
        return Err(format!(
            "{profile} P12 formal marker 數錯誤：預期 {}，實際 {}",
            selected_ids.len(),
            records.len()
        ));
    }
    Ok(actuals)
}

fn p12_check_case_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P12 crate 外 case 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P12 crate 外 case 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    if passed == Some(1) && failed == Some(0) {
        Ok(())
    } else {
        Err(format!(
            "P12 exact formal case 必須精確通過 1 個測試；摘要={line}"
        ))
    }
}

fn p12_check_filter_summary(filter: &str, output: &str) -> Result<usize, String> {
    let summaries: Vec<_> = output
        .lines()
        .filter(|line| line.contains("test result:"))
        .collect();
    if summaries.is_empty() {
        return Err(format!("P12 runtime filter {filter} 缺少測試摘要"));
    }
    let mut total_passed = 0usize;
    for line in summaries {
        let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
            return Err(format!(
                "P12 runtime filter {filter} 摘要不是成功結果：{line}"
            ));
        };
        let mut fields = summary.split(';').map(str::trim);
        let passed = fields
            .next()
            .and_then(|field| field.strip_suffix(" passed"))
            .and_then(|count| count.parse::<usize>().ok());
        let failed = fields
            .next()
            .and_then(|field| field.strip_suffix(" failed"))
            .and_then(|count| count.parse::<usize>().ok());
        if let (Some(passed), Some(0)) = (passed, failed) {
            total_passed += passed;
        } else {
            return Err(format!(
                "P12 runtime filter {filter} 必須全部成功且無失敗；摘要={line}"
            ));
        }
    }
    if total_passed == 0 {
        return Err(format!("P12 runtime filter {filter} 必須至少匹配一個測試"));
    }
    Ok(total_passed)
}

fn p12_check_unit_summary(output: &str) -> Result<usize, String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("P12 runtime unit 缺少測試摘要".into());
    };
    let Some(summary) = line.split_once("test result: ok. ").map(|(_, rest)| rest) else {
        return Err("P12 runtime unit 摘要不是成功結果".into());
    };
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()
        .and_then(|field| field.strip_suffix(" passed"))
        .and_then(|count| count.parse::<usize>().ok());
    let failed = fields
        .next()
        .and_then(|field| field.strip_suffix(" failed"))
        .and_then(|count| count.parse::<usize>().ok());
    match (passed, failed) {
        (Some(passed), Some(0)) if passed > 0 => Ok(passed),
        _ => Err(format!(
            "P12 runtime unit 必須匹配非零且無失敗；摘要={line}"
        )),
    }
}

fn p12_case_command(profile: &str, test_name: &str) -> String {
    format!(
        "RIVETLUA_P12_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p12_contracts {test_name} -- --nocapture --exact --test-threads=1"
    )
}

fn p12_capture_case(
    root: &Path,
    profile: &str,
    test_name: &str,
) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p12_contracts",
            test_name,
            "--",
            "--nocapture",
            "--exact",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P12_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P12 formal case {test_name} 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    Ok((
        success,
        exit_code,
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

fn p12_capture_command(root: &Path, arguments: &[&str]) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P12 子命令失敗：{error}"))?;
    Ok((
        output.status.success(),
        output.status.code().unwrap_or(1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

fn p12_unit_command() -> &'static str {
    "cargo test --locked -p rivetlua-runtime --lib p12_ -- --test-threads=1"
}

fn p12_reentry_command() -> &'static str {
    "cargo test --locked -p rivetlua-runtime --lib vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue -- --exact --test-threads=1"
}

fn p12_check_reentry_summary(output: &str) -> Result<(), String> {
    let Some(line) = output.lines().find(|line| line.contains("test result:")) else {
        return Err("GC-009 GC reentry unit 缺少測試摘要".into());
    };
    if !line.contains("test result: ok. 1 passed; 0 failed")
        || !output.contains("vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue ... ok")
    {
        return Err(format!("GC-009 GC reentry exact unit 未精確通過：{line}"));
    }
    Ok(())
}

fn p12_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P12.json".into(),
    }
}

fn p12_validate_p11_root_evidence(root: &Path, checks: &[StrictJsonValue]) -> Result<(), String> {
    for name in ["p11-runtime-unit", "ERR-001-lua55", "ERR-001-lua54"] {
        let matching: Vec<_> = checks
            .iter()
            .filter(|check| check.get("name").and_then(StrictJsonValue::as_str) == Some(name))
            .collect();
        if matching.len() != 1
            || matching[0].get("status").and_then(StrictJsonValue::as_str) != Some("PASS")
        {
            return Err(format!("P11 roots 前置證據 {name} 缺少或不是唯一 PASS"));
        }
    }
    for profile in ["lua55", "lua54"] {
        let path = root.join(format!(
            "target/rivetlua-reports/P11-ERR-001-{profile}.json"
        ));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 P11 root case 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("P11 root case 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS")
            || parsed.get("actual").and_then(StrictJsonValue::as_str)
                != Some("identity=preserved;nested=nearest;host_root=owned")
            || !parsed
                .get("diagnostic")
                .and_then(StrictJsonValue::as_str)
                .is_some_and(|diagnostic| diagnostic.contains("宿主 handle 根生命週期"))
        {
            return Err(format!("P11 {profile} host root case evidence 不完整"));
        }
    }
    Ok(())
}

fn p12_validate_prior_reports(root: &Path) -> Result<Vec<GateResult>, String> {
    let current_digest = source_digest(root)?;
    let mut results = Vec::new();
    let phases = [
        "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10", "P11",
    ];
    for phase in phases {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS JSON"));
        }
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 gate 報告缺少非空 checks 陣列"))?;
        for check in checks {
            let name = check
                .get("name")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查缺少名稱"))?;
            for (field, description) in [
                ("command", "command"),
                ("diagnostic", "diagnostic"),
                ("report_path", "report_path"),
            ] {
                if !check
                    .get(field)
                    .and_then(StrictJsonValue::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    return Err(format!("{phase} 前置 gate 檢查 {name} 缺少 {description}"));
                }
            }
            if check
                .get("exit_code")
                .and_then(StrictJsonValue::as_i32)
                .is_none()
            {
                return Err(format!("{phase} 前置 gate 檢查 {name} 缺少整數 exit_code"));
            }
            if check.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
                return Err(format!("{phase} 前置 gate 檢查 {name} 不是 PASS"));
            }
        }
        if phase == "P07" {
            for name in ["p01-before", "p05-before", "p06-before", "p00-p06-before"] {
                let matches = checks
                    .iter()
                    .filter(|check| {
                        check.get("name").and_then(StrictJsonValue::as_str) == Some(name)
                    })
                    .count();
                if matches != 1 {
                    return Err(format!("P07 checks 陣列中回歸檢查 {name} 應恰有一筆"));
                }
            }
        }
        validate_report_source_digest(phase, &parsed, &current_digest)?;
        if phase == "P05" {
            for name in [
                "p05-dependency-graph",
                "p05-core-bytecode",
                "p05-bytecode-contracts",
            ] {
                if checks
                    .iter()
                    .filter(|check| {
                        check.get("name").and_then(StrictJsonValue::as_str) == Some(name)
                    })
                    .count()
                    != 1
                {
                    return Err(format!(
                        "P05 InstructionEffects/owner 前置證據 {name} 缺少或重複"
                    ));
                }
            }
            for id in 1..=10 {
                for profile in ["lua55", "lua54"] {
                    let name = format!("BC-{id:03}-{profile}");
                    if checks
                        .iter()
                        .filter(|check| {
                            check.get("name").and_then(StrictJsonValue::as_str)
                                == Some(name.as_str())
                        })
                        .count()
                        != 1
                    {
                        return Err(format!(
                            "P05 RVLU_V2/InstructionEffects case 缺少或重複：{name}"
                        ));
                    }
                }
            }
            results.push(p12_result(
                "p05-effects",
                "validate P05 RVLU_V2 InstructionEffects report",
                0,
                "PASS",
                "fresh P05 bytecode/effects checks 與 BC-001..010 雙 profile 均通過",
            ));
        }
        if phase == "P11" {
            p12_validate_p11_root_evidence(root, checks)?;
            results.push(p12_result(
                "p11-error-coroutine-roots",
                "validate P11 error host-root evidence",
                0,
                "PASS",
                "P11 unit 與兩 profile ERR-001 host root case 報告均為 PASS",
            ));
        }
        results.push(p12_result(
            format!("{phase}-aggregate"),
            format!("validate target/rivetlua-reports/gate-{phase}.json"),
            0,
            "PASS",
            format!(
                "{phase} fresh source_digest 與 {} 個 checks 均為 PASS",
                checks.len()
            ),
        ));
    }

    let dependency_path = root.join("spec/phase-dependencies.csv");
    let dependency_csv = fs::read_to_string(&dependency_path)
        .map_err(|error| format!("讀取 phase dependencies 失敗：{error}"))?;
    validate_phase_dependency_graph(&dependency_csv)?;
    for row in [
        "DA-15,P11,P12,error coroutine close-stack roots,CONTRACTED,P11",
        "DA-16,P05,P12,InstructionEffects safepoint/root input; P12 owns Trace write_ref barrier,CONTRACTED,P12",
        "DA-18,P05,P20,InstructionEffects canonical RVLU_V2 flags,IMPLEMENTED,P05",
    ] {
        if !dependency_csv.lines().any(|line| line == row) {
            return Err(format!("P12 dependency contract row 不符：{row}"));
        }
    }
    Ok(results)
}

fn p12_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = root.join("target/rivetlua-reports");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P12 報告目錄失敗：{error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P12 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P12-") {
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(path)
                    .map_err(|error| format!("清除舊 P12 案例報告目錄失敗：{error}"))?;
            } else {
                fs::remove_file(path)
                    .map_err(|error| format!("清除舊 P12 案例報告失敗：{error}"))?;
            }
        }
    }
    Ok(())
}

fn write_p12_results(root: &Path, results: &[GateResult], diagnostic: &str) -> Result<(), String> {
    let source_digest = source_digest(root)?;
    let path = root.join("target/rivetlua-reports/gate-P12.json");
    fs::create_dir_all(path.parent().ok_or("無效 P12 gate 報告路徑")?)
        .map_err(|error| format!("建立 P12 報告目錄失敗：{error}"))?;
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"diagnostic\":\"{}\",\"checks\":[{checks}]}}\n",
        json_escape(diagnostic)
    );
    fs::write(path, json).map_err(|error| format!("寫入 P12 gate 報告失敗：{error}"))
}

fn p12_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    exit_code: i32,
    error: String,
) -> Result<(), String> {
    let _ = p12_clear_case_reports(root);
    results.push(p12_result(
        name,
        command,
        exit_code.max(1),
        "FAIL",
        error.clone(),
    ));
    write_p12_results(root, results, &error)?;
    Err(error)
}

fn write_p12_case_report(
    root: &Path,
    case: &P12FixtureCase,
    lua_profile: &str,
    record: &P12Record,
    command: &str,
) -> Result<PathBuf, String> {
    let source_digest = source_digest(root)?;
    let path = root.join(format!(
        "target/rivetlua-reports/P12-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P12 case report 路徑")?)
        .map_err(|error| format!("建立 P12 case report 目錄失敗：{error}"))?;
    let composite = if case.id == "GC-009" {
        "composite evidence: gc_case_009 yield/error assertions plus exact runtime unit vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue PASS; the formal case itself does not execute GC reentry"
    } else {
        "formal integration case marker matched"
    };
    let diagnostic = format!("{}；{}；{}", case.note, record.diagnostic, composite);
    let json = format!(
        "{{\"case_id\":\"{}\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"source_digest\":\"{}\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(&case.profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(&record.actual),
        json_escape(&source_digest),
        json_escape(command),
        json_escape(&path.display().to_string()),
        json_escape(&diagnostic),
    );
    fs::write(&path, json).map_err(|error| format!("寫入 P12 case report 失敗：{error}"))?;
    Ok(path)
}

fn p12_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    if let Err(error) = p12_clear_case_reports(&root) {
        return p12_fail(
            &root,
            &mut results,
            "p12-clear-cases",
            "clear old P12 reports",
            1,
            error,
        );
    }
    let gate_report = root.join("target/rivetlua-reports/gate-P12.json");
    if gate_report.exists() {
        if let Err(error) = fs::remove_file(&gate_report) {
            return p12_fail(
                &root,
                &mut results,
                "p12-clear-aggregate",
                "remove old gate-P12.json",
                1,
                format!("移除舊 P12 aggregate 失敗：{error}"),
            );
        }
    }
    match p12_validate_prior_reports(&root) {
        Ok(prior_results) => results.extend(prior_results),
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p00-p11-before",
                "validate fresh P00-P11 PASS reports and source_digest",
                1,
                error,
            );
        }
    }
    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p12-csv",
                "read P12 compatibility rows",
                1,
                format!("讀取 P12 compatibility CSV 失敗：{error}"),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p12_csv_cases(&csv)) {
        return p12_fail(
            &root,
            &mut results,
            "p12-csv",
            "validate P12 compatibility rows",
            1,
            format!("P12 compatibility CSV 驗證失敗：{error}"),
        );
    }
    results.push(p12_result(
        "p12-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各自映射 GC-001..GC-010，僅有兩列 P12 exact set",
    ));
    let fixture_contents = match fs::read_to_string(root.join(P12_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p12-fixture",
                P12_FIXTURE,
                1,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p12_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p12_fail(&root, &mut results, "p12-fixture", P12_FIXTURE, 1, error),
    };
    results.push(p12_result(
        "p12-fixture",
        P12_FIXTURE,
        0,
        "PASS",
        "兩 profile 各有 GC-001..GC-010 唯一案例與固定 mode/test/marker/expected 對照",
    ));

    let unit_command = p12_unit_command();
    let (unit_success, unit_exit, unit_output) = match p12_capture_command(
        &root,
        &[
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "p12_",
            "--",
            "--test-threads=1",
        ],
    ) {
        Ok(result) => result,
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p12-runtime-unit",
                unit_command,
                1,
                error,
            );
        }
    };
    if !unit_success {
        return p12_fail(
            &root,
            &mut results,
            "p12-runtime-unit",
            unit_command,
            unit_exit,
            format!("實際 exit={unit_exit}；P12 runtime unit 失敗：{unit_output}"),
        );
    }
    let unit_count = match p12_check_unit_summary(&unit_output) {
        Ok(count) => count,
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p12-runtime-unit",
                unit_command,
                1,
                format!("{error}；輸出：{unit_output}"),
            );
        }
    };
    results.push(p12_result(
        "p12-runtime-unit",
        unit_command,
        unit_exit,
        "PASS",
        format!("P12 runtime unit 非零匹配且全數通過：{unit_count} 個"),
    ));

    for filter in [
        "gc",
        "weak",
        "ephemeron",
        "finalizer",
        "allocation_failure",
        "vm_lifecycle",
    ] {
        let command =
            format!("cargo test --locked -p rivetlua-runtime {filter} -- --test-threads=1");
        let (success, exit_code, output) = match p12_capture_command(
            &root,
            &[
                "test",
                "--locked",
                "-p",
                "rivetlua-runtime",
                filter,
                "--",
                "--test-threads=1",
            ],
        ) {
            Ok(result) => result,
            Err(error) => {
                return p12_fail(
                    &root,
                    &mut results,
                    &format!("p12-filter-{filter}"),
                    &command,
                    1,
                    error,
                );
            }
        };
        if !success {
            return p12_fail(
                &root,
                &mut results,
                &format!("p12-filter-{filter}"),
                &command,
                exit_code,
                format!("實際 exit={exit_code}；filter {filter} 執行失敗：{output}"),
            );
        }
        let count = match p12_check_filter_summary(filter, &output) {
            Ok(count) => count,
            Err(error) => {
                return p12_fail(
                    &root,
                    &mut results,
                    &format!("p12-filter-{filter}"),
                    &command,
                    1,
                    format!("{error}；輸出：{output}"),
                );
            }
        };
        results.push(p12_result(
            format!("p12-filter-{filter}"),
            command,
            exit_code,
            "PASS",
            format!("P12 指定 runtime filter {filter} 非零匹配：{count} 個"),
        ));
    }

    let reentry_command = p12_reentry_command();
    let (reentry_success, reentry_exit, reentry_output) = match p12_capture_command(
        &root,
        &[
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue",
            "--",
            "--exact",
            "--test-threads=1",
        ],
    ) {
        Ok(result) => result,
        Err(error) => {
            return p12_fail(
                &root,
                &mut results,
                "p12-reentry-unit",
                reentry_command,
                1,
                error,
            );
        }
    };
    if !reentry_success {
        return p12_fail(
            &root,
            &mut results,
            "p12-reentry-unit",
            reentry_command,
            reentry_exit,
            format!("實際 exit={reentry_exit}；GC-009 reentry exact unit 失敗：{reentry_output}"),
        );
    }
    if let Err(error) = p12_check_reentry_summary(&reentry_output) {
        return p12_fail(
            &root,
            &mut results,
            "p12-reentry-unit",
            reentry_command,
            1,
            format!("{error}；輸出：{reentry_output}"),
        );
    }
    results.push(p12_result(
        "p12-reentry-unit",
        reentry_command,
        reentry_exit,
        "PASS",
        "GC-009 composite evidence: exact runtime unit vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue passed independently of gc_case_009 yield/error assertions",
    ));

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let selected: Vec<_> = fixture
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        let mut profile_records = Vec::new();
        for case in selected {
            let command = p12_case_command(profile, &case.input);
            let (success, exit_code, output) = match p12_capture_case(&root, profile, &case.input) {
                Ok(result) => result,
                Err(error) => return p12_fail(&root, &mut results, &case.id, &command, 1, error),
            };
            let check_name = format!("{}-{lua_profile}", case.id);
            if !success {
                return p12_fail(
                    &root,
                    &mut results,
                    &check_name,
                    &command,
                    exit_code,
                    format!("實際 exit={exit_code}；P12 exact case 子行程失敗：{output}"),
                );
            }
            if let Err(error) = p12_check_case_summary(&output) {
                return p12_fail(
                    &root,
                    &mut results,
                    &check_name,
                    &command,
                    1,
                    format!("{error}；輸出：{output}"),
                );
            }
            let records = match p12_records_from_output(profile, &output) {
                Ok(records) => records,
                Err(error) => {
                    return p12_fail(&root, &mut results, &check_name, &command, 1, error);
                }
            };
            let case_only = vec![case.clone()];
            let actuals = match validate_p12_records(profile, &case_only, &records) {
                Ok(actuals) => actuals,
                Err(error) => {
                    return p12_fail(&root, &mut results, &check_name, &command, 1, error);
                }
            };
            let record = actuals
                .get(&case.id)
                .expect("validated P12 case record exists");
            let report_path =
                match write_p12_case_report(&root, case, lua_profile, record, &command) {
                    Ok(path) => path,
                    Err(error) => {
                        return p12_fail(
                            &root,
                            &mut results,
                            &check_name,
                            "write P12 case report",
                            1,
                            error,
                        );
                    }
                };
            profile_records.extend(records);
            let diagnostic = if case.id == "GC-009" {
                format!(
                    "profile={profile};yield/error formal assertions passed; GC reentry is a separate exact runtime unit required by this gate; report={}",
                    report_path.display()
                )
            } else {
                format!(
                    "profile={profile};expected/actual/marker validated; report={}",
                    report_path.display()
                )
            };
            results.push(GateResult {
                name: check_name,
                command: command.clone(),
                exit_code,
                status: "PASS",
                diagnostic,
                report_path: report_path.display().to_string(),
            });
        }
        if let Err(error) = validate_p12_records(profile, &fixture, &profile_records) {
            return p12_fail(
                &root,
                &mut results,
                &format!("p12-markers-{lua_profile}"),
                "validate unique P12 formal markers",
                1,
                error,
            );
        }
        if profile_records.len() != P12_CASE_IDS.len() {
            return p12_fail(
                &root,
                &mut results,
                &format!("p12-case-count-{lua_profile}"),
                "validate P12 per-profile formal case count",
                1,
                format!(
                    "{profile} P12 案例數錯誤：預期 10，實際 {}",
                    profile_records.len()
                ),
            );
        }
        results.push(p12_result(
            format!("p12-profile-{lua_profile}"),
            format!("10 exact formal tests for {profile}"),
            0,
            "PASS",
            format!("{profile} 真正執行 10/10 GC-001..GC-010 unique cases"),
        ));
    }
    let case_names: std::collections::HashSet<_> = results
        .iter()
        .filter(|item| {
            P12_CASE_IDS
                .iter()
                .any(|id| item.name.starts_with(&format!("{id}-")))
        })
        .map(|item| item.name.clone())
        .collect();
    let case_count = results
        .iter()
        .filter(|item| {
            P12_CASE_IDS
                .iter()
                .any(|id| item.name.starts_with(&format!("{id}-")))
        })
        .count();
    if case_count != 20 || case_names.len() != 20 {
        return p12_fail(
            &root,
            &mut results,
            "p12-case-count",
            "validate unique P12 case reports",
            1,
            format!(
                "P12 唯一 case 報告數錯誤：預期 20，實際 {case_count} unique={}",
                case_names.len()
            ),
        );
    }
    write_p12_results(
        &root,
        &results,
        "兩 profile 各逐項 exact 執行 GC-001..GC-010，共 20 份唯一 PASS；GC-009 同時要求 yield/error formal case 與獨立 reentrant-GC unit PASS",
    )?;
    println!("PASS report={}", gate_report.display());
    Ok(())
}

fn parse_p08_fixture(contents: &str) -> Result<Vec<P08FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P08 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", id, mode, input, expected, note]
                if !id.is_empty()
                    && !mode.is_empty()
                    && !input.is_empty()
                    && !expected.is_empty()
                    && !note.is_empty()
                    && !input.contains('\t')
                    && !input.contains('\n') =>
            {
                if !seen_cases.insert(*id) {
                    return Err(format!("P08 fixture 案例重複：{id}"));
                }
                cases.push(P08FixtureCase {
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P08 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P08 fixture 缺少正確的兩個 profile 映射".into());
    }
    let actual: std::collections::HashSet<_> = cases.iter().map(|case| case.id.as_str()).collect();
    let expected: std::collections::HashSet<_> = P08_CASES.into_iter().collect();
    if cases.len() != P08_CASES.len() || actual != expected {
        return Err("P08 fixture 缺少、重複或含未知案例".into());
    }
    let expected_pairs = [
        ("TAB-001", "compiler-vm", "Returned(2)"),
        ("TAB-002", "compiler-vm", "Returned(Integer(7))"),
        ("TAB-003", "compiler-vm", "Returned(Boolean(false))"),
        ("TAB-004", "raw-api", "NilTableKey"),
        ("TAB-005", "raw-api", "NaNTableKey"),
        ("TAB-006", "compiler-vm", "Returned(Nil)"),
        ("TAB-007", "compiler-vm", "valid_border"),
        (
            "TAB-008",
            "runtime-contract",
            "stack_objects_reclaimed_then_removed_5_table_1",
        ),
        ("TAB-009", "runtime-contract", "fields_and_ledger_unchanged"),
        ("TAB-010", "runtime-internal", "five_fields_each_once"),
        ("TAB-011", "raw-api", "Nil"),
        ("TAB-012", "raw-api", "Nil"),
    ];
    for (id, mode, expected) in expected_pairs {
        let case = cases.iter().find(|case| case.id == id).unwrap();
        if case.mode != mode || case.expected != expected {
            return Err(format!("P08 fixture 案例 {id} mode／expected 映射錯誤"));
        }
    }
    Ok(cases)
}

fn validate_p08_csv_cases(csv: &str) -> Result<(), String> {
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("p08.string-table,"))
        .collect();
    if rows.len() != 2 {
        return Err(format!("P08 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    let expected: std::collections::HashSet<_> = P08_CASES.into_iter().collect();
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P08 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p08.string-table"
            || columns[1] != profile
            || columns[2] != "docs/plane/P08.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[5] != "PASS"
        {
            return Err(format!("{profile} P08 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.len() != P08_CASES.len()
            || ids.iter().any(|id| id.is_empty())
            || actual.len() != ids.len()
            || actual != expected
        {
            return Err(format!("{profile} P08 test_ids 不完整、重複或未知"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P08 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn p08_records_from_output(profile: &str, output: &str) -> Result<Vec<P08Record>, String> {
    output
        .lines()
        .filter_map(|line| line.find("P08_CASE\t").map(|index| &line[index..]))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if !(6..=7).contains(&fields.len()) || fields[0] != "P08_CASE" {
                return Err(format!("{profile} P08_CASE 欄位不完整：{line}"));
            }
            let (input, expected) = if fields[3].starts_with("input_order=") {
                if fields.len() != 6 || !fields[4].starts_with("expected_fields=") {
                    return Err(format!("{profile} TAB-010 欄位不完整：{line}"));
                }
                (
                    fields[3].strip_prefix("input_order=").unwrap().to_owned(),
                    fields[4]
                        .strip_prefix("expected_fields=")
                        .unwrap()
                        .to_owned(),
                )
            } else {
                let input = fields[3]
                    .strip_prefix("input=")
                    .ok_or_else(|| format!("{profile} P08_CASE 缺 input：{line}"))?;
                let expected = fields[4]
                    .strip_prefix("expected=")
                    .ok_or_else(|| format!("{profile} P08_CASE 缺 expected：{line}"))?;
                (input.to_owned(), expected.to_owned())
            };
            let actual = fields[5]
                .strip_prefix("actual=")
                .ok_or_else(|| format!("{profile} P08_CASE 缺 actual：{line}"))?;
            let diagnostic = fields
                .get(6)
                .map(|field| field.strip_prefix("diagnostic=").unwrap_or(field))
                .unwrap_or("");
            if fields[1].is_empty()
                || fields[2].is_empty()
                || input.is_empty()
                || actual.is_empty()
                || (fields.len() == 7 && diagnostic.is_empty())
            {
                return Err(format!("{profile} P08_CASE 含空欄位：{line}"));
            }
            Ok(P08Record {
                id: fields[1].to_owned(),
                profile: fields[2].to_owned(),
                input,
                expected,
                actual: actual.to_owned(),
                diagnostic: diagnostic.to_owned(),
            })
        })
        .collect()
}

fn validate_p08_records(
    profile: &str,
    cases: &[P08FixtureCase],
    records: &[P08Record],
) -> Result<(), String> {
    let mut by_id: std::collections::HashMap<&str, Vec<&P08Record>> =
        std::collections::HashMap::new();
    for record in records {
        if record.profile != profile {
            return Err(format!(
                "P08 案例 {} profile 不符：{}",
                record.id, record.profile
            ));
        }
        if !cases.iter().any(|case| case.id == record.id) {
            return Err(format!("P08 案例未知：{}", record.id));
        }
        by_id.entry(&record.id).or_default().push(record);
    }
    for case in cases {
        let found = by_id
            .get(case.id.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let expected_count = if case.id == "TAB-010" { 2 } else { 1 };
        if found.len() != expected_count {
            return Err(format!(
                "{profile} {} 記錄數錯誤：預期 {expected_count}，實際 {}",
                case.id,
                found.len()
            ));
        }
        for record in found {
            if case.id == "TAB-010" {
                if record.expected != "5" || record.actual.is_empty() {
                    return Err("TAB-010 欄位集合記錄不完整".into());
                }
            } else {
                let expected_input = if case.mode == "compiler-vm" {
                    format!("{:?}", case.input.as_bytes())
                } else {
                    case.input.clone()
                };
                if record.input != expected_input || record.expected != case.expected {
                    return Err(format!("{} input／expected 與 fixture 不符", case.id));
                }
            }
            let valid_actual = match case.id.as_str() {
                "TAB-001" => record.actual.contains("Integer(2)"),
                "TAB-002" => record.actual.contains("Integer(7)"),
                "TAB-003" => record.actual.contains("Boolean(false)"),
                "TAB-004" => {
                    record.actual.contains("Err(NilTableKey)") && !record.diagnostic.is_empty()
                }
                "TAB-005" => {
                    record.actual.contains("Err(NaNTableKey)") && !record.diagnostic.is_empty()
                }
                "TAB-006" => record.actual.contains("Returned([Nil])"),
                "TAB-007" => record.actual.contains("Returned([Integer("),
                "TAB-008" => [
                    "stack_objects_reclaimed,true",
                    "live,true",
                    "removed,5",
                    "table_reclaimed,1",
                    "reserved,0",
                ]
                .iter()
                .all(|field| record.actual.contains(field)),
                "TAB-009" => ["fields_unchanged,true", "roots,1", "reserved,0"]
                    .iter()
                    .all(|field| record.actual.contains(field)),
                "TAB-010" => true,
                "TAB-011" | "TAB-012" => record.actual.contains("Ok(Nil)"),
                _ => false,
            };
            if !valid_actual {
                return Err(format!(
                    "{} actual 結果不符合契約：{}",
                    case.id, record.actual
                ));
            }
        }
        if case.id == "TAB-010" {
            let mut orders: Vec<_> = found.iter().map(|record| record.input.as_str()).collect();
            orders.sort_unstable();
            if orders != ["[0, 1, 2, 3, 4]", "[4, 3, 2, 1, 0]"]
                || found[0].actual != found[1].actual
            {
                return Err("TAB-010 必須驗證兩種插入順序且欄位集合相同".into());
            }
        }
    }
    if records.len() != P08_CASES.len() + 1 {
        return Err(format!(
            "{profile} P08_CASE 記錄總數錯誤：{}",
            records.len()
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P07FixtureCase {
    id: String,
    mode: String,
    input: String,
    expected: String,
    note: String,
}

fn parse_p07_fixture(contents: &str) -> Result<Vec<P07FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P07 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", id, mode, input, expected, note]
                if !id.is_empty()
                    && !mode.is_empty()
                    && !input.is_empty()
                    && !expected.is_empty()
                    && !input.contains('\t')
                    && !input.contains('\n') =>
            {
                if !seen_cases.insert(*id) {
                    return Err(format!("P07 fixture 案例重複：{id}"));
                }
                cases.push(P07FixtureCase {
                    id: (*id).to_owned(),
                    mode: (*mode).to_owned(),
                    input: (*input).to_owned(),
                    expected: (*expected).to_owned(),
                    note: (*note).to_owned(),
                });
            }
            _ => return Err(format!("P07 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P07 fixture 缺少正確的兩個 profile 映射".into());
    }
    let actual: std::collections::HashSet<_> = cases.iter().map(|case| case.id.as_str()).collect();
    let expected: std::collections::HashSet<_> = P07_CASES.into_iter().collect();
    if cases.len() != P07_CASES.len() || actual != expected {
        return Err("P07 fixture 缺少、重複或含未知案例".into());
    }
    for case in cases
        .iter()
        .filter(|case| matches!(case.id.as_str(), "VM-005" | "VM-007"))
    {
        if case.input != "while true do end"
            || !case.note.contains("compiler-produced")
            || !case.note.contains("implicit terminal Return(Fixed(0))")
            || !case.note.contains("compiler codegen")
        {
            return Err(format!(
                "{} 未記錄 compiler-produced module 與 codegen 隱式終端 Return",
                case.id
            ));
        }
    }
    Ok(cases)
}

fn validate_p07_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P07_CASES.into_iter().collect();
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("p07.vm,"))
        .collect();
    if rows.len() != 2 {
        return Err(format!("P07 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P07 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p07.vm"
            || columns[1] != profile
            || columns[2] != "docs/plane/P07.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime"
            || columns[5] != "PASS"
        {
            return Err(format!("{profile} P07 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty())
            || ids.len() != P07_CASES.len()
            || actual.len() != ids.len()
            || actual != expected
        {
            return Err(format!("{profile} P07 test_ids 不完整、重複或未知"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P07 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

fn validate_p07_records(
    profile: &str,
    expected_cases: &[P07FixtureCase],
    records: &[(String, String, String, String)],
) -> Result<(), String> {
    let expected: std::collections::HashMap<_, _> = expected_cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();
    let mut seen = std::collections::HashSet::new();
    for (id, actual_profile, input, actual) in records {
        if actual_profile != profile {
            return Err(format!("P07 案例 {id} profile 不符：{actual_profile}"));
        }
        let Some(case) = expected.get(id.as_str()) else {
            return Err(format!("P07 案例未知：{id}"));
        };
        if !seen.insert(id.as_str()) {
            return Err(format!("P07 案例重複：{id}"));
        }
        if input != &case.input || actual.is_empty() || !actual.contains(&case.expected) {
            return Err(format!("P07 案例 {id} input／expected／actual 不符"));
        }
        if !actual.contains("fuel_remaining=") || !actual.contains("pc=") {
            return Err(format!("P07 案例 {id} 缺 fuel／pc 證據"));
        }
    }
    if records.len() != expected_cases.len() || seen.len() != expected_cases.len() {
        return Err(format!("{profile} P07 案例缺少記錄"));
    }
    Ok(())
}

const STRICT_GLOBAL_CFLAGS: &str = "-DLUA_COMPAT_GLOBAL=0";

fn write_p02_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P02.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let entries = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{entries}]}}\n"
        ),
    );
}

fn p02_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P02.json".into(),
    }
}

fn p03_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P03.json".into(),
    }
}

fn p04_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P04.json".into(),
    }
}

fn p05_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P05.json".into(),
    }
}

fn p02_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p02_result(name, command, 1, "FAIL", error.clone()));
    write_p02_results(root, results);
    Err(error)
}

fn validate_p02_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P02_CASES.into_iter().collect();
    for profile in ["lua55", "lua54"] {
        let rows: Vec<_> = csv
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with(&format!("p02.lexer,{profile},")) && line.contains(",PASS,")
            })
            .collect();
        if rows.len() != 1 {
            return Err(format!("{profile} P02 PASS 列數不正確"));
        }
        let columns: Vec<_> = rows[0].split(',').collect();
        if columns.len() != 7 || columns[1] != profile || columns[3] != "rivetlua-compiler" {
            return Err(format!("{profile} P02 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty()) || actual.len() != ids.len() || actual != expected {
            return Err(format!("{profile} P02 test_ids 不完整、重複或未知"));
        }
    }
    Ok(())
}

fn validate_p03_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P03_CASES.into_iter().collect();
    for profile in ["lua55", "lua54"] {
        let rows: Vec<_> = csv
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with(&format!("p03.parser,{profile},")) && line.contains(",PASS,")
            })
            .collect();
        if rows.len() != 1 {
            return Err(format!("{profile} P03 PASS 列數不正確"));
        }
        let columns: Vec<_> = rows[0].split(',').collect();
        if columns.len() != 7 || columns[1] != profile || columns[3] != "rivetlua-compiler" {
            return Err(format!("{profile} P03 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty()) || actual.len() != ids.len() || actual != expected {
            return Err(format!("{profile} P03 test_ids 不完整、重複或未知"));
        }
    }
    Ok(())
}

fn validate_p04_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P04_CASES.into_iter().collect();
    for profile in ["lua55", "lua54"] {
        let rows: Vec<_> = csv
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with(&format!("p04.resolve,{profile},")) && line.contains(",PASS,")
            })
            .collect();
        if rows.len() != 1 {
            return Err(format!("{profile} P04 PASS 列數不正確"));
        }
        let columns: Vec<_> = rows[0].split(',').collect();
        if columns.len() != 7 || columns[1] != profile || columns[3] != "rivetlua-compiler" {
            return Err(format!("{profile} P04 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty()) || actual.len() != ids.len() || actual != expected {
            return Err(format!("{profile} P04 test_ids 不完整、重複或未知"));
        }
    }
    Ok(())
}

fn validate_p05_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P05_CASES.into_iter().collect();
    for profile in ["lua55", "lua54"] {
        let rows: Vec<_> = csv
            .lines()
            .skip(1)
            .filter(|line| {
                line.starts_with(&format!("p05.bytecode,{profile},")) && line.contains(",PASS,")
            })
            .collect();
        if rows.len() != 1 {
            return Err(format!("{profile} P05 PASS 列數不正確"));
        }
        let columns: Vec<_> = rows[0].split(',').collect();
        if columns.len() != 7
            || columns[1] != profile
            || columns[3] != "rivetlua-core;rivetlua-compiler"
        {
            return Err(format!("{profile} P05 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty()) || actual.len() != ids.len() || actual != expected {
            return Err(format!("{profile} P05 test_ids 不完整、重複或未知"));
        }
    }
    Ok(())
}

fn validate_p06_csv_cases(csv: &str) -> Result<(), String> {
    let expected: std::collections::HashSet<_> = P06_CASES.into_iter().collect();
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("p06.heap,"))
        .collect();
    if rows.len() != 2 {
        return Err(format!("P06 CSV 列數錯誤：預期 2，實際 {}", rows.len()));
    }
    for profile in ["lua55", "lua54"] {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if selected.len() != 1 {
            return Err(format!("{profile} P06 PASS 列數不正確"));
        }
        let columns: Vec<_> = selected[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p06.heap"
            || columns[1] != profile
            || columns[3] != "rivetlua-runtime"
            || columns[5] != "PASS"
        {
            return Err(format!("{profile} P06 CSV 欄位不正確"));
        }
        let ids: Vec<_> = columns[4].split(';').collect();
        let actual: std::collections::HashSet<_> = ids.iter().copied().collect();
        if ids.iter().any(|id| id.is_empty())
            || ids.len() != P06_CASES.len()
            || actual.len() != ids.len()
            || actual != expected
        {
            return Err(format!("{profile} P06 test_ids 不完整、重複或未知"));
        }
    }
    if rows.iter().any(|row| {
        let columns: Vec<_> = row.split(',').collect();
        columns.len() != 7 || !matches!(columns[1], "lua55" | "lua54")
    }) {
        return Err("P06 CSV 含錯誤 profile 或欄位數".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct P06FixtureCase {
    id: String,
    input: String,
}

fn parse_p06_fixture(contents: &str) -> Result<Vec<P06FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen_cases = std::collections::HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P06 fixture 第 {} 行 profile 無效或重複",
                        line_index + 1
                    ));
                }
            }
            ["case", id, input] if !id.is_empty() && !input.is_empty() => {
                if !seen_cases.insert(*id) {
                    return Err(format!("P06 fixture 案例重複：{id}"));
                }
                cases.push(P06FixtureCase {
                    id: (*id).to_owned(),
                    input: (*input).to_owned(),
                });
            }
            _ => return Err(format!("P06 fixture 第 {} 行格式錯誤", line_index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P06 fixture 缺少正確的兩個 profile 映射".into());
    }
    let actual: std::collections::HashSet<_> = cases.iter().map(|case| case.id.as_str()).collect();
    let expected: std::collections::HashSet<_> = P06_CASES.into_iter().collect();
    if cases.len() != P06_CASES.len() || actual != expected {
        return Err("P06 fixture 缺少、重複或含未知案例".into());
    }
    Ok(cases)
}

fn validate_p06_records(
    profile: &str,
    expected_cases: &[P06FixtureCase],
    records: &[(String, String, String, String)],
) -> Result<(), String> {
    let expected: std::collections::HashMap<_, _> = expected_cases
        .iter()
        .map(|case| (case.id.as_str(), case.input.as_str()))
        .collect();
    let mut seen = std::collections::HashSet::new();
    for (id, actual_profile, input, actual) in records {
        if actual_profile != profile {
            return Err(format!("P06 案例 {id} profile 不符：{actual_profile}"));
        }
        if !expected.contains_key(id.as_str()) || !seen.insert(id.as_str()) {
            return Err(format!("P06 案例缺少、重複或未知：{id}"));
        }
        if expected.get(id.as_str()).copied() != Some(input.as_str()) || actual.is_empty() {
            return Err(format!("P06 案例 {id} input 無效或 actual 為空"));
        }
    }
    if records.len() != expected_cases.len() || seen.len() != expected_cases.len() {
        return Err(format!("{profile} P06 案例缺少記錄"));
    }
    Ok(())
}

fn validate_phase_dependency_graph(csv: &str) -> Result<(), String> {
    const EXPECTED_EDGES: [(&str, &str, &str, &str); 34] = [
        ("DA-01", "P01", "P06", "P01"),
        ("DA-01A", "P06", "P07", "P06"),
        ("DA-02", "P06", "P07", "P06"),
        ("DA-03", "P05", "P07", "P05"),
        ("DA-04", "P05", "P07", "P05"),
        ("DA-05", "P05", "P07", "P05"),
        ("DA-06", "P05", "P08", "P05"),
        ("DA-07", "P05", "P08", "P05"),
        ("DA-08", "P08", "P10", "P08"),
        ("DA-09", "P05", "P09", "P05"),
        ("DA-10", "P09", "P10", "P09"),
        ("DA-11", "P05", "P11", "P05"),
        ("DA-12", "P05", "P10", "P05"),
        ("DA-13", "P10", "P11", "P10"),
        ("DA-14", "P04", "P05", "P05"),
        ("DA-15", "P11", "P12", "P11"),
        ("DA-16", "P05", "P12", "P12"),
        ("DA-17", "P05", "P06", "P05"),
        ("DA-18", "P05", "P20", "P05"),
        ("DA-19", "P12", "P13", "P13"),
        ("DA-20", "P05", "P14", "P14"),
        ("DA-21", "P14", "P16", "P14"),
        ("DA-22", "P14", "P15", "P15"),
        ("DA-23", "P14", "P16", "P16"),
        ("DA-24", "P16", "P17", "P17"),
        ("DA-25", "P16", "P18", "P18"),
        ("DA-26", "P05", "P19", "P19"),
        ("DA-27", "P05", "P20", "P20"),
        ("DA-28", "P05", "P21", "P21"),
        ("DA-29", "P05", "P22", "P22"),
        ("DA-30", "P05", "P23", "P23"),
        ("DA-31", "P05", "P24", "P24"),
        ("DA-32", "P05", "P13", "P13"),
        ("DA-33", "P05", "P14", "P14"),
    ];
    let mut rows = std::collections::HashSet::new();
    let mut stages = std::collections::HashSet::new();
    let mut critical = std::collections::HashSet::new();
    for (line_number, line) in csv.lines().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let columns: Vec<_> = line.split(',').collect();
        if columns.len() != 6 || columns.iter().any(|column| column.is_empty()) {
            return Err(format!(
                "phase-dependencies.csv 第 {} 列欄位不完整",
                line_number + 1
            ));
        }
        let (id, producer, consumer, interface, status, earliest_gate) = (
            columns[0], columns[1], columns[2], columns[3], columns[4], columns[5],
        );
        if !rows.insert(id) {
            return Err(format!("phase-dependencies.csv 有重複 id：{id}"));
        }
        match EXPECTED_EDGES
            .iter()
            .find(|(expected_id, _, _, _)| *expected_id == id)
        {
            Some((_, expected_producer, expected_consumer, expected_gate)) => {
                if *expected_producer != producer || *expected_consumer != consumer {
                    return Err(format!(
                        "phase-dependencies.csv {id} owner edge 不符合核准契約：{producer}→{consumer}"
                    ));
                }
                if *expected_gate != earliest_gate {
                    return Err(format!(
                        "phase-dependencies.csv {id} earliest_gate 不符合核准契約：{earliest_gate}"
                    ));
                }
            }
            None => {
                return Err(format!(
                    "phase-dependencies.csv {id} owner edge 不符合核准契約：{producer}→{consumer}"
                ));
            }
        }
        if !matches!(status, "IMPLEMENTED" | "CONTRACTED") {
            return Err(format!(
                "phase-dependencies.csv {id} 含未解 status：{status}"
            ));
        }
        let official_interface = match id {
            "DA-32" => Some("Lua55 Lua54 official chunk codec translation VerifiedModule"),
            "DA-33" => Some("immutable validated artifact metadata transport"),
            _ => None,
        };
        if official_interface.is_some_and(|expected| interface != expected)
            || (official_interface.is_some() && status != "IMPLEMENTED")
        {
            return Err(format!("phase-dependencies.csv {id} 官方 chunk 契約不符"));
        }
        let parse_stage = |value: &str| {
            value
                .strip_prefix('P')
                .and_then(|number| number.parse::<u8>().ok())
                .filter(|number| *number <= 24)
        };
        let producer_stage = parse_stage(producer)
            .ok_or_else(|| format!("phase-dependencies.csv {id} producer 非 phase：{producer}"))?;
        let consumer_stage = parse_stage(consumer)
            .ok_or_else(|| format!("phase-dependencies.csv {id} consumer 非 phase：{consumer}"))?;
        if producer_stage >= consumer_stage {
            return Err(format!(
                "phase-dependencies.csv {id} 有 cycle 或逆向 owner edge"
            ));
        }
        stages.insert(consumer_stage);
        critical.insert((id, producer, consumer));
    }
    if rows.len() != 34
        || !(1..=33).all(|number| {
            let id = format!("DA-{number:02}");
            rows.contains(id.as_str())
        })
    {
        return Err("phase-dependencies.csv 必須完整覆蓋 DA-01～DA-33".into());
    }
    if !rows.contains("DA-01A") {
        return Err("phase-dependencies.csv 缺 P06 ObjectRef identity bridge edge".into());
    }
    if !(6..=24).all(|stage| stages.contains(&stage)) {
        return Err("phase-dependencies.csv 未完整覆蓋 P06～P24 consumer".into());
    }
    for edge in [
        ("DA-01", "P01", "P06"),
        ("DA-01A", "P06", "P07"),
        ("DA-14", "P04", "P05"),
        ("DA-04", "P05", "P07"),
        ("DA-09", "P05", "P09"),
        ("DA-18", "P05", "P20"),
        ("DA-20", "P05", "P14"),
        ("DA-30", "P05", "P23"),
        ("DA-31", "P05", "P24"),
        ("DA-32", "P05", "P13"),
        ("DA-33", "P05", "P14"),
    ] {
        if !critical.contains(&edge) {
            return Err(format!(
                "phase-dependencies.csv 缺關鍵 edge {}→{}",
                edge.1, edge.2
            ));
        }
    }
    Ok(())
}

fn p02_contracts(root: &Path, profile: &str) -> Result<Vec<(String, String, String)>, String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-compiler",
            "--test",
            "p02_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P02_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let status = output.status;
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !status.success() {
        return Err(format!(
            "{profile} P02 contracts 子行程失敗（實際退出碼 {status}）：{output}"
        ));
    }
    if !output.contains("test result: ok. 1 passed; 0 failed;") {
        return Err(format!("{profile} P02 contracts 未完整執行：{output}"));
    }
    let records = output
        .lines()
        .filter_map(|line| {
            line.find("P02_CASE\t")
                .map(|index| &line[index + "P02_CASE\t".len()..])
        })
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("{profile} P02_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actual: std::collections::HashSet<_> =
        records.iter().map(|record| record.0.as_str()).collect();
    let expected: std::collections::HashSet<_> = P02_CASES.into_iter().collect();
    if records.len() != P02_CASES.len() || actual != expected {
        return Err(format!("{profile} P02_CASE 缺少、重複或未知"));
    }
    Ok(records)
}

fn write_p02_case_report(
    root: &Path,
    case_id: &str,
    profile: &str,
    lua_profile: &str,
    input: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P02-{case_id}-{lua_profile}.json"
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P02 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-compiler\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"lexer\",\"input\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"cargo test --locked -p rivetlua-compiler --test p02_contracts -- --nocapture --test-threads=1\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"完整執行且契約斷言通過\"}}\n",
        json_escape(case_id),
        json_escape(profile),
        json_escape(lua_profile),
        json_escape(input),
        json_escape(actual),
        json_escape(&path.display().to_string())
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn p03_contracts(root: &Path, profile: &str) -> Result<Vec<(String, String, String)>, String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-compiler",
            "--test",
            "p03_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P03_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let status = output.status;
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    p03_child_status(profile, status.success(), &output)?;
    if !status.success() {
        return Err(format!(
            "{profile} P03 contracts 子行程失敗（實際退出碼 {status}）：{output}"
        ));
    }
    if !output.contains("test result: ok. 1 passed; 0 failed;") {
        return Err(format!("{profile} P03 contracts 未完整執行：{output}"));
    }
    let records = output
        .lines()
        .filter_map(|line| {
            line.find("P03_CASE\t")
                .map(|index| &line[index + "P03_CASE\t".len()..])
        })
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("{profile} P03_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_p03_records(profile, &records)?;
    Ok(records)
}
fn p03_child_status(profile: &str, success: bool, output: &str) -> Result<(), String> {
    if success {
        Ok(())
    } else {
        Err(format!("{profile} P03 contracts 子行程失敗：{output}"))
    }
}
fn validate_p03_records(profile: &str, records: &[(String, String, String)]) -> Result<(), String> {
    let actual: std::collections::HashSet<_> =
        records.iter().map(|record| record.0.as_str()).collect();
    let expected: std::collections::HashSet<_> = P03_CASES.into_iter().collect();
    if records.len() != P03_CASES.len() || actual.len() != records.len() || actual != expected {
        Err(format!("{profile} P03_CASE 缺少、重複或未知"))
    } else {
        Ok(())
    }
}
fn write_p03_case_report(
    root: &Path,
    case_id: &str,
    profile: &str,
    lua_profile: &str,
    input: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P03-{case_id}-{lua_profile}.json"
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P03 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-compiler\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"parse\",\"input\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"cargo test --locked -p rivetlua-compiler --test p03_contracts -- --nocapture --test-threads=1\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"完整執行且契約斷言通過\"}}\n",
        json_escape(case_id),
        json_escape(profile),
        json_escape(lua_profile),
        json_escape(input),
        json_escape(actual),
        json_escape(&path.display().to_string())
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn strict_lua55_reference(root: &Path) -> Result<PathBuf, String> {
    verify(root, LUA55)?;
    let nonce = VERIFY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let destination = root.join("target/rivetlua-reference").join(format!(
        "lua55-strict-global-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&destination).map_err(|error| error.to_string())?;
    let archive = root.join(LUA55.source);
    run(
        "tar",
        &[
            "-xzf",
            archive.to_str().ok_or("無法表示來源路徑")?,
            "-C",
            destination.to_str().ok_or("無法表示目標路徑")?,
        ],
        root,
    )?;
    let source = destination.join(LUA55.source_dir);
    let output = Command::new("make")
        .arg(format!("MYCFLAGS={STRICT_GLOBAL_CFLAGS}"))
        .arg(reference_make_target(env::consts::OS)?)
        .current_dir(&source)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "嚴格 lua55 參考建置失敗：{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let version = run("./src/lua", &["-v"], &source)?;
    if !version.contains("Lua 5.5.1") {
        return Err(format!("嚴格 lua55 版本不符：{version}"));
    }
    run(
        "./src/lua",
        &[
            "-e",
            "local f = load('local global = 1'); if f then error('LUA_COMPAT_GLOBAL enabled') end",
        ],
        &source,
    )?;
    Ok(source.join("src/lua"))
}

fn p02_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let p01_command = "cargo run --locked -p rivetlua-xtask -- gate P01";
    if let Err(error) = run(
        "cargo",
        &[
            "run",
            "--locked",
            "-p",
            "rivetlua-xtask",
            "--",
            "gate",
            "P01",
        ],
        &root,
    ) {
        return p02_fail(&root, &mut results, "p01-before", p01_command, error);
    }
    results.push(p02_result(
        "p01-before",
        p01_command,
        0,
        "PASS",
        "P01 回歸通過",
    ));

    let csv = fs::read_to_string(root.join("spec/compatibility.csv"))
        .map_err(|error| error.to_string())?;
    if let Err(error) = validate_p02_csv_cases(&csv) {
        return p02_fail(
            &root,
            &mut results,
            "p02-csv",
            "validate spec/compatibility.csv",
            error,
        );
    }
    results.push(p02_result(
        "p02-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "兩個 profile 的 11 個 P02 case 均完整追溯",
    ));

    let fmt_command = "cargo fmt --all -- --check";
    if let Err(error) = run("cargo", &["fmt", "--all", "--", "--check"], &root) {
        return p02_fail(&root, &mut results, "p02-fmt", fmt_command, error);
    }
    results.push(p02_result(
        "p02-fmt",
        fmt_command,
        0,
        "PASS",
        "格式檢查通過",
    ));

    for (name, test_name) in [
        ("p02-compiler-unit", "--lib"),
        ("p02-compiler-integration", "lexer_contracts"),
    ] {
        let (args, command): (Vec<&str>, String) = if test_name == "--lib" {
            (
                vec![
                    "test",
                    "--locked",
                    "-p",
                    "rivetlua-compiler",
                    "--lib",
                    "lexer",
                ],
                "cargo test --locked -p rivetlua-compiler --lib lexer".into(),
            )
        } else {
            (
                vec![
                    "test",
                    "--locked",
                    "-p",
                    "rivetlua-compiler",
                    "--test",
                    test_name,
                ],
                format!("cargo test --locked -p rivetlua-compiler --test {test_name}"),
            )
        };
        if let Err(error) = run("cargo", &args, &root) {
            return p02_fail(&root, &mut results, name, &command, error);
        }
        results.push(p02_result(name, command, 0, "PASS", "compiler 測試通過"));
    }

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = "cargo test --locked -p rivetlua-compiler --test p02_contracts";
        let records = match p02_contracts(&root, profile) {
            Ok(records) => records,
            Err(error) => {
                let long_negative = fs::read_to_string(
                    root.join("tests/p02/fixtures/wrong-long-delimiter.fixture"),
                )
                .map(|fixture| fixture.contains("expected=String"))
                .unwrap_or(false);
                let token_negative =
                    fs::read_to_string(root.join("tests/p02/fixtures/oversized-token.fixture"))
                        .map(|fixture| fixture.contains("expected=PASS"))
                        .unwrap_or(false);
                let name = if long_negative {
                    "P02-LONG-NEG-001".to_owned()
                } else if token_negative {
                    "P02-LIMIT-NEG-001".to_owned()
                } else {
                    format!("p02-contracts-{lua_profile}")
                };
                return p02_fail(&root, &mut results, &name, command, error);
            }
        };
        for (case_id, input, actual) in records {
            let path =
                match write_p02_case_report(&root, &case_id, profile, lua_profile, &input, &actual)
                {
                    Ok(path) => path,
                    Err(error) => {
                        return p02_fail(
                            &root,
                            &mut results,
                            &format!("{case_id}-{lua_profile}"),
                            command,
                            error,
                        );
                    }
                };
            let mut result = p02_result(
                format!("{case_id}-{lua_profile}"),
                command,
                0,
                "PASS",
                format!("profile={profile}; mode=lexer; token/span/literal 或診斷已驗證"),
            );
            result.report_path = path.display().to_string();
            results.push(result);
        }
    }

    let strict_command = "isolated lua55 make MYCFLAGS=-DLUA_COMPAT_GLOBAL=0";
    let strict = match strict_lua55_reference(&root) {
        Ok(path) => path,
        Err(error) => {
            return p02_fail(
                &root,
                &mut results,
                "p02-strict-reference",
                strict_command,
                error,
            );
        }
    };
    results.push(p02_result(
        "p02-strict-reference",
        strict_command,
        0,
        "PASS",
        format!("Lua 5.5.1 strict global reference={}", strict.display()),
    ));

    if let Err(error) = run(
        "cargo",
        &[
            "run",
            "--locked",
            "-p",
            "rivetlua-xtask",
            "--",
            "gate",
            "P01",
        ],
        &root,
    ) {
        return p02_fail(&root, &mut results, "p01-after", p01_command, error);
    }
    results.push(p02_result(
        "p01-after",
        p01_command,
        0,
        "PASS",
        "P01 回歸通過",
    ));
    write_p02_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P02.json").display()
    );
    Ok(())
}

fn write_p03_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P03.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks=results.iter().map(|item|format!("{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",json_escape(&item.name),json_escape(&item.command),item.exit_code,item.status,json_escape(&item.diagnostic),json_escape(&item.report_path))).collect::<Vec<_>>().join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{checks}]}}\n"
        ),
    );
}

fn p03_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p03_result(name, command, 1, "FAIL", error.clone()));
    write_p03_results(root, results);
    Err(error)
}

fn p03_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    if let Err(error) = p02_gate() {
        results.push(p03_result(
            "p02-before",
            "gate P02",
            1,
            "FAIL",
            error.clone(),
        ));
        write_p03_results(&root, &results);
        return Err(error);
    }
    results.push(p03_result("p02-before", "gate P02", 0, "PASS", "P02 通過"));
    let csv = fs::read_to_string(root.join("spec/compatibility.csv")).map_err(|e| e.to_string())?;
    if let Err(error) = validate_p03_csv_cases(&csv) {
        results.push(p03_result(
            "p03-csv",
            "validate P03 CSV",
            1,
            "FAIL",
            error.clone(),
        ));
        write_p03_results(&root, &results);
        return Err(error);
    }
    results.push(p03_result(
        "p03-csv",
        "validate P03 CSV",
        0,
        "PASS",
        "P03 CSV 通過",
    ));
    for (name, arguments) in [
        ("p03-format", vec!["fmt", "--all", "--", "--check"]),
        (
            "p03-parser-lib",
            vec!["test", "--locked", "-p", "rivetlua-compiler", "--lib"],
        ),
        (
            "p03-parser-contracts",
            vec![
                "test",
                "--locked",
                "-p",
                "rivetlua-compiler",
                "--test",
                "parser_contracts",
            ],
        ),
    ] {
        if let Err(error) = run("cargo", &arguments, &root) {
            results.push(p03_result(
                name,
                format!("cargo {}", arguments.join(" ")),
                1,
                "FAIL",
                error.clone(),
            ));
            write_p03_results(&root, &results);
            return Err(error);
        }
        results.push(p03_result(
            name,
            format!("cargo {}", arguments.join(" ")),
            0,
            "PASS",
            "P03 檢查通過",
        ));
    }
    for (profile, lua) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = "cargo test --locked -p rivetlua-compiler --test p03_contracts";
        let records = match p03_contracts(&root, profile) {
            Ok(records) => records,
            Err(error) => {
                return p03_fail(
                    &root,
                    &mut results,
                    &format!("p03-contracts-{lua}"),
                    command,
                    error,
                );
            }
        };
        for (id, input, actual) in records {
            let path = match write_p03_case_report(&root, &id, profile, lua, &input, &actual) {
                Ok(path) => path,
                Err(error) => {
                    return p03_fail(&root, &mut results, &format!("{id}-{lua}"), command, error);
                }
            };
            results.push(GateResult {
                name: id,
                command: "cargo test p03_contracts".into(),
                exit_code: 0,
                status: "PASS",
                diagnostic: "P03 contract 通過".into(),
                report_path: path.display().to_string(),
            });
        }
    }
    write_p03_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P03.json").display()
    );
    Ok(())
}

fn p04_contracts(root: &Path, profile: &str) -> Result<Vec<(String, String, String)>, String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-compiler",
            "--test",
            "p04_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P04_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let status = output.status;
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    p04_child_status(profile, status.success(), &output)?;
    if !status.success() {
        return Err(format!(
            "{profile} P04 contracts 子行程失敗（實際退出碼 {status}）：{output}"
        ));
    }
    p04_check_test_summary(&output, 2)
        .map_err(|error| format!("{profile} P04 contracts 未完整執行：{error}；輸出：{output}"))?;
    let records = output
        .lines()
        .filter_map(|line| {
            line.find("P04_CASE\t")
                .map(|index| &line[index + "P04_CASE\t".len()..])
        })
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("{profile} P04_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_p04_records(profile, &records)?;
    Ok(records)
}

fn p04_check_test_summary(output: &str, expected_passed: usize) -> Result<(), String> {
    let expected = format!("test result: ok. {expected_passed} passed; 0 failed;");
    if output.lines().any(|line| line.contains(&expected)) {
        Ok(())
    } else {
        Err(format!(
            "P04 contracts 測試數不符，要求精確 {expected_passed} 個通過案例"
        ))
    }
}

fn p04_child_status(profile: &str, success: bool, output: &str) -> Result<(), String> {
    if success {
        Ok(())
    } else {
        Err(format!("{profile} P04 contracts 子行程失敗：{output}"))
    }
}

fn validate_p04_records(profile: &str, records: &[(String, String, String)]) -> Result<(), String> {
    let actual: std::collections::HashSet<_> =
        records.iter().map(|record| record.0.as_str()).collect();
    let expected: std::collections::HashSet<_> = P04_CASES.into_iter().collect();
    if records.len() != P04_CASES.len() || actual.len() != records.len() || actual != expected {
        Err(format!("{profile} P04_CASE 缺少、重複或未知"))
    } else {
        Ok(())
    }
}

fn write_p04_case_report(
    root: &Path,
    case_id: &str,
    profile: &str,
    lua_profile: &str,
    input: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P04-{case_id}-{lua_profile}.json"
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P04 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-compiler\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"resolve\",\"input\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"cargo test --locked -p rivetlua-compiler --test p04_contracts -- --nocapture --test-threads=1\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"完整執行且 resolved AST 或診斷契約斷言通過\"}}\n",
        json_escape(case_id),
        json_escape(profile),
        json_escape(lua_profile),
        json_escape(input),
        json_escape(actual),
        json_escape(&path.display().to_string())
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn write_p04_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P04.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| format!(
            "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
            json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status,
            json_escape(&item.diagnostic), json_escape(&item.report_path)
        ))
        .collect::<Vec<_>>()
        .join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{checks}]}}\n"
        ),
    );
}

fn p04_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p04_result(name, command, 1, "FAIL", error.clone()));
    write_p04_results(root, results);
    Err(error)
}

fn p04_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let p03_command = "cargo run --locked -p rivetlua-xtask -- gate P03";
    if let Err(error) = p03_gate() {
        return p04_fail(&root, &mut results, "p03-before", p03_command, error);
    }
    results.push(p04_result(
        "p03-before",
        p03_command,
        0,
        "PASS",
        "P03 回歸通過",
    ));
    let csv = fs::read_to_string(root.join("spec/compatibility.csv"))
        .map_err(|error| error.to_string())?;
    if let Err(error) = validate_p04_csv_cases(&csv) {
        return p04_fail(&root, &mut results, "p04-csv", "validate P04 CSV", error);
    }
    results.push(p04_result(
        "p04-csv",
        "validate P04 CSV",
        0,
        "PASS",
        "兩個 profile 的 10 個 P04 case 均完整追溯",
    ));
    for (name, arguments) in [
        ("p04-format", vec!["fmt", "--all", "--", "--check"]),
        (
            "p04-resolver-lib",
            vec![
                "test",
                "--locked",
                "-p",
                "rivetlua-compiler",
                "--lib",
                "resolve",
            ],
        ),
        (
            "p04-resolver-contracts",
            vec![
                "test",
                "--locked",
                "-p",
                "rivetlua-compiler",
                "--test",
                "resolver_contracts",
            ],
        ),
    ] {
        let command = format!("cargo {}", arguments.join(" "));
        if let Err(error) = run("cargo", &arguments, &root) {
            return p04_fail(&root, &mut results, name, &command, error);
        }
        results.push(p04_result(name, command, 0, "PASS", "P04 檢查通過"));
    }
    for (profile, lua) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = "cargo test --locked -p rivetlua-compiler --test p04_contracts";
        let records = match p04_contracts(&root, profile) {
            Ok(records) => records,
            Err(error) => {
                return p04_fail(
                    &root,
                    &mut results,
                    &format!("p04-contracts-{lua}"),
                    command,
                    error,
                );
            }
        };
        for (id, input, actual) in records {
            let path = match write_p04_case_report(&root, &id, profile, lua, &input, &actual) {
                Ok(path) => path,
                Err(error) => {
                    return p04_fail(&root, &mut results, &format!("{id}-{lua}"), command, error);
                }
            };
            results.push(GateResult {
                name: format!("{id}-{lua}"),
                command: command.into(),
                exit_code: 0,
                status: "PASS",
                diagnostic: "P04 resolved AST 或診斷契約通過".into(),
                report_path: path.display().to_string(),
            });
        }
    }
    write_p04_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P04.json").display()
    );
    Ok(())
}

fn p05_contracts(root: &Path, profile: &str) -> Result<Vec<(String, String, String)>, String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-compiler",
            "--test",
            "p05_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P05_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let status = output.status;
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    p05_child_status(profile, status.success(), &output)?;
    if !status.success() {
        return Err(format!(
            "{profile} P05 contracts 子行程失敗（實際退出碼 {status}）：{output}"
        ));
    }
    p05_check_test_summary(&output, P05_CONTRACT_TEST_COUNT)
        .map_err(|error| format!("{profile} P05 contracts 未完整執行：{error}；輸出：{output}"))?;
    let records = output
        .lines()
        .filter_map(|line| {
            line.find("P05_CASE\t")
                .map(|index| &line[index + "P05_CASE\t".len()..])
        })
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("{profile} P05_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_p05_records(profile, &records)?;
    Ok(records)
}

fn p05_check_test_summary(output: &str, expected_passed: usize) -> Result<(), String> {
    let expected = format!("test result: ok. {expected_passed} passed; 0 failed;");
    if output.lines().any(|line| line.contains(&expected)) {
        Ok(())
    } else {
        Err(format!(
            "P05 contracts 測試數不符，要求精確 {expected_passed} 個通過案例"
        ))
    }
}

fn p05_child_status(profile: &str, success: bool, output: &str) -> Result<(), String> {
    if success {
        Ok(())
    } else {
        Err(format!("{profile} P05 contracts 子行程失敗：{output}"))
    }
}

fn validate_p05_records(profile: &str, records: &[(String, String, String)]) -> Result<(), String> {
    let actual: std::collections::HashSet<_> =
        records.iter().map(|record| record.0.as_str()).collect();
    let expected: std::collections::HashSet<_> = P05_CASES.into_iter().collect();
    if records.len() != P05_CASES.len() || actual.len() != records.len() || actual != expected {
        Err(format!("{profile} P05_CASE 缺少、重複或未知"))
    } else {
        Ok(())
    }
}

fn p05_mode(case_id: &str) -> &'static str {
    match case_id {
        "BC-001" | "BC-005" | "BC-006" => "compile",
        _ => "verify",
    }
}

fn write_p05_case_report(
    root: &Path,
    case_id: &str,
    profile: &str,
    lua_profile: &str,
    input: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P05-{case_id}-{lua_profile}.json"
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P05 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-core;rivetlua-compiler\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"cargo test --locked -p rivetlua-compiler --test p05_contracts -- --nocapture --test-threads=1\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"完整執行且 RVLU 或診斷契約斷言通過\"}}\n",
        json_escape(case_id),
        json_escape(profile),
        json_escape(lua_profile),
        p05_mode(case_id),
        json_escape(input),
        json_escape(actual),
        json_escape(&path.display().to_string()),
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn write_p05_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P05.json");
    let _ = fs::create_dir_all(path.parent().unwrap());
    let status = if results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results.iter().map(|item| format!(
        "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
        json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status,
        json_escape(&item.diagnostic), json_escape(&item.report_path)
    )).collect::<Vec<_>>().join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{checks}]}}\n"
        ),
    );
}

fn p05_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p05_result(name, command, 1, "FAIL", error.clone()));
    write_p05_results(root, results);
    Err(error)
}

fn p05_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let p04_command = "cargo run --locked -p rivetlua-xtask -- gate P04";
    if let Err(error) = p04_gate() {
        return p05_fail(&root, &mut results, "p04-before", p04_command, error);
    }
    results.push(p05_result(
        "p04-before",
        p04_command,
        0,
        "PASS",
        "P04 回歸通過",
    ));
    let csv = fs::read_to_string(root.join("spec/compatibility.csv"))
        .map_err(|error| error.to_string())?;
    if let Err(error) = validate_p05_csv_cases(&csv) {
        return p05_fail(&root, &mut results, "p05-csv", "validate P05 CSV", error);
    }
    results.push(p05_result(
        "p05-csv",
        "validate P05 CSV",
        0,
        "PASS",
        "兩個 profile 的全部 P05 case 均完整追溯",
    ));
    let graph_command = "validate spec/phase-dependencies.csv";
    let graph = match fs::read_to_string(root.join("spec/phase-dependencies.csv")) {
        Ok(graph) => graph,
        Err(error) => {
            return p05_fail(
                &root,
                &mut results,
                "p05-dependency-graph",
                graph_command,
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_phase_dependency_graph(&graph) {
        return p05_fail(
            &root,
            &mut results,
            "p05-dependency-graph",
            graph_command,
            error,
        );
    }
    results.push(p05_result(
        "p05-dependency-graph",
        graph_command,
        0,
        "PASS",
        "34 條 dependency edge 覆蓋 33 筆 DA 與 DA-01A、無 CONFLICT、無 cycle，且 critical owner edge 存在",
    ));
    for (name, arguments) in [
        ("p05-format", vec!["fmt", "--all", "--", "--check"]),
        (
            "p05-core-bytecode",
            vec!["test", "--locked", "-p", "rivetlua-core", "bytecode"],
        ),
        (
            "p05-core-doc",
            vec!["test", "--locked", "-p", "rivetlua-core", "--doc"],
        ),
        (
            "p05-compiler-codegen",
            vec!["test", "--locked", "-p", "rivetlua-compiler", "codegen"],
        ),
        (
            "p05-compiler-ir",
            vec!["test", "--locked", "-p", "rivetlua-compiler", "ir"],
        ),
        (
            "p05-bytecode-contracts",
            vec![
                "test",
                "--locked",
                "-p",
                "rivetlua-compiler",
                "--test",
                "bytecode_contracts",
            ],
        ),
    ] {
        let command = format!("cargo {}", arguments.join(" "));
        if let Err(error) = run("cargo", &arguments, &root) {
            return p05_fail(&root, &mut results, name, &command, error);
        }
        results.push(p05_result(name, command, 0, "PASS", "P05 檢查通過"));
    }
    for (profile, lua) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = "cargo test --locked -p rivetlua-compiler --test p05_contracts";
        let records = match p05_contracts(&root, profile) {
            Ok(records) => records,
            Err(error) => {
                return p05_fail(
                    &root,
                    &mut results,
                    &format!("p05-contracts-{lua}"),
                    command,
                    error,
                );
            }
        };
        for (id, input, actual) in records {
            let path = match write_p05_case_report(&root, &id, profile, lua, &input, &actual) {
                Ok(path) => path,
                Err(error) => {
                    return p05_fail(&root, &mut results, &format!("{id}-{lua}"), command, error);
                }
            };
            results.push(GateResult {
                name: format!("{id}-{lua}"),
                command: command.into(),
                exit_code: 0,
                status: "PASS",
                diagnostic: "P05 RVLU 或診斷契約通過".into(),
                report_path: path.display().to_string(),
            });
        }
    }
    write_p05_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P05.json").display()
    );
    Ok(())
}

fn p06_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P06.json".into(),
    }
}

fn write_p06_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P06.json");
    if fs::create_dir_all(path.parent().unwrap()).is_err() {
        return;
    }
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{checks}]}}\n"
        ),
    );
}

fn p06_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p06_result(name, command, 1, "FAIL", error.clone()));
    write_p06_results(root, results);
    Err(error)
}

fn p06_case_command(case_id: &str, profile: &str) -> String {
    if case_id == "HEAP-007" {
        format!(
            "RIVETLUA_P06_PROFILE={profile} cargo test --locked -p rivetlua-runtime --lib heap_007_retired_slot_never_revives_old_host_handle -- --nocapture --test-threads=1"
        )
    } else if case_id == "HEAP-008" {
        format!(
            "RIVETLUA_P06_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p06_contracts -- --nocapture --test-threads=1 && RIVETLUA_P06_PROFILE={profile} cargo test --locked -p rivetlua-runtime --doc with_value -- --show-output --test-threads=1"
        )
    } else {
        format!(
            "RIVETLUA_P06_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p06_contracts -- --nocapture --test-threads=1"
        )
    }
}

fn p06_case_report(
    root: &Path,
    case: &P06FixtureCase,
    profile: &str,
    lua_profile: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P06-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P06 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let command = p06_case_command(&case.id, profile);
    let mode = match case.id.as_str() {
        "HEAP-007" => "runtime-unit",
        "HEAP-008" => "runtime-integration+doctest",
        _ => "runtime-integration",
    };
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-runtime;rivetlua-core\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"案例斷言與 profile 對照完整通過\"}}\n",
        json_escape(&case.id),
        json_escape(profile),
        json_escape(lua_profile),
        mode,
        json_escape(&case.input),
        json_escape(actual),
        json_escape(&command),
        json_escape(&path.display().to_string()),
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn p06_capture(root: &Path, args: &[&str], profile: &str) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args(args)
        .env("RIVETLUA_P06_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p06_records_from_output(
    profile: &str,
    output: &str,
) -> Result<Vec<(String, String, String, String)>, String> {
    output
        .lines()
        .filter_map(|line| line.find("P06_CASE\t").map(|index| &line[index..]))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 5
                || fields[0] != "P06_CASE"
                || fields.iter().any(|field| field.is_empty())
            {
                return Err(format!("{profile} P06_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[1].to_owned(),
                fields[2].to_owned(),
                fields[3].to_owned(),
                fields[4].to_owned(),
            ))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum P06TestExpectation {
    AtLeast(usize),
    WithValueDoctests,
}

fn p06_check_test_summary(output: &str, minimum_passed: usize) -> Result<usize, String> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.contains("test result:"))
        .ok_or_else(|| "缺少 test result 摘要".to_owned())?;
    let summary = line
        .split_once("test result:")
        .map(|(_, summary)| summary.trim())
        .ok_or_else(|| "無法解析 test result 摘要".to_owned())?;
    if !summary.starts_with("ok.") {
        return Err(format!("測試摘要不是成功狀態：{summary}"));
    }
    let fields: Vec<_> = summary.split_whitespace().collect();
    let count_for = |label: &str| {
        fields
            .windows(2)
            .find(|pair| pair[1] == label)
            .and_then(|pair| pair[0].parse::<usize>().ok())
    };
    let passed = count_for("passed;").ok_or_else(|| "摘要缺少 passed 數量".to_owned())?;
    let failed = count_for("failed;").ok_or_else(|| "摘要缺少 failed 數量".to_owned())?;
    if failed != 0 {
        return Err(format!("摘要包含 {failed} 個失敗測試"));
    }
    if passed < minimum_passed {
        return Err(format!(
            "匹配測試不足：至少需要 {minimum_passed} 個，實際 {passed} 個"
        ));
    }
    Ok(passed)
}

fn p06_check_with_value_doctests(output: &str) -> Result<usize, String> {
    let passed = p06_check_test_summary(output, 2)?;
    let successful_tests: Vec<_> = output
        .lines()
        .filter(|line| line.trim_start().starts_with("test ") && line.contains(" ... ok"))
        .collect();
    let has_compiling_example = successful_tests
        .iter()
        .any(|line| line.contains("heap::Vm::with_value") && !line.contains(" - compile fail"));
    let has_compile_fail_example = successful_tests
        .iter()
        .any(|line| line.contains("heap::Vm::with_value") && line.contains(" - compile fail"));
    if !has_compiling_example || !has_compile_fail_example {
        return Err(format!(
            "with_value doctest 必須各通過一個正常範例與 compile_fail 範例；實際輸出：{output}"
        ));
    }
    Ok(passed)
}

fn p06_check_test_run(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    args: &[&str],
    expectation: P06TestExpectation,
    profile: &str,
) -> Result<String, String> {
    let command = format!("RIVETLUA_P06_PROFILE={profile} cargo {}", args.join(" "));
    let (success, exit_code, output) = match p06_capture(root, args, profile) {
        Ok(result) => result,
        Err(error) => {
            let _ = p06_fail(root, results, name, &command, error.clone());
            return Err(error);
        }
    };
    let summary = match expectation {
        P06TestExpectation::AtLeast(minimum_passed) => {
            p06_check_test_summary(&output, minimum_passed)
                .map(|passed| format!("{passed} passed; 0 failed; (minimum {minimum_passed})"))
        }
        P06TestExpectation::WithValueDoctests => p06_check_with_value_doctests(&output)
            .map(|passed| format!("{passed} passed; compile=1; compile_fail=1")),
    };
    if !success {
        let summary_error = summary.err().unwrap_or_else(|| "子測試命令失敗".into());
        let error = format!("實際 exit={exit_code}；{summary_error}；輸出：{output}");
        let _ = p06_fail(root, results, name, &command, error.clone());
        return Err(error);
    }
    let summary = match summary {
        Ok(summary) => summary,
        Err(error) => {
            let error = format!("實際 exit={exit_code}；{error}；輸出：{output}");
            let _ = p06_fail(root, results, name, &command, error.clone());
            return Err(error);
        }
    };
    results.push(p06_result(
        name,
        command,
        exit_code,
        "PASS",
        format!("{profile} 執行摘要：{summary}"),
    ));
    Ok(output)
}

fn validate_prior_gate_reports(root: &Path) -> Result<(), String> {
    for phase in ["P00", "P01", "P02", "P03", "P04", "P05"] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        if !report.starts_with("{\"status\":\"PASS\"") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS"));
        }
    }
    Ok(())
}

fn p06_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let csv = match fs::read_to_string(root.join("spec/compatibility.csv")) {
        Ok(csv) => csv,
        Err(error) => {
            return p06_fail(
                &root,
                &mut results,
                "p06-csv",
                "read P06 CSV",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_p06_csv_cases(&csv) {
        return p06_fail(&root, &mut results, "p06-csv", "validate P06 CSV", error);
    }
    results.push(p06_result(
        "p06-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "兩個 lua_profile 各自唯一追溯 HEAP-001～008",
    ));
    let fixture_contents = match fs::read_to_string(root.join(P06_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p06_fail(
                &root,
                &mut results,
                "p06-fixture",
                P06_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p06_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p06_fail(&root, &mut results, "p06-fixture", P06_FIXTURE, error),
    };
    results.push(p06_result(
        "p06-fixture",
        P06_FIXTURE,
        0,
        "PASS",
        "兩個 profile 映射與八個唯一案例輸入完整",
    ));

    let p01_command = "cargo run --locked -p rivetlua-xtask -- gate P01";
    if let Err(error) = p01_gate() {
        return p06_fail(&root, &mut results, "p01-before", p01_command, error);
    }
    results.push(p06_result(
        "p01-before",
        p01_command,
        0,
        "PASS",
        "P01 Value regression 通過",
    ));
    let p05_command = "cargo run --locked -p rivetlua-xtask -- gate P05";
    if let Err(error) = p05_gate() {
        return p06_fail(&root, &mut results, "p05-before", p05_command, error);
    }
    results.push(p06_result(
        "p05-before",
        p05_command,
        0,
        "PASS",
        "P05 RVLU_V2 baseline 通過",
    ));
    if let Err(error) = validate_prior_gate_reports(&root) {
        return p06_fail(
            &root,
            &mut results,
            "p00-p05-before",
            "validate prior gate reports",
            error,
        );
    }
    results.push(p06_result(
        "p00-p05-before",
        "validate target/rivetlua-reports/gate-P00.json..gate-P05.json",
        0,
        "PASS",
        "P00～P05 六個前置報告皆為 PASS",
    ));

    let format_command = "cargo fmt --all -- --check";
    if let Err(error) = run("cargo", &["fmt", "--all", "--", "--check"], &root) {
        return p06_fail(&root, &mut results, "p06-format", format_command, error);
    }
    results.push(p06_result(
        "p06-format",
        format_command,
        0,
        "PASS",
        "格式檢查通過",
    ));
    let unit_args = ["test", "--locked", "-p", "rivetlua-runtime", "--lib"];
    if let Err(error) = p06_check_test_run(
        &root,
        &mut results,
        "p06-runtime-unit",
        &unit_args,
        P06TestExpectation::AtLeast(17),
        "lua55-i64f64",
    ) {
        return Err(error);
    }

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let integration_command = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p06_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ];
        let output = match p06_check_test_run(
            &root,
            &mut results,
            &format!("p06-contracts-{lua_profile}"),
            &integration_command,
            P06TestExpectation::AtLeast(19),
            profile,
        ) {
            Ok(output) => output,
            Err(error) => return Err(error),
        };
        let mut records = match p06_records_from_output(profile, &output) {
            Ok(records) => records,
            Err(error) => {
                return p06_fail(
                    &root,
                    &mut results,
                    &format!("p06-contracts-{lua_profile}"),
                    "parse P06_CASE records",
                    error,
                );
            }
        };

        let unit_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "heap_007_retired_slot_never_revives_old_host_handle",
            "--",
            "--nocapture",
            "--test-threads=1",
        ];
        let unit_output = match p06_check_test_run(
            &root,
            &mut results,
            &format!("heap-007-{lua_profile}"),
            &unit_args,
            P06TestExpectation::AtLeast(1),
            profile,
        ) {
            Ok(output) => output,
            Err(error) => return Err(error),
        };
        records.extend(match p06_records_from_output(profile, &unit_output) {
            Ok(records) => records,
            Err(error) => {
                return p06_fail(
                    &root,
                    &mut results,
                    &format!("heap-007-{lua_profile}"),
                    "parse HEAP-007 record",
                    error,
                );
            }
        });

        let doc_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--doc",
            "with_value",
            "--",
            "--show-output",
            "--test-threads=1",
        ];
        if let Err(error) = p06_check_test_run(
            &root,
            &mut results,
            &format!("p06-doctest-{lua_profile}"),
            &doc_args,
            P06TestExpectation::WithValueDoctests,
            profile,
        ) {
            return Err(error);
        }
        validate_p06_records(profile, &fixture, &records).map_err(|error| {
            let _ = p06_fail(
                &root,
                &mut results,
                &format!("p06-cases-{lua_profile}"),
                "validate P06_CASE results",
                error.clone(),
            );
            error
        })?;
        for case in &fixture {
            let Some(record) = records.iter().find(|record| record.0 == case.id) else {
                return p06_fail(
                    &root,
                    &mut results,
                    &case.id,
                    "validate P06_CASE results",
                    "案例記錄不存在".into(),
                );
            };
            let mut actual = record.3.clone();
            if case.id == "HEAP-008" {
                actual
                    .push_str("; 同 profile with_value doctest 各一個正常與 compile_fail 範例通過");
            }
            let report = match p06_case_report(&root, case, profile, lua_profile, &actual) {
                Ok(path) => path,
                Err(error) => {
                    return p06_fail(
                        &root,
                        &mut results,
                        &case.id,
                        "write P06 case report",
                        error,
                    );
                }
            };
            results.push(GateResult {
                name: format!("{}-{lua_profile}", case.id),
                command: p06_case_command(&case.id, profile),
                exit_code: 0,
                status: "PASS",
                diagnostic: format!("profile={profile}; input/assertions matched; actual={actual}"),
                report_path: report.display().to_string(),
            });
        }
    }
    write_p06_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P06.json").display()
    );
    Ok(())
}

fn p07_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P07.json".into(),
    }
}

fn write_p07_results(root: &Path, results: &[GateResult]) {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P07.json");
    if fs::create_dir_all(path.parent().unwrap()).is_err() {
        return;
    }
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = fs::write(
        path,
        format!(
            "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"checks\":[{checks}]}}\n"
        ),
    );
}

fn p07_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    results.push(p07_result(name, command, 1, "FAIL", error.clone()));
    write_p07_results(root, results);
    Err(error)
}

fn p07_case_command(profile: &str) -> String {
    format!(
        "RIVETLUA_P07_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p07_contracts -- --nocapture --test-threads=1"
    )
}

fn p07_case_report(
    root: &Path,
    case: &P07FixtureCase,
    profile: &str,
    lua_profile: &str,
    actual: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P07-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P07 report 路徑")?)
        .map_err(|error| error.to_string())?;
    let diagnostic = if case.note.is_empty() {
        "兩個 profile 的公開介面斷言與實際結果相符".to_owned()
    } else {
        format!(
            "{}；{}",
            case.note, "兩個 profile 的公開介面斷言與實際結果相符"
        )
    };
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-runtime;rivetlua-compiler;rivetlua-core\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(actual),
        json_escape(&p07_case_command(profile)),
        json_escape(&path.display().to_string()),
        json_escape(&diagnostic),
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn p07_capture(root: &Path, args: &[&str], profile: &str) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args(args)
        .env("RIVETLUA_P07_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p07_records_from_output(
    profile: &str,
    output: &str,
) -> Result<Vec<(String, String, String, String)>, String> {
    output
        .lines()
        .filter_map(|line| line.find("P07_CASE\t").map(|index| &line[index..]))
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 5
                || fields[0] != "P07_CASE"
                || fields.iter().any(|field| field.is_empty())
            {
                return Err(format!("{profile} P07_CASE 欄位不完整：{line}"));
            }
            Ok((
                fields[1].to_owned(),
                fields[2].to_owned(),
                fields[3].to_owned(),
                fields[4].to_owned(),
            ))
        })
        .collect()
}

fn p07_check_test_run(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    args: &[&str],
    minimum_passed: usize,
    profile: &str,
) -> Result<String, String> {
    let command = format!("RIVETLUA_P07_PROFILE={profile} cargo {}", args.join(" "));
    let (success, exit_code, output) = match p07_capture(root, args, profile) {
        Ok(result) => result,
        Err(error) => {
            let _ = p07_fail(root, results, name, &command, error.clone());
            return Err(error);
        }
    };
    let summary = p06_check_test_summary(&output, minimum_passed)
        .map(|passed| format!("{passed} passed; 0 failed; (minimum {minimum_passed})"));
    if !success {
        let summary_error = summary.err().unwrap_or_else(|| "子測試命令失敗".into());
        let error = format!("實際 exit={exit_code}；{summary_error}；輸出：{output}");
        let _ = p07_fail(root, results, name, &command, error.clone());
        return Err(error);
    }
    let summary = match summary {
        Ok(summary) => summary,
        Err(error) => {
            let error = format!("實際 exit={exit_code}；{error}；輸出：{output}");
            let _ = p07_fail(root, results, name, &command, error.clone());
            return Err(error);
        }
    };
    results.push(p07_result(
        name,
        command,
        exit_code,
        "PASS",
        format!("{profile} 執行摘要：{summary}"),
    ));
    Ok(output)
}

fn validate_p07_prior_reports(root: &Path) -> Result<(), String> {
    for phase in ["P00", "P01", "P02", "P03", "P04", "P05", "P06"] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        if !report.starts_with("{\"status\":\"PASS\"") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS"));
        }
    }
    Ok(())
}

fn p08_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P08.json".into(),
    }
}

fn p08_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = root.join("target/rivetlua-reports");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P08 報告目錄失敗：{error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P08 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P08-TAB-") {
            fs::remove_file(entry.path())
                .map_err(|error| format!("清除舊 P08 案例報告失敗：{error}"))?;
        }
    }
    Ok(())
}

fn write_p08_results(root: &Path, results: &[GateResult], diagnostic: &str) -> Result<(), String> {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P08.json");
    fs::create_dir_all(path.parent().ok_or("無效 P08 gate 報告路徑")?)
        .map_err(|error| format!("建立 P08 報告目錄失敗：{error}"))?;
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"diagnostic\":\"{}\",\"checks\":[{checks}]}}\n",
        json_escape(diagnostic)
    );
    fs::write(path, json).map_err(|error| format!("寫入 P08 gate 報告失敗：{error}"))
}

fn p08_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    let _ = p08_clear_case_reports(root);
    results.push(p08_result(name, command, 1, "FAIL", error.clone()));
    write_p08_results(root, results, &error)?;
    Err(error)
}

#[derive(Debug, PartialEq)]
enum StrictJsonValue {
    Object(Vec<(String, Self)>),
    Array(Vec<Self>),
    String(String),
    Number(String),
    Bool(bool),
    Null,
}

impl StrictJsonValue {
    fn get(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find_map(|(key, value)| (key == name).then_some(value)),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    fn is_integer(&self) -> bool {
        match self {
            Self::Number(value) if !value.contains(['.', 'e', 'E']) => value.parse::<i64>().is_ok(),
            _ => false,
        }
    }

    fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Number(value) if !value.contains(['.', 'e', 'E']) => value.parse::<i32>().ok(),
            _ => None,
        }
    }

    fn is_zero_integer(&self) -> bool {
        matches!(self, Self::Number(value) if value == "0")
    }
}

struct StrictJsonParser<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn parse(input: &'a str) -> Result<StrictJsonValue, String> {
        let mut parser = Self {
            bytes: input.as_bytes(),
            cursor: 0,
        };
        parser.skip_whitespace();
        let value = parser.parse_value(0)?;
        parser.skip_whitespace();
        if parser.cursor != parser.bytes.len() {
            return Err(parser.error("JSON 根值後有多餘內容"));
        }
        Ok(value)
    }

    fn error(&self, message: &str) -> String {
        format!("{message}（byte {}）", self.cursor)
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.cursor),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.cursor += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<StrictJsonValue, String> {
        if depth > 128 {
            return Err(self.error("JSON 巢狀超過安全上限"));
        }
        self.skip_whitespace();
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(StrictJsonValue::String),
            Some(b't') => {
                self.parse_literal(b"true")?;
                Ok(StrictJsonValue::Bool(true))
            }
            Some(b'f') => {
                self.parse_literal(b"false")?;
                Ok(StrictJsonValue::Bool(false))
            }
            Some(b'n') => {
                self.parse_literal(b"null")?;
                Ok(StrictJsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.error("JSON 值格式錯誤")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<StrictJsonValue, String> {
        self.cursor += 1;
        self.skip_whitespace();
        let mut entries = Vec::new();
        if self.bytes.get(self.cursor) == Some(&b'}') {
            self.cursor += 1;
            return Ok(StrictJsonValue::Object(entries));
        }
        loop {
            if self.bytes.get(self.cursor) != Some(&b'"') {
                return Err(self.error("JSON 物件欄位名稱必須是字串"));
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(self.error("JSON 物件含重複欄位"));
            }
            self.skip_whitespace();
            if self.bytes.get(self.cursor) != Some(&b':') {
                return Err(self.error("JSON 物件欄位缺少冒號"));
            }
            self.cursor += 1;
            let value = self.parse_value(depth)?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.bytes.get(self.cursor) {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.cursor += 1;
                    return Ok(StrictJsonValue::Object(entries));
                }
                _ => return Err(self.error("JSON 物件缺少逗號或結尾大括號")),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<StrictJsonValue, String> {
        self.cursor += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.bytes.get(self.cursor) == Some(&b']') {
            self.cursor += 1;
            return Ok(StrictJsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            match self.bytes.get(self.cursor) {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.cursor += 1;
                    return Ok(StrictJsonValue::Array(values));
                }
                _ => return Err(self.error("JSON 陣列缺少逗號或結尾中括號")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        debug_assert_eq!(self.bytes.get(self.cursor), Some(&b'"'));
        self.cursor += 1;
        let mut value = String::new();
        let mut chunk_start = self.cursor;
        loop {
            match self.bytes.get(self.cursor).copied() {
                Some(b'"') => {
                    self.push_utf8_chunk(&mut value, chunk_start, self.cursor)?;
                    self.cursor += 1;
                    return Ok(value);
                }
                Some(b'\\') => {
                    self.push_utf8_chunk(&mut value, chunk_start, self.cursor)?;
                    self.cursor += 1;
                    let escaped = self
                        .bytes
                        .get(self.cursor)
                        .copied()
                        .ok_or_else(|| self.error("JSON 字串結尾有未完成跳脫"))?;
                    self.cursor += 1;
                    match escaped {
                        b'"' => value.push('"'),
                        b'\\' => value.push('\\'),
                        b'/' => value.push('/'),
                        b'b' => value.push('\u{0008}'),
                        b'f' => value.push('\u{000c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'u' => {
                            let first = self.parse_hex_quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                if self.bytes.get(self.cursor..self.cursor.saturating_add(2))
                                    != Some(b"\\u")
                                {
                                    return Err(self.error("JSON 高代理字元缺少低代理字元"));
                                }
                                self.cursor += 2;
                                let second = self.parse_hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(self.error("JSON 低代理字元格式錯誤"));
                                }
                                0x10000
                                    + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(self.error("JSON 低代理字元沒有配對高代理字元"));
                            } else {
                                first as u32
                            };
                            value
                                .push(char::from_u32(scalar).ok_or_else(|| {
                                    self.error("JSON Unicode 跳脫不是有效純量值")
                                })?);
                        }
                        _ => return Err(self.error("JSON 字串含無效跳脫")),
                    }
                    chunk_start = self.cursor;
                }
                Some(byte) if byte < 0x20 => {
                    return Err(self.error("JSON 字串含未跳脫控制字元"));
                }
                Some(_) => self.cursor += 1,
                None => return Err(self.error("JSON 字串未結束")),
            }
        }
    }

    fn push_utf8_chunk(&self, value: &mut String, start: usize, end: usize) -> Result<(), String> {
        let chunk = std::str::from_utf8(&self.bytes[start..end])
            .map_err(|_| self.error("JSON 字串含無效 UTF-8"))?;
        value.push_str(chunk);
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16, String> {
        let end = self.cursor.saturating_add(4);
        let digits = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| self.error("JSON Unicode 跳脫不足四位"))?;
        let mut value = 0u16;
        for digit in digits {
            value = value
                .checked_mul(16)
                .and_then(|value| hex_digit(*digit).and_then(|digit| value.checked_add(digit)))
                .ok_or_else(|| self.error("JSON Unicode 跳脫含非十六進位字元"))?;
        }
        self.cursor = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<StrictJsonValue, String> {
        let start = self.cursor;
        if self.bytes.get(self.cursor) == Some(&b'-') {
            self.cursor += 1;
        }
        match self.bytes.get(self.cursor) {
            Some(b'0') => {
                self.cursor += 1;
                if self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                    return Err(self.error("JSON 數字不可有前導零"));
                }
            }
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                    self.cursor += 1;
                }
            }
            _ => return Err(self.error("JSON 數字整數部分格式錯誤")),
        }
        if self.bytes.get(self.cursor) == Some(&b'.') {
            self.cursor += 1;
            let fraction_start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if fraction_start == self.cursor {
                return Err(self.error("JSON 小數點後至少需要一位數字"));
            }
        }
        if matches!(self.bytes.get(self.cursor), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.bytes.get(self.cursor), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            let exponent_start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if exponent_start == self.cursor {
                return Err(self.error("JSON 指數部分至少需要一位數字"));
            }
        }
        let number = std::str::from_utf8(&self.bytes[start..self.cursor])
            .map_err(|_| self.error("JSON 數字不是 ASCII"))?;
        Ok(StrictJsonValue::Number(number.to_owned()))
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        let end = self.cursor.saturating_add(literal.len());
        if self.bytes.get(self.cursor..end) != Some(literal) {
            return Err(self.error("JSON literal 格式錯誤"));
        }
        self.cursor = end;
        Ok(())
    }
}

fn hex_digit(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u16),
        b'a'..=b'f' => Some((byte - b'a' + 10) as u16),
        b'A'..=b'F' => Some((byte - b'A' + 10) as u16),
        _ => None,
    }
}

fn validate_p08_prior_reports(root: &Path) -> Result<(), String> {
    let current_digest = source_digest(root)?;
    for phase in ["P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07"] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 報告不是合法 PASS JSON"));
        }
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 gate 報告缺少非空 checks 陣列"))?;
        for check in checks {
            let name = check
                .get("name")
                .and_then(StrictJsonValue::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 報告含缺少名稱的檢查"))?;
            let status = check.get("status").and_then(StrictJsonValue::as_str);
            let exit_code_is_integer = check
                .get("exit_code")
                .is_some_and(StrictJsonValue::is_integer);
            if status != Some("PASS") || !exit_code_is_integer {
                return Err(format!(
                    "{phase} 前置 gate 檢查 {name} 缺少 PASS 狀態或整數 exit_code"
                ));
            }
        }
        if phase == "P07" {
            for name in ["p01-before", "p05-before", "p06-before", "p00-p06-before"] {
                let matching = checks
                    .iter()
                    .filter(|check| {
                        check.get("name").and_then(StrictJsonValue::as_str) == Some(name)
                    })
                    .count();
                if matching != 1 {
                    return Err(format!(
                        "P07 checks 陣列中回歸檢查 {name} 應恰有一筆，實際為 {matching} 筆"
                    ));
                }
                let check = checks
                    .iter()
                    .find(|check| check.get("name").and_then(StrictJsonValue::as_str) == Some(name))
                    .expect("matching count was checked");
                if !check
                    .get("exit_code")
                    .is_some_and(StrictJsonValue::is_zero_integer)
                {
                    return Err(format!("P07 回歸檢查 {name} 的 exit_code 必須為 0"));
                }
            }
        }
        validate_report_source_digest(phase, &parsed, &current_digest)?;
    }
    Ok(())
}

fn p08_case_command(profile: &str) -> String {
    format!(
        "RIVETLUA_P08_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p08_contracts -- --nocapture --test-threads=1"
    )
}

fn p08_traversal_command(profile: &str) -> String {
    format!(
        "RIVETLUA_P08_PROFILE={profile} cargo test --locked -p rivetlua-runtime --lib table_iteration -- --nocapture --test-threads=1"
    )
}

fn p08_case_report(
    root: &Path,
    case: &P08FixtureCase,
    profile: &str,
    lua_profile: &str,
    actual: &str,
    command: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P08-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P08 案例報告路徑")?)
        .map_err(|error| error.to_string())?;
    let diagnostic = format!(
        "{}；兩個 profile 分別執行，marker assertion 與 fixture 相符",
        case.note
    );
    let json = format!(
        "{{\"case_id\":\"{}\",\"requires\":\"rivetlua-runtime;rivetlua-compiler;rivetlua-core\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(actual),
        json_escape(command),
        json_escape(&path.display().to_string()),
        json_escape(&diagnostic),
    );
    fs::write(&path, json).map_err(|error| error.to_string())?;
    Ok(path)
}

fn p08_capture(
    root: &Path,
    args: &[&str],
    profile: Option<&str>,
) -> Result<(bool, i32, String), String> {
    let mut command = Command::new("cargo");
    command.args(args).current_dir(root);
    if let Some(profile) = profile {
        command.env("RIVETLUA_P08_PROFILE", profile);
    }
    let output = command.output().map_err(|error| error.to_string())?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn p08_check_test_run(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    args: &[&str],
    minimum_passed: usize,
    profile: Option<&str>,
    command_text: &str,
) -> Result<String, String> {
    let (success, exit_code, output) = match p08_capture(root, args, profile) {
        Ok(result) => result,
        Err(error) => {
            let _ = p08_fail(root, results, name, command_text, error.clone());
            return Err(error);
        }
    };
    let summary = p06_check_test_summary(&output, minimum_passed)
        .map(|passed| format!("{passed} passed; 0 failed; (minimum {minimum_passed})"));
    if !success {
        let summary_error = summary.err().unwrap_or_else(|| "子測試命令失敗".into());
        let error = format!("實際 exit={exit_code}；{summary_error}；輸出：{output}");
        let _ = p08_fail(root, results, name, command_text, error.clone());
        return Err(error);
    }
    let summary = match summary {
        Ok(summary) => summary,
        Err(error) => {
            let error = format!("實際 exit={exit_code}；{error}；輸出：{output}");
            let _ = p08_fail(root, results, name, command_text, error.clone());
            return Err(error);
        }
    };
    results.push(p08_result(
        name,
        command_text,
        exit_code,
        "PASS",
        format!("{} 執行摘要：{summary}", profile.unwrap_or("不分 profile")),
    ));
    Ok(output)
}

fn p08_gate() -> Result<(), String> {
    let root = root()?;
    p08_clear_case_reports(&root)?;
    let gate_report = root.join("target/rivetlua-reports/gate-P08.json");
    if gate_report.exists() {
        fs::remove_file(&gate_report)
            .map_err(|error| format!("清除舊 P08 gate 報告失敗：{error}"))?;
    }
    let mut results = Vec::new();

    if let Err(error) = validate_p08_prior_reports(&root) {
        return p08_fail(
            &root,
            &mut results,
            "p00-p07-before",
            "validate target/rivetlua-reports/gate-P00.json..gate-P07.json",
            error,
        );
    }
    results.push(p08_result(
        "p00-p07-before",
        "validate target/rivetlua-reports/gate-P00.json..gate-P07.json",
        0,
        "PASS",
        "P00～P07 報告皆存在且 status=PASS",
    ));

    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p08_fail(
                &root,
                &mut results,
                "p08-csv",
                "read spec/compatibility.csv",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p08_csv_cases(&csv)) {
        return p08_fail(
            &root,
            &mut results,
            "p08-csv",
            "validate P08 compatibility rows",
            error,
        );
    }
    results.push(p08_result(
        "p08-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各自完整映射 TAB-001～012",
    ));

    let fixture_contents = match fs::read_to_string(root.join(P08_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p08_fail(
                &root,
                &mut results,
                "p08-fixture",
                P08_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p08_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p08_fail(&root, &mut results, "p08-fixture", P08_FIXTURE, error),
    };
    results.push(p08_result(
        "p08-fixture",
        P08_FIXTURE,
        0,
        "PASS",
        "兩個 profile 映射與 TAB-001～012 唯一案例有效",
    ));

    if let Err(error) = validate_p08_prior_reports(&root) {
        return p08_fail(
            &root,
            &mut results,
            "p00-p07-after",
            "validate P00～P07 gate reports",
            error,
        );
    }
    results.push(p08_result(
        "p07-regression",
        "validate target/rivetlua-reports/gate-P07.json regression checks",
        0,
        "PASS",
        "P07 PASS 報告包含通過的 P01/P05/P06 與 P00～P06 前置回歸檢查",
    ));

    let unit_args = [
        "test",
        "--locked",
        "-p",
        "rivetlua-runtime",
        "--lib",
        "--",
        "--test-threads=1",
    ];
    if let Err(error) = p08_check_test_run(
        &root,
        &mut results,
        "p08-runtime-unit",
        &unit_args,
        68,
        Some("lua55-i64f64"),
        "RIVETLUA_P08_PROFILE=lua55-i64f64 cargo test --locked -p rivetlua-runtime --lib -- --test-threads=1",
    ) {
        return Err(error);
    }

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let contract_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p08_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ];
        let command = p08_case_command(profile);
        let test_name = format!("p08-contracts-{lua_profile}");
        let output = match p08_check_test_run(
            &root,
            &mut results,
            &test_name,
            &contract_args,
            5,
            Some(profile),
            &command,
        ) {
            Ok(output) => output,
            Err(error) => return Err(error),
        };
        let mut records = match p08_records_from_output(profile, &output) {
            Ok(records) => records,
            Err(error) => return p08_fail(&root, &mut results, &test_name, &command, error),
        };
        if records.iter().any(|record| record.id == "TAB-010") {
            return p08_fail(
                &root,
                &mut results,
                &test_name,
                &command,
                "TAB-010 必須由 runtime internal traversal unit 產生".into(),
            );
        }
        let traversal_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "table_iteration",
            "--",
            "--nocapture",
            "--test-threads=1",
        ];
        let traversal_command = p08_traversal_command(profile);
        let traversal_name = format!("p08-traversal-{lua_profile}");
        let traversal_output = match p08_check_test_run(
            &root,
            &mut results,
            &traversal_name,
            &traversal_args,
            1,
            Some(profile),
            &traversal_command,
        ) {
            Ok(output) => output,
            Err(error) => return Err(error),
        };
        let traversal_records = match p08_records_from_output(profile, &traversal_output) {
            Ok(records) => records,
            Err(error) => {
                return p08_fail(
                    &root,
                    &mut results,
                    &traversal_name,
                    &traversal_command,
                    error,
                );
            }
        };
        if traversal_records.len() != 2
            || traversal_records
                .iter()
                .any(|record| record.id != "TAB-010")
        {
            return p08_fail(
                &root,
                &mut results,
                &traversal_name,
                &traversal_command,
                format!(
                    "TAB-010 必須取得兩個插入順序 marker，實際 {}",
                    traversal_records.len()
                ),
            );
        }
        records.extend(traversal_records);
        if let Err(error) = validate_p08_records(profile, &fixture, &records) {
            return p08_fail(
                &root,
                &mut results,
                &test_name,
                "validate P08_CASE records",
                error,
            );
        }

        for case in &fixture {
            let matches: Vec<_> = records
                .iter()
                .filter(|record| record.id == case.id)
                .collect();
            let actual = if case.id == "TAB-010" {
                matches
                    .iter()
                    .map(|record| {
                        format!(
                            "input_order={}; expected_fields=5; actual={}",
                            record.input, record.actual
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" | ")
            } else {
                let record = matches[0];
                if record.diagnostic.is_empty() {
                    record.actual.clone()
                } else {
                    format!("{}; diagnostic={}", record.actual, record.diagnostic)
                }
            };
            let case_command = if case.id == "TAB-010" {
                &traversal_command
            } else {
                &command
            };
            let path =
                match p08_case_report(&root, case, profile, lua_profile, &actual, case_command) {
                    Ok(path) => path,
                    Err(error) => {
                        return p08_fail(
                            &root,
                            &mut results,
                            &case.id,
                            "write P08 case report",
                            error,
                        );
                    }
                };
            results.push(GateResult {
                name: format!("{}-{lua_profile}", case.id),
                command: case_command.clone(),
                exit_code: 0,
                status: "PASS",
                diagnostic: format!(
                    "profile={profile}; expected/input validated; report={}",
                    path.display()
                ),
                report_path: path.display().to_string(),
            });
        }
    }

    let case_count = results
        .iter()
        .filter(|item| item.name.starts_with("TAB-"))
        .count();
    if case_count != P08_CASES.len() * 2 {
        return p08_fail(
            &root,
            &mut results,
            "p08-case-count",
            "validate P08 case reports",
            format!("P08 唯一 case 報告數錯誤：預期 24，實際 {case_count}"),
        );
    }
    write_p08_results(
        &root,
        &results,
        "TAB-001～012 兩 profile 各自通過，共 24 份唯一案例報告",
    )?;
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P08.json").display()
    );
    Ok(())
}

fn p09_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P09.json".into(),
    }
}

fn p09_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = root.join("target/rivetlua-reports");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P09 報告目錄失敗：{error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P09 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P09-CALL-") {
            fs::remove_file(entry.path())
                .map_err(|error| format!("清除舊 P09 案例報告失敗：{error}"))?;
        }
    }
    Ok(())
}

fn write_p09_results(root: &Path, results: &[GateResult], diagnostic: &str) -> Result<(), String> {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P09.json");
    fs::create_dir_all(path.parent().ok_or("無效 P09 gate 報告路徑")?)
        .map_err(|error| format!("建立 P09 報告目錄失敗：{error}"))?;
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"diagnostic\":\"{}\",\"checks\":[{checks}]}}\n",
        json_escape(diagnostic)
    );
    fs::write(path, json).map_err(|error| format!("寫入 P09 gate 報告失敗：{error}"))
}

fn p09_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    let _ = p09_clear_case_reports(root);
    results.push(p09_result(name, command, 1, "FAIL", error.clone()));
    write_p09_results(root, results, &error)?;
    Err(error)
}

fn validate_p09_prior_reports(root: &Path) -> Result<(), String> {
    let current_digest = source_digest(root)?;
    for phase in [
        "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08",
    ] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS JSON"));
        }
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 gate 報告缺少非空 checks 陣列"))?;
        for check in checks {
            let name = check
                .get("name")
                .and_then(StrictJsonValue::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查缺少名稱"))?;
            let command = check
                .get("command")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 command"))?;
            let diagnostic = check
                .get("diagnostic")
                .and_then(StrictJsonValue::as_str)
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 diagnostic"))?;
            let report_path = check
                .get("report_path")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 report_path"))?;
            let _ = (command, diagnostic, report_path);
            let status = check.get("status").and_then(StrictJsonValue::as_str);
            let exit_code = check.get("exit_code");
            if status != Some("PASS") || !exit_code.is_some_and(StrictJsonValue::is_integer) {
                return Err(format!(
                    "{phase} 前置 gate 檢查 {name} 缺少 PASS 狀態或整數 exit_code"
                ));
            }
        }
        if phase == "P07" {
            for name in ["p01-before", "p05-before", "p06-before", "p00-p06-before"] {
                let matching = checks
                    .iter()
                    .filter(|check| {
                        check.get("name").and_then(StrictJsonValue::as_str) == Some(name)
                    })
                    .count();
                if matching != 1 {
                    return Err(format!(
                        "P07 checks 陣列中回歸檢查 {name} 應恰有一筆，實際為 {matching} 筆"
                    ));
                }
            }
        }
        validate_report_source_digest(phase, &parsed, &current_digest)?;
    }
    Ok(())
}

fn p09_case_command(profile: &str) -> String {
    format!(
        "RIVETLUA_P09_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p09_contracts -- --nocapture --test-threads=1"
    )
}

fn p09_check_test_summary(output: &str) -> Result<(), String> {
    if output
        .lines()
        .any(|line| line.contains("test result: ok. 11 passed; 0 failed;"))
    {
        Ok(())
    } else {
        Err("P09 contracts 必須精確執行 11 個成功測試".into())
    }
}

fn p09_capture(root: &Path, profile: &str) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p09_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P09_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P09 contracts 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn write_p09_case_report(
    root: &Path,
    case: &P09FixtureCase,
    lua_profile: &str,
    actual: &str,
    command: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P09-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P09 case report 路徑")?)
        .map_err(|error| format!("建立 P09 case report 目錄失敗：{error}"))?;
    let diagnostic = if case.id == "CALL-013" {
        "宿主環境提供兩個有效 __close Lua closure；runtime marker 與測試斷言確認 Call(All)→ClosePath→Return(All)、Returned 三值、peak=2、數值 path_pc 與 close_order=LIFO"
    } else {
        "profile 獨立執行，case marker 與斷言完整通過"
    };
    let json = format!(
        "{{\"case_id\":\"{}\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(&case.profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(actual),
        json_escape(command),
        json_escape(&path.display().to_string()),
        json_escape(diagnostic),
    );
    fs::write(&path, json).map_err(|error| format!("寫入 P09 case report 失敗：{error}"))?;
    Ok(path)
}

fn p09_gate() -> Result<(), String> {
    let root = root()?;
    if let Err(error) = p09_clear_case_reports(&root) {
        let mut results = Vec::new();
        return p09_fail(
            &root,
            &mut results,
            "p09-clear-cases",
            "clear old P09 case reports",
            error,
        );
    }
    let gate_report = root.join("target/rivetlua-reports/gate-P09.json");
    if gate_report.exists() {
        if let Err(error) = fs::remove_file(&gate_report) {
            let mut results = Vec::new();
            return p09_fail(
                &root,
                &mut results,
                "p09-clear-aggregate",
                "remove old gate-P09.json",
                error.to_string(),
            );
        }
    }
    let mut results = Vec::new();
    let prior_command = "validate target/rivetlua-reports/gate-P00.json..gate-P08.json";
    if let Err(error) = validate_p09_prior_reports(&root) {
        return p09_fail(&root, &mut results, "p00-p08-before", prior_command, error);
    }
    results.push(p09_result(
        "p00-p08-before",
        prior_command,
        0,
        "PASS",
        "P00～P08 aggregate 與必要 check 欄位均為 PASS",
    ));

    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p09_fail(
                &root,
                &mut results,
                "p09-csv",
                "read spec/compatibility.csv",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p09_csv_cases(&csv)) {
        return p09_fail(
            &root,
            &mut results,
            "p09-csv",
            "validate P09 compatibility rows",
            error,
        );
    }
    results.push(p09_result(
        "p09-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各自映射指定 12 個 CALL 案例",
    ));

    let fixture_contents = match fs::read_to_string(root.join(P09_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p09_fail(
                &root,
                &mut results,
                "p09-fixture",
                P09_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p09_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p09_fail(&root, &mut results, "p09-fixture", P09_FIXTURE, error),
    };
    results.push(p09_result(
        "p09-fixture",
        P09_FIXTURE,
        0,
        "PASS",
        "兩個完整 profile 各有 12 個唯一 CALL 案例，mode／expected 對照有效",
    ));

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = p09_case_command(profile);
        let (success, exit_code, output) = match p09_capture(&root, profile) {
            Ok(result) => result,
            Err(error) => {
                return p09_fail(
                    &root,
                    &mut results,
                    &format!("p09-contracts-{lua_profile}"),
                    &command,
                    error,
                );
            }
        };
        let name = format!("p09-contracts-{lua_profile}");
        if !success {
            return p09_fail(
                &root,
                &mut results,
                &name,
                &command,
                format!("實際 exit={exit_code}；P09 runtime 子行程失敗：{output}"),
            );
        }
        if let Err(error) = p09_check_test_summary(&output) {
            return p09_fail(
                &root,
                &mut results,
                &name,
                &command,
                format!("{error}；輸出：{output}"),
            );
        }
        let records = match p09_records_from_output(profile, &output) {
            Ok(records) => records,
            Err(error) => return p09_fail(&root, &mut results, &name, &command, error),
        };
        let actuals = match validate_p09_records(profile, &fixture, &records) {
            Ok(actuals) => actuals,
            Err(error) => return p09_fail(&root, &mut results, &name, &command, error),
        };
        for case in fixture.iter().filter(|case| case.profile == profile) {
            let Some(actual) = actuals.get(&case.id) else {
                return p09_fail(
                    &root,
                    &mut results,
                    &case.id,
                    &command,
                    format!("{profile} 缺少 {} 實際結果", case.id),
                );
            };
            let path = match write_p09_case_report(&root, case, lua_profile, actual, &command) {
                Ok(path) => path,
                Err(error) => {
                    return p09_fail(
                        &root,
                        &mut results,
                        &case.id,
                        "write P09 case report",
                        error,
                    );
                }
            };
            results.push(GateResult {
                name: format!("{}-{lua_profile}", case.id),
                command: command.clone(),
                exit_code,
                status: "PASS",
                diagnostic: format!("profile={profile}; report={}", path.display()),
                report_path: path.display().to_string(),
            });
        }
        results.push(p09_result(
            name,
            command,
            exit_code,
            "PASS",
            format!("{profile} contracts 精確通過 11 個整合測試與全部 P09 markers"),
        ));
    }

    let case_names: std::collections::HashSet<_> = results
        .iter()
        .filter(|item| item.name.starts_with("CALL-"))
        .map(|item| item.name.clone())
        .collect();
    let case_count = case_names.len();
    if case_count != 24
        || results
            .iter()
            .filter(|item| item.name.starts_with("CALL-"))
            .count()
            != 24
    {
        return p09_fail(
            &root,
            &mut results,
            "p09-case-count",
            "validate unique P09 case reports",
            format!("P09 唯一 case 報告數錯誤：預期 24，實際 {case_count}"),
        );
    }
    write_p09_results(
        &root,
        &results,
        "CALL-001～013 依 profile 矩陣各自執行，產生 24 份唯一 PASS 案例報告",
    )?;
    println!("PASS report={}", gate_report.display());
    Ok(())
}

fn validate_p10_prior_reports(root: &Path) -> Result<(), String> {
    let current_digest = source_digest(root)?;
    for phase in [
        "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09",
    ] {
        let path = root.join(format!("target/rivetlua-reports/gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告 {}：{error}", path.display()))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate 報告不是合法 JSON：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 報告不是 PASS JSON"));
        }
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 gate 報告缺少非空 checks 陣列"))?;
        for check in checks {
            let name = check
                .get("name")
                .and_then(StrictJsonValue::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查缺少名稱"))?;
            let command = check
                .get("command")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 command"))?;
            let diagnostic = check
                .get("diagnostic")
                .and_then(StrictJsonValue::as_str)
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 diagnostic"))?;
            let report_path = check
                .get("report_path")
                .and_then(StrictJsonValue::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{phase} 前置 gate 檢查 {name} 缺少 report_path"))?;
            let status = check.get("status").and_then(StrictJsonValue::as_str);
            let exit_code = check.get("exit_code");
            if status != Some("PASS") || !exit_code.is_some_and(StrictJsonValue::is_integer) {
                return Err(format!(
                    "{phase} 前置 gate 檢查 {name} 缺少 PASS 狀態或整數 exit_code"
                ));
            }
            let _ = (command, diagnostic, report_path);
        }
        if phase == "P07" {
            for name in ["p01-before", "p05-before", "p06-before", "p00-p06-before"] {
                let matching = checks
                    .iter()
                    .filter(|check| {
                        check.get("name").and_then(StrictJsonValue::as_str) == Some(name)
                    })
                    .count();
                if matching != 1 {
                    return Err(format!(
                        "P07 checks 陣列中回歸檢查 {name} 應恰有一筆，實際為 {matching} 筆"
                    ));
                }
            }
        }
        validate_report_source_digest(phase, &parsed, &current_digest)?;
    }
    Ok(())
}

fn p10_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: "target/rivetlua-reports/gate-P10.json".into(),
    }
}

fn p10_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = root.join("target/rivetlua-reports");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P10 報告目錄失敗：{error}")),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P10 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P10-META-") {
            fs::remove_file(entry.path())
                .map_err(|error| format!("清除舊 P10 案例報告失敗：{error}"))?;
        }
    }
    Ok(())
}

fn write_p10_results(root: &Path, results: &[GateResult], diagnostic: &str) -> Result<(), String> {
    let source_digest = source_digest(root).expect("無法計算 gate 來源 digest");
    let path = root.join("target/rivetlua-reports/gate-P10.json");
    fs::create_dir_all(path.parent().ok_or("無效 P10 gate 報告路徑")?)
        .map_err(|error| format!("建立 P10 報告目錄失敗：{error}"))?;
    let status = if !results.is_empty() && results.iter().all(|item| item.status == "PASS") {
        "PASS"
    } else {
        "FAIL"
    };
    let checks = results
        .iter()
        .map(|item| {
            format!(
                "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
                json_escape(&item.name),
                json_escape(&item.command),
                item.exit_code,
                item.status,
                json_escape(&item.diagnostic),
                json_escape(&item.report_path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{source_digest}\",\"diagnostic\":\"{}\",\"checks\":[{checks}]}}\n",
        json_escape(diagnostic)
    );
    fs::write(path, json).map_err(|error| format!("寫入 P10 gate 報告失敗：{error}"))
}

fn p10_fail(
    root: &Path,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    error: String,
) -> Result<(), String> {
    let _ = p10_clear_case_reports(root);
    results.push(p10_result(name, command, 1, "FAIL", error.clone()));
    write_p10_results(root, results, &error)?;
    Err(error)
}

fn p10_capture(root: &Path, profile: &str) -> Result<(bool, i32, String), String> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p10_contracts",
            "meta_case_",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RIVETLUA_P10_PROFILE", profile)
        .current_dir(root)
        .output()
        .map_err(|error| format!("啟動 P10 contracts 子行程失敗：{error}"))?;
    let success = output.status.success();
    let exit_code = output.status.code().unwrap_or(1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((success, exit_code, output))
}

fn write_p10_case_report(
    root: &Path,
    case: &P10FixtureCase,
    lua_profile: &str,
    record: &P10Record,
    command: &str,
) -> Result<PathBuf, String> {
    let path = root.join(format!(
        "target/rivetlua-reports/P10-{}-{lua_profile}.json",
        case.id
    ));
    fs::create_dir_all(path.parent().ok_or("無效 P10 case report 路徑")?)
        .map_err(|error| format!("建立 P10 case report 目錄失敗：{error}"))?;
    let diagnostic = format!("{}；{}", case.note, record.diagnostic);
    let json = format!(
        "{{\"case_id\":\"{}\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"exit_code\":0,\"report_path\":\"{}\",\"diagnostic\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(&case.profile),
        json_escape(lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(&record.actual),
        json_escape(command),
        json_escape(&path.display().to_string()),
        json_escape(&diagnostic),
    );
    fs::write(&path, json).map_err(|error| format!("寫入 P10 case report 失敗：{error}"))?;
    Ok(path)
}

fn p10_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    if let Err(error) = p10_clear_case_reports(&root) {
        return p10_fail(
            &root,
            &mut results,
            "p10-clear-cases",
            "clear old P10 case reports",
            error,
        );
    }
    let gate_report = root.join("target/rivetlua-reports/gate-P10.json");
    if gate_report.exists() {
        if let Err(error) = fs::remove_file(&gate_report) {
            return p10_fail(
                &root,
                &mut results,
                "p10-clear-aggregate",
                "remove old gate-P10.json",
                error.to_string(),
            );
        }
    }
    let prior_command = "validate target/rivetlua-reports/gate-P00.json..gate-P09.json";
    if let Err(error) = validate_p10_prior_reports(&root) {
        return p10_fail(&root, &mut results, "p00-p09-before", prior_command, error);
    }
    results.push(p10_result(
        "p00-p09-before",
        prior_command,
        0,
        "PASS",
        "P00～P09 aggregate 與必要 check 欄位均為 PASS",
    ));

    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p10_fail(
                &root,
                &mut results,
                "p10-csv",
                "read spec/compatibility.csv",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p10_csv_cases(&csv)) {
        return p10_fail(
            &root,
            &mut results,
            "p10-csv",
            "validate P10 compatibility rows",
            error,
        );
    }
    results.push(p10_result(
        "p10-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各自映射完整 10 個 META 案例",
    ));

    let fixture_contents = match fs::read_to_string(root.join(P10_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p10_fail(
                &root,
                &mut results,
                "p10-fixture",
                P10_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p10_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => {
            return p10_fail(&root, &mut results, "p10-fixture", P10_FIXTURE, error);
        }
    };
    results.push(p10_result(
        "p10-fixture",
        P10_FIXTURE,
        0,
        "PASS",
        "兩個完整 profile 各有 10 個唯一 META 案例且 expected 對照有效",
    ));

    let unit_command = p10_unit_command();
    let (unit_success, unit_exit_code, unit_output) = match p10_capture_unit(&root) {
        Ok(result) => result,
        Err(error) => {
            return p10_fail(&root, &mut results, "p10-runtime-unit", unit_command, error);
        }
    };
    if !unit_success {
        return p10_fail(
            &root,
            &mut results,
            "p10-runtime-unit",
            unit_command,
            format!("實際 exit={unit_exit_code}；P10 runtime unit 失敗：{unit_output}"),
        );
    }
    if let Err(error) = p10_check_unit_summary(&unit_output) {
        return p10_fail(
            &root,
            &mut results,
            "p10-runtime-unit",
            unit_command,
            format!("{error}；輸出：{unit_output}"),
        );
    }
    results.push(p10_result(
        "p10-runtime-unit",
        unit_command,
        unit_exit_code,
        "PASS",
        "P10 unit 精確執行 7/7；p10_3_pending_op_resume 直接斷言 caller_depth、caller/resume PC、PendingOp LIFO 與 roots 清理",
    ));

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let command = p10_case_command(profile);
        let (success, exit_code, output) = match p10_capture(&root, profile) {
            Ok(result) => result,
            Err(error) => {
                return p10_fail(
                    &root,
                    &mut results,
                    &format!("p10-contracts-{lua_profile}"),
                    &command,
                    error,
                );
            }
        };
        let name = format!("p10-contracts-{lua_profile}");
        if !success {
            return p10_fail(
                &root,
                &mut results,
                &name,
                &command,
                format!("實際 exit={exit_code}；P10 runtime 子行程失敗：{output}"),
            );
        }
        if let Err(error) = p10_check_test_summary(&output) {
            return p10_fail(
                &root,
                &mut results,
                &name,
                &command,
                format!("{error}；輸出：{output}"),
            );
        }
        let records = match p10_records_from_output(profile, &output) {
            Ok(records) => records,
            Err(error) => return p10_fail(&root, &mut results, &name, &command, error),
        };
        let actuals = match validate_p10_records(profile, &fixture, &records) {
            Ok(actuals) => actuals,
            Err(error) => return p10_fail(&root, &mut results, &name, &command, error),
        };
        for case in fixture.iter().filter(|case| case.profile == profile) {
            let Some(record) = actuals.get(&case.id) else {
                return p10_fail(
                    &root,
                    &mut results,
                    &case.id,
                    &command,
                    format!("{profile} 缺少 {} 實際結果", case.id),
                );
            };
            let path = match write_p10_case_report(&root, case, lua_profile, record, &command) {
                Ok(path) => path,
                Err(error) => {
                    return p10_fail(
                        &root,
                        &mut results,
                        &case.id,
                        "write P10 case report",
                        error,
                    );
                }
            };
            results.push(GateResult {
                name: format!("{}-{lua_profile}", case.id),
                command: command.clone(),
                exit_code,
                status: "PASS",
                diagnostic: format!(
                    "profile={profile};event/result evidence validated; report={}",
                    path.display()
                ),
                report_path: path.display().to_string(),
            });
        }
        results.push(p10_result(
            name,
            command,
            exit_code,
            "PASS",
            format!("{profile} 精確通過 10 個 meta_case_ tests 與 META markers"),
        ));
    }

    let case_names: std::collections::HashSet<_> = results
        .iter()
        .filter(|item| item.name.starts_with("META-"))
        .map(|item| item.name.clone())
        .collect();
    if case_names.len() != 20
        || results
            .iter()
            .filter(|item| item.name.starts_with("META-"))
            .count()
            != 20
    {
        return p10_fail(
            &root,
            &mut results,
            "p10-case-count",
            "validate unique P10 case reports",
            format!(
                "P10 唯一 case 報告數錯誤：預期 20，實際 {}",
                case_names.len()
            ),
        );
    }
    write_p10_results(
        &root,
        &results,
        "META-001～010 依 lua55/lua54 profile 各自執行，產生 20 份唯一 PASS 案例報告",
    )?;
    println!("PASS report={}", gate_report.display());
    Ok(())
}

fn p07_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let csv_path = root.join("spec/compatibility.csv");
    let csv = match fs::read_to_string(&csv_path) {
        Ok(csv) => csv,
        Err(error) => {
            return p07_fail(
                &root,
                &mut results,
                "p07-csv",
                "read P07 CSV",
                error.to_string(),
            );
        }
    };
    if let Err(error) = validate_csv(&csv).and_then(|()| validate_p07_csv_cases(&csv)) {
        return p07_fail(&root, &mut results, "p07-csv", "validate P07 CSV", error);
    }
    results.push(p07_result(
        "p07-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "兩個 lua_profile 各自唯一追溯 VM-001～010",
    ));

    let fixture_contents = match fs::read_to_string(root.join(P07_FIXTURE)) {
        Ok(contents) => contents,
        Err(error) => {
            return p07_fail(
                &root,
                &mut results,
                "p07-fixture",
                P07_FIXTURE,
                error.to_string(),
            );
        }
    };
    let fixture = match parse_p07_fixture(&fixture_contents) {
        Ok(fixture) => fixture,
        Err(error) => return p07_fail(&root, &mut results, "p07-fixture", P07_FIXTURE, error),
    };
    results.push(p07_result(
        "p07-fixture",
        P07_FIXTURE,
        0,
        "PASS",
        "兩個 profile 映射、十個唯一案例輸入及 fuel 限制註記完整",
    ));

    let p01_command = "cargo run --locked -p rivetlua-xtask -- gate P01";
    if let Err(error) = p01_gate() {
        return p07_fail(&root, &mut results, "p01-before", p01_command, error);
    }
    results.push(p07_result(
        "p01-before",
        p01_command,
        0,
        "PASS",
        "P01 Value regression 通過",
    ));
    let p05_command = "cargo run --locked -p rivetlua-xtask -- gate P05";
    if let Err(error) = p05_gate() {
        return p07_fail(&root, &mut results, "p05-before", p05_command, error);
    }
    results.push(p07_result(
        "p05-before",
        p05_command,
        0,
        "PASS",
        "P05 RVLU_V2 baseline 通過",
    ));
    let p06_command = "cargo run --locked -p rivetlua-xtask -- gate P06";
    if let Err(error) = p06_gate() {
        return p07_fail(&root, &mut results, "p06-before", p06_command, error);
    }
    results.push(p07_result(
        "p06-before",
        p06_command,
        0,
        "PASS",
        "P06 heap/root regression 通過",
    ));
    if let Err(error) = validate_p07_prior_reports(&root) {
        return p07_fail(
            &root,
            &mut results,
            "p00-p06-before",
            "validate target/rivetlua-reports/gate-P00.json..gate-P06.json",
            error,
        );
    }
    results.push(p07_result(
        "p00-p06-before",
        "validate target/rivetlua-reports/gate-P00.json..gate-P06.json",
        0,
        "PASS",
        "P00～P06 七個前置報告皆為 PASS",
    ));

    let format_command = "cargo fmt --all -- --check";
    if let Err(error) = run("cargo", &["fmt", "--all", "--", "--check"], &root) {
        return p07_fail(&root, &mut results, "p07-format", format_command, error);
    }
    results.push(p07_result(
        "p07-format",
        format_command,
        0,
        "PASS",
        "格式檢查通過",
    ));
    let unit_args = [
        "test",
        "--locked",
        "-p",
        "rivetlua-runtime",
        "--lib",
        "--",
        "--test-threads=1",
    ];
    if let Err(error) = p07_check_test_run(
        &root,
        &mut results,
        "p07-runtime-unit",
        &unit_args,
        48,
        "lua55-i64f64",
    ) {
        return Err(error);
    }

    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        let contract_args = [
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--test",
            "p07_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ];
        let name = format!("p07-contracts-{lua_profile}");
        let output =
            match p07_check_test_run(&root, &mut results, &name, &contract_args, 26, profile) {
                Ok(output) => output,
                Err(error) => return Err(error),
            };
        let records = match p07_records_from_output(profile, &output) {
            Ok(records) => records,
            Err(error) => {
                return p07_fail(&root, &mut results, &name, "parse P07_CASE records", error);
            }
        };
        if let Err(error) = validate_p07_records(profile, &fixture, &records) {
            return p07_fail(
                &root,
                &mut results,
                &name,
                "validate P07_CASE results",
                error,
            );
        }
        for case in &fixture {
            let Some(record) = records.iter().find(|record| record.0 == case.id) else {
                return p07_fail(
                    &root,
                    &mut results,
                    &case.id,
                    "validate P07_CASE results",
                    "案例記錄不存在".into(),
                );
            };
            let report = match p07_case_report(&root, case, profile, lua_profile, &record.3) {
                Ok(path) => path,
                Err(error) => {
                    return p07_fail(
                        &root,
                        &mut results,
                        &case.id,
                        "write P07 case report",
                        error,
                    );
                }
            };
            results.push(GateResult {
                name: format!("{}-{lua_profile}", case.id),
                command: p07_case_command(profile),
                exit_code: 0,
                status: "PASS",
                diagnostic: format!(
                    "profile={profile}; expected/input matched; actual={}",
                    record.3
                ),
                report_path: report.display().to_string(),
            });
        }
    }
    write_p07_results(&root, &results);
    println!(
        "PASS report={}",
        root.join("target/rivetlua-reports/gate-P07.json").display()
    );
    Ok(())
}

#[derive(Clone)]
struct P13FixtureCase {
    profile: String,
    id: String,
    mode: String,
    input: String,
    marker: String,
    expected: String,
    note: String,
}

#[derive(Clone)]
struct P13Record {
    id: String,
    profile: String,
    actual: String,
    diagnostic: String,
    capability_policy: String,
    fuel_trace: String,
    allocation_trace: String,
    resource_trace: String,
}

#[derive(Clone, Copy)]
struct P13CaseSpec {
    id: &'static str,
    mode: &'static str,
    test_name: &'static str,
    expected55: &'static str,
    expected54: &'static str,
}

const P13_CASE_SPECS: [P13CaseSpec; 14] = [
    P13CaseSpec {
        id: "LIB-001",
        mode: "bytes-utf8-length",
        test_name: "lib_case_001",
        expected55: "int:6,int:2",
        expected54: "int:6,int:2",
    },
    P13CaseSpec {
        id: "LIB-002",
        mode: "pack-nil",
        test_name: "lib_case_002",
        expected55: "int:3,int:3,int:1,nil,int:3",
        expected54: "int:3,int:3,int:1,nil,int:3",
    },
    P13CaseSpec {
        id: "LIB-003",
        mode: "lua-pattern-match",
        test_name: "lib_case_003",
        expected55: "bytes:313233",
        expected54: "bytes:313233",
    },
    P13CaseSpec {
        id: "LIB-004",
        mode: "require-nil-loader",
        test_name: "lib_case_004",
        expected55: "bool:true,bytes:3a7072656c6f61643a,bool:true,int:1",
        expected54: "bool:true,bytes:3a7072656c6f61643a,bool:true,int:1",
    },
    P13CaseSpec {
        id: "LIB-005",
        mode: "require-false-loader",
        test_name: "lib_case_005",
        expected55: "bool:false,bytes:7061796c6f6164,bool:false,bytes:7061796c6f6164,int:2,int:2,bool:false",
        expected54: "bool:false,bytes:7061796c6f6164,bool:false,bytes:7061796c6f6164,int:2,int:2,bool:false",
    },
    P13CaseSpec {
        id: "LIB-006",
        mode: "string-budget",
        test_name: "lib_case_006",
        expected55: "size:FuelExhausted,budget:Heap(AllocationFailed)",
        expected54: "size:StringArgument,budget:Heap(AllocationFailed)",
    },
    P13CaseSpec {
        id: "LIB-007",
        mode: "sort-abort",
        test_name: "lib_case_007",
        expected55: "inconsistent:bool:false,bytes:332c312c32,int:3;comparisons=2;swaps=0;stop=InconsistentComparator;partial:bool:false,bytes:312c332c32,int:3,int:3;comparisons=3;swaps=1;stop=LuaError",
        expected54: "inconsistent:bool:false,bytes:332c312c32,int:3;comparisons=2;swaps=0;stop=InconsistentComparator;partial:bool:false,bytes:312c332c32,int:3,int:3;comparisons=3;swaps=1;stop=LuaError",
    },
    P13CaseSpec {
        id: "LIB-008",
        mode: "load-policy",
        test_name: "lib_case_008",
        expected55: "HostPolicyLoad",
        expected54: "HostPolicyLoad",
    },
    P13CaseSpec {
        id: "LIB-009",
        mode: "lua-pattern-substitution",
        test_name: "lib_case_009",
        expected55: "bytes:28612862296329,int:2,int:3,bytes:6e616d65,bytes:616263,bytes:61786278,int:2,bytes:61326233,int:2,bytes:5859,int:2",
        expected54: "bytes:28612862296329,int:2,int:3,bytes:6e616d65,bytes:616263,bytes:61786278,int:2,bytes:61326233,int:2,bytes:5859,int:2",
    },
    P13CaseSpec {
        id: "LIB-010",
        mode: "utf8-invalid-profile",
        test_name: "lib_case_010",
        expected55: "bytes:ff,nil,int:1,bool:false,int:55296,bytes:eda080;offset:Utf8Sequence",
        expected54: "bytes:ff,nil,int:1,bool:false,int:55296,bytes:eda080;offset:int:1",
    },
    P13CaseSpec {
        id: "LIB-011",
        mode: "package-searchers",
        test_name: "lib_case_011",
        expected55: "lookup:bytes:6c656674,bytes:3a7072656c6f61643a,bytes:637573746f6d3a64617461,bytes:3a64617461,bool:false,bytes:6d6f64756c652027676f6e6527206e6f7420666f756e643a3237,bool:false,bool:true,bytes:6c656674,int:1;recursive:FuelExhausted;other-vm:bytes:7269676874,bytes:7269676874",
        expected54: "lookup:bytes:6c656674,bytes:3a7072656c6f61643a,bytes:637573746f6d3a64617461,bytes:3a64617461,bool:false,bytes:6d6f64756c652027676f6e6527206e6f7420666f756e643a3237,bool:false,bool:true,bytes:6c656674,int:1;recursive:FuelExhausted;other-vm:bytes:7269676874,bytes:7269676874",
    },
    P13CaseSpec {
        id: "LIB-012",
        mode: "host-policy",
        test_name: "lib_case_012",
        expected55: "io:HostPolicyIo;os:HostPolicyOs;debug:HostPolicyDebug;native:HostPolicyNative",
        expected54: "io:HostPolicyIo;os:HostPolicyOs;debug:HostPolicyDebug;native:HostPolicyNative",
    },
    P13CaseSpec {
        id: "LIB-013",
        mode: "vm-isolation",
        test_name: "lib_case_013",
        expected55: "left:nil,bytes:6c656674,bytes:6c656674,int:8291693048688576641,bytes:6c656674;right:nil,bytes:7269676874,bytes:7269676874,int:-8904508047278803908,bytes:7269676874;left-replay:int:8291693048688576641,bytes:6c656674,bytes:6c656674;right-replay:int:-8904508047278803908,bytes:7269676874,bytes:7269676874",
        expected54: "left:nil,bytes:6c656674,bytes:6c656674,int:8291693048688576641,bytes:6c656674;right:nil,bytes:7269676874,bytes:7269676874,int:-8904508047278803908,bytes:7269676874;left-replay:int:8291693048688576641,bytes:6c656674,bytes:6c656674;right-replay:int:-8904508047278803908,bytes:7269676874,bytes:7269676874",
    },
    P13CaseSpec {
        id: "LIB-014",
        mode: "resource-abort",
        test_name: "lib_case_014",
        expected55: "fuel:FuelExhausted;lua:Thrown:6d61726b6572;host:HostOutputFailed;sort:bool:false,bytes:312c332c32,int:3,int:3;comparisons=3;swaps=1;stop=LuaError;allocation:Heap(AllocationFailed);other:bytes:66756e6374696f6e,nil,int:42",
        expected54: "fuel:FuelExhausted;lua:Thrown:6d61726b6572;host:HostOutputFailed;sort:bool:false,bytes:312c332c32,int:3,int:3;comparisons=3;swaps=1;stop=LuaError;allocation:Heap(AllocationFailed);other:bytes:66756e6374696f6e,nil,int:42",
    },
];

fn p13_spec(id: &str) -> Option<&'static P13CaseSpec> {
    P13_CASE_SPECS.iter().find(|spec| spec.id == id)
}

fn p13_expected(spec: &P13CaseSpec, profile: &str) -> Result<&'static str, String> {
    match profile {
        "lua55-i64f64" => Ok(spec.expected55),
        "lua54-i64f64" => Ok(spec.expected54),
        _ => Err(format!("P13 完整 profile 不合法：{profile}")),
    }
}

fn parse_p13_fixture(contents: &str) -> Result<Vec<P13FixtureCase>, String> {
    let mut profiles = std::collections::HashMap::new();
    let mut cases = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (index, line) in contents.lines().enumerate() {
        let fields: Vec<_> = line.split('|').collect();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if !matches!(
                    (*profile, *lua_profile),
                    ("lua55-i64f64", "lua55") | ("lua54-i64f64", "lua54")
                ) || profiles.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P13 fixture 第 {} 行 profile 映射無效或重複",
                        index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, marker, expected, note] => {
                if [profile, id, mode, input, marker, expected, note]
                    .iter()
                    .any(|value| value.is_empty() || value.contains(['\t', '\r', '\n']))
                {
                    return Err(format!("P13 fixture 第 {} 行有空值或控制字元", index + 1));
                }
                let spec = p13_spec(id).ok_or_else(|| format!("P13 fixture 未知案例：{id}"))?;
                if !seen.insert((*profile, *id)) {
                    return Err(format!("P13 fixture 案例重複：{profile}/{id}"));
                }
                if *mode != spec.mode
                    || *input != spec.test_name
                    || *marker != format!("P13_CASE:{}", spec.id)
                    || *expected != p13_expected(spec, profile)?
                {
                    return Err(format!(
                        "P13 fixture {profile}/{id} 的 mode/test/marker/expected 與固定規格不符"
                    ));
                }
                cases.push(P13FixtureCase {
                    profile: (*profile).into(),
                    id: (*id).into(),
                    mode: (*mode).into(),
                    input: (*input).into(),
                    marker: (*marker).into(),
                    expected: (*expected).into(),
                    note: (*note).into(),
                });
            }
            _ => return Err(format!("P13 fixture 第 {} 行格式錯誤", index + 1)),
        }
    }
    if profiles.len() != 2
        || profiles.get("lua55-i64f64") != Some(&"lua55")
        || profiles.get("lua54-i64f64") != Some(&"lua54")
    {
        return Err("P13 fixture 必須有 lua55/lua54 正確完整 profile 映射".into());
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .collect();
        if selected.len() != 14
            || P13_CASE_SPECS
                .iter()
                .any(|spec| !selected.iter().any(|case| case.id == spec.id))
        {
            return Err(format!(
                "P13 fixture {profile} 必須含 LIB-001..014 唯一完整集合"
            ));
        }
    }
    Ok(cases)
}

fn validate_p13_csv_cases(csv: &str) -> Result<(), String> {
    validate_csv(csv)?;
    let rows: Vec<_> = csv
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("p13."))
        .collect();
    let ids = P13_CASE_SPECS
        .iter()
        .map(|spec| spec.id)
        .collect::<Vec<_>>()
        .join(";");
    if rows.len() != 2 {
        return Err(format!("P13 CSV 預期兩列，實際 {}", rows.len()));
    }
    for profile in ["lua55", "lua54"] {
        let matched: Vec<_> = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect();
        if matched.len() != 1 {
            return Err(format!("P13 CSV {profile} 必須恰有一列"));
        }
        let columns: Vec<_> = matched[0].split(',').collect();
        if columns.len() != 7
            || columns[0] != "p13.stdlib-modules"
            || columns[2] != "docs/plane/P13.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua-runtime/stdlib;HostServices"
            || columns[4] != ids
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("P13 CSV {profile} 欄位／案例集合與規格不符"));
        }
    }
    Ok(())
}

fn p13_records_from_output(profile: &str, output: &str) -> Result<Vec<P13Record>, String> {
    let mut records = Vec::new();
    for output_line in output.lines() {
        if let Some(position) = output_line.find("P13_CASE") {
            let line = &output_line[position..];
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 8 || fields[0] != "P13_CASE" || fields[2] != profile {
                return Err(format!("P13 marker 八欄格式或 profile 錯誤：{line}"));
            }
            let spec =
                p13_spec(fields[1]).ok_or_else(|| format!("P13 marker 未知 ID：{}", fields[1]))?;
            let payload = fields[3]
                .strip_prefix("status=PASS;actual=")
                .ok_or_else(|| format!("P13 {} marker 缺 PASS/actual", spec.id))?;
            let (actual, diagnostic) = payload
                .rsplit_once(";diagnostic=")
                .ok_or_else(|| format!("P13 {} marker 缺 diagnostic", spec.id))?;
            if actual.is_empty() || actual.contains('|') || diagnostic.is_empty() {
                return Err(format!("P13 {} marker actual/diagnostic 無效", spec.id));
            }
            let trace = |field: &str, prefix: &str| -> Result<String, String> {
                field
                    .strip_prefix(prefix)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("P13 {} marker {prefix} 缺值", spec.id))
            };
            if actual != p13_expected(spec, profile)? {
                return Err(format!("P13 {profile}/{} 實際結果不符固定預期", spec.id));
            }
            records.push(P13Record {
                id: spec.id.into(),
                profile: profile.into(),
                actual: actual.into(),
                diagnostic: diagnostic.into(),
                capability_policy: trace(fields[4], "capability=")?,
                fuel_trace: trace(fields[5], "fuel=")?,
                allocation_trace: trace(fields[6], "allocation=")?,
                resource_trace: trace(fields[7], "resource=")?,
            });
        }
    }
    if records.len() != 1 {
        return Err(format!(
            "P13 exact child marker 數錯誤：預期 1，實際 {}",
            records.len()
        ));
    }
    Ok(records)
}

fn p13_check_case_summary(output: &str) -> Result<(), String> {
    let lines: Vec<_> = output
        .lines()
        .filter(|line| line.contains("test result:"))
        .collect();
    if lines.len() != 1 {
        return Err(format!(
            "P13 exact case 摘要數錯誤：預期 1，實際 {}",
            lines.len()
        ));
    }
    let summary = lines[0]
        .split_once("test result: ok. ")
        .map(|(_, text)| text)
        .ok_or("P13 exact case 摘要不是成功結果")?;
    let fields: Vec<_> = summary.split(';').map(str::trim).collect();
    if fields.get(0) == Some(&"1 passed")
        && fields.get(1) == Some(&"0 failed")
        && fields.get(2) == Some(&"0 ignored")
    {
        Ok(())
    } else {
        Err(format!(
            "P13 exact case 必須 1 passed/0 failed/0 ignored：{}",
            lines[0]
        ))
    }
}

fn p13_result(
    name: impl Into<String>,
    command: impl Into<String>,
    exit_code: i32,
    status: &'static str,
    diagnostic: impl Into<String>,
    report_path: impl Into<String>,
) -> GateResult {
    GateResult {
        name: name.into(),
        command: command.into(),
        exit_code,
        status,
        diagnostic: diagnostic.into(),
        report_path: report_path.into(),
    }
}

fn p13_report_dir(root: &Path) -> PathBuf {
    root.join("target/rivetlua-reports")
}

fn p13_clear_case_reports(root: &Path) -> Result<(), String> {
    let directory = p13_report_dir(root);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("讀取 P13 報告目錄失敗：{error}")),
    };
    let mut failure = None;
    for entry in entries {
        let entry = entry.map_err(|error| format!("讀取 P13 報告項目失敗：{error}"))?;
        if entry.file_name().to_string_lossy().starts_with("P13-") {
            let path = entry.path();
            if !path.is_file() {
                failure.get_or_insert_with(|| {
                    format!("P13 案例路徑不是一般檔案，不刪除：{}", path.display())
                });
                continue;
            }
            if let Err(error) = fs::remove_file(&path) {
                failure.get_or_insert_with(|| {
                    format!("清除舊 P13 案例報告失敗 {}：{error}", path.display())
                });
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn p13_aggregate_json(
    digest: &str,
    results: &[GateResult],
    status: &str,
    diagnostic: &str,
) -> String {
    let checks = results.iter().map(|item| format!(
        "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
        json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status,
        json_escape(&item.diagnostic), json_escape(&item.report_path),
    )).collect::<Vec<_>>().join(",");
    let cases = if status == "PASS" {
        results
            .iter()
            .filter(|item| item.name.starts_with("LIB-"))
            .map(|item| {
                let (id, profile) = item.name.rsplit_once('-').expect("validated case check");
                format!(
                    "{{\"case_id\":\"{}\",\"lua_profile\":\"{}\",\"report_path\":\"{}\"}}",
                    json_escape(id),
                    json_escape(profile),
                    json_escape(&item.report_path)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    } else {
        String::new()
    };
    format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{}\",\"diagnostic\":\"{}\",\"checks\":[{checks}],\"case_reports\":[{cases}]}}\n",
        json_escape(digest),
        json_escape(diagnostic)
    )
}

fn p13_write_aggregate(
    digest: &str,
    results: &[GateResult],
    status: &str,
    diagnostic: &str,
    path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("P13 aggregate 路徑無 parent")?)
        .map_err(|error| format!("建立 P13 aggregate 目錄失敗：{error}"))?;
    let json = p13_aggregate_json(digest, results, status, diagnostic);
    fs::write(path, json)
        .map_err(|error| format!("寫入 P13 aggregate {} 失敗：{error}", path.display()))?;
    let parsed =
        StrictJsonParser::parse(&fs::read_to_string(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("P13 aggregate 不是合法 JSON：{error}"))?;
    if parsed.get("status").and_then(StrictJsonValue::as_str) != Some(status)
        || parsed
            .get("source_digest")
            .and_then(StrictJsonValue::as_str)
            != Some(digest)
    {
        return Err("P13 aggregate 寫後核對失敗".into());
    }
    Ok(())
}

fn p13_fail(
    root: &Path,
    digest: &str,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    exit_code: i32,
    error: String,
) -> String {
    let mut diagnostic = error;
    if let Err(clear_error) = p13_clear_case_reports(root) {
        diagnostic.push_str(&format!("；清除 P13 案例報告失敗：{clear_error}"));
    }
    let canonical = p13_report_dir(root).join("gate-P13.json");
    if canonical.is_file() {
        if let Err(error) = fs::remove_file(&canonical) {
            diagnostic.push_str(&format!("；清除舊 P13 aggregate 失敗：{error}"));
        }
    }
    results.push(p13_result(
        name,
        command,
        exit_code.max(1),
        "FAIL",
        &diagnostic,
        "target/rivetlua-reports/gate-P13.json",
    ));
    if let Err(canonical_error) =
        p13_write_aggregate(digest, results, "FAIL", &diagnostic, &canonical)
    {
        let fallback = root.join("target/gate-P13-fail.json");
        diagnostic.push_str(&format!(
            "；canonical aggregate 寫入失敗：{canonical_error}"
        ));
        if let Some(last) = results.last_mut() {
            last.diagnostic = diagnostic.clone();
            last.report_path = "target/gate-P13-fail.json".into();
        }
        if let Err(fallback_error) =
            p13_write_aggregate(digest, results, "FAIL", &diagnostic, &fallback)
        {
            diagnostic.push_str(&format!(
                "；fallback FAIL aggregate 寫入失敗：{fallback_error}"
            ));
        }
    }
    diagnostic
}

fn p13_check_names(
    checks: &[StrictJsonValue],
    names: &[String],
    phase: &str,
) -> Result<(), String> {
    for name in names {
        if checks
            .iter()
            .filter(|check| check.get("name").and_then(StrictJsonValue::as_str) == Some(name))
            .count()
            != 1
        {
            return Err(format!("{phase} 前置檢查 {name} 缺少或重複"));
        }
    }
    Ok(())
}

const P13_EXPECTED_P00_FAILURES: [(&str, &str, &str); 6] = [
    (
        "P00-SUP-001",
        "rivetlua-xtask runner --profile lua55 --case P00-SUP-001",
        "target/rivetlua-reports/P00-SUP-001-lua55.json",
    ),
    (
        "P00-REF-003",
        "rivetlua-xtask runner --profile lua55 --case P00-REF-003",
        "target/rivetlua-reports/P00-REF-003-lua55.json",
    ),
    (
        "P00-RUN-003",
        "rivetlua-xtask runner --profile lua55 --case P00-RUN-003",
        "target/rivetlua-reports/P00-RUN-003-lua55.json",
    ),
    (
        "P00-RUN-004",
        "rivetlua-xtask runner --profile lua55 --case P00-RUN-004",
        "target/rivetlua-reports/P00-RUN-004-lua55.json",
    ),
    (
        "P00-ABI-004",
        "abi_evidence_check tests/abi/fixtures/incomplete-evidence.json",
        "tests/abi/fixtures/incomplete-evidence.json",
    ),
    (
        "P00-ABI-005",
        "abi_evidence_check tests/abi/fixtures/unsafe-accepted.md",
        "tests/abi/fixtures/unsafe-accepted.md",
    ),
];

fn p13_validate_prior_check(phase: &str, check: &StrictJsonValue) -> Result<String, String> {
    let name = check
        .get("name")
        .and_then(StrictJsonValue::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{phase} 前置 check 缺名稱"))?;
    let command = check
        .get("command")
        .and_then(StrictJsonValue::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{phase} 前置 check {name} 缺 command"))?;
    let path = check
        .get("report_path")
        .and_then(StrictJsonValue::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{phase} 前置 check {name} 缺 report_path"))?;
    if !check
        .get("diagnostic")
        .and_then(StrictJsonValue::as_str)
        .is_some_and(|text| !text.trim().is_empty())
    {
        return Err(format!("{phase} 前置 check {name} 缺 diagnostic"));
    }
    if check.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
        return Err(format!("{phase} 前置 check {name} 非 PASS"));
    }
    let exit_code = check
        .get("exit_code")
        .and_then(StrictJsonValue::as_i32)
        .ok_or_else(|| format!("{phase} 前置 check {name} 缺整數 exit_code"))?;
    let original_name = if phase == "P11" {
        name.strip_prefix("P00-")
    } else if phase == "P00" {
        Some(name)
    } else {
        None
    };
    if let Some((_, expected_command, expected_path)) = P13_EXPECTED_P00_FAILURES
        .iter()
        .find(|(id, _, _)| original_name == Some(*id))
    {
        if exit_code != 1 || command != *expected_command || path != *expected_path {
            return Err(format!(
                "{phase} 預期拒絕 check {name} exit/command/path 不符"
            ));
        }
    } else if exit_code != 0 {
        return Err(format!("{phase} 前置 check {name} 非 exit0"));
    }
    Ok(name.to_owned())
}

fn p13_prior_identity(root: &Path, phase: &str, check: &StrictJsonValue) -> Result<String, String> {
    let name = p13_validate_prior_check(phase, check)?;
    let id = match phase {
        "P03" if P03_CASES.contains(&name.as_str()) => Some(name.as_str()),
        "P11" => name
            .strip_prefix("P03-")
            .filter(|id| P03_CASES.contains(id)),
        _ => None,
    };
    if let Some(id) = id {
        if check.get("command").and_then(StrictJsonValue::as_str)
            != Some("cargo test p03_contracts")
        {
            return Err(format!("{phase} P03 formal check {name} command 不符"));
        }
        let path = check
            .get("report_path")
            .and_then(StrictJsonValue::as_str)
            .expect("前置 check 已驗證非空 path");
        for profile in ["lua55", "lua54"] {
            let expected = root
                .join(format!("target/rivetlua-reports/P03-{id}-{profile}.json"))
                .display()
                .to_string();
            if path == expected {
                return Ok(format!("{name}@{profile}"));
            }
        }
        return Err(format!(
            "{phase} P03 formal check {name} report_path/profile 不符"
        ));
    }
    if (phase == "P03" && name.starts_with("PARSE-"))
        || (phase == "P11" && name.starts_with("P03-PARSE-"))
    {
        return Err(format!("{phase} 未知 P03 formal check：{name}"));
    }
    Ok(name)
}

fn p13_validate_prior_reports(root: &Path, digest: &str) -> Result<Vec<GateResult>, String> {
    let mut results = Vec::new();
    for number in 0..=12 {
        let phase = format!("P{number:02}");
        let path = p13_report_dir(root).join(format!("gate-{phase}.json"));
        let report = fs::read_to_string(&path)
            .map_err(|error| format!("缺少 {phase} 前置 gate 報告：{error}"))?;
        let parsed = StrictJsonParser::parse(&report)
            .map_err(|error| format!("{phase} 前置 gate JSON 無效：{error}"))?;
        if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
            return Err(format!("{phase} 前置 gate 不是 PASS"));
        }
        validate_report_source_digest(&phase, &parsed, digest)?;
        let checks = parsed
            .get("checks")
            .and_then(StrictJsonValue::as_array)
            .filter(|checks| !checks.is_empty())
            .ok_or_else(|| format!("{phase} 前置 checks 缺少或為空"))?;
        let mut seen = std::collections::HashSet::new();
        for check in checks {
            let name = p13_prior_identity(root, &phase, check)?;
            if !seen.insert(name.clone()) {
                return Err(format!("{phase} 前置 check 重複：{name}"));
            }
        }
        if phase == "P03" || phase == "P11" {
            for id in P03_CASES {
                let name = if phase == "P11" {
                    format!("P03-{id}")
                } else {
                    id.to_owned()
                };
                for profile in ["lua55", "lua54"] {
                    let identity = format!("{name}@{profile}");
                    if !seen.contains(&identity) {
                        return Err(format!("{phase} 前置 P03 formal check 缺少：{identity}"));
                    }
                }
            }
        }
        if phase == "P00" || phase == "P11" {
            let names = P13_EXPECTED_P00_FAILURES
                .iter()
                .map(|(id, _, _)| {
                    if phase == "P11" {
                        format!("P00-{id}")
                    } else {
                        (*id).to_owned()
                    }
                })
                .collect::<Vec<_>>();
            p13_check_names(checks, &names, &phase)?;
        }
        if phase == "P05" {
            let mut required = [
                "p05-dependency-graph",
                "p05-core-bytecode",
                "p05-bytecode-contracts",
            ]
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
            for case in 1..=10 {
                for profile in ["lua55", "lua54"] {
                    required.push(format!("BC-{case:03}-{profile}"));
                }
            }
            p13_check_names(checks, &required, &phase)?;
        }
        if phase == "P07" {
            p13_check_names(
                checks,
                &["p01-before", "p05-before", "p06-before", "p00-p06-before"].map(str::to_owned),
                &phase,
            )?;
        }
        if phase == "P12" {
            let mut required = vec!["p12-runtime-unit".into(), "p12-reentry-unit".into()];
            for filter in [
                "gc",
                "weak",
                "ephemeron",
                "finalizer",
                "allocation_failure",
                "vm_lifecycle",
            ] {
                required.push(format!("p12-filter-{filter}"));
            }
            for spec in P12_CASE_SPECS {
                for profile in ["lua55", "lua54"] {
                    required.push(format!("{}-{profile}", spec.id));
                }
            }
            p13_check_names(checks, &required, &phase)?;
            for spec in P12_CASE_SPECS {
                for (fullprofile, lua_profile) in
                    [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")]
                {
                    let case_path =
                        p13_report_dir(root).join(format!("P12-{}-{lua_profile}.json", spec.id));
                    let case_text = fs::read_to_string(&case_path).map_err(|error| {
                        format!("P12 前置案例 {} 缺少：{error}", case_path.display())
                    })?;
                    let case = StrictJsonParser::parse(&case_text)
                        .map_err(|error| format!("P12 前置案例 JSON 無效：{error}"))?;
                    if case.get("case_id").and_then(StrictJsonValue::as_str) != Some(spec.id)
                        || case.get("profile").and_then(StrictJsonValue::as_str)
                            != Some(fullprofile)
                        || case.get("lua_profile").and_then(StrictJsonValue::as_str)
                            != Some(lua_profile)
                        || case.get("actual").and_then(StrictJsonValue::as_str)
                            != Some(spec.expected)
                        || case.get("status").and_then(StrictJsonValue::as_str) != Some("PASS")
                        || case.get("exit_code").and_then(StrictJsonValue::as_i32) != Some(0)
                    {
                        return Err(format!("P12 前置案例 {} 證據不完整", case_path.display()));
                    }
                    validate_report_source_digest("P12", &case, digest)?;
                }
            }
        }
        results.push(p13_result(
            format!("{phase}-aggregate"),
            format!("validate {}", path.display()),
            0,
            "PASS",
            format!(
                "{phase} fresh PASS/digest 與 {} 個符合既有 exit 契約的 checks",
                checks.len()
            ),
            "target/rivetlua-reports/gate-P13.json",
        ));
    }
    let dependency = fs::read_to_string(root.join("spec/phase-dependencies.csv"))
        .map_err(|error| format!("讀取 phase dependencies 失敗：{error}"))?;
    validate_phase_dependency_graph(&dependency)?;
    for row in [
        "DA-09,P05,P09,prototype parameter_count is_variadic named_vararg,IMPLEMENTED,P05",
        "DA-14,P04,P05,GenericForClose binding closing register ClosePath,IMPLEMENTED,P05",
        "DA-18,P05,P20,InstructionEffects canonical RVLU_V2 flags,IMPLEMENTED,P05",
        "DA-19,P12,P13,runtime root fuel table frame effect contracts,CONTRACTED,P13",
        "DA-20,P05,P14,RVLU_V2 language payload VerifiedModule,CONTRACTED,P14",
    ] {
        if !dependency.lines().any(|line| line == row) {
            return Err(format!("P13 dependency 契約列不符：{row}"));
        }
    }
    results.push(p13_result("p13-dependencies", "validate spec/phase-dependencies.csv DA-09/14/18/19/20", 0, "PASS",
        "DA-09/14/18 IMPLEMENTED；P05 RVLU_V2/VerifiedModule；P12 roots/fuel/GC/accounting 前置保留；DA-19 由 P13 產生，DA-20 約束 VerifiedModule 消費", "target/rivetlua-reports/gate-P13.json"));
    Ok(results)
}

fn p13_capture(
    root: &Path,
    profile: Option<&str>,
    arguments: &[&str],
) -> Result<(bool, i32, String), String> {
    let mut command = Command::new("cargo");
    command.args(arguments).current_dir(root);
    if let Some(profile) = profile {
        command.env("RIVETLUA_P13_PROFILE", profile);
    }
    let output = command
        .output()
        .map_err(|error| format!("啟動 P13 子命令失敗：{error}"))?;
    Ok((
        output.status.success(),
        output.status.code().unwrap_or(1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

fn p13_case_command(profile: &str, input: &str) -> String {
    format!(
        "RIVETLUA_P13_PROFILE={profile} cargo test --locked -p rivetlua-runtime --test p13_contracts {input} -- --nocapture --exact --test-threads=1"
    )
}

fn p13_case_json(
    case: &P13FixtureCase,
    record: &P13Record,
    lua_profile: &str,
    digest: &str,
    command: &str,
    path: &str,
) -> String {
    format!(
        "{{\"case_id\":\"{}\",\"lua_profile\":\"{}\",\"profile\":\"{}\",\"fullprofile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"exit_code\":0,\"command\":\"{}\",\"report_path\":\"{}\",\"diagnostic\":\"{}\",\"capability_policy\":\"{}\",\"fuel_trace\":\"{}\",\"allocation_trace\":\"{}\",\"resource_trace\":\"{}\",\"source_digest\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(lua_profile),
        json_escape(&case.profile),
        json_escape(&case.profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(&record.actual),
        json_escape(command),
        json_escape(path),
        json_escape(&format!("{}；{}", case.note, record.diagnostic)),
        json_escape(&record.capability_policy),
        json_escape(&record.fuel_trace),
        json_escape(&record.allocation_trace),
        json_escape(&record.resource_trace),
        json_escape(digest)
    )
}

fn p13_validate_case_report(
    path: &Path,
    case: &P13FixtureCase,
    lua_profile: &str,
    digest: &str,
) -> Result<(), String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("讀取 P13 case report 失敗：{error}"))?;
    let parsed = StrictJsonParser::parse(&text)
        .map_err(|error| format!("P13 case report JSON 無效：{error}"))?;
    for (key, expected) in [
        ("case_id", case.id.as_str()),
        ("lua_profile", lua_profile),
        ("profile", case.profile.as_str()),
        ("fullprofile", case.profile.as_str()),
        ("mode", case.mode.as_str()),
        ("input", case.input.as_str()),
        ("expected", case.expected.as_str()),
        ("actual", case.expected.as_str()),
        ("status", "PASS"),
        ("source_digest", digest),
    ] {
        if parsed.get(key).and_then(StrictJsonValue::as_str) != Some(expected) {
            return Err(format!(
                "P13 case report {} 欄位 {key} 不符",
                path.display()
            ));
        }
    }
    if parsed.get("exit_code").and_then(StrictJsonValue::as_i32) != Some(0) {
        return Err(format!("P13 case report {} exit_code 非零", path.display()));
    }
    for key in [
        "command",
        "report_path",
        "diagnostic",
        "capability_policy",
        "fuel_trace",
        "allocation_trace",
        "resource_trace",
    ] {
        if !parsed
            .get(key)
            .and_then(StrictJsonValue::as_str)
            .is_some_and(|text| !text.is_empty())
        {
            return Err(format!("P13 case report {} 缺 {key}", path.display()));
        }
    }
    Ok(())
}

fn p13_validate_all_case_reports(
    root: &Path,
    cases: &[P13FixtureCase],
    digest: &str,
) -> Result<(), String> {
    let directory = p13_report_dir(root);
    let paths: Vec<_> = fs::read_dir(&directory)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("P13-"))
        })
        .collect();
    if paths.len() != 28 || cases.len() != 28 {
        return Err(format!(
            "P13 唯一 case report 數錯誤：預期 28，實際 {}",
            paths.len()
        ));
    }
    for case in cases {
        let lua_profile = if case.profile == "lua55-i64f64" {
            "lua55"
        } else {
            "lua54"
        };
        let path = directory.join(format!("P13-{}-{lua_profile}.json", case.id));
        if !paths.contains(&path) {
            return Err(format!("P13 case report 缺少 {}", path.display()));
        }
        p13_validate_case_report(&path, case, lua_profile, digest)?;
    }
    Ok(())
}

fn p13_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let digest = match source_digest(&root) {
        Ok(digest) => digest,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &"0".repeat(64),
                &mut results,
                "p13-source-digest",
                "compute source digest",
                1,
                format!("無法計算 P13 來源 digest：{error}"),
            ));
        }
    };
    if let Err(error) = p13_clear_case_reports(&root) {
        return Err(p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-clear-cases",
            "clear old P13 case reports",
            1,
            error,
        ));
    }
    for relative in [
        "target/rivetlua-reports/gate-P13.json",
        "target/gate-P13-fail.json",
    ] {
        let path = root.join(relative);
        if path.exists() {
            if !path.is_file() {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    "p13-clear-aggregate",
                    relative,
                    1,
                    format!("舊 P13 aggregate 不是一般檔案，不刪除：{}", path.display()),
                ));
            }
            if let Err(error) = fs::remove_file(&path) {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    "p13-clear-aggregate",
                    relative,
                    1,
                    format!("清除舊 P13 aggregate 失敗：{error}"),
                ));
            }
        }
    }
    match p13_validate_prior_reports(&root, &digest) {
        Ok(prior) => results.extend(prior),
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p00-p12-before",
                "validate fresh P00-P12 PASS/digest and dependencies",
                1,
                error,
            ));
        }
    }
    let csv = match fs::read_to_string(root.join("spec/compatibility.csv")) {
        Ok(csv) => csv,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-csv",
                "read spec/compatibility.csv",
                1,
                error.to_string(),
            ));
        }
    };
    if let Err(error) = validate_p13_csv_cases(&csv) {
        return Err(p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-csv",
            "validate P13 compatibility rows",
            1,
            error,
        ));
    }
    results.push(p13_result(
        "p13-csv",
        "validate spec/compatibility.csv",
        0,
        "PASS",
        "lua55/lua54 各有 LIB-001..014 exact set",
        "target/rivetlua-reports/gate-P13.json",
    ));
    let fixture_text = match fs::read_to_string(root.join("tests/p13/lib-cases.fixture")) {
        Ok(text) => text,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-fixture",
                "read tests/p13/lib-cases.fixture",
                1,
                error.to_string(),
            ));
        }
    };
    let cases = match parse_p13_fixture(&fixture_text) {
        Ok(cases) => cases,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-fixture",
                "validate P13 fixture",
                1,
                error,
            ));
        }
    };
    results.push(p13_result(
        "p13-fixture",
        "validate tests/p13/lib-cases.fixture",
        0,
        "PASS",
        "28 unique ID/profile、固定 mode/test/marker/expected",
        "target/rivetlua-reports/gate-P13.json",
    ));
    let unit_command = "cargo test --locked -p rivetlua-runtime --lib p13_ -- --test-threads=1";
    let (success, exit_code, output) = match p13_capture(
        &root,
        None,
        &[
            "test",
            "--locked",
            "-p",
            "rivetlua-runtime",
            "--lib",
            "p13_",
            "--",
            "--test-threads=1",
        ],
    ) {
        Ok(output) => output,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-runtime-unit",
                unit_command,
                1,
                error,
            ));
        }
    };
    if !success {
        return Err(p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-runtime-unit",
            unit_command,
            exit_code,
            format!("實際 exit={exit_code}；{output}"),
        ));
    }
    let unit_count = match p12_check_unit_summary(&output) {
        Ok(count) => count,
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-runtime-unit",
                unit_command,
                1,
                format!("{error}；{output}"),
            ));
        }
    };
    results.push(p13_result(
        "p13-runtime-unit",
        unit_command,
        0,
        "PASS",
        format!("P13 runtime unit {unit_count} 個非零匹配且全數通過"),
        "target/rivetlua-reports/gate-P13.json",
    ));
    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        for case in cases.iter().filter(|case| case.profile == profile) {
            let check_name = format!("{}-{lua_profile}", case.id);
            let command = p13_case_command(profile, &case.input);
            let (success, exit_code, output) = match p13_capture(
                &root,
                Some(profile),
                &[
                    "test",
                    "--locked",
                    "-p",
                    "rivetlua-runtime",
                    "--test",
                    "p13_contracts",
                    &case.input,
                    "--",
                    "--nocapture",
                    "--exact",
                    "--test-threads=1",
                ],
            ) {
                Ok(output) => output,
                Err(error) => {
                    return Err(p13_fail(
                        &root,
                        &digest,
                        &mut results,
                        &check_name,
                        &command,
                        1,
                        error,
                    ));
                }
            };
            if !success {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    &check_name,
                    &command,
                    exit_code,
                    format!("實際 exit={exit_code}；P13 exact child 失敗：{output}"),
                ));
            }
            if let Err(error) = p13_check_case_summary(&output) {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    &check_name,
                    &command,
                    1,
                    format!("{error}；{output}"),
                ));
            }
            let records = match p13_records_from_output(profile, &output) {
                Ok(records) => records,
                Err(error) => {
                    return Err(p13_fail(
                        &root,
                        &digest,
                        &mut results,
                        &check_name,
                        &command,
                        1,
                        error,
                    ));
                }
            };
            let record = &records[0];
            if record.id != case.id
                || record.profile != case.profile
                || case.marker != format!("P13_CASE:{}", record.id)
                || record.actual != case.expected
            {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    &check_name,
                    &command,
                    1,
                    "P13 marker 與 fixture 對照失敗".into(),
                ));
            }
            let relative = format!("target/rivetlua-reports/P13-{}-{lua_profile}.json", case.id);
            let path = root.join(&relative);
            let json = p13_case_json(case, record, lua_profile, &digest, &command, &relative);
            if let Err(error) = fs::write(&path, json) {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    &check_name,
                    "write P13 case report",
                    1,
                    format!("寫入 P13 case report 失敗：{error}"),
                ));
            }
            if let Err(error) = p13_validate_case_report(&path, case, lua_profile, &digest) {
                return Err(p13_fail(
                    &root,
                    &digest,
                    &mut results,
                    &check_name,
                    "validate P13 case report",
                    1,
                    error,
                ));
            }
            results.push(p13_result(
                check_name,
                command,
                0,
                "PASS",
                format!(
                    "{}；marker/summary/fixed expected/trace/schema 已核對",
                    case.note
                ),
                relative,
            ));
        }
    }
    if let Err(error) = p13_validate_all_case_reports(&root, &cases, &digest) {
        return Err(p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-case-reports",
            "validate 28 unique P13 case JSON",
            1,
            error,
        ));
    }
    results.push(p13_result(
        "p13-case-reports",
        "validate 28 unique P13 case JSON",
        0,
        "PASS",
        "兩 profile 各 14 份唯一 PASS/digest/schema",
        "target/rivetlua-reports/gate-P13.json",
    ));
    match source_digest(&root) {
        Ok(current) if current == digest => {}
        Ok(_) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-source-digest",
                "verify source digest after children",
                1,
                "P13 執行期間 source digest 已變更".into(),
            ));
        }
        Err(error) => {
            return Err(p13_fail(
                &root,
                &digest,
                &mut results,
                "p13-source-digest",
                "verify source digest after children",
                1,
                error,
            ));
        }
    }
    results.push(p13_result(
        "p13-source-digest",
        "verify source digest after children",
        0,
        "PASS",
        "來源在 28 次 child 與報告寫入後未改變",
        "target/rivetlua-reports/gate-P13.json",
    ));
    let gate_report = p13_report_dir(&root).join("gate-P13.json");
    if let Err(error) = p13_write_aggregate(
        &digest,
        &results,
        "PASS",
        "28 unique formal cases and all prerequisites verified",
        &gate_report,
    ) {
        return Err(p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-aggregate-write",
            "write gate-P13.json",
            1,
            error,
        ));
    }
    println!("PASS report={}", gate_report.display());
    Ok(())
}

#[derive(Clone, Copy)]
struct P14CaseSpec {
    id: &'static str,
    mode: &'static str,
    input: &'static str,
    expected: &'static str,
    package: &'static str,
}

const P14_CASE_SPECS: [P14CaseSpec; 14] = [
    P14CaseSpec {
        id: "SDK-001",
        mode: "roundtrip",
        input: "sdk_case_001",
        expected: "int:42",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-002",
        mode: "outer-admission",
        input: "sdk_case_002",
        expected: "length+crc:preallocation",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-003",
        mode: "p05-rejection",
        input: "sdk_case_003",
        expected: "version+numeric+profile:payload",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-004",
        mode: "vm-isolation",
        input: "sdk_case_004",
        expected: "vm:isolated",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-005",
        mode: "public-api",
        input: "sdk_case_005",
        expected: "public-api:root+callback+resume",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-006",
        mode: "cli-errors",
        input: "cli_case_006",
        expected: "lua+codec:nonzero",
        package: "rivetlua-cli",
    },
    P14CaseSpec {
        id: "SDK-007",
        mode: "cli-install",
        input: "cli_case_007",
        expected: "install:rivet-only",
        package: "rivetlua-cli",
    },
    P14CaseSpec {
        id: "SDK-008",
        mode: "decode-errors",
        input: "sdk_case_008",
        expected: "overflow+section-boundary+opcode+injection:retry",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-NEG-001",
        mode: "no-second-parser",
        input: "sdk_case_neg_001",
        expected: "payload:delegated",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-NEG-002",
        mode: "no-unchecked-module",
        input: "sdk_case_neg_002",
        expected: "private-module:compile-rejected",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-NEG-003",
        mode: "no-runtime-snapshot",
        input: "sdk_case_neg_003",
        expected: "runtime:absent-after-restart",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-NEG-004",
        mode: "no-shared-execution",
        input: "sdk_case_neg_004",
        expected: "cross-vm:rejected",
        package: "rivetlua",
    },
    P14CaseSpec {
        id: "SDK-NEG-005",
        mode: "no-system-lua",
        input: "cli_case_neg_005",
        expected: "decoy:untouched",
        package: "rivetlua-cli",
    },
    P14CaseSpec {
        id: "SDK-NEG-006",
        mode: "no-false-success",
        input: "cli_case_neg_006",
        expected: "failure:nonzero",
        package: "rivetlua-cli",
    },
];

#[derive(Clone)]
struct P14FixtureCase {
    profile: String,
    lua_profile: String,
    id: String,
    mode: String,
    input: String,
    marker: String,
    expected: String,
    note: String,
}

#[derive(Clone, Debug)]
struct P14Record {
    id: String,
    profile: String,
    actual: String,
    diagnostic: String,
    allocation: String,
    resource: String,
    vm: String,
    cli: String,
}

fn p14_spec(id: &str) -> Option<&'static P14CaseSpec> {
    P14_CASE_SPECS.iter().find(|spec| spec.id == id)
}

fn p14_lua_profile(profile: &str) -> Result<&'static str, String> {
    match profile {
        "lua55-i64f64" => Ok("lua55"),
        "lua54-i64f64" => Ok("lua54"),
        _ => Err(format!("P14 完整 profile 不合法：{profile}")),
    }
}

fn parse_p14_fixture(contents: &str) -> Result<Vec<P14FixtureCase>, String> {
    let mut mappings = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut cases = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let fields = line.split('|').collect::<Vec<_>>();
        match fields.as_slice() {
            ["profile", profile, lua_profile] => {
                if p14_lua_profile(profile)? != *lua_profile
                    || mappings.insert(*profile, *lua_profile).is_some()
                {
                    return Err(format!(
                        "P14 fixture 第 {} 行 profile 映射錯誤或重複",
                        index + 1
                    ));
                }
            }
            ["case", profile, id, mode, input, marker, expected, note] => {
                if [profile, id, mode, input, marker, expected, note]
                    .iter()
                    .any(|field| field.is_empty() || field.contains(['\t', '\r', '\n']))
                {
                    return Err(format!("P14 fixture 第 {} 行有空值或控制字元", index + 1));
                }
                let lua_profile = p14_lua_profile(profile)?;
                let spec = p14_spec(id).ok_or_else(|| format!("P14 fixture 未知案例：{id}"))?;
                if *mode != spec.mode
                    || *input != spec.input
                    || *expected != spec.expected
                    || *marker != format!("P14_CASE:{id}")
                    || !seen.insert((*profile, *id))
                {
                    return Err(format!("P14 fixture {profile}/{id} 固定契約錯誤或重複"));
                }
                cases.push(P14FixtureCase {
                    profile: (*profile).into(),
                    lua_profile: lua_profile.into(),
                    id: (*id).into(),
                    mode: (*mode).into(),
                    input: (*input).into(),
                    marker: (*marker).into(),
                    expected: (*expected).into(),
                    note: (*note).into(),
                });
            }
            _ => return Err(format!("P14 fixture 第 {} 行格式錯誤", index + 1)),
        }
    }
    if mappings.len() != 2
        || mappings.get("lua55-i64f64") != Some(&"lua55")
        || mappings.get("lua54-i64f64") != Some(&"lua54")
        || cases.len() != 28
    {
        return Err("P14 fixture 必須有兩個 profile、各 14 個唯一案例".into());
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        if P14_CASE_SPECS
            .iter()
            .any(|spec| !seen.contains(&(profile, spec.id)))
        {
            return Err(format!("P14 fixture {profile} 缺少固定案例"));
        }
    }
    Ok(cases)
}

fn p14_validate_csv_cases(csv: &str) -> Result<(), String> {
    validate_csv(csv)?;
    let p05_rows = csv
        .lines()
        .skip(1)
        .filter(|line| {
            line.starts_with("p05.official-chunk,") || line.starts_with("p05.artifact-metadata,")
        })
        .collect::<Vec<_>>();
    if p05_rows.len() != 4 {
        return Err(format!(
            "P14 CSV P05 官方／artifact 應恰有四列，實際 {}",
            p05_rows.len()
        ));
    }
    for profile in ["lua55", "lua54"] {
        let official_ids = (1..=18)
            .filter(|id| match (profile, id) {
                ("lua55", 1 | 3) | ("lua54", 2 | 4) => false,
                _ => true,
            })
            .map(|id| format!("OFFCHUNK-{id:03}"))
            .collect::<Vec<_>>()
            .join(";");
        let artifact_ids = [7, 8, 17, 18]
            .map(|id| format!("OFFCHUNK-{id:03}"))
            .join(";");
        for (feature, modules, ids) in [
            (
                "p05.official-chunk",
                "rivetlua-core;rivetlua-compiler;rivetlua-runtime",
                official_ids,
            ),
            (
                "p05.artifact-metadata",
                "rivetlua-core;rivetlua-runtime",
                artifact_ids,
            ),
        ] {
            let row = format!("{feature},{profile},docs/plane/WorkP14.md,{modules},{ids},PASS,");
            if !p05_rows.iter().any(|actual| *actual == row.as_str()) {
                return Err(format!("P14 CSV {feature}/{profile} OFFCHUNK 映射不符"));
            }
        }
    }
    let rows = csv
        .lines()
        .skip(1)
        .filter(|line| line.starts_with("p14."))
        .collect::<Vec<_>>();
    if rows.len() != 2 {
        return Err(format!(
            "P14 CSV 應恰有雙 profile 兩列，實際 {}",
            rows.len()
        ));
    }
    let ids = P14_CASE_SPECS
        .iter()
        .map(|spec| spec.id)
        .collect::<Vec<_>>()
        .join(";");
    for profile in ["lua55", "lua54"] {
        let matches = rows
            .iter()
            .filter(|row| row.split(',').nth(1) == Some(profile))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!("P14 CSV {profile} 映射缺少或重複"));
        }
        let columns = matches[0].split(',').collect::<Vec<_>>();
        if columns.len() != 7
            || columns[0] != "p14.sdk-cli"
            || columns[2] != "docs/plane/P14.md#6-正常與錯誤案例"
            || columns[3] != "rivetlua;rivetlua-cli"
            || columns[4] != ids
            || columns[5] != "PASS"
            || !columns[6].is_empty()
        {
            return Err(format!("P14 CSV {profile} 欄位或 ID 集合不符"));
        }
    }
    Ok(())
}

fn p14_records_from_output(profile: &str, output: &str) -> Result<P14Record, String> {
    let mut records = Vec::new();
    for line in output.lines() {
        if let Some(position) = line.find("P14_CASE") {
            let fields = line[position..].split('\t').collect::<Vec<_>>();
            if fields.len() != 8 || fields[0] != "P14_CASE" || fields[2] != profile {
                return Err(format!("P14 marker 八欄或 profile 錯誤：{line}"));
            }
            let spec =
                p14_spec(fields[1]).ok_or_else(|| format!("P14 marker 未知 ID：{}", fields[1]))?;
            let payload = fields[3]
                .strip_prefix("status=PASS;actual=")
                .ok_or_else(|| format!("P14 {} marker 無 PASS/actual", spec.id))?;
            let (actual, diagnostic) = payload
                .rsplit_once(";diagnostic=")
                .ok_or_else(|| format!("P14 {} marker 無 diagnostic", spec.id))?;
            if actual != spec.expected || diagnostic.is_empty() {
                return Err(format!("P14 {} marker actual/diagnostic 不符", spec.id));
            }
            let trace = |index: usize, prefix: &str| -> Result<String, String> {
                fields[index]
                    .strip_prefix(prefix)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("P14 {} 缺 trace {prefix}", spec.id))
            };
            records.push(P14Record {
                id: spec.id.into(),
                profile: profile.into(),
                actual: actual.into(),
                diagnostic: diagnostic.into(),
                allocation: trace(4, "allocation=")?,
                resource: trace(5, "resource=")?,
                vm: trace(6, "vm=")?,
                cli: trace(7, "cli=")?,
            });
        }
    }
    if records.len() != 1 {
        return Err(format!(
            "P14 exact child marker 預期 1 個，實際 {}",
            records.len()
        ));
    }
    Ok(records.remove(0))
}

fn p14_check_exact_summary(output: &str) -> Result<(), String> {
    let lines = output
        .lines()
        .filter(|line| line.contains("test result:"))
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(format!(
            "P14 exact child 摘要預期 1 個，實際 {}",
            lines.len()
        ));
    }
    let summary = lines[0]
        .split_once("test result: ok. ")
        .map(|(_, text)| text)
        .ok_or("P14 exact child 無成功摘要")?;
    let fields = summary.split(';').map(str::trim).collect::<Vec<_>>();
    if !(5..=6).contains(&fields.len())
        || fields[0] != "1 passed"
        || fields[1] != "0 failed"
        || fields[2] != "0 ignored"
        || fields[3] != "0 measured"
        || fields[4]
            .strip_suffix(" filtered out")
            .and_then(|value| value.parse::<usize>().ok())
            .is_none()
        || (fields.len() == 6 && !fields[5].starts_with("finished in "))
    {
        return Err(format!(
            "P14 exact child 必須 1 passed/0 failed/0 ignored：{}",
            lines[0]
        ));
    }
    Ok(())
}

fn p14_case_command(profile: &str, spec: &P14CaseSpec) -> String {
    let target = env::var("CARGO_TARGET_DIR")
        .ok()
        .map(|value| format!("CARGO_TARGET_DIR={value} "))
        .unwrap_or_default();
    format!(
        "{target}RIVETLUA_P14_PROFILE={profile} cargo test --locked -p {} --test p14_contracts {} -- --exact --nocapture --test-threads=1",
        spec.package, spec.input
    )
}

fn p14_capture(root: &Path, profile: Option<&str>, args: &[&str]) -> Result<(i32, String), String> {
    let mut command = Command::new("cargo");
    command.args(args).current_dir(root);
    if let Some(profile) = profile {
        command.env("RIVETLUA_P14_PROFILE", profile);
    }
    let output = command
        .output()
        .map_err(|error| format!("啟動 P14 child 失敗：{error}"))?;
    Ok((
        output.status.code().unwrap_or(1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

fn p14_clear_case_reports(root: &Path) -> Result<(), String> {
    let dir = p13_report_dir(root);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("P14 報告目錄不可讀：{error}")),
    };
    let mut failure = None;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_name().to_string_lossy().starts_with("P14-") {
            let path = entry.path();
            if !path.is_file() {
                failure
                    .get_or_insert_with(|| format!("P14 舊報告路徑不是檔案：{}", path.display()));
                continue;
            }
            if let Err(error) = fs::remove_file(&path) {
                failure.get_or_insert_with(|| format!("清除 {} 失敗：{error}", path.display()));
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn p14_aggregate_json(
    digest: &str,
    results: &[GateResult],
    status: &str,
    diagnostic: &str,
) -> String {
    let checks = results.iter().map(|item| format!(
        "{{\"name\":\"{}\",\"command\":\"{}\",\"exit_code\":{},\"status\":\"{}\",\"diagnostic\":\"{}\",\"report_path\":\"{}\"}}",
        json_escape(&item.name), json_escape(&item.command), item.exit_code, item.status,
        json_escape(&item.diagnostic), json_escape(&item.report_path)
    )).collect::<Vec<_>>().join(",");
    let cases = if status == "PASS" {
        results
            .iter()
            .filter(|item| item.name.starts_with("SDK-"))
            .map(|item| {
                let (id, profile) = item.name.rsplit_once('-').expect("已驗 P14 case check");
                format!(
                    "{{\"case_id\":\"{}\",\"lua_profile\":\"{}\",\"report_path\":\"{}\"}}",
                    json_escape(id),
                    json_escape(profile),
                    json_escape(&item.report_path)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    } else {
        String::new()
    };
    format!(
        "{{\"status\":\"{status}\",\"source_digest\":\"{}\",\"diagnostic\":\"{}\",\"checks\":[{checks}],\"case_reports\":[{cases}]}}\n",
        json_escape(digest),
        json_escape(diagnostic)
    )
}

fn p14_write_aggregate(
    digest: &str,
    results: &[GateResult],
    status: &str,
    diagnostic: &str,
    path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("P14 aggregate 路徑無 parent")?)
        .map_err(|error| error.to_string())?;
    fs::write(
        path,
        p14_aggregate_json(digest, results, status, diagnostic),
    )
    .map_err(|error| format!("寫 P14 aggregate {} 失敗：{error}", path.display()))?;
    let parsed =
        StrictJsonParser::parse(&fs::read_to_string(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("P14 aggregate JSON 無效：{error}"))?;
    if parsed.get("status").and_then(StrictJsonValue::as_str) != Some(status)
        || parsed
            .get("source_digest")
            .and_then(StrictJsonValue::as_str)
            != Some(digest)
    {
        return Err("P14 aggregate 寫後欄位不符".into());
    }
    Ok(())
}

fn p14_fail(
    root: &Path,
    digest: &str,
    results: &mut Vec<GateResult>,
    name: &str,
    command: &str,
    exit_code: i32,
    error: String,
) -> String {
    let mut diagnostic = error;
    if let Err(error) = p14_clear_case_reports(root) {
        diagnostic.push_str(&format!("；清理 P14 案例失敗：{error}"));
    }
    let canonical = p13_report_dir(root).join("gate-P14.json");
    if canonical.is_file() {
        if let Err(error) = fs::remove_file(&canonical) {
            diagnostic.push_str(&format!("；清除舊 P14 aggregate 失敗：{error}"));
        }
    }
    results.push(p13_result(
        name,
        command,
        exit_code.max(1),
        "FAIL",
        &diagnostic,
        "target/rivetlua-reports/gate-P14.json",
    ));
    if let Err(error) = p14_write_aggregate(digest, results, "FAIL", &diagnostic, &canonical) {
        let fallback = root.join("target/gate-P14-fail.json");
        diagnostic.push_str(&format!("；canonical 寫入失敗：{error}"));
        if let Some(last) = results.last_mut() {
            last.report_path = "target/gate-P14-fail.json".into();
            last.diagnostic = diagnostic.clone();
        }
        if let Err(fallback_error) =
            p14_write_aggregate(digest, results, "FAIL", &diagnostic, &fallback)
        {
            diagnostic.push_str(&format!("；fallback FAIL 寫入失敗：{fallback_error}"));
        }
    }
    diagnostic
}

fn p14_case_json(
    case: &P14FixtureCase,
    record: &P14Record,
    digest: &str,
    command: &str,
    cwd: &Path,
    report_path: &str,
) -> String {
    format!(
        "{{\"case_id\":\"{}\",\"profile\":\"{}\",\"lua_profile\":\"{}\",\"mode\":\"{}\",\"input\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\",\"status\":\"PASS\",\"command\":\"{}\",\"cwd\":\"{}\",\"exit_code\":0,\"source_digest\":\"{}\",\"report_path\":\"{}\",\"diagnostic\":\"{}\",\"allocation_trace\":\"{}\",\"resource_trace\":\"{}\",\"vm_trace\":\"{}\",\"cli_trace\":\"{}\"}}\n",
        json_escape(&case.id),
        json_escape(&case.profile),
        json_escape(&case.lua_profile),
        json_escape(&case.mode),
        json_escape(&case.input),
        json_escape(&case.expected),
        json_escape(&record.actual),
        json_escape(command),
        json_escape(&cwd.display().to_string()),
        json_escape(digest),
        json_escape(report_path),
        json_escape(&format!("{}；{}", case.note, record.diagnostic)),
        json_escape(&record.allocation),
        json_escape(&record.resource),
        json_escape(&record.vm),
        json_escape(&record.cli)
    )
}

fn p14_validate_case_report(
    path: &Path,
    case: &P14FixtureCase,
    digest: &str,
    command: &str,
    cwd: &Path,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("P14 case {} 不可讀：{error}", path.display()))?;
    let parsed = StrictJsonParser::parse(&text)
        .map_err(|error| format!("P14 case {} JSON 無效：{error}", path.display()))?;
    let relative = format!(
        "target/rivetlua-reports/P14-{}-{}.json",
        case.id, case.lua_profile
    );
    let cwd_text = cwd.display().to_string();
    for (key, expected) in [
        ("case_id", case.id.as_str()),
        ("profile", case.profile.as_str()),
        ("lua_profile", case.lua_profile.as_str()),
        ("mode", case.mode.as_str()),
        ("input", case.input.as_str()),
        ("expected", case.expected.as_str()),
        ("actual", case.expected.as_str()),
        ("status", "PASS"),
        ("command", command),
        ("cwd", cwd_text.as_str()),
        ("source_digest", digest),
        ("report_path", relative.as_str()),
    ] {
        if parsed.get(key).and_then(StrictJsonValue::as_str) != Some(expected) {
            return Err(format!("P14 case {} 欄位 {key} 不符", path.display()));
        }
    }
    if parsed.get("exit_code").and_then(StrictJsonValue::as_i32) != Some(0) {
        return Err(format!("P14 case {} exit 非零", path.display()));
    }
    for key in [
        "diagnostic",
        "allocation_trace",
        "resource_trace",
        "vm_trace",
        "cli_trace",
    ] {
        if !parsed
            .get(key)
            .and_then(StrictJsonValue::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            return Err(format!("P14 case {} 缺 {key}", path.display()));
        }
    }
    Ok(())
}

fn p14_validate_all_case_reports(
    root: &Path,
    cases: &[P14FixtureCase],
    digest: &str,
    expected: &std::collections::HashMap<PathBuf, String>,
) -> Result<(), String> {
    let dir = p13_report_dir(root);
    let paths = fs::read_dir(&dir)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("P14-"))
        })
        .collect::<Vec<_>>();
    if paths.len() != 28 || cases.len() != 28 {
        return Err(format!("P14 case reports 預期 28 個，實際 {}", paths.len()));
    }
    if expected.len() != 28 {
        return Err(format!("P14 marker 產生案例數錯誤：{}", expected.len()));
    }
    for case in cases {
        let spec = p14_spec(&case.id).ok_or("P14 未知案例")?;
        let path = dir.join(format!("P14-{}-{}.json", case.id, case.lua_profile));
        if !paths.contains(&path) {
            return Err(format!("P14 缺案例報告：{}", path.display()));
        }
        p14_validate_case_report(
            &path,
            case,
            digest,
            &p14_case_command(&case.profile, spec),
            root,
        )?;
        let actual = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        if expected.get(&path) != Some(&actual) {
            return Err(format!(
                "P14 case {} 與 child marker 原始紀錄不符",
                path.display()
            ));
        }
    }
    Ok(())
}

fn p14_validate_prior_reports(root: &Path, digest: &str) -> Result<Vec<GateResult>, String> {
    let mut results = p13_validate_prior_reports(root, digest)?;
    let path = p13_report_dir(root).join("gate-P13.json");
    let text =
        fs::read_to_string(&path).map_err(|error| format!("缺 P13 前置 gate 報告：{error}"))?;
    let parsed = StrictJsonParser::parse(&text)
        .map_err(|error| format!("P13 前置 gate JSON 無效：{error}"))?;
    if parsed.get("status").and_then(StrictJsonValue::as_str) != Some("PASS") {
        return Err("P13 前置 gate 非 PASS".into());
    }
    validate_report_source_digest("P13", &parsed, digest)?;
    let checks = parsed
        .get("checks")
        .and_then(StrictJsonValue::as_array)
        .filter(|checks| !checks.is_empty())
        .ok_or("P13 前置 checks 缺失")?;
    let mut names = std::collections::HashSet::new();
    for check in checks {
        let name = p13_validate_prior_check("P13", check)?;
        if !names.insert(name.clone()) {
            return Err(format!("P13 前置 check 重複：{name}"));
        }
        if let Some(phase) = name.strip_suffix("-aggregate") {
            let prior = results
                .iter()
                .find(|item| item.name == name)
                .ok_or_else(|| format!("P13 前置 aggregate 未經 {phase} 報告核驗"))?;
            if check.get("command").and_then(StrictJsonValue::as_str)
                != Some(prior.command.as_str())
                || check.get("report_path").and_then(StrictJsonValue::as_str)
                    != Some(prior.report_path.as_str())
            {
                return Err(format!("P13 前置 aggregate {name} command/path 不符"));
            }
        }
        let fixed_command = match name.as_str() {
            "p13-dependencies" => Some("validate spec/phase-dependencies.csv DA-09/14/18/19/20"),
            "p13-csv" => Some("validate spec/compatibility.csv"),
            "p13-fixture" => Some("validate tests/p13/lib-cases.fixture"),
            "p13-runtime-unit" => {
                Some("cargo test --locked -p rivetlua-runtime --lib p13_ -- --test-threads=1")
            }
            "p13-case-reports" => Some("validate 28 unique P13 case JSON"),
            "p13-source-digest" => Some("verify source digest after children"),
            _ => None,
        };
        if let Some(command) = fixed_command {
            if check.get("command").and_then(StrictJsonValue::as_str) != Some(command)
                || check.get("report_path").and_then(StrictJsonValue::as_str)
                    != Some("target/rivetlua-reports/gate-P13.json")
            {
                return Err(format!("P13 前置 {name} command/path 不符"));
            }
        }
        if name.starts_with("LIB-") {
            let (id, lua_profile) = name.rsplit_once('-').ok_or("P13 LIB check 無 profile")?;
            let spec = p13_spec(id).ok_or_else(|| format!("P13 未知 LIB check：{name}"))?;
            let fullprofile = match lua_profile {
                "lua55" => "lua55-i64f64",
                "lua54" => "lua54-i64f64",
                _ => return Err(format!("P13 LIB check profile 不合法：{name}")),
            };
            let expected_command = p13_case_command(fullprofile, spec.test_name);
            let expected_path = format!("target/rivetlua-reports/P13-{id}-{lua_profile}.json");
            if check.get("command").and_then(StrictJsonValue::as_str)
                != Some(expected_command.as_str())
                || check.get("report_path").and_then(StrictJsonValue::as_str)
                    != Some(expected_path.as_str())
            {
                return Err(format!("P13 LIB check {name} command/path 不符"));
            }
        }
    }
    let mut required = vec![
        "p13-csv".to_owned(),
        "p13-fixture".to_owned(),
        "p13-runtime-unit".to_owned(),
        "p13-case-reports".to_owned(),
        "p13-source-digest".to_owned(),
        "p13-dependencies".to_owned(),
    ];
    for phase in 0..=12 {
        required.push(format!("P{phase:02}-aggregate"));
    }
    for spec in P13_CASE_SPECS {
        for profile in ["lua55", "lua54"] {
            required.push(format!("{}-{profile}", spec.id));
        }
    }
    p13_check_names(checks, &required, "P13")?;
    if checks.len() != required.len() {
        return Err(format!(
            "P13 前置 checks 數錯誤：預期 {}，實際 {}",
            required.len(),
            checks.len()
        ));
    }
    let p13_fixture = fs::read_to_string(root.join("tests/p13/lib-cases.fixture"))
        .map_err(|error| format!("P13 fixture 不可讀：{error}"))?;
    let p13_cases = parse_p13_fixture(&p13_fixture)?;
    p13_validate_all_case_reports(root, &p13_cases, digest)?;
    let case_refs = parsed
        .get("case_reports")
        .and_then(StrictJsonValue::as_array)
        .ok_or("P13 aggregate 缺 case_reports")?;
    if case_refs.len() != 28 {
        return Err(format!(
            "P13 aggregate case_refs 非 28：{}",
            case_refs.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for reference in case_refs {
        let id = reference
            .get("case_id")
            .and_then(StrictJsonValue::as_str)
            .ok_or("P13 case_ref 缺 ID")?;
        let lua_profile = reference
            .get("lua_profile")
            .and_then(StrictJsonValue::as_str)
            .ok_or("P13 case_ref 缺 profile")?;
        let case = p13_cases
            .iter()
            .find(|case| {
                case.id == id
                    && ((lua_profile == "lua55" && case.profile == "lua55-i64f64")
                        || (lua_profile == "lua54" && case.profile == "lua54-i64f64"))
            })
            .ok_or_else(|| format!("P13 case_ref 未知：{id}/{lua_profile}"))?;
        let expected = format!("target/rivetlua-reports/P13-{}-{lua_profile}.json", case.id);
        if reference
            .get("report_path")
            .and_then(StrictJsonValue::as_str)
            != Some(expected.as_str())
            || !seen.insert((id, lua_profile))
        {
            return Err(format!("P13 case_ref 路徑不符或重複：{id}/{lua_profile}"));
        }
        let report = fs::read_to_string(root.join(&expected)).map_err(|error| error.to_string())?;
        let report = StrictJsonParser::parse(&report).map_err(|error| error.to_string())?;
        for (key, value) in [
            ("mode", case.mode.as_str()),
            ("input", case.input.as_str()),
            ("expected", case.expected.as_str()),
            ("actual", case.expected.as_str()),
            (
                "command",
                p13_case_command(&case.profile, &case.input).as_str(),
            ),
        ] {
            if report.get(key).and_then(StrictJsonValue::as_str) != Some(value) {
                return Err(format!("P13 case report {id}/{lua_profile} {key} 不符"));
            }
        }
        if report.get("report_path").and_then(StrictJsonValue::as_str) != Some(expected.as_str()) {
            return Err(format!("P13 case report {id}/{lua_profile} 路徑不符"));
        }
    }
    results.push(p13_result(
        "P13-aggregate",
        format!("validate {}", path.display()),
        0,
        "PASS",
        format!(
            "P13 fresh digest、{} exact checks、28 LIB reports/schema/reference",
            checks.len()
        ),
        "target/rivetlua-reports/gate-P14.json",
    ));
    Ok(results)
}

fn p14_prior_report_snapshot(
    root: &Path,
) -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    let mut snapshot = std::collections::BTreeMap::new();
    for entry in fs::read_dir(p13_report_dir(root)).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if (0..=13).any(|phase| {
            name == format!("gate-P{phase:02}.json") || name.starts_with(&format!("P{phase:02}-"))
        }) {
            let bytes = fs::read(entry.path())
                .map_err(|error| format!("前置報告 {name} 不可讀：{error}"))?;
            snapshot.insert(name, bytes);
        }
    }
    Ok(snapshot)
}

fn p14_validate_dependencies(root: &Path) -> Result<(), String> {
    let text = fs::read_to_string(root.join("spec/phase-dependencies.csv"))
        .map_err(|error| format!("讀 phase-dependencies.csv 失敗：{error}"))?;
    validate_phase_dependency_graph(&text)?;
    for row in [
        "DA-19,P12,P13,runtime root fuel table frame effect contracts,CONTRACTED,P13",
        "DA-20,P05,P14,RVLU_V2 language payload VerifiedModule,CONTRACTED,P14",
        "DA-21,P14,P16,SDK wrapper container policy,CONTRACTED,P14",
        "DA-32,P05,P13,Lua55 Lua54 official chunk codec translation VerifiedModule,IMPLEMENTED,P13",
        "DA-33,P05,P14,immutable validated artifact metadata transport,IMPLEMENTED,P14",
    ] {
        if !text.lines().any(|line| line == row) {
            return Err(format!("P14 dependency 契約列缺少或變更：{row}"));
        }
    }
    Ok(())
}

fn p14_check_filter_summary(
    label: &str,
    output: &str,
    expected_passed: usize,
) -> Result<usize, String> {
    let summaries = output
        .lines()
        .filter(|line| line.contains("test result:"))
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return Err(format!("P14 {label} 無測試摘要"));
    }
    let mut passed_total: usize = 0;
    for line in summaries {
        let summary = line
            .split_once("test result: ok. ")
            .map(|(_, text)| text)
            .ok_or_else(|| format!("P14 {label} 摘要非成功：{line}"))?;
        let fields = summary.split(';').map(str::trim).collect::<Vec<_>>();
        let count = |index: usize, suffix: &str| {
            fields
                .get(index)
                .and_then(|field| field.strip_suffix(suffix))
                .and_then(|value| value.parse::<usize>().ok())
        };
        if count(1, " failed") != Some(0) || count(2, " ignored") != Some(0) {
            return Err(format!("P14 {label} 摘要有 failed/ignored：{line}"));
        }
        passed_total = passed_total
            .checked_add(
                count(0, " passed").ok_or_else(|| format!("P14 {label} passed 數無效：{line}"))?,
            )
            .ok_or_else(|| format!("P14 {label} passed 數溢位：{line}"))?;
    }
    if passed_total == 0 {
        return Err(format!("P14 {label} 零匹配"));
    }
    if passed_total != expected_passed {
        return Err(format!(
            "P14 {label} 預期精確通過 {expected_passed} 個測試，實際 {passed_total}"
        ));
    }
    Ok(passed_total)
}

fn p14_gate() -> Result<(), String> {
    let root = root()?;
    let mut results = Vec::new();
    let digest = match source_digest(&root) {
        Ok(digest) => digest,
        Err(error) => {
            return Err(p14_fail(
                &root,
                &"0".repeat(64),
                &mut results,
                "p14-source-digest",
                "compute source digest",
                1,
                error,
            ));
        }
    };
    if let Err(error) = p14_clear_case_reports(&root) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p14-clear-cases",
            "clear old P14 case reports",
            1,
            error,
        ));
    }
    for relative in [
        "target/rivetlua-reports/gate-P14.json",
        "target/gate-P14-fail.json",
    ] {
        let path = root.join(relative);
        if path.exists() {
            if !path.is_file() {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    "p14-clear-aggregate",
                    relative,
                    1,
                    format!("舊 P14 aggregate 不是一般檔案：{}", path.display()),
                ));
            }
            if let Err(error) = fs::remove_file(&path) {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    "p14-clear-aggregate",
                    relative,
                    1,
                    error.to_string(),
                ));
            }
        }
    }
    match p14_validate_prior_reports(&root, &digest) {
        Ok(prior) => results.extend(prior),
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p00-p13-before",
                "validate fresh P00-P13 reports, checks, cases and digest",
                1,
                error,
            ));
        }
    }
    let prior_snapshot = match p14_prior_report_snapshot(&root) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p00-p13-before",
                "snapshot P00-P13 reports",
                1,
                error,
            ));
        }
    };
    if let Err(error) = p14_validate_dependencies(&root) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p14-dependencies",
            "validate DA-19/20/21/32/33",
            1,
            error,
        ));
    }
    results.push(p13_result(
        "p14-dependencies",
        "validate spec/phase-dependencies.csv DA-19/20/21/32/33",
        0,
        "PASS",
        "owner/status/interface exact rows",
        "target/rivetlua-reports/gate-P14.json",
    ));
    let csv = match fs::read_to_string(root.join("spec/compatibility.csv")) {
        Ok(csv) => csv,
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p14-csv",
                "read spec/compatibility.csv",
                1,
                error.to_string(),
            ));
        }
    };
    if let Err(error) = p14_validate_csv_cases(&csv) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p14-csv",
            "validate P14 CSV exact cases",
            1,
            error,
        ));
    }
    results.push(p13_result(
        "p14-csv",
        "validate spec/compatibility.csv P14 rows",
        0,
        "PASS",
        "兩 profile 各 14 個固定案例",
        "target/rivetlua-reports/gate-P14.json",
    ));
    let fixture = match fs::read_to_string(root.join("tests/p14/sdk-cases.fixture")) {
        Ok(text) => text,
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p14-fixture",
                "read tests/p14/sdk-cases.fixture",
                1,
                error.to_string(),
            ));
        }
    };
    let cases = match parse_p14_fixture(&fixture) {
        Ok(cases) => cases,
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p14-fixture",
                "validate P14 fixture",
                1,
                error,
            ));
        }
    };
    results.push(p13_result(
        "p14-fixture",
        "validate tests/p14/sdk-cases.fixture",
        0,
        "PASS",
        "28 unique profile/ID 與固定 mode/input/marker/expected",
        "target/rivetlua-reports/gate-P14.json",
    ));
    let sdk_filter_args = vec![
        "test",
        "--locked",
        "-p",
        "rivetlua",
        "--test",
        "p14_contracts",
        "--test",
        "sdk",
        "--test",
        "sdk_inputs",
        "--test",
        "state_separation",
        "--test",
        "wrapper",
        "--",
        "sdk",
    ];
    let wrapper_filter_args = vec![
        "test", "--locked", "-p", "rivetlua", "--lib", "--test", "wrapper", "--", "wrapper",
    ];
    let mut cli_filter_args = vec![
        "test",
        "--locked",
        "-p",
        "rivetlua-cli",
        "--lib",
        "--test",
        "cli",
        "--test",
        "p14_contracts",
        "--",
        "cli",
    ];
    for skipped in [
        "cli_dump_policy_uses_finite_work_temporary_and_encoded_limits",
        "cli_load_policy_matches_finite_gc_work_temporary_and_fuel_caps",
        "cli_debug_policy_matches_official_suite_capabilities",
        "cli_entropy_reader_consumes_exactly_one_native_endian_seed",
        "cli_entropy_reader_retries_interrupted_reads",
        "cli_entropy_reader_maps_short_reads_and_read_errors_to_read_failed",
        "cli_unix_epoch_seconds_floor_negative_fractions",
        "cli_unix_epoch_seconds_checks_i64_bounds_when_system_time_can_represent_them",
        "cli_resource_deadline_expires_and_unrepresentable_deadline_fails_closed",
        "cli_resource_budget_is_charged_before_authorize_deadline_and_perform",
        "cli_locale_response_is_precharged_and_respects_the_temporary_limit",
        "cli_entropy_provider_fails_closed_on_unsupported_platforms",
        "cli_randomseed_without_arguments_uses_host_entropy_for_both_profiles",
        "cli_randomseed_without_arguments_reports_entropy_failure_on_unsupported_platforms",
        "cli_os_clock_and_time_use_real_host_values_for_profiles_and_build_default",
        "cli_os_clock_is_unsupported_without_a_native_process_clock",
        "cli_os_resource_policy_keeps_unconfigured_operations_denied",
        "cli_os_setlocale_uses_only_fixed_c_locale_for_profiles_and_build_default",
        "cli_default_profile_identity_and_compiler_roundtrip_match_build_feature",
        "cli_host_load_handles_21_short_blocks_through_load_loadfile_and_require_for_both_profiles",
        "cli_host_load_keeps_finite_work_limit_and_allows_same_vm_retry",
        "cli_host_loads_lua55_gc_fixture_when_explicitly_enabled",
        "cli_host_loads_lua54_gc_fixture_when_explicitly_enabled",
        "cli_host_load_compiles_official_lua55_main_when_explicitly_enabled",
        "cli_string_dump_round_trips_official_lua55_db_when_explicitly_enabled",
        "cli_string_dump_round_trips_ordinary_and_stripped_closures_for_both_profiles",
        "cli_string_dump_argument_modes_profile_and_retry_for_both_profiles",
        "cli_string_dump_round_trips_official_lua55_main_when_explicitly_enabled",
        "cli_debug_table_metatable_write_preserves_registry_identity_for_both_profiles",
        "cli_debug_gethook_is_allowed_for_both_profiles",
        "cli_debug_policy_rejects_unimplemented_ops_and_restricts_table_metatable_write",
        "cli_debug_table_metatable_write_starts_lua55_tracegc_fixture_when_explicitly_enabled",
        "cli_unit_tests::cli_rejects_nested_returned_values_with_a_nonzero_diagnostic",
    ] {
        cli_filter_args.extend(["--skip", skipped]);
    }
    for (name, arguments, expected_count) in [
        ("p14-sdk-filter", sdk_filter_args, 52),
        ("p14-wrapper-filter", wrapper_filter_args, 13),
        ("p14-cli-filter", cli_filter_args, 38),
    ] {
        let command = format!("cargo {}", arguments.join(" "));
        let (exit, output) = match p14_capture(&root, None, &arguments) {
            Ok(result) => result,
            Err(error) => {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    name,
                    &command,
                    1,
                    error,
                ));
            }
        };
        if exit != 0 {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                name,
                &command,
                exit,
                format!("selector child exit={exit}；{output}"),
            ));
        }
        let passed = match p14_check_filter_summary(name, &output, expected_count) {
            Ok(passed) => passed,
            Err(error) => {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    name,
                    &command,
                    1,
                    format!("{error}；{output}"),
                ));
            }
        };
        results.push(p13_result(
            name,
            command,
            0,
            "PASS",
            format!("精確通過 {passed} 個測試；0 failed/ignored"),
            "target/rivetlua-reports/gate-P14.json",
        ));
    }
    for profile in ["lua55", "lua54"] {
        let name = format!("p14-example-{profile}");
        let command = format!("cargo run --locked -p rivetlua --example embed -- {profile}");
        let (exit, output) = match p14_capture(
            &root,
            None,
            &[
                "run",
                "--locked",
                "-p",
                "rivetlua",
                "--example",
                "embed",
                "--",
                profile,
            ],
        ) {
            Ok(result) => result,
            Err(error) => {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    1,
                    error,
                ));
            }
        };
        let marker = format!("P14_EXAMPLE:{profile}:PASS");
        if exit != 0 || output.lines().filter(|line| *line == marker).count() != 1 {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                &name,
                &command,
                exit.max(1),
                format!("公開 example exit/marker 不符：{output}"),
            ));
        }
        results.push(p13_result(
            name,
            command,
            0,
            "PASS",
            "公開 example 真 Root/GC/VM assertion 與唯一 marker",
            "target/rivetlua-reports/gate-P14.json",
        ));
    }
    let mut expected_case_json = std::collections::HashMap::new();
    for (profile, lua_profile) in [("lua55-i64f64", "lua55"), ("lua54-i64f64", "lua54")] {
        for spec in P14_CASE_SPECS {
            let case = cases
                .iter()
                .find(|case| case.profile == profile && case.id == spec.id)
                .expect("P14 fixture 已核對完整");
            let name = format!("{}-{lua_profile}", spec.id);
            let command = p14_case_command(profile, &spec);
            let (exit, output) = match p14_capture(
                &root,
                Some(profile),
                &[
                    "test",
                    "--locked",
                    "-p",
                    spec.package,
                    "--test",
                    "p14_contracts",
                    spec.input,
                    "--",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ],
            ) {
                Ok(result) => result,
                Err(error) => {
                    return Err(p14_fail(
                        &root,
                        &digest,
                        &mut results,
                        &name,
                        &command,
                        1,
                        error,
                    ));
                }
            };
            if exit != 0 {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    exit,
                    format!("exact child exit={exit}；{output}"),
                ));
            }
            if let Err(error) = p14_check_exact_summary(&output) {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    1,
                    format!("{error}；{output}"),
                ));
            }
            let record = match p14_records_from_output(profile, &output) {
                Ok(record) => record,
                Err(error) => {
                    return Err(p14_fail(
                        &root,
                        &digest,
                        &mut results,
                        &name,
                        &command,
                        1,
                        error,
                    ));
                }
            };
            if record.id != case.id
                || record.profile != case.profile
                || case.marker != format!("P14_CASE:{}", record.id)
                || record.actual != case.expected
            {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    1,
                    "P14 child marker 與 fixture 不符".into(),
                ));
            }
            let relative = format!("target/rivetlua-reports/P14-{}-{lua_profile}.json", case.id);
            let path = root.join(&relative);
            let json = p14_case_json(case, &record, &digest, &command, &root, &relative);
            if let Err(error) = fs::write(&path, &json) {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    1,
                    format!("P14 case 寫入失敗：{error}"),
                ));
            }
            expected_case_json.insert(path.clone(), json);
            if let Err(error) = p14_validate_case_report(&path, case, &digest, &command, &root) {
                return Err(p14_fail(
                    &root,
                    &digest,
                    &mut results,
                    &name,
                    &command,
                    1,
                    error,
                ));
            }
            results.push(p13_result(
                name,
                command,
                0,
                "PASS",
                format!(
                    "{}；exact 1/1、唯一 marker、固定 expected/trace/schema",
                    case.note
                ),
                relative,
            ));
        }
    }
    if let Err(error) = p14_validate_prior_reports(&root, &digest) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p00-p13-after",
            "validate P00-P13 reports after P14 children",
            1,
            error,
        ));
    }
    match p14_prior_report_snapshot(&root) {
        Ok(after) if after == prior_snapshot => {}
        Ok(_) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p00-p13-after",
                "compare P00-P13 reports after P14 children",
                1,
                "P00-P13 前置報告在 child 執行期間變更".into(),
            ));
        }
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p00-p13-after",
                "compare P00-P13 reports after P14 children",
                1,
                error,
            ));
        }
    }
    results.push(p13_result(
        "p00-p13-after",
        "validate P00-P13 reports after P14 children",
        0,
        "PASS",
        "前置報告、checks、cases 於 child 後仍有效",
        "target/rivetlua-reports/gate-P14.json",
    ));
    if let Err(error) = p14_validate_all_case_reports(&root, &cases, &digest, &expected_case_json) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p14-case-reports",
            "validate 28 P14 case reports",
            1,
            error,
        ));
    }
    results.push(p13_result(
        "p14-case-reports",
        "validate 28 P14 case reports",
        0,
        "PASS",
        "28 unique profile/ID、schema/digest/path",
        "target/rivetlua-reports/gate-P14.json",
    ));
    match source_digest(&root) {
        Ok(current) if current == digest => {}
        Ok(_) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p14-source-digest",
                "verify source digest after children",
                1,
                "P14 執行期間 source digest 已變更".into(),
            ));
        }
        Err(error) => {
            return Err(p14_fail(
                &root,
                &digest,
                &mut results,
                "p14-source-digest",
                "verify source digest after children",
                1,
                error,
            ));
        }
    }
    results.push(p13_result(
        "p14-source-digest",
        "verify source digest after children",
        0,
        "PASS",
        "受測來源於所有 child 後未變",
        "target/rivetlua-reports/gate-P14.json",
    ));
    let path = p13_report_dir(&root).join("gate-P14.json");
    if let Err(error) = p14_write_aggregate(
        &digest,
        &results,
        "PASS",
        "28 formal cases, selectors, examples and P00-P13 prerequisites verified",
        &path,
    ) {
        return Err(p14_fail(
            &root,
            &digest,
            &mut results,
            "p14-aggregate-write",
            "write gate-P14.json",
            1,
            error,
        ));
    }
    println!("PASS report={}", path.display());
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match arguments.first().map(String::as_str) {
        Some("toolchain") if arguments.len() == 1 => {
            (|| -> Result<(), String> {
                let root = root()?;
                let actual = run("rustc", &["--version"], &root)?;
                if !supported_rustc(&actual) { return Err(format!("實際 rustc 低於 MSRV {MSRV} 或版本無法辨識：{actual}")); }
                println!("msrv={MSRV}\nactual={}", actual.trim());
                Ok(())
            })()
        }
        Some("reference") => reference(&arguments[1..]),
        Some("official-tests") => p15::official_tests(&arguments[1..]),
        Some("p16-acceptance") => p16::acceptance(&arguments[1..]),
        Some("runner") => runner(&arguments[1..]),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P00") && arguments.len() == 2 => {
            GATE_REPORT_WRITTEN.store(false, Ordering::Relaxed);
            gate()
        }
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P01") && arguments.len() == 2 => p01_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P02") && arguments.len() == 2 => p02_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P03") && arguments.len() == 2 => p03_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P04") && arguments.len() == 2 => p04_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P05") && arguments.len() == 2 => p05_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P06") && arguments.len() == 2 => p06_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P07") && arguments.len() == 2 => p07_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P08") && arguments.len() == 2 => p08_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P09") && arguments.len() == 2 => p09_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P10") && arguments.len() == 2 => p10_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P11") && arguments.len() == 2 => p11_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P12") && arguments.len() == 2 => p12_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P13") && arguments.len() == 2 => p13_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P14") && arguments.len() == 2 => p14_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P15") && arguments.len() == 2 => p15::gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P16") && arguments.len() == 2 => p16::gate(),
        _ => Err(
            "用法：rivetlua-xtask toolchain | reference --profile lua55|lua54 [--offline] | runner --profile lua55|lua54 --case <P00-ID> | official-tests --profile lua55-i64f64|lua54-i64f64 --mode basic | p16-acceptance --profile lua55-i64f64|lua54-i64f64 | gate P00|P01|P02|P03|P04|P05|P06|P07|P08|P09|P10|P11|P12|P13|P14|P15|P16".into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if arguments.first().map(String::as_str) == Some("gate")
                && arguments.get(1).map(String::as_str) == Some("P00")
            {
                if !GATE_REPORT_WRITTEN.load(Ordering::Relaxed) {
                    if let Ok(root) = root() {
                        write_early_gate_failure(&root, &error);
                    }
                }
            }
            let phase = arguments
                .get(1)
                .filter(|_| arguments.first().map(String::as_str) == Some("gate"))
                .map(String::as_str)
                .unwrap_or("P00");
            eprintln!("{phase} 失敗：{error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LUA54, LUA55, MSRV, P02_CASES, P03_CASES, P04_CASES, P05_CASES, P05_CONTRACT_TEST_COUNT,
        P06_CASES, P06FixtureCase, P07_CASES, P08_CASES, P09_LUA54_CASES, P09_LUA55_CASES,
        P10_CASES, P11_CASE_IDS, P11_CASE_SPECS, P12_CASE_IDS, P12_CASE_SPECS,
        STRICT_GLOBAL_CFLAGS, StrictJsonParser, StrictJsonValue, contains_lua_engine_symbol,
        p03_child_status, p04_check_test_summary, p04_child_status, p05_check_test_summary,
        p05_child_status, p06_case_report, p06_check_test_summary, p06_check_with_value_doctests,
        p07_case_report, p08_records_from_output, p09_check_test_summary, p09_records_from_output,
        p10_check_test_summary, p10_check_unit_summary, p10_diagnostic_is_complete,
        p10_records_from_output, p11_check_case_summary, p11_check_unit_summary,
        p11_records_from_output, p12_check_case_summary, p12_check_filter_summary,
        p12_check_reentry_summary, p12_check_unit_summary, p12_records_from_output,
        p12_reentry_command, parse_p06_fixture, parse_p07_fixture, parse_p08_fixture,
        parse_p09_fixture, parse_p10_fixture, parse_p11_fixture, parse_p12_fixture, profile,
        reference_make_target, sha256_tool, source_digest, supported_rustc, validate_csv,
        validate_p01_contract_status, validate_p01_csv_cases, validate_p02_csv_cases,
        validate_p03_csv_cases, validate_p03_records, validate_p04_csv_cases, validate_p04_records,
        validate_p05_csv_cases, validate_p05_records, validate_p06_csv_cases, validate_p06_records,
        validate_p07_csv_cases, validate_p07_records, validate_p08_csv_cases,
        validate_p08_prior_reports, validate_p08_records, validate_p09_csv_cases,
        validate_p09_prior_reports, validate_p09_records, validate_p10_csv_cases,
        validate_p10_prior_reports, validate_p10_records, validate_p11_csv_cases,
        validate_p11_prior_reports, validate_p11_records, validate_p12_csv_cases,
        validate_p12_records, validate_pass_evidence, validate_phase_dependency_graph,
        write_p01_case_report, write_p02_case_report, write_p03_case_report, write_p04_case_report,
        write_p05_case_report,
    };
    use std::process::Command;

    fn initialize_gate_test_repository(root: &std::path::Path) {
        let _ = std::fs::remove_dir_all(root);
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(".gitignore"), b"target/\n").unwrap();
        std::fs::write(root.join("source.rs"), b"initial").unwrap();
        assert!(
            Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .args(["add", ".gitignore", "source.rs"])
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    fn stamp_gate_test_reports(root: &std::path::Path) {
        let digest = source_digest(root).unwrap();
        let reports = root.join("target/rivetlua-reports");
        for entry in std::fs::read_dir(reports).unwrap() {
            let path = entry.unwrap().path();
            if !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("gate-P")
            {
                continue;
            }
            let report = std::fs::read_to_string(&path).unwrap();
            if report.starts_with('{') && !report.contains("\"source_digest\"") {
                std::fs::write(
                    &path,
                    report.replacen('{', &format!("{{\"source_digest\":\"{digest}\","), 1),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn source_digest_tracks_content_presence_and_nonignored_untracked_files() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-source-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(
            Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(root.join("tracked.txt"), b"one").unwrap();
        std::fs::write(root.join(".gitignore"), b"ignored.txt\n").unwrap();
        assert!(
            Command::new("git")
                .args(["add", "tracked.txt", ".gitignore"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        let original = source_digest(&root).unwrap();
        assert_eq!(original.len(), 64);
        std::fs::write(root.join("ignored.txt"), b"ignored").unwrap();
        assert_eq!(source_digest(&root).unwrap(), original);
        std::fs::write(root.join("untracked.txt"), b"new").unwrap();
        let with_untracked = source_digest(&root).unwrap();
        assert_ne!(with_untracked, original);
        std::fs::remove_file(root.join("untracked.txt")).unwrap();
        assert_eq!(source_digest(&root).unwrap(), original);
        std::fs::write(root.join("tracked.txt"), b"two").unwrap();
        assert_ne!(source_digest(&root).unwrap(), original);
        std::fs::remove_file(root.join("tracked.txt")).unwrap();
        assert_ne!(source_digest(&root).unwrap(), original);
        std::fs::write(root.join("ignored.txt"), b"one").unwrap();
        std::os::unix::fs::symlink("ignored.txt", root.join("tracked.txt")).unwrap();
        assert_ne!(source_digest(&root).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn stable_rustc_must_meet_msrv() {
        assert_eq!(MSRV, "1.94.1");
        assert!(supported_rustc("rustc 1.94.1 (hash date)"));
        assert!(supported_rustc("rustc 1.98.1 (hash date)"));
        assert!(!supported_rustc("rustc 1.93.0 (hash date)"));
        assert!(!supported_rustc("rustc 1.98.1-beta.1 (hash date)"));
    }

    #[test]
    fn p04_contract_summary_requires_exact_two_tests() {
        assert!(p04_check_test_summary(
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            2,
        )
        .is_ok());
        assert!(p04_check_test_summary(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            2,
        )
        .is_err());
        assert!(p04_check_test_summary(
            "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            2,
        )
        .is_err());
        assert!(p04_check_test_summary(
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            2,
        )
        .is_err());
    }

    #[test]
    fn p05_contract_summary_requires_exact_seven_tests() {
        assert_eq!(P05_CONTRACT_TEST_COUNT, 7);
        assert!(p05_check_test_summary(
            "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            P05_CONTRACT_TEST_COUNT,
        )
        .is_ok());
        assert!(p05_check_test_summary(
            "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            P05_CONTRACT_TEST_COUNT,
        )
        .is_err());
        assert!(p05_check_test_summary(
            "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            P05_CONTRACT_TEST_COUNT,
        )
        .is_err());
        assert!(p05_check_test_summary(
            "test result: FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            P05_CONTRACT_TEST_COUNT,
        )
        .is_err());
    }
    #[test]
    fn reference_tools_are_selected_for_macos_and_linux() {
        assert_eq!(reference_make_target("macos").unwrap(), "macosx");
        assert_eq!(reference_make_target("linux").unwrap(), "linux");
        assert!(reference_make_target("windows").is_err());
        assert_eq!(
            sha256_tool("macos").unwrap(),
            ("shasum", &["-a", "256"][..])
        );
        assert_eq!(sha256_tool("linux").unwrap(), ("sha256sum", &[][..]));
    }
    #[test]
    fn symbol_scan_recognizes_macho_and_elf_names() {
        assert!(contains_lua_engine_symbol("00000000 T _lua_newstate"));
        assert!(contains_lua_engine_symbol("00000000 T luaL_newstate"));
        assert!(!contains_lua_engine_symbol(
            "                 U lua_newstate"
        ));
        assert!(!contains_lua_engine_symbol(
            "00000000 T lua_newstate_helper"
        ));
    }
    #[test]
    fn profiles_are_explicit_and_distinct() {
        assert_eq!(profile("lua55").unwrap().version, LUA55.version);
        assert_eq!(profile("lua54").unwrap().version, LUA54.version);
        assert!(profile("lua53").is_err());
    }
    #[test]
    fn csv_rejects_duplicate_feature_profile() {
        let csv = "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\na,lua55,s,m,P00-RUN-001,PASS,\na,lua55,s,m,P00-RUN-001,PASS,";
        assert!(validate_csv(csv).is_err());
    }
    #[test]
    fn csv_rejects_unknown_pass_case() {
        let csv = "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\na,lua55,s,m,P00-UNKNOWN,PASS,";
        assert!(validate_csv(csv).is_err());
    }
    #[test]
    fn pass_evidence_rejects_missing_runner_result() {
        let csv = "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\na,lua55,s,m,P00-RUN-001,PASS,";
        assert!(validate_pass_evidence(csv, &[]).is_err());
    }
    #[test]
    fn p01_case_report_is_valid_json() {
        let root = std::env::temp_dir().join(format!("rivetlua-p01-report-{}", std::process::id()));
        let records = vec![(
            "NUM-001".into(),
            "a\"b\n".into(),
            "Integer(-2)".into(),
            "Integer(-2)".into(),
        )];
        let path =
            write_p01_case_report(&root, "NUM-001", "lua55-i64f64", "lua55", &records).unwrap();
        let output = std::process::Command::new("python3")
            .args(["-c", "import json,sys; json.load(open(sys.argv[1]))"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(p04_child_status("lua55-i64f64", false, "failed").is_err());
    }
    #[test]
    fn p01_csv_cases_are_complete() {
        let ids = "NUM-001;NUM-002;NUM-003;NUM-004;NUM-005;NUM-006;NUM-007;NUM-008;VAL-001;VAL-002;VAL-003;ERR-001;ERR-002;ERR-003;ERR-004";
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np01.core,lua55,s,m,{ids},PASS,\np01.core,lua54,s,m,{ids},PASS,"
        );
        assert!(validate_p01_csv_cases(&csv).is_ok());
    }
    #[test]
    fn p03_case_report_is_valid_json() {
        let root = std::env::temp_dir().join(format!("rivetlua-p03-report-{}", std::process::id()));
        let path = write_p03_case_report(
            &root,
            "PARSE-001",
            "lua55-i64f64",
            "lua55",
            "return -2^2",
            "Unary { expression: Binary { span: Span { start_byte: 7, end_byte: 11 } } }",
        )
        .unwrap();
        let output = std::process::Command::new("python3")
            .args(["-c", "import json,sys; json.load(open(sys.argv[1]))"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn p03_records_and_child_status_reject_invalid_evidence() {
        let records = P03_CASES
            .iter()
            .map(|id| (id.to_string(), "i".to_string(), "a".to_string()))
            .collect::<Vec<_>>();
        assert!(validate_p03_records("lua55-i64f64", &records).is_ok());
        assert!(validate_p03_records("lua55-i64f64", &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate[1].0 = duplicate[0].0.clone();
        assert!(validate_p03_records("lua55-i64f64", &duplicate).is_err());
        let mut unknown = records.clone();
        unknown[0].0 = "UNKNOWN".into();
        assert!(validate_p03_records("lua55-i64f64", &unknown).is_err());
        assert!(p03_child_status("lua55-i64f64", false, "failed").is_err());
    }
    #[test]
    fn p01_csv_cases_reject_missing_num_001() {
        let ids = "NUM-002;NUM-003;NUM-004;NUM-005;NUM-006;NUM-007;NUM-008;VAL-001;VAL-002;VAL-003;ERR-001;ERR-002;ERR-003;ERR-004";
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np01.core,lua55,s,m,{ids},PASS,\np01.core,lua54,s,m,{ids},PASS,"
        );
        assert!(validate_p01_csv_cases(&csv).is_err());
    }
    #[test]
    fn p02_csv_cases_are_complete_and_strict_global_is_disabled() {
        let ids = P02_CASES.join(";");
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np02.lexer,lua55,s,rivetlua-compiler,{ids},PASS,\np02.lexer,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p02_csv_cases(&csv).is_ok());
        assert_eq!(STRICT_GLOBAL_CFLAGS, "-DLUA_COMPAT_GLOBAL=0");
    }
    #[test]
    fn p03_csv_cases_are_complete() {
        let ids = P03_CASES.join(";");
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np03.parser,lua55,s,rivetlua-compiler,{ids},PASS,\np03.parser,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p03_csv_cases(&csv).is_ok());
    }
    #[test]
    fn p03_csv_cases_reject_missing_wrong_profile_or_duplicate_id() {
        let missing = P03_CASES[1..].join(";");
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np03.parser,lua55,s,rivetlua-compiler,{missing},PASS,\np03.parser,lua54,s,rivetlua-compiler,{missing},PASS,"
        );
        assert!(validate_p03_csv_cases(&csv).is_err());
        let ids = P03_CASES.join(";");
        let wrong = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np03.parser,lua55-i64f64,s,rivetlua-compiler,{ids},PASS,\np03.parser,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p03_csv_cases(&wrong).is_err());
        let duplicate = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np03.parser,lua55,s,rivetlua-compiler,{ids};PARSE-001,PASS,\np03.parser,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p03_csv_cases(&duplicate).is_err());
    }
    #[test]
    fn p04_csv_cases_are_complete_and_reject_invalid_ids_or_profile() {
        let ids = P04_CASES.join(";");
        let complete = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np04.resolve,lua55,s,rivetlua-compiler,{ids},PASS,\np04.resolve,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p04_csv_cases(&complete).is_ok());
        let missing = P04_CASES[1..].join(";");
        let bad = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np04.resolve,lua55,s,rivetlua-compiler,{missing},PASS,\np04.resolve,lua54-i64f64,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p04_csv_cases(&bad).is_err());
    }
    #[test]
    fn p04_records_and_case_report_are_complete_and_valid_json() {
        let records = P04_CASES
            .iter()
            .map(|id| {
                (
                    id.to_string(),
                    "input".to_string(),
                    "Resolved { x: 1 }".to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert!(validate_p04_records("lua55-i64f64", &records).is_ok());
        assert!(validate_p04_records("lua55-i64f64", &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate[1].0 = duplicate[0].0.clone();
        assert!(validate_p04_records("lua55-i64f64", &duplicate).is_err());
        let root = std::env::temp_dir().join(format!("rivetlua-p04-report-{}", std::process::id()));
        let path = write_p04_case_report(
            &root,
            "RES-001",
            "lua55-i64f64",
            "lua55",
            "local x\\n",
            "Resolved { name: \\\"x\\\" }",
        )
        .unwrap();
        let output = Command::new("python3")
            .args(["-c", "import json,sys; report=json.load(open(sys.argv[1])); assert report['mode'] == 'resolve'; assert report['actual'].startswith('Resolved')"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn p05_csv_records_child_status_and_case_report_are_strict() {
        let ids = P05_CASES.join(";");
        let complete = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np05.bytecode,lua55,s,rivetlua-core;rivetlua-compiler,{ids},PASS,\np05.bytecode,lua54,s,rivetlua-core;rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p05_csv_cases(&complete).is_ok());
        let missing = P05_CASES[1..].join(";");
        let invalid = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np05.bytecode,lua55,s,rivetlua-core;rivetlua-compiler,{missing},PASS,\np05.bytecode,lua54-i64f64,s,rivetlua-core;rivetlua-compiler,{ids};BC-001,PASS,"
        );
        assert!(validate_p05_csv_cases(&invalid).is_err());

        let records = P05_CASES
            .iter()
            .map(|id| {
                (
                    id.to_string(),
                    "input\ttext".to_string(),
                    "actual\ntext".to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert!(validate_p05_records("lua55-i64f64", &records).is_ok());
        assert!(validate_p05_records("lua55-i64f64", &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate[1].0 = duplicate[0].0.clone();
        assert!(validate_p05_records("lua55-i64f64", &duplicate).is_err());
        assert!(p05_child_status("lua55-i64f64", false, "failed").is_err());

        let root = std::env::temp_dir().join(format!("rivetlua-p05-report-{}", std::process::id()));
        let path = write_p05_case_report(
            &root,
            "BC-ERR-001",
            "lua55-i64f64",
            "lua55",
            "return 1\n",
            "Verify\tactual",
        )
        .unwrap();
        let output = Command::new("python3")
            .args(["-c", "import json,sys; report=json.load(open(sys.argv[1])); assert report['mode'] == 'verify'; assert report['actual'] == 'Verify' + chr(9) + 'actual'; assert report['input'] == 'return 1' + chr(10)"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn phase_dependency_graph_is_complete_and_rejects_missing_owner_or_conflict() {
        let graph = include_str!("../../spec/phase-dependencies.csv");
        assert!(validate_phase_dependency_graph(graph).is_ok());
        assert!(
            validate_phase_dependency_graph(&graph.replacen(
                "DA-18,P05,P20,InstructionEffects canonical RVLU_V2 flags,IMPLEMENTED,P05",
                "DA-18,P05,P20,InstructionEffects canonical RVLU_V2 flags,IMPLEMENTED,P06",
                1,
            ))
            .is_err(),
            "DA-18 必須拒絕錯置 earliest_gate"
        );
        assert!(
            validate_phase_dependency_graph(&graph.replacen("DA-08,P08,P10", "DA-08,P09,P10", 1),)
                .is_err(),
            "DA-08 必須拒絕錯置 producer"
        );
        assert!(
            validate_phase_dependency_graph(&graph.replacen("DA-19,P12,P13", "DA-19,P11,P13", 1),)
                .is_err(),
            "非 critical edge 也必須拒絕錯置 producer"
        );
        assert!(
            validate_phase_dependency_graph(&graph.replacen("DA-01,P01,P06", "DA-01,P06,P01", 1),)
                .is_err()
        );
        assert!(
            validate_phase_dependency_graph(&graph.replacen("IMPLEMENTED", "CONFLICT", 1)).is_err()
        );
        assert!(validate_phase_dependency_graph(&graph.replacen("DA-14", "DA-99", 1)).is_err());
    }

    #[test]
    fn phase_dependency_graph_requires_official_chunk_and_artifact_edges() {
        let graph = include_str!("../../spec/phase-dependencies.csv");
        assert!(validate_phase_dependency_graph(graph).is_ok());
        for (row, wrong_owner, wrong_interface, wrong_status) in [
            (
                "DA-32,P05,P13,Lua55 Lua54 official chunk codec translation VerifiedModule,IMPLEMENTED,P13\n",
                "DA-32,P06,P13,Lua55 Lua54 official chunk codec translation VerifiedModule,IMPLEMENTED,P13\n",
                "DA-32,P05,P13,unknown official chunk contract,IMPLEMENTED,P13\n",
                "DA-32,P05,P13,Lua55 Lua54 official chunk codec translation VerifiedModule,CONTRACTED,P13\n",
            ),
            (
                "DA-33,P05,P14,immutable validated artifact metadata transport,IMPLEMENTED,P14\n",
                "DA-33,P06,P14,immutable validated artifact metadata transport,IMPLEMENTED,P14\n",
                "DA-33,P05,P14,unknown artifact contract,IMPLEMENTED,P14\n",
                "DA-33,P05,P14,immutable validated artifact metadata transport,CONTRACTED,P14\n",
            ),
        ] {
            assert!(graph.contains(row));
            assert!(validate_phase_dependency_graph(&graph.replacen(row, "", 1)).is_err());
            assert!(validate_phase_dependency_graph(&graph.replacen(row, wrong_owner, 1)).is_err());
            assert!(
                validate_phase_dependency_graph(&graph.replacen(row, wrong_interface, 1)).is_err()
            );
            assert!(
                validate_phase_dependency_graph(&graph.replacen(row, wrong_status, 1)).is_err()
            );
        }
    }

    #[test]
    fn p02_csv_cases_reject_missing_or_wrong_profile_case() {
        let ids = P02_CASES[1..].join(";");
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np02.lexer,lua55,s,rivetlua-compiler,{ids},PASS,\np02.lexer,lua54,s,rivetlua-compiler,{ids},PASS,"
        );
        assert!(validate_p02_csv_cases(&csv).is_err());
        let complete = P02_CASES.join(";");
        let wrong_profile = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np02.lexer,lua55-i64f64,s,rivetlua-compiler,{complete},PASS,\np02.lexer,lua54,s,rivetlua-compiler,{complete},PASS,"
        );
        assert!(validate_p02_csv_cases(&wrong_profile).is_err());
    }
    #[test]
    fn p02_case_report_is_valid_json() {
        let root = std::env::temp_dir().join(format!("rivetlua-p02-report-{}", std::process::id()));
        let path = write_p02_case_report(
            &root,
            "LEX-001",
            "lua55-i64f64",
            "lua55",
            "local x = 0x10",
            "[Token { kind: Keyword(Local), span: Span { start_byte: 0, end_byte: 5 } }]",
        )
        .unwrap();
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                "import json,sys; report=json.load(open(sys.argv[1])); assert report['input'] == 'local x = 0x10'; assert report['actual'].startswith('[Token { kind: Keyword(Local)')",
            ])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn p01_contracts_child_nonzero_exit_is_observable() {
        let output = Command::new("sh")
            .args([
                "-c",
                "printf 'P01_CASE\\tNUM-001\\tinput\\texpected\\texpected\\n'; exit 17",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(output.status.code(), Some(17));
        let error = validate_p01_contract_status("lua55-i64f64", &output.status, "case output")
            .unwrap_err();
        assert!(error.contains("exit status: 17"));
        assert!(error.contains("case output"));
    }

    #[test]
    fn p07_fixture_contains_ten_cases_two_profiles_and_honest_fuel_inputs() {
        let fixture = include_str!("../../tests/p07/vm-cases.fixture");
        let cases = parse_p07_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 10);
        assert_eq!(cases[0].id, "VM-001");
        assert_eq!(cases[4].input, "while true do end");
        assert!(cases[4].note.contains("compiler-produced"));
        assert!(cases[4].note.contains("implicit terminal Return(Fixed(0))"));
        assert_eq!(cases[6].input, cases[4].input);
        assert!(parse_p07_fixture(&fixture.replacen("VM-010", "VM-MISSING", 1)).is_err());
        assert!(parse_p07_fixture(&fixture.replacen("VM-010", "VM-001", 1)).is_err());
        assert!(
            parse_p07_fixture(&fixture.replace("lua54-i64f64|lua54", "lua54-i64f64|common"))
                .is_err()
        );
    }

    #[test]
    fn p07_csv_and_records_reject_missing_duplicate_wrong_profile_or_expected_result() {
        let ids = P07_CASES.join(";");
        let row = |profile: &str, test_ids: &str| {
            format!(
                "p07.vm,{profile},docs/plane/P07.md#6-正常與錯誤案例,rivetlua-runtime,{test_ids},PASS,"
            )
        };
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\n{}\n{}",
            row("lua55", &ids),
            row("lua54", &ids)
        );
        assert!(validate_csv(&csv).is_ok());
        assert!(validate_p07_csv_cases(&csv).is_ok());
        assert!(validate_p07_csv_cases(&csv.replacen("VM-010", "VM-MISSING", 1)).is_err());
        assert!(validate_p07_csv_cases(&csv.replacen("VM-010", "VM-001", 1)).is_err());
        assert!(
            validate_p07_csv_cases(&csv.replacen("p07.vm,lua54,", "p07.vm,common,", 1)).is_err()
        );

        let fixture = parse_p07_fixture(include_str!("../../tests/p07/vm-cases.fixture")).unwrap();
        let records_for = |profile: &str| {
            fixture
                .iter()
                .map(|case| {
                    (
                        case.id.clone(),
                        profile.to_owned(),
                        case.input.clone(),
                        format!("{}; fuel_remaining=3; pc=4", case.expected),
                    )
                })
                .collect::<Vec<_>>()
        };
        let records = records_for("lua55-i64f64");
        assert!(validate_p07_records("lua55-i64f64", &fixture, &records).is_ok());
        assert!(validate_p07_records("lua55-i64f64", &fixture, &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate[9] = duplicate[0].clone();
        assert!(validate_p07_records("lua55-i64f64", &fixture, &duplicate).is_err());
        let mut wrong_profile = records.clone();
        wrong_profile[0].1 = "lua54-i64f64".into();
        assert!(validate_p07_records("lua55-i64f64", &fixture, &wrong_profile).is_err());
        let mut wrong_expected = records.clone();
        wrong_expected[0].3 = "Returned([Integer(9)])".into();
        assert!(validate_p07_records("lua55-i64f64", &fixture, &wrong_expected).is_err());
    }

    #[test]
    fn p07_case_report_contains_outcome_diagnostic_fuel_and_command() {
        let root = std::env::temp_dir().join(format!("rivetlua-p07-report-{}", std::process::id()));
        let case = parse_p07_fixture(include_str!("../../tests/p07/vm-cases.fixture"))
            .unwrap()
            .remove(4);
        let path = p07_case_report(
            &root,
            &case,
            "lua55-i64f64",
            "lua55",
            "Aborted(FuelExhausted); module=compiler_verified_rvlu_v2; implicit_return=Fixed(0); p05_compiler_used=true; fuel_initial=17; fuel_remaining=0; pc=5",
        )
        .unwrap();
        let output = Command::new("python3")
            .args([
                "-c",
                "import json,sys; r=json.load(open(sys.argv[1])); assert r['case_id']=='VM-005' and r['profile']=='lua55-i64f64' and r['lua_profile']=='lua55'; assert r['mode']=='fuel' and r['input']=='while true do end'; assert 'compiler-produced' in r['diagnostic'] and 'implicit terminal Return(Fixed(0))' in r['diagnostic']; assert 'fuel_initial=17' in r['actual'] and 'fuel_remaining=0' in r['actual'] and 'p05_compiler_used=true' in r['actual'] and 'implicit_return=Fixed(0)' in r['actual']; assert '--test p07_contracts' in r['command'] and r['exit_code']==0 and r['status']=='PASS' and r['report_path']",
            ])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn p06_fixture_requires_two_mapped_profiles_and_eight_unique_cases() {
        let fixture = include_str!("../../tests/p06/heap-cases.fixture");
        let parsed = parse_p06_fixture(fixture).unwrap();
        assert_eq!(parsed.len(), 8);
        assert_eq!(parsed[0].id, "HEAP-001");
        assert!(parse_p06_fixture(&fixture.replacen("HEAP-008", "HEAP-001", 1)).is_err());
        assert!(
            parse_p06_fixture(&fixture.replace("lua54-i64f64|lua54", "lua54-i64f64|common"))
                .is_err()
        );
        assert!(parse_p06_fixture(&fixture.replace("HEAP-003", "BROKEN-003")).is_err());
    }

    #[test]
    fn p06_test_summary_allows_added_tests_but_rejects_zero_or_failed_matches() {
        let expanded = "test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s";
        assert_eq!(p06_check_test_summary(expanded, 17).unwrap(), 23);
        let zero = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s";
        assert!(p06_check_test_summary(zero, 1).is_err());
        let failed = "test result: FAILED. 16 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s";
        assert!(p06_check_test_summary(failed, 17).is_err());
        assert!(p06_check_test_summary("no test summary", 1).is_err());
    }

    #[test]
    fn p06_with_value_doctests_require_one_compiling_and_one_compile_fail_example() {
        let output = "running 3 tests\ntest crates/rivetlua-runtime/src/heap.rs - heap::Vm::with_value (line 366) ... ok\ntest crates/rivetlua-runtime/src/heap.rs - heap::Vm::with_value (line 375) - compile fail ... ok\ntest extra ... ok\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.22s";
        assert_eq!(p06_check_with_value_doctests(output).unwrap(), 3);
        assert!(p06_check_with_value_doctests(&output.replace(" - compile fail", "")).is_err());
        assert!(
            p06_check_with_value_doctests(&output.replace(
                "heap::Vm::with_value (line 366)",
                "heap::Vm::other (line 366)"
            ))
            .is_err()
        );
    }

    #[test]
    fn p06_csv_requires_exact_profiles_and_case_sets() {
        let cases = P06_CASES.join(";");
        let row = |profile: &str, ids: &str| {
            format!(
                "p06.heap,{profile},docs/plane/P06.md#6-正常與錯誤案例,rivetlua-runtime,{ids},PASS,"
            )
        };
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\n{}\n{}",
            row("lua55", &cases),
            row("lua54", &cases)
        );
        assert!(validate_csv(&csv).is_ok());
        assert!(validate_p06_csv_cases(&csv).is_ok());
        assert!(validate_p06_csv_cases(&csv.replacen("HEAP-008", "HEAP-MISSING", 1)).is_err());
        assert!(validate_p06_csv_cases(&csv.replacen("HEAP-008", "HEAP-001", 1)).is_err());
        assert!(
            validate_p06_csv_cases(&csv.replacen("p06.heap,lua54,", "p06.heap,common,", 1))
                .is_err()
        );
    }

    #[test]
    fn p06_case_records_reject_missing_duplicate_wrong_profile_and_wrong_input() {
        let cases = P06_CASES
            .iter()
            .map(|id| P06FixtureCase {
                id: (*id).into(),
                input: format!("input-{id}"),
            })
            .collect::<Vec<_>>();
        let record = |case: &P06FixtureCase, profile: &str| {
            (
                case.id.clone(),
                profile.to_owned(),
                case.input.clone(),
                "observed result".to_owned(),
            )
        };
        let complete: Vec<_> = cases
            .iter()
            .map(|case| record(case, "lua55-i64f64"))
            .collect();
        assert!(validate_p06_records("lua55-i64f64", &cases, &complete).is_ok());
        assert!(validate_p06_records("lua55-i64f64", &cases, &complete[1..]).is_err());
        let mut duplicate = complete.clone();
        duplicate[7] = duplicate[0].clone();
        assert!(validate_p06_records("lua55-i64f64", &cases, &duplicate).is_err());
        let mut wrong_profile = complete.clone();
        wrong_profile[0].1 = "lua54-i64f64".into();
        assert!(validate_p06_records("lua55-i64f64", &cases, &wrong_profile).is_err());
        let mut wrong_input = complete;
        wrong_input[0].2 = "different input".into();
        assert!(validate_p06_records("lua55-i64f64", &cases, &wrong_input).is_err());
    }

    #[test]
    fn p06_case_report_contains_complete_profile_and_observation_json() {
        let root = std::env::temp_dir().join(format!("rivetlua-p06-report-{}", std::process::id()));
        let case = P06FixtureCase {
            id: "HEAP-001".into(),
            input: "VM-A handle 在 VM-B read 與 clone".into(),
        };
        let path = p06_case_report(
            &root,
            &case,
            "lua55-i64f64",
            "lua55",
            "E_WRONG_VM; root counts unchanged",
        )
        .unwrap();
        let heap_008_path = p06_case_report(
            &root,
            &P06FixtureCase {
                id: "HEAP-008".into(),
                input: "borrow and allocation boundary".into(),
            },
            "lua55-i64f64",
            "lua55",
            "同 profile with_value doctest 各一個正常與 compile_fail 範例通過",
        )
        .unwrap();
        let output = Command::new("python3")
            .args([
                "-c",
                "import json,sys; r=json.load(open(sys.argv[1])); assert r['case_id']=='HEAP-001'; assert r['profile']=='lua55-i64f64'; assert r['lua_profile']=='lua55'; assert r['exit_code']==0; assert r['status']=='PASS'; assert r['input'] and r['actual'] and r['command'] and r['diagnostic']; h=json.load(open(sys.argv[2])); assert h['case_id']=='HEAP-008' and '--doc with_value -- --show-output --test-threads=1' in h['command'] and h['actual']=='同 profile with_value doctest 各一個正常與 compile_fail 範例通過'",
            ])
            .arg(path)
            .arg(heap_008_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn p08_fixture_and_csv_reject_missing_duplicate_wrong_profile_and_bad_expected() {
        let fixture = include_str!("../../tests/p08/table-cases.fixture");
        let cases = parse_p08_fixture(fixture).unwrap();
        assert_eq!(cases.len(), P08_CASES.len());
        assert_eq!(cases[0].id, "TAB-001");
        assert!(parse_p08_fixture(&fixture.replacen("TAB-012", "TAB-MISSING", 1)).is_err());
        assert!(parse_p08_fixture(&fixture.replacen("TAB-012", "TAB-011", 1)).is_err());
        assert!(
            parse_p08_fixture(&fixture.replace("lua54-i64f64|lua54", "lua54-i64f64|common"))
                .is_err()
        );
        assert!(
            parse_p08_fixture(&fixture.replacen("|raw_get(Nil)|Nil|", "|raw_get(Nil)|Wrong|", 1))
                .is_err()
        );
        assert!(
            parse_p08_fixture(&fixture.replacen("case|TAB-012|", "broken|TAB-012|", 1)).is_err()
        );

        let ids = P08_CASES.join(";");
        let row = |profile: &str| {
            format!(
                "p08.string-table,{profile},docs/plane/P08.md#6-正常與錯誤案例,rivetlua-runtime,{ids},PASS,"
            )
        };
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\n{}\n{}",
            row("lua55"),
            row("lua54")
        );
        assert!(validate_csv(&csv).is_ok());
        assert!(validate_p08_csv_cases(&csv).is_ok());
        assert!(validate_p08_csv_cases(&csv.replacen("TAB-012", "TAB-MISSING", 1)).is_err());
        assert!(
            validate_p08_csv_cases(&csv.replacen(
                "p08.string-table,lua54,",
                "p08.string-table,common,",
                1
            ))
            .is_err()
        );
        assert!(
            validate_p08_csv_cases(&csv.replacen(",rivetlua-runtime,", ",runtime,", 1)).is_err()
        );
        assert!(validate_p08_csv_cases(&csv.replacen(",PASS,", ",FAIL,", 1)).is_err());
    }

    #[test]
    fn p09_fixture_requires_twelve_cases_for_each_exact_profile() {
        let fixture = include_str!("../../tests/p09/call-cases.fixture");
        let cases = parse_p09_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 24);
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.profile == "lua55-i64f64")
                .count(),
            12
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.profile == "lua54-i64f64")
                .count(),
            12
        );
        assert_eq!(P09_LUA55_CASES.len(), 12);
        assert_eq!(P09_LUA54_CASES.len(), 12);
    }

    #[test]
    fn p09_fixture_and_csv_reject_missing_duplicate_wrong_profile_and_bad_expected() {
        let fixture = include_str!("../../tests/p09/call-cases.fixture");
        let cases = parse_p09_fixture(fixture).unwrap();
        assert!(
            parse_p09_fixture(&fixture.replacen(
                "case|lua55-i64f64|CALL-013|",
                "case|lua55-i64f64|CALL-MISSING|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p09_fixture(&fixture.replacen(
                "case|lua55-i64f64|CALL-013|",
                "case|lua55-i64f64|CALL-001|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p09_fixture(
                &fixture.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|lua55")
            )
            .is_err()
        );
        assert!(
            parse_p09_fixture(
                &fixture.replace("case|lua55-i64f64|CALL-011|", "case|lua54-i64f64|CALL-011|")
            )
            .is_err()
        );
        assert!(
            parse_p09_fixture(
                &fixture.replace("case|lua54-i64f64|CALL-012|", "case|lua55-i64f64|CALL-012|")
            )
            .is_err()
        );
        assert!(
            parse_p09_fixture(&fixture.replacen("|Returned([7])|", "|Returned([8])|", 1)).is_err()
        );
        assert!(
            parse_p09_fixture(&fixture.replacen(
                "case|lua55-i64f64|CALL-013|",
                "broken|lua55-i64f64|CALL-013|",
                1
            ))
            .is_err()
        );
        assert_eq!(cases.len(), 24);

        let ids55 = P09_LUA55_CASES.join(";");
        let ids54 = P09_LUA54_CASES.join(";");
        let row = |profile: &str, ids: &str| {
            format!(
                "p09.function-closure,{profile},docs/plane/P09.md#6-正常與錯誤案例,rivetlua-runtime,{ids},PASS,"
            )
        };
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\n{}\n{}",
            row("lua55", &ids55),
            row("lua54", &ids54)
        );
        assert!(validate_csv(&csv).is_ok());
        assert!(validate_p09_csv_cases(&csv).is_ok());
        assert!(validate_p09_csv_cases(&csv.replacen("CALL-013", "CALL-MISSING", 1)).is_err());
        assert!(validate_p09_csv_cases(&csv.replacen("CALL-013", "CALL-001", 1)).is_err());
        assert!(
            validate_p09_csv_cases(&csv.replacen(
                "p09.function-closure,lua54,",
                "p09.function-closure,common,",
                1
            ))
            .is_err()
        );
        assert!(
            validate_p09_csv_cases(&csv.replacen(
                "p09.function-closure,lua55,",
                "p09.function-closure,lua55",
                1
            ))
            .is_err()
        );
        assert!(
            validate_p09_csv_cases(&format!("{csv}\np09.extra,lua55,s,m,CALL-001,PASS,")).is_err()
        );
    }

    #[test]
    fn p09_markers_require_each_profile_case_and_observed_close_execution() {
        let cases = parse_p09_fixture(include_str!("../../tests/p09/call-cases.fixture")).unwrap();
        let profile = "lua55-i64f64";
        let mut records = vec![
            ("CALL-001", "actual=Returned([1,2,1])"),
            ("CALL-002", "status=PASS"),
            ("CALL-003", "status=PASS"),
            ("CALL-004", "status=PASS"),
            ("CALL-005", "status=PASS"),
            ("CALL-006", "actual=Returned([3,9])"),
            ("CALL-007", "peak=1;value=7"),
            ("CALL-008", "peak=1025;error=E_STACK_LIMIT"),
            ("CALL-009", "actual=Returned([9,7,9])"),
            ("CALL-011", "count=1;value=9"),
            (
                "CALL-013",
                "peak=2;path_pc=13;count=3;actual=Returned;close_order=LIFO",
            ),
        ]
        .into_iter()
        .map(|(id, actual)| super::P09Record {
            id: id.into(),
            profile: profile.into(),
            actual: actual.into(),
        })
        .collect::<Vec<_>>();
        for id in [
            "CALL-010-fixed-fewer",
            "CALL-010-vararg-tail-nil",
            "CALL-010-fixed-zero",
            "CALL-010-fixed-exact",
            "CALL-010-fixed-excess",
            "CALL-010-vararg-fixed",
            "CALL-010-setter-argument",
            "CALL-010-vararg-GC",
        ] {
            records.push(super::P09Record {
                id: id.into(),
                profile: profile.into(),
                actual: "status=PASS".into(),
            });
        }
        records.push(super::P09Record {
            id: "CALL-011-BODY".into(),
            profile: profile.into(),
            actual: "count=1;value=9".into(),
        });
        let actuals = validate_p09_records(profile, &cases, &records).unwrap();
        assert_eq!(actuals.len(), 12);
        assert_eq!(
            actuals["CALL-013"],
            "Returned([nil,1,nil]);peak_frames=2;path_pc=13;tail_reuse=false;result_count=3;close_order=LIFO"
        );
        assert!(actuals["CALL-013"].contains("tail_reuse=false"));
        assert!(actuals["CALL-013"].contains("result_count=3"));
        assert!(actuals["CALL-013"].contains("close_order=LIFO"));
        assert!(actuals["CALL-013"].contains("Returned([nil,1,nil])"));
        assert!(validate_p09_records(profile, &cases, &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate.push(duplicate[0].clone());
        assert!(validate_p09_records(profile, &cases, &duplicate).is_err());
        let mut wrong_profile = records.clone();
        wrong_profile[0].profile = "lua54-i64f64".into();
        assert!(validate_p09_records(profile, &cases, &wrong_profile).is_err());
        let mut wrong_stack_error = records.clone();
        wrong_stack_error
            .iter_mut()
            .find(|record| record.id == "CALL-008")
            .unwrap()
            .actual = "peak=1025;error=E_OTHER".into();
        assert!(validate_p09_records(profile, &cases, &wrong_stack_error).is_err());
        let mut wrong_close_order = records.clone();
        wrong_close_order
            .iter_mut()
            .find(|record| record.id == "CALL-013")
            .unwrap()
            .actual = "peak=2;path_pc=13;count=3;actual=Returned;close_order=FIFO".into();
        assert!(validate_p09_records(profile, &cases, &wrong_close_order).is_err());
        let mut missing_close_order = records.clone();
        missing_close_order
            .iter_mut()
            .find(|record| record.id == "CALL-013")
            .unwrap()
            .actual = "peak=2;path_pc=13;count=3;actual=Returned".into();
        assert!(validate_p09_records(profile, &cases, &missing_close_order).is_err());
        let mut pending_close_only = records.clone();
        pending_close_only
            .iter_mut()
            .find(|record| record.id == "CALL-013")
            .unwrap()
            .actual = "peak=2;path_pc=13;count=3;actual=PendingClose;close_order=LIFO".into();
        assert!(validate_p09_records(profile, &cases, &pending_close_only).is_err());
        let mut nonnumeric_path_pc = records.clone();
        nonnumeric_path_pc
            .iter_mut()
            .find(|record| record.id == "CALL-013")
            .unwrap()
            .actual = "peak=2;path_pc=pc;count=3;actual=Returned;close_order=LIFO".into();
        assert!(validate_p09_records(profile, &cases, &nonnumeric_path_pc).is_err());
        let mut duplicate_marker_field = records.clone();
        duplicate_marker_field
            .iter_mut()
            .find(|record| record.id == "CALL-013")
            .unwrap()
            .actual = "peak=2;path_pc=13;count=3;actual=Returned;close_order=LIFO;peak=2".into();
        assert!(validate_p09_records(profile, &cases, &duplicate_marker_field).is_err());

        let mut wrong_profile_marker = records.clone();
        wrong_profile_marker.push(super::P09Record {
            id: "CALL-012".into(),
            profile: profile.into(),
            actual: "status=REJECTED".into(),
        });
        assert!(validate_p09_records(profile, &cases, &wrong_profile_marker).is_err());
        let mut unknown_formal_marker = records.clone();
        unknown_formal_marker.push(super::P09Record {
            id: "CALL-014".into(),
            profile: profile.into(),
            actual: "status=PASS".into(),
        });
        assert!(validate_p09_records(profile, &cases, &unknown_formal_marker).is_err());

        let lua54_profile = "lua54-i64f64";
        let mut lua54_records = records
            .iter()
            .filter(|record| record.id != "CALL-011" && record.id != "CALL-011-BODY")
            .cloned()
            .map(|mut record| {
                record.profile = lua54_profile.into();
                record
            })
            .collect::<Vec<_>>();
        lua54_records.push(super::P09Record {
            id: "CALL-012".into(),
            profile: lua54_profile.into(),
            actual: "status=REJECTED".into(),
        });
        assert!(validate_p09_records(lua54_profile, &cases, &lua54_records).is_ok());
        lua54_records.push(super::P09Record {
            id: "CALL-011".into(),
            profile: lua54_profile.into(),
            actual: "count=1;value=9".into(),
        });
        assert!(validate_p09_records(lua54_profile, &cases, &lua54_records).is_err());

        let marker = "P09_CASE\tCALL-001\tlua55-i64f64\tactual=Returned([1,2,1])\n";
        assert_eq!(p09_records_from_output(profile, marker).unwrap().len(), 1);
        assert!(p09_records_from_output(profile, "P09_CASE\tCALL-001\tlua55\t\n").is_err());
    }

    #[test]
    fn p09_call_013_expected_shape_requires_observed_close_execution() {
        let expected = "Returned([nil,1,nil]);peak_frames=2;path_pc=numeric;tail_reuse=false;result_count=3;close_order=LIFO";
        assert_eq!(
            super::p09_expected_shape("CALL-013"),
            Some(("runtime-close", expected))
        );
        let cases = parse_p09_fixture(include_str!("../../tests/p09/call-cases.fixture")).unwrap();
        let case = cases
            .iter()
            .find(|case| case.profile == "lua55-i64f64" && case.id == "CALL-013")
            .unwrap();
        assert_eq!(case.mode, "runtime-close");
        assert_eq!(case.expected, expected);
        assert!(case.input.contains("closer_a") && case.input.contains("closer_b"));
        assert!(case.note.contains("LIFO") && case.note.contains("__close"));
    }

    #[test]
    fn p09_prerequisites_require_pass_aggregates_and_complete_check_fields() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p09-prerequisites-{}", std::process::id()));
        initialize_gate_test_repository(&root);
        let reports = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&reports).unwrap();
        let check = |name: &str, exit_code: i32| {
            format!(
                "{{\"name\":\"{name}\",\"command\":\"run {name}\",\"exit_code\":{exit_code},\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}}"
            )
        };
        for phase in ["P00", "P01", "P02", "P03", "P04", "P05", "P06", "P08"] {
            let exit_code = if phase == "P00" { 1 } else { 0 };
            std::fs::write(
                reports.join(format!("gate-{phase}.json")),
                format!(
                    "{{\"status\":\"PASS\",\"checks\":[{}]}}\n",
                    check("smoke", exit_code)
                ),
            )
            .unwrap();
        }
        let p07_checks = ["p01-before", "p05-before", "p06-before", "p00-p06-before"]
            .into_iter()
            .map(|name| check(name, 0))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            reports.join("gate-P07.json"),
            format!("{{\"status\":\"PASS\",\"checks\":[{p07_checks}]}}\n"),
        )
        .unwrap();
        stamp_gate_test_reports(&root);
        assert!(validate_p09_prior_reports(&root).is_ok());

        std::fs::write(
            reports.join("gate-P08.json"),
            "garbage{\"status\":\"PASS\",\"checks\":[]}\n",
        )
        .unwrap();
        assert!(validate_p09_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P08.json"),
            "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"run\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\"}]}\n",
        )
        .unwrap();
        assert!(validate_p09_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P08.json"),
            format!(
                "{{\"status\":\"FAIL\",\"checks\":[{}]}}\n",
                check("smoke", 0)
            ),
        )
        .unwrap();
        assert!(validate_p09_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P08.json"),
            format!(
                "{{\"status\":\"PASS\",\"checks\":[{}]}}\n",
                check("smoke", 0)
            ),
        )
        .unwrap();
        std::fs::write(
            reports.join("gate-P07.json"),
            format!(
                "{{\"status\":\"PASS\",\"checks\":[{}]}}\n",
                check("smoke", 0)
            ),
        )
        .unwrap();
        assert!(validate_p09_prior_reports(&root).is_err());
        std::fs::remove_file(reports.join("gate-P08.json")).unwrap();
        assert!(validate_p09_prior_reports(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p09_contract_summary_requires_exactly_eleven_successful_tests() {
        assert!(p09_check_test_summary(
            "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
        )
        .is_ok());
        for summary in [
            "test result: ok. 0 passed; 0 failed; 11 ignored; 0 measured; 11 filtered out; finished in 0.00s",
            "test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s",
            "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            "test result: FAILED. 10 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
        ] {
            assert!(p09_check_test_summary(summary).is_err());
        }
    }

    #[test]
    fn p08_markers_validate_twelve_cases_and_both_internal_traversal_orders() {
        let cases = parse_p08_fixture(include_str!("../../tests/p08/table-cases.fixture")).unwrap();
        let actuals = [
            "Ok(Returned([Integer(2)]))",
            "Ok(Returned([Integer(7)]))",
            "Ok(Returned([Boolean(false)]))",
            "Err(NilTableKey)",
            "Err(NaNTableKey)",
            "Ok(Returned([Nil]))",
            "Ok(Returned([Integer(2)]))",
            "stack_objects_reclaimed,true;live,true;removed,5;table_reclaimed,1;reserved,0",
            "fields_unchanged,true;roots,1;reserved,0;capacity=(8, 8)",
            "Ok(Nil)",
            "Ok(Nil)",
        ];
        let mut records = Vec::new();
        let mut actual_index = 0;
        for case in &cases {
            if case.id == "TAB-010" {
                for order in ["[0, 1, 2, 3, 4]", "[4, 3, 2, 1, 0]"] {
                    records.push(super::P08Record {
                        id: case.id.clone(),
                        profile: "lua55-i64f64".into(),
                        input: order.into(),
                        expected: "5".into(),
                        actual: "same five-key map".into(),
                        diagnostic: String::new(),
                    });
                }
                continue;
            }
            let input = if case.mode == "compiler-vm" {
                format!("{:?}", case.input.as_bytes())
            } else {
                case.input.clone()
            };
            let diagnostic = if matches!(case.id.as_str(), "TAB-004" | "TAB-005") {
                "E_TABLE_INVALID_KEY".into()
            } else {
                String::new()
            };
            records.push(super::P08Record {
                id: case.id.clone(),
                profile: "lua55-i64f64".into(),
                input,
                expected: case.expected.clone(),
                actual: actuals[actual_index].into(),
                diagnostic,
            });
            actual_index += 1;
        }
        assert!(validate_p08_records("lua55-i64f64", &cases, &records).is_ok());
        assert!(validate_p08_records("lua55-i64f64", &cases, &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate.push(duplicate[0].clone());
        assert!(validate_p08_records("lua55-i64f64", &cases, &duplicate).is_err());
        let mut wrong_profile = records.clone();
        wrong_profile[0].profile = "lua54-i64f64".into();
        assert!(validate_p08_records("lua55-i64f64", &cases, &wrong_profile).is_err());

        let marker_output = "P08_CASE\tTAB-010\tlua55-i64f64\tinput_order=[0, 1, 2, 3, 4]\texpected_fields=5\tactual={one: 1}\nP08_CASE\tTAB-010\tlua55-i64f64\tinput_order=[4, 3, 2, 1, 0]\texpected_fields=5\tactual={one: 1}\n";
        let markers = p08_records_from_output("lua55-i64f64", marker_output).unwrap();
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0].id, "TAB-010");
        assert_eq!(markers[0].expected, "5");
        assert!(
            p08_records_from_output(
                "lua55-i64f64",
                "P08_CASE\tTAB-010\tlua55\tinput_order=x\tactual=x\n"
            )
            .is_err()
        );
    }

    #[test]
    fn strict_json_parser_validates_complete_json_documents() {
        let valid = StrictJsonParser::parse(
            r#" {"string":"quote:\" slash:\/ pair:\uD83D\uDE00","number":-12.5e+2,"yes":true,"no":false,"null":null,"array":[0,-1,1.25,2e4]} "#,
        )
        .unwrap();
        assert_eq!(valid.get("yes"), Some(&StrictJsonValue::Bool(true)));
        assert_eq!(valid.get("no"), Some(&StrictJsonValue::Bool(false)));
        for invalid in [
            r#"garbage{"status":"PASS"}"#,
            r#"{"status":"PASS","status":"FAIL"}"#,
            r#"{"number":01}"#,
            r#"{"number":1.}"#,
            r#"{"number":1e}"#,
            r#"{"value":"\q"}"#,
            r#"{"value":"\uD800"}"#,
            r#"{"value":"\uDC00"}"#,
            r#"{"value":"raw
newline"}"#,
            r#"{"array":[true,]}"#,
            r#"{"status":"PASS"} trailing"#,
        ] {
            assert!(
                StrictJsonParser::parse(invalid).is_err(),
                "parser accepted invalid JSON: {invalid:?}"
            );
        }
    }

    #[test]
    fn p08_prerequisite_report_validation_requires_all_eight_pass_json_reports() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p08-prerequisites-{}", std::process::id()));
        initialize_gate_test_repository(&root);
        let reports = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&reports).unwrap();
        for phase in ["P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07"] {
            let report = if phase == "P07" {
                "{\"status\":\"PASS\",\"checks\":[{\"name\":\"p01-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p05-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p06-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p00-p06-before\",\"exit_code\":0,\"status\":\"PASS\"}]}\n"
            } else {
                "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"exit_code\":0,\"status\":\"PASS\"}]}\n"
            };
            std::fs::write(reports.join(format!("gate-{phase}.json")), report).unwrap();
        }
        stamp_gate_test_reports(&root);
        assert!(validate_p08_prior_reports(&root).is_ok());
        std::fs::write(
            reports.join("gate-P07.json"),
            "garbage{\"status\":\"PASS\",\"checks\":[{\"name\":\"p01-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p05-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p06-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p00-p06-before\",\"exit_code\":0,\"status\":\"PASS\"}]}\n",
        )
        .unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P07.json"),
            "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"exit_code\":0,\"status\":\"PASS\"}],\"metadata\":[{\"name\":\"p01-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p05-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p06-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p00-p06-before\",\"exit_code\":0,\"status\":\"PASS\"}]}\n",
        )
        .unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P07.json"),
            "{\"status\":\"PASS\",\"checks\":[{\"name\":\"p01-before\",\"exit_code\":7,\"status\":\"PASS\"},{\"name\":\"p05-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p06-before\",\"exit_code\":0,\"status\":\"PASS\"},{\"name\":\"p00-p06-before\",\"exit_code\":0,\"status\":\"PASS\"}]}\n",
        )
        .unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P07.json"),
            "{\"status\":\"PASS\",\"checks\":[]}\n",
        )
        .unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::write(
            reports.join("gate-P07.json"),
            "{\"status\":\"FAIL\",\"checks\":[]}\n",
        )
        .unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::remove_file(reports.join("gate-P07.json")).unwrap();
        assert!(validate_p08_prior_reports(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p10_fixture_and_csv_require_all_cases_for_both_profiles() {
        let fixture = include_str!("../../tests/p10/metamethod-cases.fixture");
        let cases = parse_p10_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 20);
        assert_eq!(P10_CASES.len(), 10);
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            assert_eq!(
                cases.iter().filter(|case| case.profile == profile).count(),
                10
            );
        }
        assert!(
            parse_p10_fixture(&fixture.replacen(
                "case|lua55-i64f64|META-010|",
                "case|lua55-i64f64|META-MISSING|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p10_fixture(&fixture.replacen(
                "case|lua55-i64f64|META-010|",
                "case|lua55-i64f64|META-009|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p10_fixture(
                &fixture.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|lua55")
            )
            .is_err()
        );
        assert!(
            parse_p10_fixture(
                &fixture.replace("case|lua55-i64f64|META-009|", "case|lua54-i64f64|META-009|")
            )
            .is_err()
        );
        assert!(
            parse_p10_fixture(&fixture.replacen(
                "LuaError(E_METATABLE_CHAIN_LIMIT)",
                "LuaError(E_OTHER)",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p10_fixture(&fixture.replacen(
                "case|lua55-i64f64|META-010|",
                "broken|lua55-i64f64|META-010|",
                1
            ))
            .is_err()
        );

        let csv = include_str!("../../spec/compatibility.csv");
        assert!(validate_csv(csv).is_ok());
        assert!(validate_p10_csv_cases(csv).is_ok());
        assert!(validate_p10_csv_cases(&csv.replacen("META-010", "META-MISSING", 1)).is_err());
        assert!(validate_p10_csv_cases(&csv.replacen("META-010", "META-001", 1)).is_err());
        assert!(
            validate_p10_csv_cases(&csv.replace("p10.metatable,lua54,", "p10.metatable,common,"))
                .is_err()
        );
        assert!(
            validate_p10_csv_cases(&csv.replace("p10.metatable,lua55,", "p10.metatable,lua55"))
                .is_err()
        );
        assert!(
            validate_p10_csv_cases(&format!("{csv}p10.extra,lua55,s,m,META-001,PASS,\n")).is_err()
        );
    }

    #[test]
    fn p10_markers_validate_actuals_profiles_diagnostics_and_uniqueness() {
        let cases =
            parse_p10_fixture(include_str!("../../tests/p10/metamethod-cases.fixture")).unwrap();
        let profile = "lua55-i64f64";
        let diagnostic = "event=__index;operands=target=t;pending=not-exposed;frame_pc=not-exposed;resume=result=7;fuel=default;roots=2;error=none;aborted=false;protected_boundary=run;internal_unit=vm::tests::p10_3_pending_op_resume";
        let records: Vec<_> = cases
            .iter()
            .filter(|case| case.profile == profile)
            .map(|case| super::P10Record {
                id: case.id.clone(),
                profile: profile.into(),
                actual: case.expected.clone(),
                diagnostic: diagnostic.into(),
            })
            .collect();
        let output = records
            .iter()
            .map(|record| {
                format!(
                    "P10_CASE\t{}\t{}\tactual={}\tdiagnostic={}\n",
                    record.id, record.profile, record.actual, record.diagnostic
                )
            })
            .collect::<String>();
        let parsed = p10_records_from_output(profile, &output).unwrap();
        assert_eq!(parsed.len(), 10);
        assert_eq!(
            validate_p10_records(profile, &cases, &parsed)
                .unwrap()
                .len(),
            10
        );
        assert!(p10_diagnostic_is_complete(diagnostic));
        assert!(!p10_diagnostic_is_complete("event=__index;operands=x"));
        assert!(
            p10_records_from_output(
                profile,
                "P10_CASE\tMETA-001\tlua54-i64f64\tactual=x\tdiagnostic=x\n"
            )
            .is_err()
        );
        assert!(validate_p10_records(profile, &cases, &parsed[1..]).is_err());

        let mut duplicate = parsed.clone();
        duplicate.push(duplicate[0].clone());
        assert!(validate_p10_records(profile, &cases, &duplicate).is_err());
        let mut wrong_profile = parsed.clone();
        wrong_profile[0].profile = "lua54-i64f64".into();
        assert!(validate_p10_records(profile, &cases, &wrong_profile).is_err());
        let mut unknown = parsed.clone();
        unknown[0].id = "META-011".into();
        assert!(validate_p10_records(profile, &cases, &unknown).is_err());
        let mut wrong_actual = parsed.clone();
        wrong_actual[0].actual = "Returned([Integer(0)])".into();
        assert!(validate_p10_records(profile, &cases, &wrong_actual).is_err());
        let mut incomplete_diagnostic = parsed.clone();
        incomplete_diagnostic[0].diagnostic = "event=__index".into();
        assert!(validate_p10_records(profile, &cases, &incomplete_diagnostic).is_err());
        let mut cross_profile = parsed;
        cross_profile.push(super::P10Record {
            id: "META-001".into(),
            profile: "lua54-i64f64".into(),
            actual: "Returned([Boolean(false)])".into(),
            diagnostic: diagnostic.into(),
        });
        assert!(validate_p10_records(profile, &cases, &cross_profile).is_err());
    }

    #[test]
    fn p10_contract_summary_requires_exactly_ten_successes() {
        assert!(p10_check_test_summary(
            "test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.01s"
        )
        .is_ok());
        for output in [
            "test result: ok. 0 passed; 0 failed; 16 filtered out",
            "test result: ok. 9 passed; 0 failed; 7 filtered out",
            "test result: ok. 11 passed; 0 failed; 5 filtered out",
            "test result: ok. 10 passed; 1 failed; 5 filtered out",
            "test result: FAILED. 0 passed; 1 failed",
        ] {
            assert!(
                p10_check_test_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
        assert!(
            p10_check_unit_summary("test result: ok. 7 passed; 0 failed; 100 filtered out").is_ok()
        );
        for output in [
            "test result: ok. 0 passed; 0 failed; 107 filtered out",
            "test result: ok. 6 passed; 0 failed; 101 filtered out",
            "test result: ok. 8 passed; 0 failed; 99 filtered out",
            "test result: ok. 7 passed; 1 failed; 99 filtered out",
        ] {
            assert!(
                p10_check_unit_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
    }

    #[test]
    fn p10_prerequisites_require_complete_pass_reports_p00_through_p09() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p10-prerequisites-{}", std::process::id()));
        initialize_gate_test_repository(&root);
        let reports = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&reports).unwrap();
        for phase in [
            "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09",
        ] {
            let checks = if phase == "P07" {
                [
                    "p01-before",
                    "p05-before",
                    "p06-before",
                    "p00-p06-before",
                ]
                .into_iter()
                .map(|name| {
                    format!("{{\"name\":\"{name}\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}}")
                })
                .collect::<Vec<_>>()
                .join(",")
            } else {
                let exit_code = if phase == "P00" { 1 } else { 0 };
                format!(
                    "{{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":{exit_code},\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}}"
                )
            };
            std::fs::write(
                reports.join(format!("gate-{phase}.json")),
                format!("{{\"status\":\"PASS\",\"checks\":[{checks}]}}\n"),
            )
            .unwrap();
        }
        stamp_gate_test_reports(&root);
        assert!(validate_p10_prior_reports(&root).is_ok());
        std::fs::write(root.join("source.rs"), b"changed").unwrap();
        let stale = validate_p10_prior_reports(&root).err().unwrap();
        assert!(
            stale.contains("P00") && stale.contains("source_digest"),
            "{stale}"
        );
        std::fs::write(root.join("source.rs"), b"initial").unwrap();
        assert!(validate_p10_prior_reports(&root).is_ok());
        let p09 = reports.join("gate-P09.json");
        let valid_p09 = std::fs::read_to_string(&p09).unwrap();
        std::fs::write(
            &p09,
            valid_p09.replacen("\"source_digest\"", "\"missing_digest\"", 1),
        )
        .unwrap();
        assert!(
            validate_p10_prior_reports(&root)
                .err()
                .unwrap()
                .contains("P09")
        );
        std::fs::write(
            &p09,
            valid_p09.replacen("\"source_digest\":\"", "\"source_digest\":\"broken", 1),
        )
        .unwrap();
        assert!(
            validate_p10_prior_reports(&root)
                .err()
                .unwrap()
                .contains("P09")
        );
        std::fs::write(&p09, &valid_p09).unwrap();
        for invalid in [
            "{\"status\":\"FAIL\",\"checks\":[]}\n",
            "garbage\n",
            "{\"status\":\"PASS\",\"checks\":[{\"name\":\"missing-fields\",\"status\":\"PASS\"}]}\n",
        ] {
            std::fs::write(reports.join("gate-P09.json"), invalid).unwrap();
            assert!(validate_p10_prior_reports(&root).is_err());
            std::fs::write(
                reports.join("gate-P09.json"),
                "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n",
            )
            .unwrap();
        }
        std::fs::write(
            reports.join("gate-P07.json"),
            "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n",
        )
        .unwrap();
        assert!(validate_p10_prior_reports(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p11_fixture_and_csv_require_all_formal_cases_for_both_profiles() {
        let fixture = include_str!("../../tests/p11/error-coroutine-close-cases.fixture");
        let cases = parse_p11_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 32);
        assert_eq!(P11_CASE_IDS.len(), 16);
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            let selected: Vec<_> = cases
                .iter()
                .filter(|case| case.profile == profile)
                .collect();
            assert_eq!(selected.len(), 16);
            assert_eq!(
                selected
                    .iter()
                    .filter(|case| case.id.starts_with("ERR-"))
                    .count(),
                5
            );
            assert_eq!(
                selected
                    .iter()
                    .filter(|case| case.id.starts_with("COR-"))
                    .count(),
                6
            );
            assert_eq!(
                selected
                    .iter()
                    .filter(|case| case.id.starts_with("CLOSE-"))
                    .count(),
                5
            );
        }
        assert!(
            parse_p11_fixture(&fixture.replacen(
                "case|lua55-i64f64|ERR-005|",
                "case|lua55-i64f64|ERR-MISSING|",
                1
            ))
            .is_err()
        );
        let err004 = fixture
            .lines()
            .find(|line| line.starts_with("case|lua55-i64f64|ERR-004|"))
            .unwrap();
        assert!(parse_p11_fixture(&format!("{fixture}{err004}\n")).is_err());
        assert!(
            parse_p11_fixture(
                &fixture.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|lua55")
            )
            .is_err()
        );
        assert!(
            parse_p11_fixture(
                &fixture.replace("case|lua55-i64f64|ERR-004|", "case|lua54-i64f64|ERR-004|")
            )
            .is_err()
        );
        assert!(
            parse_p11_fixture(&fixture.replacen(
                "|identity=preserved;nested=nearest;host_root=owned|",
                "|identity=stringified;nested=nearest;host_root=owned|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p11_fixture(&fixture.replacen(
                "|P11_STAGE:err_case_001|",
                "|P11_STAGE:unknown|",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p11_fixture(&fixture.replacen(
                "case|lua55-i64f64|ERR-004|",
                "broken|lua55-i64f64|ERR-004|",
                1
            ))
            .is_err()
        );

        let csv = include_str!("../../spec/compatibility.csv");
        assert!(validate_csv(csv).is_ok());
        assert!(validate_p11_csv_cases(csv).is_ok());
        assert!(validate_p11_csv_cases(&csv.replacen("ERR-005", "ERR-MISSING", 1)).is_err());
        assert!(validate_p11_csv_cases(&csv.replacen("ERR-005", "ERR-001", 1)).is_err());
        assert!(
            validate_p11_csv_cases(&csv.replace(
                "p11.errors-coroutines-close,lua54,",
                "p11.errors-coroutines-close,common,"
            ))
            .is_err()
        );
        let row55 = csv
            .lines()
            .find(|line| line.starts_with("p11.errors-coroutines-close,lua55,"))
            .unwrap();
        assert!(
            validate_p11_csv_cases(&csv.replacen(row55, row55.trim_end_matches(','), 1)).is_err()
        );
        let row54 = csv
            .lines()
            .find(|line| line.starts_with("p11.errors-coroutines-close,lua54,"))
            .unwrap();
        assert!(validate_p11_csv_cases(&csv.replacen(&format!("{row54}\n"), "", 1)).is_err());
        assert!(
            validate_p11_csv_cases(&format!(
                "{csv}p11.extra,lua55,docs/plane/P11.md,rivetlua-runtime,ERR-001,PASS,\n"
            ))
            .is_err()
        );
        assert!(
            validate_p11_csv_cases(&csv.replacen(
                "p11.errors-coroutines-close,lua55,",
                "p11.errors-coroutines-close,lua55",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn p11_markers_require_one_real_formal_marker_per_profile() {
        let cases = parse_p11_fixture(include_str!(
            "../../tests/p11/error-coroutine-close-cases.fixture"
        ))
        .unwrap();
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            let mut output = String::new();
            for spec in P11_CASE_SPECS {
                if spec.marker.starts_with("P11_CASE:") {
                    output.push_str(&format!(
                        "P11_CASE\t{}\t{profile}\tstatus=PASS;actual={};diagnostic=generic-for;error-identity=asserted\n",
                        spec.id, spec.expected
                    ));
                } else {
                    let marker = spec.marker.strip_prefix("P11_STAGE:").unwrap();
                    output.push_str(&format!(
                        "P11_STAGE\t{marker}\t{profile}\tstatus=PASS;{}\n",
                        spec.expected
                    ));
                }
            }
            let records = p11_records_from_output(profile, &output).unwrap();
            assert_eq!(records.len(), 16);
            let actuals = validate_p11_records(profile, &cases, &records).unwrap();
            assert_eq!(actuals.len(), 16);
            assert!(actuals.contains_key("ERR-001"));
            assert!(actuals.contains_key("COR-006"));
            assert!(actuals.contains_key("CLOSE-005"));
        }

        let profile = "lua55-i64f64";
        let mut output = String::new();
        for spec in P11_CASE_SPECS {
            if spec.marker.starts_with("P11_CASE:") {
                output.push_str(&format!(
                    "P11_CASE\t{}\t{profile}\tstatus=PASS;actual={};diagnostic=observed\n",
                    spec.id, spec.expected
                ));
            } else {
                output.push_str(&format!(
                    "P11_STAGE\t{}\t{profile}\tstatus=PASS;{}\n",
                    spec.marker.strip_prefix("P11_STAGE:").unwrap(),
                    spec.expected
                ));
            }
        }
        let records = p11_records_from_output(profile, &output).unwrap();
        assert!(validate_p11_records(profile, &cases, &records[1..]).is_err());
        let mut duplicate = records.clone();
        duplicate.push(duplicate[0].clone());
        assert!(validate_p11_records(profile, &cases, &duplicate).is_err());
        let mut wrong_actual = records.clone();
        wrong_actual[0].actual = "identity=stringified".into();
        assert!(validate_p11_records(profile, &cases, &wrong_actual).is_err());
        assert!(
            p11_records_from_output(profile, &output.replace("lua55-i64f64", "lua54-i64f64"))
                .is_err()
        );
        assert!(
            p11_records_from_output(
                profile,
                &format!("{output}P11_STAGE\tunknown\t{profile}\tstatus=PASS;fake=true\n")
            )
            .is_err()
        );
        assert!(
            p11_records_from_output(
                profile,
                &output.replacen("P11_CASE\tCLOSE-001", "P11_CASE\tUNKNOWN-001", 1)
            )
            .is_err()
        );
        assert!(
            p11_records_from_output(profile, &output.replacen(";diagnostic=observed", "", 1))
                .is_err()
        );
    }

    #[test]
    fn p11_case_and_unit_summaries_reject_zero_short_and_extra_matches() {
        assert!(
            p11_check_case_summary("test result: ok. 1 passed; 0 failed; 47 filtered out").is_ok()
        );
        for output in [
            "test result: ok. 0 passed; 0 failed; 48 filtered out",
            "test result: ok. 2 passed; 0 failed; 46 filtered out",
            "test result: ok. 1 passed; 1 failed; 46 filtered out",
            "test result: FAILED. 0 passed; 1 failed",
        ] {
            assert!(
                p11_check_case_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
        assert!(
            p11_check_unit_summary("test result: ok. 23 passed; 0 failed; 200 filtered out")
                .is_ok()
        );
        for output in [
            "test result: ok. 0 passed; 0 failed; 223 filtered out",
            "test result: ok. 22 passed; 0 failed; 201 filtered out",
            "test result: ok. 24 passed; 0 failed; 199 filtered out",
            "test result: ok. 23 passed; 1 failed; 199 filtered out",
        ] {
            assert!(
                p11_check_unit_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
    }

    #[test]
    fn p11_prior_reports_require_every_aggregate_and_check_to_pass() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p11-prior-reports-{}", std::process::id()));
        initialize_gate_test_repository(&root);
        let reports = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&reports).unwrap();
        let phases = [
            "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10",
        ];
        for phase in phases {
            let checks = if phase == "P07" {
                [
                    "p01-before",
                    "p05-before",
                    "p06-before",
                    "p00-p06-before",
                    "smoke",
                ]
                .into_iter()
                .map(|name| format!("{{\"name\":\"{name}\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}}"))
                .collect::<Vec<_>>()
                .join(",")
            } else {
                "{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}".to_owned()
            };
            std::fs::write(
                reports.join(format!("gate-{phase}.json")),
                format!("{{\"status\":\"PASS\",\"checks\":[{checks}]}}\n"),
            )
            .unwrap();
        }
        stamp_gate_test_reports(&root);
        assert!(validate_p11_prior_reports(&root).is_ok());
        let p10 = reports.join("gate-P10.json");
        let valid_p10 = std::fs::read_to_string(&p10).unwrap();
        std::fs::write(root.join("source.rs"), b"changed").unwrap();
        let stale = validate_p11_prior_reports(&root).err().unwrap();
        assert!(
            stale.contains("P00") && stale.contains("source_digest"),
            "{stale}"
        );
        std::fs::write(root.join("source.rs"), b"initial").unwrap();
        std::fs::write(
            &p10,
            valid_p10.replacen("\"source_digest\"", "\"missing_digest\"", 1),
        )
        .unwrap();
        assert!(
            validate_p11_prior_reports(&root)
                .err()
                .unwrap()
                .contains("P10")
        );
        std::fs::write(&p10, &valid_p10).unwrap();

        for (phase, invalid) in [
            ("P00", "{\"status\":\"FAIL\",\"checks\":[{}]}\n"),
            ("P01", "not-json\n"),
            ("P02", "{\"status\":\"PASS\"}\n"),
            (
                "P03",
                "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"cmd\",\"exit_code\":\"0\",\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n",
            ),
            (
                "P10",
                "{\"status\":\"PASS\",\"checks\":[{\"name\":\"smoke\",\"command\":\"\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report.json\"}]}\n",
            ),
        ] {
            let path = reports.join(format!("gate-{phase}.json"));
            let valid = std::fs::read(&path).unwrap();
            std::fs::write(&path, invalid).unwrap();
            let error = validate_p11_prior_reports(&root).err().unwrap();
            assert!(error.contains(phase), "{phase}: {error}");
            std::fs::write(path, valid).unwrap();
        }
        let p10 = reports.join("gate-P10.json");
        let valid_p10 = std::fs::read(&p10).unwrap();
        std::fs::remove_file(&p10).unwrap();
        assert!(
            validate_p11_prior_reports(&root)
                .err()
                .unwrap()
                .contains("P10")
        );
        std::fs::write(p10, valid_p10).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p12_fixture_and_csv_require_exact_cases_for_both_profiles() {
        let fixture = include_str!("../../tests/p12/gc-cases.fixture");
        let cases = parse_p12_fixture(fixture).unwrap();
        assert_eq!(P12_CASE_IDS.len(), 10);
        assert_eq!(cases.len(), 20);
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            assert_eq!(
                cases.iter().filter(|case| case.profile == profile).count(),
                10
            );
        }
        let gc001 = fixture
            .lines()
            .find(|line| line.starts_with("case|lua55-i64f64|GC-001|"))
            .unwrap();
        assert!(parse_p12_fixture(&fixture.replacen(gc001, "", 1)).is_err());
        assert!(parse_p12_fixture(&format!("{fixture}{gc001}\n")).is_err());
        assert!(
            parse_p12_fixture(
                &fixture.replace("profile|lua54-i64f64|lua54", "profile|lua54-i64f64|lua55")
            )
            .is_err()
        );
        assert!(
            parse_p12_fixture(&fixture.replacen(
                "case|lua55-i64f64|GC-001|",
                "case|lua54-i64f64|GC-001|",
                1
            ))
            .is_err()
        );
        assert!(parse_p12_fixture(&fixture.replacen("|GC-001|", "|GC-UNKNOWN|", 1)).is_err());
        assert!(
            parse_p12_fixture(&fixture.replacen(
                "cycle=reclaimed;roots=0;generation=stale-handle-rejected",
                "cycle=retained;roots=0;generation=stale-handle-rejected",
                1
            ))
            .is_err()
        );
        assert!(
            parse_p12_fixture(&fixture.replacen("P12_CASE:GC-001", "P12_CASE:GC-UNKNOWN", 1))
                .is_err()
        );
        assert!(
            parse_p12_fixture(&fixture.replacen(
                "case|lua55-i64f64|GC-001|",
                "broken|lua55-i64f64|GC-001|",
                1
            ))
            .is_err()
        );

        let csv = include_str!("../../spec/compatibility.csv");
        assert!(validate_csv(csv).is_ok());
        assert!(validate_p12_csv_cases(csv).is_ok());
        assert!(validate_p12_csv_cases(&csv.replacen("GC-010", "GC-MISSING", 1)).is_err());
        assert!(validate_p12_csv_cases(&csv.replacen("GC-010", "GC-001", 1)).is_err());
        assert!(
            validate_p12_csv_cases(
                &csv.replace("p12.gc-complete,lua54,", "p12.gc-complete,common,")
            )
            .is_err()
        );
        let row55 = csv
            .lines()
            .find(|line| line.starts_with("p12.gc-complete,lua55,"))
            .unwrap();
        assert!(
            validate_p12_csv_cases(&csv.replacen(row55, row55.trim_end_matches(','), 1)).is_err()
        );
        assert!(validate_p12_csv_cases(&csv.replacen(&format!("{row55}\n"), "", 1)).is_err());
        assert!(
            validate_p12_csv_cases(&format!(
                "{csv}p12.extra,lua55,docs/plane/P12.md,rivetlua-runtime,GC-001,PASS,\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn p12_markers_and_summaries_require_exact_nonzero_observed_evidence() {
        assert!(p12_reentry_command().contains(
            "--lib vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue -- --exact"
        ));
        let fixture = include_str!("../../tests/p12/gc-cases.fixture");
        let cases = parse_p12_fixture(fixture).unwrap();
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            let stage_case = &P12_CASE_SPECS[0];
            let stage_output = format!(
                "P12_STAGE\tstage-one\t{profile}\tstatus=PASS\nP12_INJECT\tprofile={profile}\tordinal=1\tretry=PASS\nP12_CASE\t{}\t{profile}\tstatus=PASS;actual={};diagnostic=asserted-by-formal-case\n",
                stage_case.id, stage_case.expected
            );
            let stage_records = p12_records_from_output(profile, &stage_output).unwrap();
            assert_eq!(
                stage_records.len(),
                1,
                "P12_STAGE/P12_INJECT must be allowed"
            );
            assert_eq!(stage_records[0].id, "GC-001");
            assert!(p12_records_from_output(profile, "P12_CASE malformed\n").is_err());
            let duplicated_stage_output =
                format!("{stage_output}{}", stage_output.lines().last().unwrap());
            let duplicated_stage_records =
                p12_records_from_output(profile, &duplicated_stage_output).unwrap();
            assert!(validate_p12_records(profile, &cases, &duplicated_stage_records).is_err());

            let mut output = String::new();
            for spec in P12_CASE_SPECS {
                output.push_str(&format!(
                    "P12_CASE\t{}\t{profile}\tstatus=PASS;actual={};diagnostic=asserted-by-formal-case\n",
                    spec.id, spec.expected
                ));
            }
            let records = p12_records_from_output(profile, &output).unwrap();
            assert_eq!(records.len(), 10);
            assert_eq!(
                validate_p12_records(profile, &cases, &records)
                    .unwrap()
                    .len(),
                10
            );
            assert!(validate_p12_records(profile, &cases, &records[..9]).is_err());
            let mut duplicate = records.clone();
            duplicate.push(records[0].clone());
            assert!(validate_p12_records(profile, &cases, &duplicate).is_err());
            let mut wrong_actual = records.clone();
            wrong_actual[0].actual = "cycle=retained".into();
            assert!(validate_p12_records(profile, &cases, &wrong_actual).is_err());
            let wrong_profile = if profile == "lua55-i64f64" {
                "lua54-i64f64"
            } else {
                "lua55-i64f64"
            };
            assert!(
                p12_records_from_output(profile, &output.replace(profile, wrong_profile)).is_err()
            );
            assert!(
                p12_records_from_output(profile, &output.replacen("GC-001", "GC-UNKNOWN", 1))
                    .is_err()
            );
            assert!(
                p12_records_from_output(
                    profile,
                    &output.replacen(";diagnostic=asserted-by-formal-case", "", 1)
                )
                .is_err()
            );
            assert!(p12_records_from_output(
                profile,
                &format!(
                    "{output}P12_CASE\tGC-UNKNOWN\t{profile}\tstatus=PASS;actual=x;diagnostic=x\n"
                )
            )
            .is_err());
        }
        assert!(
            p12_check_case_summary("test result: ok. 1 passed; 0 failed; 49 filtered out").is_ok()
        );
        for output in [
            "test result: ok. 0 passed; 0 failed; 50 filtered out",
            "test result: ok. 2 passed; 0 failed; 48 filtered out",
            "test result: ok. 1 passed; 1 failed; 48 filtered out",
            "test result: FAILED. 0 passed; 1 failed",
        ] {
            assert!(
                p12_check_case_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
        assert_eq!(
            p12_check_filter_summary("gc", "test result: ok. 3 passed; 0 failed; 1 filtered out")
                .unwrap(),
            3
        );
        assert_eq!(
            p12_check_filter_summary(
                "vm_lifecycle",
                "test result: ok. 0 passed; 0 failed; 40 filtered out\ntest result: ok. 1 passed; 0 failed; 19 filtered out"
            )
            .unwrap(),
            1
        );
        for output in [
            "test result: ok. 0 passed; 0 failed; 4 filtered out",
            "test result: ok. 2 passed; 1 failed; 1 filtered out",
            "test result: FAILED. 0 passed; 1 failed",
        ] {
            assert!(
                p12_check_filter_summary("gc", output).is_err(),
                "accepted {output:?}"
            );
            assert!(
                p12_check_unit_summary(output).is_err(),
                "accepted {output:?}"
            );
        }
        assert_eq!(
            p12_check_unit_summary("test result: ok. 46 passed; 0 failed; 131 filtered out")
                .unwrap(),
            46
        );
        let reentry = "test vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue ... ok\ntest result: ok. 1 passed; 0 failed; 176 filtered out";
        assert!(p12_check_reentry_summary(reentry).is_ok());
        assert!(p12_check_reentry_summary("test p12_5_reentrant_gc_is_rejected_without_losing_queue ... ok\ntest result: ok. 1 passed; 0 failed; 176 filtered out").is_err());
        assert!(
            p12_check_reentry_summary("test result: ok. 1 passed; 0 failed; 176 filtered out")
                .is_err()
        );
        assert!(p12_check_reentry_summary("test vm::tests::p12_5_reentrant_gc_is_rejected_without_losing_queue ... ok\ntest result: ok. 2 passed; 0 failed; 175 filtered out").is_err());
    }

    #[test]
    fn p13_fixture_csv_exact_both_profiles_and_fixed_expected() {
        let fixture = include_str!("../../tests/p13/lib-cases.fixture");
        let cases = super::parse_p13_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 28);
        for profile in ["lua55-i64f64", "lua54-i64f64"] {
            assert_eq!(
                cases.iter().filter(|case| case.profile == profile).count(),
                14
            );
        }
        let first = fixture
            .lines()
            .find(|line| line.starts_with("case|lua55-i64f64|LIB-001|"))
            .unwrap();
        assert!(super::parse_p13_fixture(&fixture.replacen(&format!("{first}\n"), "", 1)).is_err());
        assert!(super::parse_p13_fixture(&format!("{fixture}{first}\n")).is_err());
        assert!(super::parse_p13_fixture(&fixture.replacen("LIB-001", "LIB-999", 1)).is_err());
        assert!(
            super::parse_p13_fixture(&fixture.replacen(
                "profile|lua54-i64f64|lua54",
                "profile|lua54-i64f64|lua55",
                1
            ))
            .is_err()
        );
        assert!(
            super::parse_p13_fixture(&fixture.replacen("int:6,int:2", "int:7,int:2", 1)).is_err()
        );
        let csv = include_str!("../../spec/compatibility.csv");
        assert!(super::validate_p13_csv_cases(csv).is_ok());
        assert!(super::validate_p13_csv_cases(&csv.replacen("LIB-014", "LIB-999", 1)).is_err());
        assert!(
            super::validate_p13_csv_cases(
                &csv.replace("p13.stdlib-modules,lua54,", "p13.stdlib-modules,common,")
            )
            .is_err()
        );
    }

    #[test]
    fn p13_marker_and_exact_summary_require_observed_fields() {
        let marker = "test lib_case_001 ... P13_CASE\tLIB-001\tlua55-i64f64\tstatus=PASS;actual=int:6,int:2;diagnostic=asserted\tcapability=host=deny\tfuel=used=19\tallocation=reserved=0\tresource=roots=5\n";
        let records = super::p13_records_from_output("lua55-i64f64", marker).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].actual, "int:6,int:2");
        for bad in [
            marker.replace("LIB-001", "LIB-999"),
            marker.replace("lua55-i64f64", "lua54-i64f64"),
            marker.replace("int:6,int:2", "int:7,int:2"),
            marker.replace("diagnostic=asserted", "diagnostic="),
            marker.replace("fuel=used=19", "fuel="),
            marker.replace("\tresource=roots=5", ""),
            format!("{marker}{marker}"),
        ] {
            assert!(
                super::p13_records_from_output("lua55-i64f64", &bad).is_err(),
                "accepted {bad}"
            );
        }
        assert!(
            super::p13_check_case_summary(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 13 filtered out"
            )
            .is_ok()
        );
        for bad in [
            "test result: ok. 0 passed; 0 failed; 0 ignored",
            "test result: ok. 2 passed; 0 failed; 0 ignored",
            "test result: ok. 1 passed; 0 failed; 1 ignored",
            "test result: FAILED. 0 passed; 1 failed; 0 ignored",
        ] {
            assert!(super::p13_check_case_summary(bad).is_err());
        }
    }

    #[test]
    fn p13_prior_expected_rejection_is_limited_to_exact_p00_and_p11_evidence() {
        for phase in ["P00", "P11"] {
            for (name, command, report_path) in super::P13_EXPECTED_P00_FAILURES {
                let check_name = if phase == "P11" {
                    format!("P00-{name}")
                } else {
                    name.into()
                };
                let source = format!(
                    "{{\"name\":\"{check_name}\",\"command\":\"{command}\",\"exit_code\":1,\"status\":\"PASS\",\"diagnostic\":\"預期拒絕\",\"report_path\":\"{report_path}\"}}"
                );
                let parsed = StrictJsonParser::parse(&source).unwrap();
                assert_eq!(
                    super::p13_validate_prior_check(phase, &parsed).unwrap(),
                    check_name
                );
                for bad in [
                    source.replace("\"exit_code\":1", "\"exit_code\":0"),
                    source.replace("\"exit_code\":1", "\"exit_code\":2"),
                    source.replace(command, "wrong command"),
                    source.replace(report_path, "wrong/report.json"),
                    source.replace("\"diagnostic\":\"預期拒絕\"", "\"diagnostic\":\"\""),
                    source.replace("\"status\":\"PASS\"", "\"status\":\"FAIL\""),
                    source.replace(&check_name, "P00-UNKNOWN"),
                ] {
                    let bad = StrictJsonParser::parse(&bad).unwrap();
                    assert!(super::p13_validate_prior_check(phase, &bad).is_err());
                }
                assert!(super::p13_validate_prior_check("P02", &parsed).is_err());
            }
        }
        let generic = StrictJsonParser::parse("{\"name\":\"smoke\",\"command\":\"test\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"ok\",\"report_path\":\"report\"}").unwrap();
        assert!(super::p13_validate_prior_check("P02", &generic).is_ok());
    }

    #[test]
    fn p13_prior_parse_profile_identity_distinguishes_both_profiles() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        for phase in ["P03", "P11"] {
            for id in super::P03_CASES {
                let name = if phase == "P11" {
                    format!("P03-{id}")
                } else {
                    id.to_owned()
                };
                let mut identities = Vec::new();
                for profile in ["lua55", "lua54"] {
                    let path =
                        root.join(format!("target/rivetlua-reports/P03-{id}-{profile}.json"));
                    let check = format!(
                        "{{\"name\":\"{name}\",\"command\":\"cargo test p03_contracts\",\"exit_code\":0,\"status\":\"PASS\",\"diagnostic\":\"已驗證\",\"report_path\":\"{}\"}}",
                        super::json_escape(&path.display().to_string())
                    );
                    let parsed = StrictJsonParser::parse(&check).unwrap();
                    identities.push(super::p13_prior_identity(root, phase, &parsed).unwrap());
                    let unknown = if phase == "P11" {
                        "P03-PARSE-UNKNOWN"
                    } else {
                        "PARSE-UNKNOWN"
                    };
                    for bad in [
                        check.replace("cargo test p03_contracts", "cargo test wrong"),
                        check.replace(&path.display().to_string(), "/tmp/wrong-root.json"),
                        check.replace(
                            &path.display().to_string(),
                            &format!("{}-wrong.json", path.display()),
                        ),
                        check.replacen(
                            &format!("\"name\":\"{name}\""),
                            &format!("\"name\":\"{unknown}\""),
                            1,
                        ),
                    ] {
                        let bad = StrictJsonParser::parse(&bad).unwrap();
                        assert!(super::p13_prior_identity(root, phase, &bad).is_err());
                    }
                }
                assert_ne!(identities[0], identities[1]);
            }
        }
    }

    #[test]
    fn p13_fail_report_clears_stale_cases_and_uses_fallback_when_canonical_blocked() {
        let root =
            std::env::temp_dir().join(format!("rivetlua-p13-fail-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let directory = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&directory).unwrap();
        let digest = "a".repeat(64);
        let stale = directory.join("P13-LIB-001-lua55.json");
        std::fs::write(&stale, "{\"status\":\"PASS\"}").unwrap();
        let canonical = directory.join("gate-P13.json");
        std::fs::write(&canonical, "{\"status\":\"PASS\"}").unwrap();
        let mut results = Vec::new();
        let failure = super::p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-unit",
            "fake command",
            1,
            "expected failure".into(),
        );
        assert!(failure.contains("expected failure"));
        assert!(!stale.exists());
        let parsed =
            StrictJsonParser::parse(&std::fs::read_to_string(&canonical).unwrap()).unwrap();
        assert_eq!(
            parsed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        assert_eq!(
            parsed
                .get("source_digest")
                .and_then(StrictJsonValue::as_str),
            Some(digest.as_str())
        );
        std::fs::remove_file(&canonical).unwrap();
        std::fs::create_dir(&canonical).unwrap();
        std::fs::write(canonical.join("block"), "keep").unwrap();
        std::fs::write(&stale, "{\"status\":\"PASS\"}").unwrap();
        let mut results = Vec::new();
        let failure = super::p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-unit",
            "fake command",
            1,
            "blocked".into(),
        );
        assert!(failure.contains("canonical aggregate 寫入失敗"));
        assert!(!stale.exists());
        assert_eq!(
            std::fs::read_to_string(canonical.join("block")).unwrap(),
            "keep"
        );
        let fallback = root.join("target/gate-P13-fail.json");
        let parsed = StrictJsonParser::parse(&std::fs::read_to_string(&fallback).unwrap()).unwrap();
        assert_eq!(
            parsed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        assert_eq!(
            parsed
                .get("source_digest")
                .and_then(StrictJsonValue::as_str),
            Some(digest.as_str())
        );
        std::fs::remove_file(&fallback).unwrap();
        std::fs::create_dir(&fallback).unwrap();
        std::fs::write(fallback.join("block"), "keep").unwrap();
        std::fs::write(&stale, "{\"status\":\"PASS\"}").unwrap();
        let mut results = Vec::new();
        let failure = super::p13_fail(
            &root,
            &digest,
            &mut results,
            "p13-unit",
            "fake command",
            1,
            "both blocked".into(),
        );
        assert!(failure.contains("canonical aggregate 寫入失敗"));
        assert!(failure.contains("fallback FAIL aggregate 寫入失敗"));
        assert!(!stale.exists());
        assert_eq!(
            std::fs::read_to_string(canonical.join("block")).unwrap(),
            "keep"
        );
        assert_eq!(
            std::fs::read_to_string(fallback.join("block")).unwrap(),
            "keep"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p14_fixture_marker_summary_csv_and_report_reject_mutations() {
        let fixture = include_str!("../../tests/p14/sdk-cases.fixture");
        let cases = super::parse_p14_fixture(fixture).unwrap();
        assert_eq!(cases.len(), 28);
        let first = fixture
            .lines()
            .find(|line| line.starts_with("case|"))
            .unwrap();
        for bad in [
            fixture.replacen(&format!("{first}\n"), "", 1),
            format!("{fixture}{first}\n"),
            fixture.replacen("SDK-001", "SDK-999", 1),
            fixture.replacen("lua55-i64f64|lua55", "lua55-i64f64|lua54", 1),
            fixture.replacen("|int:42|", "|int:41|", 1),
            fixture.replacen("sdk_case_001", "sdk_case_002", 1),
        ] {
            assert!(super::parse_p14_fixture(&bad).is_err());
        }
        let marker = "test sdk_case_001 ... P14_CASE\tSDK-001\tlua55-i64f64\tstatus=PASS;actual=int:42;diagnostic=asserted\tallocation=reserved=0\tresource=root=1\tvm=isolated\tcli=not-applicable\n";
        let record = super::p14_records_from_output("lua55-i64f64", marker).unwrap();
        assert_eq!(record.id, "SDK-001");
        for bad in [
            "".to_owned(),
            format!("{marker}{marker}"),
            marker.replace("SDK-001", "SDK-999"),
            marker.replace("lua55-i64f64", "lua54-i64f64"),
            marker.replace("actual=int:42", "actual=int:41"),
            marker.replace("resource=root=1", "resource="),
            marker.replace("status=PASS", "status=FAIL"),
        ] {
            assert!(super::p14_records_from_output("lua55-i64f64", &bad).is_err());
        }
        let good_summary =
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out";
        assert!(super::p14_check_exact_summary(good_summary).is_ok());
        for bad in [
            "",
            "test result: ok. 0 passed; 0 failed; 0 ignored",
            "test result: ok. 2 passed; 0 failed; 0 ignored",
            "test result: ok. 1 passed; 0 failed; 1 ignored",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 1 measured; 13 filtered out",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 13 filtered out",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out; extra; fields",
            "test result: FAILED. 0 passed; 1 failed; 0 ignored",
            &format!("{good_summary}\n{good_summary}"),
        ] {
            assert!(super::p14_check_exact_summary(bad).is_err());
        }
        let filter_summaries = "test result: ok. 30 passed; 0 failed; 0 ignored\ntest result: ok. 22 passed; 0 failed; 0 ignored";
        assert_eq!(
            super::p14_check_filter_summary("sdk", filter_summaries, 52),
            Ok(52)
        );
        assert!(super::p14_check_filter_summary("sdk", filter_summaries, 51).is_err());
        assert!(super::p14_check_filter_summary("sdk", "", 52).is_err());
        assert!(
            super::p14_check_filter_summary(
                "sdk",
                "test result: ok. bad passed; 0 failed; 0 ignored",
                52
            )
            .is_err()
        );
        assert!(
            super::p14_check_filter_summary(
                "sdk",
                "test result: ok. 0 passed; 0 failed; 0 ignored",
                0
            )
            .is_err()
        );
        assert!(
            super::p14_check_filter_summary(
                "sdk",
                "test result: ok. 52 passed; 1 failed; 0 ignored",
                52
            )
            .is_err()
        );
        assert!(
            super::p14_check_filter_summary(
                "sdk",
                "test result: ok. 52 passed; 0 failed; 1 ignored",
                52
            )
            .is_err()
        );
        let overflow_summaries = format!(
            "test result: ok. {} passed; 0 failed; 0 ignored\ntest result: ok. 1 passed; 0 failed; 0 ignored",
            usize::MAX
        );
        assert!(super::p14_check_filter_summary("sdk", &overflow_summaries, 52).is_err());
        let root = std::env::temp_dir().join(format!("rivetlua-p14-unit-{}", std::process::id()));
        std::fs::create_dir_all(root.join("target/rivetlua-reports")).unwrap();
        let case = &cases[0];
        let spec = super::p14_spec(&case.id).unwrap();
        let command = super::p14_case_command(&case.profile, spec);
        let path = root.join(format!(
            "target/rivetlua-reports/P14-{}-{}.json",
            case.id, case.lua_profile
        ));
        let json = super::p14_case_json(
            case,
            &record,
            &"a".repeat(64),
            &command,
            &root,
            &format!(
                "target/rivetlua-reports/P14-{}-{}.json",
                case.id, case.lua_profile
            ),
        );
        std::fs::write(&path, &json).unwrap();
        super::p14_validate_case_report(&path, case, &"a".repeat(64), &command, &root).unwrap();
        for bad in [
            json.replacen("\"actual\":\"int:42\"", "\"actual\":\"int:41\"", 1),
            json.replacen("\"source_digest\":\"", "\"source_digest\":\"broken", 1),
            json.replacen("\"resource_trace\"", "\"missing_trace\"", 1),
            json.replacen("\"exit_code\":0", "\"exit_code\":1", 1),
            "{bad-json".into(),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(
                super::p14_validate_case_report(&path, case, &"a".repeat(64), &command, &root)
                    .is_err()
            );
        }
        let existing = include_str!("../../spec/compatibility.csv")
            .lines()
            .filter(|line| !line.starts_with("p14."))
            .collect::<Vec<_>>()
            .join("\n");
        let ids = super::P14_CASE_SPECS
            .iter()
            .map(|spec| spec.id)
            .collect::<Vec<_>>()
            .join(";");
        let csv = format!(
            "{existing}\np14.sdk-cli,lua55,docs/plane/P14.md#6-正常與錯誤案例,rivetlua;rivetlua-cli,{ids},PASS,\np14.sdk-cli,lua54,docs/plane/P14.md#6-正常與錯誤案例,rivetlua;rivetlua-cli,{ids},PASS,\n"
        );
        super::p14_validate_csv_cases(&csv).unwrap();
        for bad in [
            csv.replacen("p14.sdk-cli,lua55,", "p14.other,lua55,", 1),
            csv.replacen("SDK-NEG-006", "SDK-NEG-999", 1),
            csv.replacen("p14.sdk-cli,lua54,", "p14.sdk-cli,lua55,", 1),
            csv.replacen("rivetlua;rivetlua-cli", "rivetlua", 1),
            csv.replacen("OFFCHUNK-002;OFFCHUNK-004", "OFFCHUNK-001;OFFCHUNK-004", 1),
            csv.replacen(
                "OFFCHUNK-007;OFFCHUNK-008;OFFCHUNK-017;OFFCHUNK-018",
                "OFFCHUNK-007;OFFCHUNK-008;OFFCHUNK-017",
                1,
            ),
        ] {
            assert!(super::p14_validate_csv_cases(&bad).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p14_fail_clears_stale_case_and_falls_back_on_blocked_report() {
        let root = std::env::temp_dir().join(format!("rivetlua-p14-fail-{}", std::process::id()));
        let directory = root.join("target/rivetlua-reports");
        std::fs::create_dir_all(&directory).unwrap();
        let stale = directory.join("P14-SDK-001-lua55.json");
        std::fs::write(&stale, "{\"status\":\"PASS\"}").unwrap();
        let digest = "b".repeat(64);
        let mut results = Vec::new();
        let error = super::p14_fail(
            &root,
            &digest,
            &mut results,
            "child",
            "cargo test --exact",
            101,
            "failed".into(),
        );
        assert_eq!(error, "failed");
        assert!(!stale.exists());
        assert_eq!(results[0].exit_code, 101);
        let canonical = directory.join("gate-P14.json");
        let parsed =
            StrictJsonParser::parse(&std::fs::read_to_string(&canonical).unwrap()).unwrap();
        assert_eq!(
            parsed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        std::fs::remove_file(&canonical).unwrap();
        std::fs::create_dir(&canonical).unwrap();
        std::fs::write(canonical.join("block"), "keep").unwrap();
        std::fs::write(&stale, "{\"status\":\"PASS\"}").unwrap();
        let mut results = Vec::new();
        let error = super::p14_fail(
            &root,
            &digest,
            &mut results,
            "write",
            "write gate-P14.json",
            1,
            "blocked".into(),
        );
        assert!(error.contains("canonical 寫入失敗"));
        assert!(!stale.exists());
        let fallback = root.join("target/gate-P14-fail.json");
        let parsed = StrictJsonParser::parse(&std::fs::read_to_string(fallback).unwrap()).unwrap();
        assert_eq!(
            parsed.get("status").and_then(StrictJsonValue::as_str),
            Some("FAIL")
        );
        assert_eq!(
            parsed
                .get("source_digest")
                .and_then(StrictJsonValue::as_str),
            Some(digest.as_str())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p00_direct_opt_in_and_full_summary_fail_closed() {
        assert_eq!(super::p00_direct_opt_in(None).unwrap(), false);
        assert_eq!(super::p00_direct_opt_in(Some("1")).unwrap(), true);
        for invalid in ["", "0", "true", "/tmp/runner"] {
            assert!(super::p00_direct_opt_in(Some(invalid)).is_err());
        }
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_PROFILE_TEST_PANIC",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
        ] {
            assert!(super::p00_build_override_name(name));
        }
        assert!(!super::p00_build_override_name("CARGO_TARGET_DIR"));
        let valid = "running 101 tests\ntest result: ok. 101 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.76s\n";
        assert_eq!(super::p00_full_test_count(valid).unwrap(), 101);
        for invalid in [
            "",
            "test result: ok. 101 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.76s\n",
            &valid.replace("running 101 tests", "running 100 tests"),
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            &valid.replace("0 failed", "1 failed"),
            &valid.replace("0 ignored", "1 ignored"),
            &valid.replace("0 filtered out", "1 filtered out"),
            &valid.replace("test result: ok.", "test result: FAILED."),
            &format!("{valid}{valid}"),
        ] {
            assert!(super::p00_full_test_count(invalid).is_err());
        }
    }

    #[test]
    fn p00_direct_metadata_requires_std_only_fixed_main_target() {
        let root = std::path::Path::new("/fixed/workspace");
        let valid = format!(
            "{{\"packages\":[{{\"name\":\"rivetlua-xtask\",\"id\":\"fixed-package\",\"manifest_path\":\"{}/xtask/Cargo.toml\",\"edition\":\"2024\",\"features\":{{}},\"dependencies\":[],\"targets\":[{{\"name\":\"rivetlua-xtask\",\"kind\":[\"bin\"],\"src_path\":\"{}/xtask/src/main.rs\"}},{{\"name\":\"cli\",\"kind\":[\"test\"],\"src_path\":\"{}/xtask/tests/cli.rs\"}}]}}]}}",
            root.display(),
            root.display(),
            root.display()
        );
        assert_eq!(
            super::p00_direct_metadata_package(root, &valid).unwrap(),
            "fixed-package"
        );
        for invalid in [
            valid.replace("\"features\":{}", "\"features\":{\"extra\":[]}"),
            valid.replace("\"dependencies\":[]", "\"dependencies\":[{}]"),
            valid.replace("\"edition\":\"2024\"", "\"edition\":\"2021\""),
            valid.replace(
                "\"name\":\"rivetlua-xtask\",\"kind\":[\"bin\"]",
                "\"name\":\"wrong\",\"kind\":[\"bin\"]",
            ),
            valid.replace("xtask/src/main.rs", "xtask/src/other.rs"),
            valid.replace("xtask/Cargo.toml", "other/Cargo.toml"),
            valid.replace("\"kind\":[\"test\"]", "\"kind\":[\"custom-build\"]"),
            valid.replacen(
                "\"packages\":[",
                "\"packages\":[{\"name\":\"rivetlua-xtask\"},",
                1,
            ),
        ] {
            assert!(super::p00_direct_metadata_package(root, &invalid).is_err());
        }
    }

    #[test]
    fn p00_direct_artifact_requires_exact_test_profile_and_source() {
        let root = std::path::Path::new("/fixed/workspace");
        let cache = std::path::Path::new("/fixed/cache");
        let artifact = format!(
            "{{\"reason\":\"compiler-artifact\",\"package_id\":\"fixed-package\",\"target\":{{\"name\":\"rivetlua-xtask\",\"kind\":[\"bin\"],\"src_path\":\"{}/xtask/src/main.rs\",\"edition\":\"2024\",\"test\":true}},\"profile\":{{\"opt_level\":\"0\",\"debug_assertions\":true,\"overflow_checks\":true,\"test\":true}},\"features\":[],\"executable\":\"{}/debug/deps/rivetlua_xtask-fixed\"}}",
            root.display(),
            cache.display()
        );
        let finish = "{\"reason\":\"build-finished\",\"success\":true}";
        let valid = format!("{artifact}\n{finish}\n");
        assert_eq!(
            super::p00_direct_artifact(root, cache, "fixed-package", &valid).unwrap(),
            cache.join("debug/deps/rivetlua_xtask-fixed")
        );
        for invalid in [
            artifact.clone(),
            valid.replace("\"opt_level\":\"0\"", "\"opt_level\":\"1\""),
            valid.replace("\"debug_assertions\":true", "\"debug_assertions\":false"),
            valid.replace("\"overflow_checks\":true", "\"overflow_checks\":false"),
            valid.replace("\"test\":true", "\"test\":false"),
            valid.replace("fixed-package", "wrong-package"),
            valid.replace("xtask/src/main.rs", "xtask/src/other.rs"),
            valid.replace("/fixed/cache/debug", "/fixed/other/debug"),
            valid.replace("\"success\":true", "\"success\":false"),
            format!("{artifact}\n{artifact}\n{finish}\n"),
        ] {
            assert!(super::p00_direct_artifact(root, cache, "fixed-package", &invalid).is_err());
        }
    }
}
