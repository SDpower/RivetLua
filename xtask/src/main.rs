//! P00 階段驗證工具。

use std::env;
use std::fmt::Write as _;
use std::fs;
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
        format!("{{\"status\":\"{status}\",\"checks\":[{entries}]}}\n"),
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
            if columns[0].starts_with("p01.") || columns[0].starts_with("p02.") {
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
        if columns[0].starts_with("p01.") || columns[0].starts_with("p02.") {
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
    if let Err(error) = run(
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
    ) {
        results.push(GateResult {
            name: "xtask-tests".into(),
            command: "cargo test --locked -p rivetlua-xtask --bin rivetlua-xtask".into(),
            exit_code: 1,
            status: "FAIL",
            diagnostic: error.clone(),
            report_path: "target/rivetlua-reports/gate-P00.json".into(),
        });
        write_gate_results(&root, &results);
        return Err(error);
    }
    results.push(GateResult {
        name: "xtask-tests".into(),
        command: "cargo test --locked -p rivetlua-xtask --bin rivetlua-xtask".into(),
        exit_code: 0,
        status: "PASS",
        diagnostic: "xtask binary 單元測試通過".into(),
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

const P01_CASES: [(&str, &str); 14] = [
    ("NUM-001", "num_001_floor_division"),
    ("NUM-002", "num_002_negative_modulo"),
    ("NUM-003", "num_003_negative_divisor_modulo"),
    ("NUM-004", "num_004_integer_addition_wraps"),
    ("NUM-005", "num_005_large_integer_float_comparison_is_exact"),
    ("NUM-006", "num_006_minimum_integer_boundaries_do_not_panic"),
    ("NUM-007", "num_007_bit_conversion_and_shift_boundaries"),
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
        format!("{{\"status\":\"{status}\",\"checks\":[{entries}]}}\n"),
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
        "兩個 profile 的 14 個 P01 case 均完整追溯",
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
const STRICT_GLOBAL_CFLAGS: &str = "-DLUA_COMPAT_GLOBAL=0";

fn write_p02_results(root: &Path, results: &[GateResult]) {
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
        format!("{{\"status\":\"{status}\",\"checks\":[{entries}]}}\n"),
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
        Some("runner") => runner(&arguments[1..]),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P00") && arguments.len() == 2 => {
            GATE_REPORT_WRITTEN.store(false, Ordering::Relaxed);
            gate()
        }
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P01") && arguments.len() == 2 => p01_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P02") && arguments.len() == 2 => p02_gate(),
        _ => Err(
            "用法：rivetlua-xtask toolchain | reference --profile lua55|lua54 [--offline] | runner --profile lua55|lua54 --case <P00-ID> | gate P00|P01|P02".into(),
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
            eprintln!("P00 失敗：{error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LUA54, LUA55, MSRV, P02_CASES, STRICT_GLOBAL_CFLAGS, contains_lua_engine_symbol, profile,
        reference_make_target, sha256_tool, supported_rustc, validate_csv,
        validate_p01_contract_status, validate_p01_csv_cases, validate_p02_csv_cases,
        validate_pass_evidence, write_p01_case_report, write_p02_case_report,
    };
    use std::process::Command;
    #[test]
    fn stable_rustc_must_meet_msrv() {
        assert_eq!(MSRV, "1.94.1");
        assert!(supported_rustc("rustc 1.94.1 (hash date)"));
        assert!(supported_rustc("rustc 1.98.1 (hash date)"));
        assert!(!supported_rustc("rustc 1.93.0 (hash date)"));
        assert!(!supported_rustc("rustc 1.98.1-beta.1 (hash date)"));
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
    }
    #[test]
    fn p01_csv_cases_are_complete() {
        let ids = "NUM-001;NUM-002;NUM-003;NUM-004;NUM-005;NUM-006;NUM-007;VAL-001;VAL-002;VAL-003;ERR-001;ERR-002;ERR-003;ERR-004";
        let csv = format!(
            "feature_id,lua_profile,spec_reference,implementation_module,test_ids,status,known_difference\np01.core,lua55,s,m,{ids},PASS,\np01.core,lua54,s,m,{ids},PASS,"
        );
        assert!(validate_p01_csv_cases(&csv).is_ok());
    }
    #[test]
    fn p01_csv_cases_reject_missing_num_001() {
        let ids = "NUM-002;NUM-003;NUM-004;NUM-005;NUM-006;NUM-007;VAL-001;VAL-002;VAL-003;ERR-001;ERR-002;ERR-003;ERR-004";
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
}
