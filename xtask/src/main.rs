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
            if columns[0].starts_with("p01.")
                || columns[0].starts_with("p02.")
                || columns[0].starts_with("p03.")
                || columns[0].starts_with("p04.")
                || columns[0].starts_with("p05.")
                || columns[0].starts_with("p06.")
                || columns[0].starts_with("p07.")
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
const P06_CASES: [&str; 8] = [
    "HEAP-001", "HEAP-002", "HEAP-003", "HEAP-004", "HEAP-005", "HEAP-006", "HEAP-007", "HEAP-008",
];
const P06_FIXTURE: &str = "tests/p06/heap-cases.fixture";
const P07_CASES: [&str; 10] = [
    "VM-001", "VM-002", "VM-003", "VM-004", "VM-005", "VM-006", "VM-007", "VM-008", "VM-009",
    "VM-010",
];
const P07_FIXTURE: &str = "tests/p07/vm-cases.fixture";

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
    const EXPECTED_EDGES: [(&str, &str, &str, &str); 32] = [
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
        let (id, producer, consumer, _interface, status, earliest_gate) = (
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
    if rows.len() != 32
        || !(1..=31).all(|number| {
            let id = format!("DA-{number:02}");
            rows.contains(id.as_str())
        })
    {
        return Err("phase-dependencies.csv 必須完整覆蓋 DA-01～DA-31".into());
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
        format!("{{\"status\":\"{status}\",\"checks\":[{checks}]}}\n"),
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
    if !output.contains("test result: ok. 1 passed; 0 failed;") {
        return Err(format!("{profile} P04 contracts 未完整執行：{output}"));
    }
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
        format!("{{\"status\":\"{status}\",\"checks\":[{checks}]}}\n"),
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
    if !output.contains("test result: ok. 1 passed; 0 failed;") {
        return Err(format!("{profile} P05 contracts 未完整執行：{output}"));
    }
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
        format!("{{\"status\":\"{status}\",\"checks\":[{checks}]}}\n"),
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
        "32 條 dependency edge 覆蓋 31 筆 DA、無 CONFLICT、無 cycle，且 critical owner edge 存在",
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
        format!("{{\"status\":\"{status}\",\"checks\":[{checks}]}}\n"),
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
        format!("{{\"status\":\"{status}\",\"checks\":[{checks}]}}\n"),
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
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P03") && arguments.len() == 2 => p03_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P04") && arguments.len() == 2 => p04_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P05") && arguments.len() == 2 => p05_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P06") && arguments.len() == 2 => p06_gate(),
        Some("gate") if arguments.get(1).map(String::as_str) == Some("P07") && arguments.len() == 2 => p07_gate(),
        _ => Err(
            "用法：rivetlua-xtask toolchain | reference --profile lua55|lua54 [--offline] | runner --profile lua55|lua54 --case <P00-ID> | gate P00|P01|P02|P03|P04|P05|P06|P07".into(),
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
        LUA54, LUA55, MSRV, P02_CASES, P03_CASES, P04_CASES, P05_CASES, P06_CASES, P06FixtureCase,
        P07_CASES, STRICT_GLOBAL_CFLAGS, contains_lua_engine_symbol, p03_child_status,
        p04_child_status, p05_child_status, p06_case_report, p06_check_test_summary,
        p06_check_with_value_doctests, p07_case_report, parse_p06_fixture, parse_p07_fixture,
        profile, reference_make_target, sha256_tool, supported_rustc, validate_csv,
        validate_p01_contract_status, validate_p01_csv_cases, validate_p02_csv_cases,
        validate_p03_csv_cases, validate_p03_records, validate_p04_csv_cases, validate_p04_records,
        validate_p05_csv_cases, validate_p05_records, validate_p06_csv_cases, validate_p06_records,
        validate_p07_csv_cases, validate_p07_records, validate_pass_evidence,
        validate_phase_dependency_graph, write_p01_case_report, write_p02_case_report,
        write_p03_case_report, write_p04_case_report, write_p05_case_report,
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
}
