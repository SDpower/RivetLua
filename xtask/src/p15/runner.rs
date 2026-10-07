use super::{manifest, parser, result};
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn validate_environment() -> Result<(), String> {
    for name in ["LUA_INIT", "LUA_INIT_5_4", "LUA_INIT_5_5"] {
        if env::var_os(name).is_some_and(|value| !value.is_empty()) {
            return Err(format!(
                "P15 官方 Basic 不接受非空 {name}；該 init 會改變官方 suite 的載入環境"
            ));
        }
    }
    Ok(())
}

fn build(root: &Path, source: &manifest::Source) -> Result<PathBuf, String> {
    let target = root
        .join("target/rivetlua-p15")
        .join(format!("build-{}", source.profile));
    let mut command = Command::new("cargo");
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args([
            "build",
            "--locked",
            "-p",
            "rivetlua-cli",
            "--bin",
            "rivetlua",
        ]);
    if source.feature == "default-lua54" {
        command.args(["--features", "default-lua54"]);
    }
    let output = command
        .output()
        .map_err(|error| format!("建置 P15 binary 失敗：{error}"))?;
    let build_log = root
        .join("target/rivetlua-p15")
        .join(format!("build-{}.log", source.profile));
    fs::write(
        &build_log,
        [&output.stdout[..], &output.stderr[..]].concat(),
    )
    .map_err(|error| format!("寫入 P15 build log 失敗：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "建置 P15 binary 失敗 exit={:?} log={}",
            output.status.code(),
            build_log.display()
        ));
    }
    fs::canonicalize(target.join("debug/rivetlua"))
        .map_err(|error| format!("P15 binary 不存在：{error}"))
}

fn version(binary: &Path, expected: &str) -> Result<String, String> {
    let output = Command::new(binary)
        .arg("-v")
        .output()
        .map_err(|error| format!("P15 binary -v 啟動失敗：{error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual = format!("{}{}", stdout, stderr).trim().to_owned();
    if !output.status.success() || actual != expected {
        return Err(format!(
            "P15 binary/profile/release 身分不符：預期 {expected:?}，實際 {actual:?}，exit={:?}",
            output.status.code()
        ));
    }
    Ok(actual)
}

fn execute(
    binary: &Path,
    suite: &Path,
    stdout: &Path,
    stderr: &Path,
) -> Result<(Option<i32>, u128), String> {
    let out = File::create(stdout).map_err(|error| format!("建立 stdout log 失敗：{error}"))?;
    let err = File::create(stderr).map_err(|error| format!("建立 stderr log 失敗：{error}"))?;
    let start = Instant::now();
    let mut child = Command::new(binary)
        .args(["-e_U=true", "all.lua"])
        .current_dir(suite)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|error| format!("官方 tests child 啟動失敗：{error}"))?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("等待官方 tests child 失敗：{error}"))?
        {
            return Ok((status.code(), start.elapsed().as_millis()));
        }
        if start.elapsed() > Duration::from_secs(600) {
            child
                .kill()
                .map_err(|error| format!("逾時 child 終止失敗：{error}"))?;
            child
                .wait()
                .map_err(|error| format!("逾時 child 回收失敗：{error}"))?;
            return Ok((None, start.elapsed().as_millis()));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run(root: &Path, source: &manifest::Source) -> Result<(), String> {
    validate_environment()?;
    manifest::verify_archive(root, source)?;
    let source_digest_before = super::super::source_digest(root)?;
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let work = root.join("target/rivetlua-p15").join(format!(
        "work-{}-{}-{time}",
        source.profile,
        std::process::id()
    ));
    let (suite, before, tree_sha256) = manifest::prepare(root, source, &work)?;
    let binary = build(root, source)?;
    let actual_version = version(&binary, source.version)?;
    let binary_sha256 = manifest::sha256(&binary)?;
    let stdout_path = work.join("stdout.raw");
    let stderr_path = work.join("stderr.raw");
    let (exit_code, elapsed_ms) = execute(&binary, &suite, &stdout_path, &stderr_path)?;
    let stdout =
        fs::read(&stdout_path).map_err(|error| format!("官方 stdout log 缺失：{error}"))?;
    let stderr =
        fs::read(&stderr_path).map_err(|error| format!("官方 stderr log 缺失：{error}"))?;
    let parsed = parser::parse(&stdout, &stderr, exit_code);
    let source_after = manifest::file_map(&suite)?;
    let source_unchanged = before == source_after;
    let binary_unchanged = manifest::sha256(&binary)? == binary_sha256;
    let repository_unchanged = super::super::source_digest(root)? == source_digest_before;
    let infrastructure_ok = source_unchanged && binary_unchanged && repository_unchanged;
    let diagnostic = if !source_unchanged {
        "官方 suite 檔案於 child 執行後變更"
    } else if !binary_unchanged {
        "binary 檔案於 child 執行後變更"
    } else if !repository_unchanged {
        "repository 來源於 child 執行後變更"
    } else if !parsed.provisional_pass {
        "oracle 觀察完成；官方 Basic child 未滿足暫時成功條件"
    } else {
        "oracle 觀察完成；完整 skip trace/coverage 尚未驗收"
    };
    let path = result::run(&result::RunReport {
        root,
        source,
        binary: &binary,
        binary_sha256: &binary_sha256,
        version: &actual_version,
        suite: &suite,
        tree_sha256: &tree_sha256,
        stdout_path: &stdout_path,
        stderr_path: &stderr_path,
        stdout: &stdout,
        stderr: &stderr,
        exit_code,
        elapsed_ms,
        parsed: &parsed,
        diagnostic,
        source_digest: &source_digest_before,
        infrastructure_ok,
    })?;
    if !infrastructure_ok {
        return Err(format!("{diagnostic}；report={}", path.display()));
    }
    println!(
        "oracle infrastructure PASS；Basic {}；report={}",
        if parsed.provisional_pass {
            "INCOMPLETE"
        } else {
            "FAIL"
        },
        path.display()
    );
    Ok(())
}

pub(super) fn official_tests(args: &[String]) -> Result<(), String> {
    let root = super::super::root()?;
    let profile = match args.get(1).map(String::as_str) {
        Some("lua55-i64f64") if args.first().map(String::as_str) == Some("--profile") => {
            "lua55-i64f64"
        }
        Some("lua54-i64f64") if args.first().map(String::as_str) == Some("--profile") => {
            "lua54-i64f64"
        }
        _ => "invalid",
    };
    let previous = result::report_path(&root, profile);
    if previous.is_file() {
        fs::remove_file(&previous).map_err(|error| format!("清除舊 P15 report 失敗：{error}"))?;
    }
    let outcome = (|| {
        if args.len() != 4 || args[0] != "--profile" || args[2] != "--mode" || args[3] != "basic" {
            return Err(
                "official-tests 用法：--profile lua55-i64f64|lua54-i64f64 --mode basic".into(),
            );
        }
        let source = manifest::source(&root, &args[1])?;
        run(&root, &source)
    })();
    if let Err(error) = &outcome {
        let report = result::report_path(&root, profile);
        if !report.is_file() {
            result::early_failure(&root, profile, error)?;
        }
    }
    outcome
}
