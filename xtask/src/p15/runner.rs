use super::{manifest, parser, result};
use std::env;
use std::ffi::OsStr;
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

fn build_paths(
    root: &Path,
    profile: &str,
    configured_target: Option<&OsStr>,
) -> Result<(PathBuf, PathBuf), String> {
    let artifact_dir = root
        .join("target/rivetlua-p15")
        .join(format!("build-{profile}"));
    let target = match configured_target {
        Some(value) => {
            let path = Path::new(value);
            if !path.is_absolute() {
                return Err("P15 CARGO_TARGET_DIR 必須為既有的絕對外接目錄".into());
            }
            let target = fs::canonicalize(path)
                .map_err(|error| format!("P15 CARGO_TARGET_DIR 無效：{error}"))?;
            if !target.is_dir() {
                return Err("P15 CARGO_TARGET_DIR 必須是目錄".into());
            }
            let root = fs::canonicalize(root)
                .map_err(|error| format!("P15 workspace 路徑無效：{error}"))?;
            if target.starts_with(root) {
                return Err("P15 CARGO_TARGET_DIR 必須位於 workspace 以外".into());
            }
            target
        }
        None => artifact_dir.clone(),
    };
    Ok((target, artifact_dir.join("debug/rivetlua")))
}

fn archive_binary(target: &Path, artifact: &Path) -> Result<PathBuf, String> {
    let built = fs::canonicalize(target.join("debug/rivetlua"))
        .map_err(|error| format!("P15 建置 binary 不存在：{error}"))?;
    let parent = artifact.parent().ok_or("P15 binary 封存路徑沒有父目錄")?;
    fs::create_dir_all(parent).map_err(|error| format!("建立 P15 binary 封存目錄失敗：{error}"))?;
    let destination = fs::canonicalize(parent)
        .map_err(|error| format!("P15 binary 封存目錄不可讀：{error}"))?
        .join("rivetlua");
    if built != destination {
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("P15 binary 封存目標不得是 symlink".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("檢查 P15 binary 封存目標失敗：{error}")),
        }
        fs::copy(&built, &destination).map_err(|error| format!("封存 P15 binary 失敗：{error}"))?;
    }
    fs::canonicalize(artifact).map_err(|error| format!("P15 封存 binary 不存在：{error}"))
}

fn build(root: &Path, source: &manifest::Source) -> Result<PathBuf, String> {
    let configured_target = env::var_os("CARGO_TARGET_DIR");
    let (target, artifact) = build_paths(root, source.profile, configured_target.as_deref())?;
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
    archive_binary(&target, &artifact)
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

#[cfg(test)]
mod tests {
    use super::{archive_binary, build_paths};
    use std::ffi::OsStr;
    use std::fs;
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> std::path::PathBuf {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        scratch_with_timestamp(time)
    }

    fn scratch_with_timestamp(time: u128) -> std::path::PathBuf {
        loop {
            let id = NEXT_SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rivetlua-p15-build-paths-{}-{time}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("建立 P15 測試暫存目錄失敗：{error}"),
            }
        }
    }

    #[test]
    fn p15_scratch_is_unique_for_parallel_callers_at_the_same_timestamp() {
        use std::collections::HashSet;
        use std::sync::{Arc, Barrier};
        use std::thread;

        let callers = 8;
        let barrier = Arc::new(Barrier::new(callers));
        let handles = (0..callers)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    scratch_with_timestamp(0)
                })
            })
            .collect::<Vec<_>>();
        let paths = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(paths.iter().collect::<HashSet<_>>().len(), callers);
        for path in paths {
            assert!(path.is_dir());
            fs::remove_dir(path).unwrap();
        }
    }

    #[test]
    fn p15_build_paths_use_external_target_and_reject_invalid_values() {
        let scratch = scratch();
        let root = scratch.join("repo");
        let external = scratch.join("shared-cache");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&external).unwrap();
        fs::create_dir(root.join("target")).unwrap();

        let artifact = root.join("target/rivetlua-p15/build-lua55-i64f64/debug/rivetlua");
        let (target, selected_artifact) =
            build_paths(&root, "lua55-i64f64", Some(external.as_os_str())).unwrap();
        assert_eq!(target, fs::canonicalize(&external).unwrap());
        assert_eq!(selected_artifact, artifact);
        assert_eq!(
            build_paths(&root, "lua55-i64f64", None).unwrap(),
            (
                artifact.parent().unwrap().parent().unwrap().to_path_buf(),
                artifact
            )
        );
        assert!(build_paths(&root, "lua55-i64f64", Some(OsStr::new(""))).is_err());
        assert!(build_paths(&root, "lua55-i64f64", Some(OsStr::new("relative"))).is_err());
        assert!(build_paths(&root, "lua55-i64f64", Some(root.join("target").as_os_str())).is_err());
        assert!(
            build_paths(
                &root,
                "lua55-i64f64",
                Some(scratch.join("missing").as_os_str())
            )
            .is_err()
        );

        fs::remove_dir_all(scratch).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn p15_shared_target_archives_both_profiles_and_skips_self_copy() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let scratch = scratch();
        let root = scratch.join("repo");
        let target = scratch.join("shared-cache");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(target.join("debug")).unwrap();
        let built = target.join("debug/rivetlua");
        let artifact55 = root.join("target/rivetlua-p15/build-lua55-i64f64/debug/rivetlua");
        let artifact54 = root.join("target/rivetlua-p15/build-lua54-i64f64/debug/rivetlua");

        fs::write(&built, b"#!/bin/sh\nprintf '55\\n'\n").unwrap();
        fs::set_permissions(&built, fs::Permissions::from_mode(0o755)).unwrap();
        let archived55 = archive_binary(&target, &artifact55).unwrap();
        assert_eq!(archived55, fs::canonicalize(&artifact55).unwrap());
        assert_eq!(Command::new(&archived55).output().unwrap().stdout, b"55\n");

        fs::write(&built, b"#!/bin/sh\nprintf '54\\n'\n").unwrap();
        let archived54 = archive_binary(&target, &artifact54).unwrap();
        assert_eq!(Command::new(&archived54).output().unwrap().stdout, b"54\n");
        assert_eq!(Command::new(&archived55).output().unwrap().stdout, b"55\n");
        assert_ne!(
            fs::read(&archived55).unwrap(),
            fs::read(&archived54).unwrap()
        );
        assert_ne!(
            fs::metadata(&archived55).unwrap().permissions().mode() & 0o111,
            0
        );
        assert_ne!(
            fs::metadata(&archived54).unwrap().permissions().mode() & 0o111,
            0
        );
        let legacy_target = artifact55.parent().unwrap().parent().unwrap();
        assert_eq!(
            archive_binary(legacy_target, &artifact55).unwrap(),
            archived55
        );
        assert_eq!(Command::new(&archived55).output().unwrap().stdout, b"55\n");

        fs::remove_dir_all(scratch).unwrap();
    }
}
