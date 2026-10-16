mod b02;
mod b03;
mod grant;
mod manifest;
mod report;
mod runner;

use report::{Check, Report};
use std::path::Path;

pub(crate) fn package_sha256_bytes(bytes: &[u8]) -> Result<String, String> {
    let digest = manifest::sha256_bytes(bytes).ok_or("SHA-256 輸入長度溢位")?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn gate(args: &[String]) -> Result<(), String> {
    let root = crate::root()?;
    let selection = match args {
        [] => Some((None, "phase")),
        [flag, batch] if flag == "--batch" && batch == "P17-B01" => {
            Some((Some("P17-B01"), "P17-B01"))
        }
        [flag, batch] if flag == "--batch" && batch == "P17-B02" => {
            Some((Some("P17-B02"), "P17-B02"))
        }
        [flag, batch] if flag == "--batch" && batch == "P17-B03" => {
            Some((Some("P17-B03"), "P17-B03"))
        }
        _ => None,
    };
    let Some((batch, suffix)) = selection else {
        let mut report = Report::new(None);
        report.diagnostic = "P17 batch selector 非法；僅接受固定 P17-B01/B02/B03 或無 batch".into();
        report
            .checks
            .push(Check::failure("batch-selector", &report.diagnostic));
        let path = report.write(&root, "invalid")?;
        return Err(format!("{}；report={}", report.diagnostic, path.display()));
    };
    let mut report = Report::new(batch);
    let result = if batch == Some("P17-B01") {
        run_b01(&root, &mut report)
    } else if batch == Some("P17-B02") {
        b02::run(&root, &mut report)
    } else if batch == Some("P17-B03") {
        b03::run(&root, &mut report)
    } else {
        b03::run_phase(&root, &mut report)
    };
    if let Err(error) = &result {
        if !matches!(batch, Some("P17-B03") | None)
            && !report.checks.iter().any(|check| check.status == "FAIL")
        {
            report.checks.push(Check::failure("preflight", error));
        }
    }
    report.diagnostic = result
        .as_ref()
        .err()
        .cloned()
        .unwrap_or_else(|| format!("{} 固定 facets 全部通過", batch.unwrap_or("P17")));
    if !report.pass() && result.is_ok() {
        report.diagnostic = if batch == Some("P17-B01") {
            "P17-B01 必要 facet/profile 缺失或零匹配"
        } else {
            "P17 必要 facet/profile 缺失或零匹配"
        }
        .into();
    }
    let path = report.write(&root, suffix)?;
    if report.pass() {
        let validation = if batch == Some("P17-B01") {
            report::validate_b01(&root, &path)
        } else if batch == Some("P17-B02") {
            b02::validate_report(&root, &path)
        } else if batch == Some("P17-B03") {
            b03::validate_report(&root, &path)
        } else {
            b03::validate_phase(&root, &path)
        };
        if let Err(error) = validation {
            report.diagnostic = if batch == Some("P17-B01") {
                format!("P17-B01 自我驗證失敗：{error}")
            } else {
                format!("P17 批次自我驗證失敗：{error}")
            };
            report
                .checks
                .push(Check::failure("report-validation", &report.diagnostic));
            report.write(&root, suffix)?;
            return Err(format!("{}；report={}", report.diagnostic, path.display()));
        }
        println!("{} PASS report={}", batch.unwrap_or("P17"), path.display());
        Ok(())
    } else {
        Err(format!("{}；report={}", report.diagnostic, path.display()))
    }
}

fn run_b01(root: &Path, report: &mut Report) -> Result<(), String> {
    let environment = runner::environment(root)?;
    report.target = environment.target.clone();
    report.environment = runner::related_environment(&environment);
    report.toolchain = runner::toolchain_identity()?;
    for path in runner::related_sources(root)? {
        report.input(&path)?;
    }
    manifest::validate(root)?;
    for profile in manifest::PROFILES {
        runner::run_profile(root, &environment, profile, report)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{manifest, report, runner};

    #[test]
    fn p17_manifest_has_exact_two_versions_and_five_modules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        manifest::validate(root).unwrap();
        assert_eq!(manifest::MODULES.len(), 5);
    }

    #[test]
    fn p17_producer_inputs_cover_native_c_and_cc_environment() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let sources = runner::related_sources(root).unwrap();
        for relative in [
            "crates/rivetlua-capi/src/trampoline.c",
            "crates/rivetlua-capi/src/native/platform.c",
            "crates/rivetlua-cli/tests/p17_native_modules.rs",
            "xtask/tests/p17_cli.rs",
            "tests/p17/native-fixtures/host_probe.c",
            "vendor/lua55/lua-5.5.1-tests/api.lua",
            "vendor/lua54/lua-5.4.9-tests/api.lua",
        ] {
            assert!(sources.contains(&root.join(relative)), "缺少 {relative}");
        }
        for (profile, expected_files) in manifest::PROFILES.into_iter().zip([43, 42]) {
            let suite = root.join(profile.suite);
            assert_eq!(
                sources
                    .iter()
                    .filter(|path| path.starts_with(&suite))
                    .count(),
                expected_files,
                "{} 必須納入完整 canonical fixture tree",
                profile.name
            );
        }
        let environment = runner::Environment {
            target_dir: root.to_path_buf(),
            evidence_dir: root.to_path_buf(),
            target: "aarch64-apple-darwin".into(),
        };
        let names = runner::related_environment(&environment)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<std::collections::BTreeSet<_>>();
        for prefix in ["CC", "CFLAGS", "AR", "ARFLAGS"] {
            for name in [
                prefix.to_owned(),
                format!("{prefix}_aarch64-apple-darwin"),
                format!("{prefix}_aarch64_apple_darwin"),
                format!("HOST_{prefix}"),
                format!("TARGET_{prefix}"),
            ] {
                assert!(names.contains(&name), "缺少環境鍵 {name}");
            }
        }
        assert!(names.contains("CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"));
    }

    #[test]
    fn p17_tarball_and_canonical_suite_match_full_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let scratch =
            std::env::temp_dir().join(format!("rivetlua-p17-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        for profile in manifest::PROFILES {
            let suite =
                manifest::verify_fixture(root, profile, &scratch.join(profile.name)).unwrap();
            assert!(suite.join("all.lua").is_file());
            assert!(suite.join("libs/makefile").is_file());
        }
        std::fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn p17_binding_rejects_each_wrong_identity() {
        let profile = manifest::PROFILES[0];
        let sha = "a".repeat(64);
        assert!(
            runner::binding(
                profile,
                profile.name,
                profile.release,
                profile.tarball_sha256,
                profile.all_lua_sha256,
                &sha,
                &sha,
                &sha,
                &sha
            )
            .is_ok()
        );
        assert!(
            runner::binding(
                profile,
                "lua54-i64f64",
                profile.release,
                profile.tarball_sha256,
                profile.all_lua_sha256,
                &sha,
                &sha,
                &sha,
                &sha
            )
            .is_err()
        );
        assert!(
            runner::binding(
                profile,
                profile.name,
                profile.release,
                profile.tarball_sha256,
                profile.all_lua_sha256,
                &sha,
                "b",
                &sha,
                &sha
            )
            .is_err()
        );
        assert!(
            runner::binding(
                profile,
                profile.name,
                profile.release,
                profile.tarball_sha256,
                profile.all_lua_sha256,
                &sha,
                &sha,
                &sha,
                "b"
            )
            .is_err()
        );
    }

    #[test]
    fn p17_report_requires_all_profiles_and_facets_with_real_counts() {
        let mut report = report::Report::new(Some("P17-B01"));
        assert!(!report.pass());
        report.checks.push(report::Check::observed(
            "fixture",
            "lua55-i64f64",
            vec![],
            std::path::Path::new("."),
            Some(0),
            None,
            true,
            "fixture",
        ));
        assert!(!report.pass());
        report.checks[0].matched = 0;
        assert!(!report.pass());
    }

    #[test]
    fn p17_validator_reads_and_rejects_fake_pass_reports() {
        use std::fs;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let scratch =
            std::env::temp_dir().join(format!("rivetlua-p17-validator-{}", std::process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("proof.log");
        let mut proof = String::from(
            "P17 synthetic validator proof\nP17_SDK_RESULT PASS\nP17_SDK_ABI revision=1 layout=37 PASS\nP17_SDK_CLOSE ALLOCATOR_RELEASE PASS\nP17_RUNNER_ARGV PASS\nP17_RUNNER_CWD PASS\nP17_RUNNER_NO_U PASS\nP17_INTENTIONAL_FAILURE\nRivetLua 0.0.0 (Lua 5.5.1)\nRivetLua 0.0.0 (Lua 5.4.9)\n",
        );
        for profile in manifest::PROFILES {
            proof.push_str(&format!(
                "P17_FIXTURE {} tar={} all={} canonical_tree=exact PASS\n",
                profile.name, profile.tarball_sha256, profile.all_lua_sha256
            ));
            proof.push_str(&format!(
                "P17_NEGATIVE_CONTROLS {} profile release tar all binary abi PASS\n",
                profile.name
            ));
        }
        fs::write(&log, proof).unwrap();
        let mut report = report::Report::new(Some("P17-B01"));
        let environment = runner::Environment {
            target_dir: scratch.clone(),
            evidence_dir: scratch.clone(),
            target: "aarch64-apple-darwin".into(),
        };
        report.target = environment.target.clone();
        report.toolchain = runner::toolchain_identity().unwrap();
        report.environment = runner::related_environment(&environment);
        for path in runner::related_sources(root).unwrap() {
            report.input(&path).unwrap();
        }
        for profile in manifest::PROFILES {
            let module_dir = scratch.join(format!("b01-{}-synthetic", profile.name));
            fs::create_dir_all(&module_dir).unwrap();
            let profile_log = module_dir.join("proof.log");
            fs::copy(&log, &profile_log).unwrap();
            for facet in [
                "fixture",
                "binary",
                "profile",
                "abi",
                "module-build",
                "module-load",
                "runner-argv",
                "runner-cwd",
                "runner-no-u",
                "runner-error",
                "negative-controls",
            ] {
                let amount = match facet {
                    "module-build" => 5,
                    "abi" | "module-load" => 2,
                    _ => 1,
                };
                for index in 0..amount {
                    let mut check = report::Check::observed(
                        facet,
                        profile.name,
                        vec!["synthetic-unit".into()],
                        root,
                        Some(if facet == "runner-error" { 1 } else { 0 }),
                        Some(report::Input::from_path(&profile_log).unwrap()),
                        true,
                        "synthetic",
                    );
                    if facet == "module-build" {
                        let (name, source) = manifest::MODULES[index];
                        let output = module_dir.join(name);
                        fs::write(&output, name).unwrap();
                        check.inputs = vec![
                            report::Input::from_path(
                                &root.join(profile.suite).join("libs").join(source),
                            )
                            .unwrap(),
                            report::Input::from_path(&output).unwrap(),
                        ];
                    } else if facet == "module-load" {
                        check.inputs = vec![report::Input::from_path(&profile_log).unwrap(); 9];
                        if index == 1 {
                            check.operation = "cli-native-load";
                            check.execution_path = "cli-rust-vm";
                        }
                    } else if facet == "abi" && index == 1 {
                        check.operation = "cc-capi-driver";
                    } else if facet == "negative-controls" {
                        check.matched = 6;
                        check.passed = 6;
                        check.negative_runs = runner::NEGATIVE_CASES
                            .into_iter()
                            .map(|(label, category)| report::NegativeRun {
                                label,
                                command: vec!["synthetic-unit".into()],
                                cwd: root.display().to_string(),
                                exit_code: Some(1),
                                log: report::Input::from_path(&profile_log).unwrap(),
                                grant: None,
                                environment: Vec::new(),
                                expected_category: category,
                                status: "PASS",
                            })
                            .collect();
                    }
                    report.checks.push(check);
                }
            }
        }
        assert!(report.pass());
        let native_index = report
            .checks
            .iter()
            .position(|check| check.operation == "cli-native-load")
            .unwrap();
        report.checks[native_index].operation = "capi-driver-load";
        assert!(!report.pass(), "同一路徑不可代替 CLI 同 VM 載入");
        report.checks[native_index].operation = "cli-native-load";
        report.checks[native_index].execution_path = "capi-independent-host";
        assert!(!report.pass(), "CLI 同 VM proof 必須有獨立 execution_path");
        report.checks[native_index].execution_path = "cli-rust-vm";
        assert!(report.pass());
        let path = scratch.join("report.json");
        let valid = report.json();
        fs::write(&path, &valid).unwrap();
        let receipt = |path: &std::path::Path| {
            let digest = manifest::sha256(path).unwrap();
            fs::write(
                path.with_extension("sha256"),
                format!("{digest}  report.json\n"),
            )
            .unwrap();
        };
        receipt(&path);
        let validate = |path: &std::path::Path| {
            report::validate_b01_with_environment_for_test(root, path, &environment)
        };
        assert_eq!(
            validate(&path).unwrap_err(),
            "P17 fixture-tree 命令/hash/tree marker 不符"
        );
        let mutations = [
            ("\"matched\":1", "\"matched\":0", "zero-match/exit/count"),
            (
                "\"log_sha256\":\"",
                "\"log_sha256\":\"wrong",
                "log SHA/path",
            ),
            (
                "\"profile\":\"lua55-i64f64\"",
                "\"profile\":\"wrong-profile\"",
                "錯誤 profile",
            ),
            (
                "\"case_id\":\"COMPLETE-002\"",
                "\"case_id\":\"OUT-OF-SCOPE\"",
                "範圍外 case",
            ),
        ];
        for (before, after, reason) in mutations {
            let forged = valid.replacen(before, after, 1);
            assert_ne!(forged, valid);
            fs::write(&path, forged).unwrap();
            receipt(&path);
            let error = validate(&path).unwrap_err();
            assert!(
                error.contains(reason),
                "未以 {reason} 拒絕 {before}：{error}"
            );
        }
        let missing_input_hash = valid.replacen(
            &format!("\"sha256\":\"{}\"", report.source_inputs[0].sha256),
            "\"sha256\":null",
            1,
        );
        assert_ne!(missing_input_hash, valid);
        fs::write(&path, missing_input_hash).unwrap();
        receipt(&path);
        assert!(
            validate(&path).unwrap_err().contains("非字串"),
            "未以缺少來源 SHA 拒絕"
        );
        for (before, after, reason) in [
            (
                "\"target\":\"aarch64-apple-darwin\"",
                "\"target\":\"wrong-target\"",
                "configuration/dependencies",
            ),
            (
                "\"operation\":\"fixture-tree\"",
                "\"operation\":\"cli-native-load\"",
                "fixture operation 不符",
            ),
            (
                "\"declared_cases\":[\"COMPLETE-002\"]",
                "\"declared_cases\":[\"COMPLETE-001\"]",
                "scope 越界",
            ),
        ] {
            let forged = valid.replacen(before, after, 1);
            assert_ne!(forged, valid);
            fs::write(&path, forged).unwrap();
            receipt(&path);
            assert!(
                validate(&path).unwrap_err().contains(reason),
                "未以 {reason} 拒絕 {before}"
            );
        }
        fs::remove_dir_all(&scratch).unwrap();
    }
}
