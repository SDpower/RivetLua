mod gate;
mod manifest;
mod matrix;
mod native;
mod report;
mod rowproof;
mod runner;
mod sdk;
mod selection;
mod valueprobe;

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

fn q(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}

fn is_sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn named_libtest_passed(log: &str, test: &str) -> bool {
    let lines = log.lines().collect::<Vec<_>>();
    let running = lines
        .iter()
        .filter(|line| line.starts_with("running "))
        .copied()
        .collect::<Vec<_>>();
    let summaries = lines
        .iter()
        .filter(|line| line.starts_with("test result:"))
        .copied()
        .collect::<Vec<_>>();
    if running != ["running 1 test"] || summaries.len() != 1 {
        return false;
    }
    let Some(rest) =
        summaries[0].strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
    else {
        return false;
    };
    let Some((filtered, elapsed)) = rest.split_once(" filtered out; finished in ") else {
        return false;
    };
    let seconds = elapsed.strip_suffix('s');
    let valid_seconds = seconds.is_some_and(|seconds| {
        let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
        !whole.is_empty()
            && whole.bytes().all(|byte| byte.is_ascii_digit())
            && (fraction.is_empty() || fraction.bytes().all(|byte| byte.is_ascii_digit()))
            && !seconds.ends_with('.')
    });
    if filtered.is_empty() || !filtered.bytes().all(|byte| byte.is_ascii_digit()) || !valid_seconds
    {
        return false;
    }
    let same_line = format!("test {test} ... ok");
    let prefix = format!("test {test} ... ");
    let test_lines = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("test ") && !line.starts_with("test result:"))
        .collect::<Vec<_>>();
    if test_lines.len() != 1 || !test_lines[0].1.starts_with(&prefix) {
        return false;
    }
    let start = test_lines[0].0;
    let Some(running_at) = lines.iter().position(|line| *line == "running 1 test") else {
        return false;
    };
    let Some(end) = lines.iter().position(|line| *line == summaries[0]) else {
        return false;
    };
    if !(running_at < start && start < end)
        || lines[start..end]
            .iter()
            .any(|line| line.contains("FAILED") || line.contains("ignored"))
    {
        return false;
    }
    if *test_lines[0].1 == same_line {
        return true;
    }
    lines[start + 1..end]
        .iter()
        .rev()
        .find(|line| !line.is_empty())
        == Some(&"ok")
}

fn evidence_mode(kind: &str, status: &str) -> &'static str {
    if status == "HEADER_ONLY" {
        return "compile-runtime-abi";
    }
    match kind {
        "constant" | "type" | "opaque_type" | "layout" | "layout_field" | "alignment" | "size" => {
            "compile-runtime-abi"
        }
        "macro" => "macro-expansion-effect",
        "function" => "public-effect-boundary",
        _ => "invalid",
    }
}

fn sha_bytes(bytes: &[u8]) -> Result<String, String> {
    let (program, prefix) = crate::sha256_tool(std::env::consts::OS)?;
    let mut child = Command::new(program)
        .args(prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("P16 SHA-256 啟動失敗：{error}"))?;
    child
        .stdin
        .take()
        .ok_or("P16 SHA-256 stdin 缺失")?
        .write_all(bytes)
        .map_err(|error| error.to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let digest = text.split_whitespace().next().unwrap_or("");
    if !output.status.success() || !is_sha(digest) {
        return Err("P16 SHA-256 指令未回傳有效 digest".into());
    }
    Ok(digest.to_ascii_lowercase())
}

fn sha_file(path: &Path) -> Result<String, String> {
    sha_bytes(
        &fs::read(path).map_err(|error| format!("P16 證據不可讀 {}：{error}", path.display()))?,
    )
}

fn host_target() -> Result<&'static str, String> {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        Ok("aarch64-apple-darwin")
    } else if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Ok("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
        Ok("aarch64-unknown-linux-gnu")
    } else {
        Err("P16 host target 不在固定矩陣".into())
    }
}

pub(super) fn acceptance(args: &[String]) -> Result<(), String> {
    let root = crate::root()?;
    let target = host_target()?;
    let profile = if args.len() == 2
        && args[0] == "--profile"
        && matrix::PROFILES.contains(&args[1].as_str())
    {
        args[1].as_str()
    } else {
        "invalid"
    };
    let path = report::path(&root, profile, target);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("清除舊 P16 acceptance report 失敗：{error}"))?;
    }
    let result = (|| -> Result<(), String> {
        if !matrix::PROFILES.contains(&profile) {
            return Err("P16 用法：p16-acceptance --profile lua55-i64f64|lua54-i64f64".into());
        }
        let cases = matrix::load(&root)?;
        let manifest = manifest::load(&root)?;
        let digest = crate::source_digest(&root)?;
        report::not_run(&root, profile, target, &digest, &cases, &manifest)?;
        runner::run(&root, profile, target, &digest, &cases, &manifest)
    })();
    if let Err(error) = &result {
        if !report::path(&root, profile, target).is_file() {
            report::early_failure(&root, profile, target, error)?;
        }
    }
    result
}

pub(super) fn gate() -> Result<(), String> {
    gate::run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_matrix_and_manifest_cover_fixed_surface() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let cases = matrix::load(root).unwrap();
        let manifest = manifest::load(root).unwrap();
        assert_eq!(cases.len(), 15);
        assert_eq!(manifest.rows.len(), 951);
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.status == "HEADER_ONLY")
                .count(),
            538
        );
        assert_eq!(
            manifest
                .rows
                .iter()
                .filter(|row| row.status != "HEADER_ONLY")
                .count(),
            413
        );
        for short in ["lua55", "lua54"] {
            gate::verify_header_set(root, &manifest, short).unwrap();
        }
    }

    #[test]
    fn p16_sha_rejects_missing_artifact() {
        assert!(sha_file(Path::new("/p16-no-such-artifact")).is_err());
        assert!(is_sha(&sha_bytes(b"P16").unwrap()));
    }

    #[test]
    fn p16_named_libtest_accepts_nocapture_interleaving_only_with_one_pass() {
        let test = "abi_005_every_identity_field_rejected_before_loader";
        let split = format!(
            "running 1 test\ntest {test} ... A26_ORDINAL checked=8\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        );
        assert!(named_libtest_passed(&split, test));
        assert!(named_libtest_passed(
            &split.replace(
                &format!("test {test} ... A26_ORDINAL checked=8\nok"),
                &format!("test {test} ... ok")
            ),
            test,
        ));
        assert!(!named_libtest_passed(
            &split.replace(test, "wrong_name"),
            test
        ));
        assert!(!named_libtest_passed(
            &split.replace("\nok\n", &format!("\nok\ntest {test} ... ok\n")),
            test,
        ));
        assert!(!named_libtest_passed(
            &split.replace("1 passed", "0 passed"),
            test
        ));
        assert!(!named_libtest_passed(
            &split.replace("\nok\n", "\nFAILED\n"),
            test
        ));
        assert!(!named_libtest_passed(&split.replace("\nok\n", "\n"), test));
        assert!(!named_libtest_passed(&split.replace("0.01s", "nans"), test));
        assert!(!named_libtest_passed(&split.replace("0.01s", "1.s"), test));
        assert!(!named_libtest_passed(
            &split.replace("running 1 test\n", ""),
            test
        ));
        assert!(!named_libtest_passed(
            &split
                .replace("running 1 test\n", "")
                .replace("test result:", "running 1 test\ntest result:"),
            test
        ));
        assert!(!named_libtest_passed(
            &split.replace("\nok\n", "\nFAILED\nok\n"),
            test
        ));
        assert!(!named_libtest_passed(
            &split.replace("0 ignored", "1 ignored"),
            test,
        ));
        assert!(!named_libtest_passed(
            &split.replace("running 1 test", "running 0 tests"),
            test,
        ));
        assert!(!named_libtest_passed(
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;",
            test
        ));
    }

    #[test]
    fn p16_header_only_constants_and_types_require_layout_runtime() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let selected54 = selection::capture(root, "lua54").unwrap();
        let selected55 = selection::capture(root, "lua55").unwrap();
        let mut mapped = 0;
        for row in manifest
            .rows
            .iter()
            .filter(|row| row.status == "HEADER_ONLY")
        {
            let observed = if row.profile == "lua54" {
                &selected54
            } else {
                &selected55
            };
            if let Ok(keys) = rowproof::required_with(root, row, Some(observed)) {
                mapped += 1;
                assert!(keys.contains(&rowproof::ProofKey::Layout(row.profile.clone())));
            }
        }
        assert!(mapped > 0);
        for kind in ["constant", "type"] {
            let row = manifest
                .rows
                .iter()
                .find(|row| {
                    row.profile == "lua55" && row.status == "HEADER_ONLY" && row.kind == kind
                })
                .unwrap();
            let keys = rowproof::required_with(root, row, Some(&selected55)).unwrap();
            assert!(keys.contains(&rowproof::ProofKey::Layout("lua55".into())));
        }
        let macro_row = manifest
            .rows
            .iter()
            .find(|row| row.status == "HEADER_ONLY" && row.kind == "macro")
            .unwrap();
        let reported = crate::StrictJsonParser::parse(&report::row_not_run(macro_row)).unwrap();
        assert_eq!(
            reported
                .get("evidence_mode")
                .and_then(crate::StrictJsonValue::as_str),
            Some("compile-runtime-abi")
        );
    }

    #[test]
    fn p16_pushfail_conditional_rows_require_distinct_c_proofs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let conditional = manifest
            .rows
            .iter()
            .find(|row| row.id == rowproof::FAILFALSE_ROW)
            .unwrap();
        let default = manifest
            .rows
            .iter()
            .find(|row| row.id == "lua55:lauxlib.h:macro:luaL_pushfail:174")
            .unwrap();
        let conditional_keys = rowproof::required_with(root, conditional, None).unwrap();
        let default_keys = rowproof::required_with(root, default, None).unwrap();
        let false_branch = rowproof::ProofKey::CFixtureFailFalse {
            profile: "lua55".into(),
        };
        let nil_branch = rowproof::ProofKey::CFixture {
            profile: "lua55".into(),
            source: rowproof::FAILFALSE_SOURCE.into(),
        };
        assert!(conditional_keys.contains(&false_branch));
        assert!(!conditional_keys.contains(&nil_branch));
        assert!(default_keys.contains(&nil_branch));
        assert!(!default_keys.contains(&false_branch));
        assert_ne!(false_branch.id(), nil_branch.id());
        for tamper in ["id", "name", "profile", "definition", "condition"] {
            let mut row = conditional.clone();
            match tamper {
                "id" => row.id = "lua55:lauxlib.h:macro:luaL_pushfail:173".into(),
                "name" => row.name = "luaL_error".into(),
                "profile" => row.profile = "lua54".into(),
                "definition" => row.definition = "#define luaL_pushfail(L) lua_pushnil(L)".into(),
                "condition" => row.condition = "#else".into(),
                _ => unreachable!(),
            }
            assert!(
                rowproof::required_with(root, &row, None).is_err(),
                "{tamper}"
            );
        }
    }

    #[test]
    fn p16_row_mapping_uses_typed_manifest_references_and_fail_closed_reasons() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = manifest::load(root).unwrap();
        let selected54 = selection::capture(root, "lua54").unwrap();
        let selected55 = selection::capture(root, "lua55").unwrap();
        let mut mapped = 0;
        let mut reasons = std::collections::BTreeMap::<String, usize>::new();
        let mut samples = std::collections::BTreeMap::<String, Vec<String>>::new();
        let mut kinds = std::collections::BTreeMap::<String, usize>::new();
        let mut distinct = std::collections::BTreeSet::new();
        let mut legacy_total = 0;
        let mut legacy_mapped = 0;
        let mut legacy_reasons = std::collections::BTreeMap::<String, usize>::new();
        for row in &manifest.rows {
            let legacy = row.evidence.contains("NOT_RUN");
            if legacy {
                legacy_total += 1;
            }
            let observed = if row.profile == "lua54" {
                &selected54
            } else {
                &selected55
            };
            match rowproof::required_with(root, row, Some(observed)) {
                Ok(proofs) => {
                    mapped += 1;
                    if legacy {
                        legacy_mapped += 1;
                    }
                    assert!(!proofs.is_empty());
                    for proof in proofs {
                        *kinds.entry(proof.kind().into()).or_default() += 1;
                        distinct.insert(proof.id());
                    }
                }
                Err(reason) => {
                    if legacy {
                        *legacy_reasons.entry(reason.clone()).or_default() += 1;
                    }
                    *reasons.entry(reason.clone()).or_default() += 1;
                    let ids = samples.entry(reason).or_default();
                    if ids.len() < 4 {
                        ids.push(row.id.clone());
                    }
                }
            }
        }
        eprintln!(
            "P16 typed row mapping: mapped={mapped} unmapped={} distinct_proofs={} legacy_NOT_RUN={legacy_total}/mapped={legacy_mapped}/unmapped={} legacy_reasons={legacy_reasons:?} kinds={kinds:?} reasons={reasons:?} samples={samples:?}",
            manifest.rows.len() - mapped,
            distinct.len(),
            legacy_total - legacy_mapped
        );
        assert!(mapped > 6);
        assert_eq!(mapped + reasons.values().sum::<usize>(), 951);
        let row = manifest
            .rows
            .iter()
            .find(|row| row.name == "luaL_newstate" && row.profile == "lua55")
            .unwrap();
        let mut tampered = row.clone();
        tampered
            .evidence
            .push_str(";crates/rivetlua-capi/tests/unknown.rs:no_test:lua55+lua54:PASS");
        assert!(rowproof::required(root, &tampered).is_err());
        let mut wrong_profile = row.clone();
        wrong_profile.evidence = wrong_profile
            .evidence
            .replace("lua55+lua54:PASS", "lua54:PASS");
        assert!(rowproof::required(root, &wrong_profile).is_err());
        let mut missing = row.clone();
        missing.evidence = "tests/p16/surface_lua55.c:COMPILE_ONLY".into();
        assert!(rowproof::required(root, &missing).is_err());
    }
}
