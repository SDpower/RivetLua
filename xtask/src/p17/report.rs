use super::{grant, manifest};
use crate::{StrictJsonParser, StrictJsonValue};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub(super) fn q(value: &str) -> String {
    format!("\"{}\"", crate::json_escape(value))
}

fn strings(values: &[String]) -> String {
    values
        .iter()
        .map(|value| q(value))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone)]
pub(super) struct Input {
    pub path: String,
    pub sha256: String,
}

pub(super) struct HistoricalSource {
    pub before_sha256: String,
    pub snapshot: PathBuf,
}

#[derive(Default)]
pub(super) struct PhaseSourceView {
    historical: BTreeMap<String, HistoricalSource>,
    old_absent: BTreeSet<String>,
    historical_environment: Option<Vec<(String, String)>>,
}

impl PhaseSourceView {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn insert(&mut self, path: String, source: HistoricalSource) {
        self.historical.insert(path, source);
    }

    pub(super) fn mark_old_absent(&mut self, path: String) {
        self.old_absent.insert(path);
    }

    pub(super) fn was_absent(&self, path: &str) -> bool {
        self.old_absent.contains(path)
    }

    pub(super) fn set_historical_environment(
        &mut self,
        environment: Vec<(String, String)>,
    ) -> Result<(), String> {
        if self.historical_environment.is_some() {
            return Err("P17 phase 歷史 environment 重複設定".into());
        }
        self.historical_environment = Some(environment);
        Ok(())
    }

    fn get(&self, path: &str) -> Option<&HistoricalSource> {
        self.historical.get(path)
    }
}

pub(super) fn parse_historical_environment(
    value: &StrictJsonValue,
    current: &super::runner::Environment,
) -> Result<Vec<(String, String)>, String> {
    let entries = value
        .as_array()
        .ok_or("P17 phase 歷史 environment 非陣列")?;
    let expected = super::runner::related_environment(current);
    if entries.len() != expected.len() {
        return Err("P17 phase 歷史 environment 欄位數不符".into());
    }
    let mut observed = Vec::with_capacity(entries.len());
    for (item, (expected_name, expected_value)) in entries.iter().zip(expected) {
        let StrictJsonValue::Object(fields) = item else {
            return Err("P17 phase 歷史 environment 元素非物件".into());
        };
        if fields.len() != 2
            || fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["name", "value"])
        {
            return Err("P17 phase 歷史 environment 元素欄位不符".into());
        }
        let name = string(item, "name")?;
        let value = string(item, "value")?;
        if name != expected_name
            || value.is_empty()
            || (matches!(
                name,
                "CARGO_TARGET_DIR" | "RIVETLUA_P17_EVIDENCE_DIR" | "SDK_HOST_TRUST"
            ) && value != expected_value)
        {
            return Err(format!("P17 phase 歷史 environment 名稱／值不符：{name}"));
        }
        observed.push((name.to_owned(), value.to_owned()));
    }
    Ok(observed)
}

pub(super) fn expected_environment(
    current: &super::runner::Environment,
    view: Option<&PhaseSourceView>,
) -> Vec<(String, String)> {
    view.and_then(|view| view.historical_environment.as_ref())
        .cloned()
        .unwrap_or_else(|| super::runner::related_environment(current))
}

pub(super) fn historical_input(
    value: &StrictJsonValue,
    view: &PhaseSourceView,
) -> Result<Option<String>, String> {
    let path = string(value, "path")?;
    if view.was_absent(path) {
        return Err(format!("P17 phase 舊報告聲稱不存在的 source：{path}"));
    }
    let Some(source) = view.get(path) else {
        return Ok(None);
    };
    if !Path::new(path).is_absolute()
        || string(value, "sha256")? != source.before_sha256
        || manifest::sha256(&source.snapshot)? != source.before_sha256
    {
        return Err(format!("P17 phase 歷史 source/snapshot SHA 不符：{path}"));
    }
    Ok(Some(path.to_owned()))
}

pub(super) fn phase_relocated_source(
    original_root: &Path,
    current_root: &Path,
    recorded: &str,
    expected_sha256: &str,
) -> Result<PathBuf, String> {
    let old = Path::new(recorded);
    let relative = old
        .strip_prefix(original_root)
        .map_err(|_| format!("P17 phase source 越出原repo：{recorded}"))?;
    if !old.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || original_root.join(relative) != old
    {
        return Err(format!("P17 phase source 非固定 repo 路徑：{recorded}"));
    }
    let canonical_root = fs::canonicalize(current_root).map_err(|error| error.to_string())?;
    if !current_root.is_absolute() || canonical_root != current_root {
        return Err("P17 phase current checkout root 非正規絕對路徑".into());
    }
    let current = current_root.join(relative);
    if !fs::symlink_metadata(&current)
        .map_err(|error| error.to_string())?
        .file_type()
        .is_file()
        || !fs::canonicalize(&current)
            .map_err(|error| error.to_string())?
            .starts_with(&canonical_root)
        || manifest::sha256(&current)? != expected_sha256
    {
        return Err(format!(
            "P17 phase current source 缺失／SHA不符：{}",
            relative.display()
        ));
    }
    Ok(relative.to_path_buf())
}

pub(super) fn phase_copied_report(
    current_root: &Path,
    original_root: &Path,
    batch: &str,
    expected_sha256: &str,
) -> Result<(), String> {
    if !["B01", "B02", "B03"].contains(&batch) {
        return Err("P17 phase copy 範圍外批次".into());
    }
    let relative = format!("target/rivetlua-reports/gate-P17-{batch}.json");
    let original = original_root.join(&relative);
    let current = current_root.join(&relative);
    let original_receipt = original.with_extension("sha256");
    let current_receipt = current.with_extension("sha256");
    let canonical_current = fs::canonicalize(current_root).map_err(|error| error.to_string())?;
    if canonical_current != current_root {
        return Err("P17 phase report copy 的 current root 非正規絕對路徑".into());
    }
    for path in [&original, &current, &original_receipt, &current_receipt] {
        if !fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_file()
        {
            return Err(format!("P17 phase {batch} report copy 非一般檔案"));
        }
    }
    if !fs::canonicalize(&current)
        .map_err(|error| error.to_string())?
        .starts_with(&canonical_current)
        || !fs::canonicalize(&current_receipt)
            .map_err(|error| error.to_string())?
            .starts_with(&canonical_current)
    {
        return Err(format!("P17 phase {batch} report copy 越出 current root"));
    }
    if manifest::sha256(&original)? != expected_sha256
        || manifest::sha256(&current)? != expected_sha256
    {
        return Err(format!("P17 phase {batch} report copy SHA 不符"));
    }
    let name = format!("gate-P17-{batch}.json");
    let receipt = format!("{expected_sha256}  {name}\n");
    for path in [&original_receipt, &current_receipt] {
        if fs::read_to_string(path).map_err(|error| error.to_string())? != receipt {
            return Err(format!("P17 phase {batch} report copy receipt 不符"));
        }
    }
    if fs::read(&original).map_err(|error| error.to_string())?
        != fs::read(&current).map_err(|error| error.to_string())?
        || fs::read(&original_receipt).map_err(|error| error.to_string())?
            != fs::read(&current_receipt).map_err(|error| error.to_string())?
    {
        return Err(format!("P17 phase {batch} report/receipt copy bytes 不符"));
    }
    Ok(())
}

impl Input {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        Ok(Self {
            path: path.display().to_string(),
            sha256: manifest::sha256(path)?,
        })
    }

    pub(super) fn json(&self) -> String {
        format!(
            "{{\"path\":{},\"sha256\":{}}}",
            q(&self.path),
            q(&self.sha256)
        )
    }
}

pub(super) struct NegativeRun {
    pub label: &'static str,
    pub command: Vec<String>,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub log: Input,
    pub grant: Option<Input>,
    pub environment: Vec<(String, String)>,
    pub expected_category: &'static str,
    pub status: &'static str,
}

impl NegativeRun {
    fn json(&self) -> String {
        let command = strings(&self.command);
        let grant = self
            .grant
            .as_ref()
            .map_or_else(|| "null".into(), Input::json);
        let exit = self
            .exit_code
            .map_or_else(|| "null".into(), |value| value.to_string());
        let environment = self
            .environment
            .iter()
            .map(|(name, value)| format!("{{\"name\":{},\"value\":{}}}", q(name), q(value)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"label\":{},\"command\":[{command}],\"cwd\":{},\"exit_code\":{exit},\"log\":{},\"grant\":{grant},\"environment\":[{environment}],\"expected_category\":{},\"status\":{}}}",
            q(self.label),
            q(&self.cwd),
            self.log.json(),
            q(self.expected_category),
            q(self.status),
        )
    }
}

pub(super) struct Check {
    pub case_id: String,
    pub facet: String,
    pub operation: &'static str,
    pub execution_path: &'static str,
    pub profile: Option<String>,
    pub command: Vec<String>,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub matched: u32,
    pub passed: u32,
    pub failed: u32,
    pub ignored: u32,
    pub status: &'static str,
    pub log: Option<Input>,
    pub inputs: Vec<Input>,
    pub environment: Vec<(String, String)>,
    pub negative_runs: Vec<NegativeRun>,
    pub diagnostic: String,
}

impl Check {
    pub fn failure(facet: &str, diagnostic: &str) -> Self {
        let mut check = Self::pending(facet, None, diagnostic);
        check.status = "FAIL";
        check
    }
    pub fn pending(facet: &str, profile: Option<&str>, diagnostic: &str) -> Self {
        Self {
            case_id: "COMPLETE-002".into(),
            facet: facet.into(),
            operation: "not-run",
            execution_path: "not-run",
            profile: profile.map(str::to_owned),
            command: Vec::new(),
            cwd: String::new(),
            exit_code: None,
            matched: 0,
            passed: 0,
            failed: 0,
            ignored: 0,
            status: "NOT_RUN",
            log: None,
            inputs: Vec::new(),
            environment: Vec::new(),
            negative_runs: Vec::new(),
            diagnostic: diagnostic.into(),
        }
    }

    pub fn observed(
        facet: &str,
        profile: &str,
        command: Vec<String>,
        cwd: &Path,
        exit_code: Option<i32>,
        log: Option<Input>,
        passed: bool,
        diagnostic: &str,
    ) -> Self {
        Self {
            case_id: "COMPLETE-002".into(),
            facet: facet.into(),
            operation: match facet {
                "fixture" => "fixture-tree",
                "binary" => "cargo-cli-build",
                "profile" => "cli-version",
                "abi" => "cargo-capi-build",
                "module-build" => "cc-sdk-module",
                "module-load" => "capi-driver-load",
                "runner-argv" | "runner-cwd" | "runner-no-u" => "cli-runner-ok",
                "runner-error" => "cli-runner-error",
                "negative-controls" => "binding-negative",
                _ => "unexpected",
            },
            execution_path: if facet == "module-build" || facet == "module-load" || facet == "abi" {
                "capi-independent-host"
            } else if facet.starts_with("runner-") || facet == "profile" || facet == "binary" {
                "cli-rust-vm"
            } else {
                "p17-preflight"
            },
            profile: Some(profile.into()),
            command,
            cwd: cwd.display().to_string(),
            exit_code,
            matched: 1,
            passed: u32::from(passed),
            failed: u32::from(!passed),
            ignored: 0,
            status: if passed { "PASS" } else { "FAIL" },
            log,
            inputs: Vec::new(),
            environment: Vec::new(),
            negative_runs: Vec::new(),
            diagnostic: diagnostic.into(),
        }
    }

    fn json(&self) -> String {
        let log_path = self
            .log
            .as_ref()
            .map_or_else(|| "null".into(), |v| q(&v.path));
        let log_sha = self
            .log
            .as_ref()
            .map_or_else(|| "null".into(), |v| q(&v.sha256));
        let profile = self.profile.as_deref().map_or_else(|| "null".into(), q);
        let exit = self
            .exit_code
            .map_or_else(|| "null".into(), |v| v.to_string());
        let inputs = self
            .inputs
            .iter()
            .map(Input::json)
            .collect::<Vec<_>>()
            .join(",");
        let environment = self
            .environment
            .iter()
            .map(|(name, value)| format!("{{\"name\":{},\"value\":{}}}", q(name), q(value)))
            .collect::<Vec<_>>()
            .join(",");
        let negative_runs = self
            .negative_runs
            .iter()
            .map(NegativeRun::json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"case_id\":{},\"facet\":{},\"operation\":{},\"execution_path\":{},\"profile\":{},\"command\":[{}],\"cwd\":{},\"exit_code\":{},\"matched\":{},\"passed\":{},\"failed\":{},\"ignored\":{},\"status\":{},\"log_path\":{},\"log_sha256\":{},\"inputs\":[{}],\"environment\":[{}],\"negative_runs\":[{negative_runs}],\"diagnostic\":{}}}",
            q(&self.case_id),
            q(&self.facet),
            q(self.operation),
            q(self.execution_path),
            profile,
            strings(&self.command),
            q(&self.cwd),
            exit,
            self.matched,
            self.passed,
            self.failed,
            self.ignored,
            q(self.status),
            log_path,
            log_sha,
            inputs,
            environment,
            q(&self.diagnostic)
        )
    }
}

pub(super) struct Report {
    pub batch: Option<&'static str>,
    pub diagnostic: String,
    pub checks: Vec<Check>,
    pub source_inputs: Vec<Input>,
    pub dependencies: Vec<Input>,
    pub target: String,
    pub toolchain: String,
    pub environment: Vec<(String, String)>,
    pub b02: Option<super::b02::Evidence>,
    pub b03: Option<super::b03::Evidence>,
    pub phase: Option<super::b03::PhaseEvidence>,
}

impl Report {
    pub fn new(batch: Option<&'static str>) -> Self {
        Self {
            batch,
            diagnostic: String::new(),
            checks: Vec::new(),
            source_inputs: Vec::new(),
            dependencies: Vec::new(),
            target: String::new(),
            toolchain: String::new(),
            environment: Vec::new(),
            b02: None,
            b03: None,
            phase: None,
        }
    }

    pub fn input(&mut self, path: &Path) -> Result<(), String> {
        let input = Input::from_path(path)?;
        if let Some(prior) = self
            .source_inputs
            .iter()
            .find(|item| item.path == input.path)
        {
            if prior.sha256 != input.sha256 {
                return Err(format!("P17 source input 建置期間變更：{}", input.path));
            }
        } else {
            self.source_inputs.push(input);
        }
        Ok(())
    }

    pub fn pass(&self) -> bool {
        if self.batch == Some("P17-B03") {
            return self.b03.is_some()
                && self.checks.len() == 18
                && ["lua55-i64f64", "lua54-i64f64"].iter().all(|profile| {
                    super::b03::CASES.iter().all(|spec| {
                        self.checks
                            .iter()
                            .filter(|check| {
                                check.profile.as_deref() == Some(profile)
                                    && check
                                        .diagnostic
                                        .contains(&format!("\"case_id\":\"{}\"", spec.id()))
                            })
                            .count()
                            == 1
                    })
                })
                && self.checks.iter().all(|check| {
                    check.status == "PASS"
                        && check.matched == 1
                        && check.passed == 1
                        && check.failed == 0
                        && check.ignored == 0
                        && check.exit_code == Some(0)
                        && check.log.is_some()
                });
        }
        if self.batch.is_none() {
            let platform = self
                .phase
                .as_ref()
                .is_some_and(super::b03::PhaseEvidence::requires_platform);
            return self.b03.is_none()
                && self.checks.len() == if platform { 4 } else { 2 }
                && ["lua55-i64f64", "lua54-i64f64"].iter().all(|profile| {
                    let suite = self
                        .checks
                        .iter()
                        .filter(|check| {
                            check.profile.as_deref() == Some(profile)
                                && check.case_id == "COMPLETE-001"
                                && check.facet == "full-suite"
                                && check.operation == "cli-all-lua"
                                && check.status == "PASS"
                                && check.matched == 1
                                && check.passed == 1
                                && check.failed == 0
                                && check.ignored == 0
                                && check.exit_code == Some(0)
                        })
                        .count()
                        == 1;
                    let platform_check = !platform
                        || self
                            .checks
                            .iter()
                            .filter(|check| {
                                check.profile.as_deref() == Some(profile)
                                    && check.case_id == "COMPLETE-004"
                                    && check.facet == "platform"
                                    && check.operation == "b03-platform-cli"
                                    && check.execution_path == "cli-rust-vm"
                                    && check.status == "PASS"
                                    && check.matched == 1
                                    && check.passed == 1
                                    && check.failed == 0
                                    && check.ignored == 0
                                    && check.exit_code == Some(0)
                            })
                            .count()
                            == 1;
                    suite && platform_check
                });
        }
        if self.batch == Some("P17-B02") {
            return self.b02.as_ref().is_some_and(super::b02::Evidence::pass)
                && self.checks.len() == super::b02::FAMILIES.len()
                && self.checks.iter().all(|check| {
                    check.case_id == "COMPLETE-005"
                        && check.facet == "internal-mapping"
                        && check.operation == "b02-case"
                        && check.status == "PASS"
                        && check.matched > 0
                        && check.passed == check.matched
                        && check.failed == 0
                        && check.ignored == 0
                })
                && super::b02::FAMILIES.iter().all(|family| {
                    self.checks
                        .iter()
                        .filter(|check| check.diagnostic == *family)
                        .count()
                        == 1
                });
        }
        let facets = [
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
        ];
        self.batch == Some("P17-B01")
            && self.checks.iter().all(|check| {
                facets.contains(&check.facet.as_str())
                    && check.case_id == "COMPLETE-002"
                    && matches!(
                        check.profile.as_deref(),
                        Some("lua55-i64f64" | "lua54-i64f64")
                    )
                    && check.status == "PASS"
                    && if check.facet == "negative-controls" {
                        check.matched == 6
                            && check.negative_runs.len() == super::runner::NEGATIVE_CASES.len()
                            && check
                                .negative_runs
                                .iter()
                                .zip(super::runner::NEGATIVE_CASES)
                                .all(|(run, (label, category))| {
                                    run.label == label
                                        && run.expected_category == category
                                        && run.status == "PASS"
                                        && run.exit_code.is_some_and(|exit| exit != 0)
                                })
                    } else {
                        check.matched == 1 && check.negative_runs.is_empty()
                    }
                    && check.passed == check.matched
                    && check.failed == 0
                    && check.ignored == 0
                    && check.log.as_ref().is_some_and(|log| log.sha256.len() == 64)
                    && if check.facet == "runner-error" {
                        check.exit_code.is_some_and(|code| code != 0)
                    } else {
                        check.exit_code == Some(0)
                    }
            })
            && ["lua55-i64f64", "lua54-i64f64"].iter().all(|profile| {
                facets.iter().all(|facet| {
                    self.checks
                        .iter()
                        .filter(|check| {
                            check.profile.as_deref() == Some(profile) && check.facet == *facet
                        })
                        .count()
                        == match *facet {
                            "module-build" => 5,
                            "module-load" => 2,
                            "abi" => 2,
                            _ => 1,
                        }
                }) && self
                    .checks
                    .iter()
                    .filter(|check| {
                        check.profile.as_deref() == Some(profile)
                            && check.facet == "module-load"
                            && check.execution_path == "capi-independent-host"
                    })
                    .count()
                    == 1
                    && self
                        .checks
                        .iter()
                        .filter(|check| {
                            check.profile.as_deref() == Some(profile)
                                && check.facet == "module-load"
                                && check.execution_path == "cli-rust-vm"
                        })
                        .count()
                        == 1
                    && [
                        ("fixture-tree", 1),
                        ("cargo-cli-build", 1),
                        ("cli-version", 1),
                        ("cargo-capi-build", 1),
                        ("cc-capi-driver", 1),
                        ("cc-sdk-module", 5),
                        ("capi-driver-load", 1),
                        ("cli-native-load", 1),
                        ("cli-runner-ok", 3),
                        ("cli-runner-error", 1),
                        ("binding-negative", 1),
                    ]
                    .iter()
                    .all(|(operation, amount)| {
                        self.checks
                            .iter()
                            .filter(|check| {
                                check.profile.as_deref() == Some(profile)
                                    && check.operation == *operation
                            })
                            .count()
                            == *amount
                    })
            })
    }

    pub fn json(&self) -> String {
        let batch = self.batch.map_or_else(|| "null".into(), q);
        let (cases, facets, selectors, execution_paths): (&[&str], &[&str], &[&str], &[&str]) =
            match self.batch {
                Some("P17-B01") => (
                    &["COMPLETE-002"],
                    &[
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
                    ],
                    &["COMPLETE-002:lua55-i64f64", "COMPLETE-002:lua54-i64f64"],
                    &["p17-preflight", "capi-independent-host", "cli-rust-vm"],
                ),
                Some("P17-B02") => (
                    &["COMPLETE-005"],
                    &["internal-mapping"],
                    &["P17-B02"],
                    &["capi-public", "b01-evidence"],
                ),
                Some("P17-B03") => (
                    &["COMPLETE-003", "COMPLETE-004", "COMPLETE-006"],
                    &["lifecycle", "stress", "platform", "fuzz"],
                    &["P17-B03"],
                    &[
                        "capi-independent-host",
                        "capi-public",
                        "cli-rust-vm",
                        "c-platform",
                    ],
                ),
                _ => (
                    &[
                        "COMPLETE-001",
                        "COMPLETE-002",
                        "COMPLETE-003",
                        "COMPLETE-004",
                        "COMPLETE-005",
                        "COMPLETE-006",
                    ],
                    if self
                        .phase
                        .as_ref()
                        .is_some_and(super::b03::PhaseEvidence::requires_platform)
                    {
                        &["batch-dependency", "full-suite", "platform"]
                    } else {
                        &["batch-dependency", "full-suite"]
                    },
                    &["P17-B01", "P17-B02", "P17-B03"],
                    &["cli-rust-vm", "p17-evidence"],
                ),
            };
        let json_list = |items: &[&str]| {
            items
                .iter()
                .map(|item| q(item))
                .collect::<Vec<_>>()
                .join(",")
        };
        let cases = json_list(cases);
        let facets = json_list(facets);
        let selectors = json_list(selectors);
        let execution_paths = json_list(execution_paths);
        let inputs = self
            .source_inputs
            .iter()
            .map(Input::json)
            .collect::<Vec<_>>()
            .join(",");
        let checks = self
            .checks
            .iter()
            .map(Check::json)
            .collect::<Vec<_>>()
            .join(",");
        let dependencies = self
            .dependencies
            .iter()
            .map(Input::json)
            .collect::<Vec<_>>()
            .join(",");
        let environment = self
            .environment
            .iter()
            .map(|(name, value)| format!("{{\"name\":{},\"value\":{}}}", q(name), q(value)))
            .collect::<Vec<_>>()
            .join(",");
        let b02 = self.b02.as_ref().map_or_else(String::new, |evidence| {
            format!(",\"internal_mapping\":{}", evidence.json())
        });
        let b03 = self.b03.as_ref().map_or_else(String::new, |evidence| {
            format!(",\"stress_evidence\":{}", evidence.json())
        });
        let phase = self.phase.as_ref().map_or_else(String::new, |evidence| {
            format!(",\"phase_evidence\":{}", evidence.json())
        });
        format!(
            "{{\"schema\":\"rivetlua-phase-gate-v1\",\"phase\":\"P17\",\"batch\":{batch},\"status\":{},\"diagnostic\":{},\"scope\":{{\"phase\":\"P17\",\"batch\":{batch},\"declared_cases\":[{cases}],\"declared_facets\":[{facets}],\"selectors\":[{selectors}],\"execution_paths\":[{execution_paths}]}},\"source_inputs\":[{inputs}],\"configuration\":{{\"profiles\":[\"lua55-i64f64\",\"lua54-i64f64\"],\"target\":{},\"features\":[\"native-lua55\",\"default-lua54,native-lua54\"],\"toolchain\":{},\"environment\":[{environment}]}},\"dependencies\":[{dependencies}],\"checks\":[{checks}]{b02}{b03}{phase}}}\n",
            q(if self.pass() { "PASS" } else { "FAIL" }),
            q(&self.diagnostic),
            q(&self.target),
            q(&self.toolchain),
        )
    }

    pub fn write(&self, root: &Path, suffix: &str) -> Result<PathBuf, String> {
        let name = if suffix == "phase" {
            "gate-P17.json".to_owned()
        } else if matches!(suffix, "P17-B01" | "P17-B02" | "P17-B03") {
            format!("gate-{suffix}.json")
        } else {
            "gate-P17-invalid.json".to_owned()
        };
        let path = root.join("target/rivetlua-reports").join(name);
        fs::create_dir_all(path.parent().ok_or("P17 report parent 缺失")?)
            .map_err(|error| format!("P17 report 目錄失敗：{error}"))?;
        fs::write(&path, self.json()).map_err(|error| format!("P17 report 寫入失敗：{error}"))?;
        let digest = manifest::sha256(&path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("P17 report 名稱無效")?;
        fs::write(path.with_extension("sha256"), format!("{digest}  {name}\n"))
            .map_err(|error| format!("P17 report SHA receipt 寫入失敗：{error}"))?;
        Ok(path)
    }
}

fn property<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value
        .get(name)
        .ok_or_else(|| format!("P17 report 缺 {name}"))
}

fn string<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    property(value, name)?
        .as_str()
        .ok_or_else(|| format!("P17 report {name} 非字串"))
}

fn array<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a [StrictJsonValue], String> {
    property(value, name)?
        .as_array()
        .ok_or_else(|| format!("P17 report {name} 非陣列"))
}

fn strings_exact(values: &[StrictJsonValue], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_str() == Some(*expected))
}

#[derive(Clone, PartialEq, Eq)]
struct CheckedInputIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn checked_input_identity(path: &Path) -> Result<CheckedInputIdentity, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err(format!("P17 scoped report input 非一般檔案：{}", path.display()));
    }
    Ok(CheckedInputIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[derive(Clone)]
struct CheckedInputEntry {
    sha256: String,
    identity: CheckedInputIdentity,
}

#[derive(Default)]
struct CheckedInputState {
    entries: BTreeMap<PathBuf, CheckedInputEntry>,
    hash_reads: usize,
}

thread_local! {
    static CHECKED_INPUT_SCOPE: RefCell<Option<CheckedInputState>> = RefCell::new(None);
}

pub(super) struct CheckedInputScope {
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

pub(super) fn begin_checked_input_scope() -> Result<CheckedInputScope, String> {
    CHECKED_INPUT_SCOPE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("P17 checked input scope 不可巢狀".into());
        }
        *slot = Some(CheckedInputState::default());
        Ok(CheckedInputScope { active: true, _not_send: PhantomData })
    })
}

impl CheckedInputScope {
    pub(super) fn finish(mut self) -> Result<usize, String> {
        let state = CHECKED_INPUT_SCOPE.with(|slot| slot.borrow_mut().take())
            .ok_or("P17 checked input scope 已失效")?;
        self.active = false;
        let mut hash_reads = state.hash_reads;
        for (path, entry) in state.entries {
            let before = checked_input_identity(&path)?;
            if before != entry.identity {
                return Err(format!("P17 checked input scope 出口身分已變：{}", path.display()));
            }
            let actual = manifest::sha256(&path)?;
            hash_reads += 1;
            let after = checked_input_identity(&path)?;
            if actual != entry.sha256 || after != entry.identity {
                return Err(format!("P17 checked input scope 出口 SHA／身分已變：{}", path.display()));
            }
        }
        Ok(hash_reads)
    }
}

impl Drop for CheckedInputScope {
    fn drop(&mut self) {
        if self.active {
            CHECKED_INPUT_SCOPE.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
}

#[cfg(test)]
fn checked_input_scope_hash_reads() -> Option<usize> {
    CHECKED_INPUT_SCOPE.with(|slot| slot.borrow().as_ref().map(|state| state.hash_reads))
}

fn checked_input(value: &StrictJsonValue) -> Result<String, String> {
    let path = string(value, "path")?;
    let digest = string(value, "sha256")?;
    if !Path::new(path).is_absolute()
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!("P17 report input SHA/path 不符：{path}"));
    }
    let file = Path::new(path);
    let scoped = CHECKED_INPUT_SCOPE.with(|slot| {
        slot.borrow().as_ref().map(|state| state.entries.get(file).cloned())
    });
    match scoped {
        Some(Some(entry)) => {
            if entry.sha256 != digest || checked_input_identity(file)? != entry.identity {
                return Err(format!("P17 report input SHA/path／身分不符：{path}"));
            }
        }
        Some(None) => {
            let before = checked_input_identity(file)?;
            let actual = manifest::sha256(file)?;
            let after = checked_input_identity(file)?;
            if actual != digest || before != after {
                return Err(format!("P17 report input SHA/path／身分不符：{path}"));
            }
            CHECKED_INPUT_SCOPE.with(|slot| {
                let mut slot = slot.borrow_mut();
                let state = slot.as_mut().ok_or("P17 checked input scope 已失效")?;
                if state.entries.insert(file.to_path_buf(), CheckedInputEntry {
                    sha256: digest.to_owned(), identity: after,
                }).is_some() {
                    return Err("P17 checked input scope 重複入口".into());
                }
                state.hash_reads += 1;
                Ok::<(), String>(())
            })?;
        }
        None => {
            if manifest::sha256(file)? != digest {
                return Err(format!("P17 report input SHA/path 不符：{path}"));
            }
        }
    }
    Ok(path.to_owned())
}

fn count(value: &StrictJsonValue, name: &str) -> Result<i32, String> {
    property(value, name)?
        .as_i32()
        .filter(|number| *number >= 0)
        .ok_or_else(|| format!("P17 report {name} 不是非負整數"))
}

fn binary_span(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], String> {
    let end = offset.checked_add(size).ok_or("P17 binary 範圍溢位")?;
    bytes.get(offset..end).ok_or("P17 binary 範圍越界".into())
}

fn binary_offset(base: usize, delta: usize) -> Result<usize, String> {
    base.checked_add(delta)
        .ok_or("P17 binary offset 溢位".into())
}

fn binary_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let word: [u8; 4] = binary_span(bytes, offset, 4)?
        .try_into()
        .map_err(|_| "P17 binary u32 缺失")?;
    Ok(u32::from_le_bytes(word))
}

fn fixed_name(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bytes[end..]
        .iter()
        .all(|byte| *byte == 0)
        .then_some(&bytes[..end])
}

struct MachSymbolTable {
    offset: usize,
    count: usize,
    strings_offset: usize,
    strings_size: usize,
}

struct Mach64 {
    file_type: u32,
    text_sections: Vec<bool>,
    symbols: Option<MachSymbolTable>,
}

fn parse_mach64(bytes: &[u8]) -> Result<Mach64, String> {
    const HEADER_SIZE: usize = 32;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const LC_SYMTAB: u32 = 0x2;
    const LC_SEGMENT_64: u32 = 0x19;
    const SEGMENT_SIZE: usize = 72;
    const SECTION_SIZE: usize = 80;
    binary_span(bytes, 0, HEADER_SIZE)?;
    if binary_u32(bytes, 0)? != 0xfeed_facf || binary_u32(bytes, 4)? != CPU_TYPE_ARM64 {
        return Err("P17 artifact 非小端 arm64 Mach-O 64".into());
    }
    let file_type = binary_u32(bytes, 12)?;
    let command_count =
        usize::try_from(binary_u32(bytes, 16)?).map_err(|_| "P17 Mach-O command 數溢位")?;
    let commands_size =
        usize::try_from(binary_u32(bytes, 20)?).map_err(|_| "P17 Mach-O command 尺寸溢位")?;
    if command_count == 0
        || command_count
            .checked_mul(8)
            .is_none_or(|minimum| minimum > commands_size)
    {
        return Err("P17 Mach-O command 數／尺寸不符".into());
    }
    let commands_end = HEADER_SIZE
        .checked_add(commands_size)
        .ok_or("P17 Mach-O command 範圍溢位")?;
    binary_span(bytes, HEADER_SIZE, commands_size)?;
    let mut cursor = HEADER_SIZE;
    let mut text_sections = Vec::new();
    let mut symbols = None;
    let mut has_segment = false;
    for _ in 0..command_count {
        let command = binary_u32(bytes, cursor)?;
        let size = usize::try_from(binary_u32(bytes, binary_offset(cursor, 4)?)?)
            .map_err(|_| "P17 Mach-O command 尺寸溢位")?;
        let next = cursor
            .checked_add(size)
            .ok_or("P17 Mach-O command 範圍溢位")?;
        if size < 8 || size % 8 != 0 || next > commands_end {
            return Err("P17 Mach-O command 越界".into());
        }
        if command == LC_SEGMENT_64 {
            has_segment = true;
            if size < SEGMENT_SIZE {
                return Err("P17 Mach-O segment 截斷".into());
            }
            let parent_segname = fixed_name(binary_span(bytes, binary_offset(cursor, 8)?, 16)?)
                .ok_or("P17 Mach-O segment 名稱不合法")?;
            let count = usize::try_from(binary_u32(bytes, binary_offset(cursor, 64)?)?)
                .map_err(|_| "P17 Mach-O section 數溢位")?;
            let sections_size = count
                .checked_mul(SECTION_SIZE)
                .and_then(|value| SEGMENT_SIZE.checked_add(value))
                .ok_or("P17 Mach-O section 範圍溢位")?;
            if sections_size > size || text_sections.len().saturating_add(count) > 255 {
                return Err("P17 Mach-O section 越界／超額".into());
            }
            for index in 0..count {
                let offset = binary_offset(
                    binary_offset(cursor, SEGMENT_SIZE)?,
                    index
                        .checked_mul(SECTION_SIZE)
                        .ok_or("P17 Mach-O section offset 溢位")?,
                )?;
                let section = binary_span(bytes, offset, SECTION_SIZE)?;
                let sectname = fixed_name(&section[..16]).ok_or("P17 Mach-O section 名稱不合法")?;
                let segname =
                    fixed_name(&section[16..32]).ok_or("P17 Mach-O segment 名稱不合法")?;
                let flags = binary_u32(section, 64)?;
                text_sections.push(
                    sectname == b"__text"
                        && segname == b"__TEXT"
                        && parent_segname == segname
                        && flags & 0xff == 0
                        && flags & (0x8000_0000 | 0x0000_0400) != 0,
                );
            }
        } else if command == LC_SYMTAB {
            if size < 24 || symbols.is_some() {
                return Err("P17 Mach-O symbol command 重複／截斷".into());
            }
            let offset = usize::try_from(binary_u32(bytes, binary_offset(cursor, 8)?)?)
                .map_err(|_| "P17 Mach-O symbol offset 溢位")?;
            let count = usize::try_from(binary_u32(bytes, binary_offset(cursor, 12)?)?)
                .map_err(|_| "P17 Mach-O symbol 數溢位")?;
            let strings_offset = usize::try_from(binary_u32(bytes, binary_offset(cursor, 16)?)?)
                .map_err(|_| "P17 Mach-O string offset 溢位")?;
            let strings_size = usize::try_from(binary_u32(bytes, binary_offset(cursor, 20)?)?)
                .map_err(|_| "P17 Mach-O string 尺寸溢位")?;
            binary_span(
                bytes,
                offset,
                count.checked_mul(16).ok_or("P17 Mach-O symbol 範圍溢位")?,
            )?;
            binary_span(bytes, strings_offset, strings_size)?;
            symbols = Some(MachSymbolTable {
                offset,
                count,
                strings_offset,
                strings_size,
            });
        }
        cursor = next;
    }
    if cursor != commands_end || !has_segment {
        return Err("P17 Mach-O command 合計尺寸不符".into());
    }
    Ok(Mach64 {
        file_type,
        text_sections,
        symbols,
    })
}

pub(super) fn mach_type(path: &Path, required: &str) -> Result<(), String> {
    let expected = match required {
        "EXECUTE" => 0x2,
        "DYLIB" => 0x6,
        _ => return Err(format!("P17 Mach-O 未宣告的檔案類型：{required}")),
    };
    let bytes = fs::read(path).map_err(|error| format!("P17 Mach-O 讀取失敗：{error}"))?;
    if parse_mach64(&bytes)?.file_type != expected {
        return Err(format!(
            "P17 artifact 不是 Mach-O {required}：{}",
            path.display()
        ));
    }
    Ok(())
}

fn global_text_symbol(bytes: &[u8], symbol: &str) -> Result<bool, String> {
    let parsed = parse_mach64(bytes)?;
    let table = parsed.symbols.ok_or("P17 Mach-O 缺 LC_SYMTAB")?;
    let strings = binary_span(bytes, table.strings_offset, table.strings_size)?;
    let expected = format!("_{symbol}");
    let mut found = false;
    for index in 0..table.count {
        let entry = binary_span(
            bytes,
            binary_offset(
                table.offset,
                index
                    .checked_mul(16)
                    .ok_or("P17 Mach-O symbol offset 溢位")?,
            )?,
            16,
        )?;
        let string_index = usize::try_from(binary_u32(entry, 0)?)
            .map_err(|_| "P17 Mach-O symbol string index 溢位")?;
        let name = strings
            .get(string_index..)
            .and_then(|tail| tail.split(|byte| *byte == 0).next())
            .ok_or("P17 Mach-O symbol string index 越界")?;
        if !strings[string_index..].contains(&0) {
            return Err("P17 Mach-O symbol string 未終止".into());
        }
        let kind = entry[4];
        let section = usize::from(entry[5]);
        if kind & 0xe0 == 0 && kind & 0x0e == 0x0e && section == 0 {
            return Err("P17 Mach-O 已定義 symbol 缺 section".into());
        }
        if kind & 0xe0 == 0 && kind & 0x0e == 0x0e && section > parsed.text_sections.len() {
            return Err("P17 Mach-O symbol section 越界".into());
        }
        if name == expected.as_bytes()
            && kind & 0xe0 == 0
            && kind & 0x10 == 0
            && kind & 0x0f == 0x0f
            && section > 0
            && parsed.text_sections[section - 1]
        {
            found = true;
        }
    }
    Ok(found)
}

fn defined_global(path: &Path, symbol: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("P17 Mach-O 讀取失敗：{error}"))?;
    if !global_text_symbol(&bytes, symbol)? {
        return Err(format!(
            "P17 artifact 缺定義全域文字符號 {symbol}：{}",
            path.display()
        ));
    }
    Ok(())
}

fn archive_number(field: &[u8], radix: u32) -> Result<usize, String> {
    let start = field
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(start, |index| index + 1);
    let field = &field[start..end];
    if field.is_empty()
        || !field.iter().all(|byte| match radix {
            8 => (b'0'..=b'7').contains(byte),
            _ => byte.is_ascii_digit(),
        })
    {
        return Err("P17 ar numeric header 不合法".into());
    }
    usize::from_str_radix(
        std::str::from_utf8(field).map_err(|_| "P17 ar numeric header 非ASCII")?,
        radix,
    )
    .map_err(|_| "P17 ar numeric header 溢位".into())
}

fn nonempty_archive(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err("P17 staticlib snapshot 非 ar archive".into());
    }
    let mut offset = 8usize;
    let mut members = 0usize;
    while offset < bytes.len() {
        let header = binary_span(bytes, offset, 60)?;
        if &header[58..60] != b"`\n" {
            return Err("P17 ar member header 結尾不符".into());
        }
        let name = header[..16]
            .iter()
            .copied()
            .take_while(|byte| *byte != b' ')
            .collect::<Vec<_>>();
        if name.is_empty() || !name.iter().all(|byte| byte.is_ascii_graphic()) {
            return Err("P17 ar member 名稱缺失".into());
        }
        for field in [&header[16..28], &header[28..34], &header[34..40]] {
            archive_number(field, 10)?;
        }
        archive_number(&header[40..48], 8)?;
        let size = archive_number(&header[48..58], 10)?;
        let data_start = offset.checked_add(60).ok_or("P17 ar header 範圍溢位")?;
        let body = binary_span(bytes, data_start, size)?;
        if name.starts_with(b"#1/") {
            let length = archive_number(&name[3..], 10)?;
            if length == 0 || length > body.len() || body[..length].iter().all(|byte| *byte == 0) {
                return Err("P17 ar extended member 名稱不合法".into());
            }
        }
        offset = data_start
            .checked_add(size)
            .ok_or("P17 ar member 範圍溢位")?;
        if offset % 2 == 1 {
            if binary_span(bytes, offset, 1)? != b"\n" {
                return Err("P17 ar member 對齊位元組不符".into());
            }
            offset += 1;
        }
        members += 1;
    }
    if offset != bytes.len() || members == 0 {
        return Err("P17 staticlib snapshot 不是非空 archive".into());
    }
    Ok(())
}

#[derive(Default)]
struct ProfileArtifacts {
    binary: Option<String>,
    library: Option<String>,
    driver: Option<String>,
    modules: BTreeMap<String, String>,
    suite: Option<String>,
    native_flags: Vec<String>,
    abi: Option<grant::ValidatedAbi>,
    abi_log: Option<String>,
}

pub(super) fn validate_b01(root: &Path, path: &Path) -> Result<(), String> {
    let environment = super::runner::environment(root)?;
    validate_b01_with_environment(root, path, &environment, None, None, None).map(|_| ())
}

pub(super) struct ToolingImpact {
    pub path: String,
    pub before_sha256: String,
    pub after_sha256: String,
}

pub(super) fn validate_b01_for_b02(root: &Path, path: &Path) -> Result<Vec<ToolingImpact>, String> {
    const B01_SHA: &str = "f915bb587d537f703c4d4ec1093b14163122af3fa73f0af9e9caf7f1cf6a7c77";
    if manifest::sha256(path)? != B01_SHA {
        return Err("P17 B02 B01 report 原始 SHA 不符".into());
    }
    let environment = super::runner::environment(root)?;
    let baseline = environment.evidence_dir.join("p17-b01-tooling-baseline");
    validate_b01_with_environment(root, path, &environment, Some(&baseline), None, None)
}

pub(super) fn validate_b01_for_b03(root: &Path, path: &Path) -> Result<Vec<ToolingImpact>, String> {
    const B01_SHA: &str = "f915bb587d537f703c4d4ec1093b14163122af3fa73f0af9e9caf7f1cf6a7c77";
    if manifest::sha256(path)? != B01_SHA {
        return Err("P17 B03 B01 report 原始 SHA 不符".into());
    }
    let environment = super::runner::environment(root)?;
    let b01_baseline = environment.evidence_dir.join("p17-b01-tooling-baseline");
    let b02_baseline = environment.evidence_dir.join("p17-b02-tooling-baseline");
    for (snapshot, expected) in [
        (
            "xtask__src__p17__mod.rs",
            "a76a276cbca80c7ddfa15b496a23c837dd7b1663220767093c6c3fcaa888cc55",
        ),
        (
            "xtask__src__p17__report.rs",
            "22a5f7e0cc5450f1eed50da886178c43ced85d8a07441d41e15ee36be26e4261",
        ),
    ] {
        if manifest::sha256(&b02_baseline.join(snapshot))? != expected {
            return Err(format!("P17 B03 B02 tooling baseline 不符：{snapshot}"));
        }
    }
    validate_b01_with_environment(
        root,
        path,
        &environment,
        Some(&b01_baseline),
        Some(&b02_baseline),
        None,
    )
}

pub(super) fn validate_b01_for_phase(
    root: &Path,
    path: &Path,
    view: &PhaseSourceView,
) -> Result<Vec<ToolingImpact>, String> {
    const B01_SHA: &str = "f915bb587d537f703c4d4ec1093b14163122af3fa73f0af9e9caf7f1cf6a7c77";
    if manifest::sha256(path)? != B01_SHA {
        return Err("P17 phase B01 report 原始 SHA 不符".into());
    }
    let environment = super::runner::environment(root)?;
    let b01_baseline = environment.evidence_dir.join("p17-b01-tooling-baseline");
    let b02_baseline = environment.evidence_dir.join("p17-b02-tooling-baseline");
    validate_b01_with_environment(
        root,
        path,
        &environment,
        Some(&b01_baseline),
        Some(&b02_baseline),
        Some(view),
    )
}

#[cfg(test)]
pub(super) fn validate_b01_with_environment_for_test(
    root: &Path,
    path: &Path,
    environment: &super::runner::Environment,
) -> Result<(), String> {
    validate_b01_with_environment(root, path, environment, None, None, None).map(|_| ())
}

fn validate_b01_with_environment(
    root: &Path,
    path: &Path,
    actual_environment: &super::runner::Environment,
    reuse_baseline: Option<&Path>,
    effective_tooling: Option<&Path>,
    phase_view: Option<&PhaseSourceView>,
) -> Result<Vec<ToolingImpact>, String> {
    let receipt = fs::read_to_string(path.with_extension("sha256"))
        .map_err(|error| format!("P17 B01 report SHA receipt 不可讀：{error}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("P17 B01 report 名稱無效")?;
    if receipt != format!("{}  {name}\n", manifest::sha256(path)?) {
        return Err("P17 B01 report SHA receipt 不符".into());
    }
    let body =
        fs::read_to_string(path).map_err(|error| format!("P17 B01 report 不可讀：{error}"))?;
    let value = StrictJsonParser::parse(&body)?;
    if string(&value, "schema")? != "rivetlua-phase-gate-v1"
        || string(&value, "phase")? != "P17"
        || string(&value, "batch")? != "P17-B01"
        || string(&value, "status")? != "PASS"
    {
        return Err("P17 B01 report schema/phase/batch/status 不符".into());
    }
    let scope = property(&value, "scope")?;
    if string(scope, "phase")? != "P17"
        || string(scope, "batch")? != "P17-B01"
        || !strings_exact(array(scope, "declared_cases")?, &["COMPLETE-002"])
        || !strings_exact(
            array(scope, "selectors")?,
            &["COMPLETE-002:lua55-i64f64", "COMPLETE-002:lua54-i64f64"],
        )
        || !strings_exact(
            array(scope, "declared_facets")?,
            &[
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
            ],
        )
        || !strings_exact(
            array(scope, "execution_paths")?,
            &["p17-preflight", "capi-independent-host", "cli-rust-vm"],
        )
    {
        return Err("P17 B01 report scope 越界或缺必要 facet".into());
    }
    let configuration = property(&value, "configuration")?;
    let expected_environment = expected_environment(actual_environment, phase_view);
    let observed_environment = array(configuration, "environment")?
        .iter()
        .map(|item| {
            let StrictJsonValue::Object(fields) = item else {
                return Err("P17 B01 report environment 元素非物件".into());
            };
            if fields.len() != 2
                || fields
                    .iter()
                    .map(|(key, _)| key.as_str())
                    .collect::<BTreeSet<_>>()
                    != BTreeSet::from(["name", "value"])
            {
                return Err("P17 B01 report environment 欄位不符".into());
            }
            Ok((
                string(item, "name")?.to_owned(),
                string(item, "value")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if !strings_exact(
        array(configuration, "profiles")?,
        &["lua55-i64f64", "lua54-i64f64"],
    ) || string(configuration, "target")? != actual_environment.target
        || string(configuration, "toolchain")? != super::runner::toolchain_identity()?
        || !strings_exact(
            array(configuration, "features")?,
            &["native-lua55", "default-lua54,native-lua54"],
        )
        || observed_environment != expected_environment
        || !array(&value, "dependencies")?.is_empty()
    {
        return Err("P17 B01 report configuration/dependencies 不符".into());
    }
    let mut paths = BTreeSet::new();
    let mut tooling_impacts = Vec::new();
    for input in array(&value, "source_inputs")? {
        let path = string(input, "path")?;
        let digest = string(input, "sha256")?;
        let relative = Path::new(path)
            .strip_prefix(root)
            .ok()
            .and_then(|path| path.to_str());
        let historical = match relative {
            Some("xtask/src/p17/mod.rs") => Some((
                "013c1e17689405e655dc89257a85083931c668873e018ba18abe3e1dd724e72d",
                "xtask__src__p17__mod.rs",
            )),
            Some("xtask/src/p17/report.rs") => Some((
                "2b6938e755b80fcd3a7da0db7f7a11fa98a28caf12d2ec00b1ef9395bfbda35c",
                "xtask__src__p17__report.rs",
            )),
            _ => None,
        };
        let current = if let (Some(baseline), Some((_, snapshot))) = (effective_tooling, historical)
        {
            manifest::sha256(&baseline.join(snapshot))?
        } else {
            manifest::sha256(Path::new(path))?
        };
        let checked =
            if let (Some(baseline), Some((before, snapshot))) = (reuse_baseline, historical) {
                if digest != before || manifest::sha256(&baseline.join(snapshot))? != before {
                    return Err(format!("P17 B02 B01 tooling baseline 不符：{path}"));
                }
                if current != before {
                    tooling_impacts.push(ToolingImpact {
                        path: path.to_owned(),
                        before_sha256: before.into(),
                        after_sha256: current,
                    });
                }
                path.to_owned()
            } else if let Some(checked) = phase_view
                .map(|view| historical_input(input, view))
                .transpose()?
                .flatten()
            {
                checked
            } else {
                checked_input(input)?
            };
        if !paths.insert(checked) {
            return Err("P17 B01 report 重複 source input".into());
        }
    }
    for path in super::runner::related_sources(root)? {
        if phase_view.is_some_and(|view| view.was_absent(&path.display().to_string())) {
            continue;
        }
        if !paths.contains(&path.display().to_string()) {
            return Err(format!(
                "P17 B01 report 缺 source input：{}",
                path.display()
            ));
        }
    }
    let checks = array(&value, "checks")?;
    if checks.len() != 34 {
        return Err("P17 B01 report check 數不符".into());
    }
    let mut coverage = BTreeMap::<(String, String), usize>::new();
    let mut operation_coverage = BTreeMap::<(String, String), usize>::new();
    let mut modules = BTreeMap::<String, BTreeSet<String>>::new();
    let mut artifacts = BTreeMap::<String, ProfileArtifacts>::new();
    for check in checks {
        if string(check, "case_id")? != "COMPLETE-002" || string(check, "status")? != "PASS" {
            return Err("P17 B01 report 範圍外 case 或非 PASS check".into());
        }
        let profile = string(check, "profile")?;
        if !["lua55-i64f64", "lua54-i64f64"].contains(&profile) {
            return Err("P17 B01 report 錯誤 profile".into());
        }
        let facet = string(check, "facet")?;
        if ![
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
        ]
        .contains(&facet)
        {
            return Err("P17 B01 report 範圍外 facet".into());
        }
        let operation = string(check, "operation")?;
        let valid_operation = match facet {
            "fixture" => operation == "fixture-tree",
            "binary" => operation == "cargo-cli-build",
            "profile" => operation == "cli-version",
            "abi" => matches!(operation, "cargo-capi-build" | "cc-capi-driver"),
            "module-build" => operation == "cc-sdk-module",
            "module-load" => matches!(operation, "capi-driver-load" | "cli-native-load"),
            "runner-argv" | "runner-cwd" | "runner-no-u" => operation == "cli-runner-ok",
            "runner-error" => operation == "cli-runner-error",
            "negative-controls" => operation == "binding-negative",
            _ => false,
        };
        if !valid_operation {
            return Err(format!("P17 B01 report {facet} operation 不符"));
        }
        let execution = string(check, "execution_path")?;
        let expected_execution = if operation == "cli-native-load" {
            "cli-rust-vm"
        } else if facet == "module-build" || facet == "module-load" || facet == "abi" {
            "capi-independent-host"
        } else if facet.starts_with("runner-") || facet == "profile" || facet == "binary" {
            "cli-rust-vm"
        } else {
            "p17-preflight"
        };
        if execution != expected_execution {
            return Err("P17 B01 report execution path 不符".into());
        }
        let command = array(check, "command")?;
        let command_parts = command
            .iter()
            .map(|part| {
                part.as_str()
                    .map(str::to_owned)
                    .ok_or("P17 B01 report command 非字串")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if command_parts.is_empty() {
            return Err("P17 B01 report command 缺失".into());
        }
        let cwd = string(check, "cwd")?;
        if !Path::new(cwd).is_absolute() || !Path::new(cwd).is_dir() {
            return Err("P17 B01 report cwd 無效".into());
        }
        let exit = property(check, "exit_code")?
            .as_i32()
            .ok_or("P17 B01 report exit 缺失")?;
        let expected_count = if facet == "negative-controls" { 6 } else { 1 };
        if (facet == "runner-error" && exit == 0)
            || (facet != "runner-error" && exit != 0)
            || count(check, "matched")? != expected_count
            || count(check, "passed")? != expected_count
            || count(check, "failed")? != 0
            || count(check, "ignored")? != 0
        {
            return Err("P17 B01 report zero-match/exit/count 不符".into());
        }
        let log = Path::new(string(check, "log_path")?);
        let digest = string(check, "log_sha256")?;
        if !log.is_absolute() || digest.len() != 64 || manifest::sha256(log)? != digest {
            return Err("P17 B01 report log SHA/path 不符".into());
        }
        let log_body = fs::read_to_string(log)
            .map_err(|error| format!("P17 B01 report log 不可讀：{error}"))?;
        let required = match operation {
            "fixture-tree" => Some(format!("P17_FIXTURE {profile} ")),
            "cli-version" => Some(if profile == "lua55-i64f64" {
                "RivetLua 0.0.0 (Lua 5.5.1)".into()
            } else {
                "RivetLua 0.0.0 (Lua 5.4.9)".into()
            }),
            "capi-driver-load" => Some("P17_SDK_RESULT PASS".into()),
            "cli-runner-ok" => Some("P17_RUNNER_ARGV PASS".into()),
            "cli-runner-error" => Some("P17_INTENTIONAL_FAILURE".into()),
            "binding-negative" => Some(format!("P17_NEGATIVE_BINDING {profile} ")),
            _ => None,
        };
        if required
            .as_ref()
            .is_some_and(|marker| !log_body.contains(marker))
        {
            return Err(format!("P17 B01 report {facet} log 缺真實效果 marker"));
        }
        if operation == "capi-driver-load"
            && (!log_body.contains("P17_SDK_ABI revision=1 layout=37 PASS")
                || !log_body.contains("P17_SDK_CLOSE ALLOCATOR_RELEASE PASS"))
        {
            return Err("P17 B01 module-load 缺 ABI 或 close ledger marker".into());
        }
        let input_paths = array(check, "inputs")?
            .iter()
            .map(checked_input)
            .collect::<Result<Vec<_>, _>>()?;
        let negative_runs = array(check, "negative_runs")?;
        if operation != "binding-negative" && !negative_runs.is_empty() {
            return Err("P17 非 negative-controls check 不可含負向子行程".into());
        }
        let effective_environment = array(check, "environment")?
            .iter()
            .map(|item| {
                Ok((
                    string(item, "name")?.to_owned(),
                    string(item, "value")?.to_owned(),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if operation != "cli-native-load" && !effective_environment.is_empty() {
            return Err("P17 非 native CLI check 不可宣稱覆寫子行程環境".into());
        }
        let fixed = manifest::PROFILES
            .iter()
            .find(|candidate| candidate.name == profile)
            .ok_or("P17 profile 不在固定 manifest")?;
        let proof = artifacts.entry(profile.to_owned()).or_default();
        match operation {
            "fixture-tree" => {
                let extraction = log
                    .parent()
                    .ok_or("P17 fixture log 目錄缺失")?
                    .join("fixture");
                if !extraction.starts_with(&actual_environment.evidence_dir)
                    || !extraction
                        .parent()
                        .and_then(|parent| parent.file_name())
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&format!("b01-{profile}-")))
                {
                    return Err("P17 fixture 解壓路徑不在 profile 專屬證據目錄".into());
                }
                if cwd != root.display().to_string()
                    || command_parts
                        != [
                            "tar".into(),
                            "-xzf".into(),
                            root.join(fixed.tarball).display().to_string(),
                            "-C".into(),
                            extraction.display().to_string(),
                        ]
                    || input_paths
                        != [
                            root.join(fixed.tarball).display().to_string(),
                            root.join(fixed.suite).join("all.lua").display().to_string(),
                        ]
                    || !log_body.lines().any(|line| {
                        line == format!(
                            "P17_FIXTURE {} tar={} all={} canonical_tree=exact PASS",
                            profile, fixed.tarball_sha256, fixed.all_lua_sha256
                        )
                    })
                {
                    return Err("P17 fixture-tree 命令/hash/tree marker 不符".into());
                }
            }
            "cargo-cli-build" | "cargo-capi-build" => {
                let expected = if operation == "cargo-cli-build" {
                    super::runner::cli_build_command(*fixed)
                } else {
                    super::runner::capi_build_command(*fixed)
                };
                if cwd != root.display().to_string()
                    || command_parts != expected
                    || input_paths.len() != 1
                {
                    return Err("P17 Cargo 命令/profile/features/snapshot 不符".into());
                }
                let snapshot = Path::new(&input_paths[0]);
                let expected_name = if operation == "cargo-cli-build" {
                    "rivetlua"
                } else {
                    "librivetlua_capi.a"
                };
                if snapshot.file_name().and_then(|name| name.to_str()) != Some(expected_name)
                    || !snapshot.starts_with(&actual_environment.evidence_dir)
                    || !snapshot
                        .parent()
                        .and_then(|parent| parent.file_name())
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&format!("b01-{profile}-")))
                {
                    return Err("P17 immutable snapshot 身分/路徑不符".into());
                }
                let digest = string(
                    array(check, "inputs")?
                        .first()
                        .ok_or("P17 snapshot input 缺失")?,
                    "sha256",
                )?;
                let artifact = super::runner::cargo_artifact(
                    &log_body,
                    if operation == "cargo-cli-build" {
                        "rivetlua"
                    } else {
                        "rivetlua_capi"
                    },
                    if operation == "cargo-cli-build" {
                        "bin"
                    } else {
                        "staticlib"
                    },
                )?;
                if string(check, "diagnostic")?
                    != format!(
                        "Cargo artifact={} immutable_snapshot_sha256={digest}",
                        artifact.display()
                    )
                {
                    return Err("P17 Cargo artifact 與 snapshot 記錄不符".into());
                }
                if operation == "cargo-cli-build" {
                    mach_type(snapshot, "EXECUTE")?;
                    if proof.binary.replace(input_paths[0].clone()).is_some() {
                        return Err("P17 CLI snapshot 重複".into());
                    }
                } else {
                    let archive = fs::read(snapshot)
                        .map_err(|error| format!("P17 ar archive 讀取失敗：{error}"))?;
                    nonempty_archive(&archive)?;
                    proof.native_flags = super::runner::native_libs(&log_body)?;
                    if proof.library.replace(input_paths[0].clone()).is_some() {
                        return Err("P17 CAPI snapshot 重複".into());
                    }
                }
            }
            "cli-version" => {
                if cwd != root.display().to_string()
                    || input_paths.len() != 1
                    || proof.binary.as_ref() != input_paths.first()
                    || command_parts != [input_paths[0].clone(), "-v".into()]
                    || log_body.trim() != fixed.version
                {
                    return Err("P17 CLI version/binary snapshot 不符".into());
                }
            }
            "binding-negative" => {
                let binary = proof
                    .binary
                    .as_ref()
                    .ok_or("P17 negative 缺 CLI snapshot")?;
                let suite = Path::new(proof.suite.as_deref().ok_or("P17 negative 缺 suite")?);
                let work = Path::new(binary)
                    .parent()
                    .ok_or("P17 negative 缺 work 目錄")?;
                let abi_header = root.join("include/rivetlua/rivetlua_abi.h");
                let script = root.join("tests/p17/modules/cli_native_reject.lua");
                let legal_grant = work.join("p17-native-grant.json");
                if cwd != root.display().to_string()
                    || command_parts
                        != ["P17 binding negative controls and CLI native preflight".to_owned()]
                    || input_paths.len() != 13
                    || input_paths[0] != *binary
                    || input_paths[1] != abi_header.display().to_string()
                    || input_paths[2] != script.display().to_string()
                    || input_paths[3] != legal_grant.display().to_string()
                    || negative_runs.len() != super::runner::NEGATIVE_CASES.len()
                    || log != work.join("negative-controls.log").as_path()
                    || string(check, "diagnostic")?
                        != "fixture/release/binary binding 與 no-grant/profile/target/ABI/digest CLI 預檢拒絕"
                {
                    return Err("P17 binding/CLI negative 複合證據缺失".into());
                }
                if !super::runner::negative_controls(
                    *fixed,
                    &manifest::sha256(Path::new(binary))?,
                    &manifest::sha256(&abi_header)?,
                ) {
                    return Err("P17 binding 負向控制未實際拒絕錯配".into());
                }
                let mut built = Vec::new();
                for (index, &(name, _)) in manifest::MODULES.iter().enumerate() {
                    let module = proof
                        .modules
                        .get(name)
                        .ok_or("P17 negative 缺 module build")?;
                    if input_paths[index + 4] != *module {
                        return Err("P17 negative module SHA/path 不符".into());
                    }
                    built.push(PathBuf::from(module.as_str()));
                }
                let built: [PathBuf; 5] =
                    built.try_into().map_err(|_| "P17 negative 缺固定五模組")?;
                grant::validate_file(
                    root,
                    *fixed,
                    proof.abi.as_ref().ok_or("P17 negative 缺 typed C ABI")?,
                    suite,
                    &built,
                    &legal_grant,
                )?;
                let legal = fs::read_to_string(&legal_grant).map_err(|error| error.to_string())?;
                let abi_manifest_sha = manifest::sha256(&root.join("tests/p16/abi-manifest.toml"))?;
                let first_sha = manifest::sha256(&built[0])?;
                let binding_line = format!(
                    "P17_NEGATIVE_BINDING {profile} profile release tar all binary abi PASS"
                );
                if log_body
                    .lines()
                    .filter(|line| *line == binding_line)
                    .count()
                    != 1
                    || log_body.lines().count() != 1 + super::runner::NEGATIVE_CASES.len()
                {
                    return Err("P17 binding negative log 不完整".into());
                }
                let mut bad_grant_index = 9;
                for (run, (label, category)) in
                    negative_runs.iter().zip(super::runner::NEGATIVE_CASES)
                {
                    let expected_command = super::runner::native_reject_command(
                        root,
                        Path::new(binary),
                        *fixed,
                        label,
                    );
                    let parts = array(run, "command")?
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .ok_or("P17 negative argv 非字串")
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let run_exit = property(run, "exit_code")?
                        .as_i32()
                        .ok_or("P17 negative 子行程 exit 缺失")?;
                    let run_log = property(run, "log")?;
                    let run_log_path = checked_input(run_log)?;
                    let expected_log = work.join(format!("negative-{label}.log"));
                    let grant_value = property(run, "grant")?;
                    let expected_environment = if label == "no-grant" {
                        if grant_value != &StrictJsonValue::Null {
                            return Err("P17 no-grant 子行程不得帶 grant".into());
                        }
                        super::runner::effective_no_native_environment()
                    } else {
                        let bad_grant = super::runner::negative_grant_path(work, label);
                        if checked_input(grant_value)? != bad_grant.display().to_string()
                            || input_paths[bad_grant_index] != bad_grant.display().to_string()
                        {
                            return Err("P17 negative mutation grant SHA/path 不符".into());
                        }
                        bad_grant_index += 1;
                        let expected = grant::rejected_variant(
                            &legal,
                            *fixed,
                            label,
                            &built[0],
                            &first_sha,
                            &abi_manifest_sha,
                        )?;
                        if fs::read_to_string(&bad_grant).map_err(|error| error.to_string())?
                            != expected
                        {
                            return Err("P17 negative mutation grant 內容不符".into());
                        }
                        super::runner::effective_native_environment(&bad_grant)
                    };
                    let effective = array(run, "environment")?
                        .iter()
                        .map(|item| {
                            Ok((
                                string(item, "name")?.to_owned(),
                                string(item, "value")?.to_owned(),
                            ))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    let run_body = fs::read_to_string(&expected_log)
                        .map_err(|error| format!("P17 negative CLI log 不可讀：{error}"))?;
                    let summary = format!(
                        "P17_NEGATIVE_CLI {profile} {label} category={category} exit=Some({run_exit}) log_sha256={} PASS",
                        string(run_log, "sha256")?
                    );
                    if string(run, "label")? != label
                        || string(run, "expected_category")? != category
                        || string(run, "status")? != "PASS"
                        || run_exit == 0
                        || string(run, "cwd")? != suite.display().to_string()
                        || parts != expected_command
                        || run_log_path != expected_log.display().to_string()
                        || effective != expected_environment
                        || !super::runner::negative_log_pass(&run_body, label, *fixed, category)
                        || log_body.lines().filter(|line| *line == summary).count() != 1
                    {
                        return Err(format!("P17 {profile}/{label} 真 CLI 預檢拒絕證據不符"));
                    }
                }
                if bad_grant_index != input_paths.len() {
                    return Err("P17 negative mutation grant 數目不符".into());
                }
            }
            "cc-sdk-module" => {
                if cwd != root.display().to_string() || input_paths.len() != 2 {
                    return Err("P17 module-build 來源/輸出缺失".into());
                }
                let name = Path::new(&input_paths[1])
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("P17 module 名稱無效")?
                    .to_owned();
                let (index, (_, source)) = manifest::MODULES
                    .iter()
                    .enumerate()
                    .find(|(_, (module, _))| *module == name)
                    .ok_or("P17 module 輸出不在固定清單")?;
                let expected_source = root.join(fixed.suite).join("libs").join(source);
                let expected_destination = Path::new(
                    proof
                        .binary
                        .as_deref()
                        .ok_or("P17 module 缺 CLI snapshot")?,
                )
                .parent()
                .ok_or("P17 module work 目錄缺失")?
                .join("fixture")
                .join(
                    Path::new(fixed.suite)
                        .file_name()
                        .ok_or("P17 suite 名稱缺失")?,
                )
                .join("libs")
                .join(&name);
                if input_paths
                    != [
                        expected_source.display().to_string(),
                        expected_destination.display().to_string(),
                    ]
                    || command_parts
                        != super::runner::module_build_command(
                            root,
                            *fixed,
                            index,
                            &expected_source,
                            &expected_destination,
                        )
                {
                    return Err("P17 module-build 官方來源/命令/profile 不符".into());
                }
                mach_type(&expected_destination, "DYLIB")?;
                let symbol = match name.as_str() {
                    "lib1.so" => "luaopen_lib1_sub",
                    "lib11.so" => "luaopen_lib11",
                    "lib2.so" | "lib2-v2.so" => "luaopen_lib2",
                    "lib21.so" => "luaopen_lib21",
                    _ => unreachable!(),
                };
                defined_global(&expected_destination, symbol)?;
                if proof
                    .modules
                    .insert(name.clone(), input_paths[1].clone())
                    .is_some()
                    || !modules.entry(profile.into()).or_default().insert(name)
                {
                    return Err("P17 module-build 重複輸出".into());
                }
                proof.suite = Some(
                    expected_destination
                        .parent()
                        .and_then(Path::parent)
                        .ok_or("P17 suite 路徑缺失")?
                        .display()
                        .to_string(),
                );
            }
            "cc-capi-driver" => {
                if cwd != root.display().to_string()
                    || input_paths.len() != 4
                    || input_paths[0]
                        != root
                            .join("tests/p17/modules/driver.c")
                            .display()
                            .to_string()
                    || Some(&input_paths[1]) != proof.library.as_ref()
                {
                    return Err("P17 CAPI driver source/staticlib 身分不符".into());
                }
                let driver = Path::new(&input_paths[2]);
                if driver.file_name().and_then(|name| name.to_str()) != Some("sdk-driver")
                    || driver.parent() != Path::new(&input_paths[1]).parent()
                    || command_parts
                        != super::runner::driver_build_command(
                            root,
                            *fixed,
                            Path::new(&input_paths[0]),
                            Path::new(&input_paths[1]),
                            &proof.native_flags,
                            driver,
                        )
                {
                    return Err("P17 CAPI driver link 命令/native flags 不符".into());
                }
                mach_type(driver, "EXECUTE")?;
                defined_global(driver, "rivetlua_abi_identity_v1")?;
                let abi_log = Path::new(&input_paths[3]);
                if abi_log
                    != driver
                        .parent()
                        .ok_or("P17 driver work 目錄缺失")?
                        .join("driver-abi.json")
                {
                    return Err("P17 ABI metadata log 路徑不符".into());
                }
                let observed = Command::new(driver)
                    .arg("--abi-json")
                    .current_dir(root)
                    .output()
                    .map_err(|error| format!("P17 ABI metadata probe 啟動失敗：{error}"))?;
                if !observed.status.success()
                    || !observed.stderr.is_empty()
                    || observed.stdout != fs::read(abi_log).map_err(|error| error.to_string())?
                {
                    return Err("P17 ABI metadata 與 C driver 真輸出不符".into());
                }
                let body =
                    String::from_utf8(observed.stdout).map_err(|_| "P17 ABI metadata 非 UTF-8")?;
                let abi = grant::validate_abi_json(root, *fixed, &body)?;
                if proof.abi.replace(abi).is_some()
                    || proof.abi_log.replace(input_paths[3].clone()).is_some()
                {
                    return Err("P17 ABI metadata 重複".into());
                }
                if proof.driver.replace(input_paths[2].clone()).is_some() {
                    return Err("P17 CAPI driver 重複".into());
                }
            }
            "capi-driver-load" => {
                if cwd != root.display().to_string()
                    || input_paths.len() != 9
                    || Some(&input_paths[0]) != proof.driver.as_ref()
                    || Some(&input_paths[1]) != proof.library.as_ref()
                {
                    return Err("P17 CAPI module-load driver/staticlib 關聯不符".into());
                }
                let suite = Path::new(proof.suite.as_deref().ok_or("P17 module-load 缺 suite")?);
                let mut run = vec![input_paths[0].clone()];
                for (index, &(name, _)) in manifest::MODULES.iter().enumerate() {
                    let path = proof
                        .modules
                        .get(name)
                        .ok_or("P17 module-load 缺模組 build 證據")?;
                    if input_paths[index + 2] != *path {
                        return Err("P17 module-load 模組 SHA/path 未連動".into());
                    }
                    run.push(path.clone());
                }
                for (index, (name, aa)) in [("init.lua", 10), ("xuxu.lua", 20)].iter().enumerate() {
                    let path = suite.join("libs/P1").join(name);
                    if input_paths[index + 7] != path.display().to_string()
                        || fs::read_to_string(&path).map_err(|error| error.to_string())?
                            != format!("_ENV = {{}}\nAA = {aa}\nreturn _ENV\n")
                    {
                        return Err("P17 P1 package 路徑/內容不符".into());
                    }
                    run.push(path.display().to_string());
                }
                if command_parts != run
                    || !log_body.lines().any(|line| line == "P17_SDK_RESULT PASS")
                {
                    return Err("P17 CAPI module-load argv/effect 不符".into());
                }
                let mut markers = vec![
                    "P17_SDK_ABI revision=1 layout=37 PASS".to_owned(),
                    "P17_SDK_HOST_LIMITS source=65536 encoded=4194304 module=8388608 temporary=1048576 work=2000000 chunks=256 paths=256 PASS".to_owned(),
                    "P17_SDK_LIB11 lib11.so GLOBAL_LINK PASS".to_owned(),
                    "P17_SDK_LIB1 FUNCTIONS PASS".to_owned(),
                    "P17_SDK_CLOSE ALLOCATOR_RELEASE PASS".to_owned(),
                    "P17_SDK_DLCLOSE AFTER_LUA_CLOSE PASS".to_owned(),
                    "P17_SDK_RESULT PASS".to_owned(),
                ];
                for path in &input_paths[2..7] {
                    markers.push(format!("P17_SDK_DLOPEN {path} PASS"));
                }
                for (name, symbol) in [
                    ("lib1.so", "luaopen_lib1_sub"),
                    ("lib2.so", "luaopen_lib2"),
                    ("lib21.so", "luaopen_lib21"),
                    ("lib2-v2.so", "luaopen_lib2"),
                ] {
                    markers.push(format!("P17_SDK_MODULE {name} {symbol} TWO_ARG_ID PASS"));
                }
                for (path, aa) in input_paths[7..9].iter().zip([10, 20]) {
                    markers.push(format!("P17_SDK_P1 {path} AA={aa} GLOBAL=0 PASS"));
                }
                if !markers
                    .iter()
                    .all(|marker| log_body.lines().filter(|line| *line == marker).count() == 1)
                {
                    return Err("P17 CAPI module-load 五模組/P1/ABI/關閉效果不全".into());
                }
            }
            "cli-runner-ok" | "cli-runner-error" => {
                let script = root.join(if operation == "cli-runner-ok" {
                    "tests/p17/modules/runner_ok.lua"
                } else {
                    "tests/p17/modules/runner_fail.lua"
                });
                let binary = proof.binary.as_ref().ok_or("P17 runner 缺 CLI snapshot")?;
                let suite = Path::new(binary)
                    .parent()
                    .ok_or("P17 runner work 路徑缺失")?
                    .join("fixture")
                    .join(
                        Path::new(fixed.suite)
                            .file_name()
                            .ok_or("P17 suite 名稱缺失")?,
                    );
                if cwd != suite.display().to_string()
                    || input_paths != [binary.clone(), script.display().to_string()]
                    || command_parts != input_paths
                {
                    return Err("P17 runner raw argv/cwd/binary snapshot 不符".into());
                }
                if operation == "cli-runner-ok"
                    && ![
                        "P17_RUNNER_ARGV PASS",
                        "P17_RUNNER_CWD PASS",
                        "P17_RUNNER_NO_U PASS",
                    ]
                    .iter()
                    .all(|marker| log_body.lines().filter(|line| line == marker).count() == 1)
                {
                    return Err("P17 runner argv/cwd/no_U marker 不全".into());
                }
            }
            "cli-native-load" => {
                if input_paths.len() != 13
                    || proof.binary.as_ref() != input_paths.first()
                    || Some(&input_paths[3]) != proof.abi_log.as_ref()
                    || Some(&input_paths[4]) != proof.driver.as_ref()
                    || Some(&input_paths[5]) != proof.library.as_ref()
                {
                    return Err("P17 CLI native binary/ABI/CAPI artifact 關聯不符".into());
                }
                let binary = Path::new(&input_paths[0]);
                let work = binary.parent().ok_or("P17 CLI native work 目錄缺失")?;
                let nonce = work
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("P17 CLI native nonce 缺失")?;
                let suite = Path::new(proof.suite.as_deref().ok_or("P17 CLI native suite 缺失")?);
                let grant_path = work.join("p17-native-grant.json");
                let script = root.join("tests/p17/modules/cli_native_load.lua");
                if cwd != suite.display().to_string()
                    || log != work.join("cli-native-load.log")
                    || input_paths[1] != grant_path.display().to_string()
                    || input_paths[2] != script.display().to_string()
                    || command_parts
                        != super::runner::native_cli_command(root, binary, *fixed, nonce)
                    || effective_environment
                        != super::runner::effective_native_environment(&grant_path)
                    || string(check, "diagnostic")?
                        != "CLI 同一 Rust VM 真載入官方五 C module、公開效果與 P1 隔離"
                {
                    return Err("P17 CLI native argv/cwd/env/grant/log 身分不符".into());
                }
                let mut built = Vec::new();
                for (index, &(name, _)) in manifest::MODULES.iter().enumerate() {
                    let module = proof
                        .modules
                        .get(name)
                        .ok_or("P17 CLI native 缺 module build 證據")?;
                    if input_paths[index + 6] != *module {
                        return Err("P17 CLI native module SHA/path 未連動".into());
                    }
                    built.push(PathBuf::from(module));
                }
                let built: [PathBuf; 5] = built
                    .try_into()
                    .map_err(|_| "P17 CLI native 固定五模組缺失")?;
                for (index, (name, aa)) in [("init.lua", 10), ("xuxu.lua", 20)].iter().enumerate() {
                    let path = suite.join("libs/P1").join(name);
                    if input_paths[index + 11] != path.display().to_string()
                        || fs::read_to_string(&path).map_err(|error| error.to_string())?
                            != format!("_ENV = {{}}\nAA = {aa}\nreturn _ENV\n")
                    {
                        return Err("P17 CLI native P1 package SHA/path/content 不符".into());
                    }
                }
                grant::validate_file(
                    root,
                    *fixed,
                    proof
                        .abi
                        .as_ref()
                        .ok_or("P17 CLI native 缺 C ABI identity")?,
                    suite,
                    &built,
                    &grant_path,
                )?;
                for marker in [
                    format!("P17_NATIVE_FIVE {profile} {nonce} PASS"),
                    format!("P17_NATIVE_P1 {profile} {nonce} PASS"),
                ] {
                    if log_body.lines().filter(|line| *line == marker).count() != 1 {
                        return Err("P17 CLI native 五模組/P1 真效果 marker 缺失或重複".into());
                    }
                }
            }
            _ => return Err("P17 B01 未知 operation".into()),
        }
        *coverage.entry((profile.into(), facet.into())).or_default() += 1;
        *operation_coverage
            .entry((profile.into(), operation.into()))
            .or_default() += 1;
    }
    for profile in ["lua55-i64f64", "lua54-i64f64"] {
        let expected_modules = ["lib1.so", "lib11.so", "lib2.so", "lib21.so", "lib2-v2.so"]
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        if modules.get(profile) != Some(&expected_modules) {
            return Err("P17 module-build 固定五模組缺失".into());
        }
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
            let expected = match facet {
                "module-build" => 5,
                "module-load" => 2,
                "abi" => 2,
                _ => 1,
            };
            if coverage.get(&(profile.into(), facet.into())) != Some(&expected) {
                return Err("P17 B01 report facet/profile 數目不符".into());
            }
        }
        for (operation, amount) in [
            ("fixture-tree", 1),
            ("cargo-cli-build", 1),
            ("cli-version", 1),
            ("cargo-capi-build", 1),
            ("cc-capi-driver", 1),
            ("cc-sdk-module", 5),
            ("capi-driver-load", 1),
            ("cli-native-load", 1),
            ("cli-runner-ok", 3),
            ("cli-runner-error", 1),
            ("binding-negative", 1),
        ] {
            if operation_coverage.get(&(profile.into(), operation.into())) != Some(&amount) {
                return Err("P17 B01 report operation/profile 數目不符".into());
            }
        }
    }
    Ok(tooling_impacts)
}

#[cfg(test)]
mod binary_parser_tests {
    use super::{defined_global, global_text_symbol, mach_type, nonempty_archive, parse_mach64};
    use std::{env, fs, path::PathBuf};

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn mach_fixture(file_type: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 32 + 152 + 24 + 16 + 9];
        put_u32(&mut bytes, 0, 0xfeed_facf);
        put_u32(&mut bytes, 4, 0x0100_000c);
        put_u32(&mut bytes, 12, file_type);
        put_u32(&mut bytes, 16, 2);
        put_u32(&mut bytes, 20, 176);
        put_u32(&mut bytes, 32, 0x19);
        put_u32(&mut bytes, 36, 152);
        bytes[40..46].copy_from_slice(b"__TEXT");
        put_u32(&mut bytes, 96, 1);
        bytes[104..110].copy_from_slice(b"__text");
        bytes[120..126].copy_from_slice(b"__TEXT");
        put_u32(&mut bytes, 168, 0x8000_0400);
        put_u32(&mut bytes, 184, 0x2);
        put_u32(&mut bytes, 188, 24);
        put_u32(&mut bytes, 192, 208);
        put_u32(&mut bytes, 196, 1);
        put_u32(&mut bytes, 200, 224);
        put_u32(&mut bytes, 204, 9);
        put_u32(&mut bytes, 208, 1);
        bytes[212] = 0x0f;
        bytes[213] = 1;
        bytes[224..233].copy_from_slice(b"\0_symbol\0");
        bytes
    }

    fn archive_fixture(name: &[u8], body: &[u8]) -> Vec<u8> {
        let mut header = [b' '; 60];
        header[..name.len()].copy_from_slice(name);
        header[16] = b'0';
        header[28] = b'0';
        header[34] = b'0';
        header[40..46].copy_from_slice(b"100644");
        let size = body.len().to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend_from_slice(&header);
        archive.extend_from_slice(body);
        if body.len() % 2 != 0 {
            archive.push(b'\n');
        }
        archive
    }

    #[test]
    fn p17_phase_binary_mach_type_and_defined_global_text() {
        let execute = mach_fixture(0x2);
        let dylib = mach_fixture(0x6);
        assert_eq!(parse_mach64(&execute).unwrap().file_type, 0x2);
        assert_eq!(parse_mach64(&dylib).unwrap().file_type, 0x6);
        assert_eq!(global_text_symbol(&execute, "symbol"), Ok(true));
        assert_eq!(global_text_symbol(&dylib, "other"), Ok(false));
    }

    #[test]
    fn p17_phase_binary_mach_rejects_malformed_or_non_global_text() {
        let valid = mach_fixture(0x6);
        for offset in [0, 4, 16, 20, 32, 36, 96, 188, 192, 200, 204] {
            let mut bad = valid.clone();
            put_u32(&mut bad, offset, u32::MAX);
            assert!(parse_mach64(&bad).is_err());
        }
        assert!(parse_mach64(&valid[..31]).is_err());
        for (offset, value) in [(212, 0x01), (212, 0x0e), (212, 0x1f)] {
            let mut bad = valid.clone();
            bad[offset] = value;
            assert_eq!(global_text_symbol(&bad, "symbol"), Ok(false));
        }
        let mut no_section = valid.clone();
        no_section[213] = 0;
        assert!(global_text_symbol(&no_section, "symbol").is_err());
        let mut data = valid.clone();
        data[104..110].copy_from_slice(b"__data");
        assert_eq!(global_text_symbol(&data, "symbol"), Ok(false));
        let mut no_instructions = valid.clone();
        put_u32(&mut no_instructions, 168, 0);
        assert_eq!(global_text_symbol(&no_instructions, "symbol"), Ok(false));
        let mut outside = valid.clone();
        outside[213] = 2;
        assert!(global_text_symbol(&outside, "symbol").is_err());
        let mut bad_index = valid.clone();
        put_u32(&mut bad_index, 208, 99);
        assert!(global_text_symbol(&bad_index, "symbol").is_err());
        let mut unterminated = valid.clone();
        unterminated[232] = b'x';
        assert!(global_text_symbol(&unterminated, "symbol").is_err());
    }

    #[test]
    fn p17_phase_binary_archive_requires_valid_nonempty_members() {
        let regular = archive_fixture(b"member.o/", b"x");
        assert!(nonempty_archive(&regular).is_ok());
        let extended = archive_fixture(b"#1/4", b"namex");
        assert!(nonempty_archive(&extended).is_ok());
        assert!(nonempty_archive(b"!<arch>\n").is_err());
        assert!(nonempty_archive(b"not an archive").is_err());
        assert!(nonempty_archive(&regular[..67]).is_err());
        for offset in [8, 24, 48, 56, 66, regular.len() - 1] {
            let mut bad = regular.clone();
            bad[offset] = if offset == 8 { b' ' } else { b'?' };
            assert!(nonempty_archive(&bad).is_err(), "archive offset {offset}");
        }
        let mut invalid_extended = extended.clone();
        invalid_extended[11] = b'9';
        assert!(nonempty_archive(&invalid_extended).is_err());
    }

    #[test]
    #[ignore = "需固定 P17 B01 artifact 證據"]
    fn p17_phase_binary_b01_plain_artifacts_match_read_only() {
        let evidence = PathBuf::from(env::var_os("RIVETLUA_P17_EVIDENCE_DIR").unwrap());
        for (work, suite) in [
            (
                "b01-lua55-i64f64-85855-1791613374781148000",
                "lua-5.5.1-tests",
            ),
            (
                "b01-lua54-i64f64-85855-1791613383015514000",
                "lua-5.4.9-tests",
            ),
        ] {
            let base = evidence.join(work);
            mach_type(&base.join("rivetlua"), "EXECUTE").unwrap();
            let driver = base.join("sdk-driver");
            mach_type(&driver, "EXECUTE").unwrap();
            defined_global(&driver, "rivetlua_abi_identity_v1").unwrap();
            nonempty_archive(&fs::read(base.join("librivetlua_capi.a")).unwrap()).unwrap();
            for (name, symbol) in [
                ("lib1.so", "luaopen_lib1_sub"),
                ("lib11.so", "luaopen_lib11"),
                ("lib2.so", "luaopen_lib2"),
                ("lib21.so", "luaopen_lib21"),
                ("lib2-v2.so", "luaopen_lib2"),
            ] {
                let module = base.join("fixture").join(suite).join("libs").join(name);
                mach_type(&module, "DYLIB").unwrap();
                defined_global(&module, symbol).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod checked_input_scope_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rivetlua-p17-checked-input-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn declared(path: &Path, digest: &str) -> StrictJsonValue {
        StrictJsonParser::parse(&format!(
            "{{\"path\":{},\"sha256\":{}}}",
            q(&path.display().to_string()), q(digest))).unwrap()
    }

    #[test]
    fn p17_phase_checked_input_scope_one_hash_per_unique_entry_and_exit() {
        let directory = TestDir::new();
        let file = directory.0.join("artifact.bin");
        fs::write(&file, b"alpha").unwrap();
        let digest = manifest::sha256(&file).unwrap();
        let record = declared(&file, &digest);
        let scope = begin_checked_input_scope().unwrap();
        assert!(begin_checked_input_scope().is_err());
        for _ in 0..4 {
            assert_eq!(checked_input(&record).unwrap(), file.display().to_string());
        }
        assert_eq!(checked_input_scope_hash_reads(), Some(1));
        assert_eq!(scope.finish().unwrap(), 2);
        assert_eq!(checked_input_scope_hash_reads(), None);
        assert_eq!(checked_input(&record).unwrap(), file.display().to_string());
        begin_checked_input_scope().unwrap().finish().unwrap();
    }

    #[test]
    fn p17_phase_checked_input_scope_rejects_wrong_changed_missing_symlink_and_early_exit() {
        let directory = TestDir::new();
        let file = directory.0.join("artifact.bin");
        fs::write(&file, b"alpha").unwrap();
        let digest = manifest::sha256(&file).unwrap();
        let record = declared(&file, &digest);
        let wrong = declared(&file, &"0".repeat(64));
        let scope = begin_checked_input_scope().unwrap();
        checked_input(&record).unwrap();
        assert!(checked_input(&wrong).is_err());
        assert_eq!(checked_input_scope_hash_reads(), Some(1));
        drop(scope);
        assert_eq!(checked_input_scope_hash_reads(), None);

        let scope = begin_checked_input_scope().unwrap();
        checked_input(&record).unwrap();
        fs::write(&file, b"bravo").unwrap();
        assert!(checked_input(&record).is_err());
        assert!(scope.finish().is_err());
        assert_eq!(checked_input_scope_hash_reads(), None);

        fs::write(&file, b"alpha").unwrap();
        let scope = begin_checked_input_scope().unwrap();
        checked_input(&record).unwrap();
        fs::write(&file, b"bravo").unwrap();
        assert!(scope.finish().is_err());

        fs::write(&file, b"alpha").unwrap();
        let replacement = directory.0.join("replacement.bin");
        fs::write(&replacement, b"alpha").unwrap();
        let scope = begin_checked_input_scope().unwrap();
        checked_input(&record).unwrap();
        fs::rename(&replacement, &file).unwrap();
        assert!(checked_input(&record).is_err());
        drop(scope);

        fs::remove_file(&file).unwrap();
        let scope = begin_checked_input_scope().unwrap();
        assert!(checked_input(&record).is_err());
        drop(scope);

        fs::write(&file, b"alpha").unwrap();
        let link = directory.0.join("link.bin");
        symlink(&file, &link).unwrap();
        let scope = begin_checked_input_scope().unwrap();
        assert!(checked_input(&declared(&link, &digest)).is_err());
        drop(scope);

        let early = || -> Result<(), String> {
            let _scope = begin_checked_input_scope()?;
            checked_input(&record)?;
            Err("預期的早退".into())
        };
        assert!(early().is_err());
        assert_eq!(checked_input_scope_hash_reads(), None);
        begin_checked_input_scope().unwrap().finish().unwrap();
    }
}
