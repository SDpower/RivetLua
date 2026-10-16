use super::{manifest, report, runner};
use crate::{StrictJsonParser, StrictJsonValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const FAMILIES: [&str; 12] = [
    "allocation-ledger",
    "gc-roots",
    "table-string",
    "verified-code",
    "c-stack-errors",
    "userdata-registry",
    "state-coroutine",
    "upvalue-debug",
    "numeric-bytes",
    "external-strings",
    "native-modules",
    "gc-parameters",
];
const PROFILES: [&str; 2] = ["lua55-i64f64", "lua54-i64f64"];
const PRIVATE_55: &str = "checkmemory limits sizes listcode printcode listk listabslineinfo listlocals printallstack totalmem alloccount allocfailnext trick gccolor gcage gcstate tracegc pobj gcquery hash stacklevel resetCI reallocstack querytab querystr codeparam applyparam externKstr externstr loadlib runC:alloccount runC:printstack";
const PRIVATE_54: &str = "checkmemory listcode listk pobj gccolor gcage gcstate hash querytab querystr totalmem alloccount allocfailnext trick stacklevel loadlib runC:printstack";

#[derive(Clone, Debug)]
pub(super) struct LuaReference {
    pub path: String,
    pub line: usize,
    pub source_sha256: String,
}

#[derive(Clone, Debug)]
pub(super) struct MappingItem {
    pub id: String,
    pub profile: String,
    pub symbol: String,
    pub c_function: String,
    pub c_source: String,
    pub c_source_sha256: String,
    pub lua_references: Vec<LuaReference>,
    pub reason: String,
    pub rust_invariant: String,
    pub case_id: String,
    pub public_gap: String,
}

#[derive(Clone, Debug)]
pub(super) struct CaseRun {
    pub target: String,
    pub selector: String,
    pub expected_matched: u32,
}

#[derive(Clone, Debug)]
pub(super) struct InternalCase {
    pub case_id: String,
    pub profiles: Vec<String>,
    pub runs: Vec<CaseRun>,
    pub evidence: Option<NativeEvidence>,
}

#[derive(Clone, Debug)]
pub(super) struct NativeEvidence {
    pub batch: String,
    pub facet: String,
}

fn object<'a>(
    value: &'a StrictJsonValue,
    keys: &[&str],
) -> Result<&'a [(String, StrictJsonValue)], String> {
    let StrictJsonValue::Object(entries) = value else {
        return Err("P17 B02 JSON 必須是物件".into());
    };
    let actual = entries
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<BTreeSet<_>>();
    let expected = keys.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected || entries.len() != keys.len() {
        return Err(format!("P17 B02 JSON 欄位不符：預期 {keys:?}"));
    }
    Ok(entries)
}

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(name).ok_or_else(|| format!("P17 B02 缺 {name}"))
}

fn string<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a str, String> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("P17 B02 {name} 非字串"))
}

fn array<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a [StrictJsonValue], String> {
    field(value, name)?
        .as_array()
        .ok_or_else(|| format!("P17 B02 {name} 非陣列"))
}

fn useful(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 8
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "not applicable" | "unknown" | "placeholder"
        )
        && !value.contains("TODO")
        && !value.contains("TBD")
}

fn relative_source(
    root: &Path,
    relative: &str,
    profile: &str,
    lua: bool,
) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || !relative.starts_with(if profile == PROFILES[0] {
            "vendor/lua55/"
        } else {
            "vendor/lua54/"
        })
        || if lua {
            !relative.ends_with(".lua")
        } else {
            !(relative.ends_with(".c") || relative.ends_with(".h"))
        }
    {
        return Err(format!("P17 B02 非固定來源路徑：{relative}"));
    }
    let absolute = root.join(path);
    if !absolute.is_file() {
        return Err(format!("P17 B02 來源不存在：{relative}"));
    }
    Ok(absolute)
}

fn checked_sha(path: &Path, expected: &str) -> Result<(), String> {
    if expected.len() != 64
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || manifest::sha256(path)? != expected
    {
        return Err(format!("P17 B02 來源 SHA 不符：{}", path.display()));
    }
    Ok(())
}

pub(super) fn parse_mapping(root: &Path, body: &str) -> Result<Vec<MappingItem>, String> {
    let value = StrictJsonParser::parse(body)?;
    object(&value, &["schema", "items"])?;
    if string(&value, "schema")? != "rivetlua-internal-mapping-v1" {
        return Err("P17 B02 mapping schema 不符".into());
    }
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    let mut originals = BTreeSet::new();
    let mut references = BTreeSet::new();
    for item in array(&value, "items")? {
        object(
            item,
            &["id", "original", "reason", "rust_invariant", "replacement"],
        )?;
        let id = string(item, "id")?.to_owned();
        if id.is_empty() || !ids.insert(id.clone()) {
            return Err("P17 B02 mapping id 空白或重複".into());
        }
        let original = field(item, "original")?;
        object(
            original,
            &[
                "profile",
                "symbol",
                "c_function",
                "c_source",
                "c_source_sha256",
                "lua_references",
            ],
        )?;
        let profile = string(original, "profile")?.to_owned();
        if !PROFILES.contains(&profile.as_str()) {
            return Err(format!("P17 B02 mapping profile 不符：{id}"));
        }
        let symbol = string(original, "symbol")?.to_owned();
        let c_function = string(original, "c_function")?.to_owned();
        let c_source = string(original, "c_source")?.to_owned();
        let c_source_sha256 = string(original, "c_source_sha256")?.to_owned();
        if symbol.is_empty() || c_function.is_empty() {
            return Err(format!("P17 B02 mapping 原 C identity 缺失：{id}"));
        }
        let leaf = symbol.strip_prefix("T.").unwrap_or(&symbol);
        if id != format!("{profile}:{leaf}") {
            return Err(format!("P17 B02 mapping id 與私有 symbol 不符：{id}"));
        }
        let c_path = relative_source(root, &c_source, &profile, false)?;
        checked_sha(&c_path, &c_source_sha256)?;
        let c_text = fs::read_to_string(&c_path).map_err(|error| error.to_string())?;
        let registered = if let Some(member) = symbol.strip_prefix("T.") {
            c_text.contains(&format!("{{\"{member}\", {c_function}}}"))
        } else if let Some(command) = symbol.strip_prefix("runC:") {
            c_function == "runC" && c_text.contains(&format!("EQ(\"{command}\")"))
        } else {
            false
        };
        if !registered {
            return Err(format!("P17 B02 C function 不在來源：{id}"));
        }
        if !originals.insert((
            profile.clone(),
            symbol.clone(),
            c_function.clone(),
            c_source.clone(),
        )) {
            return Err(format!("P17 B02 重複 private item：{id}"));
        }
        let mut lua_references = Vec::new();
        for reference in array(original, "lua_references")? {
            object(reference, &["path", "line", "source_sha256"])?;
            let path = string(reference, "path")?.to_owned();
            let source_sha256 = string(reference, "source_sha256")?.to_owned();
            let line = match field(reference, "line")? {
                StrictJsonValue::Number(value) => {
                    value.parse::<usize>().ok().filter(|line| *line > 0)
                }
                _ => None,
            }
            .ok_or_else(|| format!("P17 B02 Lua reference 行號不符：{id}"))?;
            let source = relative_source(root, &path, &profile, true)?;
            checked_sha(&source, &source_sha256)?;
            let bytes = fs::read(&source).map_err(|error| error.to_string())?;
            let source_line = bytes
                .split(|byte| *byte == b'\n')
                .nth(line - 1)
                .ok_or_else(|| format!("P17 B02 Lua reference 行號越界：{id}"))?;
            let source_line = String::from_utf8_lossy(source_line);
            let normalized = source_line.split_whitespace().collect::<String>();
            let symbol_found = if let Some(command) = symbol.strip_prefix("runC:") {
                normalized.contains(command)
            } else {
                normalized.contains(&symbol)
            };
            if !symbol_found {
                return Err(format!("P17 B02 Lua reference 行內容不符：{id}:{line}"));
            }
            if source_line.is_empty() {
                return Err(format!("P17 B02 Lua reference 行號越界：{id}"));
            }
            if !references.insert((profile.clone(), symbol.clone(), path.clone(), line)) {
                return Err(format!("P17 B02 Lua reference 重複：{id}"));
            }
            lua_references.push(LuaReference {
                path,
                line,
                source_sha256,
            });
        }
        let reason = string(item, "reason")?.to_owned();
        let rust_invariant = string(item, "rust_invariant")?.to_owned();
        if !useful(&reason) || !useful(&rust_invariant) {
            return Err(format!("P17 B02 四欄缺具體原因／不變量：{id}"));
        }
        let replacement = field(item, "replacement")?;
        object(replacement, &["case_id", "public_gap"])?;
        let case_id = string(replacement, "case_id")?.to_owned();
        let public_gap = string(replacement, "public_gap")?.to_owned();
        if !FAMILIES.contains(&case_id.as_str()) || (!public_gap.is_empty() && !useful(&public_gap))
        {
            return Err(format!("P17 B02 替代 case 未對應：{id}"));
        }
        items.push(MappingItem {
            id,
            profile,
            symbol,
            c_function,
            c_source,
            c_source_sha256,
            lua_references,
            reason,
            rust_invariant,
            case_id,
            public_gap,
        });
    }
    let profiles = PROFILES.map(|profile| {
        (
            items.iter().filter(|item| item.profile == profile).count(),
            items
                .iter()
                .filter(|item| item.profile == profile && item.lua_references.is_empty())
                .count(),
        )
    });
    let actual_55 = items
        .iter()
        .filter(|item| item.profile == PROFILES[0])
        .map(|item| item.id.split_once(':').map(|(_, leaf)| leaf).unwrap_or(""))
        .collect::<BTreeSet<_>>();
    let actual_54 = items
        .iter()
        .filter(|item| item.profile == PROFILES[1])
        .map(|item| item.id.split_once(':').map(|(_, leaf)| leaf).unwrap_or(""))
        .collect::<BTreeSet<_>>();
    if items.len() != 49
        || items
            .iter()
            .map(|item| item.lua_references.len())
            .sum::<usize>()
            != 270
        || profiles != [(32, 10), (17, 4)]
        || actual_55 != PRIVATE_55.split_whitespace().collect()
        || actual_54 != PRIVATE_54.split_whitespace().collect()
    {
        return Err("P17 B02 private inventory 49項／270refs／14未引用分布不符".into());
    }
    Ok(items)
}

pub(super) fn parse_cases(body: &str) -> Result<Vec<InternalCase>, String> {
    let value = StrictJsonParser::parse(body)?;
    object(&value, &["schema", "cases"])?;
    if string(&value, "schema")? != "rivetlua-internal-cases-v1" {
        return Err("P17 B02 cases schema 不符".into());
    }
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    for item in array(&value, "cases")? {
        object(item, &["case_id", "profiles", "runs", "evidence"])?;
        let case_id = string(item, "case_id")?.to_owned();
        if !FAMILIES.contains(&case_id.as_str()) || !seen.insert(case_id.clone()) {
            return Err(format!("P17 B02 case 缺失、範圍外或重複：{case_id}"));
        }
        let profiles = array(item, "profiles")?
            .iter()
            .map(|profile| {
                profile
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("P17 B02 cases profile 非字串".into())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let expected = if matches!(case_id.as_str(), "external-strings" | "gc-parameters") {
            &PROFILES[..1]
        } else {
            &PROFILES[..]
        };
        if profiles.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(format!("P17 B02 case profile 不符：{case_id}"));
        }
        let mut runs = Vec::new();
        let mut run_ids = BTreeSet::new();
        for run in array(item, "runs")? {
            object(run, &["crate", "target", "selector", "expected_matched"])?;
            let crate_name = string(run, "crate")?.to_owned();
            let target = string(run, "target")?.to_owned();
            let selector = string(run, "selector")?.to_owned();
            let expected_matched = match field(run, "expected_matched")? {
                StrictJsonValue::Number(value) => {
                    value.parse::<u32>().ok().filter(|count| *count > 0)
                }
                _ => None,
            }
            .ok_or_else(|| format!("P17 B02 expected_matched 無效：{case_id}"))?;
            if crate_name != "rivetlua-capi"
                || ![
                    "p17_internal_replacements",
                    "native_bridge",
                    "external_string",
                ]
                .contains(&target.as_str())
                || (target == "p17_internal_replacements"
                    && selector != format!("p17_internal_{}", case_id.replace('-', "_")))
                || selector.is_empty()
                || !selector
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
                || !run_ids.insert((target.clone(), selector.clone()))
            {
                return Err(format!("P17 B02 run target/selector 不符：{case_id}"));
            }
            runs.push(CaseRun {
                target,
                selector,
                expected_matched,
            });
        }
        let evidence = match field(item, "evidence")? {
            StrictJsonValue::Null => None,
            value => {
                object(value, &["batch", "facet"])?;
                Some(NativeEvidence {
                    batch: string(value, "batch")?.to_owned(),
                    facet: string(value, "facet")?.to_owned(),
                })
            }
        };
        if case_id == "native-modules" {
            if !runs.is_empty()
                || !matches!(evidence, Some(ref value) if value.batch == "P17-B01" && value.facet == "module-load")
            {
                return Err("P17 B02 native-modules 必須引用 B01 真實 module-load".into());
            }
        } else if runs.is_empty() || evidence.is_some() {
            return Err(format!(
                "P17 B02 case 缺真實替代 run 或範圍外 evidence：{case_id}"
            ));
        }
        cases.push(InternalCase {
            case_id,
            profiles,
            runs,
            evidence,
        });
    }
    if seen.len() != FAMILIES.len() {
        return Err("P17 B02 未涵蓋固定 12 families".into());
    }
    Ok(cases)
}

pub(super) fn bind(items: &[MappingItem], cases: &[InternalCase]) -> Result<(), String> {
    let by_id = cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    for item in items {
        let case = by_id
            .get(item.case_id.as_str())
            .ok_or_else(|| format!("P17 B02 未對應 case：{}", item.id))?;
        if !case.profiles.contains(&item.profile) {
            return Err(format!("P17 B02 mapping/profile 不對應：{}", item.id));
        }
    }
    Ok(())
}

pub(super) struct RunProof {
    pub case_id: String,
    pub profile: String,
    pub target: String,
    pub selector: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub exit_code: i32,
    pub matched: u32,
    pub passed: u32,
    pub failed: u32,
    pub ignored: u32,
    pub log: report::Input,
    pub executable: Option<report::Input>,
    pub build_log: Option<report::Input>,
    pub build_command: Option<Vec<String>>,
    pub source_batch: Option<&'static str>,
}

impl RunProof {
    fn json(&self) -> String {
        let command = self
            .command
            .iter()
            .map(|part| report::q(part))
            .collect::<Vec<_>>()
            .join(",");
        let executable = self
            .executable
            .as_ref()
            .map_or_else(|| "null".into(), report::Input::json);
        let build_log = self
            .build_log
            .as_ref()
            .map_or_else(|| "null".into(), report::Input::json);
        let build_command = self.build_command.as_ref().map_or_else(
            || "null".into(),
            |command| {
                format!(
                    "[{}]",
                    command
                        .iter()
                        .map(|part| report::q(part))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            },
        );
        let batch = self.source_batch.map_or_else(|| "null".into(), report::q);
        format!(
            "{{\"case_id\":{},\"profile\":{},\"target\":{},\"selector\":{},\"command\":[{command}],\"cwd\":{},\"exit_code\":{},\"matched\":{},\"passed\":{},\"failed\":{},\"ignored\":{},\"log\":{},\"executable\":{executable},\"build_log\":{build_log},\"build_command\":{build_command},\"source_batch\":{batch}}}",
            report::q(&self.case_id),
            report::q(&self.profile),
            report::q(&self.target),
            report::q(&self.selector),
            report::q(&self.cwd),
            self.exit_code,
            self.matched,
            self.passed,
            self.failed,
            self.ignored,
            self.log.json()
        )
    }

    fn pass(&self) -> bool {
        self.exit_code == 0
            && self.matched > 0
            && self.passed == self.matched
            && self.failed == 0
            && self.ignored == 0
    }
}

pub(super) struct RowProof {
    pub item: MappingItem,
    pub run_indices: Vec<usize>,
}

pub(super) struct Evidence {
    pub mapping: report::Input,
    pub cases: report::Input,
    pub b01: report::Input,
    pub review: report::Input,
    pub impacts: Vec<report::ToolingImpact>,
    pub rows: Vec<RowProof>,
    pub runs: Vec<RunProof>,
}

impl Evidence {
    pub(super) fn pass(&self) -> bool {
        !self.rows.is_empty()
            && self.impacts.len() == 2
            && self.runs.iter().all(RunProof::pass)
            && self.rows.iter().all(|row| {
                !row.run_indices.is_empty()
                    && row.run_indices.iter().all(|index| {
                        self.runs.get(*index).is_some_and(|run| {
                            run.case_id == row.item.case_id
                                && run.profile == row.item.profile
                                && run.pass()
                        })
                    })
            })
    }

    pub(super) fn json(&self) -> String {
        let impacts = self
            .impacts
            .iter()
            .map(|impact| {
                format!(
                    "{{\"path\":{},\"before_sha256\":{},\"after_sha256\":{}}}",
                    report::q(&impact.path),
                    report::q(&impact.before_sha256),
                    report::q(&impact.after_sha256)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let runs = self
            .runs
            .iter()
            .map(RunProof::json)
            .collect::<Vec<_>>()
            .join(",");
        let rows = self.rows.iter().map(|row| {
            let refs = row.item.lua_references.iter().map(|reference| format!("{{\"path\":{},\"line\":{},\"source_sha256\":{}}}", report::q(&reference.path), reference.line, report::q(&reference.source_sha256))).collect::<Vec<_>>().join(",");
            let results = row.run_indices.iter().map(|index| index.to_string()).collect::<Vec<_>>().join(",");
            format!("{{\"id\":{},\"original\":{{\"profile\":{},\"symbol\":{},\"c_function\":{},\"c_source\":{},\"c_source_sha256\":{},\"lua_references\":[{refs}]}},\"reason\":{},\"rust_invariant\":{},\"replacement\":{{\"case_id\":{},\"public_gap\":{}}},\"run_indices\":[{results}]}}",report::q(&row.item.id),report::q(&row.item.profile),report::q(&row.item.symbol),report::q(&row.item.c_function),report::q(&row.item.c_source),report::q(&row.item.c_source_sha256),report::q(&row.item.reason),report::q(&row.item.rust_invariant),report::q(&row.item.case_id),report::q(&row.item.public_gap))
        }).collect::<Vec<_>>().join(",");
        format!(
            "{{\"mapping\":{},\"cases\":{},\"b01\":{},\"source_impact_review\":{},\"tooling_changes\":[{impacts}],\"rows\":[{rows}],\"runs\":[{runs}]}}",
            self.mapping.json(),
            self.cases.json(),
            self.b01.json(),
            self.review.json()
        )
    }
}

struct BuildProof {
    executable: report::Input,
    log: report::Input,
    command: Vec<String>,
}

fn invoke(command: &[String], cwd: &Path, log: &Path) -> Result<(i32, String), String> {
    let (program, args) = command.split_first().ok_or("P17 B02 空命令")?;
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|error| format!("P17 B02 啟動 {program} 失敗：{error}"))?;
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    fs::write(log, &bytes).map_err(|error| format!("P17 B02 log 寫入失敗：{error}"))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

fn build_target(
    root: &Path,
    work: &Path,
    profile: &str,
    target: &str,
) -> Result<BuildProof, String> {
    let command = build_command(profile, target);
    let log = work.join(format!("build-{profile}-{target}.log"));
    let (exit, body) = invoke(&command, root, &log)?;
    if exit != 0 {
        return Err(format!(
            "P17 B02 target build 非零：{profile}/{target}；log={}",
            log.display()
        ));
    }
    let executable = compiler_artifact(&body, target)?;
    if !Path::new(&executable).starts_with(
        std::env::var("CARGO_TARGET_DIR").map_err(|_| "P17 B02 CARGO_TARGET_DIR 缺失")?,
    ) {
        return Err("P17 B02 test executable 不在共用 P17 target".into());
    }
    Ok(BuildProof {
        executable: report::Input::from_path(Path::new(&executable))?,
        log: report::Input::from_path(&log)?,
        command,
    })
}

fn parse_test_counts(body: &str, selector: &str) -> Result<(u32, u32, u32, u32), String> {
    let mut names = BTreeSet::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut ignored = 0;
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("test ") else {
            continue;
        };
        let Some((name, result)) = rest.split_once(" ... ") else {
            continue;
        };
        if !name.contains(selector) || !names.insert(name.to_owned()) {
            return Err(format!("P17 B02 test output selector/重複不符：{selector}"));
        }
        match result {
            "ok" => passed += 1,
            "FAILED" => failed += 1,
            "ignored" => ignored += 1,
            value if value.starts_with("ignored, ") => ignored += 1,
            _ => return Err(format!("P17 B02 test output 狀態不符：{name}")),
        }
    }
    let matched = names.len() as u32;
    let status = if failed == 0 { "ok" } else { "FAILED" };
    let summary =
        format!("test result: {status}. {passed} passed; {failed} failed; {ignored} ignored;");
    if !body.contains(&summary) || passed + failed + ignored != matched {
        return Err(format!(
            "P17 B02 test output summary/count 不符：{selector}"
        ));
    }
    Ok((matched, passed, failed, ignored))
}

fn parse_test_log(
    body: &str,
    selector: &str,
    expected: u32,
    exit: i32,
) -> Result<(u32, u32, u32, u32), String> {
    let (matched, passed, failed, ignored) = parse_test_counts(body, selector)?;
    if exit != 0 || matched != expected || failed != 0 || ignored != 0 || passed != matched {
        return Err(format!(
            "P17 B02 test 非真實匹配 PASS：{selector} matched={matched} expected={expected} exit={exit}"
        ));
    }
    Ok((matched, passed, failed, ignored))
}

fn run_test(
    root: &Path,
    work: &Path,
    case_id: &str,
    profile: &str,
    run: &CaseRun,
    build: &BuildProof,
) -> Result<(RunProof, Option<String>), String> {
    let command = vec![
        build.executable.path.clone(),
        run.selector.clone(),
        "--exact".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ];
    let log = work.join(format!(
        "run-{profile}-{case_id}-{}.log",
        run.selector.replace(':', "_")
    ));
    let (exit, body, launch_issue) = match invoke(&command, root, &log) {
        Ok((exit, body)) => (exit, body, None),
        Err(error) => {
            fs::write(&log, &error).map_err(|write_error| {
                format!("P17 B02 test 啟動／log 均失敗：{error}；{write_error}")
            })?;
            (-1, error.clone(), Some(error))
        }
    };
    let (counts, parse_issue) = match parse_test_counts(&body, &run.selector) {
        Ok(counts) => (counts, None),
        Err(error) => ((0, 0, 0, 0), Some(error)),
    };
    let (matched, passed, failed, ignored) = counts;
    let issue = launch_issue.or(parse_issue).or_else(|| {
        (exit != 0
            || matched != run.expected_matched
            || failed != 0
            || ignored != 0
            || passed != matched)
            .then(|| {
                format!(
                    "P17 B02 test 非真實匹配 PASS：{} matched={matched} expected={} exit={exit} passed={passed} failed={failed} ignored={ignored}",
                    run.selector, run.expected_matched
                )
            })
    });
    Ok((
        RunProof {
            case_id: case_id.into(),
            profile: profile.into(),
            target: run.target.clone(),
            selector: run.selector.clone(),
            command,
            cwd: root.display().to_string(),
            exit_code: exit,
            matched,
            passed,
            failed,
            ignored,
            log: report::Input::from_path(&log)?,
            executable: Some(report::Input::from_path(Path::new(&build.executable.path))?),
            build_log: Some(report::Input::from_path(Path::new(&build.log.path))?),
            build_command: Some(build.command.clone()),
            source_batch: None,
        },
        issue,
    ))
}

const B01_SHA: &str = "f915bb587d537f703c4d4ec1093b14163122af3fa73f0af9e9caf7f1cf6a7c77";
const B02_SHA: &str = "87e66ca8005bc01e2af1b07a804623573ffd689b7ee899d17ad5a247dc160d30";
const B02_TOOLING: [(&str, &str, &str); 3] = [
    (
        "xtask/src/p17/mod.rs",
        "xtask__src__p17__mod.rs",
        "a76a276cbca80c7ddfa15b496a23c837dd7b1663220767093c6c3fcaa888cc55",
    ),
    (
        "xtask/src/p17/report.rs",
        "xtask__src__p17__report.rs",
        "22a5f7e0cc5450f1eed50da886178c43ced85d8a07441d41e15ee36be26e4261",
    ),
    (
        "xtask/src/p17/b02.rs",
        "xtask__src__p17__b02.rs",
        "9170c8dc9acda4eb4a016ff184c57c12dddf79884e8d638d8b46156f0c0c214f",
    ),
];

pub(super) fn review_path(evidence: &Path) -> PathBuf {
    evidence.join("p17-b02-source-impact-review.json")
}

pub(super) fn canonical_diff_headers(bytes: &[u8]) -> Result<String, String> {
    let body = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut counts = [0u32; 3];
    let mut normalized = String::new();
    for line in body.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            counts[0] += 1;
            normalized.push_str("diff --git a/HISTORICAL b/CURRENT\n");
        } else if line.starts_with("--- ") {
            counts[1] += 1;
            normalized.push_str("--- a/HISTORICAL\n");
        } else if line.starts_with("+++ ") {
            counts[2] += 1;
            normalized.push_str("+++ b/CURRENT\n");
        } else {
            normalized.push_str(line);
        }
    }
    if counts != [1, 1, 1] {
        return Err("P17 B03 歷史 diff 路徑 header 數不符".into());
    }
    Ok(normalized)
}

fn validate_review(
    root: &Path,
    evidence: &Path,
    impacts: &[report::ToolingImpact],
    historical_tooling: Option<&Path>,
) -> Result<report::Input, String> {
    let path = review_path(evidence);
    let body = fs::read_to_string(&path)
        .map_err(|error| format!("P17 B02 source-impact 審查紀錄缺失：{error}"))?;
    let value = StrictJsonParser::parse(&body)?;
    object(
        &value,
        &[
            "schema",
            "b01_report_sha256",
            "changes",
            "regression",
            "review_note",
        ],
    )?;
    if string(&value, "schema")? != "rivetlua-b02-source-impact-v1"
        || string(&value, "b01_report_sha256")? != B01_SHA
        || !useful(string(&value, "review_note")?)
    {
        return Err("P17 B02 source-impact 審查主鍵不符".into());
    }
    let changes = array(&value, "changes")?;
    if changes.len() != impacts.len() || impacts.len() != 2 {
        return Err("P17 B02 source-impact 需精確兩個共用工具差異".into());
    }
    let expected = [
        (
            "xtask/src/p17/mod.rs",
            "xtask__src__p17__mod.rs",
            "p17-b02-impact-mod.diff",
        ),
        (
            "xtask/src/p17/report.rs",
            "xtask__src__p17__report.rs",
            "p17-b02-impact-report.diff",
        ),
    ];
    for ((change, impact), (relative, snapshot, diff_name)) in
        changes.iter().zip(impacts).zip(expected)
    {
        object(
            change,
            &[
                "path",
                "before_sha256",
                "after_sha256",
                "diff_path",
                "diff_sha256",
            ],
        )?;
        let source = root.join(relative);
        let effective_source = historical_tooling
            .map(|dir| dir.join(snapshot))
            .unwrap_or_else(|| source.clone());
        let baseline = evidence.join("p17-b01-tooling-baseline").join(snapshot);
        let diff = evidence.join(diff_name);
        if string(change, "path")? != relative
            || impact.path != source.display().to_string()
            || string(change, "before_sha256")? != impact.before_sha256
            || string(change, "after_sha256")? != impact.after_sha256
            || string(change, "diff_path")? != diff.display().to_string()
        {
            return Err(format!(
                "P17 B02 source-impact identity/hash 不符：{relative}"
            ));
        }
        if historical_tooling.is_some() {
            checked_sha(&effective_source, &impact.after_sha256)?;
        }
        checked_sha(&diff, string(change, "diff_sha256")?)?;
        let output = Command::new("git")
            .args(["diff", "--no-index", "--no-ext-diff", "--"])
            .arg(&baseline)
            .arg(&effective_source)
            .current_dir(root)
            .output()
            .map_err(|error| format!("P17 B02 source-impact diff 失敗：{error}"))?;
        let stored = fs::read(&diff).map_err(|error| error.to_string())?;
        let same_diff = if historical_tooling.is_some() {
            canonical_diff_headers(&output.stdout)? == canonical_diff_headers(&stored)?
        } else {
            output.stdout == stored
        };
        if output.status.code() != Some(1) || !same_diff {
            return Err(format!(
                "P17 B02 source-impact diff 原始 bytes 不符：{relative}"
            ));
        }
    }
    let regression = field(&value, "regression")?;
    object(
        regression,
        &[
            "command",
            "cwd",
            "exit_code",
            "matched",
            "passed",
            "failed",
            "ignored",
            "log_path",
            "log_sha256",
        ],
    )?;
    let command = array(regression, "command")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or("P17 B02 regression command 非字串".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expected_command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "rivetlua-xtask",
        "--bin",
        "rivetlua-xtask",
        "p17_b02_reuse",
        "--",
        "--ignored",
        "--test-threads=1",
    ];
    let log = evidence.join("p17-b02-reuse-regression.log");
    if command.iter().map(String::as_str).collect::<Vec<_>>() != expected_command
        || string(regression, "cwd")? != root.display().to_string()
        || field(regression, "exit_code")?.as_i32() != Some(0)
        || field(regression, "matched")?.as_i32() != Some(1)
        || field(regression, "passed")?.as_i32() != Some(1)
        || field(regression, "failed")?.as_i32() != Some(0)
        || field(regression, "ignored")?.as_i32() != Some(0)
        || string(regression, "log_path")? != log.display().to_string()
    {
        return Err("P17 B02 source-impact 定點回歸欄位不符".into());
    }
    checked_sha(&log, string(regression, "log_sha256")?)?;
    let log_body = fs::read_to_string(&log).map_err(|error| error.to_string())?;
    parse_test_log(&log_body, "p17_b02_reuse", 1, 0)?;
    report::Input::from_path(&path)
}

fn native_proof(b01: &Path, profile: &str) -> Result<RunProof, String> {
    let body =
        fs::read_to_string(b01).map_err(|error| format!("P17 B02 B01 report 不可讀：{error}"))?;
    let value = StrictJsonParser::parse(&body)?;
    let check = array(&value, "checks")?
        .iter()
        .find(|check| {
            string(check, "profile").ok() == Some(profile)
                && string(check, "facet").ok() == Some("module-load")
                && string(check, "execution_path").ok() == Some("cli-rust-vm")
        })
        .ok_or_else(|| format!("P17 B02 B01 缺 CLI native module-load：{profile}"))?;
    if string(check, "status")? != "PASS"
        || field(check, "exit_code")?.as_i32() != Some(0)
        || field(check, "matched")?.as_i32() != Some(1)
        || field(check, "passed")?.as_i32() != Some(1)
        || field(check, "failed")?.as_i32() != Some(0)
        || field(check, "ignored")?.as_i32() != Some(0)
    {
        return Err(format!("P17 B02 B01 native module-load 非 PASS：{profile}"));
    }
    let command = array(check, "command")?
        .iter()
        .map(|part| {
            part.as_str()
                .map(str::to_owned)
                .ok_or("P17 B02 B01 native argv 非字串".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let log = Path::new(string(check, "log_path")?);
    let log_input = report::Input::from_path(log)?;
    if log_input.sha256 != string(check, "log_sha256")? {
        return Err("P17 B02 B01 native log SHA 不符".into());
    }
    let executable = report::Input::from_path(Path::new(
        command.first().ok_or("P17 B02 B01 native argv 空白")?,
    ))?;
    Ok(RunProof {
        case_id: "native-modules".into(),
        profile: profile.into(),
        target: "module-load".into(),
        selector: "cli-rust-vm".into(),
        command,
        cwd: string(check, "cwd")?.into(),
        exit_code: 0,
        matched: 1,
        passed: 1,
        failed: 0,
        ignored: 0,
        log: log_input,
        executable: Some(executable),
        build_log: None,
        build_command: None,
        source_batch: Some("P17-B01"),
    })
}

pub(super) fn run(root: &Path, report: &mut report::Report) -> Result<(), String> {
    let environment = runner::environment(root)?;
    report.target = environment.target.clone();
    report.environment = runner::related_environment(&environment);
    report.toolchain = runner::toolchain_identity()?;
    let mapping_path = root.join("tests/p17/internal/mapping.json");
    let cases_path = root.join("tests/p17/internal/cases.json");
    let mapping_body = fs::read_to_string(&mapping_path)
        .map_err(|error| format!("P17 B02 mapping 不可讀：{error}"))?;
    let cases_body = fs::read_to_string(&cases_path)
        .map_err(|error| format!("P17 B02 cases 不可讀：{error}"))?;
    let items = parse_mapping(root, &mapping_body)?;
    let cases = parse_cases(&cases_body)?;
    bind(&items, &cases)?;
    let b01 = root.join("target/rivetlua-reports/gate-P17-B01.json");
    let impacts = report::validate_b01_for_b02(root, &b01)?;
    let review = validate_review(root, &environment.evidence_dir, &impacts, None)?;
    for path in runner::related_sources(root)? {
        report.input(&path)?;
    }
    for path in [
        root.join("xtask/src/p17/b02.rs"),
        mapping_path.clone(),
        cases_path.clone(),
        root.join("crates/rivetlua-capi/tests/p17_internal_replacements.rs"),
        root.join("crates/rivetlua-capi/tests/native_bridge.rs"),
        root.join("crates/rivetlua-capi/tests/external_string.rs"),
    ] {
        report.input(&path)?;
    }
    for item in &items {
        report.input(&root.join(&item.c_source))?;
        for reference in &item.lua_references {
            report.input(&root.join(&reference.path))?;
        }
    }
    report.dependencies.push(report::Input::from_path(&b01)?);
    report.dependencies.push(review.clone());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let work = environment
        .evidence_dir
        .join(format!("b02-{}-{stamp}", std::process::id()));
    fs::create_dir(&work).map_err(|error| format!("P17 B02 evidence 目錄失敗：{error}"))?;
    let mut builds = BTreeMap::<(String, String), BuildProof>::new();
    let mut runs = Vec::new();
    let mut failed_runs = Vec::<(usize, String)>::new();
    for case in &cases {
        for profile in &case.profiles {
            if case.evidence.is_some() {
                runs.push(native_proof(&b01, profile)?);
                continue;
            }
            for run in &case.runs {
                let key = (profile.clone(), run.target.clone());
                if !builds.contains_key(&key) {
                    builds.insert(
                        key.clone(),
                        build_target(root, &work, profile, &run.target)?,
                    );
                }
                let build = builds.get(&key).ok_or("P17 B02 build cache 缺失")?;
                let (observed, issue) = run_test(root, &work, &case.case_id, profile, run, build)?;
                if let Some(diagnostic) = issue {
                    failed_runs.push((runs.len(), diagnostic));
                }
                runs.push(observed);
            }
        }
    }
    let rows = items
        .into_iter()
        .map(|item| {
            let run_indices = runs
                .iter()
                .enumerate()
                .filter_map(|(index, run)| {
                    (run.case_id == item.case_id && run.profile == item.profile).then_some(index)
                })
                .collect::<Vec<_>>();
            RowProof { item, run_indices }
        })
        .collect::<Vec<_>>();
    let evidence = Evidence {
        mapping: report::Input::from_path(&mapping_path)?,
        cases: report::Input::from_path(&cases_path)?,
        b01: report::Input::from_path(&b01)?,
        review,
        impacts,
        rows,
        runs,
    };
    if !failed_runs.is_empty() {
        for (index, diagnostic) in &failed_runs {
            let run = &evidence.runs[*index];
            let mut check = report::Check::observed(
                "internal-mapping",
                &run.profile,
                run.command.clone(),
                Path::new(&run.cwd),
                Some(run.exit_code),
                Some(report::Input::from_path(Path::new(&run.log.path))?),
                false,
                diagnostic,
            );
            check.case_id = "COMPLETE-005".into();
            check.operation = "b02-case";
            check.execution_path = "capi-public";
            check.matched = run.matched;
            check.passed = run.passed;
            check.failed = run.failed;
            check.ignored = run.ignored;
            report.checks.push(check);
        }
        report.b02 = Some(evidence);
        return Err(format!(
            "P17 B02 {} 個具名測試未通過；其餘固定 selectors 已執行",
            failed_runs.len()
        ));
    }
    if !evidence.pass() {
        return Err("P17 B02 mapping/run evidence 非完整 PASS".into());
    }
    for family in FAMILIES {
        let matching = evidence
            .runs
            .iter()
            .filter(|run| run.case_id == family)
            .collect::<Vec<_>>();
        let first = matching
            .first()
            .ok_or(format!("P17 B02 family 無替代結果：{family}"))?;
        let mut check = report::Check::observed(
            "internal-mapping",
            &first.profile,
            first.command.clone(),
            Path::new(&first.cwd),
            Some(0),
            Some(report::Input::from_path(Path::new(&first.log.path))?),
            true,
            family,
        );
        check.case_id = "COMPLETE-005".into();
        check.operation = "b02-case";
        check.execution_path = if family == "native-modules" {
            "b01-evidence"
        } else {
            "capi-public"
        };
        check.profile = None;
        check.matched = matching.iter().map(|run| run.matched).sum();
        check.passed = check.matched;
        check.failed = 0;
        check.ignored = 0;
        report.checks.push(check);
    }
    report.b02 = Some(evidence);
    Ok(())
}

fn input(value: &StrictJsonValue) -> Result<report::Input, String> {
    object(value, &["path", "sha256"])?;
    let path = string(value, "path")?;
    let expected = string(value, "sha256")?;
    if !Path::new(path).is_absolute() {
        return Err(format!("P17 B02 input 非絕對路徑：{path}"));
    }
    let actual = report::Input::from_path(Path::new(path))?;
    if actual.sha256 != expected {
        return Err(format!("P17 B02 input SHA 不符：{path}"));
    }
    Ok(actual)
}

fn historical_executable_input(
    value: &StrictJsonValue,
    phase_view: Option<&report::PhaseSourceView>,
) -> Result<report::Input, String> {
    object(value, &["path", "sha256"])?;
    if let Some(path) = phase_view
        .map(|view| report::historical_input(value, view))
        .transpose()?
        .flatten()
    {
        return Ok(report::Input {
            path,
            sha256: string(value, "sha256")?.to_owned(),
        });
    }
    input(value)
}

fn historical_source_input(
    value: &StrictJsonValue,
    root: &Path,
    baseline: Option<&Path>,
    phase_view: Option<&report::PhaseSourceView>,
) -> Result<report::Input, String> {
    if let Some(view) = phase_view {
        if view.was_absent(string(value, "path")?) {
            return Err("P17 phase B02 舊報告聲稱不存在的 source".into());
        }
    }
    if let Some(baseline) = baseline {
        let path = string(value, "path")?;
        let relative = Path::new(path)
            .strip_prefix(root)
            .ok()
            .and_then(|path| path.to_str());
        if let Some((_, snapshot, expected)) = B02_TOOLING
            .iter()
            .find(|(source, _, _)| Some(*source) == relative)
        {
            object(value, &["path", "sha256"])?;
            if string(value, "sha256")? != *expected {
                return Err(format!("P17 B03 B02 歷史 source input SHA 不符：{path}"));
            }
            checked_sha(&baseline.join(snapshot), expected)?;
            return Ok(report::Input {
                path: path.to_owned(),
                sha256: (*expected).into(),
            });
        }
    }
    if let Some(path) = phase_view
        .map(|view| report::historical_input(value, view))
        .transpose()?
        .flatten()
    {
        return Ok(report::Input {
            path,
            sha256: string(value, "sha256")?.to_owned(),
        });
    }
    input(value)
}

fn string_list(value: &StrictJsonValue, name: &str) -> Result<Vec<String>, String> {
    array(value, name)?
        .iter()
        .map(|part| {
            part.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("P17 B02 {name} 元素非字串"))
        })
        .collect()
}

fn number(value: &StrictJsonValue, name: &str) -> Result<u32, String> {
    match field(value, name)? {
        StrictJsonValue::Number(text) => text
            .parse::<u32>()
            .map_err(|_| format!("P17 B02 {name} 非非負整數")),
        _ => Err(format!("P17 B02 {name} 非數值")),
    }
}

fn build_command(profile: &str, target: &str) -> Vec<String> {
    let mut command = vec![
        "cargo".into(),
        "test".into(),
        "--locked".into(),
        "-p".into(),
        "rivetlua-capi".into(),
        "--test".into(),
        target.into(),
        "--no-run".into(),
        "--message-format=json-render-diagnostics".into(),
    ];
    if profile == PROFILES[0] {
        command.extend(["--features".into(), "lua55".into()]);
    } else {
        command.extend([
            "--no-default-features".into(),
            "--features".into(),
            "lua54".into(),
        ]);
    }
    command
}

fn compiler_artifact(body: &str, target: &str) -> Result<String, String> {
    let mut executables = BTreeSet::new();
    for line in body.lines() {
        let Ok(value) = StrictJsonParser::parse(line) else {
            continue;
        };
        if value.get("reason").and_then(StrictJsonValue::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(target_value) = value.get("target") else {
            continue;
        };
        if target_value.get("name").and_then(StrictJsonValue::as_str) != Some(target) {
            continue;
        }
        if let Some(path) = value.get("executable").and_then(StrictJsonValue::as_str) {
            executables.insert(path.to_owned());
        }
    }
    if executables.len() != 1 {
        return Err(format!("P17 B02 build executable 數不符：{target}"));
    }
    executables
        .into_iter()
        .next()
        .ok_or("P17 B02 build executable 缺失".into())
}

fn validate_run(
    value: &StrictJsonValue,
    case: &InternalCase,
    profile: &str,
    specified: Option<&CaseRun>,
    root: &Path,
    b01: &Path,
    target_dir: &Path,
    evidence_dir: &Path,
    phase_view: Option<&report::PhaseSourceView>,
) -> Result<(u32, report::Input), String> {
    object(
        value,
        &[
            "case_id",
            "profile",
            "target",
            "selector",
            "command",
            "cwd",
            "exit_code",
            "matched",
            "passed",
            "failed",
            "ignored",
            "log",
            "executable",
            "build_log",
            "build_command",
            "source_batch",
        ],
    )?;
    if string(value, "case_id")? != case.case_id || string(value, "profile")? != profile {
        return Err("P17 B02 run case/profile 不符".into());
    }
    let command = string_list(value, "command")?;
    let log = input(field(value, "log")?)?;
    let matched = number(value, "matched")?;
    if field(value, "exit_code")?.as_i32() != Some(0)
        || matched == 0
        || number(value, "passed")? != matched
        || number(value, "failed")? != 0
        || number(value, "ignored")? != 0
    {
        return Err("P17 B02 run count/exit 非 PASS".into());
    }
    if let Some(run) = specified {
        if string(value, "target")? != run.target
            || string(value, "selector")? != run.selector
            || matched != run.expected_matched
            || string(value, "cwd")? != root.display().to_string()
            || field(value, "source_batch")? != &StrictJsonValue::Null
        {
            return Err("P17 B02 run binding/cwd 不符".into());
        }
        let executable = historical_executable_input(field(value, "executable")?, phase_view)?;
        let build_log = input(field(value, "build_log")?)?;
        let work = Path::new(&log.path)
            .parent()
            .ok_or("P17 B02 run log 缺工作目錄")?;
        if work.parent() != Some(evidence_dir)
            || !work
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("b02-"))
            || Path::new(&log.path)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(
                    format!(
                        "run-{profile}-{}-{}.log",
                        case.case_id,
                        run.selector.replace(':', "_")
                    )
                    .as_str(),
                )
            || Path::new(&build_log.path)
                != work.join(format!("build-{profile}-{}.log", run.target))
        {
            return Err("P17 B02 run/build log 路徑不在批次 evidence".into());
        }
        if !Path::new(&executable.path).starts_with(target_dir)
            || command
                != [
                    executable.path.clone(),
                    run.selector.clone(),
                    "--exact".into(),
                    "--nocapture".into(),
                    "--test-threads=1".into(),
                ]
            || string_list(value, "build_command")? != build_command(profile, &run.target)
        {
            return Err("P17 B02 run executable/argv/build 命令不符".into());
        }
        let build_body = fs::read_to_string(&build_log.path).map_err(|error| error.to_string())?;
        if compiler_artifact(&build_body, &run.target)? != executable.path {
            return Err("P17 B02 build log 與 executable 不符".into());
        }
        let body = fs::read_to_string(&log.path).map_err(|error| error.to_string())?;
        parse_test_log(&body, &run.selector, run.expected_matched, 0)?;
    } else {
        let expected = native_proof(b01, profile)?;
        if string(value, "target")? != expected.target
            || string(value, "selector")? != expected.selector
            || string(value, "cwd")? != expected.cwd
            || command != expected.command
            || log.path != expected.log.path
            || log.sha256 != expected.log.sha256
            || matched != 1
            || input(field(value, "executable")?)?.sha256
                != expected
                    .executable
                    .as_ref()
                    .ok_or("P17 B02 native executable 缺失")?
                    .sha256
            || field(value, "build_log")? != &StrictJsonValue::Null
            || field(value, "build_command")? != &StrictJsonValue::Null
            || string(value, "source_batch")? != "P17-B01"
        {
            return Err("P17 B02 B01 module-load evidence 不符".into());
        }
    }
    Ok((matched, log))
}

pub(super) fn validate_report(root: &Path, path: &Path) -> Result<(), String> {
    validate_report_with_tooling(root, path, None, None)
}

pub(super) fn validate_b02_for_b03(root: &Path, path: &Path) -> Result<(), String> {
    if manifest::sha256(path)? != B02_SHA {
        return Err("P17 B03 B02 report 原始 SHA 不符".into());
    }
    let environment = runner::environment(root)?;
    let baseline = environment.evidence_dir.join("p17-b02-tooling-baseline");
    for (_, snapshot, expected) in B02_TOOLING {
        checked_sha(&baseline.join(snapshot), expected)?;
    }
    for (source, snapshot) in [
        (path.to_path_buf(), baseline.join("gate-P17-B02.json")),
        (
            path.with_extension("sha256"),
            baseline.join("gate-P17-B02.sha256"),
        ),
    ] {
        if fs::read(&source).map_err(|error| error.to_string())?
            != fs::read(&snapshot).map_err(|error| error.to_string())?
        {
            return Err("P17 B03 B02 report/receipt 原始 bytes 不符".into());
        }
    }
    validate_report_with_tooling(root, path, Some(&baseline), None)
}

pub(super) fn validate_b02_for_phase(
    root: &Path,
    path: &Path,
    view: &report::PhaseSourceView,
) -> Result<(), String> {
    if manifest::sha256(path)? != B02_SHA {
        return Err("P17 phase B02 report 原始 SHA 不符".into());
    }
    let environment = runner::environment(root)?;
    let baseline = environment.evidence_dir.join("p17-b02-tooling-baseline");
    for (_, snapshot, expected) in B02_TOOLING {
        checked_sha(&baseline.join(snapshot), expected)?;
    }
    for (source, snapshot) in [
        (path.to_path_buf(), baseline.join("gate-P17-B02.json")),
        (
            path.with_extension("sha256"),
            baseline.join("gate-P17-B02.sha256"),
        ),
    ] {
        if fs::read(&source).map_err(|error| error.to_string())?
            != fs::read(&snapshot).map_err(|error| error.to_string())?
        {
            return Err("P17 phase B02 report/receipt 原始 bytes 不符".into());
        }
    }
    validate_report_with_tooling(root, path, Some(&baseline), Some(view))
}

pub(super) fn validate_b02_phase_copy(
    current_root: &Path,
    original_root: &Path,
) -> Result<(), String> {
    report::phase_copied_report(current_root, original_root, "B02", B02_SHA)
}

fn validate_report_with_tooling(
    root: &Path,
    path: &Path,
    historical_tooling: Option<&Path>,
    phase_view: Option<&report::PhaseSourceView>,
) -> Result<(), String> {
    let environment = runner::environment(root)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("P17 B02 report 名稱無效")?;
    if name != "gate-P17-B02.json" {
        return Err("P17 B02 report path 不符".into());
    }
    let digest = manifest::sha256(path)?;
    let receipt =
        fs::read_to_string(path.with_extension("sha256")).map_err(|error| error.to_string())?;
    if receipt != format!("{digest}  {name}\n") {
        return Err("P17 B02 report receipt 不符".into());
    }
    let value =
        StrictJsonParser::parse(&fs::read_to_string(path).map_err(|error| error.to_string())?)?;
    object(
        &value,
        &[
            "schema",
            "phase",
            "batch",
            "status",
            "diagnostic",
            "scope",
            "source_inputs",
            "configuration",
            "dependencies",
            "checks",
            "internal_mapping",
        ],
    )?;
    if string(&value, "schema")? != "rivetlua-phase-gate-v1"
        || string(&value, "phase")? != "P17"
        || string(&value, "batch")? != "P17-B02"
        || string(&value, "status")? != "PASS"
    {
        return Err("P17 B02 report 主鍵非 PASS".into());
    }
    let scope = field(&value, "scope")?;
    object(
        scope,
        &[
            "phase",
            "batch",
            "declared_cases",
            "declared_facets",
            "selectors",
            "execution_paths",
        ],
    )?;
    if string(scope, "phase")? != "P17"
        || string(scope, "batch")? != "P17-B02"
        || string_list(scope, "declared_cases")? != ["COMPLETE-005"]
        || string_list(scope, "declared_facets")? != ["internal-mapping"]
        || string_list(scope, "selectors")? != ["P17-B02"]
        || string_list(scope, "execution_paths")? != ["capi-public", "b01-evidence"]
    {
        return Err("P17 B02 report scope 越界".into());
    }
    let configuration = field(&value, "configuration")?;
    object(
        configuration,
        &["profiles", "target", "features", "toolchain", "environment"],
    )?;
    if string_list(configuration, "profiles")? != PROFILES
        || string_list(configuration, "features")? != ["native-lua55", "default-lua54,native-lua54"]
        || string(configuration, "target")? != environment.target
        || string(configuration, "toolchain")? != runner::toolchain_identity()?
    {
        return Err("P17 B02 report configuration 不符".into());
    }
    let observed_env = array(configuration, "environment")?
        .iter()
        .map(|item| {
            object(item, &["name", "value"])?;
            Ok((
                string(item, "name")?.to_owned(),
                string(item, "value")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if observed_env != report::expected_environment(&environment, phase_view) {
        return Err("P17 B02 report environment 不符".into());
    }
    let mapping_path = root.join("tests/p17/internal/mapping.json");
    let cases_path = root.join("tests/p17/internal/cases.json");
    let mapping_body = fs::read_to_string(&mapping_path).map_err(|error| error.to_string())?;
    let cases_body = fs::read_to_string(&cases_path).map_err(|error| error.to_string())?;
    let items = parse_mapping(root, &mapping_body)?;
    let cases = parse_cases(&cases_body)?;
    bind(&items, &cases)?;
    let b01 = root.join("target/rivetlua-reports/gate-P17-B01.json");
    let impacts = if let Some(view) = phase_view {
        report::validate_b01_for_phase(root, &b01, view)?
    } else if historical_tooling.is_some() {
        report::validate_b01_for_b03(root, &b01)?
    } else {
        report::validate_b01_for_b02(root, &b01)?
    };
    let review = validate_review(
        root,
        &environment.evidence_dir,
        &impacts,
        historical_tooling,
    )?;
    let mut expected_sources = runner::related_sources(root)?;
    expected_sources.extend([
        root.join("xtask/src/p17/b02.rs"),
        mapping_path.clone(),
        cases_path.clone(),
        root.join("crates/rivetlua-capi/tests/p17_internal_replacements.rs"),
        root.join("crates/rivetlua-capi/tests/native_bridge.rs"),
        root.join("crates/rivetlua-capi/tests/external_string.rs"),
    ]);
    for item in &items {
        expected_sources.push(root.join(&item.c_source));
        expected_sources.extend(
            item.lua_references
                .iter()
                .map(|reference| root.join(&reference.path)),
        );
    }
    expected_sources.sort();
    expected_sources.dedup();
    if let Some(view) = phase_view {
        expected_sources.retain(|path| !view.was_absent(&path.display().to_string()));
    }
    let mut observed_sources = BTreeSet::new();
    for source in array(&value, "source_inputs")? {
        if !observed_sources
            .insert(historical_source_input(source, root, historical_tooling, phase_view)?.path)
        {
            return Err("P17 B02 report 重複 source input".into());
        }
    }
    if observed_sources
        != expected_sources
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    {
        return Err("P17 B02 report source input 範圍不符".into());
    }
    let dependencies = array(&value, "dependencies")?;
    if dependencies.len() != 2
        || input(&dependencies[0])?.path != b01.display().to_string()
        || input(&dependencies[0])?.sha256 != B01_SHA
        || input(&dependencies[1])?.path != review.path
        || input(&dependencies[1])?.sha256 != review.sha256
    {
        return Err("P17 B02 report dependency 不符".into());
    }
    let internal = field(&value, "internal_mapping")?;
    object(
        internal,
        &[
            "mapping",
            "cases",
            "b01",
            "source_impact_review",
            "tooling_changes",
            "rows",
            "runs",
        ],
    )?;
    for (name, expected_path) in [
        ("mapping", mapping_path.as_path()),
        ("cases", cases_path.as_path()),
        ("b01", b01.as_path()),
        ("source_impact_review", Path::new(&review.path)),
    ] {
        if input(field(internal, name)?)?.path != expected_path.display().to_string() {
            return Err(format!("P17 B02 internal {name} input 不符"));
        }
    }
    let tooling = array(internal, "tooling_changes")?;
    if tooling.len() != impacts.len() {
        return Err("P17 B02 internal tooling impact 數不符".into());
    }
    for (item, impact) in tooling.iter().zip(&impacts) {
        object(item, &["path", "before_sha256", "after_sha256"])?;
        if string(item, "path")? != impact.path
            || string(item, "before_sha256")? != impact.before_sha256
            || string(item, "after_sha256")? != impact.after_sha256
        {
            return Err("P17 B02 internal tooling impact SHA 不符".into());
        }
    }
    let observed_runs = array(internal, "runs")?;
    let mut expected_bindings = Vec::new();
    for case in &cases {
        for profile in &case.profiles {
            if case.evidence.is_some() {
                expected_bindings.push((case, profile.as_str(), None));
            } else {
                for run in &case.runs {
                    expected_bindings.push((case, profile.as_str(), Some(run)));
                }
            }
        }
    }
    if observed_runs.len() != expected_bindings.len() {
        return Err("P17 B02 替代 run 數不符".into());
    }
    let mut run_counts = Vec::new();
    let mut shared_builds = BTreeMap::<(String, String), (String, String)>::new();
    for (observed, (case, profile, run)) in observed_runs.iter().zip(&expected_bindings) {
        run_counts.push(validate_run(
            observed,
            case,
            profile,
            *run,
            root,
            &b01,
            &environment.target_dir,
            &environment.evidence_dir,
            phase_view,
        )?);
        if let Some(run) = run {
            let build_log = input(field(observed, "build_log")?)?;
            let executable =
                historical_executable_input(field(observed, "executable")?, phase_view)?;
            let key = ((*profile).to_owned(), run.target.clone());
            let value = (build_log.path, executable.sha256);
            if let Some(prior) = shared_builds.insert(key, value.clone()) {
                if prior != value {
                    return Err("P17 B02 同 profile/target 重複建置證據不一致".into());
                }
            }
        }
    }
    let rows = array(internal, "rows")?;
    if rows.len() != items.len() {
        return Err("P17 B02 mapping row 數不符".into());
    }
    for (observed, item) in rows.iter().zip(&items) {
        validate_row(observed, item, &expected_bindings)?;
    }
    let checks = array(&value, "checks")?;
    if checks.len() != FAMILIES.len() {
        return Err("P17 B02 case check 數不符".into());
    }
    for (check, family) in checks.iter().zip(FAMILIES) {
        object(
            check,
            &[
                "case_id",
                "facet",
                "operation",
                "execution_path",
                "profile",
                "command",
                "cwd",
                "exit_code",
                "matched",
                "passed",
                "failed",
                "ignored",
                "status",
                "log_path",
                "log_sha256",
                "inputs",
                "environment",
                "negative_runs",
                "diagnostic",
            ],
        )?;
        let first_index = expected_bindings
            .iter()
            .position(|(case, _, _)| case.case_id == family)
            .ok_or("P17 B02 family 結果缺失")?;
        let expected_matched = expected_bindings
            .iter()
            .enumerate()
            .filter(|(_, (case, _, _))| case.case_id == family)
            .map(|(index, _)| run_counts[index].0)
            .sum::<u32>();
        if string(check, "case_id")? != "COMPLETE-005"
            || string(check, "facet")? != "internal-mapping"
            || string(check, "operation")? != "b02-case"
            || string(check, "execution_path")?
                != if family == "native-modules" {
                    "b01-evidence"
                } else {
                    "capi-public"
                }
            || string(check, "status")? != "PASS"
            || string(check, "diagnostic")? != family
            || field(check, "profile")? != &StrictJsonValue::Null
            || string_list(check, "command")?
                != string_list(&observed_runs[first_index], "command")?
            || string(check, "cwd")? != string(&observed_runs[first_index], "cwd")?
            || field(check, "exit_code")?.as_i32() != Some(0)
            || !array(check, "inputs")?.is_empty()
            || !array(check, "environment")?.is_empty()
            || !array(check, "negative_runs")?.is_empty()
            || number(check, "matched")? != expected_matched
            || number(check, "passed")? != expected_matched
            || number(check, "failed")? != 0
            || number(check, "ignored")? != 0
            || string(check, "log_path")? != run_counts[first_index].1.path
            || string(check, "log_sha256")? != run_counts[first_index].1.sha256
        {
            return Err(format!("P17 B02 case check 無效：{family}"));
        }
    }
    Ok(())
}

fn validate_row(
    value: &StrictJsonValue,
    item: &MappingItem,
    runs: &[(&InternalCase, &str, Option<&CaseRun>)],
) -> Result<(), String> {
    object(
        value,
        &[
            "id",
            "original",
            "reason",
            "rust_invariant",
            "replacement",
            "run_indices",
        ],
    )?;
    let original = field(value, "original")?;
    object(
        original,
        &[
            "profile",
            "symbol",
            "c_function",
            "c_source",
            "c_source_sha256",
            "lua_references",
        ],
    )?;
    let replacement = field(value, "replacement")?;
    object(replacement, &["case_id", "public_gap"])?;
    if string(value, "id")? != item.id
        || string(original, "profile")? != item.profile
        || string(original, "symbol")? != item.symbol
        || string(original, "c_function")? != item.c_function
        || string(original, "c_source")? != item.c_source
        || string(original, "c_source_sha256")? != item.c_source_sha256
        || string(value, "reason")? != item.reason
        || string(value, "rust_invariant")? != item.rust_invariant
        || string(replacement, "case_id")? != item.case_id
        || string(replacement, "public_gap")? != item.public_gap
    {
        return Err(format!("P17 B02 mapping 四欄內容不符：{}", item.id));
    }
    let references = array(original, "lua_references")?;
    if references.len() != item.lua_references.len() {
        return Err(format!("P17 B02 Lua refs 數不符：{}", item.id));
    }
    for (reference, expected) in references.iter().zip(&item.lua_references) {
        object(reference, &["path", "line", "source_sha256"])?;
        if string(reference, "path")? != expected.path
            || number(reference, "line")? as usize != expected.line
            || string(reference, "source_sha256")? != expected.source_sha256
        {
            return Err(format!("P17 B02 Lua ref 不符：{}", item.id));
        }
    }
    let observed = array(value, "run_indices")?
        .iter()
        .map(|part| match part {
            StrictJsonValue::Number(text) => text
                .parse::<usize>()
                .map_err(|_| "P17 B02 run index 無效".into()),
            _ => Err("P17 B02 run index 非數字".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expected = runs
        .iter()
        .enumerate()
        .filter_map(|(index, (case, profile, _))| {
            (case.case_id == item.case_id && *profile == item.profile).then_some(index)
        })
        .collect::<Vec<_>>();
    if observed != expected || observed.is_empty() {
        return Err(format!("P17 B02 mapping 替代結果未對應：{}", item.id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bind, parse_cases, parse_mapping, parse_test_counts, parse_test_log};
    use std::path::Path;

    #[test]
    fn p17_phase_b02_archive_executable_requires_explicit_view() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let original = root.join("xtask/p17-missing-executable-for-parser-test");
        let snapshot = root.join("xtask/src/p17/b02.rs");
        assert!(!original.exists());
        let digest = super::manifest::sha256(&snapshot).unwrap();
        let entry = |hash: &str| {
            super::StrictJsonParser::parse(&format!(
                "{{\"path\":{},\"sha256\":{}}}",
                super::report::q(&original.display().to_string()),
                super::report::q(hash),
            ))
            .unwrap()
        };
        let mut view = super::report::PhaseSourceView::new();
        view.insert(
            original.display().to_string(),
            super::report::HistoricalSource {
                before_sha256: digest.clone(),
                snapshot,
            },
        );
        assert!(super::historical_executable_input(&entry(&digest), None).is_err());
        assert_eq!(
            super::historical_executable_input(&entry(&digest), Some(&view))
                .unwrap()
                .sha256,
            digest,
        );
        assert!(super::historical_executable_input(&entry(&"0".repeat(64)), Some(&view)).is_err());
        let extra = super::StrictJsonParser::parse(&format!(
            "{{\"path\":{},\"sha256\":{},\"pass\":true}}",
            super::report::q(&original.display().to_string()),
            super::report::q(&digest),
        ))
        .unwrap();
        assert!(super::historical_executable_input(&extra, Some(&view)).is_err());
    }

    #[test]
    fn p17_b02_parser_rejects_empty_and_old_family() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert!(parse_mapping(
            root,
            r#"{"schema":"rivetlua-internal-mapping-v1","items":[]}"#
        )
        .is_err());
        assert!(parse_mapping(
            root,
            r#"{"schema":"rivetlua-internal-mapping-v1","items":[],"pass":true}"#
        )
        .is_err());
        assert!(parse_cases(r#"{"schema":"rivetlua-internal-cases-v1","cases":[]}"#).is_err());
        let old = r#"{"schema":"rivetlua-internal-cases-v1","cases":[{"case_id":"function-params","profiles":["lua55-i64f64"],"runs":[{"crate":"rivetlua-capi","target":"p17_internal_replacements","selector":"p17_internal_function_params","expected_matched":1}],"evidence":null}]}"#;
        assert!(parse_cases(old).is_err());
    }

    #[test]
    fn p17_b02_parser_binds_all_fixed_private_sources_and_rejects_mutations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mapping =
            std::fs::read_to_string(root.join("tests/p17/internal/mapping.json")).unwrap();
        let cases = std::fs::read_to_string(root.join("tests/p17/internal/cases.json")).unwrap();
        let items = parse_mapping(root, &mapping).unwrap();
        let parsed_cases = parse_cases(&cases).unwrap();
        bind(&items, &parsed_cases).unwrap();
        assert_eq!(items.len(), 49);
        assert_eq!(
            items
                .iter()
                .map(|item| item.lua_references.len())
                .sum::<usize>(),
            270
        );
        let wrong_symbol = mapping.replacen(
            "\"symbol\": \"T.checkmemory\"",
            "\"symbol\": \"T.missing\"",
            1,
        );
        assert_ne!(wrong_symbol, mapping);
        assert!(parse_mapping(root, &wrong_symbol).is_err());
        let missing_line = mapping.replacen("\"line\": 120", "\"line\": 0", 1);
        assert_ne!(missing_line, mapping);
        assert!(parse_mapping(root, &missing_line).is_err());
        let wrong_selector = cases.replacen(
            "p17_internal_allocation_ledger",
            "p17_internal_unrelated",
            1,
        );
        assert_ne!(wrong_selector, cases);
        assert!(parse_cases(&wrong_selector).is_err());
        let zero = cases.replacen("\"expected_matched\": 1", "\"expected_matched\": 0", 1);
        assert_ne!(zero, cases);
        assert!(parse_cases(&zero).is_err());
    }

    #[test]
    fn p17_b02_test_log_requires_named_nonzero_execution() {
        let selector = "p17_internal_gc_roots";
        assert!(parse_test_log("P17_B02_PASS\n", selector, 1, 0).is_err());
        assert!(parse_test_log("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n",selector,1,0).is_err());
        assert!(parse_test_log("test unrelated ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n",selector,1,0).is_err());
        assert!(parse_test_log("test p17_internal_gc_roots ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n",selector,1,0).is_ok());
        let failed = "test p17_internal_gc_roots ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out\n";
        assert_eq!(parse_test_counts(failed, selector).unwrap(), (1, 0, 1, 0));
        assert!(parse_test_log(failed, selector, 1, 101).is_err());
        let ignored = "test p17_internal_gc_roots ... ignored, reason\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 10 filtered out\n";
        assert_eq!(parse_test_counts(ignored, selector).unwrap(), (1, 0, 0, 1));
        assert!(parse_test_log(ignored, selector, 1, 0).is_err());
        let zero = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n";
        assert_eq!(parse_test_counts(zero, selector).unwrap(), (0, 0, 0, 0));
        assert!(parse_test_log(zero, selector, 1, 0).is_err());
    }

    #[test]
    #[ignore = "僅於 B01 有效證據凍結後的 B02 來源影響定點回歸執行"]
    fn p17_b02_reuse_validates_prior_logs_without_rerunning_gate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let prior = root.join("target/rivetlua-reports/gate-P17-B01.json");
        assert!(super::report::validate_b01(root, &prior).is_err());
        let impacts = super::report::validate_b01_for_b02(root, &prior).unwrap();
        assert_eq!(impacts.len(), 2);
        assert!(impacts
            .iter()
            .all(|impact| impact.path.ends_with("/mod.rs") || impact.path.ends_with("/report.rs")));
    }
}
