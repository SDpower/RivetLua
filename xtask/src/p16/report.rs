use super::manifest::{Manifest, Row};
use super::matrix::Case;
use super::selection::Applicability;
use super::{q, sha_file};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const SCHEMA: &str = "rivetlua-p16-acceptance-v1";
pub(super) const GATE_SCHEMA: &str = "rivetlua-p16-gate-v1";

pub(super) fn path(root: &Path, profile: &str, target: &str) -> PathBuf {
    root.join("target/rivetlua-reports")
        .join(format!("P16-acceptance-{profile}-{target}.json"))
}

pub(super) fn gate_path(root: &Path) -> PathBuf {
    root.join("target/rivetlua-reports/gate-P16.json")
}

pub(super) fn write(path: &Path, contents: &str) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("P16 report 無父目錄")?)
        .map_err(|error| format!("建立 P16 report 目錄失敗：{error}"))?;
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&temporary, contents).map_err(|error| format!("寫入 P16 report 失敗：{error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("提交 P16 report 失敗：{error}"))
}

pub(super) fn early_failure(
    root: &Path,
    profile: &str,
    target: &str,
    diagnostic: &str,
) -> Result<(), String> {
    let path = path(root, profile, target);
    write(
        &path,
        &format!(
            "{{\"schema\":{},\"status\":\"FAIL\",\"profile\":{},\"target\":{},\"source_digest\":null,\"matrix_sha256\":null,\"manifest_sha256\":null,\"header_set_sha256\":null,\"diagnostic\":{},\"cases\":[],\"rows\":[],\"report_path\":{}}}\n",
            q(SCHEMA),
            q(profile),
            q(target),
            q(diagnostic),
            q(&path.display().to_string())
        ),
    )
}

pub(super) fn not_run(
    root: &Path,
    profile: &str,
    target: &str,
    digest: &str,
    cases: &[Case],
    manifest: &Manifest,
) -> Result<(), String> {
    let short = profile
        .strip_suffix("-i64f64")
        .ok_or("P16 profile numeric 無效")?;
    let cases = cases
        .iter()
        .map(|case| case_not_run(case, profile, target))
        .collect::<Vec<_>>();
    let rows = manifest
        .rows
        .iter()
        .filter(|row| row.profile == short)
        .map(row_not_run)
        .collect::<Vec<_>>();
    partial(
        root,
        profile,
        target,
        digest,
        manifest,
        &cases,
        &rows,
        "P16-4/5 與正式 C ABI 證據尚未完成",
    )
}

pub(super) fn case_not_run(case: &Case, profile: &str, target: &str) -> String {
    format!(
        "{{\"id\":{},\"profile\":{},\"target\":{},\"execution_kind\":{},\"status\":\"NOT_RUN\",\"fixture\":{},\"assertions\":[{}],\"build_command\":[],\"build_exit_code\":null,\"build_signal\":null,\"command\":[],\"environment\":[],\"cwd\":null,\"exit_code\":null,\"signal\":null,\"matched\":0,\"passed\":0,\"failed\":0,\"ignored\":0,\"source_path\":null,\"source_sha256\":null,\"header_path\":null,\"header_sha256\":null,\"header_set_sha256\":null,\"library_path\":null,\"library_sha256\":null,\"binary_path\":null,\"binary_sha256\":null,\"build_log_path\":null,\"build_log_sha256\":null,\"log_path\":null,\"log_sha256\":null,\"local_tests\":[],\"local_failure\":null,\"worker\":null,\"artifact_record_path\":null,\"artifact_record_sha256\":null,\"modules\":[],\"package_artifacts\":[],\"diagnostic\":\"尚未執行正式 staticlib/module 驗收\"}}",
        q(&case.id),
        q(profile),
        q(target),
        q(case.execution_kind.as_str()),
        q(&case.fixture),
        case.assertions
            .iter()
            .map(|value| q(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(super) fn row_not_run(row: &Row) -> String {
    row_with_proofs(row, "NOT_RUN", &[], "尚未執行固定逐列 proof")
}

pub(super) fn row_with_proofs(
    row: &Row,
    status: &str,
    required: &[String],
    reason: &str,
) -> String {
    row_with_observation(row, status, required, reason, None)
}

pub(super) fn row_with_observation(
    row: &Row,
    status: &str,
    required: &[String],
    reason: &str,
    applicability: Option<&Applicability>,
) -> String {
    let count = if status == "PASS" { required.len() } else { 0 };
    let mode = if row.status == "IMPLEMENTED"
        && required
            .iter()
            .any(|id| id.starts_with("rust-cross-contract:"))
    {
        "c-abi-effect-with-rust-cross-contract"
    } else if row.kind == "layout_field" && status == "PASS" {
        "header-layout-effect"
    } else {
        match applicability {
            Some(Applicability::Excluded(_)) | Some(Applicability::Undefined) => {
                "header-guard-exclusion"
            }
            Some(Applicability::Selected(_))
                if row.kind == "macro"
                    && row
                        .definition
                        .starts_with(&format!("#define {}(", row.name)) =>
            {
                "macro-expansion-effect"
            }
            Some(Applicability::Selected(_)) if super::rowproof::needs_value(row) => {
                "header-value-effect"
            }
            Some(Applicability::Selected(_)) if row.kind == "macro" => {
                "header-selected-declaration"
            }
            _ => super::evidence_mode(&row.kind, &row.status),
        }
    };
    let active = applicability.and_then(Applicability::active);
    let effect_count = usize::from(
        status == "PASS"
            && (row.kind == "layout_field"
                || (matches!(applicability, Some(Applicability::Selected(_)))
                    && (super::rowproof::needs_value(row)
                        || (row.kind == "macro"
                            && row
                                .definition
                                .starts_with(&format!("#define {}(", row.name)))))),
    );
    format!(
        "{{\"id\":{},\"status\":{},\"evidence_mode\":{},\"applicability\":{},\"active_header\":{},\"active_line\":{},\"active_definition\":{},\"manifest_guard\":{},\"effect_matched\":{},\"effect_passed\":{},\"required_proofs\":[{}],\"case_id\":null,\"command\":[],\"cwd\":null,\"exit_code\":null,\"matched\":{},\"passed\":{},\"failed\":0,\"ignored\":0,\"log_path\":null,\"log_sha256\":null,\"unmapped_reason\":{},\"manifest_evidence\":{},\"manifest_mapping\":{},\"manifest_p17_use\":{}}}",
        q(&row.id),
        q(status),
        q(mode),
        q(applicability
            .map(Applicability::as_str)
            .unwrap_or("unobserved")),
        active
            .map(|value| q(&value.header))
            .unwrap_or_else(|| "null".into()),
        active
            .map(|value| value.line.to_string())
            .unwrap_or_else(|| "null".into()),
        active
            .map(|value| q(&value.text))
            .unwrap_or_else(|| "null".into()),
        q(&row.condition),
        effect_count,
        effect_count,
        required
            .iter()
            .map(|key| q(key))
            .collect::<Vec<_>>()
            .join(","),
        count,
        count,
        q(reason),
        q(&row.evidence),
        q(&row.mapping),
        q(&row.p17_use)
    )
}

pub(super) fn partial(
    root: &Path,
    profile: &str,
    target: &str,
    digest: &str,
    manifest: &Manifest,
    cases: &[String],
    rows: &[String],
    diagnostic: &str,
) -> Result<(), String> {
    partial_with_proofs(
        root,
        profile,
        target,
        digest,
        manifest,
        cases,
        rows,
        &[],
        &[],
        diagnostic,
        false,
    )
}

pub(super) fn partial_with_proofs(
    root: &Path,
    profile: &str,
    target: &str,
    digest: &str,
    manifest: &Manifest,
    cases: &[String],
    rows: &[String],
    proofs: &[String],
    unmapped: &[String],
    diagnostic: &str,
    complete: bool,
) -> Result<(), String> {
    let short = profile
        .strip_suffix("-i64f64")
        .ok_or("P16 profile numeric 無效")?;
    let header_set = manifest
        .header_sets
        .get(short)
        .ok_or("P16 profile header set 缺失")?;
    let matrix_sha = sha_file(&root.join("tests/p16/acceptance-cases.toml"))?;
    let manifest_sha = sha_file(&root.join("tests/p16/abi-manifest.toml"))?;
    let path = path(root, profile, target);
    let value = format!(
        "{{\"schema\":{},\"status\":{},\"profile\":{},\"target\":{},\"source_digest\":{},\"matrix_sha256\":{},\"manifest_sha256\":{},\"header_set_sha256\":{},\"diagnostic\":{},\"cases\":[{}],\"proofs\":[{}],\"rows\":[{}],\"unmapped\":[{}],\"report_path\":{}}}\n",
        q(SCHEMA),
        q(if complete { "PASS" } else { "FAIL" }),
        q(profile),
        q(target),
        q(digest),
        q(&matrix_sha),
        q(&manifest_sha),
        q(header_set),
        q(diagnostic),
        cases.join(","),
        proofs.join(","),
        rows.join(","),
        unmapped.join(","),
        q(&path.display().to_string())
    );
    write(&path, &value)
}

pub(super) fn gate_result(
    root: &Path,
    digest: Option<&str>,
    status: &str,
    diagnostic: &str,
    checks: &str,
) -> Result<(), String> {
    let path = gate_path(root);
    let value = format!(
        "{{\"schema\":{},\"status\":{},\"scope\":\"c-api-abi-native\",\"source_digest\":{},\"diagnostic\":{},\"checks\":[{checks}],\"report_path\":{}}}\n",
        q(GATE_SCHEMA),
        q(status),
        digest.map(q).unwrap_or_else(|| "null".into()),
        q(diagnostic),
        q(&path.display().to_string())
    );
    write(&path, &value)
}
