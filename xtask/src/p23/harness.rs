//! P23 共同 fuzz selector 與有界重播；各語言入口由獨立 lane 實作。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use rivetlua_core::LuaProfile;

use super::{capi_sequence, codec, language, manifest::ExperimentManifest, sdk};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HarnessLimits {
    pub max_input_bytes: usize,
    pub max_depth: usize,
    pub fuel: u64,
    pub heap_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaseOutcome {
    Accepted,
    Rejected,
    Limit,
    Finding(&'static str),
    Blocked(&'static str),
}

#[derive(Debug)]
pub(super) struct FuzzSummary {
    pub status: &'static str,
    pub code: Option<&'static str>,
    pub cases: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub limited: u64,
    pub minimized_sha256: Option<String>,
    pub minimized_len: Option<usize>,
}

impl FuzzSummary {
    pub fn blocked(code: &'static str) -> Self {
        Self {
            status: "BLOCKED",
            code: Some(code),
            cases: 0,
            accepted: 0,
            rejected: 0,
            limited: 0,
            minimized_sha256: None,
            minimized_len: None,
        }
    }

    pub fn panic(cases: u64) -> Self {
        Self {
            status: "FINDING",
            code: Some("E_FUZZ_PANIC"),
            cases,
            accepted: 0,
            rejected: 0,
            limited: 0,
            minimized_sha256: None,
            minimized_len: None,
        }
    }
}

pub(super) fn run_case(
    id: &str,
    profile: LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    if input.len() > limits.max_input_bytes
        || limits.max_input_bytes == 0
        || limits.max_depth == 0
        || limits.fuel == 0
        || limits.heap_bytes == 0
    {
        return CaseOutcome::Limit;
    }
    match id {
        "FZ-001" => language::source(profile, input, limits),
        "FZ-002" => language::ast(profile, input, limits),
        "FZ-003" => codec::rvlu_bytecode(profile, input, limits),
        "FZ-004" => codec::rvlu_header(profile, input, limits),
        "FZ-005" => {
            #[cfg(test)]
            if input == b"\0P23-FZ005-PANIC-CONTROL\0" {
                // 測試專用負控制；略過 panic hook，避免輸出 payload。
                std::panic::resume_unwind(Box::new(()));
            }
            sdk::sdk_values(profile, input, limits)
        }
        "FZ-006" => capi_sequence::capi_sequence(profile, input, limits),
        "FZ-CHUNK-001" => codec::official_chunk(profile, input, limits),
        _ => CaseOutcome::Blocked("E_FUZZ_UNKNOWN_TARGET"),
    }
}

pub(super) fn fuzz(manifest: &ExperimentManifest, input: &[u8]) -> Result<FuzzSummary, String> {
    manifest.validate()?;
    let limits = HarnessLimits {
        max_input_bytes: manifest
            .budget
            .max_input_bytes
            .try_into()
            .map_err(|_| "E_FUZZ_BUDGET")?,
        max_depth: manifest
            .budget
            .max_depth
            .try_into()
            .map_err(|_| "E_FUZZ_BUDGET")?,
        fuel: manifest.budget.fuel,
        heap_bytes: manifest
            .budget
            .heap_bytes
            .try_into()
            .map_err(|_| "E_FUZZ_BUDGET")?,
    };
    if input.len() > limits.max_input_bytes || limits.max_input_bytes > limits.heap_bytes / 4 {
        return Err("E_FUZZ_BUDGET".into());
    }
    let profile = match manifest.profile.as_str() {
        "lua55-i64f64" => LuaProfile::Lua55,
        "lua54-i64f64" => LuaProfile::Lua54,
        _ => return Err("E_FUZZ_PROFILE".into()),
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(manifest.budget.seconds))
        .ok_or("E_FUZZ_BUDGET")?;
    let mut rng = manifest.seed;
    let mut summary = FuzzSummary {
        status: "NO_FINDING",
        code: None,
        cases: 0,
        accepted: 0,
        rejected: 0,
        limited: 0,
        minimized_sha256: None,
        minimized_len: None,
    };
    while summary.cases < manifest.budget.cases {
        // shortcut: deadline 在每次呼叫前後檢查；無法中斷單次卡住的 in-process lane。
        if Instant::now() >= deadline {
            summary.status = "LIMIT";
            break;
        }
        let candidate = if summary.cases == 0 {
            input.to_vec()
        } else {
            mutate(input, limits.max_input_bytes, &mut rng)
        };
        let outcome = run_caught(&manifest.target_id, profile, &candidate, &limits);
        summary.cases += 1;
        if Instant::now() >= deadline
            && !matches!(outcome, CaseOutcome::Finding(_) | CaseOutcome::Blocked(_))
        {
            summary.status = "LIMIT";
            break;
        }
        match outcome {
            CaseOutcome::Accepted => summary.accepted += 1,
            CaseOutcome::Rejected => summary.rejected += 1,
            CaseOutcome::Limit => summary.limited += 1,
            CaseOutcome::Blocked(code) => {
                summary.status = "BLOCKED";
                summary.code = Some(public_code(code));
                break;
            }
            CaseOutcome::Finding(raw_code) => {
                summary.status = "FINDING";
                summary.code = Some(public_code(raw_code));
                let minimized = minimize(
                    manifest,
                    profile,
                    &limits,
                    deadline,
                    &candidate,
                    raw_code,
                    &mut summary,
                );
                summary.minimized_sha256 = Some(
                    crate::p17::package_sha256_bytes(&minimized)
                        .map_err(|_| "E_FUZZ_DIGEST".to_owned())?,
                );
                summary.minimized_len = Some(minimized.len());
                break;
            }
        }
    }
    Ok(summary)
}

fn run_caught(id: &str, profile: LuaProfile, input: &[u8], limits: &HarnessLimits) -> CaseOutcome {
    catch_unwind(AssertUnwindSafe(|| run_case(id, profile, input, limits)))
        .unwrap_or(CaseOutcome::Finding("E_FUZZ_PANIC"))
}

fn minimize(
    manifest: &ExperimentManifest,
    profile: LuaProfile,
    limits: &HarnessLimits,
    deadline: Instant,
    original: &[u8],
    code: &'static str,
    summary: &mut FuzzSummary,
) -> Vec<u8> {
    let mut current = original.to_vec();
    let mut parts = 2usize;
    while !current.is_empty() && summary.cases < manifest.budget.cases && Instant::now() < deadline
    {
        let chunk = current.len().div_ceil(parts);
        let mut changed = false;
        let mut start = 0;
        while start < current.len()
            && summary.cases < manifest.budget.cases
            && Instant::now() < deadline
        {
            let end = (start + chunk).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - start));
            candidate.extend_from_slice(&current[..start]);
            candidate.extend_from_slice(&current[end..]);
            let outcome = run_caught(&manifest.target_id, profile, &candidate, limits);
            summary.cases += 1;
            if Instant::now() >= deadline {
                break;
            }
            if outcome == CaseOutcome::Finding(code) {
                current = candidate;
                parts = 2;
                changed = true;
                break;
            }
            start = end;
        }
        if !changed {
            if parts >= current.len() {
                break;
            }
            parts = (parts * 2).min(current.len());
        }
    }
    current
}

fn mutate(original: &[u8], max: usize, rng: &mut u64) -> Vec<u8> {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let choice = *rng as usize;
    let mut candidate = original.to_vec();
    if candidate.is_empty() {
        candidate.push(choice as u8);
    } else {
        let index = choice % candidate.len();
        match choice % 3 {
            0 => candidate[index] ^= 1 << ((choice >> 8) % 8),
            1 if candidate.len() > 1 => {
                candidate.remove(index);
            }
            _ if candidate.len() < max => {
                candidate.insert(index, (choice >> 8) as u8);
            }
            _ => candidate[index] ^= 1,
        }
    }
    candidate
}

fn public_code(code: &'static str) -> &'static str {
    if code.len() <= 64
        && code.starts_with("E_")
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        code
    } else {
        "E_FUZZ_FINDING"
    }
}

#[cfg(test)]
mod tests {
    use super::{CaseOutcome, HarnessLimits, run_caught};
    use rivetlua_core::LuaProfile;

    #[test]
    fn fz005_panic_negative_control() {
        let input = b"\0P23-FZ005-PANIC-CONTROL\0";
        let limits = HarnessLimits {
            max_input_bytes: input.len(),
            max_depth: 1,
            fuel: 32,
            heap_bytes: 16 * 1024,
        };
        assert_eq!(
            run_caught("FZ-005", LuaProfile::Lua55, input, &limits),
            CaseOutcome::Finding("E_FUZZ_PANIC")
        );
    }
}
