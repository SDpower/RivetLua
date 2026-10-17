//! P23 實驗身分：只解析公開中繼資料，不讀取或執行實驗輸入。

use std::collections::BTreeSet;

use crate::{StrictJsonParser, StrictJsonValue};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const TOP_KEYS: [&str; 24] = [
    "version",
    "phase",
    "batch",
    "experiment_id",
    "commit",
    "dirty",
    "crate",
    "features",
    "profile",
    "numeric",
    "target",
    "cpu",
    "os",
    "toolchain",
    "tools",
    "target_id",
    "seed",
    "corpus_sha256",
    "scenario_sha256",
    "input_sha256",
    "budget",
    "fault_plan",
    "worker_policy",
    "started_at",
];
const BUDGET_KEYS: [&str; 6] = [
    "max_input_bytes",
    "max_depth",
    "fuel",
    "heap_bytes",
    "cases",
    "seconds",
];
const TOOL_KEYS: [&str; 5] = ["name", "version", "scope", "status", "alternative"];
const FAULT_KEYS: [&str; 3] = ["point_id", "occurrence", "action"];
const RELEASE_SEED_STEP: u64 = 1_000_000;
pub(super) const MAX_RELEASE_SEEDS: usize = 3600;

pub(super) fn release_seed(primary: u64, index: usize) -> Option<u64> {
    (index < MAX_RELEASE_SEEDS)
        .then_some(index)
        .and_then(|index| u64::try_from(index).ok())
        .and_then(|index| index.checked_mul(RELEASE_SEED_STEP))
        .and_then(|offset| primary.checked_add(offset))
}

fn seed_in_family(primary: u64, actual: u64) -> bool {
    actual.checked_sub(primary).is_some_and(|offset| {
        offset % RELEASE_SEED_STEP == 0 && offset / RELEASE_SEED_STEP < MAX_RELEASE_SEEDS as u64
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub max_input_bytes: u64,
    pub max_depth: u64,
    pub fuel: u64,
    pub heap_bytes: u64,
    pub cases: u64,
    pub seconds: u64,
}

impl Budget {
    fn parse(value: &StrictJsonValue) -> Result<Self, String> {
        exact_object(value, &BUDGET_KEYS)?;
        Ok(Self {
            max_input_bytes: integer(value, "max_input_bytes")?,
            max_depth: integer(value, "max_depth")?,
            fuel: integer(value, "fuel")?,
            heap_bytes: integer(value, "heap_bytes")?,
            cases: integer(value, "cases")?,
            seconds: integer(value, "seconds")?,
        })
    }

    fn validate(&self) -> Result<(), String> {
        for (value, maximum) in [
            (self.max_input_bytes, 16 * 1024 * 1024),
            (self.max_depth, 128),
            (self.fuel, 100_000_000),
            (self.heap_bytes, 1024 * 1024 * 1024),
            (self.cases, 1_000_000),
            (self.seconds, 3600),
        ] {
            if value == 0 || value > maximum {
                return Err("E_MANIFEST_BUDGET".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    pub point_id: String,
    pub occurrence: u64,
    pub action: String,
}

impl FaultPlan {
    fn parse(value: &StrictJsonValue) -> Result<Self, String> {
        exact_object(value, &FAULT_KEYS)?;
        Ok(Self {
            point_id: string(value, "point_id")?,
            occurrence: integer(value, "occurrence")?,
            action: string(value, "action")?,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if !public_id(&self.point_id, 64)
            || !public_id(&self.action, 32)
            || self.occurrence == 0
            || self.occurrence > 1_000_000
        {
            return Err("E_MANIFEST_FAULT".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolStatus {
    NotRun,
    Blocked,
    NotApplicable,
    Pass,
    Fail,
}

impl ToolStatus {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "NOT_RUN" => Ok(Self::NotRun),
            "BLOCKED" => Ok(Self::Blocked),
            "NOT_APPLICABLE" => Ok(Self::NotApplicable),
            "PASS" => Ok(Self::Pass),
            "FAIL" => Ok(Self::Fail),
            _ => Err("E_MANIFEST_TOOL".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolScope {
    pub name: String,
    pub version: String,
    pub scope: String,
    pub status: ToolStatus,
    pub alternative: Option<String>,
}

impl ToolScope {
    fn parse(value: &StrictJsonValue) -> Result<Self, String> {
        exact_object(value, &TOOL_KEYS)?;
        let alternative = match field(value, "alternative")? {
            StrictJsonValue::Null => None,
            StrictJsonValue::String(value) => Some(value.clone()),
            _ => return Err("E_MANIFEST_TOOL".into()),
        };
        Ok(Self {
            name: string(value, "name")?,
            version: string(value, "version")?,
            scope: string(value, "scope")?,
            status: ToolStatus::parse(field(value, "status")?.as_str().ok_or("E_MANIFEST_TOOL")?)?,
            alternative,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if !public_id(&self.name, 64)
            || !public_metadata(&self.version, 64)
            || !public_id(&self.scope, 64)
            || self
                .alternative
                .as_ref()
                .is_some_and(|value| !public_id(value, 64))
            || (self.status == ToolStatus::Pass && self.alternative.is_some())
            || (self.status == ToolStatus::Pass && !supports_pass(&self.name, &self.scope))
        {
            return Err("E_MANIFEST_TOOL".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentManifest {
    pub version: u32,
    pub phase: String,
    pub batch: String,
    pub experiment_id: String,
    pub commit: String,
    pub dirty: bool,
    pub crate_name: String,
    pub features: Vec<String>,
    pub profile: String,
    pub numeric: String,
    pub target: String,
    pub cpu: String,
    pub os: String,
    pub toolchain: String,
    pub tools: Vec<ToolScope>,
    pub target_id: String,
    pub seed: u64,
    pub corpus_sha256: String,
    pub scenario_sha256: String,
    pub input_sha256: String,
    pub budget: Budget,
    pub fault_plan: Option<FaultPlan>,
    pub worker_policy: String,
    pub started_at: String,
}

impl ExperimentManifest {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > MAX_MANIFEST_BYTES {
            return Err("E_MANIFEST_SIZE".into());
        }
        let value = StrictJsonParser::parse(input).map_err(|_| "E_MANIFEST_JSON".to_owned())?;
        exact_object(&value, &TOP_KEYS)?;
        let features = field(&value, "features")?
            .as_array()
            .ok_or("E_MANIFEST_SCHEMA")?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("E_MANIFEST_SCHEMA".into())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tools = field(&value, "tools")?
            .as_array()
            .ok_or("E_MANIFEST_SCHEMA")?
            .iter()
            .map(ToolScope::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let fault_plan = match field(&value, "fault_plan")? {
            StrictJsonValue::Null => None,
            other => Some(FaultPlan::parse(other)?),
        };
        let version = integer(&value, "version")?
            .try_into()
            .map_err(|_| "E_MANIFEST_VERSION".to_owned())?;
        let manifest = Self {
            version,
            phase: string(&value, "phase")?,
            batch: string(&value, "batch")?,
            experiment_id: string(&value, "experiment_id")?,
            commit: string(&value, "commit")?,
            dirty: match field(&value, "dirty")? {
                StrictJsonValue::Bool(value) => *value,
                _ => return Err("E_MANIFEST_SCHEMA".into()),
            },
            crate_name: string(&value, "crate")?,
            features,
            profile: string(&value, "profile")?,
            numeric: string(&value, "numeric")?,
            target: string(&value, "target")?,
            cpu: string(&value, "cpu")?,
            os: string(&value, "os")?,
            toolchain: string(&value, "toolchain")?,
            tools,
            target_id: string(&value, "target_id")?,
            seed: integer(&value, "seed")?,
            corpus_sha256: string(&value, "corpus_sha256")?,
            scenario_sha256: string(&value, "scenario_sha256")?,
            input_sha256: string(&value, "input_sha256")?,
            budget: Budget::parse(field(&value, "budget")?)?,
            fault_plan,
            worker_policy: string(&value, "worker_policy")?,
            started_at: string(&value, "started_at")?,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.phase != "P23" {
            return Err("E_MANIFEST_VERSION".into());
        }
        if !matches!(
            self.batch.as_str(),
            "P23-B01" | "P23-B02" | "P23-B03" | "P23-B04"
        ) || !public_id(&self.experiment_id, 96)
            || !hex(&self.commit, 40)
            || !public_id(&self.crate_name, 64)
            || !matches!(self.profile.as_str(), "lua55-i64f64" | "lua54-i64f64")
            || self.numeric != "i64f64"
            || !public_metadata(&self.cpu, 128)
            || !public_metadata(&self.toolchain, 128)
            || !matches!(
                self.worker_policy.as_str(),
                "Compatibility" | "Sandbox" | "PrivateService"
            )
            || !utc_timestamp(&self.started_at)
        {
            return Err("E_MANIFEST_IDENTITY".into());
        }
        if target_os(&self.target) != Some(self.os.as_str()) {
            return Err("E_MANIFEST_TARGET".into());
        }
        if select_target(&self.target_id)
            .is_none_or(|target| !seed_in_family(target.seed, self.seed))
        {
            return Err("E_MANIFEST_SELECTOR".into());
        }
        if !hex(&self.corpus_sha256, 64)
            || !hex(&self.scenario_sha256, 64)
            || !hex(&self.input_sha256, 64)
        {
            return Err("E_MANIFEST_DIGEST".into());
        }
        if self.features.len() > 32 || self.tools.len() > 32 {
            return Err("E_MANIFEST_SIZE".into());
        }
        let mut feature_names = BTreeSet::new();
        for feature in &self.features {
            if !public_id(feature, 64) || !feature_names.insert(feature) {
                return Err("E_MANIFEST_FEATURE".into());
            }
        }
        let mut tool_keys = BTreeSet::new();
        for tool in &self.tools {
            tool.validate()?;
            if !tool_keys.insert((&tool.name, &tool.scope)) {
                return Err("E_MANIFEST_TOOL".into());
            }
        }
        self.budget.validate()?;
        if let Some(plan) = &self.fault_plan {
            plan.validate()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn comparable_to(&self, other: &Self) -> bool {
        if self.validate().is_err() || other.validate().is_err() {
            return false;
        }
        let mut left = self.clone();
        let mut right = other.clone();
        for value in [&mut left, &mut right] {
            value.experiment_id.clear();
            value.started_at.clear();
            value.commit.make_ascii_lowercase();
            value.corpus_sha256.make_ascii_lowercase();
            value.scenario_sha256.make_ascii_lowercase();
            value.input_sha256.make_ascii_lowercase();
            value.features.sort();
            value
                .tools
                .sort_by(|a, b| (&a.name, &a.scope).cmp(&(&b.name, &b.scope)));
        }
        left == right
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuzzTarget {
    pub id: &'static str,
    pub seed: u64,
    pub input_kind: &'static str,
    pub oracle: &'static str,
}

static TARGETS: [FuzzTarget; 7] = [
    FuzzTarget {
        id: "FZ-001",
        seed: 23001,
        input_kind: "source",
        oracle: "parser",
    },
    FuzzTarget {
        id: "FZ-002",
        seed: 23002,
        input_kind: "ast",
        oracle: "compiler",
    },
    FuzzTarget {
        id: "FZ-003",
        seed: 23003,
        input_kind: "rvlu-bytecode",
        oracle: "p05-verifier",
    },
    FuzzTarget {
        id: "FZ-004",
        seed: 23004,
        input_kind: "rvlu-header",
        oracle: "p05-codec",
    },
    FuzzTarget {
        id: "FZ-005",
        seed: 23005,
        input_kind: "sdk-values",
        oracle: "sdk-conversion",
    },
    FuzzTarget {
        id: "FZ-006",
        seed: 23006,
        input_kind: "c-api-sequence",
        oracle: "c-api",
    },
    FuzzTarget {
        id: "FZ-CHUNK-001",
        seed: 23007,
        input_kind: "official-lua-chunk",
        oracle: "p05-verifier",
    },
];

pub fn target_registry() -> &'static [FuzzTarget; 7] {
    &TARGETS
}

pub fn select_target(id: &str) -> Option<&'static FuzzTarget> {
    TARGETS.iter().find(|target| target.id == id)
}

fn exact_object(value: &StrictJsonValue, expected: &[&str]) -> Result<(), String> {
    let StrictJsonValue::Object(entries) = value else {
        return Err("E_MANIFEST_SCHEMA".into());
    };
    if entries.len() != expected.len()
        || entries
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err("E_MANIFEST_SCHEMA".into());
    }
    Ok(())
}

fn field<'a>(value: &'a StrictJsonValue, name: &str) -> Result<&'a StrictJsonValue, String> {
    value.get(name).ok_or_else(|| "E_MANIFEST_SCHEMA".into())
}

fn string(value: &StrictJsonValue, name: &str) -> Result<String, String> {
    field(value, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "E_MANIFEST_SCHEMA".into())
}

fn integer(value: &StrictJsonValue, name: &str) -> Result<u64, String> {
    match field(value, name)? {
        StrictJsonValue::Number(value) if !value.contains(['.', 'e', 'E']) => {
            value.parse().map_err(|_| "E_MANIFEST_SCHEMA".into())
        }
        _ => Err("E_MANIFEST_SCHEMA".into()),
    }
}

fn public_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn public_metadata(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'-' | b'_' | b'.' | b'+' | b':' | b'(' | b')')
        })
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn target_os(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-apple-darwin" | "x86_64-apple-darwin" => Some("macos"),
        "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-gnu" => Some("linux"),
        "x86_64-pc-windows-msvc" => Some("windows"),
        "thumbv7em-none-eabi" | "riscv32-unknown-none-elf" => Some("none"),
        _ => None,
    }
}

fn supports_pass(name: &str, scope: &str) -> bool {
    // shortcut: 此處只驗工具與範圍的靜態相容性；B03 產生執行證據時再核對實際覆蓋。
    match name {
        "miri" => scope == "pure-rust",
        "asan" | "ubsan" => matches!(scope, "pure-rust" | "ffi" | "jit" | "native"),
        "tsan" => matches!(scope, "pure-rust" | "ffi" | "native"),
        "cargo-fuzz" | "libfuzzer" => matches!(
            scope,
            "source"
                | "ast"
                | "rvlu-bytecode"
                | "rvlu-header"
                | "sdk"
                | "c-api"
                | "official-lua-chunk"
        ),
        "native-jit" => matches!(scope, "jit" | "native"),
        "worker-os" => scope == "os-worker",
        "perf" => scope == "performance",
        _ => false,
    }
}

fn utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .any(|&index| !bytes[index].is_ascii_digit())
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> u32 { value[range].parse().unwrap_or(0) };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year > 0 && day > 0 && day <= days && hour < 24 && minute < 60 && second < 60
}
