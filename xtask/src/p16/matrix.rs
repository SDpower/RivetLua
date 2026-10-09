use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub(super) const IDS: [&str; 15] = [
    "ABI-001",
    "ABI-002",
    "ABI-003",
    "ABI-004",
    "ABI-005",
    "ABI-006",
    "ABI-007",
    "ABI-NEG-001",
    "ABI-NEG-002",
    "ABI-NEG-003",
    "ABI-NEG-004",
    "ABI-NEG-005",
    "ABI-NEG-006",
    "SDK-MODULE",
    "ABI-STRESS",
];
const STEPS: [&str; 15] = [
    "P16-3", "P16-3", "P16-3", "P16-5", "P16-5", "P16-4", "P16-5", "P16-3", "P16-3", "P16-2",
    "P16-5", "P16-4", "P16-5", "P16-1", "P16-5",
];
const KINDS: [ExecutionKind; 15] = [
    ExecutionKind::CDriver,
    ExecutionKind::CDriver,
    ExecutionKind::CDriver,
    ExecutionKind::CDriver,
    ExecutionKind::RustTest,
    ExecutionKind::RustTest,
    ExecutionKind::RustTest,
    ExecutionKind::CDriver,
    ExecutionKind::RustTest,
    ExecutionKind::RustTest,
    ExecutionKind::CDriver,
    ExecutionKind::RustTest,
    ExecutionKind::BuildAudit,
    ExecutionKind::SdkModules,
    ExecutionKind::CDriver,
];
const ASSERTIONS: [&str; 15] = [
    "stack,results,multret,roots",
    "nested_error,classification,frame_cleanup,rust_boundary",
    "gc,parameters,refs,userdata,root_ledger",
    "allocation_ordinals,structured_failure,no_fallback,cleanup",
    "header,layout,revision,target,profile,numeric,preload",
    "crash,timeout,malformed,private_vm,heap_cleanup",
    "policy,preload,no_constructor",
    "reject_rust_frame_longjmp",
    "reject_foreign_unwind,panic_boundary",
    "reject_cross_vm,reject_stale",
    "reject_allocator_fallback",
    "reject_pointer_sharing,reject_vm_sharing",
    "reject_c_lua_fallback",
    "fixed_sdk_build,module_link,module_load,module_run",
    "callback_longrun,gc,coroutine,debug_ref,no_leak",
];
pub(super) const PROFILES: [&str; 2] = ["lua55-i64f64", "lua54-i64f64"];
pub(super) const TARGETS: [&str; 3] = [
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
];

#[derive(Clone, Debug)]
pub(super) struct Case {
    pub id: String,
    pub execution_kind: ExecutionKind,
    pub step: String,
    pub fixture: String,
    pub local_test: String,
    pub assertions: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExecutionKind {
    Unset,
    CDriver,
    RustTest,
    SdkModules,
    BuildAudit,
}

#[derive(Clone, Copy)]
pub(super) struct RustProof {
    pub target: &'static str,
    pub test: &'static str,
    pub assertions: &'static [&'static str],
}

pub(super) fn original_source(id: &str) -> Option<&'static str> {
    match id {
        "ABI-001" => Some("tests/p16/callback_execution_b4.c"),
        "ABI-002" => Some("tests/p16/public_callback_error_a2.c"),
        "ABI-004" | "ABI-NEG-004" => Some("tests/p16/allocator_state_a50.c"),
        "ABI-NEG-001" => Some("tests/p16/trampoline_a1.c"),
        _ => None,
    }
}

pub(super) fn rust_proofs(id: &str) -> &'static [RustProof] {
    match id {
        "ABI-001" => &[
            RustProof {
                target: "callback_execution",
                test: "fixed_and_multret_callback_results_follow_c_stack_contract_b4",
                assertions: &["multret"],
            },
            RustProof {
                target: "callback_execution",
                test: "callback_can_collect_gc_and_reacquire_captured_table_b4",
                assertions: &["roots"],
            },
        ],
        "ABI-002" => &[
            RustProof {
                target: "public_callback_error",
                test: "nested_bytecode_error_reparks_outer_c_callback_and_leaves_reusable_state",
                assertions: &[],
            },
            RustProof {
                target: "abi_acceptance",
                test: "abi_neg001_live_rust_guard_rejects_missing_c_checkpoint",
                assertions: &["rust_boundary"],
            },
        ],
        "ABI-003" => &[RustProof {
            target: "abi_acceptance",
            test: "abi003_refs_userdata_survive_gc_and_release_ledger",
            assertions: &["root_ledger"],
        }],
        "ABI-004" => &[
            RustProof {
                target: "abi_acceptance",
                test: "abi004_internal_adapter_ledger_every_allocation_ordinal_rolls_back",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "custom_allocator_tracks_public_domains_and_close_releases_every_token_once",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "null_allocator_fails_without_callback_and_default_state_works",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "rejected_admission_does_not_fallback_and_state_can_retry",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "setallocf_routes_new_tokens_and_old_token_frees_through_current_binding",
                assertions: &[],
            },
        ],
        "ABI-005" => &[RustProof {
            target: "native_modes",
            test: "abi_005_every_identity_field_rejected_before_loader",
            assertions: &[
                "header", "layout", "revision", "target", "profile", "numeric", "preload",
            ],
        }],
        "ABI-006" => &[RustProof {
            target: "worker",
            test: "abi_006_worker_primitives_bytes_gc_crash_timeout_malformed_and_fresh_reuse",
            assertions: &[
                "crash",
                "timeout",
                "malformed",
                "private_vm",
                "heap_cleanup",
            ],
        }],
        "ABI-007" => &[RustProof {
            target: "native_modes",
            test: "abi_007_denied_digest_and_foreign_unwind_rejected_before_loader",
            assertions: &["policy", "preload", "no_constructor"],
        }],
        "ABI-NEG-001" => &[RustProof {
            target: "abi_acceptance",
            test: "abi_neg001_live_rust_guard_rejects_missing_c_checkpoint",
            assertions: &["reject_rust_frame_longjmp"],
        }],
        "ABI-NEG-002" => &[RustProof {
            target: "abi_acceptance",
            test: "abi_neg002_panic_is_caught_and_foreign_unwind_boundary_is_static",
            assertions: &["reject_foreign_unwind", "panic_boundary"],
        }],
        "ABI-NEG-003" => &[RustProof {
            target: "abi_negative_handles",
            test: "abi_neg003_rejects_foreign_and_stale_handles_without_mutation",
            assertions: &["reject_cross_vm", "reject_stale"],
        }],
        "ABI-NEG-004" => &[
            RustProof {
                target: "allocator_state",
                test: "custom_allocator_tracks_public_domains_and_close_releases_every_token_once",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "null_allocator_fails_without_callback_and_default_state_works",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "rejected_admission_does_not_fallback_and_state_can_retry",
                assertions: &[],
            },
            RustProof {
                target: "allocator_state",
                test: "setallocf_routes_new_tokens_and_old_token_frees_through_current_binding",
                assertions: &[],
            },
        ],
        "ABI-NEG-005" => &[RustProof {
            target: "worker",
            test: "neg_005_pointer_state_function_tags_and_noncopyable_rejected",
            assertions: &["reject_pointer_sharing", "reject_vm_sharing"],
        }],
        "SDK-MODULE" => &[RustProof {
            target: "sdk_modules",
            test: "sdk_modules_official_five_load_execute_and_p1",
            assertions: &[
                "fixed_sdk_build",
                "module_link",
                "module_load",
                "module_run",
            ],
        }],
        _ => &[],
    }
}

impl ExecutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "Unset",
            Self::CDriver => "CDriver",
            Self::RustTest => "RustTest",
            Self::SdkModules => "SdkModules",
            Self::BuildAudit => "BuildAudit",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "CDriver" => Ok(Self::CDriver),
            "RustTest" => Ok(Self::RustTest),
            "SdkModules" => Ok(Self::SdkModules),
            "BuildAudit" => Ok(Self::BuildAudit),
            _ => Err(format!("P16 矩陣 execution_kind 無效：{value}")),
        }
    }
}

fn quoted(value: &str) -> Result<&str, String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.contains(['"', '\\', '\n', '\r']))
        .ok_or_else(|| format!("P16 矩陣字串格式錯誤：{value}"))
}

pub(super) fn load(root: &Path) -> Result<Vec<Case>, String> {
    let source = fs::read_to_string(root.join("tests/p16/acceptance-cases.toml"))
        .map_err(|error| format!("P16 矩陣不可讀：{error}"))?;
    let mut schema = false;
    let mut cases = Vec::new();
    let mut current: Option<Case> = None;
    let mut seen_fields = HashSet::new();
    for (line_number, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[case]]" {
            if let Some(case) = current.take() {
                if seen_fields.len() != 6 {
                    return Err(format!("P16 矩陣案例欄位不完整：{}", case.id));
                }
                cases.push(case);
            }
            current = Some(Case {
                id: String::new(),
                execution_kind: ExecutionKind::Unset,
                step: String::new(),
                fixture: String::new(),
                local_test: String::new(),
                assertions: Vec::new(),
            });
            seen_fields.clear();
            continue;
        }
        let (key, raw) = line
            .split_once('=')
            .ok_or_else(|| format!("P16 矩陣第 {} 行缺等號", line_number + 1))?;
        let key = key.trim();
        let value = quoted(raw.trim())?;
        if let Some(case) = current.as_mut() {
            if !seen_fields.insert(key.to_owned()) {
                return Err(format!("P16 矩陣重複欄位：{key}"));
            }
            match key {
                "id" => case.id = value.into(),
                "execution_kind" => case.execution_kind = ExecutionKind::parse(value)?,
                "step" => case.step = value.into(),
                "fixture" => case.fixture = value.into(),
                "local_test" => case.local_test = value.into(),
                "assertions" => case.assertions = value.split(',').map(str::to_owned).collect(),
                _ => return Err(format!("P16 矩陣未知欄位：{key}")),
            }
        } else if key == "schema" && !schema && value == "rivetlua-p16-acceptance-cases-v1" {
            schema = true;
        } else {
            return Err(format!("P16 矩陣根欄位無效：{key}"));
        }
    }
    if let Some(case) = current {
        if seen_fields.len() != 6 {
            return Err(format!("P16 矩陣案例欄位不完整：{}", case.id));
        }
        cases.push(case);
    }
    if !schema || cases.len() != IDS.len() {
        return Err("P16 矩陣 schema 或案例總數不符".into());
    }
    let mut seen = HashSet::new();
    for (index, (expected, case)) in IDS.iter().zip(&cases).enumerate() {
        if case.id != *expected || !seen.insert(case.id.as_str()) {
            return Err(format!("P16 矩陣案例 ID 缺失、重複或順序錯誤：{}", case.id));
        }
        if case.step != STEPS[index]
            || case.execution_kind != KINDS[index]
            || case.assertions.join(",") != ASSERTIONS[index]
        {
            return Err(format!("P16 矩陣步驟無效：{}", case.id));
        }
        if case.assertions.is_empty()
            || case.assertions.iter().any(|item| {
                item.is_empty() || !item.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
            })
        {
            return Err(format!("P16 矩陣 assertion 名稱無效：{}", case.id));
        }
        if !case.fixture.is_empty() {
            let valid = match case.execution_kind {
                ExecutionKind::CDriver => {
                    case.fixture.starts_with("tests/p16/") && case.fixture.ends_with(".c")
                }
                ExecutionKind::BuildAudit => {
                    case.fixture.starts_with("tests/p16/acceptance/")
                        && case.fixture.ends_with(".py")
                }
                _ => false,
            };
            if !valid || case.fixture.contains("..") || !root.join(&case.fixture).is_file() {
                return Err(format!("P16 矩陣 fixture 無效：{}", case.id));
            }
        }
        if !case.local_test.is_empty() {
            let (target, name) = case
                .local_test
                .split_once(':')
                .ok_or_else(|| format!("P16 矩陣局部測試格式錯誤：{}", case.id))?;
            let path = root.join(format!("crates/rivetlua-capi/tests/{target}.rs"));
            if target.is_empty()
                || name.is_empty()
                || !path.is_file()
                || !fs::read_to_string(&path)
                    .map_err(|error| error.to_string())?
                    .contains(&format!("fn {name}("))
            {
                return Err(format!("P16 矩陣局部測試不存在：{}", case.id));
            }
        }
        let proofs = rust_proofs(&case.id);
        if !proofs.is_empty()
            && !proofs
                .iter()
                .any(|proof| case.local_test == format!("{}:{}", proof.target, proof.test))
        {
            return Err(format!("P16 矩陣 {} 局部測試與固定 proof 不符", case.id));
        }
    }
    Ok(cases)
}
