use std::path::{Path, PathBuf};

use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, lex, lower, parse, resolve,
};
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

// RAW v13 執行時的固定 CLI 基線；下方候選額度僅供診斷，本檔不修改產品政策。
const RAW_V13_WORK: usize = 256 * 1024 * 1024;
const RAW_V13_TEMPORARY: usize = 128 * 1024 * 1024;
const MODULE: usize = 64 * 1024 * 1024;
const CANDIDATE_TEMPORARY: usize = 256 * 1024 * 1024;
const GIB: usize = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dimension {
    Work,
    Temporary,
    Module,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    dimension: Dimension,
    request: usize,
    spent_before: usize,
    accepted: bool,
}

#[derive(Clone, Copy, Debug)]
struct Denial {
    index: usize,
    dimension: Dimension,
    request: usize,
    spent_before: usize,
    limit: usize,
}

struct RecordingSink {
    limits: [usize; 3],
    spent: [usize; 3],
    claims: Vec<Claim>,
}

impl RecordingSink {
    fn new(work: usize, temporary: usize) -> Self {
        Self {
            limits: [work, temporary, MODULE],
            spent: [0; 3],
            claims: Vec::new(),
        }
    }

    fn claim(&mut self, dimension: Dimension, request: usize) -> Result<(), Denial> {
        let slot = match dimension {
            Dimension::Work => 0,
            Dimension::Temporary => 1,
            Dimension::Module => 2,
        };
        let spent_before = self.spent[slot];
        let limit = self.limits[slot];
        let accepted = spent_before
            .checked_add(request)
            .is_some_and(|total| total <= limit);
        let index = self.claims.len();
        self.claims.push(Claim {
            dimension,
            request,
            spent_before,
            accepted,
        });
        if !accepted {
            return Err(Denial {
                index,
                dimension,
                request,
                spent_before,
                limit,
            });
        }
        self.spent[slot] += request;
        Ok(())
    }
}

impl CompileBudgetSink for RecordingSink {
    type Error = Denial;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Work, units)
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Temporary, bytes)
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.claim(Dimension::Module, bytes)
    }
}

struct Case {
    label: &'static str,
    profile: LanguageProfile,
    path: PathBuf,
    chunk_name: &'static [u8],
}

fn cases() -> Vec<Case> {
    let raw = PathBuf::from(
        std::env::var_os("RIVETLUA_RAW_V13_DIR")
            .expect("RIVETLUA_RAW_V13_DIR 須指向唯讀 RAW v13 目錄"),
    );
    let lua54 =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/lua54/lua-5.4.9-tests/gc.lua");
    vec![
        Case {
            label: "55-full-gc",
            profile: LanguageProfile::Lua55,
            path: raw.join("lua-5.5.1-tests/gc.lua"),
            chunk_name: b"@gc.lua",
        },
        Case {
            label: "55-prefix-350",
            profile: LanguageProfile::Lua55,
            path: raw.join("repro/gc_prefix_350.lua"),
            chunk_name: b"@gc_prefix_350.lua",
        },
        Case {
            label: "55-prefix-395",
            profile: LanguageProfile::Lua55,
            path: raw.join("repro/gc_prefix_395.lua"),
            chunk_name: b"@gc_prefix_395.lua",
        },
        Case {
            label: "55-simple-21",
            profile: LanguageProfile::Lua55,
            path: raw.join("repro/simple_21.lua"),
            chunk_name: b"@simple_21.lua",
        },
        Case {
            label: "55-simple-5",
            profile: LanguageProfile::Lua55,
            path: raw.join("repro/simple_5.lua"),
            chunk_name: b"@simple_5.lua",
        },
        Case {
            label: "54-full-gc",
            profile: LanguageProfile::Lua54,
            path: lua54,
            chunk_name: b"@gc.lua",
        },
        Case {
            label: "54-simple-21",
            profile: LanguageProfile::Lua54,
            path: raw.join("repro/simple_21.lua"),
            chunk_name: b"@simple_21.lua",
        },
        Case {
            label: "54-simple-5",
            profile: LanguageProfile::Lua54,
            path: raw.join("repro/simple_5.lua"),
            chunk_name: b"@simple_5.lua",
        },
    ]
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Complete,
    Denied(Denial),
    Unexpected,
}

fn run(case: &Case, work: usize, temporary: usize) -> Outcome {
    let source = std::fs::read(&case.path).unwrap();
    run_source(case, &source, work, temporary)
}

fn run_source(case: &Case, source: &[u8], work: usize, temporary: usize) -> Outcome {
    let mut sink = RecordingSink::new(work, temporary);
    let result = compile_with_budget(
        source,
        case.chunk_name,
        case.profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut sink,
    );
    eprintln!(
        "case={} profile={:?} path={} source_bytes={} chunk_name={:?} caps={work}/{temporary}/{MODULE}",
        case.label,
        case.profile,
        case.path.display(),
        source.len(),
        String::from_utf8_lossy(case.chunk_name),
    );
    for (index, claim) in sink.claims.iter().enumerate() {
        eprintln!(
            "case={} claim#{index} {:?} request={} before={} remaining={} accepted={}",
            case.label,
            claim.dimension,
            claim.request,
            claim.spent_before,
            sink.limits[match claim.dimension {
                Dimension::Work => 0,
                Dimension::Temporary => 1,
                Dimension::Module => 2,
            }]
            .saturating_sub(claim.spent_before),
            claim.accepted,
        );
    }
    match result {
        Ok(module) => {
            let actual = verified_module_allocation_bytes(&module).unwrap();
            assert!(actual <= sink.spent[2]);
            let lexed = lex(source, case.profile, &CompileLimits::default()).unwrap();
            let parsed = parse(&lexed, case.profile, &CompileLimits::default()).unwrap();
            let resolved =
                resolve(&parsed, &lexed, case.profile, &CompileLimits::default()).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let bindings: usize = resolved
                .functions
                .iter()
                .map(|function| function.bindings.len())
                .sum();
            let instructions: usize = ir
                .prototypes
                .iter()
                .map(|proto| proto.instructions.len())
                .sum();
            eprintln!(
                "case={} COMPLETE work={} temporary_cumulative_claimed={} module_claimed={} module_actual={} tokens={} functions={} bindings={} prototypes={} instructions={} claims={}",
                case.label,
                sink.spent[0],
                sink.spent[1],
                sink.spent[2],
                actual,
                lexed.tokens.len(),
                resolved.functions.len(),
                bindings,
                ir.prototypes.len(),
                instructions,
                sink.claims.len(),
            );
            Outcome::Complete
        }
        Err(BudgetedCompileError::Budget(denial)) => {
            assert!(!sink.claims[denial.index].accepted);
            eprintln!(
                "case={} DENIED {:?} claim#{} request={} spent_before={} limit={} accepted_work={} temporary_cumulative_claimed={} module_claimed={}",
                case.label,
                denial.dimension,
                denial.index,
                denial.request,
                denial.spent_before,
                denial.limit,
                sink.spent[0],
                sink.spent[1],
                sink.spent[2],
            );
            Outcome::Denied(denial)
        }
        Err(other) => {
            eprintln!("case={} UNEXPECTED compile={other:?}", case.label);
            Outcome::Unexpected
        }
    }
}

#[test]
#[ignore = "需明示唯讀 RAW v13 來源；記錄 RAW v13 固定 CLI 基線的 GC 編譯"]
fn record_gc_compiler_baseline() {
    let mut failures = Vec::new();
    for case in cases() {
        let outcome = run(&case, RAW_V13_WORK, RAW_V13_TEMPORARY);
        let expected = match case.label {
            "55-full-gc" | "55-prefix-395" => matches!(
                outcome,
                Outcome::Denied(Denial {
                    dimension: Dimension::Work,
                    ..
                })
            ),
            "55-prefix-350" | "55-simple-21" | "55-simple-5" | "54-simple-21" | "54-simple-5" => {
                matches!(outcome, Outcome::Complete)
            }
            "54-full-gc" => !matches!(outcome, Outcome::Unexpected),
            _ => unreachable!(),
        };
        if !expected {
            failures.push(format!("{}: {outcome:?}", case.label));
        }
    }
    assert!(
        failures.is_empty(),
        "基線與 RAW 或既有控制案例不符：{failures:?}"
    );
}

#[test]
#[ignore = "需先完成 baseline；只提高真正遭拒的有限維度"]
fn record_gc_compiler_finite_controls() {
    let mut failures = Vec::new();
    for case in cases() {
        let baseline = run(&case, RAW_V13_WORK, RAW_V13_TEMPORARY);
        let Outcome::Denied(denial) = baseline else {
            if matches!(baseline, Outcome::Unexpected) {
                failures.push(format!("{}: unexpected baseline", case.label));
            }
            continue;
        };
        if denial.dimension != Dimension::Work {
            failures.push(format!(
                "{}: baseline denied {:?}, not authorized for work control",
                case.label, denial.dimension
            ));
            continue;
        }
        let mut complete = false;
        for work in [GIB, 2 * GIB] {
            match run(&case, work, RAW_V13_TEMPORARY) {
                Outcome::Complete => {
                    complete = true;
                    break;
                }
                Outcome::Denied(Denial {
                    dimension: Dimension::Work,
                    ..
                }) => continue,
                Outcome::Denied(Denial {
                    dimension: Dimension::Temporary,
                    ..
                }) => {
                    match run(&case, work, 512 * 1024 * 1024) {
                        Outcome::Complete => complete = true,
                        other => failures.push(format!("{}: {work}/512Mi {other:?}", case.label)),
                    }
                    break;
                }
                other => {
                    failures.push(format!("{}: {work}/128Mi {other:?}", case.label));
                    break;
                }
            }
        }
        if !complete && !failures.iter().any(|entry| entry.starts_with(case.label)) {
            failures.push(format!("{}: finite work 2Gi did not complete", case.label));
        }
    }
    assert!(failures.is_empty(), "有限控制尚未完成：{failures:?}");
}

#[test]
#[ignore = "診斷 RAW v13 後候選 CLI 2Gi work units／256MiB temp；本檔不修改產品政策"]
fn record_gc_compiler_candidate_policy() {
    for case in cases()
        .into_iter()
        .filter(|case| case.label == "55-full-gc" || case.label == "54-full-gc")
    {
        assert!(
            matches!(run(&case, 2 * GIB, CANDIDATE_TEMPORARY), Outcome::Complete),
            "{} 在候選有限額度下須完整編譯",
            case.label,
        );
    }
}

#[test]
#[ignore = "僅診斷候選 CLI 的 Work 優先拒絕；不更動 CLI 原測試"]
fn record_gc_compiler_candidate_work_negative() {
    let source = b"do local x=1 end\n".repeat(8_000);
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let case = Case {
            label: "synthetic-8000-blocks",
            profile,
            path: PathBuf::from("<memory:8000-independent-blocks>"),
            chunk_name: b"@gc_work_8000.lua",
        };
        let outcome = run_source(&case, &source, 2 * GIB, CANDIDATE_TEMPORARY);
        assert!(
            matches!(
                outcome,
                Outcome::Denied(Denial {
                    dimension: Dimension::Work,
                    ..
                })
            ),
            "{profile:?} 候選 Work-first 負向來源的實際結果：{outcome:?}",
        );
    }
}

const RAW_V23_WORK: usize = 2 * GIB;
const RAW_V23_TEMPORARY: usize = 256 * 1024 * 1024;

fn raw_v23_normalized_source(raw: &[u8]) -> Vec<u8> {
    let bytes = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    if bytes.first() != Some(&b'#') {
        return bytes.to_vec();
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |index| index + 1);
    let mut normalized = Vec::with_capacity(bytes.len() - end + 1);
    normalized.push(b'\n');
    normalized.extend_from_slice(&bytes[end..]);
    normalized
}

fn raw_v23_db_source() -> Vec<u8> {
    let path = std::env::var_os("RIVETLUA_RAW_V23_DB")
        .expect("RIVETLUA_RAW_V23_DB 須指向唯讀 RAW v23 lua-5.5.1-tests/db.lua");
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(raw.len(), 26_598);
    let normalized = raw_v23_normalized_source(&raw);
    eprintln!(
        "raw_v23_db path={} raw_bytes={} normalized_bytes={} identical={} expected_raw_sha256=82ed710f0aa5ab23eb86fc0ad73705e6d8f8b0cd9c8a3d1b4da31623c3e40f10",
        Path::new(&path).display(),
        raw.len(),
        normalized.len(),
        raw == normalized,
    );
    assert_eq!(raw, normalized, "RAW v23 db.lua 應無 BOM/shebang");
    normalized
}

fn raw_v23_compile(
    source: &[u8],
    chunk_name: &[u8],
    profile: LanguageProfile,
    caps: [usize; 3],
) -> (
    RecordingSink,
    Result<rivetlua_core::VerifiedModule, BudgetedCompileError<Denial>>,
) {
    let mut sink = RecordingSink {
        limits: caps,
        spent: [0; 3],
        claims: Vec::new(),
    };
    // runtime create_loaded_function 在呼叫 host compiler 前先扣 1 work。
    sink.claim(Dimension::Work, 1).unwrap();
    let result = compile_with_budget(
        source,
        chunk_name,
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut sink,
    );
    (sink, result)
}

fn raw_v23_phase(index: usize, temporary_claims: &[usize]) -> &'static str {
    match temporary_claims {
        [lex, parse, resolve, lower, candidate, _emit] => {
            if index <= *lex {
                "host+lex"
            } else if index < parse - 1 {
                "lex-numeric"
            } else if index <= *parse {
                "parse"
            } else if index <= *resolve {
                "resolve"
            } else if index <= *lower {
                "lower"
            } else if index <= *candidate {
                "candidate"
            } else {
                "emit+verify"
            }
        }
        [lex, parse] => {
            if index <= *lex {
                "host+lex"
            } else if index < parse - 1 {
                "lex-numeric"
            } else {
                "parse"
            }
        }
        _ => "incomplete",
    }
}

fn raw_v23_trace(
    label: &str,
    profile: LanguageProfile,
    sink: &RecordingSink,
    reference: &RecordingSink,
) {
    let temporary_claims: Vec<_> = reference
        .claims
        .iter()
        .enumerate()
        .filter_map(|(index, claim)| (claim.dimension == Dimension::Temporary).then_some(index))
        .collect();
    let mut phase_totals = [[0usize; 3]; 7];
    let mut counts = [0usize; 3];
    for (index, claim) in sink.claims.iter().enumerate() {
        let slot = match claim.dimension {
            Dimension::Work => 0,
            Dimension::Temporary => 1,
            Dimension::Module => 2,
        };
        counts[slot] += 1;
        if claim.accepted {
            let phase_slot = match raw_v23_phase(index, &temporary_claims) {
                "host+lex" => 0,
                "lex-numeric" => 1,
                "parse" => 2,
                "resolve" => 3,
                "lower" => 4,
                "candidate" => 5,
                "emit+verify" => 6,
                _ => continue,
            };
            phase_totals[phase_slot][slot] += claim.request;
        }
    }
    eprintln!(
        "raw_v23_{label} profile={profile:?} caps={:?} spent={:?} claims_by_dimension={counts:?} claims_total={}",
        sink.limits,
        sink.spent,
        sink.claims.len(),
    );
    for (name, amounts) in [
        "host+lex",
        "lex-numeric",
        "parse",
        "resolve",
        "lower",
        "candidate",
        "emit+verify",
    ]
    .into_iter()
    .zip(phase_totals)
    {
        eprintln!("raw_v23_{label} profile={profile:?} phase={name} work/temp/module={amounts:?}");
    }
    let mut top_work: Vec<_> = sink
        .claims
        .iter()
        .enumerate()
        .filter(|(_, claim)| claim.dimension == Dimension::Work)
        .map(|(index, claim)| {
            (
                index,
                claim.request,
                raw_v23_phase(index, &temporary_claims),
            )
        })
        .collect();
    top_work.sort_unstable_by_key(|(_, request, _)| std::cmp::Reverse(*request));
    eprintln!(
        "raw_v23_{label} profile={profile:?} top_work_claims={:?}",
        &top_work[..top_work.len().min(8)]
    );
    if let Some((index, denial)) = sink
        .claims
        .iter()
        .enumerate()
        .find(|(_, claim)| !claim.accepted)
    {
        eprintln!(
            "raw_v23_{label} profile={profile:?} FIRST_DENIAL phase={} claim#{index} dimension={:?} request={} spent_before={} limit={}",
            raw_v23_phase(index, &temporary_claims),
            denial.dimension,
            denial.request,
            denial.spent_before,
            sink.limits[match denial.dimension {
                Dimension::Work => 0,
                Dimension::Temporary => 1,
                Dimension::Module => 2,
            }],
        );
        for nearby in index.saturating_sub(2)..=(index + 2).min(sink.claims.len() - 1) {
            eprintln!(
                "raw_v23_{label} profile={profile:?} nearby_claim#{nearby} {:?}",
                sink.claims[nearby]
            );
        }
    }
}

fn raw_v23_shape(label: &str, source: &[u8], profile: LanguageProfile) {
    let limits = CompileLimits::default();
    let lexed = lex(source, profile, &limits).unwrap();
    let parsed = parse(&lexed, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &lexed, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    eprintln!(
        "raw_v23_{label} profile={profile:?} shape tokens={} statements={} functions={} bindings={} upvalues={} prototypes={} instructions={} constants={}",
        lexed.tokens.len(),
        parsed.root.statements.len(),
        resolved.functions.len(),
        resolved
            .functions
            .iter()
            .map(|function| function.bindings.len())
            .sum::<usize>(),
        resolved
            .functions
            .iter()
            .map(|function| function.upvalues.len())
            .sum::<usize>(),
        ir.prototypes.len(),
        ir.prototypes
            .iter()
            .map(|proto| proto.instructions.len())
            .sum::<usize>(),
        ir.prototypes
            .iter()
            .map(|proto| proto.constants.len())
            .sum::<usize>(),
    );
}

#[test]
#[ignore = "需明示 RIVETLUA_RAW_V23_DB；只診斷 RAW v23 db.lua 的 compiler 計帳"]
fn record_raw_v23_db_compiler_budget() {
    let source = raw_v23_db_source();
    eprintln!(
        "raw_v23_db compiler sink 僅量 work/temporary/module；不涵蓋 source/encoded/reader/path 准入"
    );
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let (cli_sink, cli_result) = raw_v23_compile(
            &source,
            b"@db.lua",
            profile,
            [RAW_V23_WORK, RAW_V23_TEMPORARY, MODULE],
        );
        let (unbounded, result) = raw_v23_compile(&source, b"@db.lua", profile, [usize::MAX; 3]);
        raw_v23_trace("db", profile, &cli_sink, &unbounded);
        eprintln!(
            "raw_v23_db profile={profile:?} cli_result={:?}",
            cli_result.as_ref().map(|_| ())
        );
        raw_v23_trace("db", profile, &unbounded, &unbounded);
        match result {
            Ok(module) => {
                let actual = verified_module_allocation_bytes(&module).unwrap();
                eprintln!(
                    "raw_v23_db profile={profile:?} COMPLETE work={} temporary_cumulative={} module_claimed={} module_actual={actual}",
                    unbounded.spent[0], unbounded.spent[1], unbounded.spent[2]
                );
                assert!(actual <= unbounded.spent[2]);
                raw_v23_shape("db", &source, profile);

                let (exact, exact_result) =
                    raw_v23_compile(&source, b"@db.lua", profile, unbounded.spent);
                eprintln!(
                    "raw_v23_db profile={profile:?} AT_EXACT result={:?}",
                    exact_result.as_ref().map(|_| ())
                );
                assert!(exact_result.is_ok());
                assert_eq!(exact.spent, unbounded.spent);

                for slot in 0..3 {
                    let mut below_caps = unbounded.spent;
                    below_caps[slot] -= 1;
                    let (below, below_result) =
                        raw_v23_compile(&source, b"@db.lua", profile, below_caps);
                    let expected = [Dimension::Work, Dimension::Temporary, Dimension::Module][slot];
                    let denial = match below_result {
                        Err(BudgetedCompileError::Budget(denial)) => denial,
                        other => panic!("{profile:?} dimension={expected:?} 1-below: {other:?}"),
                    };
                    eprintln!(
                        "raw_v23_db profile={profile:?} ONE_BELOW dimension={expected:?} claim#{} request={} spent_before={} limit={}",
                        denial.index, denial.request, denial.spent_before, denial.limit,
                    );
                    assert_eq!(denial.dimension, expected);
                    assert_eq!(below.claims.len() - 1, denial.index);
                }
            }
            Err(error) => eprintln!("raw_v23_db profile={profile:?} UNBOUNDED_ERROR={error:?}"),
        }
    }
}

#[test]
#[ignore = "需明示 RIVETLUA_RAW_V23_DB；僅比較已知通過 main/gc 的結構，不重跑正式驗收"]
fn record_raw_v23_db_shape_controls() {
    let path = PathBuf::from(
        std::env::var_os("RIVETLUA_RAW_V23_DB")
            .expect("RIVETLUA_RAW_V23_DB 須指向唯讀 RAW v23 db.lua"),
    );
    let directory = path.parent().unwrap();
    for label in ["main", "gc"] {
        let raw = std::fs::read(directory.join(format!("{label}.lua"))).unwrap();
        let normalized = raw_v23_normalized_source(&raw);
        eprintln!(
            "raw_v23_{label} raw_bytes={} normalized_bytes={}",
            raw.len(),
            normalized.len()
        );
        raw_v23_shape(label, &normalized, LanguageProfile::Lua55);
    }
}

fn raw_v23_small_structure() -> Vec<u8> {
    let mut source = b"local x1,x2,x3,x4,x5,x6=1,2,3,4,5,6\n".to_vec();
    for index in 0..52 {
        source.extend_from_slice(
            format!("local function f{index}() return x1,x2,x3,x4,x5,x6 end\n").as_bytes(),
        );
    }
    source
}

#[test]
fn raw_v23_small_structure_cli_budget_regression() {
    let source = raw_v23_small_structure();
    eprintln!("raw_v23_small source_bytes={}", source.len());
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let (cli_sink, result) = raw_v23_compile(
            &source,
            b"@small.lua",
            profile,
            [RAW_V23_WORK, RAW_V23_TEMPORARY, MODULE],
        );
        let (unbounded, unbounded_result) =
            raw_v23_compile(&source, b"@small.lua", profile, [usize::MAX; 3]);
        assert!(
            unbounded_result.is_ok(),
            "{profile:?}: {unbounded_result:?}"
        );
        raw_v23_trace("small", profile, &cli_sink, &unbounded);
        raw_v23_trace("small", profile, &unbounded, &unbounded);
        raw_v23_shape("small", &source, profile);
        assert!(
            result.is_ok(),
            "{profile:?} 縮小結構應由固定 CLI caps 准入：{result:?}"
        );
    }
}
