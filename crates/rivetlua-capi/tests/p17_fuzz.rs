#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, RVLU_MAGIC, RVLU_V2,
    VerifyLimits, decode_module, decode_official_chunk, preflight_official_chunk,
    translate_official_chunk_with_work, verify_module,
};

const ITERATIONS: usize = 128;
const PARSER_SEED: u64 = 0x173101;
const RVLU_SEED: u64 = 0x173102;
const OFFICIAL_SEED: u64 = 0x173103;
const OFFICIAL_WORK_UNITS: u64 = 1_000_000;

fn selected_profile() -> LuaProfile {
    match (cfg!(feature = "lua55"), cfg!(feature = "lua54")) {
        (true, false) => LuaProfile::Lua55,
        (false, true) => LuaProfile::Lua54,
        _ => panic!("p17_fuzz 需要且只需要一個 Lua profile feature"),
    }
}

fn profile_id(profile: LuaProfile) -> &'static str {
    match profile {
        LuaProfile::Lua55 => "lua55-i64f64",
        LuaProfile::Lua54 => "lua54-i64f64",
    }
}

fn language_profile(profile: LuaProfile) -> LanguageProfile {
    match profile {
        LuaProfile::Lua55 => LanguageProfile::Lua55,
        LuaProfile::Lua54 => LanguageProfile::Lua54,
    }
}

fn compile_limits() -> CompileLimits {
    CompileLimits {
        max_source_bytes: 4 * 1024,
        max_tokens: 4096,
        max_parse_depth: 64,
        ..CompileLimits::default()
    }
}

fn ir_limits() -> IrLimits {
    IrLimits {
        max_prototypes: 32,
        max_instructions: 512,
        max_registers: 256,
        max_upvalues_per_prototype: 255,
    }
}

fn verify_limits() -> VerifyLimits {
    VerifyLimits {
        max_module_bytes: 16 * 1024,
        max_artifact_bytes: 16 * 1024,
        max_prototypes: 32,
        max_instructions: 512,
        max_constants: 256,
        max_registers: 256,
        max_upvalues_per_prototype: 255,
    }
}

fn compile_source(source: &[u8], profile: LuaProfile) -> Result<Vec<u8>, String> {
    let language = language_profile(profile);
    let limits = compile_limits();
    let lexed = lex(source, language, &limits).map_err(|error| format!("詞法分析：{error:?}"))?;
    let ast = parse(&lexed, language, &limits).map_err(|error| format!("語法分析：{error:?}"))?;
    let resolved =
        resolve(&ast, &lexed, language, &limits).map_err(|error| format!("名稱解析：{error:?}"))?;
    let ir = lower(&resolved, &ir_limits()).map_err(|error| format!("IR lowering：{error:?}"))?;
    let encoded =
        emit(&ir, &verify_limits()).map_err(|error| format!("RVLU 編碼／驗證：{error:?}"))?;
    let bytes = encoded.bytes().to_vec();
    decode_module(&bytes, profile, &verify_limits())
        .map_err(|error| format!("RVLU 解碼／驗證：{error:?}"))?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

fn mutate_bytes(input: &[u8], rng: &mut XorShift64, maximum: usize) -> Vec<u8> {
    let mut mutated = input.to_vec();
    match rng.next() % 3 {
        0 if !mutated.is_empty() => {
            let index = (rng.next() as usize) % mutated.len();
            mutated[index] ^= (rng.next() as u8) | 1;
        }
        1 if mutated.len() < maximum => {
            let index = (rng.next() as usize) % (mutated.len() + 1);
            mutated.insert(index, rng.next() as u8);
        }
        2 if !mutated.is_empty() => {
            let index = (rng.next() as usize) % mutated.len();
            mutated.remove(index);
        }
        _ => {}
    }
    mutated
}

fn input_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len().saturating_mul(2));
    for byte in input {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 15)] as char);
    }
    output
}

const SHRINK_EVALUATION_BUDGET: usize = 256;

struct ShrinkResult {
    candidate: Vec<u8>,
    evaluations: usize,
    budget_exhausted: bool,
}

fn minimize_preserving<F>(input: &[u8], mut predicate: F) -> ShrinkResult
where
    F: FnMut(&[u8]) -> bool,
{
    let mut candidate = input.to_vec();
    let mut evaluations = 1;
    if !predicate(&candidate) || candidate.len() < 2 {
        return ShrinkResult {
            candidate,
            evaluations,
            budget_exhausted: false,
        };
    }

    let mut parts = 2usize;
    let mut budget_exhausted = false;
    'shrink: while candidate.len() >= 2 {
        let chunk = candidate.len().div_ceil(parts);
        let mut reduced = false;
        let mut start = 0usize;
        while start < candidate.len() {
            if evaluations >= SHRINK_EVALUATION_BUDGET {
                budget_exhausted = true;
                break 'shrink;
            }
            let end = start.saturating_add(chunk).min(candidate.len());
            let mut trial = Vec::with_capacity(candidate.len() - (end - start));
            trial.extend_from_slice(&candidate[..start]);
            trial.extend_from_slice(&candidate[end..]);
            evaluations += 1;
            if predicate(&trial) {
                candidate = trial;
                parts = parts.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            start = end;
        }
        if !reduced {
            if parts >= candidate.len() {
                break;
            }
            parts = parts.saturating_mul(2).min(candidate.len());
        }
    }

    ShrinkResult {
        candidate,
        evaluations,
        budget_exhausted,
    }
}

fn reproduction_command(test_name: &str, profile: LuaProfile) -> String {
    let feature_args = match profile {
        LuaProfile::Lua55 => "--features lua55",
        LuaProfile::Lua54 => "--no-default-features --features lua54",
    };
    format!(
        "CARGO_TARGET_DIR=/Volumes/VP4300L_4T/stevelo/.cache/rivetlua-p17-target TMPDIR=/Volumes/VP4300L_4T/stevelo/.cache/rivetlua-p17-target/tmp cargo test --locked -p rivetlua-capi {feature_args} --test p17_fuzz {test_name} -- --exact --nocapture"
    )
}

fn report_failure(
    case_id: &str,
    test_name: &str,
    profile: LuaProfile,
    seed: u64,
    iteration: usize,
    detail: &str,
    original: &[u8],
    minimized: &[u8],
) -> ! {
    report_failure_impl(
        case_id, test_name, profile, seed, iteration, detail, original, minimized, "none", 0, false,
    )
}

fn report_failure_found(
    case_id: &str,
    test_name: &str,
    profile: LuaProfile,
    seed: u64,
    iteration: usize,
    detail: &str,
    original: &[u8],
) {
    eprintln!(
        "P17_B03_FAILURE_FOUND family={case_id} seed=0x{seed:06x} iteration={iteration} detail={detail} original_hex={} reproduce={}",
        input_hex(original),
        reproduction_command(test_name, profile),
    );
}

fn report_shrunk_failure(
    case_id: &str,
    test_name: &str,
    profile: LuaProfile,
    seed: u64,
    iteration: usize,
    detail: &str,
    original: &[u8],
    shrink: &ShrinkResult,
) -> ! {
    report_failure_impl(
        case_id,
        test_name,
        profile,
        seed,
        iteration,
        detail,
        original,
        &shrink.candidate,
        "bounded",
        shrink.evaluations,
        shrink.budget_exhausted,
    )
}

#[allow(clippy::too_many_arguments)]
fn report_failure_impl(
    case_id: &str,
    test_name: &str,
    profile: LuaProfile,
    seed: u64,
    iteration: usize,
    detail: &str,
    original: &[u8],
    minimized: &[u8],
    shrink_method: &str,
    shrink_evaluations: usize,
    shrink_budget_exhausted: bool,
) -> ! {
    let shrink_description = if shrink_method == "bounded" {
        "有界縮減"
    } else {
        "未執行"
    };
    eprintln!(
        "P17_B03_FAILURE family={case_id} seed=0x{seed:06x} iteration={iteration} detail={detail} original_hex={} minimized_hex={} shrink_method={shrink_method} shrink_description={shrink_description} shrink_evaluations={shrink_evaluations} shrink_budget={SHRINK_EVALUATION_BUDGET} shrink_budget_exhausted={shrink_budget_exhausted} reproduce={}",
        input_hex(original),
        input_hex(minimized),
        reproduction_command(test_name, profile),
    );
    panic!("P17-B03 mutation 失敗：{case_id} iteration {iteration}：{detail}");
}

fn parser_result(source: &[u8], profile: LuaProfile, iteration: usize) -> bool {
    match catch_unwind(AssertUnwindSafe(|| compile_source(source, profile).is_ok())) {
        Ok(accepted) => accepted,
        Err(_) => {
            let detail = "parser pipeline 發生 panic";
            report_failure_found(
                "p17_fuzz_parser",
                "p17_fuzz_parser",
                profile,
                PARSER_SEED,
                iteration,
                detail,
                source,
            );
            let shrink = minimize_preserving(source, |candidate| {
                catch_unwind(AssertUnwindSafe(|| {
                    compile_source(candidate, profile).is_ok()
                }))
                .is_err()
            });
            report_shrunk_failure(
                "p17_fuzz_parser",
                "p17_fuzz_parser",
                profile,
                PARSER_SEED,
                iteration,
                detail,
                source,
                &shrink,
            );
        }
    }
}

fn parser_trial(
    iteration: usize,
    baseline: &[u8],
    rng: &mut XorShift64,
) -> (Vec<u8>, Option<bool>) {
    match iteration {
        0 => (baseline.to_vec(), Some(true)),
        1 => (b"local broken = \"unterminated".to_vec(), Some(false)),
        2 => (b"return @".to_vec(), Some(false)),
        3 => (vec![b'x'; 4097], Some(false)),
        4 => {
            let mut source = b"return ".to_vec();
            source.extend(std::iter::repeat_n(b'(', 128));
            source.push(b'1');
            source.extend(std::iter::repeat_n(b')', 128));
            (source, Some(false))
        }
        _ => (mutate_bytes(baseline, rng, 4096), None),
    }
}

#[test]
fn p17_fuzz_parser() {
    let profile = selected_profile();
    let baseline = b"return 42\n";
    let baseline_accepted = parser_result(baseline, profile, 0);
    if !baseline_accepted {
        report_failure(
            "p17_fuzz_parser",
            "p17_fuzz_parser",
            profile,
            PARSER_SEED,
            0,
            "合法 parser baseline 被拒絕",
            baseline,
            baseline,
        );
    }

    let mut rng = XorShift64::new(PARSER_SEED);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut explicit_negative_rejects = 0usize;
    for iteration in 0..ITERATIONS {
        let (source, expected) = parser_trial(iteration, baseline, &mut rng);
        let is_accepted = parser_result(&source, profile, iteration);
        if let Some(expected_accepted) = expected {
            if is_accepted != expected_accepted {
                let detail = if expected_accepted {
                    "合法基底遭拒絕"
                } else {
                    "明確錯誤格式／邊界輸入遭接受"
                };
                report_failure_found(
                    "p17_fuzz_parser",
                    "p17_fuzz_parser",
                    profile,
                    PARSER_SEED,
                    iteration,
                    detail,
                    &source,
                );
                let shrink = minimize_preserving(&source, |candidate| {
                    matches!(
                        parser_result_without_reporting(candidate, profile),
                        Some(actual) if actual != expected_accepted
                    )
                });
                report_shrunk_failure(
                    "p17_fuzz_parser",
                    "p17_fuzz_parser",
                    profile,
                    PARSER_SEED,
                    iteration,
                    detail,
                    &source,
                    &shrink,
                );
            }
            if !expected_accepted {
                explicit_negative_rejects += 1;
            }
        }
        if is_accepted {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(accepted + rejected, ITERATIONS);
    assert!(accepted >= 1, "至少應有合法 baseline 成功");
    assert!(explicit_negative_rejects >= 4);
    println!(
        "P17_B03_CASE {{\"case_id\":\"p17_fuzz_parser\",\"profile\":\"{}\",\"seed\":{},\"iterations\":{},\"outcome\":\"PASS\",\"accepted\":{},\"rejected\":{},\"limits\":{{\"compile_limits\":{{\"max_source_bytes\":4096,\"max_tokens\":4096,\"max_parse_depth\":64}},\"ir_limits\":{{\"max_prototypes\":32,\"max_instructions\":512,\"max_registers\":256,\"max_upvalues_per_prototype\":255}},\"verify_limits\":{{\"max_module_bytes\":16384,\"max_artifact_bytes\":16384,\"max_prototypes\":32,\"max_instructions\":512,\"max_constants\":256,\"max_registers\":256,\"max_upvalues_per_prototype\":255}}}},\"baseline_source\":\"編譯器產生的 return 42\",\"explicit_negative_rejects\":{},\"counts_include_baseline_and_four_explicit_rejections\":true}}",
        profile_id(profile),
        PARSER_SEED,
        ITERATIONS,
        accepted,
        rejected,
        explicit_negative_rejects,
    );
}

fn parser_result_without_reporting(source: &[u8], profile: LuaProfile) -> Option<bool> {
    catch_unwind(AssertUnwindSafe(|| compile_source(source, profile).is_ok())).ok()
}

fn compile_baseline(
    source: &[u8],
    profile: LuaProfile,
    case_id: &str,
    test_name: &str,
    seed: u64,
) -> Vec<u8> {
    match catch_unwind(AssertUnwindSafe(|| compile_source(source, profile))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => report_failure(
            case_id,
            test_name,
            profile,
            seed,
            0,
            &format!("合法編譯基底失敗：{error}"),
            source,
            source,
        ),
        Err(_) => {
            let detail = "合法編譯基底 pipeline 發生 panic";
            report_failure_found(case_id, test_name, profile, seed, 0, detail, source);
            let shrink = minimize_preserving(source, |candidate| {
                catch_unwind(AssertUnwindSafe(|| compile_source(candidate, profile))).is_err()
            });
            report_shrunk_failure(
                case_id, test_name, profile, seed, 0, detail, source, &shrink,
            );
        }
    }
}

fn verify_limits_with(
    max_module_bytes: usize,
    max_prototypes: usize,
    max_instructions: usize,
    max_constants: usize,
    max_registers: u16,
    max_upvalues_per_prototype: usize,
) -> VerifyLimits {
    VerifyLimits {
        max_module_bytes,
        max_artifact_bytes: 16 * 1024,
        max_prototypes,
        max_instructions,
        max_constants,
        max_registers,
        max_upvalues_per_prototype,
    }
}

fn rvlu_result(bytes: &[u8], profile: LuaProfile, limits: &VerifyLimits) -> bool {
    let Ok(verified) = decode_module(bytes, profile, limits) else {
        return false;
    };
    verify_module(verified.module().clone(), profile, limits).is_ok()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn first_rvlu_opcode_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..4)? != RVLU_MAGIC || read_u32(bytes, 28)? != 1 {
        return None;
    }
    let record_len = usize::try_from(read_u32(bytes, 32)?).ok()?;
    let record_start = 36usize;
    let record_end = record_start.checked_add(record_len)?;
    if record_end > bytes.len() {
        return None;
    }
    let mut cursor = record_start.checked_add(8)?;
    match *bytes.get(cursor)? {
        0 => cursor += 1,
        1 => cursor = cursor.checked_add(5)?,
        _ => return None,
    }
    cursor = cursor.checked_add(16 + 2 + 2 + 1)?;
    match *bytes.get(cursor)? {
        0 => cursor += 1,
        1 => cursor = cursor.checked_add(11)?,
        _ => return None,
    }
    cursor = cursor.checked_add(10)?;
    let environment_source = *bytes.get(cursor)?;
    cursor += match environment_source {
        0 => 1,
        1 => 7,
        2 | 3 => 3,
        _ => return None,
    };
    cursor = cursor.checked_add(1 + 2 + 8)?;
    let constants_len = usize::try_from(read_u32(bytes, cursor)?).ok()?;
    cursor = cursor.checked_add(4)?.checked_add(constants_len)?;
    let instructions_len = usize::try_from(read_u32(bytes, cursor)?).ok()?;
    let instructions_start = cursor.checked_add(4)?;
    let instructions_end = instructions_start.checked_add(instructions_len)?;
    if instructions_end > record_end || read_u32(bytes, instructions_start)? == 0 {
        return None;
    }
    instructions_start.checked_add(4)
}

struct RvluTrial {
    bytes: Vec<u8>,
    limits: VerifyLimits,
    expected: Option<bool>,
}

fn rvlu_trial(
    iteration: usize,
    baseline: &[u8],
    upvalue_baseline: &[u8],
    profile: LuaProfile,
    rng: &mut XorShift64,
) -> RvluTrial {
    let max = 16 * 1024;
    let base_limits = verify_limits();
    match iteration {
        0 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: base_limits,
            expected: Some(true),
        },
        1 => {
            let mut bytes = baseline.to_vec();
            bytes[0] ^= 0xff;
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        2 => {
            let mut bytes = baseline.to_vec();
            bytes[4..6].copy_from_slice(&0u16.to_le_bytes());
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        3 => {
            let mut bytes = baseline.to_vec();
            bytes[6] = match profile {
                LuaProfile::Lua55 => 1,
                LuaProfile::Lua54 => 0,
            };
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        4 => {
            let mut bytes = baseline.to_vec();
            bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        5 => {
            let mut bytes = baseline.to_vec();
            let opcode =
                first_rvlu_opcode_offset(&bytes).expect("canonical RVLU 應含第一個 opcode");
            bytes[opcode] = 0xff;
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        6 => {
            let mut bytes = baseline.to_vec();
            bytes.pop();
            RvluTrial {
                bytes,
                limits: base_limits,
                expected: Some(false),
            }
        }
        7 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: verify_limits_with(baseline.len() - 1, 32, 512, 256, 256, 255),
            expected: Some(false),
        },
        8 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: verify_limits_with(max, 0, 512, 256, 256, 255),
            expected: Some(false),
        },
        9 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: verify_limits_with(max, 32, 0, 256, 256, 255),
            expected: Some(false),
        },
        10 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: verify_limits_with(max, 32, 512, 0, 256, 255),
            expected: Some(false),
        },
        11 => RvluTrial {
            bytes: baseline.to_vec(),
            limits: verify_limits_with(max, 32, 512, 256, 0, 255),
            expected: Some(false),
        },
        12 => RvluTrial {
            bytes: upvalue_baseline.to_vec(),
            limits: verify_limits_with(max, 32, 512, 256, 256, 0),
            expected: Some(false),
        },
        _ => RvluTrial {
            bytes: mutate_bytes(baseline, rng, max),
            limits: base_limits,
            expected: None,
        },
    }
}

fn rvlu_trial_result(trial: &RvluTrial, profile: LuaProfile, iteration: usize) -> bool {
    match catch_unwind(AssertUnwindSafe(|| {
        rvlu_result(&trial.bytes, profile, &trial.limits)
    })) {
        Ok(accepted) => accepted,
        Err(_) => {
            let detail = "RVLU 解碼／驗證 pipeline 發生 panic";
            report_failure_found(
                "p17_fuzz_rvlu",
                "p17_fuzz_rvlu",
                profile,
                RVLU_SEED,
                iteration,
                detail,
                &trial.bytes,
            );
            let shrink = minimize_preserving(&trial.bytes, |candidate| {
                catch_unwind(AssertUnwindSafe(|| {
                    rvlu_result(candidate, profile, &trial.limits)
                }))
                .is_err()
            });
            report_shrunk_failure(
                "p17_fuzz_rvlu",
                "p17_fuzz_rvlu",
                profile,
                RVLU_SEED,
                iteration,
                detail,
                &trial.bytes,
                &shrink,
            );
        }
    }
}

#[test]
fn p17_fuzz_rvlu() {
    let profile = selected_profile();
    let baseline = compile_baseline(
        b"return 42\n",
        profile,
        "p17_fuzz_rvlu",
        "p17_fuzz_rvlu",
        RVLU_SEED,
    );
    if baseline.len() < 7 || !baseline.starts_with(&RVLU_MAGIC) {
        report_failure(
            "p17_fuzz_rvlu",
            "p17_fuzz_rvlu",
            profile,
            RVLU_SEED,
            0,
            "compiler 未產生完整 RVLU header",
            &baseline,
            &baseline,
        );
    }
    if u16::from_le_bytes([baseline[4], baseline[5]]) != RVLU_V2.0 {
        report_failure(
            "p17_fuzz_rvlu",
            "p17_fuzz_rvlu",
            profile,
            RVLU_SEED,
            0,
            "compiler 未產生 RVLU_V2 format marker",
            &baseline,
            &baseline,
        );
    }
    let expected_profile_tag = match profile {
        LuaProfile::Lua55 => 0,
        LuaProfile::Lua54 => 1,
    };
    if baseline.get(6) != Some(&expected_profile_tag) {
        report_failure(
            "p17_fuzz_rvlu",
            "p17_fuzz_rvlu",
            profile,
            RVLU_SEED,
            0,
            "compiler 產生 RVLU profile 與測試 profile 不符",
            &baseline,
            &baseline,
        );
    }
    let baseline_accepted = match catch_unwind(AssertUnwindSafe(|| {
        rvlu_result(&baseline, profile, &verify_limits())
    })) {
        Ok(accepted) => accepted,
        Err(_) => {
            let detail = "RVLU baseline 解碼／驗證 pipeline 發生 panic";
            report_failure_found(
                "p17_fuzz_rvlu",
                "p17_fuzz_rvlu",
                profile,
                RVLU_SEED,
                0,
                detail,
                &baseline,
            );
            let shrink = minimize_preserving(&baseline, |candidate| {
                catch_unwind(AssertUnwindSafe(|| {
                    rvlu_result(candidate, profile, &verify_limits())
                }))
                .is_err()
            });
            report_shrunk_failure(
                "p17_fuzz_rvlu",
                "p17_fuzz_rvlu",
                profile,
                RVLU_SEED,
                0,
                detail,
                &baseline,
                &shrink,
            );
        }
    };
    if !baseline_accepted {
        let detail = "合法 RVLU_V2 基底未通過 decode／verify";
        report_failure_found(
            "p17_fuzz_rvlu",
            "p17_fuzz_rvlu",
            profile,
            RVLU_SEED,
            0,
            detail,
            &baseline,
        );
        let shrink = minimize_preserving(&baseline, |candidate| {
            matches!(
                catch_unwind(AssertUnwindSafe(|| {
                    rvlu_result(candidate, profile, &verify_limits())
                })),
                Ok(actual) if !actual
            )
        });
        report_shrunk_failure(
            "p17_fuzz_rvlu",
            "p17_fuzz_rvlu",
            profile,
            RVLU_SEED,
            0,
            detail,
            &baseline,
            &shrink,
        );
    }
    let upvalue_baseline = compile_baseline(
        b"local x = 1; return function() return x end\n",
        profile,
        "p17_fuzz_rvlu",
        "p17_fuzz_rvlu",
        RVLU_SEED,
    );

    let mut rng = XorShift64::new(RVLU_SEED);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut explicit_negative_rejects = 0usize;
    for iteration in 0..ITERATIONS {
        let trial = rvlu_trial(iteration, &baseline, &upvalue_baseline, profile, &mut rng);
        let is_accepted = rvlu_trial_result(&trial, profile, iteration);
        if let Some(expected_accepted) = trial.expected {
            if is_accepted != expected_accepted {
                let detail = if expected_accepted {
                    "合法 RVLU_V2 基底遭拒絕"
                } else {
                    "錯誤格式／profile／長度／opcode／限制輸入遭接受"
                };
                report_failure_found(
                    "p17_fuzz_rvlu",
                    "p17_fuzz_rvlu",
                    profile,
                    RVLU_SEED,
                    iteration,
                    detail,
                    &trial.bytes,
                );
                let shrink = minimize_preserving(&trial.bytes, |candidate| {
                    matches!(
                        catch_unwind(AssertUnwindSafe(|| {
                            rvlu_result(candidate, profile, &trial.limits)
                        })),
                        Ok(actual) if actual != expected_accepted
                    )
                });
                report_shrunk_failure(
                    "p17_fuzz_rvlu",
                    "p17_fuzz_rvlu",
                    profile,
                    RVLU_SEED,
                    iteration,
                    detail,
                    &trial.bytes,
                    &shrink,
                );
            }
            if !expected_accepted {
                explicit_negative_rejects += 1;
            }
        }
        if is_accepted {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(accepted + rejected, ITERATIONS);
    assert!(accepted >= 1, "RVLU mutation family 至少接受合法 baseline");
    assert!(
        explicit_negative_rejects >= 12,
        "RVLU header/profile/length/opcode/truncation 與 limit 負例都須拒絕"
    );
    println!(
        "P17_B03_CASE {{\"case_id\":\"p17_fuzz_rvlu\",\"profile\":\"{}\",\"seed\":{},\"iterations\":{},\"outcome\":\"PASS\",\"accepted\":{},\"rejected\":{},\"limits\":{{\"compile_limits\":{{\"max_source_bytes\":4096,\"max_tokens\":4096,\"max_parse_depth\":64}},\"ir_limits\":{{\"max_prototypes\":32,\"max_instructions\":512,\"max_registers\":256,\"max_upvalues_per_prototype\":255}},\"verify_limits\":{{\"max_module_bytes\":16384,\"max_artifact_bytes\":16384,\"max_prototypes\":32,\"max_instructions\":512,\"max_constants\":256,\"max_registers\":256,\"max_upvalues_per_prototype\":255}}}},\"baseline_source\":\"編譯器產生的 RVLU_V2 return 42\",\"explicit_negative_rejects\":{},\"counts_include_baseline_and_twelve_explicit_negative_cases\":true}}",
        profile_id(profile),
        RVLU_SEED,
        ITERATIONS,
        accepted,
        rejected,
        explicit_negative_rejects,
    );
}

fn official_limits() -> OfficialChunkLimits {
    OfficialChunkLimits {
        max_bytes: 16 * 1024,
        max_depth: 8,
        max_prototypes: 32,
        max_instructions: 512,
        max_constants: 256,
        max_upvalues: 256,
        max_debug_entries: 2048,
        max_strings: 256,
        max_string_bytes: 4 * 1024,
        max_total_string_bytes: 8 * 1024,
        max_allocated_bytes: 1024 * 1024,
    }
}

fn official_verify_limits() -> VerifyLimits {
    verify_limits()
}

fn official_fixtures(profile: LuaProfile) -> [(&'static str, &'static [u8]); 3] {
    match profile {
        LuaProfile::Lua55 => [
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac"
                ),
            ),
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua55-strip.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-strip.luac"
                ),
            ),
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua55-closure.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua55-closure.luac"
                ),
            ),
        ],
        LuaProfile::Lua54 => [
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac"
                ),
            ),
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua54-strip.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-strip.luac"
                ),
            ),
            (
                "crates/rivetlua-core/tests/official_chunk_fixtures/lua54-closure.luac",
                include_bytes!(
                    "../../rivetlua-core/tests/official_chunk_fixtures/lua54-closure.luac"
                ),
            ),
        ],
    }
}

fn official_result(
    input: &[u8],
    profile: LuaProfile,
    chunk_limits: &OfficialChunkLimits,
    verify: &VerifyLimits,
) -> Result<(), String> {
    let scan_work = input
        .len()
        .checked_mul(2)
        .and_then(|work| work.checked_add(1))
        .ok_or_else(|| "官方預掃描工作量溢位".to_owned())?;
    let mut work = OfficialWorkBudget::new(OFFICIAL_WORK_UNITS);
    work.charge(scan_work, ProtoId(0), 0)
        .map_err(|error| format!("官方工作額度：{error:?}"))?;
    let preflight = preflight_official_chunk(input, profile, chunk_limits, verify)
        .map_err(|error| format!("官方預掃描：{error:?}"))?;
    let chunk = decode_official_chunk(input, profile, chunk_limits)
        .map_err(|error| format!("官方解碼：{error:?}"))?;
    let translated = translate_official_chunk_with_work(&chunk, verify, &mut work)
        .map_err(|error| format!("官方轉譯：{error:?}"))?;
    if work.consumed() > OFFICIAL_WORK_UNITS {
        return Err("官方工作額度超額".to_owned());
    }
    if translated.verified().profile() != profile || preflight.prototypes == 0 {
        return Err("官方基底 profile／prototype 不變量不符".to_owned());
    }
    Ok(())
}

fn official_attempt(
    input: &[u8],
    profile: LuaProfile,
    chunk_limits: &OfficialChunkLimits,
    verify: &VerifyLimits,
    iteration: usize,
) -> bool {
    match catch_unwind(AssertUnwindSafe(|| {
        official_result(input, profile, chunk_limits, verify).is_ok()
    })) {
        Ok(accepted) => accepted,
        Err(_) => {
            let detail = "官方預掃描／解碼／轉譯 pipeline 發生 panic";
            report_failure_found(
                "p17_fuzz_official_chunk",
                "p17_fuzz_official_chunk",
                profile,
                OFFICIAL_SEED,
                iteration,
                detail,
                input,
            );
            let shrink = minimize_preserving(input, |candidate| {
                catch_unwind(AssertUnwindSafe(|| {
                    official_result(candidate, profile, chunk_limits, verify).is_ok()
                }))
                .is_err()
            });
            report_shrunk_failure(
                "p17_fuzz_official_chunk",
                "p17_fuzz_official_chunk",
                profile,
                OFFICIAL_SEED,
                iteration,
                detail,
                input,
                &shrink,
            );
        }
    }
}

struct OfficialTrial {
    bytes: Vec<u8>,
    limits: OfficialChunkLimits,
    expected: Option<bool>,
}

fn official_trial(
    iteration: usize,
    fixtures: &[(&'static str, &'static [u8]); 3],
    rng: &mut XorShift64,
) -> OfficialTrial {
    let baseline = fixtures[0].1;
    let standard = official_limits();
    match iteration {
        0 => OfficialTrial {
            bytes: baseline.to_vec(),
            limits: standard,
            expected: Some(true),
        },
        1 => {
            let mut bytes = baseline.to_vec();
            bytes[4] ^= 1;
            OfficialTrial {
                bytes,
                limits: standard,
                expected: Some(false),
            }
        }
        2 => {
            let mut bytes = baseline.to_vec();
            bytes.pop();
            OfficialTrial {
                bytes,
                limits: standard,
                expected: Some(false),
            }
        }
        3 => {
            let mut bytes = baseline.to_vec();
            bytes[0] ^= 0xff;
            OfficialTrial {
                bytes,
                limits: standard,
                expected: Some(false),
            }
        }
        4 => {
            let mut limits = standard;
            limits.max_prototypes = 0;
            OfficialTrial {
                bytes: baseline.to_vec(),
                limits,
                expected: Some(false),
            }
        }
        5 => {
            let mut limits = standard;
            limits.max_bytes = baseline.len() - 1;
            OfficialTrial {
                bytes: baseline.to_vec(),
                limits,
                expected: Some(false),
            }
        }
        6 => {
            let mut limits = standard;
            limits.max_depth = 0;
            OfficialTrial {
                bytes: baseline.to_vec(),
                limits,
                expected: Some(false),
            }
        }
        7 => {
            let mut limits = standard;
            limits.max_allocated_bytes = 0;
            OfficialTrial {
                bytes: baseline.to_vec(),
                limits,
                expected: Some(false),
            }
        }
        _ => {
            let fixture = fixtures[(rng.next() as usize) % fixtures.len()].1;
            OfficialTrial {
                bytes: mutate_bytes(fixture, rng, 16 * 1024),
                limits: standard,
                expected: None,
            }
        }
    }
}

#[test]
fn p17_fuzz_official_chunk() {
    let profile = selected_profile();
    let fixtures = official_fixtures(profile);
    let marker = match profile {
        LuaProfile::Lua55 => 0x55,
        LuaProfile::Lua54 => 0x54,
    };
    for (fixture_index, (name, fixture)) in fixtures.iter().enumerate() {
        if fixture.get(4) != Some(&marker) {
            report_failure(
                "p17_fuzz_official_chunk",
                "p17_fuzz_official_chunk",
                profile,
                OFFICIAL_SEED,
                fixture_index,
                &format!("官方 fixture version marker 與 profile 不符：{name}"),
                fixture,
                fixture,
            );
        }
        if !official_attempt(
            fixture,
            profile,
            &official_limits(),
            &official_verify_limits(),
            fixture_index,
        ) {
            report_failure(
                "p17_fuzz_official_chunk",
                "p17_fuzz_official_chunk",
                profile,
                OFFICIAL_SEED,
                fixture_index,
                &format!("官方 golden 未完成預掃描／解碼／轉譯：{name}"),
                fixture,
                fixture,
            );
        }
    }

    let mut rng = XorShift64::new(OFFICIAL_SEED);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut explicit_negative_rejects = 0usize;
    for iteration in 0..ITERATIONS {
        let trial = official_trial(iteration, &fixtures, &mut rng);
        let is_accepted = official_attempt(
            &trial.bytes,
            profile,
            &trial.limits,
            &official_verify_limits(),
            iteration,
        );
        if let Some(expected_accepted) = trial.expected {
            if is_accepted != expected_accepted {
                let detail = if expected_accepted {
                    "官方 golden 基底遭拒絕"
                } else {
                    "明確錯誤格式／計數／大小／深度／配置限制輸入遭接受"
                };
                report_failure_found(
                    "p17_fuzz_official_chunk",
                    "p17_fuzz_official_chunk",
                    profile,
                    OFFICIAL_SEED,
                    iteration,
                    detail,
                    &trial.bytes,
                );
                let shrink = minimize_preserving(&trial.bytes, |candidate| {
                    matches!(
                        catch_unwind(AssertUnwindSafe(|| {
                            official_result(
                                candidate,
                                profile,
                                &trial.limits,
                                &official_verify_limits(),
                            )
                            .is_ok()
                        })),
                        Ok(actual) if actual != expected_accepted
                    )
                });
                report_shrunk_failure(
                    "p17_fuzz_official_chunk",
                    "p17_fuzz_official_chunk",
                    profile,
                    OFFICIAL_SEED,
                    iteration,
                    detail,
                    &trial.bytes,
                    &shrink,
                );
            }
            if !expected_accepted {
                explicit_negative_rejects += 1;
            }
        }
        if is_accepted {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(accepted + rejected, ITERATIONS);
    assert!(
        accepted >= 1,
        "official mutation family 至少接受 golden baseline"
    );
    assert_eq!(explicit_negative_rejects, 7);
    println!(
        "P17_B03_CASE {{\"case_id\":\"p17_fuzz_official_chunk\",\"profile\":\"{}\",\"seed\":{},\"iterations\":{},\"outcome\":\"PASS\",\"accepted\":{},\"rejected\":{},\"official\":{{\"version_marker\":{},\"chunk_limits\":{{\"max_bytes\":16384,\"max_depth\":8,\"max_prototypes\":32,\"max_instructions\":512,\"max_constants\":256,\"max_upvalues\":256,\"max_debug_entries\":2048,\"max_strings\":256,\"max_string_bytes\":4096,\"max_total_string_bytes\":8192,\"max_allocated_bytes\":1048576}},\"verify_limits\":{{\"max_module_bytes\":16384,\"max_artifact_bytes\":16384,\"max_prototypes\":32,\"max_instructions\":512,\"max_constants\":256,\"max_registers\":256,\"max_upvalues_per_prototype\":255}},\"work_budget\":1000000,\"baseline_fixtures\":3}},\"explicit_negative_rejects\":{},\"counts_include_baseline_and_seven_explicit_negative_cases\":true}}",
        profile_id(profile),
        OFFICIAL_SEED,
        ITERATIONS,
        accepted,
        rejected,
        marker,
        explicit_negative_rejects,
    );
}
