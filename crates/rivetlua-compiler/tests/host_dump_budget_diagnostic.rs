//! 顯式 fixture 診斷：以 SDK 的 native debug producer 測量官方 dump 准入。

use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_export::{OfficialExportErrorKind, emit_official_chunk};
use rivetlua_core::bytecode::official_translation::{
    OfficialWorkBudget, translate_official_chunk_with_work,
};
use rivetlua_core::{LuaProfile, ProtoId, VerifiedModule, VerifyLimits, preflight_official_chunk};
use std::time::Instant;

#[derive(Default)]
struct CliCompileSink {
    work: usize,
    temporary: usize,
    module: usize,
}

impl CompileBudgetSink for CliCompileSink {
    type Error = &'static str;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work = self
            .work
            .checked_add(units)
            .ok_or("compile work overflow")?;
        (self.work <= 2 * 1024 * 1024 * 1024)
            .then_some(())
            .ok_or("compile work limit")
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary = self
            .temporary
            .checked_add(bytes)
            .ok_or("compile temporary overflow")?;
        (self.temporary <= 256 * 1024 * 1024)
            .then_some(())
            .ok_or("compile temporary limit")
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.module = self
            .module
            .checked_add(bytes)
            .ok_or("compile module overflow")?;
        (self.module <= 64 * 1024 * 1024)
            .then_some(())
            .ok_or("compile module limit")
    }
}

fn compile_native(source: &[u8], chunk_name: &[u8], profile: LanguageProfile) -> VerifiedModule {
    let mut sink = CliCompileSink::default();
    let module = compile_with_budget(
        source,
        chunk_name,
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut sink,
    )
    .unwrap_or_else(|error| panic!("native producer 編譯失敗：{error:?}"));
    assert!(module.native_debug().is_some());
    eprintln!(
        "producer profile={profile:?} source_len={} chunk_name={:?} functions={} native_debug=true native_helper={} work={} temporary={} module_claim={}",
        source.len(),
        chunk_name,
        module.module().prototypes.len(),
        module
            .official_execution()
            .is_some_and(|plan| plan.is_native_builtin()),
        sink.work,
        sink.temporary,
        sink.module,
    );
    module
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DumpResult {
    Success,
    ExportFailure(OfficialExportErrorKind),
    PostOutputWorkFailure,
}

#[test]
fn sequential_call_cleanup_does_not_exhaust_official_stack() {
    let mut source = b"local function f() end\n".to_vec();
    for _ in 0..260 {
        source.extend_from_slice(b"f()\n");
    }
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = compile_native(&source, b"=sequential-calls", language);
        assert!(
            module.module().prototypes[0].register_count > 255,
            "register count={} 在本回歸案例應超出官方 stack 總槽數",
            module.module().prototypes[0].register_count,
        );
        for strip in [false, true] {
            let mut limits = OfficialChunkLimits::default();
            limits.max_bytes = limits.max_bytes.min(1024 * 1024);
            limits.max_allocated_bytes = limits.max_allocated_bytes.min(4 * 1024 * 1024);
            let mut work = OfficialWorkBudget::new(64 * 1024 * 1024);
            let bytes =
                emit_official_chunk(&module, ProtoId(0), profile, strip, &limits, &mut work)
                    .unwrap_or_else(|error| panic!("{profile:?}/strip={strip}: {error:?}"));
            let decoded = decode_official_chunk(&bytes, profile, &limits).unwrap();
            assert!(decoded.main.max_stack_size < 255);
            let call_pcs = decoded
                .main
                .code
                .iter()
                .enumerate()
                .filter_map(|(pc, word)| (word & 0x7f == 68).then_some(pc))
                .take(2)
                .collect::<Vec<_>>();
            assert_eq!(call_pcs.len(), 2);
            assert!(
                decoded.main.code[call_pcs[0] + 1..call_pcs[1]]
                    .iter()
                    .any(|word| word & 0x7f == 8),
                "{profile:?}/strip={strip}: Call 後仍須輸出實體槽的 nil cleanup"
            );
            let exact_work = work.consumed();
            let mut tight_work = OfficialWorkBudget::new(exact_work);
            assert_eq!(
                emit_official_chunk(
                    &module,
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut tight_work,
                )
                .unwrap(),
                bytes
            );
            let mut short_work = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                emit_official_chunk(
                    &module,
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut short_work,
                )
                .unwrap_err()
                .kind,
                OfficialExportErrorKind::WorkExhausted
            );
            let mut short_output = limits;
            short_output.max_bytes = bytes.len() - 1;
            assert_eq!(
                emit_official_chunk(
                    &module,
                    ProtoId(0),
                    profile,
                    strip,
                    &short_output,
                    &mut OfficialWorkBudget::new(64 * 1024 * 1024),
                )
                .unwrap_err()
                .kind,
                OfficialExportErrorKind::LimitExceeded
            );
        }
    }
}

fn dump_case(
    case: &str,
    module: &VerifiedModule,
    profile: LuaProfile,
    strip: bool,
    work_limit: u64,
    allocated_limit: usize,
    encoded_limit: usize,
) -> DumpResult {
    let selected = ProtoId(0);
    let mut limits = OfficialChunkLimits::default();
    limits.max_bytes = limits.max_bytes.min(encoded_limit);
    limits.max_allocated_bytes = limits.max_allocated_bytes.min(allocated_limit);
    let mut work = OfficialWorkBudget::new(work_limit);
    match emit_official_chunk(module, selected, profile, strip, &limits, &mut work) {
        Ok(bytes) => {
            let len = bytes.len();
            let header = bytes.get(..6);
            match work.charge(len, selected, 0) {
                Ok(()) => {
                    let decoded =
                        decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default())
                            .unwrap_or_else(|error| {
                                panic!("離線官方 chunk round-trip 失敗：{error:?}")
                            });
                    assert_eq!(decoded.profile, profile);
                    eprintln!(
                        "case={case} strip={strip} work_limit={work_limit} max_bytes={} allocated_limit={} status=PASS export=PASS post_output=PASS offline_decode=PASS encoded_len={len} header={header:?} consumed={} remaining={}",
                        limits.max_bytes,
                        limits.max_allocated_bytes,
                        work.consumed(),
                        work.remaining(),
                    );
                    DumpResult::Success
                }
                Err(error) => {
                    eprintln!(
                        "case={case} strip={strip} work_limit={work_limit} max_bytes={} allocated_limit={} status=FAIL phase=post_output kind={:?} prototype={} pc={} detail={:?} encoded_len={len} header={header:?} consumed={} remaining={}",
                        limits.max_bytes,
                        limits.max_allocated_bytes,
                        error.kind,
                        error.prototype.0,
                        error.pc,
                        error.detail,
                        work.consumed(),
                        work.remaining(),
                    );
                    DumpResult::PostOutputWorkFailure
                }
            }
        }
        Err(error) => {
            eprintln!(
                "case={case} strip={strip} work_limit={work_limit} max_bytes={} allocated_limit={} status=FAIL phase=export kind={:?} prototype={} pc={} detail={:?} consumed={} remaining={}",
                limits.max_bytes,
                limits.max_allocated_bytes,
                error.kind,
                error.prototype.0,
                error.pc,
                error.detail,
                work.consumed(),
                work.remaining(),
            );
            DumpResult::ExportFailure(error.kind)
        }
    }
}

#[test]
#[ignore = "需明示 RIVETLUA_HOSTLOAD_MAIN 與 RIVETLUA_HOST_DUMP_ADMISSION"]
fn record_native_host_dump_default_and_finite_calibration() {
    let main_path = std::env::var_os("RIVETLUA_HOSTLOAD_MAIN")
        .expect("須以 RIVETLUA_HOSTLOAD_MAIN 指定本次唯讀官方 main.lua");
    let main_raw = std::fs::read(main_path).unwrap();
    assert_eq!(main_raw.len(), 16_146);
    let first_line_end = main_raw.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut main = vec![b'\n'];
    main.extend_from_slice(&main_raw[first_line_end..]);
    assert_eq!(main.len(), 16_107);
    eprintln!(
        "fixture raw_len={} normalized_len={} expected_raw_sha256=844d13f96bdbf03a554b8b466fdf21aeac2bcddb907ad2b971814c994898d457",
        main_raw.len(),
        main.len()
    );

    let admission = std::env::var("RIVETLUA_HOST_DUMP_ADMISSION")
        .expect("須指定 ordinary/strip:work:temporary:encoded 單一准入");
    let fields: Vec<_> = admission.split(':').collect();
    assert_eq!(fields.len(), 4, "單一准入格式錯誤");
    let strip = match fields[0] {
        "ordinary" => false,
        "strip" => true,
        _ => panic!("未知 dump 模式"),
    };
    let work_limit = fields[1].parse::<u64>().expect("work 必須為 u64");
    let allocated_limit = fields[2].parse::<usize>().expect("temporary 必須為 usize");
    let encoded_limit = fields[3].parse::<usize>().expect("encoded 必須為 usize");
    eprintln!("diagnostic start admission={admission}");
    let started = Instant::now();
    let main_module = compile_native(&main, b"@main.lua", LanguageProfile::Lua55);
    let result = dump_case(
        &admission,
        &main_module,
        LuaProfile::Lua55,
        strip,
        work_limit,
        allocated_limit,
        encoded_limit,
    );
    eprintln!(
        "diagnostic completed admission={admission} result={result:?} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

#[test]
#[ignore = "需明示 RIVETLUA_HOSTLOAD_DB 與 RIVETLUA_HOST_DUMP_ADMISSION"]
fn record_db_host_dump_admission() {
    let path = std::env::var_os("RIVETLUA_HOSTLOAD_DB")
        .expect("須以 RIVETLUA_HOSTLOAD_DB 指定未修改的 db.lua");
    let source = std::fs::read(path).unwrap();
    let admission = std::env::var("RIVETLUA_HOST_DUMP_ADMISSION")
        .expect("須指定 ordinary/strip:work:temporary:encoded 單一准入");
    let fields: Vec<_> = admission.split(':').collect();
    assert_eq!(fields.len(), 4, "單一准入格式錯誤");
    let strip = match fields[0] {
        "ordinary" => false,
        "strip" => true,
        _ => panic!("未知 dump 模式"),
    };
    let work_limit = fields[1].parse::<u64>().expect("work 必須為 u64");
    let allocated_limit = fields[2].parse::<usize>().expect("temporary 必須為 usize");
    let encoded_limit = fields[3].parse::<usize>().expect("encoded 必須為 usize");
    eprintln!(
        "db fixture source_len={} admission={admission}",
        source.len()
    );
    let started = Instant::now();
    let module = compile_native(&source, b"@db.lua", LanguageProfile::Lua55);
    let result = dump_case(
        &admission,
        &module,
        LuaProfile::Lua55,
        strip,
        work_limit,
        allocated_limit,
        encoded_limit,
    );
    eprintln!(
        "db diagnostic completed result={result:?} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    if std::env::var_os("RIVETLUA_HOST_LOAD_DIAG").is_some() {
        let mut export_limits = OfficialChunkLimits::default();
        export_limits.max_bytes = 1024 * 1024;
        export_limits.max_allocated_bytes = 4 * 1024 * 1024;
        let mut export_work = OfficialWorkBudget::new(1024 * 1024 * 1024);
        let bytes = emit_official_chunk(
            &module,
            ProtoId(0),
            LuaProfile::Lua55,
            strip,
            &export_limits,
            &mut export_work,
        )
        .unwrap();
        if let Some(path) = std::env::var_os("RIVETLUA_HOST_DUMP_OUTPUT") {
            std::fs::write(&path, &bytes).unwrap();
            eprintln!("db official product chunk written to {path:?}");
        }
        let verify = VerifyLimits::default();
        let mut load_limits = OfficialChunkLimits::default();
        load_limits.max_bytes = load_limits.max_bytes.min(64 * 1024 * 1024);
        load_limits.max_prototypes = load_limits.max_prototypes.min(verify.max_prototypes);
        load_limits.max_instructions = load_limits.max_instructions.min(verify.max_instructions);
        load_limits.max_constants = load_limits.max_constants.min(verify.max_constants);
        load_limits.max_allocated_bytes = load_limits.max_allocated_bytes.min(256 * 1024 * 1024);
        let preflight = preflight_official_chunk(&bytes, LuaProfile::Lua55, &load_limits, &verify);
        eprintln!(
            "db official reload preflight encoded_len={} result={preflight:?}",
            bytes.len()
        );
        if let Ok(stats) = preflight {
            load_limits.max_allocated_bytes =
                load_limits.max_allocated_bytes.min(stats.decoded_bytes);
            let decoded = decode_official_chunk(&bytes, LuaProfile::Lua55, &load_limits);
            eprintln!(
                "db official reload decode={:?}",
                decoded.as_ref().map(|_| ())
            );
            if let Ok(decoded) = decoded {
                let mut work = OfficialWorkBudget::new(stats.subsequent_work);
                let translated = translate_official_chunk_with_work(&decoded, &verify, &mut work);
                eprintln!(
                    "db official reload translate={:?} work_consumed={} work_remaining={}",
                    translated.as_ref().map(|_| ()),
                    work.consumed(),
                    work.remaining(),
                );
                if let Ok(translated) = &translated {
                    let verified = translated.verified();
                    eprintln!(
                        "db official reload actual_retained={} artifact_allocated={}",
                        rivetlua_core::verified_module_allocation_bytes(verified).unwrap(),
                        verified.official_artifact().unwrap().allocated_bytes(),
                    );
                    let mut low = 0;
                    let mut high = load_limits.max_allocated_bytes;
                    while low + 1 < high {
                        let mid = low + (high - low) / 2;
                        let mut trial = load_limits;
                        trial.max_allocated_bytes = mid;
                        if decode_official_chunk(&bytes, LuaProfile::Lua55, &trial).is_ok() {
                            high = mid;
                        } else {
                            low = mid;
                        }
                    }
                    eprintln!("db official reload minimum_decode_allocation_limit={high}");
                }
                if let Some(failure_pc) = translated.as_ref().err().map(|error| error.pc)
                    && !decoded.main.debug.line_info.is_empty()
                {
                    let end = decoded.main.code.len().min(failure_pc.saturating_add(6));
                    let mut line = i64::from(decoded.main.line_defined);
                    for pc in 0..end {
                        let delta = decoded.main.debug.line_info[pc];
                        if delta == -128 {
                            line = i64::from(
                                decoded
                                    .main
                                    .debug
                                    .abs_line_info
                                    .iter()
                                    .find(|entry| entry.pc as usize == pc)
                                    .unwrap()
                                    .line,
                            );
                        } else {
                            line += i64::from(delta);
                        }
                        if pc < failure_pc.saturating_sub(6) {
                            continue;
                        }
                        let word = decoded.main.code[pc];
                        eprintln!(
                            "db official pc={pc} word=0x{word:08x} opcode={} A={} B={} C={} vB={} vC={} k={} line={line}",
                            word & 0x7f,
                            (word >> 7) & 0xff,
                            (word >> 16) & 0xff,
                            (word >> 24) & 0xff,
                            (word >> 16) & 0x3f,
                            (word >> 22) & 0x3ff,
                            (word >> 15) & 1,
                        );
                        if pc == failure_pc {
                            if let Some(native) = module
                                .native_debug()
                                .and_then(|entry| entry.prototype(ProtoId(0)))
                            {
                                for (source_pc, &source_line) in native.lines.iter().enumerate() {
                                    if i64::from(source_line) == line {
                                        eprintln!(
                                            "db source candidate ir_pc={source_pc} line={source_line} instruction={:?}",
                                            module.module().prototypes[0].instructions[source_pc]
                                                .instruction,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if std::env::var_os("RIVETLUA_HOST_DUMP_CALIBRATE").is_some() {
        let mut generous_limits = OfficialChunkLimits::default();
        generous_limits.max_bytes = 1024 * 1024;
        generous_limits.max_allocated_bytes = 4 * 1024 * 1024;
        let mut generous_work = OfficialWorkBudget::new(1024 * 1024 * 1024);
        let bytes = emit_official_chunk(
            &module,
            ProtoId(0),
            LuaProfile::Lua55,
            strip,
            &generous_limits,
            &mut generous_work,
        )
        .unwrap();
        generous_work.charge(bytes.len(), ProtoId(0), 0).unwrap();
        let exact_work = generous_work.consumed();
        let exact_encoded = bytes.len();
        let mut low = 0_usize;
        let mut high = generous_limits.max_allocated_bytes;
        while low + 1 < high {
            let mid = low + (high - low) / 2;
            let mut limits = generous_limits;
            limits.max_allocated_bytes = mid;
            let mut work = OfficialWorkBudget::new(exact_work);
            if emit_official_chunk(
                &module,
                ProtoId(0),
                LuaProfile::Lua55,
                strip,
                &limits,
                &mut work,
            )
            .is_ok()
            {
                high = mid;
            } else {
                low = mid;
            }
        }
        eprintln!(
            "db exact strip={strip} work={exact_work} temporary={high} encoded={exact_encoded}"
        );
        assert_eq!(
            dump_case(
                "db-exact",
                &module,
                LuaProfile::Lua55,
                strip,
                exact_work,
                high,
                exact_encoded,
            ),
            DumpResult::Success
        );
        assert_ne!(
            dump_case(
                "db-work-one-below",
                &module,
                LuaProfile::Lua55,
                strip,
                exact_work - 1,
                high,
                exact_encoded,
            ),
            DumpResult::Success
        );
        assert_ne!(
            dump_case(
                "db-temporary-one-below",
                &module,
                LuaProfile::Lua55,
                strip,
                exact_work,
                high - 1,
                exact_encoded,
            ),
            DumpResult::Success
        );
        assert_ne!(
            dump_case(
                "db-encoded-one-below",
                &module,
                LuaProfile::Lua55,
                strip,
                exact_work,
                high,
                exact_encoded - 1,
            ),
            DumpResult::Success
        );
    }
}
