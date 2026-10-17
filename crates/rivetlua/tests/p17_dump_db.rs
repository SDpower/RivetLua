use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::{OfficialExportErrorKind, emit_official_chunk};
use rivetlua_core::{
    Instruction, IrLimits, LuaProfile, OfficialChunkLimits, OfficialConstant, OfficialWorkBudget,
    ProtoId, Register, ResultMode, Value, VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{RootKind, RunOutcome, Vm};

const SOURCE: &[u8] = br#"
local function entries()
  return {alpha = 11, beta = 19}
end

local function check()
  local expected = {alpha = 11, beta = 19}
  local sum = 0
  for key, value in pairs(entries()) do
    assert(expected[key] == value)
    expected[key] = nil
    sum = sum + value
  end
  assert(next(expected) == nil)
  return sum
end

return check()
"#;

struct Unlimited;

impl CompileBudgetSink for Unlimited {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn has_open_call_with_redefined_result(module: &rivetlua_core::VerifiedModule) -> bool {
    module.module().prototypes.iter().any(|proto| {
        proto.instructions.windows(2).enumerate().any(|(pc, pair)| {
            let (
                Instruction::Call {
                    base: producer,
                    result_mode: ResultMode::All,
                    ..
                },
                Instruction::Call {
                    base: terminal,
                    arg_count: u16::MAX,
                    result_mode: ResultMode::Fixed(results),
                },
            ) = (&pair[0].instruction, &pair[1].instruction)
            else {
                return false;
            };
            let Some(register) = producer.0.checked_add(1).map(Register) else {
                return false;
            };
            register.0 >= terminal.0
                && register.0 - terminal.0 < *results
                && proto.instructions.iter().skip(pc + 2).any(|entry| {
                    matches!(&entry.instruction, Instruction::Move { src, .. } if *src == register)
                })
        })
    })
}

#[test]
fn p17_dump_open_call_terminal_results_roundtrip() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = compile_with_budget(
            SOURCE,
            b"@p17-db-open-call.lua",
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut Unlimited,
        )
        .unwrap();
        assert!(
            has_open_call_with_redefined_result(&module),
            "{profile:?} 未產生本次回歸的開放引數與固定結果鏈"
        );

        // work 失敗不改變已驗證模組；新額度可在同一模組重試。
        let original = module.clone();
        let exhausted = emit_official_chunk(
            &module,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut OfficialWorkBudget::new(0),
        )
        .unwrap_err();
        assert_eq!(exhausted.kind, OfficialExportErrorKind::WorkExhausted);
        assert_eq!(module, original);

        for strip in [false, true] {
            let bytes = emit_official_chunk(
                &module,
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap_or_else(|error| panic!("{profile:?} strip={strip}: {error:?}"));
            let decoded =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            if strip {
                assert!(decoded.main.source.is_none());
                assert!(decoded.main.debug.line_info.is_empty());
            } else {
                assert_eq!(
                    decoded.main.source.as_deref(),
                    Some(b"@p17-db-open-call.lua".as_slice())
                );
                assert!(!decoded.main.debug.line_info.is_empty());
            }
            let imported = translate_official_chunk(&decoded, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            for (origin, candidate) in [("native", module.clone()), ("official", imported)] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let environment = vm.allocate_table().unwrap();
                let root = vm.add_root(RootKind::Host, environment).unwrap();
                vm.install_basic_builtins(environment).unwrap();
                let outcome = {
                    let mut execution = vm
                        .load_with_environment(candidate, Value::Object(environment))
                        .unwrap();
                    execution.run().unwrap()
                };
                assert_eq!(
                    outcome,
                    RunOutcome::Returned(vec![Value::Integer(30)]),
                    "{profile:?} strip={strip} origin={origin}"
                );
                vm.remove_root(root).unwrap();
            }
        }
    }
}

#[test]
fn p17_full_db_dump_obeys_cli_finite_quota() {
    let evidence = std::env::var("RIVETLUA_P17_EVIDENCE_DIR").unwrap();
    let fixtures = [
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            "b01-lua55-i64f64-85855-1791613374781148000/fixture/lua-5.5.1-tests/db.lua",
        ),
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            "b01-lua54-i64f64-85855-1791613383015514000/fixture/lua-5.4.9-tests/db.lua",
        ),
    ];
    let mut failures = Vec::new();
    for (language, profile, path) in fixtures {
        let source = std::fs::read(std::path::Path::new(&evidence).join(path)).unwrap();
        let module = compile_with_budget(
            &source,
            b"@db.lua",
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut Unlimited,
        )
        .unwrap();
        let limits = OfficialChunkLimits {
            max_bytes: 1024 * 1024,
            max_allocated_bytes: 4 * 1024 * 1024,
            ..OfficialChunkLimits::default()
        };
        let mut work = OfficialWorkBudget::new(512 * 1024 * 1024);
        match emit_official_chunk(&module, ProtoId(0), profile, false, &limits, &mut work) {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                let consumed = work.consumed();
                let mut one_short = OfficialWorkBudget::new(consumed - 1);
                let error = emit_official_chunk(
                    &module,
                    ProtoId(0),
                    profile,
                    false,
                    &limits,
                    &mut one_short,
                )
                .expect_err("少一 work 單位必須拒絕");
                assert_eq!(error.kind, OfficialExportErrorKind::WorkExhausted);
                let mut exact = OfficialWorkBudget::new(consumed);
                let exact_bytes =
                    emit_official_chunk(&module, ProtoId(0), profile, false, &limits, &mut exact)
                        .unwrap();
                assert_eq!(exact.consumed(), consumed);
                assert_eq!(exact_bytes, bytes);
                let decoded = decode_official_chunk(&bytes, profile, &limits).unwrap();
                let imported = translate_official_chunk(&decoded, &VerifyLimits::default())
                    .unwrap()
                    .verified()
                    .clone();
                let lines = imported
                    .official_artifact()
                    .unwrap()
                    .pc_map(ProtoId(0))
                    .unwrap();
                let count_line = if profile == LuaProfile::Lua55 {
                    603
                } else {
                    597
                };
                // 完整 db.lua 的後段 assert key 超過 8-bit 索引，須重用較早的同值常數。
                assert!(decoded.main.code.iter().enumerate().any(|(pc, word)| {
                    let field = ((word >> 24) & 0xff) as usize;
                    word & 0x7f == 11
                        && lines.line_at_official(pc as u32) == Some(count_line)
                        && matches!(decoded.main.constants.get(field),
                            Some(OfficialConstant::String { bytes, .. }) if bytes.as_slice() == b"assert")
                }), "{profile:?} count 斷言未以既有字串常數融合 GETTABUP");
                eprintln!("{profile:?}: encoded={} work={consumed}", bytes.len());
            }
            Err(error) => {
                eprintln!(
                    "{profile:?}: {error:?} work={} remaining={}",
                    work.consumed(),
                    work.remaining()
                );
                failures.push(format!("{profile:?}: {error:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
