use rivetlua_compiler::{
    CompileLimits, Instruction, IrLimits, LanguageProfile, LuaProfile, ProtoId, ResultMode,
    VerifyLimits, emit, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_export::{OfficialExportErrorKind, emit_official_chunk};
use rivetlua_core::bytecode::official_translation::OfficialWorkBudget;
use rivetlua_core::bytecode::official_translation::translate_official_chunk;
use std::process::Command;

fn native_ir_with_resolved(
    source: &[u8],
    profile: LanguageProfile,
) -> (
    rivetlua_compiler::ResolvedModule,
    rivetlua_compiler::IrModule,
) {
    let compile_limits = CompileLimits::default();
    let chunk = lex(source, profile, &compile_limits).unwrap();
    let syntax = parse(&chunk, profile, &compile_limits).unwrap();
    let resolved = resolve(&syntax, &chunk, profile, &compile_limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    (resolved, ir)
}

fn native_ir(source: &[u8], profile: LanguageProfile) -> rivetlua_compiler::IrModule {
    native_ir_with_resolved(source, profile).1
}

fn native_module(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    emit(&native_ir(source, profile), &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

#[test]
fn native_pending_call_uses_visible_official_slots_before_callee_in_both_profiles() {
    for (source, pending_count) in [
        (
            b"function f() return 20 end\nfunction g(a,b) return (a+1)+f() end\nreturn g\n"
                .as_slice(),
            1usize,
        ),
        (
            b"function f() return 30 end\nfunction g(a,b) return (a+1)+((b+2)+f()) end\nreturn g\n"
                .as_slice(),
            2usize,
        ),
    ] {
        for (language, profile) in [
            (LanguageProfile::Lua55, LuaProfile::Lua55),
            (LanguageProfile::Lua54, LuaProfile::Lua54),
        ] {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@pending-call.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let module = emitted.verified();
            let g = module
                .module()
                .prototypes
                .iter()
                .find(|proto| proto.parameter_count == 2)
                .unwrap();
            let pending = module
                .native_debug()
                .unwrap()
                .temporaries_for(g.id)
                .unwrap();
            assert_eq!(pending.len(), pending_count, "{profile:?}");
            for (index, entry) in pending.iter().enumerate() {
                assert_eq!(usize::from(entry.ordinal), index + 1, "{profile:?}");
            }
            let export = |strip| {
                let bytes = emit_official_chunk(
                    module,
                    g.id,
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap();
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap()
            };
            let full = export(false);
            let strip = export(true);
            assert_eq!(full.main.code, strip.main.code, "{profile:?}");
            assert_eq!(full.main.debug.locals.len(), 2, "{profile:?}");
            assert!(strip.main.debug.locals.is_empty(), "{profile:?}");
            let call_slots: Vec<_> = full
                .main
                .code
                .iter()
                .filter(|word| *word & 0x7f == 68)
                .map(|word| (word >> 7) & 0xff)
                .collect();
            assert_eq!(call_slots, [u32::try_from(2 + pending_count).unwrap()]);
            for slot in 2..2 + pending_count {
                let slot = u32::try_from(slot).unwrap();
                assert!(
                    full.main
                        .code
                        .iter()
                        .any(|word| { *word & 0x7f == 34 && (word >> 7) & 0xff == slot }),
                    "{profile:?}: pending slot {slot} 缺少算術產生者"
                );
            }
            assert!(
                usize::from(full.main.max_stack_size) > 2 + pending_count,
                "{profile:?}"
            );
        }
    }
}

#[test]
fn native_pending_call_reuses_outer_input_slot_after_dead_cleanup_write() {
    let source = b"local function getoutput() return 'abc' end\nlocal function sink() end\nsink()\nlocal release=string.match(getoutput(),'a')\nreturn release\n";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@nested-dead-cleanup.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        for strip in [false, true] {
            let defaults = OfficialChunkLimits::default();
            let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
            let bytes = emit_official_chunk(
                emitted.verified(),
                ProtoId(0),
                profile,
                strip,
                &defaults,
                &mut unrestricted,
            )
            .unwrap();
            assert!(!bytes.is_empty(), "{profile:?} strip={strip}");
            let exact_work = unrestricted.consumed();
            let mut below = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &defaults,
                    &mut below
                )
                .unwrap_err()
                .kind,
                OfficialExportErrorKind::WorkExhausted
            );
            let mut exact = OfficialWorkBudget::new(exact_work);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &defaults,
                    &mut exact
                )
                .unwrap(),
                bytes
            );
            assert_eq!(exact.remaining(), 0);

            let mut low = 1usize;
            let mut high = defaults.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                let mut limits = defaults;
                limits.max_allocated_bytes = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work,
                )
                .is_ok()
                {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            let mut limits = defaults;
            limits.max_allocated_bytes = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work
                )
                .unwrap(),
                bytes
            );
            limits.max_allocated_bytes -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work
                )
                .unwrap_err()
                .kind,
                OfficialExportErrorKind::LimitExceeded
            );

            let mut low = 1usize;
            let mut high = defaults.max_instructions;
            while low < high {
                let mid = low + (high - low) / 2;
                let mut limits = defaults;
                limits.max_instructions = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work,
                )
                .is_ok()
                {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            limits = defaults;
            limits.max_instructions = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work
                )
                .unwrap(),
                bytes
            );
            limits.max_instructions -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &limits,
                    &mut work
                )
                .unwrap_err()
                .kind,
                OfficialExportErrorKind::LimitExceeded
            );
        }
    }
}

#[test]
fn native_open_result_chain_with_pending_nested_calls_exports() {
    let source = b"local func=load(string.dump(load('print(10)'), true)); return func";
    let mut failures = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@open-result-chain.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        for strip in [false, true] {
            let result = emit_official_chunk(
                emitted.verified(),
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            );
            if let Err(error) = result {
                failures.push(format!("{profile:?} strip={strip}: {error:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn native_open_chain_reloads_global_environment_cache_after_dynamic_result() {
    for (case, source) in [
        (
            "local-call",
            b"function f() return 1 end; assert(f()); return print".as_slice(),
        ),
        (
            "os-execute-shape",
            b"assert(os.execute()); return print".as_slice(),
        ),
    ] {
        for (language, profile) in [
            (LanguageProfile::Lua54, LuaProfile::Lua54),
            (LanguageProfile::Lua55, LuaProfile::Lua55),
        ] {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@open-chain-environment-cache.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            for strip in [false, true] {
                let bytes = emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap_or_else(|error| panic!("{case} {profile:?} strip={strip}: {error:?}"));
                let decoded =
                    decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default())
                        .unwrap();
                assert_eq!(decoded.main.upvalues.len(), 1, "{case} {profile:?}");
                assert!(decoded.main.upvalues[0].in_stack, "{case} {profile:?}");
            }
        }
    }
}

#[test]
fn native_open_chain_reloads_nested_parent_environment_sources() {
    for (case, source, explicit_capture) in [
        (
            "parent-frame",
            b"function f() return 1 end; local function outer() return function() assert(f()); return print end end; return outer()".as_slice(),
            false,
        ),
        (
            "parent-upvalue",
            b"function f() return 1 end; local function outer() local prior=_ENV; return function() local keep=_ENV; assert(f()); return print end end; return outer()".as_slice(),
            true,
        ),
    ] {
        for (language, profile) in [
            (LanguageProfile::Lua54, LuaProfile::Lua54),
            (LanguageProfile::Lua55, LuaProfile::Lua55),
        ] {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@nested-open-chain-environment.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let child = emitted
                .verified()
                .module()
                .prototypes
                .iter()
                .find(|proto| {
                    proto.parent.is_some()
                        && proto.instructions.iter().any(|entry| {
                            matches!(
                                entry.instruction,
                                Instruction::Call {
                                    result_mode: ResultMode::All,
                                    ..
                                }
                            )
                        })
                })
                .unwrap();
            assert_eq!(
                matches!(
                    child.frame.environment_source,
                    rivetlua_compiler::EnvironmentSource::ParentUpvalue { .. }
                ),
                explicit_capture || profile == LuaProfile::Lua54,
                "{case} {profile:?}"
            );
            for strip in [false, true] {
                let bytes = emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap_or_else(|error| {
                    panic!("{case} {profile:?} strip={strip}: {error:?}")
                });
                let decoded =
                    decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default())
                        .unwrap();
                assert_eq!(decoded.main.upvalues.len(), 1, "{case} {profile:?}");
            }
        }
    }
}

#[test]
fn native_open_chain_environment_cache_has_exact_work_and_instruction_limits() {
    let source = b"function f() return 1 end; assert(f()); return print";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@open-chain-env-limits.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        for strip in [false, true] {
            let defaults = OfficialChunkLimits::default();
            let export = |limits: &OfficialChunkLimits, work: &mut OfficialWorkBudget| {
                emit_official_chunk(emitted.verified(), ProtoId(0), profile, strip, limits, work)
            };
            let mut unlimited = OfficialWorkBudget::new(u64::MAX);
            let bytes = export(&defaults, &mut unlimited).unwrap();
            let exact_work = unlimited.consumed();
            assert!(exact_work > 0);
            let mut exact = OfficialWorkBudget::new(exact_work);
            assert_eq!(export(&defaults, &mut exact).unwrap(), bytes);
            assert_eq!(exact.remaining(), 0);
            let mut short = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                export(&defaults, &mut short).unwrap_err().kind,
                OfficialExportErrorKind::WorkExhausted,
                "{profile:?} strip={strip}"
            );

            let decoded = decode_official_chunk(&bytes, profile, &defaults).unwrap();
            let mut limits = defaults;
            limits.max_instructions = decoded.main.code.len()
                + decoded
                    .main
                    .children
                    .iter()
                    .map(|child| child.code.len())
                    .sum::<usize>();
            assert_eq!(
                export(&limits, &mut OfficialWorkBudget::new(u64::MAX)).unwrap(),
                bytes
            );
            limits.max_instructions -= 1;
            assert_eq!(
                export(&limits, &mut OfficialWorkBudget::new(u64::MAX))
                    .unwrap_err()
                    .kind,
                OfficialExportErrorKind::LimitExceeded,
                "{profile:?} strip={strip}"
            );
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_open_chain_c_loader_preserves_nested_callees() {
    let cases: &[(&[u8], &str, &[u8])] = &[
        (
            b"local func=load(string.dump(load('return 19'), true)); return func",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f()())",
            b"19\n",
        ),
        (
            b"a=7; function g() return 2,3 end; function f(a,b,c,d) return a*1000+b*100+c*10+(d or 0) end; return f(a,g())",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"7230\n",
        ),
        (
            b"function g() return 2,3 end; function h() return 4,5 end; function f(a,b,c,d) return a*1000+b*100+c*10+(d or 0) end; return f(g(),h())",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"2450\n",
        ),
        (
            b"function g() return 2,3 end; function h() return 4,5 end; function f(a,b,c,d) return a*1000+b*100+c*10+(d or 0) end; return f(11,g(),h())",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"11245\n",
        ),
        (
            b"function f() return 1 end; assert(f()); return print",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(type(f()))",
            b"function\n",
        ),
        (
            b"assert(os.execute()); return print",
            "local path=os.getenv('RIVETLUA_P15_CHUNK'); os={execute=function() return true end}; local f=assert(loadfile(path)); print(type(f()))",
            b"function\n",
        ),
        (
            b"function f() return 1 end; assert(f()); marker=73; return marker",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"73\n",
        ),
        (
            b"local replacement={marker=77}; function f() _ENV=replacement; return 1 end; assert(f()); return marker",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"77\n",
        ),
        (
            b"function f() return 1 end; local function outer() return function() assert(f()); return print end end; return outer()",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(type(f()()))",
            b"function\n",
        ),
        (
            b"function f() return 1 end; local function outer() local prior=_ENV; return function() local keep=_ENV; assert(f()); return print end end; return outer()",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(type(f()()))",
            b"function\n",
        ),
        (
            b"function f() return 1 end; function outer(env,x) return env==_ENV and x end; return outer(_ENV,f())",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())",
            b"1\n",
        ),
        (
            b"function f() return 1 end; local function make() return function() assert(f()); return print end, function() return print end end; return make()",
            "local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); local a,b=f(); print(debug.upvalueid(a,1)==debug.upvalueid(b,1),type(a()),type(b()))",
            b"true\tfunction\tfunction\n",
        ),
        (
            b"function f() return 1 end; return function() assert(f()); return marker end",
            "local root=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); local g=root(); local replacement={assert=assert,f=f,marker=88}; assert(debug.setupvalue(g,1,replacement)); print(g())",
            b"88\n",
        ),
    ];
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).expect("官方 Lua oracle 路徑必須設定");
        for (case, (source, invoke, expected)) in cases.iter().enumerate() {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@open-chain-c-loader.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            for strip in [false, true] {
                let bytes = emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap_or_else(|error| panic!("{profile:?} case={case} strip={strip}: {error:?}"));
                let path = std::env::temp_dir().join(format!(
                    "rivetlua-p15-open-chain-c-loader-{profile:?}-{case}-{strip}-{}.luac",
                    std::process::id()
                ));
                std::fs::write(&path, bytes).unwrap();
                let output = Command::new(&lua)
                    .env("RIVETLUA_P15_CHUNK", &path)
                    .arg("-e")
                    .arg(invoke)
                    .output()
                    .unwrap();
                std::fs::remove_file(path).unwrap();
                assert!(
                    output.status.success(),
                    "{profile:?} case={case} strip={strip}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    output.stdout, *expected,
                    "{profile:?} case={case} strip={strip}"
                );
            }
        }
    }
}

#[test]
fn native_open_chain_layout_obeys_exact_export_limits() {
    let source = b"return f(11,g(),h())";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@open-chain-limits.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        for strip in [false, true] {
            let defaults = OfficialChunkLimits::default();
            let export = |limits: &OfficialChunkLimits, work: &mut OfficialWorkBudget| {
                emit_official_chunk(emitted.verified(), ProtoId(0), profile, strip, limits, work)
            };
            let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
            let expected = export(&defaults, &mut unrestricted).unwrap();
            let exact_work = unrestricted.consumed();
            assert!(exact_work > 0);
            let mut below = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                export(&defaults, &mut below).unwrap_err().kind,
                OfficialExportErrorKind::WorkExhausted,
                "{profile:?}/strip={strip}"
            );
            let mut exact = OfficialWorkBudget::new(exact_work);
            assert_eq!(export(&defaults, &mut exact).unwrap(), expected);
            assert_eq!(exact.remaining(), 0);

            let chunk = decode_official_chunk(&expected, profile, &defaults).unwrap();
            let mut limited = defaults;
            limited.max_instructions = chunk.main.code.len();
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), expected);
            limited.max_instructions -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded,
                "{profile:?}/strip={strip}"
            );

            let mut low = 1usize;
            let mut high = defaults.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                limited = defaults;
                limited.max_allocated_bytes = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if export(&limited, &mut work).is_ok() {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            limited = defaults;
            limited.max_allocated_bytes = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), expected);
            limited.max_allocated_bytes -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded,
                "{profile:?}/strip={strip}"
            );
        }
    }
}

#[test]
fn native_open_chain_rejects_missing_pending_prefix() {
    let source = b"return f(11,g(),h())";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, mut ir) = native_ir_with_resolved(source, language);
        let producer_pc = ir.prototypes[0]
            .instructions
            .iter()
            .position(|entry| {
                matches!(
                    entry.instruction,
                    Instruction::Call {
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            })
            .unwrap();
        let temporaries = &mut ir.prototypes[0].native_debug.as_mut().unwrap().temporaries;
        let last = temporaries
            .iter()
            .filter(|entry| entry.call_pc.0 as usize == producer_pc)
            .map(|entry| entry.ordinal)
            .max()
            .unwrap();
        temporaries
            .retain(|entry| entry.call_pc.0 as usize != producer_pc || entry.ordinal != last);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@missing-open-prefix.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert_eq!(
            emit_official_chunk(
                emitted.verified(),
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap_err()
            .kind,
            OfficialExportErrorKind::Unsupported,
            "{profile:?}"
        );
    }
}

#[test]
fn native_open_chain_respects_255_slot_boundary() {
    for (language, profile, fitting) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, 251),
        (LanguageProfile::Lua55, LuaProfile::Lua55, 250),
    ] {
        for fixed in [fitting, fitting + 1] {
            let mut source = b"return f(".to_vec();
            for _ in 0..fixed {
                source.extend_from_slice(b"1,");
            }
            source.extend_from_slice(b"g())");
            let (resolved, ir) = native_ir_with_resolved(&source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                &source,
                b"@open-chain-255.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            for strip in [false, true] {
                let result = emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                );
                if fixed == fitting {
                    let bytes = result.unwrap_or_else(|error| {
                        panic!("{profile:?} fixed={fixed} strip={strip}: {error:?}")
                    });
                    let chunk =
                        decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default())
                            .unwrap();
                    assert_eq!(chunk.main.max_stack_size, 255, "{profile:?}/strip={strip}");
                } else {
                    assert_eq!(
                        result.unwrap_err().kind,
                        OfficialExportErrorKind::LimitExceeded,
                        "{profile:?}/strip={strip}"
                    );
                }
            }
        }
    }
}

#[test]
fn native_vararg_table_concat_nested_call_exports() {
    let source = b"local function f(a,...) return table.concat({tostring(a)},'|') end; return f";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@vararg-nested-concat.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let child = emitted
            .verified()
            .module()
            .prototypes
            .iter()
            .find(|proto| proto.parameter_count == 1)
            .unwrap();
        for strip in [false, true] {
            emit_official_chunk(
                emitted.verified(),
                child.id,
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap_or_else(|error| panic!("{profile:?}/strip={strip}: {error:?}"));
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_pending_call_preserves_outer_callee_across_nested_call() {
    let cases: &[(&[u8], &[u8])] = &[
        (
            b"local function f() return 19 end\nlocal g={x=19}\nreturn assert(g.x==f())\n",
            b"true\n",
        ),
        (
            b"function probe() local n1,v1=debug.getlocal(2,1); local n2,v2=debug.getlocal(2,2); local n3,v3=debug.getlocal(2,3); assert(n1=='(temporary)' and type(v1)=='function' and n2=='(temporary)' and v2==11 and n3=='(temporary)' and v3==22); assert(debug.setlocal(2,2,17)=='(temporary)'); return 5 end\nfunction outer(a,b,c) return a+b+c end\nfunction g() return outer(11,22,probe()+0) end\nreturn g()\n",
            b"44\n",
        ),
        (
            b"obj={value=7}; replacement={value=31}\nfunction probe() local n1,v1=debug.getlocal(2,1); local n2,v2=debug.getlocal(2,2); local n3,v3=debug.getlocal(2,3); assert(n1=='(temporary)' and type(v1)=='function' and n2=='(temporary)' and v2==obj and n3=='(temporary)' and v3==11); assert(debug.setlocal(2,2,replacement)=='(temporary)'); collectgarbage('collect'); return 5 end\nfunction obj:m(a,b) return self.value+a+b end\nfunction g() return obj:m(11,probe()+0) end\nreturn g()\n",
            b"47\n",
        ),
        (
            b"local function getoutput() return 'abc' end\nlocal function sink() end\nsink()\nlocal release=string.match(getoutput(),'a')\nreturn release\n",
            b"a\n",
        ),
    ];
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).expect("官方 Lua oracle 路徑必須設定");
        for (case, (source, expected)) in cases.iter().enumerate() {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@nested-callee.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            for strip in [false, true] {
                let bytes = emit_official_chunk(
                    emitted.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap();
                let path = std::env::temp_dir().join(format!(
                    "rivetlua-p15-nested-callee-{profile:?}-{case}-{strip}-{}.luac",
                    std::process::id()
                ));
                std::fs::write(&path, bytes).unwrap();
                let output = Command::new(&lua)
                    .env("RIVETLUA_P15_CHUNK", &path)
                    .arg("-e")
                    .arg("local f=assert(loadfile(os.getenv('RIVETLUA_P15_CHUNK'))); print(f())")
                    .output()
                    .unwrap();
                std::fs::remove_file(path).unwrap();
                assert!(
                    output.status.success(),
                    "{profile:?} case={case} strip={strip}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    output.stdout, *expected,
                    "{profile:?} case={case} strip={strip}"
                );
            }
        }
    }
}

#[test]
fn native_pending_call_layout_obeys_exact_export_limits() {
    let source =
        b"function f() return 30 end\nfunction g(a,b) return (a+1)+((b+2)+f()) end\nreturn g\n";
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@pending-call-limits.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let module = emitted.verified();
        let g = module
            .module()
            .prototypes
            .iter()
            .find(|proto| proto.parameter_count == 2)
            .unwrap();
        for strip in [false, true] {
            let defaults = OfficialChunkLimits::default();
            let export = |limits: &OfficialChunkLimits, work: &mut OfficialWorkBudget| {
                emit_official_chunk(module, g.id, profile, strip, limits, work)
            };
            let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
            let expected = export(&defaults, &mut unrestricted).unwrap();
            let exact_work = unrestricted.consumed();
            assert!(exact_work > 0);
            let mut below = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                export(&defaults, &mut below).unwrap_err().kind,
                OfficialExportErrorKind::WorkExhausted,
                "{profile:?}/strip={strip}"
            );
            let mut exact = OfficialWorkBudget::new(exact_work);
            assert_eq!(export(&defaults, &mut exact).unwrap(), expected);
            assert_eq!(exact.remaining(), 0);

            let chunk = decode_official_chunk(&expected, profile, &defaults).unwrap();
            let mut limited = defaults;
            limited.max_instructions = chunk.main.code.len();
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), expected);
            limited.max_instructions -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded,
                "{profile:?}/strip={strip}"
            );

            let mut low = 1usize;
            let mut high = defaults.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                limited = defaults;
                limited.max_allocated_bytes = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if export(&limited, &mut work).is_ok() {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            limited = defaults;
            limited.max_allocated_bytes = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), expected);
            limited.max_allocated_bytes -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded,
                "{profile:?}/strip={strip}"
            );
        }
    }
}

#[test]
fn native_parameter_locals_start_before_official_varargprep() {
    let source = b"local function foo(a,b,...) local d,e end\nreturn foo\n";
    for (language, profile, varargprep) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, 81),
        (LanguageProfile::Lua55, LuaProfile::Lua55, 83),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let emitted = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@parameter-locals.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let module = emitted.verified();
        let child = &module.module().prototypes[1];
        assert_eq!(child.parameter_count, 2);
        let native = module.native_debug().unwrap().prototype(child.id).unwrap();
        assert_eq!(native.locals.len(), 4);
        for (slot, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
            let local = &native.locals[slot];
            assert_eq!(local.name, name);
            assert_eq!(usize::from(local.slot), slot);
            assert_eq!(local.initialized_pc, 0);
            assert_eq!(local.start_pc, 0);
            assert_eq!(local.end_pc as usize, child.instructions.len());
        }
        let export = |strip| {
            let bytes = emit_official_chunk(
                module,
                child.id,
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap()
        };
        let full = export(false);
        let stripped = export(true);
        assert_eq!(full.main.num_params, 2);
        assert_eq!(full.main.flags, 1);
        assert_eq!(full.main.code[0] & 0x7f, varargprep);
        assert_eq!(full.main.code, stripped.main.code);
        assert!(stripped.main.debug.locals.is_empty());
        let locals = &full.main.debug.locals;
        let anonymous = usize::from(profile == LuaProfile::Lua55);
        assert_eq!(locals.len(), 4 + anonymous);
        for (slot, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
            assert_eq!(locals[slot].name.as_deref(), Some(name));
            assert_eq!(locals[slot].start_pc, 0);
            assert_eq!(locals[slot].end_pc as usize, full.main.code.len());
        }
        if anonymous != 0 {
            assert_eq!(
                locals[2].name.as_deref(),
                Some(b"(vararg table)".as_slice())
            );
            assert_eq!(locals[2].start_pc, 1);
            assert_eq!(locals[2].end_pc as usize, full.main.code.len());
        }
        for (slot, name) in [b"d".as_slice(), b"e".as_slice()].into_iter().enumerate() {
            let local = &locals[slot + 2 + anonymous];
            assert_eq!(local.name.as_deref(), Some(name));
            assert!(local.start_pc > 0);
            assert_eq!(local.start_pc, local.end_pc);
        }
    }
}

#[test]
fn lua55_anonymous_vararg_exports_its_own_official_debug_local() {
    for (source, later) in [
        (
            b"local function foo(a,b,...) local d,e=...; return d,e end\nreturn foo\n".as_slice(),
            [b"d".as_slice(), b"e".as_slice()],
        ),
        (
            b"local function foo(a,b,...) local d,e=1,2; return d,e end\nreturn foo\n".as_slice(),
            [b"d".as_slice(), b"e".as_slice()],
        ),
    ] {
        for (language, profile) in [
            (LanguageProfile::Lua54, LuaProfile::Lua54),
            (LanguageProfile::Lua55, LuaProfile::Lua55),
        ] {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let emitted = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@anonymous-vararg-debug.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let module = emitted.verified();
            let child = &module.module().prototypes[1];
            let native = module.native_debug().unwrap().prototype(child.id).unwrap();
            assert_eq!(native.locals.len(), 4);
            let export = |strip| {
                let bytes = emit_official_chunk(
                    module,
                    child.id,
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::new(u64::MAX),
                )
                .unwrap();
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap()
            };
            let full = export(false);
            let strip = export(true);
            assert_eq!(full.main.num_params, 2);
            assert_eq!(full.main.flags, 1);
            assert_eq!(
                full.main.code[0] & 0x7f,
                if profile == LuaProfile::Lua55 { 83 } else { 81 }
            );
            assert_eq!(strip.main.code, full.main.code);
            assert_eq!(strip.main.max_stack_size, full.main.max_stack_size);
            assert!(strip.main.debug.locals.is_empty());
            let locals = &full.main.debug.locals;
            let expected = if profile == LuaProfile::Lua55 {
                vec![
                    b"a".as_slice(),
                    b"b".as_slice(),
                    b"(vararg table)".as_slice(),
                    later[0],
                    later[1],
                ]
            } else {
                vec![b"a".as_slice(), b"b".as_slice(), later[0], later[1]]
            };
            assert_eq!(
                locals
                    .iter()
                    .map(|local| local.name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                expected,
                "{profile:?}"
            );
            if profile == LuaProfile::Lua55 {
                assert_eq!(locals[2].start_pc, 1);
                assert_eq!(locals[2].end_pc as usize, full.main.code.len());
                assert!(full.main.max_stack_size as usize >= locals.len());
            }
        }
    }
}

#[test]
fn lua55_anonymous_vararg_export_accounts_for_debug_and_layout_limits() {
    let source = b"local function foo(a,b,...) local d,e=...; return d,e end\nreturn foo\n";
    let (resolved, ir) = native_ir_with_resolved(source, LanguageProfile::Lua55);
    let emitted = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@anonymous-vararg-limits.lua",
        &VerifyLimits::default(),
    )
    .unwrap();
    let module = emitted.verified();
    let child = module.module().prototypes[1].id;
    let defaults = OfficialChunkLimits::default();
    let mut minimum_allocations = Vec::new();
    for strip in [false, true] {
        let export = |limits: &OfficialChunkLimits, work: &mut OfficialWorkBudget| {
            emit_official_chunk(module, child, LuaProfile::Lua55, strip, limits, work)
        };
        let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
        let expected = export(&defaults, &mut unrestricted).unwrap();
        let exact_work = unrestricted.consumed();
        assert!(exact_work > 0);
        let mut below = OfficialWorkBudget::new(exact_work - 1);
        assert_eq!(
            export(&defaults, &mut below).unwrap_err().kind,
            OfficialExportErrorKind::WorkExhausted
        );
        let mut exact = OfficialWorkBudget::new(exact_work);
        assert_eq!(export(&defaults, &mut exact).unwrap(), expected);
        assert_eq!(exact.remaining(), 0);

        let decoded = decode_official_chunk(&expected, LuaProfile::Lua55, &defaults).unwrap();
        assert!(decoded.main.max_stack_size > decoded.main.num_params);
        let mut limited = defaults;
        limited.max_instructions = decoded.main.code.len();
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(export(&limited, &mut work).unwrap(), expected);
        limited.max_instructions -= 1;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(
            export(&limited, &mut work).unwrap_err().kind,
            OfficialExportErrorKind::LimitExceeded
        );

        let mut low = 1usize;
        let mut high = defaults.max_allocated_bytes;
        while low < high {
            let mid = low + (high - low) / 2;
            limited = defaults;
            limited.max_allocated_bytes = mid;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            if export(&limited, &mut work).is_ok() {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        minimum_allocations.push(low);
        limited = defaults;
        limited.max_allocated_bytes = low;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(export(&limited, &mut work).unwrap(), expected);
        limited.max_allocated_bytes -= 1;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(
            export(&limited, &mut work).unwrap_err().kind,
            OfficialExportErrorKind::LimitExceeded
        );
    }
    assert!(minimum_allocations[0] > minimum_allocations[1]);
}

#[test]
fn native_named_vararg_local_at_native_zero_is_not_a_parameter() {
    let source = b"local function foo(a,b,...arg) return arg end\nreturn foo\n";
    let (resolved, ir) = native_ir_with_resolved(source, LanguageProfile::Lua55);
    let emitted = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@named-vararg-local.lua",
        &VerifyLimits::default(),
    )
    .unwrap();
    let module = emitted.verified();
    let child = &module.module().prototypes[1];
    assert_eq!(child.parameter_count, 2);
    let native = module.native_debug().unwrap().prototype(child.id).unwrap();
    let named = native
        .locals
        .iter()
        .find(|local| local.name == b"arg")
        .unwrap();
    assert_eq!(named.slot, 2);
    assert_eq!(named.start_pc, 0);
    let bytes = emit_official_chunk(
        module,
        child.id,
        LuaProfile::Lua55,
        false,
        &OfficialChunkLimits::default(),
        &mut OfficialWorkBudget::new(u64::MAX),
    )
    .unwrap();
    let chunk =
        decode_official_chunk(&bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let locals = &chunk.main.debug.locals;
    assert_eq!(locals[0].start_pc, 0);
    assert_eq!(locals[1].start_pc, 0);
    let named = locals
        .iter()
        .find(|local| local.name.as_deref() == Some(b"arg"))
        .unwrap();
    assert!(named.start_pc > 0);
}

#[test]
fn native_closure_exports_an_official_chunk_in_both_profiles() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = native_module(b"return 1 + 2", language);
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            &module,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let decoded =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        assert_eq!(decoded.profile, profile);
        assert!(!decoded.main.code.is_empty());
        assert!(work.consumed() > 0);
    }
}

#[test]
fn native_explicit_returns_export_unreachable_end_line_without_changing_implicit_return() {
    let source = b"local function f()\n  return 1\nend\nlocal function v(...)\n  return ...\nend\nlocal function h()\n  local x=1\nend\nlocal function g()\n  return f()\nend\nreturn f,v,h,g\n";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@return-lines.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let export = |strip| {
            let bytes = emit_official_chunk(
                module.verified(),
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap()
        };
        let full = export(false);
        let stripped = export(true);
        for (defined, last, statement_line, final_opcode) in
            [(1, 3, 2, 70), (4, 6, 5, 70), (10, 12, 11, 69)]
        {
            let child = full
                .main
                .children
                .iter()
                .find(|child| child.line_defined == defined)
                .unwrap();
            assert_eq!(child.last_line_defined, last, "{profile:?}");
            let mut current = child.line_defined as i64;
            let lines: Vec<_> = child
                .debug
                .line_info
                .iter()
                .map(|delta| {
                    current += i64::from(*delta);
                    current
                })
                .collect();
            assert!(child.debug.abs_line_info.is_empty());
            assert_eq!(child.code[child.code.len() - 2] & 0x7f, final_opcode);
            assert_eq!(lines[lines.len() - 2], statement_line);
            assert_eq!(child.code.last().unwrap() & 0x7f, 71, "{profile:?}");
            assert_eq!(lines.last(), Some(&i64::from(last)), "{profile:?}");
        }
        let implicit = full
            .main
            .children
            .iter()
            .find(|child| child.line_defined == 7)
            .unwrap();
        assert_eq!(implicit.last_line_defined, 9);
        assert_eq!(implicit.code.last().unwrap() & 0x7f, 70);
        assert_eq!(
            implicit
                .debug
                .line_info
                .iter()
                .map(|v| i64::from(*v))
                .sum::<i64>(),
            2
        );
        for (full_child, stripped_child) in full.main.children.iter().zip(&stripped.main.children) {
            assert_eq!(full_child.code, stripped_child.code, "{profile:?}");
            assert!(stripped_child.debug.line_info.is_empty());
        }
    }
}

#[test]
fn native_unreachable_end_line_obeys_exact_export_limits_and_work_budget() {
    let source = b"local function f()\n  local x=1\n  return x\nend\nreturn f\n";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@limit-return.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let module = encoded.verified();
        let child_proto = module
            .module()
            .prototypes
            .iter()
            .find(|candidate| candidate.parent == Some(ProtoId(0)))
            .unwrap();
        let child_debug = module
            .native_debug()
            .unwrap()
            .prototype(child_proto.id)
            .unwrap();
        assert_eq!(child_debug.locals.len(), 1);
        assert_eq!(
            child_debug.locals[0].end_pc as usize,
            child_proto.instructions.len()
        );

        for strip in [false, true] {
            let defaults = OfficialChunkLimits::default();
            let export = |limits: &OfficialChunkLimits, work: &mut OfficialWorkBudget| {
                emit_official_chunk(module, ProtoId(0), profile, strip, limits, work)
            };
            let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
            let bytes = export(&defaults, &mut unrestricted).unwrap();
            let exact_work = unrestricted.consumed();
            let mut below = OfficialWorkBudget::new(exact_work - 1);
            assert_eq!(
                export(&defaults, &mut below).unwrap_err().kind,
                OfficialExportErrorKind::WorkExhausted,
                "{profile:?}/strip={strip}"
            );
            let mut work = OfficialWorkBudget::new(exact_work);
            assert_eq!(export(&defaults, &mut work).unwrap(), bytes);
            assert_eq!(work.remaining(), 0);

            let chunk = decode_official_chunk(&bytes, profile, &defaults).unwrap();
            let child = &chunk.main.children[0];
            assert_eq!(child.code.last().unwrap() & 0x7f, 71);
            if !strip {
                assert_eq!(child.debug.locals.len(), 1);
                assert_eq!(child.debug.locals[0].end_pc as usize, child.code.len());
            }
            let instructions = chunk.main.code.len() + child.code.len();
            let mut limited = defaults;
            limited.max_instructions = instructions;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), bytes);
            limited.max_instructions -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded
            );

            let mut low = 1usize;
            let mut high = defaults.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                limited = defaults;
                limited.max_allocated_bytes = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if export(&limited, &mut work).is_ok() {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            limited = defaults;
            limited.max_allocated_bytes = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(export(&limited, &mut work).unwrap(), bytes);
            limited.max_allocated_bytes -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                export(&limited, &mut work).unwrap_err().kind,
                OfficialExportErrorKind::LimitExceeded
            );
        }
    }
}

#[test]
fn native_terminal_jump_keeps_its_target_and_bare_export_has_no_extra_return() {
    let source = b"local function forever()\n  ::loop:: goto loop\nend\nreturn forever\n";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let sidecar = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@jump-end.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let bare = emit(&ir, &VerifyLimits::default()).unwrap();
        let export = |module: &rivetlua_core::VerifiedModule| {
            let bytes = emit_official_chunk(
                module,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap()
        };
        let with_debug = export(sidecar.verified());
        let without_debug = export(bare.verified());
        let child = &with_debug.main.children[0];
        let bare_child = &without_debug.main.children[0];
        assert_eq!(child.code.last().unwrap() & 0x7f, 71);
        assert_eq!(child.code[child.code.len() - 2] & 0x7f, 56);
        assert_eq!(&child.code[..child.code.len() - 1], bare_child.code);
        assert!(bare_child.debug.line_info.is_empty());
        assert_eq!(child.last_line_defined, 3);
        let mut line = child.line_defined as i64;
        for delta in &child.debug.line_info {
            line += i64::from(*delta);
        }
        assert_eq!(line, 3);
    }
}

#[test]
fn native_final_constructor_helper_exports_as_official_setlist_without_hidden_upvalue() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let source = b"local function pack(...) local t={11,...}; return t[1],t[2],t[3] end; return pack(7,8)";
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let module = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-setlist.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(
            module
                .verified()
                .official_execution()
                .is_some_and(|plan| plan.is_native_builtin())
        );
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        for strip in [false, true] {
            let bytes = emit_official_chunk(
                module.verified(),
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap();
            let chunk =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            let pack = &chunk.main.children[0];
            assert_eq!(
                pack.upvalues.len(),
                0,
                "helper binding 不得寫入官方 upvalues"
            );
            assert_eq!(pack.debug.upvalue_names.len(), 0);
            assert!(pack.code.iter().any(|word| word & 0x7f == 78));
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_final_constructor_helper_matches_both_official_oracles() {
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).expect("官方 Lua oracle 路徑必須設定");
        for (case, source) in [
            ("call", b"local function f() return 7,nil,9 end; local t={4,f()}; return t[1],t[2],t[3],t[4]".as_slice()),
            ("vararg", b"local function f(...) local t={3,...}; return t[1],t[2],t[3],t[4] end; return f(7,nil,9)".as_slice()),
            ("empty", b"local function f() end; local t={3,f()}; return t[1],t[2]".as_slice()),
            ("named", b"local function f() return 7,nil,9 end; local t={x=5,[4]=11,3,f()}; return t.x,t[1],t[2],t[3],t[4]".as_slice()),
            ("capture", b"local function make(n) local saved='saved'; return function(x,...) local inner=function() return n,saved end; local a,b=inner(); return a+x,b,select('#',...),... end end; local callback=make(40); local t={10,callback(2,'left','right')}; return t[1],t[2],t[3],t[4],t[5],t[6]".as_slice()),
            ("deep-two", b"local n=11; local function outer(x) local hold='ok'; return function(...) local function values() return n+x,hold,9 end; local a={values()}; local b={...}; return a[1],a[2],a[3],b[1],b[2] end end; return outer(20)(7,8)".as_slice()),
        ] {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let module = emit_with_native_debug(&ir, &resolved, source, b"@native-setlist-oracle.lua", &VerifyLimits::default()).unwrap();
            for strip in [false, true] {
                let bytes = emit_official_chunk(
                    module.verified(), ProtoId(0), profile, strip,
                    &OfficialChunkLimits::default(),
                    &mut OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap(),
                ).unwrap();
                let suffix = format!("{}-{profile:?}-{case}-{strip}", std::process::id());
                let source_path = std::env::temp_dir().join(format!("rivetlua-native-setlist-{suffix}.lua"));
                let chunk_path = std::env::temp_dir().join(format!("rivetlua-native-setlist-{suffix}.luac"));
                std::fs::write(&source_path, source).unwrap();
                std::fs::write(&chunk_path, bytes).unwrap();
                let execute = |path: &std::path::Path| Command::new(&lua)
                    .env("RIVETLUA_NATIVE_SETLIST_CHUNK", path)
                    .arg("-e")
                    .arg("local f=assert(loadfile(os.getenv('RIVETLUA_NATIVE_SETLIST_CHUNK'))); print(f())")
                    .output().unwrap();
                let expected = execute(&source_path);
                let actual = execute(&chunk_path);
                std::fs::remove_file(source_path).unwrap();
                std::fs::remove_file(chunk_path).unwrap();
                assert!(expected.status.success(), "{}", String::from_utf8_lossy(&expected.stderr));
                assert!(actual.status.success(), "{}", String::from_utf8_lossy(&actual.stderr));
                assert_eq!(actual.stdout, expected.stdout, "{profile:?}/{case}/strip={strip}");
            }
        }
    }
}

#[test]
fn native_nested_closure_without_environment_keeps_zero_upvalues() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = native_module(b"return function(x) return x + 1 end", language);
        let child = module
            .module()
            .prototypes
            .iter()
            .find(|candidate| candidate.parent == Some(ProtoId(0)))
            .unwrap();
        assert!(child.upvalues.is_empty());
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            &module,
            child.id,
            profile,
            true,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let decoded =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        assert_eq!(decoded.root_upvalues, 0);
        assert_eq!(decoded.main.num_params, 1);
        assert!(decoded.main.debug.line_info.is_empty());
    }
}

#[test]
fn imported_nested_prototype_exports_without_runtime_capture_values() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac")
                .as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac")
                .as_slice(),
        ),
    ] {
        let source =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        let child = translated
            .verified()
            .module()
            .prototypes
            .iter()
            .find(|candidate| candidate.parent == Some(ProtoId(0)))
            .unwrap();
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let dumped = emit_official_chunk(
            translated.verified(),
            child.id,
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let standalone =
            decode_official_chunk(&dumped, profile, &OfficialChunkLimits::default()).unwrap();
        assert_eq!(
            usize::from(standalone.root_upvalues),
            standalone.main.upvalues.len()
        );
        assert_eq!(standalone.main.code, source.main.children[0].code);
    }
}

#[test]
fn export_rejects_tight_limits_and_exhausted_work_before_materializing_chunk() {
    let source = decode_official_chunk(
        include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac"),
        LuaProfile::Lua54,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    let imported = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let native = native_module(b"return 1 + 2", LanguageProfile::Lua54);
    for module in [imported.verified(), &native] {
        let mut limits = OfficialChunkLimits::default();
        limits.max_allocated_bytes = 0;
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let error = emit_official_chunk(
            module,
            ProtoId(0),
            LuaProfile::Lua54,
            false,
            &limits,
            &mut work,
        )
        .unwrap_err();
        assert_eq!(error.kind, OfficialExportErrorKind::LimitExceeded);
        assert!(work.consumed() > 0);

        let mut limits = OfficialChunkLimits::default();
        limits.max_prototypes = 0;
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let error = emit_official_chunk(
            module,
            ProtoId(0),
            LuaProfile::Lua54,
            false,
            &limits,
            &mut work,
        )
        .unwrap_err();
        assert_eq!(error.kind, OfficialExportErrorKind::LimitExceeded);

        let mut work = OfficialWorkBudget::new(0);
        let error = emit_official_chunk(
            module,
            ProtoId(0),
            LuaProfile::Lua54,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_err();
        assert_eq!(error.kind, OfficialExportErrorKind::WorkExhausted);
    }
}

#[test]
fn imported_and_native_exports_share_exact_encoder_work_budget() {
    for (profile, language, fixture) in [
        (
            LuaProfile::Lua54,
            LanguageProfile::Lua54,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac")
                .as_slice(),
        ),
        (
            LuaProfile::Lua55,
            LanguageProfile::Lua55,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac")
                .as_slice(),
        ),
    ] {
        let decoded =
            decode_official_chunk(fixture, profile, &OfficialChunkLimits::default()).unwrap();
        let imported = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let native = native_module(b"local s='a repeated string'; return s,s,s", language);
        for module in [imported.verified(), &native] {
            let limits = OfficialChunkLimits::default();
            let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
            let expected = emit_official_chunk(
                module,
                ProtoId(0),
                profile,
                false,
                &limits,
                &mut unrestricted,
            )
            .unwrap();
            let exact = unrestricted.consumed();
            assert!(exact > expected.len() as u64);
            let mut below = OfficialWorkBudget::new(exact - 1);
            assert_eq!(
                emit_official_chunk(module, ProtoId(0), profile, false, &limits, &mut below)
                    .unwrap_err()
                    .kind,
                OfficialExportErrorKind::WorkExhausted
            );
            let mut exact_work = OfficialWorkBudget::new(exact);
            assert_eq!(
                emit_official_chunk(module, ProtoId(0), profile, false, &limits, &mut exact_work)
                    .unwrap(),
                expected
            );
            assert_eq!(exact_work.remaining(), 0);

            let mut low = 1usize;
            let mut high = limits.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                let mut bounded = limits;
                bounded.max_allocated_bytes = mid;
                let mut work = OfficialWorkBudget::new(u64::MAX);
                if emit_official_chunk(module, ProtoId(0), profile, false, &bounded, &mut work)
                    .is_ok()
                {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            let mut bounded = limits;
            bounded.max_allocated_bytes = low;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(module, ProtoId(0), profile, false, &bounded, &mut work)
                    .unwrap(),
                expected
            );
            bounded.max_allocated_bytes -= 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(module, ProtoId(0), profile, false, &bounded, &mut work)
                    .unwrap_err()
                    .kind,
                OfficialExportErrorKind::LimitExceeded
            );
        }
    }
}

#[test]
fn imported_and_native_nested_exports_obey_depth_limit() {
    for (profile, language, fixture) in [
        (
            LuaProfile::Lua54,
            LanguageProfile::Lua54,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac")
                .as_slice(),
        ),
        (
            LuaProfile::Lua55,
            LanguageProfile::Lua55,
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac")
                .as_slice(),
        ),
    ] {
        let decoded =
            decode_official_chunk(fixture, profile, &OfficialChunkLimits::default()).unwrap();
        let imported = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let native = native_module(
            b"return function() return function() return 1 end end",
            language,
        );
        for module in [imported.verified(), &native] {
            let mut generous_work = OfficialWorkBudget::new(u64::MAX);
            assert!(
                emit_official_chunk(
                    module,
                    ProtoId(0),
                    profile,
                    false,
                    &OfficialChunkLimits::default(),
                    &mut generous_work
                )
                .is_ok()
            );
            let mut tight = OfficialChunkLimits::default();
            tight.max_depth = 1;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            assert_eq!(
                emit_official_chunk(module, ProtoId(0), profile, false, &tight, &mut work)
                    .unwrap_err()
                    .kind,
                OfficialExportErrorKind::LimitExceeded
            );
        }
    }
}

#[test]
fn native_debug_line_index_and_candidate_share_artifact_peak() {
    let mut source = vec![b'\n'; 1_024];
    source.extend_from_slice(b"return 1");
    let (resolved, ir) = native_ir_with_resolved(&source, LanguageProfile::Lua55);
    let defaults = VerifyLimits::default();
    assert!(emit_with_native_debug(&ir, &resolved, &source, b"@lines.lua", &defaults).is_ok());

    let line_bytes = 1_025 * core::mem::size_of::<usize>();
    let mut limited = defaults;
    limited.max_artifact_bytes =
        line_bytes + core::mem::size_of::<rivetlua_core::NativeDebugCandidate>() - 1;
    let error =
        emit_with_native_debug(&ir, &resolved, &source, b"@lines.lua", &limited).unwrap_err();
    assert_eq!(error.code, rivetlua_core::BytecodeErrorCode::CompileLimit);
    assert!(error.message.contains("配置額度超限"));
}

#[test]
fn native_strip_skips_debug_allocation_and_honors_exact_byte_limits() {
    let source = b"local long_debug_name=7\nreturn long_debug_name";
    let (resolved, ir) = native_ir_with_resolved(source, LanguageProfile::Lua55);
    let encoded = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@a-long-native-debug-source.lua",
        &VerifyLimits::default(),
    )
    .unwrap();
    let module = encoded.verified();
    let defaults = OfficialChunkLimits::default();
    let export = |strip: bool, limits: &OfficialChunkLimits| {
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        emit_official_chunk(
            module,
            ProtoId(0),
            LuaProfile::Lua55,
            strip,
            limits,
            &mut work,
        )
    };
    let stripped = export(true, &defaults).unwrap();
    let unstripped = export(false, &defaults).unwrap();
    assert!(stripped.len() < unstripped.len());
    let mut exact_bytes = defaults;
    exact_bytes.max_bytes = stripped.len();
    assert_eq!(export(true, &exact_bytes).unwrap(), stripped);
    exact_bytes.max_bytes -= 1;
    assert!(export(true, &exact_bytes).is_err());
    let mut low = 1usize;
    let mut high = defaults.max_allocated_bytes;
    while low < high {
        let mid = low + (high - low) / 2;
        let mut limits = defaults;
        limits.max_allocated_bytes = mid;
        if export(true, &limits).is_ok() {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let mut exact_allocation = defaults;
    exact_allocation.max_allocated_bytes = low;
    assert_eq!(export(true, &exact_allocation).unwrap(), stripped);
    assert!(export(false, &exact_allocation).is_err());
    exact_allocation.max_allocated_bytes -= 1;
    assert!(export(true, &exact_allocation).is_err());
}

#[test]
fn compiler_native_debug_attaches_verified_nonwire_metadata() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let source = b"local function f(x) x=x+2; local y=4; return x+y end; return f(5)";
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-debug.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(encoded.verified().native_debug().is_some());
        assert_eq!(
            encoded.verified().origin(),
            rivetlua_core::ModuleOrigin::NativeRvlu
        );
        let decoded =
            rivetlua_core::decode_module(encoded.bytes(), profile, &VerifyLimits::default())
                .unwrap();
        assert!(decoded.native_debug().is_none());
    }
}

#[test]
fn compiler_native_debug_all_result_before_later_local_is_valid() {
    let source = b"local function f() return 1, 2 end; local n=select('#', f()); local later=3; return n+later";
    for language in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-open-before-local.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(encoded.verified().native_debug().is_some());
    }
}

#[test]
fn compiler_native_debug_recursive_capture_and_loop_are_valid() {
    let source = b"local function fact(n) if n<=1 then return 1 end return n*fact(n-1) end; local sum=0; for i=1,3 do local z=i; sum=sum+z end; return fact(sum)";
    for language in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-capture-loop.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(encoded.verified().native_debug().is_some());
    }
}

#[test]
fn compiler_native_debug_captured_to_be_closed_local_is_valid() {
    let source = b"local x <close> = setmetatable({}, {__close=function() end}); local f=function() return x end; return f()";
    for language in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-captured-close.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        assert!(encoded.verified().native_debug().is_some());
    }
}

fn long_native_sources() -> [(Vec<u8>, &'static [u8]); 2] {
    let mut straight = b"local n=0; ".to_vec();
    for _ in 0..100 {
        straight.extend_from_slice(b"n=n+1; ");
    }
    straight.extend_from_slice(b"return n");
    let mut loops = b"local n=0; ".to_vec();
    for _ in 0..70 {
        loops.extend_from_slice(b"for i=1,2 do n=n+i end; ");
    }
    loops.extend_from_slice(b"return n");
    [(straight, b"100\n"), (loops, b"210\n")]
}

#[test]
fn native_debug_long_straight_and_sequential_loops_fit_official_stack() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for (source, _) in long_native_sources() {
            let (resolved, ir) = native_ir_with_resolved(&source, language);
            assert!(ir.prototypes[0].register_count > 255);
            let encoded = emit_with_native_debug(
                &ir,
                &resolved,
                &source,
                b"@native-long.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
            let bytes = emit_official_chunk(
                encoded.verified(),
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap();
            let decoded =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            assert!(u16::from(decoded.main.max_stack_size) < ir.prototypes[0].register_count);
        }
    }
}

#[test]
fn native_without_debug_reuses_registers_for_long_straight_code() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let (source, _) = &long_native_sources()[0];
        let ir = native_ir(source, language);
        assert!(ir.prototypes[0].register_count > 255);
        let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
        assert!(encoded.verified().native_debug().is_none());
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            encoded.verified(),
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let decoded =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        assert!(u16::from(decoded.main.max_stack_size) < ir.prototypes[0].register_count);
    }
}

fn sequential_capture_source() -> Vec<u8> {
    let mut source = b"local n=0; ".to_vec();
    for index in 1..=260 {
        source.extend_from_slice(
            format!("do local x={index}; local f=function() return x end; n=n+f() end; ")
                .as_bytes(),
        );
    }
    source.extend_from_slice(b"return n");
    source
}

#[test]
fn native_without_debug_reuses_closed_sequential_capture_slots() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let source = sequential_capture_source();
        let ir = native_ir(&source, language);
        assert!(ir.prototypes[0].register_count > 255);
        let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
        assert!(encoded.verified().native_debug().is_none());
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            encoded.verified(),
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let decoded =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        assert!(u16::from(decoded.main.max_stack_size) < ir.prototypes[0].register_count);
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_bare_sequential_captures_and_captured_close_match_oracles() {
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        for (case, source) in [
            ("sequential", sequential_capture_source()),
            ("captured-close", b"local function outer() local x=1; local f=function() return x end; do local resource <close> = setmetatable({}, {__close=function() x=x+10 end}); x=x+1 end; return f() end; return outer()".to_vec()),
        ] {
            let (resolved, ir) = native_ir_with_resolved(&source, language);
            let bare = emit(&ir, &VerifyLimits::default()).unwrap();
            let sidecar = emit_with_native_debug(&ir, &resolved, &source,
                b"@native-captured-close.lua", &VerifyLimits::default()).unwrap();
            for (label, module) in [("bare", bare.verified()), ("sidecar", sidecar.verified())] {
                let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
                let bytes = emit_official_chunk(module, ProtoId(0), profile, false,
                    &OfficialChunkLimits::default(), &mut work).unwrap();
                let dir = std::env::temp_dir();
                let source_path = dir.join(format!("rivetlua-p14-{case}-{profile:?}-{}.lua", std::process::id()));
                let chunk_path = dir.join(format!("rivetlua-p14-{case}-{profile:?}-{label}-{}.luac", std::process::id()));
                std::fs::write(&source_path, &source).unwrap();
                std::fs::write(&chunk_path, bytes).unwrap();
                let execute = |path: &std::path::Path| Command::new(&lua)
                    .env("RIVETLUA_P14_CHUNK", path)
                    .arg("-e").arg("local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())")
                    .output().unwrap();
                let expected = execute(&source_path);
                let actual = execute(&chunk_path);
                std::fs::remove_file(source_path).unwrap();
                std::fs::remove_file(chunk_path).unwrap();
                assert!(expected.status.success(), "{case} {profile:?}: {}", String::from_utf8_lossy(&expected.stderr));
                assert!(actual.status.success(), "{case} {profile:?} {label}: {}", String::from_utf8_lossy(&actual.stderr));
                assert_eq!(actual.stdout, expected.stdout, "{case} {profile:?} {label}");
            }
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_environment_rebinding_uses_one_shared_upvalue_cell() {
    let cases: [(&str, &[u8]); 10] = [
        ("root-to-old-child", b"local f=function() return x end; local t={x=12}; _ENV=t; return f()"),
        ("child-to-parent", b"local f=function(t) _ENV=t end; f({x=23}); return x"),
        ("forwarded-grandchild", b"local outer=function() return function(t) _ENV=t end end; local setter=outer(); setter({x=34}); return x"),
        ("scope-close", b"local f=function() return x end; local t={x=40}; do local r <close> = setmetatable({}, {__close=function() end}); _ENV=t end; return f()"),
        ("close-callback", b"local t={x=45}; do local r <close> = setmetatable({}, {__close=function() _ENV=t end}) end; return x"),
        ("captured-upvalue-tail", b"local t={x=46}; local setter=function() _ENV=t end; setter(); local reader=function() return x end; return reader()"),
        ("reentrant-close", b"local t={x=46}; local reader=function() return x end; do local r <close> = setmetatable({}, {__close=function() _ENV=t end}) end; return reader()"),
        ("nested-reentrant-close", b"local t={x=47}; local reader=function() return x end; do local r <close> = setmetatable({}, {__close=function() local setter=function() _ENV=t end; setter(); reader() end}) end; return reader()"),
        ("lexical-env-capture-close", b"local child; do local _ENV <close> = setmetatable({x=72}, {__close=function() end}); child=function() return x end end; _ENV={x=71}; return child(), x"),
        ("prior-implicit-lexical-env", b"local prior=x; do local _ENV={x=72}; local f=function() return x end; return prior,f() end"),
    ];
    let lua55_cases: [(&str, &[u8]); 2] = [
        (
            "declared-global-lexical-env",
            b"global x; local _ENV={x=72}; local f=function() return x end; return f()",
        ),
        (
            "global-star-lexical-env",
            b"global *; local _ENV={x=72}; local f=function() return x end; return f()",
        ),
    ];
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        for (case, source) in cases.iter().copied().chain(
            lua55_cases
                .iter()
                .copied()
                .filter(|_| profile == LuaProfile::Lua55),
        ) {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let bare = emit(&ir, &VerifyLimits::default()).unwrap();
            let sidecar = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@native-env.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let source_path = std::env::temp_dir().join(format!(
                "rivetlua-p14-env-{case}-{profile:?}-{}.lua",
                std::process::id()
            ));
            std::fs::write(&source_path, source).unwrap();
            let execute = |path: &std::path::Path, program: &str| {
                Command::new(&lua)
                    .env("RIVETLUA_P14_CHUNK", path)
                    .arg("-e")
                    .arg(program)
                    .output()
                    .unwrap()
            };
            for (label, module) in [("bare", bare.verified()), ("sidecar", sidecar.verified())] {
                let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
                let bytes = emit_official_chunk(
                    module,
                    ProtoId(0),
                    profile,
                    false,
                    &OfficialChunkLimits::default(),
                    &mut work,
                )
                .unwrap();
                let chunk_path = std::env::temp_dir().join(format!(
                    "rivetlua-p14-env-{case}-{profile:?}-{label}-{}.luac",
                    std::process::id()
                ));
                std::fs::write(&chunk_path, bytes).unwrap();
                for (caller, program) in [
                    (
                        "open",
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())",
                    ),
                    (
                        "fixed",
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); local a,b=f(); print(a,b)",
                    ),
                    (
                        "gc-open",
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); collectgarbage('collect'); for i=1,256 do local waste={i} end; print(f())",
                    ),
                ] {
                    let expected = execute(&source_path, program);
                    let actual = execute(&chunk_path, program);
                    assert!(
                        expected.status.success(),
                        "{case} {profile:?} {caller}: {}",
                        String::from_utf8_lossy(&expected.stderr)
                    );
                    assert!(
                        actual.status.success(),
                        "{case} {profile:?} {label} {caller}: {}",
                        String::from_utf8_lossy(&actual.stderr)
                    );
                    assert_eq!(
                        actual.stdout, expected.stdout,
                        "{case} {profile:?} {label} {caller}"
                    );
                }
                std::fs::remove_file(&chunk_path).unwrap();
            }
            std::fs::remove_file(&source_path).unwrap();
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_close_preserves_precomputed_fixed_and_open_returns() {
    let cases: [(&str, &[u8]); 4] = [
        ("fixed", b"local x=5; local function pass(...) return ... end; do local c <close> = setmetatable({}, {__close=function() x=9; collectgarbage('collect'); pass(100) end}); return x, (pass(x+1)) end"),
        ("open", b"local x=5; local function pass(...) return ... end; do local c <close> = setmetatable({}, {__close=function() x=9; collectgarbage('collect'); pass(100) end}); return x, pass(x+1) end"),
        ("tail", b"local x=5; local function pass(...) return ... end; do local c <close> = setmetatable({}, {__close=function() x=9; collectgarbage('collect'); pass(100) end}); return pass(x,x+1) end"),
        ("captured-open-many", b"local x=5; local function capture() return x end; local function pass(...) return ... end; return x, pass(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24)"),
    ];
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        for (case, source) in cases {
            let (resolved, ir) = native_ir_with_resolved(source, language);
            let bare = emit(&ir, &VerifyLimits::default()).unwrap();
            let sidecar = emit_with_native_debug(
                &ir,
                &resolved,
                source,
                b"@native-close-return.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            let source_path = std::env::temp_dir().join(format!(
                "rivetlua-p14-close-return-{case}-{profile:?}-{}.lua",
                std::process::id()
            ));
            std::fs::write(&source_path, source).unwrap();
            let execute = |path: &std::path::Path, program: &str| {
                Command::new(&lua)
                    .env("RIVETLUA_P14_CHUNK", path)
                    .arg("-e")
                    .arg(program)
                    .output()
                    .unwrap()
            };
            for (label, module) in [("bare", bare.verified()), ("sidecar", sidecar.verified())] {
                let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
                let bytes = emit_official_chunk(
                    module,
                    ProtoId(0),
                    profile,
                    false,
                    &OfficialChunkLimits::default(),
                    &mut work,
                )
                .unwrap();
                let chunk_path = std::env::temp_dir().join(format!(
                    "rivetlua-p14-close-return-{case}-{profile:?}-{label}-{}.luac",
                    std::process::id()
                ));
                std::fs::write(&chunk_path, bytes).unwrap();
                for (caller, program) in [
                    (
                        "open",
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())",
                    ),
                    (
                        "fixed",
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); local a,b=f(); print(a,b)",
                    ),
                ] {
                    let expected = execute(&source_path, program);
                    let actual = execute(&chunk_path, program);
                    assert!(
                        expected.status.success(),
                        "{case} {profile:?} {caller}: {}",
                        String::from_utf8_lossy(&expected.stderr)
                    );
                    assert!(
                        actual.status.success(),
                        "{case} {profile:?} {label} {caller}: {}",
                        String::from_utf8_lossy(&actual.stderr)
                    );
                    assert_eq!(
                        actual.stdout, expected.stdout,
                        "{case} {profile:?} {label} {caller}"
                    );
                }
                std::fs::remove_file(&chunk_path).unwrap();
            }
            std::fs::remove_file(&source_path).unwrap();
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_fixed_call_reuses_stack_after_completed_scope() {
    let names = (0..190)
        .map(|index| format!("v{index}"))
        .collect::<Vec<_>>();
    let source = format!(
        "do local {} = {}; local s=0; {} end; local function f(...) return ... end; local a,b,c=f({}); return a,b,c",
        names.join(","),
        vec!["1"; 190].join(","),
        names
            .iter()
            .map(|name| format!("s=s+{name}"))
            .collect::<Vec<_>>()
            .join(";"),
        (1..=70)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        let (resolved, ir) = native_ir_with_resolved(source.as_bytes(), language);
        let bare = emit(&ir, &VerifyLimits::default()).unwrap();
        let sidecar = emit_with_native_debug(
            &ir,
            &resolved,
            source.as_bytes(),
            b"@native-wide-fixed.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let source_path = std::env::temp_dir().join(format!(
            "rivetlua-p14-wide-fixed-{profile:?}-{}.lua",
            std::process::id()
        ));
        std::fs::write(&source_path, &source).unwrap();
        for (label, module) in [("sidecar", sidecar.verified()), ("bare", bare.verified())] {
            let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
            let bytes = emit_official_chunk(
                module,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap();
            let chunk_path = std::env::temp_dir().join(format!(
                "rivetlua-p14-wide-fixed-{profile:?}-{label}-{}.luac",
                std::process::id()
            ));
            std::fs::write(&chunk_path, bytes).unwrap();
            for (caller, program) in [
                (
                    "open",
                    "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())",
                ),
                (
                    "fixed",
                    "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); local a,b=f(); print(a,b)",
                ),
            ] {
                let execute = |path: &std::path::Path| {
                    Command::new(&lua)
                        .env("RIVETLUA_P14_CHUNK", path)
                        .arg("-e")
                        .arg(program)
                        .output()
                        .unwrap()
                };
                let expected = execute(&source_path);
                let actual = execute(&chunk_path);
                assert!(
                    expected.status.success(),
                    "{profile:?} {caller}: {}",
                    String::from_utf8_lossy(&expected.stderr)
                );
                assert!(
                    actual.status.success(),
                    "{profile:?} {label} {caller}: {}",
                    String::from_utf8_lossy(&actual.stderr)
                );
                assert_eq!(
                    actual.stdout, expected.stdout,
                    "{profile:?} {label} {caller}"
                );
            }
            std::fs::remove_file(chunk_path).unwrap();
        }
        std::fs::remove_file(source_path).unwrap();
    }
}

fn check_wide_argument_window(case: &str, source: String, call_args: &str) {
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        let (resolved, ir) = native_ir_with_resolved(source.as_bytes(), language);
        let bare = emit(&ir, &VerifyLimits::default()).unwrap();
        let sidecar = emit_with_native_debug(
            &ir,
            &resolved,
            source.as_bytes(),
            b"@native-wide-direct.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let source_path = std::env::temp_dir().join(format!(
            "rivetlua-p14-wide-{case}-{profile:?}-{}.lua",
            std::process::id()
        ));
        std::fs::write(&source_path, &source).unwrap();
        for (label, module) in [("bare", bare.verified()), ("sidecar", sidecar.verified())] {
            let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
            let bytes = emit_official_chunk(
                module,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap();
            let chunk_path = std::env::temp_dir().join(format!(
                "rivetlua-p14-wide-{case}-{profile:?}-{label}-{}.luac",
                std::process::id()
            ));
            std::fs::write(&chunk_path, bytes).unwrap();
            for (caller, program) in [
                (
                    "open",
                    format!(
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f({call_args}))"
                    ),
                ),
                (
                    "fixed",
                    format!(
                        "local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); local a,b=f({call_args}); print(a,b)"
                    ),
                ),
            ] {
                let execute = |path: &std::path::Path| {
                    Command::new(&lua)
                        .env("RIVETLUA_P14_CHUNK", path)
                        .arg("-e")
                        .arg(&program)
                        .output()
                        .unwrap()
                };
                let expected = execute(&source_path);
                let actual = execute(&chunk_path);
                assert!(
                    expected.status.success(),
                    "{profile:?} {caller}: {}",
                    String::from_utf8_lossy(&expected.stderr)
                );
                assert!(
                    actual.status.success(),
                    "{profile:?} {label} {caller}: {}",
                    String::from_utf8_lossy(&actual.stderr)
                );
                assert_eq!(
                    actual.stdout, expected.stdout,
                    "{profile:?} {label} {caller}"
                );
            }
            std::fs::remove_file(chunk_path).unwrap();
        }
        std::fs::remove_file(source_path).unwrap();
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_contiguous_call_uses_existing_argument_window() {
    check_wide_argument_window(
        "tailcall",
        format!(
            "local function f(...) return select('#', ...) end; return f({})",
            vec!["1"; 200].join(","),
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_ordinary_call_uses_existing_argument_window() {
    check_wide_argument_window(
        "call",
        format!(
            "local function f(...) return select('#', ...) end; local n=f({}); return n",
            vec!["1"; 200].join(","),
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_fixed_return_uses_existing_value_window() {
    check_wide_argument_window(
        "return",
        format!(
            "return {}",
            (1..=200)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_call_preserves_local_live_across_callee() {
    check_wide_argument_window(
        "live",
        format!(
            "local keep=21; local function f(...) return select('#', ...) end; local n=f({}); return keep,n",
            vec!["1"; 200].join(","),
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_call_preserves_numeric_loop_tuple() {
    check_wide_argument_window(
        "loop",
        format!(
            "local function f(...) return select('#', ...) end; local s=0; for i=1,2 do local n=f({}); s=s+n+i end; return s",
            vec!["1"; 200].join(","),
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_call_result_window_wider_than_arguments() {
    let keeps = (0..60).map(|i| format!("k{i}")).collect::<Vec<_>>();
    let outputs = (0..130).map(|i| format!("a{i}")).collect::<Vec<_>>();
    check_wide_argument_window(
        "results",
        format!(
            "local function f() return {} end; local {}={}; local {}=f(); return k0,a129",
            (1..=130)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(","),
            keeps.join(","),
            (1..=60)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(","),
            outputs.join(","),
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_fixed_vararg_reuses_result_window() {
    let names = (1..=190)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let arguments = (1..=190)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    check_wide_argument_window(
        "vararg",
        format!(
            "local function g(...) local {names}=...; return a1,a190 end; return g({arguments})"
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_wide_fixed_vararg_preserves_numeric_loop_tuple() {
    let names = (1..=190)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let arguments = (1..=190)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    check_wide_argument_window(
        "vararg-loop",
        format!(
            "local function g(...) local s=0; for i=1,2 do local {names}=...; s=s+a1+a190+i end; return s end; return g({arguments})"
        ),
        "",
    );
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_debug_long_straight_and_sequential_loops_match_oracles() {
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        for (index, (source, expected)) in long_native_sources().into_iter().enumerate() {
            let (resolved, ir) = native_ir_with_resolved(&source, language);
            let encoded = emit_with_native_debug(
                &ir,
                &resolved,
                &source,
                b"@native-long.lua",
                &VerifyLimits::default(),
            )
            .unwrap();
            for strip in [false, true] {
                let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
                let bytes = emit_official_chunk(
                    encoded.verified(),
                    ProtoId(0),
                    profile,
                    strip,
                    &OfficialChunkLimits::default(),
                    &mut work,
                )
                .unwrap();
                let path = std::env::temp_dir().join(format!(
                    "rivetlua-p14-native-long-{}-{profile:?}-{index}-{strip}.luac",
                    std::process::id()
                ));
                std::fs::write(&path, bytes).unwrap();
                let output = Command::new(&lua)
                    .env("RIVETLUA_P14_CHUNK", &path)
                    .arg("-e")
                    .arg("local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())")
                    .output()
                    .unwrap();
                std::fs::remove_file(path).unwrap();
                assert!(
                    output.status.success(),
                    "{profile:?} {index} {strip}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.stdout, expected, "{profile:?} {index} {strip}");
            }
        }
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_debug_local_values_match_both_official_oracles() {
    let source = b"local function f(x) x=x+2; local y=4; local function inspect() local a,b=debug.getlocal(2,1); local c,d=debug.getlocal(2,2); return a,b,c,d end; local a,b,c,d=inspect(); return a,b,c,d end; return f(5)";
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let (resolved, ir) = native_ir_with_resolved(source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@native-debug.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            encoded.verified(),
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "rivetlua-p14-native-debug-{}-{profile:?}.luac",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        let output = Command::new(std::env::var_os(variable).unwrap())
            .env("RIVETLUA_P14_CHUNK", &path)
            .arg("-e")
            .arg("local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())")
            .output()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"x\t7\ty\t4\n");
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_debug_currentline_matches_oracles_across_periodic_and_jump_anchors() {
    let mut source = b"local function probe()\nlocal n=0\n".to_vec();
    for _ in 0..140 {
        source.extend_from_slice(b"n=n+1\n");
    }
    for _ in 0..200 {
        source.push(b'\n');
    }
    for _ in 0..140 {
        source.extend_from_slice(b"n=n+1\n");
    }
    source.extend_from_slice(
        b"local line=debug.getinfo(1, 'l').currentline\nreturn line,n\nend\nreturn probe()\n",
    );
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).unwrap();
        let (resolved, ir) = native_ir_with_resolved(&source, language);
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            &source,
            b"@native-currentline.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let bytes = emit_official_chunk(
            encoded.verified(),
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap();
        let decoded =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let child = &decoded.main.children[0];
        assert!(child.code.len() > 256);
        assert!(child.debug.abs_line_info.len() > 2);
        assert!(
            child
                .debug
                .abs_line_info
                .windows(2)
                .all(|pair| pair[1].pc - pair[0].pc <= 128)
        );
        let dir = std::env::temp_dir();
        let source_path = dir.join(format!(
            "rivetlua-p14-currentline-{}-{profile:?}.lua",
            std::process::id()
        ));
        let chunk_path = dir.join(format!(
            "rivetlua-p14-currentline-{}-{profile:?}.luac",
            std::process::id()
        ));
        std::fs::write(&source_path, &source).unwrap();
        std::fs::write(&chunk_path, bytes).unwrap();
        let execute = |path: &std::path::Path| {
            Command::new(&lua)
                .env("RIVETLUA_P14_CHUNK", path)
                .arg("-e")
                .arg("local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())")
                .output()
                .unwrap()
        };
        let expected = execute(&source_path);
        let actual = execute(&chunk_path);
        std::fs::remove_file(source_path).unwrap();
        std::fs::remove_file(chunk_path).unwrap();
        assert!(
            expected.status.success(),
            "{}",
            String::from_utf8_lossy(&expected.stderr)
        );
        assert!(
            actual.status.success(),
            "{}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(actual.stdout, expected.stdout, "{profile:?}");
    }
}

#[test]
#[ignore = "須提供本機官方 Lua 5.4.9／5.5.1 oracle 路徑"]
fn native_chunk_executes_in_both_official_oracles() {
    for (language, profile, variable) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54, "RIVETLUA_LUA54"),
        (LanguageProfile::Lua55, LuaProfile::Lua55, "RIVETLUA_LUA55"),
    ] {
        let lua = std::env::var_os(variable).expect("官方 Lua oracle 路徑必須設定");
        for (case, source, expected) in [
            ("simple", b"return 1 + 2".as_slice(), b"3\n".as_slice()),
            ("nested", b"local function make(x) local y=7; return function(z) return x+y+z end end; return make(3)(4)".as_slice(), b"14\n".as_slice()),
            ("table", b"local t={}; t[1]=4; return t[1]".as_slice(), b"4\n".as_slice()),
            ("numeric", b"local n=0; for i=1,3 do n=n+i end; return n".as_slice(), b"6\n".as_slice()),
            ("vararg", b"local function f(...) return ... end; return f(2,nil,4)".as_slice(), b"2\tnil\t4\n".as_slice()),
            ("environment", b"return math.max(2,3)".as_slice(), b"3\n".as_slice()),
            ("branch", b"local a=1; if a<2 then a=a+3 else a=0 end; return a".as_slice(), b"4\n".as_slice()),
            ("while", b"local x=2; while x<5 do x=x+1 end; return x".as_slice(), b"5\n".as_slice()),
            ("repeat", b"local x=0; repeat x=x+1 until x>=4; return x".as_slice(), b"4\n".as_slice()),
            ("short-circuit", b"local a=false; local b=0; if a or (1<2 and 4>3) then b=7 end; return b".as_slice(), b"7\n".as_slice()),
            ("not-equal", b"return 1~=2, 3>2, 3>=3, 2<=1".as_slice(), b"true\ttrue\ttrue\tfalse\n".as_slice()),
            ("for-open-call", b"local function many() return 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24 end; local n=0; for i=1,3 do n=n+select('#', many())+i end; return n".as_slice(), b"78\n".as_slice()),
            ("for-empty-call", b"local function empty() end; local n=0; for i=1,3 do n=n+select('#', empty())+i end; return n".as_slice(), b"6\n".as_slice()),
            ("for-fixed-call", b"local function one() return 5 end; local n=0; for i=1,3 do local x=one(); n=n+x+i end; return n".as_slice(), b"21\n".as_slice()),
            ("for-vararg", b"local function count(...) local n=0; for i=1,2 do n=n+select('#', ...)+i end; return n end; return count(1,2,3,4,5,6,7,8,9,10,11,12)".as_slice(), b"27\n".as_slice()),
            ("for-body-label", if profile == LuaProfile::Lua54 {
                b"local n=0; for i=1,3 do ::again:: if i<10 then i=i+10; goto again end; n=n+i end; return n".as_slice()
            } else {
                b"local n=0; for i=1,3 do ::again:: if i<2 and n<1 then n=n+1; goto again end; n=n+i end; return n".as_slice()
            }, if profile == LuaProfile::Lua54 { b"36\n".as_slice() } else { b"7\n".as_slice() }),
            ("named-table-all", if profile == LuaProfile::Lua55 {
                b"local function f(... args) args[1]=99; args.n=3; args[3]=7; return ... end; return f(1,nil)".as_slice()
            } else { b"return 0".as_slice() }, if profile == LuaProfile::Lua55 { b"99\tnil\t7\n".as_slice() } else { b"0\n".as_slice() }),
            ("named-table-fixed", if profile == LuaProfile::Lua55 {
                b"local function f(... args) args.n=1; local a,b=...; return a,b end; return f(7,8)".as_slice()
            } else { b"return 0".as_slice() }, if profile == LuaProfile::Lua55 { b"7\tnil\n".as_slice() } else { b"0\n".as_slice() }),
            ("named-table-empty", if profile == LuaProfile::Lua55 {
                b"local function f(... args) args.n=0; return ... end; return f(1,nil)".as_slice()
            } else { b"return 0".as_slice() }, if profile == LuaProfile::Lua55 { b"\n".as_slice() } else { b"0\n".as_slice() }),
            ("named-table-tail", if profile == LuaProfile::Lua55 {
                b"local function f(... args) args.n=2; args[2]=nil; local function g(...) return ... end; return g(...) end; return f(11,22)".as_slice()
            } else { b"return 0".as_slice() }, if profile == LuaProfile::Lua55 { b"11\tnil\n".as_slice() } else { b"0\n".as_slice() }),
            ("bitwise", b"return (1<<3) | 2".as_slice(), b"10\n".as_slice()),
            ("metamethod", b"local t=setmetatable({}, {__add=function() return 9 end}); return t+t".as_slice(), b"9\n".as_slice()),
            ("close", b"local out={}; do local x<close> = setmetatable({}, {__close=function() out[1]=7 end}) end; return out[1]".as_slice(), b"7\n".as_slice()),
        ] {
            let module = native_module(source, language);
            let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
            let bytes = emit_official_chunk(
                &module,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));
            let name = if profile == LuaProfile::Lua54 { "54" } else { "55" };
            let path = std::env::temp_dir().join(format!(
                "rivetlua-p14-export-{}-{name}-{case}.luac",
                std::process::id()
            ));
            std::fs::write(&path, bytes).unwrap();
            let output = Command::new(&lua)
                .env("RIVETLUA_P14_CHUNK", &path)
                .arg("-e")
                .arg("local f=assert(loadfile(os.getenv('RIVETLUA_P14_CHUNK'))); print(f())")
                .output()
                .unwrap();
            std::fs::remove_file(path).unwrap();
            assert!(output.status.success(), "{case}: {}", String::from_utf8_lossy(&output.stderr));
            assert_eq!(output.stdout, expected, "{case}");
        }
    }
}
