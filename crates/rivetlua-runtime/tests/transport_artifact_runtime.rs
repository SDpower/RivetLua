use std::{cell::RefCell, rc::Rc};

use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, emit_with_native_debug, lex, lower, parse,
    resolve,
};
use rivetlua_core::{
    LuaProfile, ModuleOrigin, NativeDebugCandidate, OfficialChunkLimits, OfficialWorkBudget,
    TransportLimits, Value, VerifyLimits, decode_module, decode_official_chunk,
    decode_transport_module, encode_module, encode_transport_module, preflight_transport_decode,
    translate_official_chunk, transport_scan_admission, verify_native_debug,
};
use rivetlua_runtime::{CallbackResult, RootKind, RunOutcome, Vm};

fn transported(profile: LuaProfile, bytes: &[u8]) -> rivetlua_core::VerifiedModule {
    let limits = TransportLimits::default();
    let chunk = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&chunk, &limits.verify).unwrap();
    let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
    let encoded = encode_transport_module(translated.verified(), &limits, &mut work).unwrap();
    decode_transport_module(
        encoded.rvlu(),
        encoded.sidecar(),
        profile,
        &limits,
        &mut work,
    )
    .unwrap()
}

fn rich_native(profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let source =
        b"local x = 5\nlocal y = 7\nlocal function inner() return x + y end\nreturn inner()";
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let syntax = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&syntax, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@transport-rich.lua",
        &TransportLimits::default().verify,
    )
    .unwrap()
    .verified()
    .clone()
}

#[test]
fn native_initializer_temporary_is_ephemeral_across_transport() {
    let source = b"local A=function() return 7 end; return A()";
    let limits = TransportLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let tokens = lex(source, language, &CompileLimits::default()).unwrap();
        let ast = parse(&tokens, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&ast, &tokens, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let original = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@transport-initializer.lua",
            &limits.verify,
        )
        .unwrap();
        let original_debug = original.verified().native_debug().unwrap();
        assert_eq!(
            original_debug
                .initializer_temporaries_for(ir.prototypes[0].id)
                .unwrap()
                .len(),
            1
        );
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(original.verified(), &limits, &mut work).unwrap();
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work,
        )
        .unwrap();
        // RVAS/RVLU 只保存既有可執行語意；native initializer mapping 不進 wire。
        assert!(
            reloaded
                .native_debug()
                .unwrap()
                .initializer_temporaries_for(ir.prototypes[0].id)
                .unwrap()
                .is_empty()
        );
        assert_eq!(reloaded.module(), original.verified().module());
        for module in [original.verified().clone(), reloaded] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            assert_eq!(
                vm.load(module).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![Value::Integer(7)])
            );
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn native_raw_list_write_kind3_roundtrips_with_optional_debug_both_profiles() {
    let source =
        b"local function values() return 7,8,9 end; local t={values()}; return t[1],t[2],t[3]";
    let limits = TransportLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let chunk = lex(source, language, &CompileLimits::default()).unwrap();
        let syntax = parse(&chunk, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&syntax, &chunk, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        for debug in [false, true] {
            let original = if debug {
                emit_with_native_debug(&ir, &resolved, source, b"@native-list.lua", &limits.verify)
                    .unwrap()
            } else {
                emit(&ir, &limits.verify).unwrap()
            };
            assert_eq!(original.verified().origin(), ModuleOrigin::NativeRvlu);
            assert!(
                original
                    .verified()
                    .official_execution()
                    .is_some_and(|plan| plan.is_native_builtin())
            );
            let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
            let encoded = encode_transport_module(original.verified(), &limits, &mut work).unwrap();
            assert_eq!(encoded.sidecar()[6], 3);
            let bare = decode_module(encoded.rvlu(), profile, &limits.verify).unwrap();
            assert!(bare.official_execution().is_none());
            let decoded = decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut work,
            )
            .unwrap();
            assert_eq!(decoded.origin(), ModuleOrigin::NativeRvlu);
            assert_eq!(decoded.native_debug().is_some(), debug);
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_collect_every_allocation(true);
            assert_eq!(
                vm.load(decoded).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![
                    Value::Integer(7),
                    Value::Integer(8),
                    Value::Integer(9)
                ]),
            );
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn native_helper_debug_cannot_name_hidden_upvalue_or_private_scratch() {
    let source =
        b"local function values() return 7,8,9 end; local t={values()}; return t[1],t[2],t[3]";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let chunk = lex(source, language, &CompileLimits::default()).unwrap();
        let syntax = parse(&chunk, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&syntax, &chunk, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let original = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@helper-debug.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let module = original.verified();
        let debug = module.native_debug().unwrap();
        let call = &module.official_execution().unwrap().calls()[0];
        let proto_index = debug
            .prototypes()
            .iter()
            .position(|proto| proto.prototype == call.prototype)
            .unwrap();
        let make_candidate = || NativeDebugCandidate {
            source_name: debug.source_name().to_vec(),
            prototypes: debug.prototypes().to_vec(),
            temporaries: Vec::new(),
            initializer_temporaries: Vec::new(),
            non_counted_pcs: Vec::new(),
        };
        let mut forged = make_candidate();
        let hidden = forged.prototypes[proto_index]
            .upvalue_names
            .last_mut()
            .unwrap();
        *hidden = Some(b"RawListWrite".to_vec());
        assert!(
            verify_native_debug(
                module,
                forged,
                &VerifyLimits::default(),
                &mut OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap()
            )
            .is_err()
        );
        let mut forged = make_candidate();
        let local = forged.prototypes[proto_index].locals.first_mut().unwrap();
        local.register = call.function_register;
        assert!(
            verify_native_debug(
                module,
                forged,
                &VerifyLimits::default(),
                &mut OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap()
            )
            .is_err()
        );
        for _ in 0..2 {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_collect_every_allocation(true);
            assert_eq!(
                vm.load(module.clone()).unwrap().run(),
                Ok(RunOutcome::Returned(vec![
                    Value::Integer(7),
                    Value::Integer(8),
                    Value::Integer(9)
                ]))
            );
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn native_kind3_multiple_deep_helper_declarations_roundtrip() {
    let source = b"local n=11; local function outer(x) local hold=5; return function(...) local function values() return n+x,hold,9 end; local a={values()}; local b={...}; return a[1],a[2],a[3],b[1],b[2] end end; return outer(20)(7,8)";
    let limits = TransportLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let chunk = lex(source, language, &CompileLimits::default()).unwrap();
        let syntax = parse(&chunk, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&syntax, &chunk, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let original = emit(&ir, &limits.verify).unwrap();
        assert_eq!(
            original
                .verified()
                .official_execution()
                .unwrap()
                .calls()
                .len(),
            2
        );
        let encoded = encode_transport_module(
            original.verified(),
            &limits,
            &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
        )
        .unwrap();
        let decoded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded.origin(), ModuleOrigin::NativeRvlu);
        assert_eq!(decoded.official_execution().unwrap().calls().len(), 2);
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_collect_every_allocation(true);
        assert_eq!(
            vm.load(decoded).unwrap().run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(31),
                Value::Integer(5),
                Value::Integer(9),
                Value::Integer(7),
                Value::Integer(8),
            ]))
        );
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn native_raw_list_write_kind3_rejects_forged_and_spliced_declarations() {
    let limits = TransportLimits::default();
    let source = b"local function values() return 7,8 end; return {values()}";
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let chunk = lex(source, language, &CompileLimits::default()).unwrap();
        let syntax = parse(&chunk, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&syntax, &chunk, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &limits.verify).unwrap();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(module.verified(), &limits, &mut work).unwrap();
        let rvlu = encoded.rvlu();
        let sidecar = encoded.sidecar();
        assert_eq!(sidecar[6], 3);
        assert_eq!(u32::from_le_bytes(sidecar[48..52].try_into().unwrap()), 1);
        let mut cases = Vec::new();
        let mut forged = sidecar.to_vec();
        forged[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(forged);
        let mut forged = sidecar.to_vec();
        forged[62..64].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(forged);
        let mut forged = sidecar.to_vec();
        forged[73..75].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(forged);
        let mut forged = sidecar.to_vec();
        forged[75] = 99;
        cases.push(forged);
        let mut forged = sidecar.to_vec();
        forged[76] = 2;
        cases.push(forged);
        let mut forged = sidecar.to_vec();
        forged[48..52].copy_from_slice(&2u32.to_le_bytes());
        forged.splice(76..76, sidecar[52..76].iter().copied());
        let forged_len = forged.len() as u64;
        forged[8..16].copy_from_slice(&forged_len.to_le_bytes());
        cases.push(forged);
        for forged in cases {
            assert!(
                decode_transport_module(
                    rvlu,
                    &forged,
                    profile,
                    &limits,
                    &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
                )
                .is_err()
            );
        }
        let mut wrong_rvlu = rvlu.to_vec();
        let last = wrong_rvlu.len() - 1;
        wrong_rvlu[last] ^= 1;
        assert!(
            decode_transport_module(
                &wrong_rvlu,
                sidecar,
                profile,
                &limits,
                &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
            )
            .is_err()
        );
    }
}

#[test]
fn native_raw_list_write_kind3_has_exact_and_one_below_admission() {
    let source = b"local function values() return 7,8 end; return {values()}";
    let limits = TransportLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        let chunk = lex(source, language, &CompileLimits::default()).unwrap();
        let syntax = parse(&chunk, language, &CompileLimits::default()).unwrap();
        let resolved = resolve(&syntax, &chunk, language, &CompileLimits::default()).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &limits.verify).unwrap();
        let encoded = encode_transport_module(
            module.verified(),
            &limits,
            &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
        )
        .unwrap();
        let scan = transport_scan_admission(encoded.rvlu().len(), encoded.sidecar().len()).unwrap();
        let admission =
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &limits)
                .unwrap();
        let total = scan.work + admission.subsequent_work;
        let mut exact = limits;
        exact.max_work = total;
        exact.max_temporary_bytes = admission.temporary_bytes;
        exact.max_retained_bytes = admission.retained_bytes;
        let loaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &exact,
            &mut OfficialWorkBudget::new(total),
        )
        .unwrap();
        assert!(
            loaded
                .official_execution()
                .is_some_and(|plan| plan.is_native_builtin())
        );
        for one_below in [
            TransportLimits {
                max_work: total - 1,
                ..exact
            },
            TransportLimits {
                max_temporary_bytes: admission.temporary_bytes - 1,
                ..exact
            },
            TransportLimits {
                max_retained_bytes: admission.retained_bytes - 1,
                ..exact
            },
        ] {
            assert!(
                preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &one_below,)
                    .is_err()
            );
        }
        assert!(
            decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &exact,
                &mut OfficialWorkBudget::new(total - 1),
            )
            .is_err()
        );
    }
}

fn first_local_offset(sidecar: &[u8]) -> usize {
    fn u32_at(bytes: &[u8], offset: usize) -> usize {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
    }
    let mut at = 16;
    at += 4 + u32_at(sidecar, at);
    let count = u32_at(sidecar, at);
    at += 4;
    for _ in 0..count {
        at += 13;
        let lines = u32_at(sidecar, at);
        at += 4 + 4 * lines;
        let locals = u32_at(sidecar, at);
        at += 4;
        if locals > 0 {
            return at;
        }
        let names = u32_at(sidecar, at);
        at += 4;
        for _ in 0..names {
            let tag = sidecar[at];
            at += 1;
            if tag == 1 {
                at += 4 + u32_at(sidecar, at);
            }
        }
    }
    panic!("rich native fixture 應至少有一個 local")
}

#[test]
fn loaded_transport_preserves_normal_and_open_multivalue_execution_both_profiles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
        ),
    ] {
        let module = transported(profile, bytes);
        assert!(module.official_execution().is_some());
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let result = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            result,
            RunOutcome::Returned(vec![
                Value::Integer(22),
                Value::Integer(44),
                Value::Integer(55),
                Value::Integer(66),
                Value::Integer(0),
                Value::Integer(11),
                Value::Integer(33),
            ])
        );
    }
}

#[test]
fn loaded_transport_preserves_close_callback_and_error_unwind_both_profiles() {
    for (profile, bytes, expected, in_error) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-interop-close-callback.luac").as_slice(),
            vec![
                Value::Integer(213),
                Value::Integer(9),
                Value::Integer(6),
                Value::Integer(7),
                Value::Integer(13),
            ],
            false,
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-interop-close-callback.luac").as_slice(),
            vec![
                Value::Integer(213),
                Value::Integer(9),
                Value::Integer(6),
                Value::Integer(7),
                Value::Integer(13),
            ],
            false,
        ),
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-interop-error-close.luac").as_slice(),
            vec![Value::Boolean(false), Value::Integer(21)],
            true,
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-interop-error-close.luac").as_slice(),
            vec![Value::Boolean(false), Value::Integer(21)],
            true,
        ),
    ] {
        let module = transported(profile, bytes);
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let capture = Rc::clone(&calls);
        let callback = vm
            .register_callback(
                &[],
                Rc::new(move |_, args| {
                    if in_error {
                        let [Value::Integer(index), Value::Boolean(flag)] = args else {
                            return CallbackResult::Throw(Value::Nil);
                        };
                        capture.borrow_mut().push((*index, *flag));
                        CallbackResult::Return(vec![Value::Integer(0)])
                    } else {
                        let [Value::Integer(left), Value::Integer(right)] = args else {
                            return CallbackResult::Throw(Value::Nil);
                        };
                        CallbackResult::Return(vec![Value::Integer(left + right)])
                    }
                }),
            )
            .unwrap();
        let key = vm.allocate_byte_string(b"host").unwrap();
        vm.raw_set(
            environment,
            Value::Object(key),
            callback.as_value(&vm).unwrap(),
        )
        .unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(expected),
            "{profile:?} error={in_error}"
        );
        if in_error {
            assert_eq!(&*calls.borrow(), &[(2, true), (1, true)]);
        }
        drop(callback);
        vm.remove_root(root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn native_debug_transport_revalidates_nested_locals_names_and_forged_slots_both_profiles() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let verified = rich_native(profile);
        let original = verified.native_debug().unwrap();
        assert!(verified.module().prototypes.len() > 1);
        assert!(
            original
                .prototypes()
                .iter()
                .any(|proto| !proto.locals.is_empty())
        );
        assert!(original.prototypes().iter().any(|proto| {
            proto
                .upvalue_names
                .iter()
                .filter(|name| name.is_some())
                .count()
                >= 2
        }));
        let limits = TransportLimits::default();
        let mut work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let encoded = encode_transport_module(&verified, &limits, &mut work).unwrap();
        let scan = transport_scan_admission(encoded.rvlu().len(), encoded.sidecar().len()).unwrap();
        let admission =
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &limits)
                .unwrap();
        let total = scan.work + admission.subsequent_work;
        assert!(
            decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut OfficialWorkBudget::new(total - 1)
            )
            .is_err()
        );
        let mut tight = limits;
        tight.max_work = total;
        tight.max_temporary_bytes = admission.temporary_bytes;
        tight.max_retained_bytes = admission.retained_bytes;
        let _ = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &tight,
            &mut OfficialWorkBudget::new(total),
        )
        .unwrap();
        tight.max_temporary_bytes -= 1;
        assert!(
            preflight_transport_decode(encoded.rvlu(), encoded.sidecar(), profile, &tight).is_err()
        );
        let reloaded = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut work,
        )
        .unwrap();
        assert_eq!(
            reloaded.native_debug().unwrap().source_name(),
            b"@transport-rich.lua"
        );
        assert_eq!(
            reloaded.native_debug().unwrap().prototypes(),
            original.prototypes()
        );
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        assert_eq!(
            vm.load_with_environment(reloaded, Value::Object(env))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(12)])
        );

        let local = first_local_offset(encoded.sidecar());
        for (offset, value) in [
            (local + 8, u16::MAX.to_le_bytes().to_vec()),
            (local + 10, vec![u8::MAX]),
            (local + 15, u32::MAX.to_le_bytes().to_vec()),
        ] {
            let mut forged = encoded.sidecar().to_vec();
            forged[offset..offset + value.len()].copy_from_slice(&value);
            assert!(
                decode_transport_module(
                    encoded.rvlu(),
                    &forged,
                    profile,
                    &limits,
                    &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap()
                )
                .is_err()
            );
        }

        let mut candidate = NativeDebugCandidate {
            source_name: original.source_name().to_vec(),
            prototypes: original.prototypes().to_vec(),
            temporaries: Vec::new(),
            initializer_temporaries: Vec::new(),
            non_counted_pcs: Vec::new(),
        };
        let named = candidate
            .prototypes
            .iter_mut()
            .find(|proto| {
                proto
                    .upvalue_names
                    .iter()
                    .filter(|name| name.is_some())
                    .count()
                    >= 2
            })
            .unwrap();
        named.upvalue_names[0] = None;
        let mut native_work = OfficialWorkBudget::for_limits(&limits.verify).unwrap();
        let one_hidden = encode_module(verified.module().clone(), profile, &limits.verify)
            .unwrap()
            .with_native_debug(candidate, &limits.verify, &mut native_work)
            .unwrap();
        let encoded =
            encode_transport_module(one_hidden.verified(), &limits, &mut native_work).unwrap();
        let recovered = decode_transport_module(
            encoded.rvlu(),
            encoded.sidecar(),
            profile,
            &limits,
            &mut native_work,
        )
        .unwrap();
        assert!(
            recovered
                .native_debug()
                .unwrap()
                .prototypes()
                .iter()
                .any(|proto| {
                    proto.upvalue_names.iter().any(Option::is_none)
                        && proto.upvalue_names.iter().any(Option::is_some)
                })
        );
    }
}
