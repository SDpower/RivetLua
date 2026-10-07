use rivetlua_compiler::{OfficialFixedBuiltin, OfficialTranslation, translate_official_chunk};
use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::{
    BytecodeUpvalueSource, EnvironmentSource, LuaProfile, OfficialPlanBuiltin, OfficialPlanCall,
    OfficialPlanCandidate, OfficialPlanFrameInputSource, OfficialWorkBudget, UpvalueId, Value,
    VerifyLimits, preflight_official_chunk, translate_official_chunk_with_work, verify_module,
    verify_official_execution_plan,
};
use rivetlua_runtime::{
    AbortReason, AllocationFailureKind, CallbackResult, DebugCapability, DebugLimits,
    DebugPermission, FailPoint, HostServices, RootKind, RunOutcome, RuntimeErrorKind, Vm, VmError,
};

fn candidate_from_translation(translation: &OfficialTranslation) -> OfficialPlanCandidate {
    let plan = translation.verified().official_execution().unwrap();
    let prototypes = &translation.verified().module().prototypes;
    OfficialPlanCandidate {
        root_bindings: plan.root_bindings().to_vec(),
        upvalue_maps: prototypes
            .iter()
            .map(|proto| plan.upvalue_map(proto.id).unwrap().clone())
            .collect(),
        frame_inputs: prototypes
            .iter()
            .flat_map(|proto| plan.frame_inputs(proto.id).copied())
            .collect(),
        calls: translation
            .internal_calls()
            .iter()
            .map(|call| OfficialPlanCall {
                prototype: call.prototype(),
                call_pc: call.call_pc(),
                function_register: call.function_register(),
                source_upvalue: call.source_upvalue(),
                inputs: call.inputs().to_vec(),
                open_tail: call.open_tail(),
                builtin: match call.builtin() {
                    OfficialFixedBuiltin::RawListWrite => OfficialPlanBuiltin::RawListWrite,
                    OfficialFixedBuiltin::RawVarargGet => OfficialPlanBuiltin::RawVarargGet,
                    OfficialFixedBuiltin::PackUnpack => OfficialPlanBuiltin::PackUnpack,
                    OfficialFixedBuiltin::GlobalNilCheck => OfficialPlanBuiltin::GlobalNilCheck,
                },
            })
            .collect(),
    }
}

fn live_objects(vm: &Vm) -> usize {
    let trace = vm.gc_trace();
    trace.young + trace.survivor + trace.old
}

fn byte_string(vm: &Vm, value: Value) -> Vec<u8> {
    let Value::Object(object) = value else {
        panic!("debug 回傳值應為 byte string: {value:?}");
    };
    vm.with_byte_string(object, |text| text.as_bytes().to_vec())
        .unwrap()
}

#[test]
fn official_p13_preflight_bounds_both_profiles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-small-return.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-small-return.luac").as_slice(),
        ),
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-list-flow.luac").as_slice(),
        ),
    ] {
        let limits = OfficialChunkLimits::default();
        let stats =
            preflight_official_chunk(bytes, profile, &limits, &VerifyLimits::default()).unwrap();
        let decoded = decode_official_chunk(bytes, profile, &limits).unwrap();
        let mut work = OfficialWorkBudget::new(u64::MAX);
        let translated =
            translate_official_chunk_with_work(&decoded, &VerifyLimits::default(), &mut work)
                .unwrap();
        let actual = translated
            .verified()
            .module()
            .prototypes
            .iter()
            .map(|proto| proto.instructions.len())
            .sum::<usize>();
        assert!(actual <= stats.expanded_instructions);
        assert!(work.consumed() <= stats.subsequent_work);
        let total_work = (bytes.len() as u64) * 2 + 1 + stats.subsequent_work;
        if bytes.len() < 200 {
            assert!(total_work < 10_000);
        } else {
            assert!(total_work > 50_000);
            assert!(total_work < 100_000);
        }
    }
}

#[test]
fn official_list_flow_matches_both_oracles() {
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
        let decoded = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default())
            .expect("官方 oracle fixture 必須可解碼");
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default())
            .expect("官方 oracle fixture 必須可轉譯");
        let mut vm = Vm::new_with_profile(profile).expect("VM 必須可建立");
        let environment = vm.allocate_table().expect("測試環境必須可建立");
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .expect("已驗證官方 chunk 必須可載入")
            .run();
        assert_eq!(
            outcome,
            Ok(RunOutcome::Returned(vec![
                Value::Integer(22),
                Value::Integer(44),
                Value::Integer(55),
                Value::Integer(66),
                Value::Integer(0),
                Value::Integer(11),
                Value::Integer(33),
            ])),
            "{profile:?}"
        );
    }
}

#[test]
fn official_imported_close_capture_numeric_metamethod_and_host_callback_match_both_oracles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-interop-close-callback.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-interop-close-callback.luac").as_slice(),
        ),
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-interop-close-callback-strip.luac")
                .as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-interop-close-callback-strip.luac")
                .as_slice(),
        ),
    ] {
        let decoded =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let callback = vm
            .register_callback(
                &[],
                std::rc::Rc::new(|_, args| {
                    let [Value::Integer(left), Value::Integer(right)] = args else {
                        return CallbackResult::Throw(Value::Nil);
                    };
                    CallbackResult::Return(vec![Value::Integer(left + right)])
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
        let mut execution = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![
                Value::Integer(213),
                Value::Integer(9),
                Value::Integer(6),
                Value::Integer(7),
                Value::Integer(13),
            ]),
            "{profile:?}"
        );
        drop(execution);
        drop(callback);
        vm.remove_root(environment_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn official_imported_error_close_calls_host_in_reverse_order_and_survives_abort_retry() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-interop-error-close.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-interop-error-close.luac").as_slice(),
        ),
    ] {
        let decoded =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let observed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let capture = std::rc::Rc::clone(&observed);
        let callback = vm
            .register_callback(
                &[],
                std::rc::Rc::new(move |_, args| {
                    let [Value::Integer(index), Value::Boolean(in_error)] = args else {
                        return CallbackResult::Throw(Value::Nil);
                    };
                    capture.borrow_mut().push((*index, *in_error));
                    CallbackResult::Return(vec![Value::Integer(0)])
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
        let module = translated.verified().clone();
        let run = |vm: &mut Vm| {
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            let result = execution.run().unwrap();
            let remaining = execution.fuel_remaining();
            drop(execution);
            (result, remaining)
        };
        let (first, remaining) = run(&mut vm);
        assert_eq!(
            first,
            RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(21)]),
            "{profile:?}"
        );
        assert_eq!(&*observed.borrow(), &[(2, true), (1, true)]);
        let successful_work = 1_000_000 - remaining;
        assert!(successful_work > 1);
        let roots_before = vm.roots().total_count();
        let mut aborted = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .unwrap();
        aborted.set_fuel(1).unwrap();
        assert_eq!(
            aborted.run().unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted)
        );
        drop(aborted);
        assert_eq!(vm.roots().total_count(), roots_before);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let mut lower = 2;
        let mut upper = successful_work;
        while lower < upper {
            let candidate = lower + (upper - lower) / 2;
            observed.borrow_mut().clear();
            let mut execution = vm
                .load_with_environment(module.clone(), Value::Object(environment))
                .unwrap();
            execution.set_fuel(candidate).unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            if observed.borrow().is_empty() {
                lower = candidate + 1;
            } else {
                upper = candidate;
            }
            assert!(matches!(
                outcome,
                RunOutcome::Aborted(_) | RunOutcome::Returned(_)
            ));
            assert_eq!(vm.roots().total_count(), roots_before);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        observed.borrow_mut().clear();
        let mut after_first_close = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .unwrap();
        after_first_close.set_fuel(lower).unwrap();
        assert_eq!(
            after_first_close.run().unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted),
            "{profile:?} fuel={lower}"
        );
        drop(after_first_close);
        assert_eq!(&*observed.borrow(), &[(2, true)]);
        assert_eq!(vm.roots().total_count(), roots_before);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        observed.borrow_mut().clear();
        assert_eq!(
            run(&mut vm).0,
            RunOutcome::Returned(vec![Value::Boolean(false), Value::Integer(21)]),
            "{profile:?} retry"
        );
        assert_eq!(&*observed.borrow(), &[(2, true), (1, true)]);
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(callback);
        vm.remove_root(environment_root).unwrap();
    }
}

#[test]
fn lua55_global_initializer_checks_only_nonnil_and_names_error() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-global-nil.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    for prior in [None, Some(Value::Integer(1))] {
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let environment = vm.allocate_table().unwrap();
        if let Some(prior) = prior {
            let key = vm.allocate_byte_string(b"x").unwrap();
            vm.raw_set(environment, Value::Object(key), prior).unwrap();
        }
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        match (prior, outcome) {
            (None, RunOutcome::Returned(values)) => {
                assert_eq!(values, vec![Value::Integer(7)]);
            }
            (Some(_), RunOutcome::LuaError(error)) => {
                assert_eq!(error.diagnostic_id, "E_GLOBAL_NOT_NIL");
                assert_eq!(error.source_prototype, Some(0));
                assert!(error.source_pc.is_some());
                let Value::Object(message) = error.value else {
                    panic!("OP_ERRNNIL 必須傳遞 Lua 字串錯誤值");
                };
                let bytes = vm
                    .with_byte_string(message, |text| text.as_bytes().to_vec())
                    .unwrap();
                assert_eq!(bytes, b"global 'x' already defined");
            }
            (prior, other) => panic!("{prior:?}: {other:?}"),
        }
    }
}

#[test]
fn lua55_named_varargs_snapshot_and_repeated_calls_match_oracle() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-named-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert_eq!(
        outcome,
        Ok(RunOutcome::Returned(vec![
            Value::Integer(11),
            Value::Integer(2),
            Value::Integer(99),
            Value::Integer(99),
            Value::Integer(22),
            Value::Integer(33),
            Value::Integer(2),
            Value::Integer(99),
            Value::Integer(99),
            Value::Integer(44),
        ]))
    );
}

#[test]
fn lua55_named_varargs_fixed_result_uses_current_n_and_fills_missing_with_nil() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-fixed-named-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    assert!(
        translated
            .internal_calls()
            .iter()
            .any(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
    );
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert_eq!(
        outcome,
        Ok(RunOutcome::Returned(vec![Value::Integer(7), Value::Nil]))
    );
}

#[test]
fn lua55_getvarg_reads_original_pack_and_canonical_numeric_keys() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-getvarg.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert_eq!(
        outcome,
        Ok(RunOutcome::Returned(vec![
            Value::Integer(5),
            Value::Integer(2),
            Value::Integer(5),
            Value::Nil,
            Value::Integer(6),
            Value::Integer(7),
            Value::Integer(1),
            Value::Integer(7),
            Value::Nil,
            Value::Nil,
        ]))
    );
}

#[test]
fn lua55_named_varargs_reject_invalid_n_even_for_zero_results_after_tail_call() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-invalid-named-n.luac");
    let original =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    for result_c in [0_u32, 1] {
        let mut decoded = original.clone();
        let child = &mut decoded.main.children[0];
        let vararg = child
            .code
            .iter_mut()
            .find(|word| **word & 0x7f == 80)
            .unwrap();
        *vararg = (*vararg & !(0xff << 24)) | (result_c << 24);
        if result_c == 1 {
            child.code[4] = 71;
        }
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let environment = vm.allocate_table().unwrap();
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::LuaError(error) = outcome else {
            panic!("VARARG C={result_c} 必須拒絕無效 n：{outcome:?}");
        };
        let Value::Object(message) = error.value else {
            panic!("VARARG C={result_c} 必須產生 Lua 字串錯誤");
        };
        let actual = vm
            .with_byte_string(message, |text| text.as_bytes().to_vec())
            .unwrap();
        assert!(
            actual
                .windows(b"vararg table has no proper 'n'".len())
                .any(|window| window == b"vararg table has no proper 'n'"),
            "C={result_c}: {actual:?}"
        );
    }
}

#[test]
fn lua55_official_varargs_survive_recursive_tail_calls_and_coroutine_resume() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-recursive-coroutine.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert_eq!(
        outcome,
        Ok(RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(11),
            Value::Integer(11),
            Value::Boolean(true),
            Value::Integer(11),
            Value::Integer(99),
            Value::Integer(99),
            Value::Integer(4),
            Value::Integer(8),
        ]))
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    vm.collect_major().unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn official_parameter_ingress_and_captured_environment_match_both_oracles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-parameter-abi.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-parameter-abi.luac").as_slice(),
        ),
    ] {
        let decoded =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let plan = translated.verified().official_execution().unwrap();
        for prototype in &translated.verified().module().prototypes {
            let environment = prototype.frame.environment.0;
            assert_eq!(environment, prototype.parameter_count + 1);
            let mapping = plan.upvalue_map(prototype.id).unwrap();
            assert!(mapping.guest_start.0 > environment + 6);
            for input in plan.frame_inputs(prototype.id) {
                match input.source {
                    OfficialPlanFrameInputSource::GuestNamedVarargTable => {
                        assert!(input.register.0 >= mapping.guest_start.0);
                        assert!(
                            input.register.0 < mapping.guest_start.0 + mapping.guest_register_count
                        );
                    }
                    OfficialPlanFrameInputSource::OriginalVarargs
                    | OfficialPlanFrameInputSource::ActiveVarargs => {
                        assert!(input.register.0 > environment);
                        assert!(input.register.0 < mapping.guest_start.0);
                    }
                }
            }
            for call in translated
                .internal_calls()
                .iter()
                .filter(|call| call.prototype() == prototype.id)
            {
                assert_ne!(call.function_register().0, environment);
                assert!(call.inputs().iter().all(|input| input.0 != environment));
            }
        }
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let marker = vm.allocate_byte_string(b"marker").unwrap();
        vm.raw_set(environment, Value::Object(marker), Value::Integer(29))
            .unwrap();
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run();
        assert_eq!(
            outcome,
            Ok(RunOutcome::Returned(vec![
                Value::Nil,
                Value::Integer(5),
                Value::Integer(3),
                Value::Nil,
                Value::Integer(7),
                Value::Integer(8),
                Value::Integer(29),
            ])),
            "{profile:?}"
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn official_private_frame_values_survive_gc_on_every_allocation_and_are_released() {
    for (profile, bytes, expected) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-list-flow.luac").as_slice(),
            vec![22, 44, 55, 66, 0, 11, 33],
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-named-varargs.luac").as_slice(),
            vec![11, 2, 99, 99, 22, 33, 2, 99, 99, 44],
        ),
    ] {
        let decoded =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.set_collect_every_allocation(true);
        for _ in 0..3 {
            let mut execution = vm
                .load_with_environment(translated.verified().clone(), Value::Object(environment))
                .unwrap();
            let outcome = execution.run();
            assert_eq!(
                outcome,
                Ok(RunOutcome::Returned(
                    expected.iter().copied().map(Value::Integer).collect()
                )),
                "{profile:?}"
            );
            drop(execution);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.object_kind(environment), Err(VmError::StaleObject));
    }
}

#[test]
fn official_variadic_frame_allocation_failure_cleans_roots_and_can_retry() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-named-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    let before_roots = vm.roots().total_count();
    vm.inject_failure_once(FailPoint::TableArrayReserve);
    let mut execution = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap();
    let error = execution.run().unwrap_err();
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::TableArrayReserve))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), before_roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let result = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert!(matches!(result, Ok(RunOutcome::Returned(_))), "{result:?}");
    vm.remove_root(root).unwrap();
    vm.collect_major().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn official_private_registers_and_upvalues_remain_hidden_by_debug_policy() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-debug-private.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("debug policy 錯誤必須可由 pcall 捕捉：{outcome:?}");
    };
    assert_eq!(values.len(), 13);
    assert_eq!(values[0], Value::Integer(11));
    for pair in values[1..].chunks_exact(2) {
        assert_eq!(pair[0], Value::Boolean(false));
        let value = pair[1];
        let Value::Object(message) = value else {
            panic!("debug policy 必須傳遞 Lua 字串錯誤");
        };
        let actual = vm
            .with_byte_string(message, |text| text.as_bytes().to_vec())
            .unwrap();
        assert_eq!(actual, b"E_HOST_POLICY_DEBUG");
    }
}

#[test]
fn official_debug_metadata_reports_guest_names_lines_and_counts_for_both_profiles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-debug-metadata.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-debug-metadata.luac").as_slice(),
        ),
    ] {
        let source =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        let debug = DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::Upvalues)
            .allow(DebugPermission::Traceback);
        let mut vm =
            Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_debug_builtins(environment).unwrap();
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("官方 debug 查詢必須返回: {outcome:?}");
        };
        assert_eq!(values.len(), 12);
        let source_name = byte_string(&vm, values[0]);
        assert_eq!(
            source_name,
            b"@crates/rivetlua-runtime/tests/official_chunk_fixtures/debug_metadata.lua"
        );
        assert_eq!(values[1], Value::Integer(3));
        assert_eq!(values[2], Value::Integer(5));
        assert_eq!(values[3], Value::Integer(2));
        assert_eq!(values[4], Value::Integer(1));
        assert_eq!(values[5], Value::Boolean(false));
        for (index, expected) in [(6, b"x".as_slice()), (8, b"a".as_slice())] {
            let name = byte_string(&vm, values[index]);
            assert_eq!(name, expected);
        }
        assert_eq!(values[7], Value::Integer(11));
        assert_eq!(values[9], Value::Integer(2));
        let trace = byte_string(&vm, values[10]);
        assert!(
            trace
                .windows(b"debug_metadata.lua:11".len())
                .any(|part| part == b"debug_metadata.lua:11")
        );
        assert_eq!(values[11], Value::Boolean(true));
    }
}

#[test]
fn official_short_source_matches_fixed_lua_oracles_for_both_profiles() {
    let long_path = format!("@{}/tail.lua", "x".repeat(70)).into_bytes();
    let long_short = format!("...{}/tail.lua", "x".repeat(47)).into_bytes();
    let long_literal = vec![b'q'; 50];
    let literal_short = format!("[string \"{}...\"]", "q".repeat(45)).into_bytes();
    let cases = [
        (
            Some(b"=literal-name".to_vec()),
            b"=literal-name".to_vec(),
            b"literal-name".to_vec(),
        ),
        (Some(long_path.clone()), long_path, long_short),
        (
            Some(b"alpha\nbeta".to_vec()),
            b"alpha\nbeta".to_vec(),
            b"[string \"alpha...\"]".to_vec(),
        ),
        (Some(long_literal.clone()), long_literal, literal_short),
        (None, b"=?".to_vec(), b"?".to_vec()),
    ];
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-short-source.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-short-source.luac").as_slice(),
        ),
    ] {
        for (name, expected_source, expected_short) in &cases {
            let mut source =
                decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
            source.main.source = name.clone();
            for child in &mut source.main.children {
                child.source = None;
            }
            let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
            let debug = DebugCapability::deny_all().allow(DebugPermission::Info);
            let mut vm =
                Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.install_debug_builtins(environment).unwrap();
            let outcome = vm
                .load_with_environment(translated.verified().clone(), Value::Object(environment))
                .unwrap()
                .run()
                .unwrap();
            let RunOutcome::Returned(values) = outcome else {
                panic!("short_src 查詢應返回: {outcome:?}")
            };
            assert_eq!(byte_string(&vm, values[0]), *expected_source);
            assert_eq!(byte_string(&vm, values[1]), *expected_short);
        }
    }
}

#[test]
fn official_traceback_uses_current_and_saved_caller_pc_lines() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-traceback-lines.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-traceback-lines.luac").as_slice(),
        ),
    ] {
        let source =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        let debug = DebugCapability::deny_all().allow(DebugPermission::Traceback);
        let mut vm =
            Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.install_debug_builtins(environment).unwrap();
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("traceback 應返回: {outcome:?}")
        };
        let trace = byte_string(&vm, values[0]);
        for line in [3, 6, 9] {
            let expected = format!("traceback_lines.lua:{line}");
            assert!(
                trace
                    .windows(expected.len())
                    .any(|part| part == expected.as_bytes()),
                "{trace:?}"
            );
        }
    }
}

#[test]
fn official_debug_long_source_prepays_lookup_and_copy_work() {
    fn inherit_source(proto: &mut rivetlua_core::bytecode::official::OfficialPrototype) {
        for child in &mut proto.children {
            child.source = None;
            inherit_source(child);
        }
    }
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug-metadata.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    assert!(source.main.children.len() >= 1);
    source.main.source = Some(vec![b'z'; 8192]);
    inherit_source(&mut source.main);
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    assert!(translated.verified().module().prototypes.len() >= 3);
    for (debug, low_fuel) in [
        (
            DebugCapability::deny_all()
                .allow(DebugPermission::Info)
                .with_limits(DebugLimits {
                    max_work_units: 128,
                    ..DebugLimits::default()
                }),
            false,
        ),
        (
            DebugCapability::deny_all().allow(DebugPermission::Info),
            true,
        ),
    ] {
        let mut vm =
            Vm::new_with_services(LuaProfile::Lua55, HostServices::deny_all().and_debug(debug))
                .unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_debug_builtins(environment).unwrap();
        let mut execution = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap();
        if low_fuel {
            execution.set_fuel(1000).unwrap();
        }
        let outcome = execution.run();
        if low_fuel {
            assert_eq!(
                outcome.unwrap(),
                RunOutcome::Aborted(AbortReason::FuelExhausted)
            );
        } else {
            let RunOutcome::LuaError(error) = outcome.unwrap() else {
                panic!("低 debug 額度應回 LuaError")
            };
            assert_eq!(error.kind, RuntimeErrorKind::DebugBudget);
        }
    }
}

#[test]
fn official_debug_stripped_upvalue_names_have_bounded_fallback() {
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug-metadata.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    fn strip_names(proto: &mut rivetlua_core::bytecode::official::OfficialPrototype) {
        for name in &mut proto.debug.upvalue_names {
            *name = None;
        }
        for child in &mut proto.children {
            strip_names(child);
        }
    }
    strip_names(&mut source.main);
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::Info)
        .allow(DebugPermission::Upvalues)
        .allow(DebugPermission::Traceback);
    let mut vm =
        Vm::new_with_services(LuaProfile::Lua55, HostServices::deny_all().and_debug(debug))
            .unwrap();
    let environment = vm.allocate_table().unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("缺失名稱應返回預設字串: {outcome:?}")
    };
    assert_eq!(byte_string(&vm, values[6]), b"(no name)");
    assert_eq!(byte_string(&vm, values[8]), b"(no name)");
}

#[test]
fn official_long_upvalue_name_is_charged_before_copy() {
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug-metadata.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    source.main.children[0].children[0].debug.upvalue_names[0] = Some(vec![b'n'; 8192]);
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    for (low_fuel, limit) in [(false, 1024), (true, 100_000)] {
        let debug = DebugCapability::deny_all()
            .allow(DebugPermission::Info)
            .allow(DebugPermission::Upvalues)
            .allow(DebugPermission::Traceback)
            .with_limits(DebugLimits {
                max_work_units: limit,
                ..DebugLimits::default()
            });
        let mut vm =
            Vm::new_with_services(LuaProfile::Lua55, HostServices::deny_all().and_debug(debug))
                .unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_debug_builtins(environment).unwrap();
        let mut execution = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap();
        if low_fuel {
            execution.set_fuel(3000).unwrap();
        }
        let outcome = execution.run().unwrap();
        if low_fuel {
            assert_eq!(outcome, RunOutcome::Aborted(AbortReason::FuelExhausted));
        } else {
            let RunOutcome::LuaError(error) = outcome else {
                panic!("長名稱應被 DebugBudget 拒絕")
            };
            assert_eq!(error.kind, RuntimeErrorKind::DebugBudget);
        }
        drop(execution);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn official_debug_source_survives_each_gc_and_table_write_failure_cleans_roots() {
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-short-source.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    source.main.source = Some(b"@\xff.lua".to_vec());
    source.main.children[0].source = None;
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let debug = DebugCapability::deny_all().allow(DebugPermission::Info);
    let mut vm =
        Vm::new_with_services(LuaProfile::Lua55, HostServices::deny_all().and_debug(debug))
            .unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    vm.set_collect_every_allocation(true);
    for _ in 0..2 {
        let outcome = vm
            .load_with_environment(translated.verified().clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("metadata/GC 應返回: {outcome:?}")
        };
        assert_eq!(byte_string(&vm, values[0]), b"@\xff.lua");
        assert_eq!(byte_string(&vm, values[1]), b"\xff.lua");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    vm.inject_failure_once(FailPoint::TableInsert);
    let outcome = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run();
    assert!(
        matches!(outcome, Err(ref error) if error.kind == RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::TableInsert))),
        "{outcome:?}"
    );
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    let retry = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    assert!(matches!(retry, RunOutcome::Returned(_)), "{retry:?}");
    vm.remove_root(root).unwrap();
    vm.collect_major().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn official_hidden_upvalue_is_not_read_when_public_plan_uses_parent_upvalue_environment() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-debug-hidden.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut module = translated.verified().module().clone();
    let child = &mut module.prototypes[1];
    assert_eq!(
        translated
            .verified()
            .official_execution()
            .unwrap()
            .upvalue_map(child.id)
            .unwrap()
            .guest_count,
        0
    );
    assert!(matches!(
        child.upvalues[0].source,
        BytecodeUpvalueSource::ParentUpvalue(_)
    ));
    child.frame.environment_source = EnvironmentSource::ParentUpvalue {
        upvalue: UpvalueId(0),
    };
    let verified = verify_module(module, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let verified = verify_official_execution_plan(
        verified,
        candidate_from_translation(&translated),
        &VerifyLimits::default(),
    )
    .unwrap();
    let services = HostServices::deny_all()
        .and_debug(DebugCapability::deny_all().allow(DebugPermission::Upvalues));
    let mut vm = Vm::new_with_services(LuaProfile::Lua55, services).unwrap();
    let environment = vm.allocate_table().unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let outcome = vm
        .load_with_environment(verified, Value::Object(environment))
        .unwrap()
        .run();
    assert_eq!(
        outcome,
        Ok(RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
        ]))
    );
}

#[test]
fn official_object_varargs_remain_live_across_tail_call_and_park_then_collect() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-object-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(translated.verified().clone(), Value::Object(environment))
        .unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    let RunOutcome::Returned(values) = outcome else {
        panic!("object varargs 必須在 coroutine resume 後保活：{outcome:?}");
    };
    assert_eq!(values.len(), 8);
    assert_eq!(
        values[0..3],
        [
            Value::Boolean(true),
            Value::Integer(1),
            Value::Boolean(true)
        ]
    );
    assert_eq!(values[3], values[4]);
    let Value::Object(table) = values[3] else {
        panic!("vararg table 值必須存活");
    };
    assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(41)));
    assert_eq!(values[5], Value::Integer(41));
    let Value::Object(text) = values[6] else {
        panic!("vararg 字串值必須存活");
    };
    assert_eq!(
        vm.with_byte_string(text, |bytes| bytes.as_bytes().to_vec())
            .unwrap(),
        b"edge"
    );
    assert_eq!(values[7], Value::Integer(43));
    vm.remove_root(root).unwrap();
    vm.collect_major().unwrap();
    assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(text), Err(VmError::StaleObject));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn official_root_closure_and_root_pack_allocation_sites_rollback_and_retry() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-root-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    let module = translated.verified().clone();
    let mut baseline = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = baseline.allocate_table().unwrap();
    let root = baseline.add_root(RootKind::Host, environment).unwrap();
    let first = baseline.allocation_trace().next_ordinal;
    let probe = baseline.ledger_probe();
    let execution = baseline
        .load_with_environment(module.clone(), Value::Object(environment))
        .unwrap();
    let last = probe.trace().next_ordinal;
    drop(execution);
    baseline.remove_root(root).unwrap();
    assert!(last > first && last - first < 256);
    let mut sites = Vec::new();
    for ordinal in first..last {
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        let before_live = live_objects(&vm);
        assert_eq!(vm.allocation_trace().next_ordinal, first);
        vm.inject_allocation_failure_at(ordinal);
        let error = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .err()
            .unwrap_or_else(|| panic!("ordinal {ordinal} 注入後載入竟成功"));
        assert!(
            matches!(error.kind, RuntimeErrorKind::Heap(_)),
            "ordinal {ordinal}: {error:?}"
        );
        let failure = vm.allocation_trace().last_failure.unwrap();
        assert_eq!(failure.attempt.ordinal, ordinal);
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        sites.push((
            ordinal,
            failure.attempt.point,
            failure.attempt.site.file,
            failure.attempt.site.line,
        ));
        assert_eq!(vm.roots().total_count(), 1, "ordinal {ordinal}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "ordinal {ordinal}");
        vm.collect_major().unwrap();
        assert_eq!(
            live_objects(&vm),
            before_live,
            "ordinal {ordinal}: {failure:?}"
        );
        let outcome = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .unwrap()
            .run();
        assert!(
            matches!(outcome, Ok(RunOutcome::Returned(_))),
            "ordinal {ordinal}: {outcome:?}"
        );
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(live_objects(&vm), 0, "ordinal {ordinal}");
        assert_eq!(vm.roots().total_count(), 0, "ordinal {ordinal}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "ordinal {ordinal}");
    }
    let pack_start = sites
        .iter()
        .find(|site| site.1 == Some(FailPoint::TableArrayReserve))
        .map(|site| site.0)
        .expect("root vararg table array 配置點未覆蓋");
    let before_pack = sites
        .iter()
        .filter(|site| site.0 < pack_start)
        .collect::<Vec<_>>();
    assert!(
        before_pack
            .iter()
            .filter(|site| site.1 == Some(FailPoint::SlotReserve))
            .count()
            >= 5,
        "module/builtin/upvalue/closure 配置點未覆蓋：{sites:?}"
    );
    assert!(
        before_pack
            .iter()
            .any(|site| site.1 == Some(FailPoint::ClosureCapturesReserve)),
        "closure captures 配置點未覆蓋：{sites:?}"
    );
    assert!(
        sites
            .iter()
            .any(|site| site.0 > pack_start && site.1 == Some(FailPoint::TableHashReserve)),
        "root closure 後 vararg pack 初始化未覆蓋：{sites:?}"
    );
}

#[test]
fn official_pack_unpack_allocation_sites_rollback_and_retry() {
    let bytes = include_bytes!("official_chunk_fixtures/lua55-named-varargs.luac");
    let decoded =
        decode_official_chunk(bytes, LuaProfile::Lua55, &OfficialChunkLimits::default()).unwrap();
    let translated = translate_official_chunk(&decoded, &VerifyLimits::default()).unwrap();
    assert!(
        translated
            .internal_calls()
            .iter()
            .any(|call| call.builtin() == OfficialFixedBuiltin::PackUnpack)
    );
    let module = translated.verified().clone();
    let mut baseline = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = baseline.allocate_table().unwrap();
    let root = baseline.add_root(RootKind::Host, environment).unwrap();
    let probe = baseline.ledger_probe();
    let mut execution = baseline
        .load_with_environment(module.clone(), Value::Object(environment))
        .unwrap();
    let first = probe.trace().next_ordinal;
    assert!(matches!(execution.run(), Ok(RunOutcome::Returned(_))));
    let last = probe.trace().next_ordinal;
    drop(execution);
    baseline.remove_root(root).unwrap();
    assert!(last > first && last - first < 512);
    let mut sites = Vec::new();
    for ordinal in first..last {
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        let before_live = live_objects(&vm);
        vm.inject_allocation_failure_at(ordinal);
        let probe = vm.ledger_probe();
        let mut execution = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .unwrap();
        assert_eq!(probe.trace().next_ordinal, first, "ordinal {ordinal}");
        let outcome = execution.run();
        assert!(outcome.is_err(), "ordinal {ordinal}: {outcome:?}");
        let failure = probe.trace().last_failure.unwrap();
        assert_eq!(failure.attempt.ordinal, ordinal);
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        sites.push((
            ordinal,
            failure.attempt.point,
            failure.attempt.site.file,
            failure.attempt.site.line,
        ));
        drop(execution);
        assert_eq!(vm.roots().total_count(), 1, "ordinal {ordinal}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "ordinal {ordinal}");
        vm.collect_major().unwrap();
        assert_eq!(
            live_objects(&vm),
            before_live,
            "ordinal {ordinal}: {failure:?}"
        );
        let retry = vm
            .load_with_environment(module.clone(), Value::Object(environment))
            .unwrap()
            .run();
        assert!(
            matches!(retry, Ok(RunOutcome::Returned(_))),
            "ordinal {ordinal}: {retry:?}"
        );
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(live_objects(&vm), 0, "ordinal {ordinal}");
        assert_eq!(vm.roots().total_count(), 0, "ordinal {ordinal}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "ordinal {ordinal}");
    }
    let helper_entries = sites
        .iter()
        .filter(|site| site.1 == Some(FailPoint::WorkReserve) && site.2.ends_with("/vm/mod.rs"))
        .map(|site| site.0)
        .collect::<Vec<_>>();
    assert_eq!(
        helper_entries.len(),
        2,
        "兩次 PackUnpack 入口配置點：{sites:?}"
    );
    for (index, &start) in helper_entries.iter().enumerate() {
        let end = helper_entries.get(index + 1).copied().unwrap_or(last);
        let segment = sites
            .iter()
            .filter(|site| start < site.0 && site.0 < end)
            .collect::<Vec<_>>();
        let snapshot = segment
            .iter()
            .find(|site| site.1 == Some(FailPoint::TableArrayReserve))
            .map(|site| site.0)
            .expect("PackUnpack snapshot table 配置未命中");
        let key = segment
            .iter()
            .find(|site| {
                site.0 > snapshot
                    && site.1 == Some(FailPoint::StringBytesReserve)
                    && site.2.ends_with("/string.rs")
            })
            .map(|site| site.0)
            .expect("PackUnpack snapshot key 配置未命中");
        assert!(
            segment.iter().any(|site| site.0 > key
                && site.1 == Some(FailPoint::ReturnReserve)
                && site.2.ends_with("/stdlib/math.rs")),
            "PackUnpack result staging 配置未命中：{segment:?}"
        );
    }
}
