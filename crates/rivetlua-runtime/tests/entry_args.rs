use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    LuaProfile, OfficialChunkLimits, Value, VerifyLimits, decode_official_chunk,
    translate_official_chunk,
};
use rivetlua_runtime::{
    AbortReason, AllocationFailureKind, HostHandle, RunOutcome, RuntimeErrorKind, Vm, VmError,
};

fn compile(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let lexed = lex(source, profile, &limits).unwrap();
    let parsed = parse(&lexed, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &lexed, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn official(bytes: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let source = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&source, &VerifyLimits::default())
        .unwrap()
        .into_verified()
}

#[test]
fn native_root_receives_explicit_arguments_and_trailing_nil() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        let text = vm.allocate_byte_string(b"arg").unwrap();
        let text_root = HostHandle::<Value>::new(&mut vm, text).unwrap();
        vm.set_collect_every_allocation(true);
        let environment = env_root.as_value(&vm).unwrap();
        let outcome = vm
            .load_with_environment_and_args(
                compile(b"return ...", language),
                environment,
                &[Value::Integer(7), Value::Object(text), Value::Nil],
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("root 須完成返回")
        };
        assert_eq!(values, [Value::Integer(7), Value::Object(text), Value::Nil]);
        assert_eq!(
            vm.with_byte_string(text, |string| string.as_bytes().to_vec()),
            Ok(b"arg".to_vec())
        );
        drop(text_root);
        drop(env_root);
    }
}

#[test]
fn native_root_adjusts_open_parenthesized_and_nested_arguments() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_basic_builtins(env).unwrap();
        let environment = env_root.as_value(&vm).unwrap();
        let args = [Value::Integer(7), Value::Nil, Value::Integer(9), Value::Nil];
        let cases: &[(&[u8], &[Value])] = &[
            (
                b"return select('#', ...), ...",
                &[
                    Value::Integer(4),
                    Value::Integer(7),
                    Value::Nil,
                    Value::Integer(9),
                    Value::Nil,
                ],
            ),
            (
                b"return (...), 21",
                &[Value::Integer(7), Value::Integer(21)],
            ),
            (b"local t={...}; return t[1],t[2],t[3],t[4]", &args),
            (
                b"local x=...; local function f() return x end; return f()",
                &[Value::Integer(7)],
            ),
        ];
        for (source, expected) in cases {
            let outcome = vm
                .load_with_environment_and_args(compile(source, language), environment, &args)
                .unwrap()
                .run()
                .unwrap();
            let RunOutcome::Returned(values) = outcome else {
                panic!("root 須完成返回")
            };
            assert_eq!(
                values,
                *expected,
                "source={}",
                String::from_utf8_lossy(source)
            );
        }
        let outcome = vm
            .load_with_environment_and_args(
                compile(b"return select('#', ...)", language),
                environment,
                &[],
            )
            .unwrap()
            .run()
            .unwrap();
        assert!(matches!(outcome, RunOutcome::Returned(values) if values == [Value::Integer(0)]));

        let many = (0..300).map(Value::Integer).collect::<Vec<_>>();
        let outcome = vm
            .load_with_environment_and_args(
                compile(b"return select('#', ...), ...", language),
                environment,
                &many,
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("多參數 root 須成功返回")
        };
        assert_eq!(values.len(), many.len() + 1);
        assert_eq!(values[0], Value::Integer(300));
        assert_eq!(&values[1..], many);
    }
}

#[test]
fn official_root_receives_arguments_both_profiles() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-root-varargs.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-root-varargs.luac").as_slice(),
        ),
    ] {
        let module = official(bytes, profile);
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        let text = vm.allocate_byte_string(b"official arg").unwrap();
        let text_root = HostHandle::<Value>::new(&mut vm, text).unwrap();
        vm.set_collect_every_allocation(true);
        let environment = env_root.as_value(&vm).unwrap();
        let outcome = vm
            .load_with_environment_and_args(
                module,
                environment,
                &[
                    Value::Float(-0.0),
                    Value::Nil,
                    Value::Object(text),
                    Value::Nil,
                ],
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = outcome else {
            panic!("官方 root 須返回 table")
        };
        let [Value::Object(table)] = values.as_slice() else {
            panic!("官方 root 應返回 table")
        };
        let table_root = HostHandle::<Value>::new(&mut vm, *table).unwrap();
        for (index, expected) in [
            Value::Float(-0.0),
            Value::Nil,
            Value::Object(text),
            Value::Nil,
        ]
        .into_iter()
        .enumerate()
        {
            let actual = vm
                .raw_get(*table, Value::Integer(index as i64 + 1))
                .unwrap();
            if index == 0 {
                let Value::Float(number) = actual else {
                    panic!("浮點參數須保持型別")
                };
                assert_eq!(number.to_bits(), (-0.0f64).to_bits());
            } else {
                assert_eq!(actual, expected);
            }
        }
        assert_eq!(
            vm.with_byte_string(text, |string| string.as_bytes().to_vec()),
            Ok(b"official arg".to_vec())
        );
        drop(table_root);
        drop(text_root);
        drop(env_root);
    }
}

#[test]
fn official_nonmain_fixed_entry_fills_missing_and_discards_extras() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-fixed-entry.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-fixed-entry.luac").as_slice(),
        ),
    ] {
        let module = official(bytes, profile);
        assert_eq!(module.module().prototypes[0].parameter_count, 2);
        assert!(!module.module().prototypes[0].is_variadic);
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        let text = vm.allocate_byte_string(b"fixed arg").unwrap();
        let text_root = HostHandle::<Value>::new(&mut vm, text).unwrap();
        let environment = env_root.as_value(&vm).unwrap();
        vm.set_collect_every_allocation(true);
        let missing = vm
            .load_with_environment_and_args(module.clone(), environment, &[Value::Object(text)])
            .unwrap()
            .run()
            .unwrap();
        assert!(
            matches!(missing, RunOutcome::Returned(values) if values == [Value::Object(text), Value::Nil])
        );
        let extra = vm
            .load_with_environment_and_args(
                module,
                environment,
                &[Value::Object(text), Value::Float(-0.0), Value::Integer(99)],
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = extra else {
            panic!("固定參數官方入口須成功返回")
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Object(text));
        let Value::Float(number) = values[1] else {
            panic!("浮點固定參數須保持型別")
        };
        assert_eq!(number.to_bits(), (-0.0f64).to_bits());
        assert_eq!(
            vm.with_byte_string(text, |string| string.as_bytes().to_vec()),
            Ok(b"fixed arg".to_vec())
        );
        drop(text_root);
        drop(env_root);
    }
}

#[test]
fn official_lua55_named_vararg_entry_keeps_nil_and_byte_string() {
    let module = official(
        include_bytes!("official_chunk_fixtures/lua55-named-entry.luac"),
        LuaProfile::Lua55,
    );
    assert_eq!(module.module().prototypes[0].parameter_count, 1);
    assert!(module.module().prototypes[0].is_variadic);
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
    let text = vm.allocate_byte_string(b"named arg").unwrap();
    let text_root = HostHandle::<Value>::new(&mut vm, text).unwrap();
    vm.set_collect_every_allocation(true);
    let environment = env_root.as_value(&vm).unwrap();
    let outcome = vm
        .load_with_environment_and_args(
            module,
            environment,
            &[Value::Object(text), Value::Integer(7), Value::Nil],
        )
        .unwrap()
        .run()
        .unwrap();
    assert!(matches!(
        outcome,
        RunOutcome::Returned(values)
            if values == [Value::Object(text), Value::Integer(2), Value::Integer(7), Value::Nil,
                Value::Integer(7), Value::Nil]
    ));
    assert_eq!(
        vm.with_byte_string(text, |string| string.as_bytes().to_vec()),
        Ok(b"named arg".to_vec())
    );
    drop(text_root);
    drop(env_root);
}

#[test]
fn entry_arguments_reject_foreign_and_stale_objects_before_loading() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut owner = Vm::new_with_profile(profile).unwrap();
        let foreign = owner.allocate_table().unwrap();
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        let environment = env_root.as_value(&vm).unwrap();
        let module = compile(b"return ...", language);
        assert!(matches!(
            vm.load_with_environment_and_args(module.clone(), environment, &[Value::Object(foreign)]),
            Err(error) if matches!(error.kind, rivetlua_runtime::RuntimeErrorKind::Heap(VmError::WrongVm))
        ));
        let stale = vm.allocate_table().unwrap();
        vm.collect().unwrap();
        assert!(matches!(
            vm.load_with_environment_and_args(module.clone(), environment, &[Value::Object(stale)]),
            Err(error) if matches!(error.kind, rivetlua_runtime::RuntimeErrorKind::Heap(VmError::StaleObject))
        ));
        let outcome = vm
            .load_with_environment_and_args(module, environment, &[Value::Integer(13)])
            .unwrap()
            .run()
            .unwrap();
        assert!(matches!(outcome, RunOutcome::Returned(values) if values == [Value::Integer(13)]));
    }
}

#[test]
fn entry_arguments_release_roots_after_error_fuel_and_retry() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_basic_builtins(env).unwrap();
        let argument = vm.allocate_byte_string(b"live").unwrap();
        let _arg_root = HostHandle::<Value>::new(&mut vm, argument).unwrap();
        let environment = env_root.as_value(&vm).unwrap();
        let baseline_roots = vm.roots().total_count();
        vm.set_collect_every_allocation(true);

        let mut exhausted = vm
            .load_with_environment_and_args(
                compile(b"local x=...; while true do end", language),
                environment,
                &[Value::Object(argument)],
            )
            .unwrap();
        exhausted.set_fuel(1).unwrap();
        assert_eq!(
            exhausted.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        drop(exhausted);
        assert_eq!(vm.roots().total_count(), baseline_roots);

        let error = vm
            .load_with_environment_and_args(
                compile(b"local x=...; error('boom')", language),
                environment,
                &[Value::Object(argument)],
            )
            .unwrap()
            .run();
        let Ok(RunOutcome::LuaError(error)) = error else {
            panic!("root vararg 錯誤須保留 LuaError: {error:?}");
        };
        assert_eq!(error.kind, RuntimeErrorKind::Thrown);
        let Value::Object(message) = error.value else {
            panic!("root vararg 錯誤值須為字串");
        };
        assert_eq!(
            vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
            Ok(b"boom".to_vec())
        );
        drop(error);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let outcome = vm
            .load_with_environment_and_args(
                compile(b"return ...", language),
                environment,
                &[Value::Object(argument)],
            )
            .unwrap()
            .run()
            .unwrap();
        assert!(
            matches!(outcome, RunOutcome::Returned(values) if values == [Value::Object(argument)])
        );
        assert_eq!(vm.roots().total_count(), baseline_roots);
    }
}

#[test]
fn entry_argument_close_paths_release_payloads_on_return_error_and_abort() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_basic_builtins(env).unwrap();
        let closed_key = vm.allocate_byte_string(b"closed").unwrap();
        vm.raw_set(env, Value::Object(closed_key), Value::Integer(0))
            .unwrap();
        let environment = env_root.as_value(&vm).unwrap();
        let handler = vm
            .load_with_environment(
                compile(b"return function() closed=closed+1 end", language),
                environment,
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = handler else {
            panic!("close handler 須為 closure")
        };
        let [Value::Object(closure)] = values.as_slice() else {
            panic!("close handler 須為 closure")
        };
        let _closure_root = HostHandle::<Value>::new(&mut vm, *closure).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let close_key = vm.allocate_byte_string(b"__close").unwrap();
        vm.raw_set(metatable, Value::Object(close_key), Value::Object(*closure))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        let roots = vm.roots().total_count();
        vm.set_collect_every_allocation(true);

        let outcome = vm
            .load_with_environment_and_args(
                compile(b"local x <close> = ...; return 13", language),
                environment,
                &[Value::Object(table)],
            )
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(13)]));
        assert_eq!(
            vm.raw_get(env, Value::Object(closed_key)),
            Ok(Value::Integer(1))
        );
        assert_eq!(vm.roots().total_count(), roots);

        let outcome = vm
            .load_with_environment_and_args(
                compile(b"local x <close> = ...; error('boom')", language),
                environment,
                &[Value::Object(table)],
            )
            .unwrap()
            .run();
        let Ok(RunOutcome::LuaError(error)) = outcome else {
            panic!("close 錯誤須保留 LuaError: {outcome:?}");
        };
        assert_eq!(error.kind, RuntimeErrorKind::Thrown);
        let Value::Object(message) = error.value else {
            panic!("close 錯誤值須為字串");
        };
        assert_eq!(
            vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
            Ok(b"boom".to_vec())
        );
        drop(error);
        assert_eq!(
            vm.raw_get(env, Value::Object(closed_key)),
            Ok(Value::Integer(2))
        );
        assert_eq!(vm.roots().total_count(), roots);

        let mut execution = vm
            .load_with_environment_and_args(
                compile(b"local x <close> = ...; while true do end", language),
                environment,
                &[Value::Object(table)],
            )
            .unwrap();
        execution.set_fuel(3).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn entry_argument_allocation_failure_at_each_real_load_site_retries() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let module = compile(b"return ...", language);
        let make_vm = || {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let env = vm.allocate_table().unwrap();
            let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
            let arg = vm.allocate_byte_string(b"held").unwrap();
            let arg_root = HostHandle::<Value>::new(&mut vm, arg).unwrap();
            vm.set_collect_every_allocation(true);
            (vm, env_root, arg_root, arg)
        };
        let (mut vm, env_root, _arg_root, arg) = make_vm();
        let probe = vm.ledger_probe();
        let start = probe.trace().next_ordinal;
        let environment = env_root.as_value(&vm).unwrap();
        let execution = vm
            .load_with_environment_and_args(module.clone(), environment, &[Value::Object(arg)])
            .unwrap();
        let end = probe.trace().next_ordinal;
        drop(execution);
        assert!(
            end > start && end - start < 128,
            "{profile:?}: {start}..{end}"
        );

        for ordinal in start..end {
            let (mut vm, env_root, _arg_root, arg) = make_vm();
            let probe = vm.ledger_probe();
            let environment = env_root.as_value(&vm).unwrap();
            let baseline_roots = vm.roots().total_count();
            assert_eq!(probe.trace().next_ordinal, start);
            vm.inject_allocation_failure_at(ordinal);
            let failed = vm.load_with_environment_and_args(
                module.clone(),
                environment,
                &[Value::Object(arg)],
            );
            assert!(
                failed.is_err(),
                "{profile:?} ordinal {ordinal} unexpectedly loaded"
            );
            drop(failed);
            assert_eq!(probe.trace().last_failure.unwrap().attempt.ordinal, ordinal);
            assert_eq!(
                probe.trace().last_failure.unwrap().kind,
                AllocationFailureKind::Injection
            );
            assert_eq!(vm.roots().total_count(), baseline_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            let outcome = vm
                .load_with_environment_and_args(module.clone(), environment, &[Value::Object(arg)])
                .unwrap()
                .run()
                .unwrap();
            assert!(
                matches!(outcome, RunOutcome::Returned(values) if values == [Value::Object(arg)])
            );
            assert_eq!(vm.roots().total_count(), baseline_roots);
        }
    }
}

#[test]
fn module_closure_private_helper_and_official_plan_failures_retry_without_retained_payload() {
    for (language, profile, official_bytes) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-root-varargs.luac").as_slice(),
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-root-varargs.luac").as_slice(),
        ),
    ] {
        let native = compile(
            b"local t={...}; local function read() return t[1],t[2] end; return read()",
            language,
        );
        assert!(native.official_execution().is_some());
        for (module, returns_table) in [(native, false), (official(official_bytes, profile), true)]
        {
            let make_vm = || {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let env = vm.allocate_table().unwrap();
                let env_root = HostHandle::<Value>::new(&mut vm, env).unwrap();
                let arg = vm.allocate_byte_string(b"payload").unwrap();
                let arg_root = HostHandle::<Value>::new(&mut vm, arg).unwrap();
                vm.set_collect_every_allocation(true);
                (vm, env_root, arg_root, arg)
            };
            let run = |vm: &mut Vm, env: Value, arg| {
                vm.load_with_environment_and_args(
                    module.clone(),
                    env,
                    &[Value::Object(arg), Value::Nil],
                )?
                .run()
            };
            let check = |vm: &mut Vm, outcome: RunOutcome, arg| {
                let RunOutcome::Returned(values) = outcome else {
                    panic!("有效入口必須返回")
                };
                if returns_table {
                    let [Value::Object(table)] = values.as_slice() else {
                        panic!("官方 root 須回傳 table")
                    };
                    assert_eq!(
                        vm.raw_get(*table, Value::Integer(1)),
                        Ok(Value::Object(arg))
                    );
                    assert_eq!(vm.raw_get(*table, Value::Integer(2)), Ok(Value::Nil));
                } else {
                    assert_eq!(values, [Value::Object(arg), Value::Nil]);
                }
            };
            let (mut vm, env_root, _arg_root, arg) = make_vm();
            let environment = env_root.as_value(&vm).unwrap();
            let outcome = run(&mut vm, environment, arg).unwrap();
            check(&mut vm, outcome, arg);
            vm.collect_major().unwrap();
            let clean = vm.ledger_snapshot();
            let clean_roots = vm.roots().total_count();
            let probe = vm.ledger_probe();
            let start = probe.trace().next_ordinal;
            let outcome = run(&mut vm, environment, arg).unwrap();
            check(&mut vm, outcome, arg);
            let end = probe.trace().next_ordinal;
            assert!(
                end > start && end - start < 256,
                "{profile:?}: {start}..{end}"
            );
            drop(vm);

            for ordinal in start..end {
                let (mut vm, env_root, _arg_root, arg) = make_vm();
                let environment = env_root.as_value(&vm).unwrap();
                let outcome = run(&mut vm, environment, arg).unwrap();
                check(&mut vm, outcome, arg);
                vm.collect_major().unwrap();
                assert_eq!(vm.ledger_probe().trace().next_ordinal, start);
                vm.inject_allocation_failure_at(ordinal);
                let failed = run(&mut vm, environment, arg);
                assert!(
                    failed.is_err(),
                    "{profile:?} ordinal {ordinal} unexpectedly succeeded"
                );
                drop(failed);
                let failure = vm.ledger_probe().trace().last_failure.unwrap();
                assert_eq!(failure.attempt.ordinal, ordinal);
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(vm.roots().total_count(), clean_roots);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.collect_major().unwrap();
                assert_eq!(
                    vm.ledger_snapshot().committed,
                    clean.committed,
                    "{profile:?} ordinal {ordinal}"
                );
                assert_eq!(
                    vm.ledger_snapshot().lua_heap_bytes,
                    clean.lua_heap_bytes,
                    "{profile:?} ordinal {ordinal}"
                );
                assert_eq!(
                    vm.ledger_snapshot().host_allocation_bytes,
                    clean.host_allocation_bytes,
                    "{profile:?} ordinal {ordinal}"
                );
                let outcome = run(&mut vm, environment, arg).unwrap();
                check(&mut vm, outcome, arg);
                assert_eq!(vm.roots().total_count(), clean_roots);
            }
        }
    }
}
