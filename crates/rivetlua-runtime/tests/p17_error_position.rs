use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, emit_with_native_debug, lex, lower, parse,
    resolve, translate_official_chunk,
};
use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    HostFunctionId, LuaProfile, ObjectRef, OfficialWorkBudget, ProtoId, Value, VerifyLimits,
};
use rivetlua_runtime::{
    ExternalCommand, FailPoint, RootKind, RunOutcome, RuntimeErrorKind, Vm, VmError,
};

fn compile_debug(
    source: &[u8],
    name: &[u8],
    language: LanguageProfile,
) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(&ir, &resolved, source, name, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn compile_plain(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn error_bytes(
    source: &[u8],
    name: &[u8],
    language: LanguageProfile,
    profile: LuaProfile,
    debug: bool,
) -> Vec<u8> {
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    let outcome = {
        let module = if debug {
            compile_debug(source, name, language)
        } else {
            compile_plain(source, language)
        };
        let mut execution = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        outcome
    };
    let RunOutcome::LuaError(error) = outcome else {
        panic!("error() 必須產生 LuaError");
    };
    assert_eq!(error.kind, RuntimeErrorKind::Thrown);
    let Value::Object(message) = error.value else {
        panic!("字串錯誤必須保有 byte string 值");
    };
    let bytes = vm
        .with_byte_string(message, |string| string.as_bytes().to_vec())
        .unwrap();
    drop(error);
    vm.remove_root(env_root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    bytes
}

fn returned_values(
    source: &[u8],
    name: &[u8],
    language: LanguageProfile,
    profile: LuaProfile,
) -> Vec<Value> {
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    let returned = {
        let mut execution = vm
            .load_with_environment(compile_debug(source, name, language), Value::Object(env))
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        let RunOutcome::Returned(values) = outcome else {
            panic!("受保護錯誤應返回檢查結果");
        };
        values
    };
    vm.remove_root(env_root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    returned
}

fn byte_string(vm: &Vm, value: Value) -> Vec<u8> {
    let Value::Object(object) = value else {
        panic!("錯誤值須為 byte string");
    };
    vm.with_byte_string(object, |string| string.as_bytes().to_vec())
        .unwrap()
}

#[test]
fn p17_error_position_basic() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        assert_eq!(
            error_bytes(b"error('msg')", b"=LUA_INIT", language, profile, true),
            b"LUA_INIT:1: msg"
        );
        assert_eq!(
            error_bytes(
                b"local a = 1\nerror('later')",
                b"=LUA_INIT",
                language,
                profile,
                true,
            ),
            b"LUA_INIT:2: later"
        );
        assert_eq!(
            error_bytes(
                b"local a = 1\nerror('file')",
                b"@sample.lua",
                language,
                profile,
                true,
            ),
            b"sample.lua:2: file"
        );
        assert_eq!(
            error_bytes(b"error('raw', 0)", b"=LUA_INIT", language, profile, true),
            b"raw"
        );
        assert_eq!(
            error_bytes(b"error('far', 99)", b"=LUA_INIT", language, profile, true),
            b"far"
        );
        assert_eq!(
            error_bytes(b"error('plain')", b"=LUA_INIT", language, profile, false),
            b"plain"
        );
        assert_eq!(
            error_bytes(
                b"local function inner()\n  error('inner')\nend\ninner()",
                b"=LUA_INIT",
                language,
                profile,
                true,
            ),
            b"LUA_INIT:2: inner"
        );
        assert_eq!(
            error_bytes(
                b"local function inner()\n  error('outer', 2)\nend\ninner()",
                b"=LUA_INIT",
                language,
                profile,
                true,
            ),
            b"LUA_INIT:4: outer"
        );
        assert_eq!(
            returned_values(
                b"local t = {}; local ok, e = pcall(error, t); return ok, e == t",
                b"=identity",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(error, 17); return ok, e",
                b"=identity",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Integer(17)]
        );
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(error, 'msg', 'bad'); return ok, e == 'msg'",
                b"=level",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(false)]
        );
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(error, 'msg'); return ok, e == 'msg'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(error, 'msg', 2); return ok, e == 'LUA_INIT:1: msg'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local prior = 1\nlocal ok, e = pcall(error, 'msg', 2)\nreturn ok, e == 'LUA_INIT:2: msg'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local function f() error('inner', 2) end\nlocal ok, e = pcall(f)\nreturn ok, e == 'inner'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local function f() error('outer', 3) end\nlocal ok, e = pcall(f)\nreturn ok, e == 'LUA_INIT:2: outer'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local function f() error('outer', 3) end\nlocal prior = 1\nlocal ok, e = pcall(f)\nreturn ok, e == 'LUA_INIT:3: outer'",
                b"=LUA_INIT",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
    }
}

#[test]
fn p17_error_position_dispatch_lifecycle() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let tail_source = b"local function tail()\n  return error('tail')\nend\nreturn tail()";
        let native = compile_debug(tail_source, b"@position.lua", language);
        for strip in [false, true] {
            let encoded = emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            let decoded =
                decode_official_chunk(&encoded, profile, &OfficialChunkLimits::default()).unwrap();
            let imported = translate_official_chunk(&decoded, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            for (origin, module) in [("native", native.clone()), ("official", imported)] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let env = vm.allocate_table().unwrap();
                let env_root = vm.add_root(RootKind::Host, env).unwrap();
                vm.install_basic_builtins(env).unwrap();
                let baseline = vm.roots().total_count();
                vm.set_collect_every_allocation(true);
                let outcome = {
                    let mut execution = vm
                        .load_with_environment(module, Value::Object(env))
                        .unwrap();
                    let outcome = execution.run().unwrap();
                    drop(execution);
                    outcome
                };
                let RunOutcome::LuaError(error) = outcome else {
                    panic!("{profile:?} {origin} strip={strip}: tail error 必須傳出");
                };
                assert_eq!(error.kind, RuntimeErrorKind::Thrown);
                assert_eq!(vm.roots().total_count(), baseline + 1);
                let expected = if origin == "official" && strip {
                    b"tail".as_slice()
                } else {
                    b"position.lua:2: tail".as_slice()
                };
                assert_eq!(byte_string(&vm, error.value), expected);
                vm.collect_major().unwrap();
                assert_eq!(byte_string(&vm, error.value), expected);
                drop(error);
                assert_eq!(vm.roots().total_count(), baseline);
                let returned = vm
                    .load_with_environment(compile_plain(b"return 7", language), Value::Object(env))
                    .unwrap()
                    .run()
                    .unwrap();
                assert_eq!(returned, RunOutcome::Returned(vec![Value::Integer(7)]));
                vm.remove_root(env_root).unwrap();
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            }
        }

        let source = b"local closed = 0\nlocal t = setmetatable({}, {__add=error, __close=function(_, e) closed=closed+1 end})\nlocal function fail()\n  local x <close> = t\n  error('protected')\nend\nlocal ok, a = pcall(fail)\nlocal ok2, b = xpcall(function() error('handled') end, function(e) return e end)\nlocal ok3, c = pcall(function() return t+0 end)\nlocal ok4, d = xpcall(error, function(e) return e end, 'direct')\nreturn ok, a, closed, ok2, b, ok3, c == t, ok4, d == 'direct'";
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, env).unwrap();
        vm.install_basic_builtins(env).unwrap();
        vm.set_collect_every_allocation(true);
        let returned = {
            let mut execution = vm
                .load_with_environment(
                    compile_debug(source, b"@protected.lua", language),
                    Value::Object(env),
                )
                .unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            let RunOutcome::Returned(values) = outcome else {
                panic!("{profile:?}: protected/close/event 案例須返回");
            };
            values
        };
        assert_eq!(returned.len(), 9);
        assert_eq!(returned[0], Value::Boolean(false));
        assert_eq!(returned[2], Value::Integer(1));
        assert_eq!(returned[3], Value::Boolean(false));
        assert_eq!(returned[5], Value::Boolean(false));
        assert_eq!(returned[6], Value::Boolean(true));
        assert_eq!(returned[7], Value::Boolean(false));
        assert_eq!(returned[8], Value::Boolean(true));
        let Value::Object(a) = returned[1] else {
            panic!("pcall error 須為字串");
        };
        let Value::Object(b) = returned[4] else {
            panic!("xpcall error 須為字串");
        };
        let a_root = vm.add_root(RootKind::Host, a).unwrap();
        let b_root = vm.add_root(RootKind::Host, b).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(byte_string(&vm, returned[1]), b"protected.lua:5: protected");
        assert_eq!(byte_string(&vm, returned[4]), b"protected.lua:8: handled");
        vm.remove_root(a_root).unwrap();
        vm.remove_root(b_root).unwrap();
        vm.remove_root(env_root).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let module = compile_debug(b"error('fail')", b"@failpoint.lua", language);
        let mut baseline_vm = Vm::new_with_profile(profile).unwrap();
        let baseline_env = baseline_vm.allocate_table().unwrap();
        let baseline_root = baseline_vm.add_root(RootKind::Host, baseline_env).unwrap();
        baseline_vm.install_basic_builtins(baseline_env).unwrap();
        let first = baseline_vm.allocation_trace().next_ordinal;
        let baseline_outcome = baseline_vm
            .load_with_environment(module.clone(), Value::Object(baseline_env))
            .unwrap()
            .run()
            .unwrap();
        assert!(matches!(baseline_outcome, RunOutcome::LuaError(_)));
        drop(baseline_outcome);
        let last = baseline_vm.allocation_trace().next_ordinal;
        baseline_vm.remove_root(baseline_root).unwrap();
        assert!(last > first && last - first < 256);
        let mut hit_prefix_reserve = false;
        let mut hit_string_reserve = false;
        for ordinal in first..last {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let env = vm.allocate_table().unwrap();
            let env_root = vm.add_root(RootKind::Host, env).unwrap();
            vm.install_basic_builtins(env).unwrap();
            assert_eq!(vm.allocation_trace().next_ordinal, first);
            vm.inject_allocation_failure_at(ordinal);
            let outcome = vm
                .load_with_environment(module.clone(), Value::Object(env))
                .and_then(|mut execution| execution.run());
            let Some(failure) = vm.allocation_trace().last_failure else {
                panic!("{profile:?} ordinal {ordinal}: 配置注入須觸發");
            };
            let prefix_reserve = failure.attempt.point == Some(FailPoint::WorkReserve)
                && failure.attempt.site.file.ends_with("/vm/mod.rs");
            let string_reserve = failure.attempt.point == Some(FailPoint::StringBytesReserve)
                && failure.attempt.site.file.ends_with("/string.rs");
            if (prefix_reserve || string_reserve)
                && failure.attempt.bytes == b"failpoint.lua:1: fail".len()
            {
                let RuntimeErrorKind::Heap(VmError::InjectedAllocation(attempt)) =
                    outcome.unwrap_err().kind
                else {
                    panic!("{profile:?}: 前綴配置失敗必須中止執行");
                };
                assert_eq!(attempt, failure.attempt);
                assert_eq!(vm.roots().total_count(), 1);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                let retry = vm
                    .load_with_environment(module.clone(), Value::Object(env))
                    .unwrap()
                    .run()
                    .unwrap();
                let RunOutcome::LuaError(error) = retry else {
                    panic!("{profile:?}: 注入失敗後應能重用 VM");
                };
                assert_eq!(byte_string(&vm, error.value), b"failpoint.lua:1: fail");
                drop(error);
                vm.remove_root(env_root).unwrap();
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                let probe = vm.ledger_probe();
                drop(vm);
                assert_eq!(probe.snapshot().committed, 0);
                assert_eq!(probe.snapshot().reserved, 0);
                hit_prefix_reserve |= prefix_reserve;
                hit_string_reserve |= string_reserve;
                if hit_prefix_reserve && hit_string_reserve {
                    break;
                }
            }
        }
        assert!(
            hit_prefix_reserve,
            "{profile:?}: 須命中 error() 來源前綴配置"
        );
        assert!(hit_string_reserve, "{profile:?}: 須命中新增錯誤字串配置");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OuterCallbackArtifact {
    NativeDebug,
    OfficialDebug,
    OfficialStripped,
}

fn outer_callback_source(level: usize) -> Vec<u8> {
    format!(
        "local function main()\n  bridge(function()\n    error('outer', {level})\n  end)\nend\nmain()\n"
    )
    .into_bytes()
}

fn compile_outer_callback_error(
    language: LanguageProfile,
    profile: LuaProfile,
    artifact: OuterCallbackArtifact,
    level: usize,
) -> rivetlua_core::VerifiedModule {
    let source = outer_callback_source(level);
    let native = compile_debug(&source, b"@outer-callback.lua", language);
    match artifact {
        OuterCallbackArtifact::NativeDebug => native,
        OuterCallbackArtifact::OfficialDebug | OuterCallbackArtifact::OfficialStripped => {
            let strip = artifact == OuterCallbackArtifact::OfficialStripped;
            let encoded = emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            let decoded =
                decode_official_chunk(&encoded, profile, &OfficialChunkLimits::default()).unwrap();
            translate_official_chunk(&decoded, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone()
        }
    }
}

fn park_outer_callback(
    vm: &mut Vm,
    environment: ObjectRef,
    module: rivetlua_core::VerifiedModule,
) -> (rivetlua_runtime::ExternalToken, Value) {
    let bridge = HostFunctionId::new_unique(vm.id()).unwrap();
    let key = vm.allocate_byte_string(b"bridge").unwrap();
    vm.raw_set(environment, Value::Object(key), Value::CFunction(bridge))
        .unwrap();
    let outcome = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::External(token) = outcome else {
        panic!("外層 bridge 必須停泊在公開 C callback 邊界");
    };
    let args = vm.external_event(token).unwrap().args.to_vec();
    assert_eq!(args.len(), 1, "bridge 必須收到單一 Lua callback");
    assert!(
        matches!(args[0], Value::Object(_)),
        "參數必須是 Lua closure"
    );
    (token, args[0])
}

fn outer_callback_error_expected(artifact: OuterCallbackArtifact, level: usize) -> Vec<u8> {
    match (artifact, level) {
        (OuterCallbackArtifact::OfficialStripped, _) | (_, 0 | 2 | 99) => b"outer".to_vec(),
        (_, 1) => b"outer-callback.lua:3: outer".to_vec(),
        (_, 3) => b"outer-callback.lua:2: outer".to_vec(),
        _ => unreachable!("測試只傳入固定的 Lua error level"),
    }
}

#[test]
fn p17_outer_callback_error_position_levels_basic() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        for artifact in [
            OuterCallbackArtifact::NativeDebug,
            OuterCallbackArtifact::OfficialDebug,
            OuterCallbackArtifact::OfficialStripped,
        ] {
            for level in [0, 1, 2, 3, 99] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let environment = vm.allocate_table().unwrap();
                let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
                vm.install_basic_builtins(environment).unwrap();
                let module = compile_outer_callback_error(language, profile, artifact, level);
                let (token, callback) = park_outer_callback(&mut vm, environment, module);
                let nested = vm
                    .continue_external(
                        token,
                        ExternalCommand::NestedCall {
                            target: callback,
                            args: Vec::new(),
                            results: rivetlua_core::ResultMode::Fixed(0),
                        },
                    )
                    .unwrap();
                let RunOutcome::NestedErrored(error) = nested else {
                    panic!("{profile:?} {artifact:?} level={level}: 必須收到巢狀 LuaError");
                };
                assert_eq!(error.kind, RuntimeErrorKind::Thrown);
                assert_eq!(
                    byte_string(&vm, error.value),
                    outer_callback_error_expected(artifact, level),
                    "{profile:?} {artifact:?} level={level}"
                );
                assert_eq!(
                    vm.continue_external(token, ExternalCommand::Return(Vec::new()))
                        .unwrap(),
                    RunOutcome::Returned(Vec::new()),
                    "NestedErrored 後外層 callback 應能完成"
                );
                drop(error);
                vm.collect_major().unwrap();
                vm.remove_root(environment_root).unwrap();
                assert_eq!(vm.roots().total_count(), 0);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            }
        }
    }
}

#[test]
fn p17_outer_callback_error_position_nested_error_cleanup_complete() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        for artifact in [
            OuterCallbackArtifact::NativeDebug,
            OuterCallbackArtifact::OfficialDebug,
            OuterCallbackArtifact::OfficialStripped,
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            let module = compile_outer_callback_error(language, profile, artifact, 1);
            let (token, callback) = park_outer_callback(&mut vm, environment, module);
            let base_roots = vm.roots().total_count();
            let stale_handle = vm.debug_frame_external(token, 0).unwrap().unwrap();

            let nested = vm
                .continue_external(
                    token,
                    ExternalCommand::NestedCall {
                        target: callback,
                        args: Vec::new(),
                        results: rivetlua_core::ResultMode::Fixed(0),
                    },
                )
                .unwrap();
            let RunOutcome::NestedErrored(error) = nested else {
                panic!("{profile:?} {artifact:?}: 首次巢狀呼叫必須失敗");
            };
            assert_eq!(error.kind, RuntimeErrorKind::Thrown);
            let error_object = match error.value {
                Value::Object(object) => object,
                _ => panic!("LuaError 須保留錯誤字串物件"),
            };
            assert_eq!(
                byte_string(&vm, error.value),
                outer_callback_error_expected(artifact, 1)
            );
            assert_eq!(vm.roots().total_count(), base_roots + 1);
            vm.collect_major().unwrap();
            assert_eq!(
                byte_string(&vm, error.value),
                outer_callback_error_expected(artifact, 1),
                "LuaError 持有的 root 須跨 GC 存活"
            );
            assert!(vm.debug_frame_info(stale_handle).is_err());
            assert!(vm.external_event(token).is_ok(), "外層 token 應可續接");
            drop(error);
            vm.collect_major().unwrap();
            if artifact != OuterCallbackArtifact::OfficialStripped {
                assert_eq!(vm.object_kind(error_object), Err(VmError::StaleObject));
            }
            assert_eq!(vm.roots().total_count(), base_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);

            let retry = vm
                .continue_external(
                    token,
                    ExternalCommand::NestedCall {
                        target: callback,
                        args: Vec::new(),
                        results: rivetlua_core::ResultMode::Fixed(0),
                    },
                )
                .unwrap();
            let RunOutcome::NestedErrored(retry_error) = retry else {
                panic!("{profile:?} {artifact:?}: 外層 callback 應能重試巢狀呼叫");
            };
            assert_eq!(
                byte_string(&vm, retry_error.value),
                outer_callback_error_expected(artifact, 1)
            );
            drop(retry_error);
            assert_eq!(
                vm.continue_external(token, ExternalCommand::Return(Vec::new()))
                    .unwrap(),
                RunOutcome::Returned(Vec::new())
            );
            assert!(vm.external_event(token).is_err(), "完成後舊 token 須失效");
            assert!(
                vm.continue_external(token, ExternalCommand::Return(Vec::new()))
                    .is_err()
            );
            assert!(vm.debug_frame_info(stale_handle).is_err());
            let probe = vm
                .load_with_environment(
                    compile_plain(b"return 42", language),
                    Value::Object(environment),
                )
                .unwrap()
                .run()
                .unwrap();
            assert_eq!(probe, RunOutcome::Returned(vec![Value::Integer(42)]));
            vm.collect_major().unwrap();
            assert_eq!(vm.roots().total_count(), 1);
            vm.remove_root(environment_root).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}
