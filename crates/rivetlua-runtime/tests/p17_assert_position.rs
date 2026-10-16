use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, emit_with_native_debug, lex, lower, parse,
    resolve, translate_official_chunk,
};
use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{LuaProfile, OfficialWorkBudget, ProtoId, Value, VerifyLimits};
use rivetlua_runtime::{FailPoint, RootKind, RunOutcome, RuntimeErrorKind, Vm, VmError};

fn compile(
    source: &[u8],
    name: &[u8],
    language: LanguageProfile,
    debug: bool,
) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    if debug {
        emit_with_native_debug(&ir, &resolved, source, name, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    } else {
        emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    }
}

fn string_bytes(vm: &Vm, value: Value) -> Vec<u8> {
    let Value::Object(object) = value else {
        panic!("assert 錯誤值須是 byte string");
    };
    vm.with_byte_string(object, |string| string.as_bytes().to_vec())
        .unwrap()
}

fn assert_error_bytes(
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
        let mut execution = vm
            .load_with_environment(compile(source, name, language, debug), Value::Object(env))
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        outcome
    };
    let RunOutcome::LuaError(error) = outcome else {
        panic!("assert(false) 必須產生 LuaError");
    };
    assert_eq!(error.kind, RuntimeErrorKind::Thrown);
    let bytes = string_bytes(&vm, error.value);
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
    let outcome = {
        let mut execution = vm
            .load_with_environment(compile(source, name, language, true), Value::Object(env))
            .unwrap();
        let outcome = execution.run().unwrap();
        drop(execution);
        outcome
    };
    let RunOutcome::Returned(values) = outcome else {
        panic!("受保護的 assert 結果須返回");
    };
    vm.remove_root(env_root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    values
}

#[test]
fn p17_assert_position_basic() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        assert_eq!(
            assert_error_bytes(b"assert(false)", b"=LUA_INIT", language, profile, true),
            b"LUA_INIT:1: assertion failed!"
        );
        assert_eq!(
            assert_error_bytes(
                b"local n = 1\nassert(false, 'custom')",
                b"@position.lua",
                language,
                profile,
                true,
            ),
            b"position.lua:2: custom"
        );
        assert_eq!(
            assert_error_bytes(b"assert(false)", b"=LUA_INIT", language, profile, false),
            b"assertion failed!"
        );
        assert_eq!(
            returned_values(
                b"return assert(true, 17, nil, 23)",
                b"=success",
                language,
                profile,
            ),
            vec![
                Value::Boolean(true),
                Value::Integer(17),
                Value::Nil,
                Value::Integer(23),
            ]
        );
        assert_eq!(
            returned_values(
                b"local t = {}; local ok, e = pcall(assert, false, t); return ok, e == t",
                b"=identity",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(assert, false, 17); return ok, e",
                b"=identity",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Integer(17)]
        );
    }
}

#[test]
fn p17_assert_position_dispatch_lifecycle() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        assert_eq!(
            returned_values(
                b"local ok, e = pcall(assert, false, 'direct'); return ok, e == 'direct'",
                b"=protected",
                language,
                profile,
            ),
            vec![Value::Boolean(false), Value::Boolean(true)]
        );
        assert_eq!(
            returned_values(
                b"local function fail()\n  assert(false, 'inside')\nend\nlocal ok, e = pcall(fail)\nlocal ok2, f = xpcall(fail, function(v) return v end)\nreturn ok, e == 'protected.lua:2: inside', ok2, f == 'protected.lua:2: inside'",
                b"@protected.lua",
                language,
                profile,
            ),
            vec![
                Value::Boolean(false),
                Value::Boolean(true),
                Value::Boolean(false),
                Value::Boolean(true),
            ]
        );
        assert_eq!(
            returned_values(
                b"local t = setmetatable({}, {__pairs = assert}); local a, b, c = pairs(t); return a == t, b, c",
                b"=pairs",
                language,
                profile,
            ),
            vec![Value::Boolean(true), Value::Nil, Value::Nil]
        );

        let source = b"local function fail()\n  assert(false, 'official')\nend\nfail()";
        let native = compile(source, b"@assert.lua", language, true);
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
                    panic!("{profile:?} {origin} strip={strip}: assert 應拋錯");
                };
                assert_eq!(error.kind, RuntimeErrorKind::Thrown);
                assert_eq!(vm.roots().total_count(), baseline + 1);
                let expected = if origin == "official" && strip {
                    b"official".as_slice()
                } else {
                    b"assert.lua:2: official".as_slice()
                };
                assert_eq!(string_bytes(&vm, error.value), expected);
                vm.collect_major().unwrap();
                assert_eq!(string_bytes(&vm, error.value), expected);
                drop(error);
                assert_eq!(vm.roots().total_count(), baseline);
                let retry = vm
                    .load_with_environment(
                        compile(b"return assert(true, 7)", b"=retry", language, false),
                        Value::Object(env),
                    )
                    .unwrap()
                    .run()
                    .unwrap();
                assert_eq!(
                    retry,
                    RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
                );
                vm.remove_root(env_root).unwrap();
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                let probe = vm.ledger_probe();
                drop(vm);
                assert_eq!(probe.snapshot().committed, 0);
                assert_eq!(probe.snapshot().reserved, 0);
            }
        }

        let module = compile(b"assert(false, 'fail')", b"@failpoint.lua", language, true);
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
                panic!("{profile:?} ordinal {ordinal}: 注入必須觸發");
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
                    panic!("{profile:?}: 前綴配置失敗必須中止");
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
                    panic!("{profile:?}: 注入後 VM 應可重用");
                };
                assert_eq!(string_bytes(&vm, error.value), b"failpoint.lua:1: fail");
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
        assert!(hit_prefix_reserve, "{profile:?}: 須命中前綴暫存配置失敗");
        assert!(hit_string_reserve, "{profile:?}: 須命中錯誤字串配置失敗");

        // 預設訊息本身也是新配置；配置失敗後不得留下錯誤 root。
        let default_module = compile(b"assert(false)", b"@default.lua", language, true);
        let mut baseline_vm = Vm::new_with_profile(profile).unwrap();
        let baseline_env = baseline_vm.allocate_table().unwrap();
        let baseline_root = baseline_vm.add_root(RootKind::Host, baseline_env).unwrap();
        baseline_vm.install_basic_builtins(baseline_env).unwrap();
        let first = baseline_vm.allocation_trace().next_ordinal;
        let outcome = baseline_vm
            .load_with_environment(default_module.clone(), Value::Object(baseline_env))
            .unwrap()
            .run()
            .unwrap();
        assert!(matches!(outcome, RunOutcome::LuaError(_)));
        drop(outcome);
        let last = baseline_vm.allocation_trace().next_ordinal;
        baseline_vm.remove_root(baseline_root).unwrap();
        assert!(last > first && last - first < 256);
        let mut hit_default_string = false;
        for ordinal in first..last {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let env = vm.allocate_table().unwrap();
            let env_root = vm.add_root(RootKind::Host, env).unwrap();
            vm.install_basic_builtins(env).unwrap();
            assert_eq!(vm.allocation_trace().next_ordinal, first);
            vm.inject_allocation_failure_at(ordinal);
            let outcome = vm
                .load_with_environment(default_module.clone(), Value::Object(env))
                .and_then(|mut execution| execution.run());
            let Some(failure) = vm.allocation_trace().last_failure else {
                panic!("{profile:?} ordinal {ordinal}: 預設訊息配置注入須觸發");
            };
            if failure.attempt.point == Some(FailPoint::StringBytesReserve)
                && failure.attempt.site.file.ends_with("/string.rs")
                && failure.attempt.bytes == b"assertion failed!".len()
            {
                let RuntimeErrorKind::Heap(VmError::InjectedAllocation(attempt)) =
                    outcome.unwrap_err().kind
                else {
                    panic!("{profile:?}: 預設訊息配置失敗必須中止");
                };
                assert_eq!(attempt, failure.attempt);
                assert_eq!(vm.roots().total_count(), 1);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.set_collect_every_allocation(true);
                let retry = vm
                    .load_with_environment(default_module.clone(), Value::Object(env))
                    .unwrap()
                    .run()
                    .unwrap();
                let RunOutcome::LuaError(error) = retry else {
                    panic!("{profile:?}: 預設訊息失敗後 VM 應可重用");
                };
                assert_eq!(
                    string_bytes(&vm, error.value),
                    b"default.lua:1: assertion failed!"
                );
                vm.collect_major().unwrap();
                assert_eq!(
                    string_bytes(&vm, error.value),
                    b"default.lua:1: assertion failed!"
                );
                drop(error);
                vm.remove_root(env_root).unwrap();
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                let probe = vm.ledger_probe();
                drop(vm);
                assert_eq!(probe.snapshot().committed, 0);
                assert_eq!(probe.snapshot().reserved, 0);
                hit_default_string = true;
                break;
            }
        }
        assert!(hit_default_string, "{profile:?}: 須命中預設訊息配置失敗");
    }
}
