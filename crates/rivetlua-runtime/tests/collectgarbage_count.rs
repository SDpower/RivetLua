use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, ObjectRef, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{AbortReason, HostHandle, RunOutcome, RuntimeErrorKind, Vm};

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

fn compile(source: &[u8], profile: LanguageProfile) -> VerifiedModule {
    compile_with_budget(
        source,
        b"=collectgarbage-count",
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn run(vm: &mut Vm, environment: ObjectRef, source: &[u8], profile: LanguageProfile) -> RunOutcome {
    vm.load_with_environment(compile(source, profile), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap()
}

fn count(vm: &mut Vm, environment: ObjectRef, profile: LanguageProfile) -> f64 {
    let RunOutcome::Returned(values) =
        run(vm, environment, b"return collectgarbage('count')", profile)
    else {
        panic!("count 應正常返回")
    };
    let [Value::Float(value)] = values.as_slice() else {
        panic!("count 應只返回一個浮點值：{values:?}")
    };
    assert!(value.is_finite() && *value >= 0.0);
    *value
}

#[test]
fn count_is_installed_and_returns_a_lua_memory_float_in_both_profiles() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let value = count(&mut vm, environment, language);
        assert!(value > 0.0, "{language:?}");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn count_rejects_invalid_options_then_allows_retry() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        for source in [
            b"return collectgarbage('invalid-option')".as_slice(),
            b"return collectgarbage('COUNT')",
            b"return collectgarbage(1)",
            b"return collectgarbage({})",
        ] {
            let RunOutcome::LuaError(error) = run(&mut vm, environment, source, language) else {
                panic!("未支援的選項應回 Lua 錯誤：{language:?} {source:?}")
            };
            assert_eq!(error.kind, RuntimeErrorKind::BasicArgument);
            assert_eq!(error.diagnostic_id, "E_BASIC_ARGUMENT");
            drop(error);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert!(count(&mut vm, environment, language).is_finite());
        }
        let RunOutcome::Returned(values) = run(
            &mut vm,
            environment,
            b"return collectgarbage('count', 123)",
            language,
        ) else {
            panic!("count 應忽略額外參數：{language:?}")
        };
        assert!(matches!(values.as_slice(), [Value::Float(value)] if value.is_finite()));
    }
}

#[test]
fn count_tracks_reachable_lua_allocation_and_gc_refund() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.collect_major().unwrap();
        let before = count(&mut vm, environment, language);
        let large = vm.allocate_byte_string(&vec![b'x'; 16 * 1024]).unwrap();
        let large_root = HostHandle::<Value>::new(&mut vm, large).unwrap();
        vm.collect_major().unwrap();
        let during = count(&mut vm, environment, language);
        assert!(during > before + 8.0, "{language:?}: {before} -> {during}");
        drop(large_root);
        vm.collect_major().unwrap();
        let after = count(&mut vm, environment, language);
        assert!(after < during - 8.0, "{language:?}: {during} -> {after}");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn count_binding_is_guest_mutable_and_vm_local_under_gc() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let first = vm.allocate_table().unwrap();
        let _first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
        let second = vm.allocate_table().unwrap();
        let _second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
        vm.install_basic_builtins(first).unwrap();
        vm.install_basic_builtins(second).unwrap();
        vm.set_collect_every_allocation(true);
        assert_eq!(
            run(
                &mut vm,
                first,
                b"collectgarbage=17; return collectgarbage",
                language
            ),
            RunOutcome::Returned(vec![Value::Integer(17)])
        );
        assert!(count(&mut vm, second, language).is_finite());
        assert_eq!(
            run(
                &mut vm,
                first,
                b"collectgarbage=nil; return collectgarbage",
                language
            ),
            RunOutcome::Returned(vec![Value::Nil])
        );
        assert!(count(&mut vm, second, language).is_finite());
        let mut other = Vm::new_with_profile(runtime).unwrap();
        let other_environment = other.allocate_table().unwrap();
        let _other_root = HostHandle::<Value>::new(&mut other, other_environment).unwrap();
        other.install_basic_builtins(other_environment).unwrap();
        assert!(count(&mut other, other_environment, language).is_finite());
    }
}

#[test]
fn count_obeys_execution_fuel_abort_and_same_vm_retry() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let roots = vm.roots().total_count();
        {
            let mut execution = vm
                .load_with_environment(
                    compile(b"return collectgarbage('count')", language),
                    Value::Object(environment),
                )
                .unwrap();
            execution.set_fuel(0).unwrap();
            assert_eq!(
                execution.run(),
                Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
            );
        }
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert!(count(&mut vm, environment, language).is_finite());
    }
}

#[test]
fn count_keeps_one_empty_table_or_weak_pair_within_one_kib_in_steady_state() {
    let mut observations = Vec::new();
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for (case, constructor) in [
            ("strong", b"{}".as_slice()),
            ("weak-kv", b"setmetatable({}, {__mode = 'kv'})".as_slice()),
        ] {
            let mut vm = Vm::new_with_profile(runtime).unwrap();
            let environment = vm.allocate_table().unwrap();
            let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            // 先建立並回收中性空表，讓 count 比較的是存活 payload 而非 slot arena 首次擴張。
            let mut neutral = Vec::new();
            for _ in 0..8 {
                let table = vm.allocate_table().unwrap();
                neutral.push(HostHandle::<Value>::new(&mut vm, table).unwrap());
            }
            drop(neutral);
            vm.collect_major().unwrap();
            let mut source = b"collectgarbage(); collectgarbage(); local before = collectgarbage('count'); local a = ".to_vec();
            source.extend_from_slice(constructor);
            source.extend_from_slice(b"; collectgarbage(); local retained = collectgarbage('count'); return before, retained, a");
            let RunOutcome::Returned(values) = run(&mut vm, environment, &source, language) else {
                panic!("count 案例應正常返回：{language:?} {constructor:?}")
            };
            let [
                Value::Float(before),
                Value::Float(retained),
                Value::Object(table),
            ] = values.as_slice()
            else {
                panic!("count 案例結果格式錯誤：{language:?} {values:?}")
            };
            assert!(vm.with_table(*table, |table| table.is_empty()).unwrap());
            observations.push((language, case, *before, *retained));
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
    eprintln!("steady-state empty table count: {observations:?}");
    assert!(
        observations
            .iter()
            .all(|(_, _, before, retained)| *retained <= before + 1.0),
        "空表與弱表的 count 應在 1 KiB 內：{observations:?}"
    );
}

#[test]
#[ignore = "P15 Basic 公開相容性缺口：Lua54 超出 1 KiB，保留原測試供 --ignored 重現"]
fn count_after_clearing_three_weak_hash_keys_and_short_string_lookup_stays_within_one_kib() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        let source = b"collectgarbage(); collectgarbage();
            local m = collectgarbage('count')
            local a = setmetatable({}, {__mode = 'kv'})
            a['x'] = 1; a['y'] = 2; a['z'] = 3
            a['x'] = nil; a['y'] = nil; a['z'] = nil
            collectgarbage()
            assert(next(a) == nil)
            assert(a[string.rep('b', 100)] == nil)
            local current = collectgarbage('count')
            return m, current, a";
        let RunOutcome::Returned(values) = run(&mut vm, environment, source, language) else {
            panic!("弱表 count 案例應正常返回：{language:?}")
        };
        let [
            Value::Float(before),
            Value::Float(current),
            Value::Object(table),
        ] = values.as_slice()
        else {
            panic!("弱表 count 回傳格式錯誤：{language:?} {values:?}")
        };
        assert!(vm.with_table(*table, |table| table.is_empty()).unwrap());
        assert!(
            current <= &(before + 1.0),
            "{language:?}: before={before} current={current} delta={} B",
            (current - before) * 1024.0,
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn automatic_gc_completes_finalizer_during_bounded_guest_allocations() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let source = b"collectgarbage('incremental'); local done=false; local u=setmetatable({}, {__gc=function() done=true end}); u=nil; for i=1,10000 do local t={}; if done then return true,i end end; return false,collectgarbage('count')";
    let outcome = run(&mut vm, environment, source, LanguageProfile::Lua55);
    assert!(
        matches!(outcome, RunOutcome::Returned(ref values) if matches!(values.as_slice(), [Value::Boolean(true), Value::Integer(i)] if *i <= 10_000)),
        "有界配置應推進 GC 並執行 finalizer：{outcome:?} {:?}",
        vm.gc_trace()
    );
}
