use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, ObjectRef, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{AbortReason, HostHandle, RunOutcome, RuntimeErrorKind, Vm, VmError};

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
fn count_matches_ledger_for_empty_table_and_weak_pair_then_refunds() {
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
            let table = *table;
            let retained_bytes = *retained * 1024.0;
            assert!(retained > before, "{language:?} {case}");
            assert_eq!(retained_bytes, vm.ledger_snapshot().lua_heap_bytes as f64);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            drop(values);
            vm.collect_major().unwrap();
            assert_eq!(
                vm.object_kind(table),
                Err(VmError::StaleObject),
                "{language:?} {case}"
            );
            assert!(
                (vm.ledger_snapshot().lua_heap_bytes as f64) < retained_bytes,
                "{language:?} {case}"
            );
            assert_eq!(
                count(&mut vm, environment, language) * 1024.0,
                vm.ledger_snapshot().lua_heap_bytes as f64,
                "{language:?} {case}"
            );
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn count_after_collecting_weak_keys_and_values_matches_ledger() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        // 沿用官方 gc.lua 弱鍵語義；縮小長字串，以 Lua heap 對帳取代 C 物件大小上限。
        let source = b"collectgarbage(); collectgarbage();
            local before = collectgarbage('count')
            local a = setmetatable({}, {__mode = 'kv'})
            a[string.rep('a', 4096)] = 25
            a[string.rep('b', 4096)] = {}
            a[{}] = 14
            local allocated = collectgarbage('count')
            collectgarbage()
            local after_weak = collectgarbage('count')
            local k, v = next(a)
            assert(k == string.rep('a', 4096) and v == 25)
            assert(next(a, k) == nil)
            assert(a[string.rep('b', 4096)] == nil)
            a[k] = nil; k = nil
            collectgarbage()
            assert(next(a) == nil)
            assert(a[string.rep('b', 100)] == nil)
            local current = collectgarbage('count')
            return before, allocated, after_weak, current, a";
        let RunOutcome::Returned(values) = run(&mut vm, environment, source, language) else {
            panic!("弱表 count 案例應正常返回：{language:?}")
        };
        let [
            Value::Float(before),
            Value::Float(allocated),
            Value::Float(after_weak),
            Value::Float(current),
            Value::Object(table),
        ] = values.as_slice()
        else {
            panic!("弱表 count 回傳格式錯誤：{language:?} {values:?}")
        };
        assert!(vm.with_table(*table, |table| table.is_empty()).unwrap());
        let table = *table;
        let current_bytes = *current * 1024.0;
        assert!(
            allocated > before,
            "{language:?}: before={before} allocated={allocated}"
        );
        assert!(
            after_weak < allocated,
            "{language:?}: allocated={allocated} after_weak={after_weak}"
        );
        assert!(
            current < allocated,
            "{language:?}: allocated={allocated} current={current}"
        );
        assert_eq!(current_bytes, vm.ledger_snapshot().lua_heap_bytes as f64);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(values);
        vm.collect_major().unwrap();
        assert_eq!(
            vm.object_kind(table),
            Err(VmError::StaleObject),
            "{language:?}"
        );
        assert!(
            (vm.ledger_snapshot().lua_heap_bytes as f64) < current_bytes,
            "{language:?}"
        );
        assert_eq!(
            count(&mut vm, environment, language) * 1024.0,
            vm.ledger_snapshot().lua_heap_bytes as f64,
            "{language:?}"
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
