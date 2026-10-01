use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{Value, VerifyLimits};
use rivetlua_runtime::{
    ActiveRootKind, AllocationDomain, AllocationFailureKind, FailPoint, GcAge, GcColor,
    GcCycleKind, GcMode, GcPhase, HostHandle, RootKind, RunOutcome, Vm, VmError,
};

#[test]
fn p12_6_ledger_reports_separate_lua_and_host_bytes() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let table = vm.allocate_table_with_capacity(2, 4).unwrap();
    let _root = vm.add_root(RootKind::Registry, table).unwrap();
    let snapshot = format!("{:?}", vm.ledger_snapshot());
    assert!(snapshot.contains("lua_heap_bytes"), "{snapshot}");
    assert!(snapshot.contains("host_allocation_bytes"), "{snapshot}");
    let values = vm.ledger_snapshot();
    assert!(values.lua_heap_bytes > 0);
    assert!(values.host_allocation_bytes > 0);
    assert_eq!(
        values.lua_heap_bytes + values.host_allocation_bytes,
        values.committed
    );
    assert_eq!(values.shared_rss_observation, None);
}

fn p12_6_is_vm_mod_site(file: &str) -> bool {
    let mut components = file.rsplit(['/', '\\']);
    components.next() == Some("mod.rs") && components.next() == Some("vm")
}

fn p12_6_site_file_is(file: &str, name: &str) -> bool {
    file.rsplit(['/', '\\']).next() == Some(name)
}

fn p12_6_lua_allocation_sequence(vm: &mut Vm) -> Result<(), VmError> {
    let table = vm.allocate_table_with_capacity(2, 2)?;
    let string = vm.allocate_byte_string(b"key")?;
    vm.raw_set(table, Value::Integer(3), Value::Integer(7))?;
    vm.raw_set(table, Value::Integer(100), Value::Integer(8))?;
    vm.raw_set(table, Value::Integer(101), Value::Integer(9))?;
    vm.raw_set(table, Value::Object(string), Value::Integer(10))?;
    vm.add_child(table, string)?;
    Ok(())
}

#[test]
fn p12_6_allocation_failure_each_lua_site_ordinal_fails_atomically_and_retries() {
    use std::collections::BTreeSet;

    let profile = profile();
    let mut baseline = new_profile_vm(&profile);
    p12_6_lua_allocation_sequence(&mut baseline).unwrap();
    let total = baseline.allocation_trace().next_ordinal - 1;
    assert!(total >= 8, "配置操作過少: {total}");
    let mut lua_sites = BTreeSet::new();
    let mut lua_points = Vec::new();
    let mut lua_ordinals = 0;
    for ordinal in 1..=total {
        let mut vm = new_profile_vm(&profile);
        vm.inject_allocation_failure_at(ordinal);
        let error = p12_6_lua_allocation_sequence(&mut vm).unwrap_err();
        let VmError::InjectedAllocation(attempt) = error else {
            panic!("ordinal {ordinal}: 失敗錯誤缺 site: {error:?}");
        };
        assert_eq!(attempt.ordinal, ordinal);
        assert_eq!(
            vm.allocation_trace().last_failure.unwrap().kind,
            AllocationFailureKind::Injection
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let snapshot = vm.ledger_snapshot();
        assert_eq!(
            snapshot.lua_heap_bytes + snapshot.host_allocation_bytes,
            snapshot.committed
        );
        assert_eq!(vm.roots().total_count(), 0);
        if attempt.domain == AllocationDomain::LuaHeap {
            lua_ordinals += 1;
            lua_sites.insert((attempt.site.file, attempt.site.line, attempt.site.column));
            if let Some(point) = attempt.point {
                if !lua_points.contains(&point) {
                    lua_points.push(point);
                }
            }
        }
        vm.collect().unwrap();
        let trace = vm.gc_trace();
        assert_eq!(trace.white + trace.gray + trace.black, 0);
        p12_6_lua_allocation_sequence(&mut vm).unwrap();
        println!(
            "P12_INJECT\tprofile={profile}\tordinal={ordinal}\tdomain={:?}\tpoint={:?}\tsite={:?}\tretry=PASS",
            attempt.domain, attempt.point, attempt.site
        );
    }
    for point in [
        FailPoint::SlotReserve,
        FailPoint::ObjectReserve,
        FailPoint::StringBytesReserve,
        FailPoint::TableArrayReserve,
        FailPoint::TableHashReserve,
        FailPoint::TableArrayGrow,
        FailPoint::TableHashGrow,
        FailPoint::ChildReserve,
    ] {
        assert!(
            lua_points.contains(&point),
            "缺少 Lua allocation site: {point:?}; 已見 {lua_points:?}"
        );
    }
    assert!(
        lua_sites.len() >= 8,
        "Lua heap site 覆蓋不足: {lua_sites:?}"
    );
    println!("P12_ALLOC\tprofile={profile}\tordinals={lua_ordinals}\tsites={lua_sites:?}");
}

#[test]
fn p12_6_vm_lifecycle_10_000_balances_all_domains() {
    let profile = profile();
    let finalizer_module = compile(b"return function(o) count=(count or 0)+1 end", &profile);
    let close_module = compile(
        b"return function(self,err) closed=(closed or 0)+1 end",
        &profile,
    );
    let index_module = compile(
        b"return function() pending=(pending or 0)+1; return 17 end",
        &profile,
    );
    let rich = compile(
        b"local x <close> = closable; local co=coroutine.create(function() return observed.missing end); local ok,v=coroutine.resume(co); resumed=ok; error('stop')",
        &profile,
    );
    let mut cycles = [0usize; 3];
    let mut weak_runs = 0;
    let mut finalizer_runs = 0;
    let mut rich_runs = 0;
    let mut close_callbacks = 0;
    let mut coroutine_resumes = 0;
    let mut pending_events = 0;
    let mut lua_errors = 0;
    let mut failure_runs = 0;
    for iteration in 0..10_000 {
        let mut vm = new_profile_vm(&profile);
        let probe = vm.ledger_probe();
        let mode = iteration % 3;
        if mode == 2 {
            vm.set_gc_mode(GcMode::Generational).unwrap();
        }
        let value = vm.allocate_table().unwrap();
        let host = HostHandle::<Value>::new(&mut vm, value).unwrap();
        assert_eq!(vm.collect(), Ok(0));
        if iteration % 7 == 0 {
            let ordinal = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(ordinal);
            assert!(matches!(
                vm.allocate_byte_string(b"retry"),
                Err(VmError::InjectedAllocation(attempt)) if attempt.ordinal == ordinal
            ));
            vm.allocate_byte_string(b"retry").unwrap();
            failure_runs += 1;
        }
        if iteration % 4 == 0 {
            let weak = vm.allocate_table().unwrap();
            let mt = vm.allocate_table().unwrap();
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode_value = vm.allocate_byte_string(b"k").unwrap();
            vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode_value))
                .unwrap();
            vm.set_metatable(weak, Some(mt)).unwrap();
            let weak_root = vm.add_root(RootKind::Host, weak).unwrap();
            let key = vm.allocate_table().unwrap();
            let key_root = vm.add_root(RootKind::Host, key).unwrap();
            let linked = vm.allocate_table().unwrap();
            vm.raw_set(linked, Value::Integer(1), Value::Object(key))
                .unwrap();
            vm.raw_set(weak, Value::Object(key), Value::Object(linked))
                .unwrap();
            vm.collect().unwrap();
            assert_eq!(
                vm.raw_get(weak, Value::Object(key)),
                Ok(Value::Object(linked))
            );
            vm.remove_root(key_root).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(linked), Err(VmError::StaleObject));
            vm.remove_root(weak_root).unwrap();
            weak_runs += 1;
        }
        if iteration % 12 == 1 {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            let callback = p12_6_loaded_closure(&mut vm, environment, &finalizer_module);
            let target = vm.allocate_table().unwrap();
            attach_finalizer(&mut vm, target, callback);
            vm.collect().unwrap();
            let count_key = vm.allocate_byte_string(b"count").unwrap();
            assert_eq!(
                vm.raw_get(environment, Value::Object(count_key)),
                Ok(Value::Integer(1))
            );
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(target), Err(VmError::StaleObject));
            vm.remove_root(environment_root).unwrap();
            finalizer_runs += 1;
        }
        if iteration % 12 == 2 {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_coroutine_builtins(environment).unwrap();
            vm.install_error_builtins(environment).unwrap();
            let closable = vm.allocate_table().unwrap();
            let close_mt = vm.allocate_table().unwrap();
            let close_key = vm.allocate_byte_string(b"__close").unwrap();
            let close_callback = p12_6_loaded_closure(&mut vm, environment, &close_module);
            vm.raw_set(
                close_mt,
                Value::Object(close_key),
                Value::Object(close_callback),
            )
            .unwrap();
            vm.set_metatable(closable, Some(close_mt)).unwrap();
            let observed = vm.allocate_table().unwrap();
            let observed_mt = vm.allocate_table().unwrap();
            let index_key = vm.allocate_byte_string(b"__index").unwrap();
            let index_callback = p12_6_loaded_closure(&mut vm, environment, &index_module);
            vm.raw_set(
                observed_mt,
                Value::Object(index_key),
                Value::Object(index_callback),
            )
            .unwrap();
            vm.set_metatable(observed, Some(observed_mt)).unwrap();
            let closable_key = vm.allocate_byte_string(b"closable").unwrap();
            let observed_key = vm.allocate_byte_string(b"observed").unwrap();
            vm.raw_set(
                environment,
                Value::Object(closable_key),
                Value::Object(closable),
            )
            .unwrap();
            vm.raw_set(
                environment,
                Value::Object(observed_key),
                Value::Object(observed),
            )
            .unwrap();
            let mut execution = vm
                .load_with_environment(rich.clone(), Value::Object(environment))
                .unwrap();
            let outcome = execution.run().unwrap();
            drop(execution);
            assert!(matches!(outcome, RunOutcome::LuaError(_)));
            let closed = vm.allocate_byte_string(b"closed").unwrap();
            let pending = vm.allocate_byte_string(b"pending").unwrap();
            let resumed = vm.allocate_byte_string(b"resumed").unwrap();
            assert_eq!(
                vm.raw_get(environment, Value::Object(closed)),
                Ok(Value::Integer(1))
            );
            assert_eq!(
                vm.raw_get(environment, Value::Object(pending)),
                Ok(Value::Integer(1))
            );
            assert_eq!(
                vm.raw_get(environment, Value::Object(resumed)),
                Ok(Value::Boolean(true))
            );
            close_callbacks += 1;
            coroutine_resumes += 1;
            pending_events += 1;
            lua_errors += 1;
            vm.remove_root(environment_root).unwrap();
            drop(outcome);
            rich_runs += 1;
        }
        if mode == 1 {
            for _ in 0..1024 {
                if vm.incremental_step(1).unwrap().phase == GcPhase::Pause {
                    break;
                }
            }
            assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
        } else {
            vm.collect().unwrap();
        }
        assert!(vm.object_kind(value).is_ok());
        if mode == 2 {
            vm.collect().unwrap();
        }
        cycles[mode] += 1;
        drop(vm);
        let after = probe.snapshot();
        assert_eq!(after.lua_heap_bytes, 0, "iteration={iteration}");
        assert_eq!(after.host_allocation_bytes, 0, "iteration={iteration}");
        assert_eq!(after.committed, 0, "iteration={iteration}");
        assert_eq!(after.reserved, 0, "iteration={iteration}");
        drop(host);
        assert_eq!(probe.snapshot().committed, 0);
    }
    assert_eq!(cycles, [3334, 3333, 3333]);
    assert_eq!(weak_runs, 2500);
    assert_eq!(finalizer_runs, 834);
    assert_eq!(rich_runs, 834);
    assert_eq!(close_callbacks, 834);
    assert_eq!(coroutine_resumes, 834);
    assert_eq!(pending_events, 834);
    assert_eq!(lua_errors, 834);
    assert_eq!(failure_runs, 1429);
    println!(
        "P12_LIFECYCLE\tprofile={profile}\tvms=10000\tcycles={cycles:?}\tweak_ephemeron={weak_runs}\tfinalizer_callbacks={finalizer_runs}\tclose_callbacks={close_callbacks}\tcoroutine_resumes={coroutine_resumes}\tpending_events={pending_events}\tlua_errors={lua_errors}\tinjected={failure_runs}\tlua_heap=0\thost=0"
    );
}

fn p12_6_loaded_closure(
    vm: &mut Vm,
    environment: rivetlua_core::ObjectRef,
    module: &rivetlua_core::VerifiedModule,
) -> rivetlua_core::ObjectRef {
    let mut execution = vm
        .load_with_environment(module.clone(), Value::Object(environment))
        .unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("缺少生命週期 callback");
    };
    let Value::Object(callback) = values[0] else {
        panic!("生命週期 callback 必須為 closure");
    };
    callback
}

#[test]
fn p12_6_lua_error_clone_keeps_rc_host_charge_until_last_drop() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let baseline = vm.ledger_snapshot().host_allocation_bytes;
    let handle = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    let handle_charge = vm.ledger_snapshot().host_allocation_bytes - baseline;
    drop(handle);
    assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline);
    let mut execution = vm
        .load_with_environment(compile(b"error({})", &profile), Value::Object(environment))
        .unwrap();
    let RunOutcome::LuaError(error) = execution.run().unwrap() else {
        panic!("需要含物件的 LuaError");
    };
    drop(execution);
    let Value::Object(value) = error.value else {
        panic!("錯誤值應為物件");
    };
    let charged = vm.ledger_snapshot().host_allocation_bytes;
    assert!(
        charged - baseline > handle_charge,
        "Rc wrapper 未計 host bytes"
    );
    let clone = error.clone();
    drop(error);
    assert_eq!(vm.ledger_snapshot().host_allocation_bytes, charged);
    assert_eq!(vm.roots().count(RootKind::Host), 2);
    vm.collect().unwrap();
    assert!(vm.object_kind(value).is_ok());
    drop(clone);
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
    vm.remove_root(environment_root).unwrap();
}

#[test]
fn p12_6_closure_capture_site_ordinal_fails_and_retries() {
    let profile = profile();
    let module = compile(
        b"local captured=7; return function() return captured end",
        &profile,
    );
    let mut baseline = new_profile_vm(&profile);
    let probe = baseline.ledger_probe();
    let mut baseline_run = baseline.load(module.clone()).unwrap();
    assert!(matches!(baseline_run.run(), Ok(RunOutcome::Returned(_))));
    drop(baseline_run);
    let end = probe.trace().next_ordinal;
    let mut matched = 0;
    let mut host_staging = 0;
    for ordinal in 1..end {
        let mut vm = new_profile_vm(&profile);
        vm.inject_allocation_failure_at(ordinal);
        let succeeded = match vm.load(module.clone()) {
            Ok(mut execution) => execution.run().is_ok(),
            Err(_) => false,
        };
        let failure = vm.allocation_trace().last_failure;
        let Some(failure) = failure.filter(|failure| failure.attempt.ordinal == ordinal) else {
            continue;
        };
        if p12_6_is_vm_mod_site(failure.attempt.site.file)
            && failure.attempt.point == Some(FailPoint::ClosureCapturesReserve)
        {
            assert_eq!(failure.attempt.domain, AllocationDomain::Host);
            host_staging += 1;
        }
        if p12_6_site_file_is(failure.attempt.site.file, "closure.rs") {
            assert_eq!(failure.attempt.domain, AllocationDomain::LuaHeap);
            assert_eq!(
                failure.attempt.point,
                Some(FailPoint::ClosureCapturesReserve)
            );
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert!(!succeeded, "capture reserve 失敗必須退出該次執行");
            assert_eq!(vm.roots().total_count(), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            let mut retry = vm.load(module.clone()).unwrap();
            assert!(matches!(retry.run(), Ok(RunOutcome::Returned(_))));
            drop(retry);
            matched += 1;
            println!(
                "P12_CLOSURE\tprofile={profile}\tordinal={ordinal}\tsite={:?}\tretry=PASS",
                failure.attempt.site
            );
        }
    }
    assert_eq!(
        matched, 1,
        "closure payload allocation site 未被逐 ordinal 注入"
    );
    assert_eq!(host_staging, 1, "VM 暫存 captures site 分欄錯誤");
}

#[test]
fn p12_6_string_constant_staging_is_host_and_payload_is_lua() {
    let profile = profile();
    let module = compile(b"return 'abc'", &profile);
    let mut baseline = new_profile_vm(&profile);
    let probe = baseline.ledger_probe();
    let mut baseline_run = baseline.load(module.clone()).unwrap();
    assert!(matches!(baseline_run.run(), Ok(RunOutcome::Returned(_))));
    drop(baseline_run);
    let end = probe.trace().next_ordinal;
    let mut staging = 0;
    let mut payload = 0;
    for ordinal in 1..end {
        let mut vm = new_profile_vm(&profile);
        vm.inject_allocation_failure_at(ordinal);
        let _ = match vm.load(module.clone()) {
            Ok(mut execution) => execution.run().is_ok(),
            Err(_) => false,
        };
        let Some(failure) = vm
            .allocation_trace()
            .last_failure
            .filter(|failure| failure.attempt.ordinal == ordinal)
        else {
            continue;
        };
        if failure.attempt.point == Some(FailPoint::StringBytesReserve) {
            if p12_6_is_vm_mod_site(failure.attempt.site.file) {
                assert_eq!(failure.attempt.domain, AllocationDomain::Host);
                staging += 1;
            } else if p12_6_site_file_is(failure.attempt.site.file, "string.rs") {
                assert_eq!(failure.attempt.domain, AllocationDomain::LuaHeap);
                payload += 1;
            }
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    assert_eq!(staging, 1);
    assert_eq!(payload, 1);
}

#[test]
fn p12_5_lua_finalizer_revives_once_then_reclaims() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(
                b"return function(o) count = (count or 0) + 1; saved = o end",
                &profile,
            ),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("無法取得 Lua finalizer");
    };
    let Value::Object(callback) = values[0] else {
        panic!("finalizer 必須是 Lua closure");
    };
    drop(execution);
    let target = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let count_key_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let saved_key_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    vm.raw_set(metatable, Value::Object(gc_key), Value::Object(callback))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(
        vm.raw_get(environment, Value::Object(saved_key)),
        Ok(Value::Object(target))
    );
    vm.raw_set(environment, Value::Object(saved_key), Value::Nil)
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(target), Err(VmError::StaleObject));
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    vm.remove_root(environment_root).unwrap();
    vm.remove_root(saved_key_root).unwrap();
    vm.remove_root(count_key_root).unwrap();
    println!("P12_STAGE\tp12_5_lua_finalizer_revives_once_then_reclaims\t{profile}\tstatus=PASS");
}

#[test]
fn p12_5_active_lua_callback_drains_before_return() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_key_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let mut callback_run = vm
        .load_with_environment(
            compile(b"return function(o) count = (count or 0) + 1 end", &profile),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = callback_run.run().unwrap() else {
        panic!("缺少 Lua callback");
    };
    let Value::Object(callback) = values[0] else {
        panic!("callback 必須是 closure");
    };
    drop(callback_run);
    let target = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
    vm.raw_set(metatable, Value::Object(gc_key), Value::Object(callback))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    let target_root = HostHandle::<Value>::new(&mut vm, target).unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm
        .load_with_environment(compile(b"return {}", &profile), Value::Object(environment))
        .unwrap();
    drop(target_root);
    assert!(matches!(main.run(), Ok(RunOutcome::Returned(_))));
    drop(main);
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    vm.remove_root(count_key_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!("P12_STAGE\tp12_5_active_lua_callback_drains_before_return\t{profile}\tstatus=PASS");
}

#[test]
fn p12_5_error_yield_and_explicit_remark() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let count_key_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let saved_key_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) count = (count or 0) + 1; saved = o end",
    );
    let target = vm.allocate_table().unwrap();
    let metatable = attach_finalizer(&mut vm, target, callback);
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    vm.set_metatable(target, Some(metatable)).unwrap();
    vm.raw_set(environment, Value::Object(saved_key), Value::Nil)
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(2))
    );
    vm.raw_set(environment, Value::Object(saved_key), Value::Nil)
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(target), Err(VmError::StaleObject));
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(2))
    );

    let failing = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) error('gc fail') end",
    );
    let failed = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, failed, failing);
    let yielding = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) coroutine.yield(1) end",
    );
    let yielded = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, yielded, yielding);
    let warnings = vm.gc_trace().finalizer_warnings;
    vm.collect().unwrap();
    assert_eq!(vm.gc_trace().finalizer_warnings, warnings + 2);
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(failed), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(yielded), Err(VmError::StaleObject));
    vm.remove_root(saved_key_root).unwrap();
    vm.remove_root(count_key_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!("P12_STAGE\tp12_5_error_yield_and_explicit_remark\t{profile}\tstatus=PASS");
}

#[test]
fn p12_5_terminal_tailcall_preserves_result_and_drains_callback() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) count = (count or 0) + 1; error('gc fail') end",
    );
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    vm.raw_set(environment, Value::Object(saved_key), Value::Object(target))
        .unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm
        .load_with_environment(
            compile(
                b"local f = coroutine.status; local co = coroutine.create(function() end); saved = nil; return f(co)",
                &profile,
            ),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::Returned(values) = main.run().unwrap() else {
        panic!("原始 tail call 結果遭 finalizer 覆蓋");
    };
    let Value::Object(status) = values[0] else {
        panic!("coroutine.status 應回傳字串");
    };
    drop(main);
    assert_eq!(
        vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
        Ok(b"suspended".to_vec())
    );
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert!(vm.gc_trace().finalizer_deferred_terminals > 0);
    assert_eq!(vm.gc_trace().finalizer_warnings, 1);
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_terminal_tailcall_preserves_result_and_drains_callback\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_coroutine_finalizer_yield_is_warning_only() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) coroutine.yield(99) end",
    );
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    vm.raw_set(environment, Value::Object(saved_key), Value::Object(target))
        .unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm.load_with_environment(
        compile(
            b"local co = coroutine.create(function() saved = nil; local t = {}; return 7 end); return coroutine.resume(co)",
            &profile,
        ),
        Value::Object(environment),
    ).unwrap();
    assert_eq!(
        main.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Integer(7)
        ]))
    );
    drop(main);
    assert_eq!(vm.gc_trace().finalizer_warnings, 1);
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!("P12_STAGE\tp12_5_coroutine_finalizer_yield_is_warning_only\t{profile}\tstatus=PASS");
}

#[test]
fn p12_5_original_lua_error_survives_finalizer_yield() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) coroutine.yield(99) end",
    );
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    vm.raw_set(environment, Value::Object(saved_key), Value::Object(target))
        .unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm
        .load_with_environment(
            compile(b"saved = nil; local t = {}; error('original')", &profile),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::LuaError(error) = main.run().unwrap() else {
        panic!("原始 LuaError 被 finalizer 改寫");
    };
    drop(main);
    let Value::Object(message) = error.value else {
        panic!("原始 LuaError 應為字串");
    };
    assert_eq!(
        vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
        Ok(b"original".to_vec())
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 1);
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_original_lua_error_survives_finalizer_yield\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_native_error_finalizer_preserves_original_lua_error() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let error_key = vm.allocate_byte_string(b"error").unwrap();
    let Value::Object(callback) = vm.raw_get(environment, Value::Object(error_key)).unwrap() else {
        panic!("缺少 native error builtin");
    };
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    vm.raw_set(environment, Value::Object(saved_key), Value::Object(target))
        .unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm
        .load_with_environment(
            compile(b"saved = nil; local t = {}; error('original')", &profile),
            Value::Object(environment),
        )
        .unwrap();
    let RunOutcome::LuaError(error) = main.run().unwrap() else {
        panic!("原始 LuaError 被 native finalizer 改寫");
    };
    drop(main);
    let Value::Object(message) = error.value else {
        panic!("原始 LuaError 應為字串");
    };
    assert_eq!(
        vm.with_byte_string(message, |s| s.as_bytes().to_vec()),
        Ok(b"original".to_vec())
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 1);
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_native_error_finalizer_preserves_original_lua_error\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_callable_table_finalizer_uses_call_metamethod() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(self,o) count = (count or 0) + 1 end",
    );
    let callable = vm.allocate_table().unwrap();
    let callable_mt = vm.allocate_table().unwrap();
    let call_key = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(
        callable_mt,
        Value::Object(call_key),
        Value::Object(callback),
    )
    .unwrap();
    vm.set_metatable(callable, Some(callable_mt)).unwrap();
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callable);
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 0);
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_callable_table_finalizer_uses_call_metamethod\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_native_pcall_finalizer_invokes_callable_target() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(self) count = (count or 0) + 1 end",
    );
    let target = vm.allocate_table().unwrap();
    let target_mt = vm.allocate_table().unwrap();
    let call_key = vm.allocate_byte_string(b"__call").unwrap();
    let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
    let pcall_key = vm.allocate_byte_string(b"pcall").unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let pcall = vm.raw_get(environment, Value::Object(pcall_key)).unwrap();
    vm.raw_set(target_mt, Value::Object(call_key), Value::Object(callback))
        .unwrap();
    vm.raw_set(target_mt, Value::Object(gc_key), pcall).unwrap();
    vm.set_metatable(target, Some(target_mt)).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 0);
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_native_pcall_finalizer_invokes_callable_target\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_active_native_pcall_finalizer_drains_before_return() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(self) count = (count or 0) + 1 end",
    );
    let target = vm.allocate_table().unwrap();
    let target_mt = vm.allocate_table().unwrap();
    let call_key = vm.allocate_byte_string(b"__call").unwrap();
    let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
    let pcall_key = vm.allocate_byte_string(b"pcall").unwrap();
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let pcall = vm.raw_get(environment, Value::Object(pcall_key)).unwrap();
    vm.raw_set(target_mt, Value::Object(call_key), Value::Object(callback))
        .unwrap();
    vm.raw_set(target_mt, Value::Object(gc_key), pcall).unwrap();
    vm.set_metatable(target, Some(target_mt)).unwrap();
    let target_root = HostHandle::<Value>::new(&mut vm, target).unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(compile(b"return {}", &profile), Value::Object(environment))
        .unwrap();
    drop(target_root);
    assert!(matches!(execution.run(), Ok(RunOutcome::Returned(_))));
    drop(execution);
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 0);
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_active_native_pcall_finalizer_drains_before_return\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_call_metamethod_resolves_to_native_coroutine_wrapper() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let wrapped = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return coroutine.wrap(function(self,o) count = (count or 0) + 1 end)",
    );
    let callback = vm.allocate_table().unwrap();
    let callback_mt = vm.allocate_table().unwrap();
    let call_key = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(callback_mt, Value::Object(call_key), Value::Object(wrapped))
        .unwrap();
    vm.set_metatable(callback, Some(callback_mt)).unwrap();
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 0);
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_call_metamethod_resolves_to_native_coroutine_wrapper\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_active_native_coroutine_wrapper_preserves_terminal_return() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let wrapped = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return coroutine.wrap(function(self,o) count = (count or 0) + 1 end)",
    );
    let callback = vm.allocate_table().unwrap();
    let callback_mt = vm.allocate_table().unwrap();
    let call_key = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(callback_mt, Value::Object(call_key), Value::Object(wrapped))
        .unwrap();
    vm.set_metatable(callback, Some(callback_mt)).unwrap();
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    let count_key = vm.allocate_byte_string(b"count").unwrap();
    let count_root = vm.add_root(RootKind::Host, count_key).unwrap();
    let target_root = HostHandle::<Value>::new(&mut vm, target).unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(compile(b"return {}", &profile), Value::Object(environment))
        .unwrap();
    drop(target_root);
    assert!(matches!(execution.run(), Ok(RunOutcome::Returned(_))));
    drop(execution);
    assert_eq!(
        vm.raw_get(environment, Value::Object(count_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 0);
    vm.remove_root(count_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!(
        "P12_STAGE\tp12_5_active_native_coroutine_wrapper_preserves_terminal_return\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_5_reverse_registration_order() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    let seq_key = vm.allocate_byte_string(b"seq").unwrap();
    let seq_root = vm.add_root(RootKind::Host, seq_key).unwrap();
    let first_callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) seq = (seq or 0) * 10 + 1 end",
    );
    let second_callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) seq = (seq or 0) * 10 + 2 end",
    );
    let first = vm.allocate_table().unwrap();
    let second = vm.allocate_table().unwrap();
    let first_metatable = attach_finalizer(&mut vm, first, first_callback);
    attach_finalizer(&mut vm, second, second_callback);
    vm.set_metatable(first, Some(first_metatable)).unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(seq_key)),
        Ok(Value::Integer(21))
    );
    vm.remove_root(seq_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!("P12_STAGE\tp12_5_reverse_registration_order\t{profile}\tstatus=PASS");
}

#[test]
fn p12_5_close_callback_survives_finalizer_error() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_error_builtins(environment).unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let closer_key = vm.allocate_byte_string(b"closer").unwrap();
    let closed_key = vm.allocate_byte_string(b"closed").unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    let closed_root = vm.add_root(RootKind::Host, closed_key).unwrap();
    let finalizer = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) error('gc fail') end",
    );
    let close_callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o,e) closed = (closed or 0) + 1 end",
    );
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, finalizer);
    let closer = vm.allocate_table().unwrap();
    let close_metatable = vm.allocate_table().unwrap();
    let close_key = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(
        close_metatable,
        Value::Object(close_key),
        Value::Object(close_callback),
    )
    .unwrap();
    vm.set_metatable(closer, Some(close_metatable)).unwrap();
    vm.raw_set(environment, Value::Object(saved_key), Value::Object(target))
        .unwrap();
    vm.raw_set(
        environment,
        Value::Object(closer_key),
        Value::Object(closer),
    )
    .unwrap();
    vm.set_collect_every_allocation(true);
    let mut main = vm
        .load_with_environment(
            compile(
                b"local x <close> = closer; saved = nil; local t = {}; return 7",
                &profile,
            ),
            Value::Object(environment),
        )
        .unwrap();
    assert_eq!(
        main.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    drop(main);
    assert_eq!(
        vm.raw_get(environment, Value::Object(closed_key)),
        Ok(Value::Integer(1))
    );
    assert_eq!(vm.gc_trace().finalizer_warnings, 1);
    vm.remove_root(closed_root).unwrap();
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    println!("P12_STAGE\tp12_5_close_callback_survives_finalizer_error\t{profile}\tstatus=PASS");
}

#[test]
fn gc_case_008() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let weak_v = vm.allocate_table().unwrap();
    let weak_k = vm.allocate_table().unwrap();
    let weak_kv = vm.allocate_table().unwrap();
    for (table, mode) in [
        (weak_v, b"v".as_slice()),
        (weak_k, b"k".as_slice()),
        (weak_kv, b"kv".as_slice()),
    ] {
        let metatable = vm.allocate_table().unwrap();
        let mode_value = vm.allocate_byte_string(mode).unwrap();
        vm.raw_set(
            metatable,
            Value::Object(mode_key),
            Value::Object(mode_value),
        )
        .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
    }
    let weak_v_key = vm.allocate_byte_string(b"weak_v").unwrap();
    let weak_k_key = vm.allocate_byte_string(b"weak_k").unwrap();
    let weak_kv_key = vm.allocate_byte_string(b"weak_kv").unwrap();
    let seen_v_key = vm.allocate_byte_string(b"seen_v").unwrap();
    let seen_k_key = vm.allocate_byte_string(b"seen_k").unwrap();
    let seen_kv_key = vm.allocate_byte_string(b"seen_kv").unwrap();
    let saved_key = vm.allocate_byte_string(b"saved").unwrap();
    let seen_v_root = vm.add_root(RootKind::Host, seen_v_key).unwrap();
    let seen_k_root = vm.add_root(RootKind::Host, seen_k_key).unwrap();
    let seen_kv_root = vm.add_root(RootKind::Host, seen_kv_key).unwrap();
    let saved_root = vm.add_root(RootKind::Host, saved_key).unwrap();
    vm.raw_set(
        environment,
        Value::Object(weak_v_key),
        Value::Object(weak_v),
    )
    .unwrap();
    vm.raw_set(
        environment,
        Value::Object(weak_k_key),
        Value::Object(weak_k),
    )
    .unwrap();
    vm.raw_set(
        environment,
        Value::Object(weak_kv_key),
        Value::Object(weak_kv),
    )
    .unwrap();
    let callback = lua_finalizer(
        &mut vm,
        environment,
        &profile,
        b"return function(o) seen_v = weak_v[1] == nil; seen_k = weak_k[o]; seen_kv = weak_kv[o] == nil; saved = o end",
    );
    let target = vm.allocate_table().unwrap();
    attach_finalizer(&mut vm, target, callback);
    vm.raw_set(weak_v, Value::Integer(1), Value::Object(target))
        .unwrap();
    vm.raw_set(weak_k, Value::Object(target), Value::Integer(42))
        .unwrap();
    vm.raw_set(weak_kv, Value::Object(target), Value::Object(target))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.raw_get(environment, Value::Object(seen_v_key)),
        Ok(Value::Boolean(true))
    );
    assert_eq!(
        vm.raw_get(environment, Value::Object(seen_k_key)),
        Ok(Value::Integer(42))
    );
    assert_eq!(
        vm.raw_get(environment, Value::Object(seen_kv_key)),
        Ok(Value::Boolean(true))
    );
    assert_eq!(
        vm.raw_get(weak_k, Value::Object(target)),
        Ok(Value::Integer(42))
    );
    vm.raw_set(environment, Value::Object(saved_key), Value::Nil)
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(target), Err(VmError::StaleObject));
    vm.remove_root(saved_root).unwrap();
    vm.remove_root(seen_kv_root).unwrap();
    vm.remove_root(seen_k_root).unwrap();
    vm.remove_root(seen_v_root).unwrap();
    vm.remove_root(environment_root).unwrap();
    record_gc_case(
        "GC-008",
        &profile,
        "weak-v=cleared-before-finalizer;weak-k=visible-to-finalizer;weak-kv=cleared-before-finalizer;revival=collected",
    );
}

#[test]
fn p12_4_public_ephemeron_and_all_weak_cleanup() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let weak = vm.allocate_table().unwrap();
    let mt = vm.allocate_table().unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mode = vm.allocate_byte_string(b"k").unwrap();
    vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(weak, Some(mt)).unwrap();
    let root = vm.add_root(RootKind::Host, weak).unwrap();
    let key = vm.allocate_table().unwrap();
    let value = vm.allocate_table().unwrap();
    vm.add_child(value, key).unwrap();
    vm.raw_set(weak, Value::Object(key), Value::Object(value))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));

    let all = vm.allocate_table().unwrap();
    let all_mt = vm.allocate_table().unwrap();
    let all_mode = vm.allocate_byte_string(b"kv").unwrap();
    vm.raw_set(all_mt, Value::Object(mode_key), Value::Object(all_mode))
        .unwrap();
    vm.set_metatable(all, Some(all_mt)).unwrap();
    let all_root = vm.add_root(RootKind::Host, all).unwrap();
    let all_key = vm.allocate_table().unwrap();
    let all_value = vm.allocate_table().unwrap();
    vm.raw_set(all, Value::Object(all_key), Value::Object(all_value))
        .unwrap();
    vm.raw_set(all, Value::Integer(1), Value::Integer(2))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(all_key), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(all_value), Err(VmError::StaleObject));
    assert_eq!(vm.raw_get(all, Value::Integer(1)), Ok(Value::Integer(2)));
    vm.remove_root(all_root).unwrap();
    vm.remove_root(root).unwrap();
    println!("P12_STAGE\tp12_4_public_ephemeron_and_all_weak_cleanup\t{profile}\tstatus=PASS");
}

#[test]
fn p12_4_public_multihop_ephemeron_fixed_point() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mode = vm.allocate_byte_string(b"k").unwrap();
    let later = vm.allocate_table().unwrap();
    let later_mt = vm.allocate_table().unwrap();
    vm.raw_set(later_mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(later, Some(later_mt)).unwrap();
    let first = vm.allocate_table().unwrap();
    let first_mt = vm.allocate_table().unwrap();
    vm.raw_set(first_mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(first, Some(first_mt)).unwrap();
    let later_root = vm.add_root(RootKind::Host, later).unwrap();
    let first_root = vm.add_root(RootKind::Host, first).unwrap();
    let key1 = vm.allocate_table().unwrap();
    let key1_root = vm.add_root(RootKind::Host, key1).unwrap();
    let key2 = vm.allocate_table().unwrap();
    let value1 = vm.allocate_table().unwrap();
    let value2 = vm.allocate_table().unwrap();
    vm.add_child(value1, key2).unwrap();
    vm.raw_set(later, Value::Object(key2), Value::Object(value2))
        .unwrap();
    vm.raw_set(first, Value::Object(key1), Value::Object(value1))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(value2),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );
    assert!(vm.gc_trace().ephemeron_iterations >= 2);
    assert_eq!(vm.gc_trace().ephemeron_last_key, Some(key2));
    assert!(vm.gc_trace().ephemeron_converged);
    vm.remove_root(key1_root).unwrap();
    vm.collect().unwrap();
    for object in [key1, key2, value1, value2] {
        assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
    }
    vm.remove_root(first_root).unwrap();
    vm.remove_root(later_root).unwrap();
    println!("P12_STAGE\tp12_4_public_multihop_ephemeron_fixed_point\t{profile}\tstatus=PASS");
}

#[test]
fn p12_4_public_minor_major_weak_key_boundary() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    vm.set_gc_mode(GcMode::Generational).unwrap();
    vm.set_gc_promotion_survivals(1).unwrap();
    let weak = vm.allocate_table().unwrap();
    let mt = vm.allocate_table().unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mode = vm.allocate_byte_string(b"k").unwrap();
    vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(weak, Some(mt)).unwrap();
    let weak_root = vm.add_root(RootKind::Host, weak).unwrap();
    let key = vm.allocate_table().unwrap();
    let key_root = vm.add_root(RootKind::Host, key).unwrap();
    let value = vm.allocate_table().unwrap();
    vm.raw_set(weak, Value::Object(key), Value::Object(value))
        .unwrap();
    vm.collect_minor().unwrap();
    vm.remove_root(key_root).unwrap();
    vm.collect_minor().unwrap();
    assert_eq!(
        vm.object_kind(value),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );
    vm.collect_major().unwrap();
    assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
    vm.remove_root(weak_root).unwrap();
    println!("P12_STAGE\tp12_4_public_minor_major_weak_key_boundary\t{profile}\tstatus=PASS");
}

#[test]
fn p12_4_public_weak_value_and_string_exception() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let weak = vm.allocate_table().unwrap();
    let mt = vm.allocate_table().unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mode = vm.allocate_byte_string(b"v").unwrap();
    vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(weak, Some(mt)).unwrap();
    let root = vm.add_root(RootKind::Host, weak).unwrap();
    let lost = vm.allocate_table().unwrap();
    let retained = vm.allocate_byte_string(b"string").unwrap();
    vm.raw_set(weak, Value::Integer(1), Value::Object(lost))
        .unwrap();
    vm.raw_set(weak, Value::Integer(2), Value::Object(retained))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(lost), Err(VmError::StaleObject));
    assert_eq!(vm.raw_get(weak, Value::Integer(1)), Ok(Value::Nil));
    assert_eq!(
        vm.object_kind(retained),
        Ok(rivetlua_runtime::ObjectKind::ByteString)
    );
    vm.remove_root(root).unwrap();
    println!("P12_STAGE\tp12_4_public_weak_value_and_string_exception\t{profile}\tstatus=PASS");
}

#[test]
fn p12_4_public_long_mode_profile_difference() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let weak = vm.allocate_table().unwrap();
    let mt = vm.allocate_table().unwrap();
    let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
    let mut long_mode = vec![b'x'; 40];
    long_mode.push(b'v');
    let mode = vm.allocate_byte_string(&long_mode).unwrap();
    vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode))
        .unwrap();
    vm.set_metatable(weak, Some(mt)).unwrap();
    let root = vm.add_root(RootKind::Host, weak).unwrap();
    let value = vm.allocate_table().unwrap();
    vm.raw_set(weak, Value::Integer(1), Value::Object(value))
        .unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(value).is_err(), profile == "lua55-i64f64");
    vm.remove_root(root).unwrap();
    println!("P12_STAGE\tp12_4_public_long_mode_profile_difference\t{profile}\tstatus=PASS");
}

#[test]
fn p12_3_old_to_young_minor_then_unrooted_major_reclaims_both() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    vm.set_gc_mode(GcMode::Generational).unwrap();
    vm.set_gc_promotion_survivals(1).unwrap();
    let table = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, table).unwrap();
    assert_eq!(vm.collect_minor(), Ok(0));
    assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
    let child = vm.allocate_table().unwrap();
    vm.raw_set(table, Value::Integer(7), Value::Object(child))
        .unwrap();
    assert_eq!(vm.gc_trace().remembered_len, 1);
    assert_eq!(vm.collect_minor(), Ok(0));
    assert_eq!(
        vm.raw_get(table, Value::Integer(7)),
        Ok(Value::Object(child))
    );
    vm.remove_root(root).unwrap();
    assert_eq!(vm.collect_major(), Ok(2));
    assert_eq!(vm.gc_trace().remembered_len, 0);
    assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
    println!(
        "P12_STAGE\tp12_3_old_to_young_minor_then_unrooted_major_reclaims_both\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_3_public_mode_threshold_and_remembered_failure() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    vm.set_gc_promotion_survivals(1).unwrap();
    vm.set_gc_major_threshold(1).unwrap();
    vm.set_gc_mode(GcMode::Generational).unwrap();
    let table = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, table).unwrap();
    let trace = vm.incremental_step(1).unwrap();
    assert_eq!(trace.cycle, GcCycleKind::Major);
    assert_eq!(
        vm.set_gc_mode(GcMode::Incremental),
        Err(VmError::WrongGcPhase)
    );
    while vm.gc_trace().phase != GcPhase::Pause {
        vm.incremental_step(1).unwrap();
    }
    assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
    let child = vm.allocate_table().unwrap();
    let before = vm.ledger_snapshot();
    vm.inject_failure_once(FailPoint::RememberedReserve);
    assert_eq!(
        vm.raw_set(table, Value::Integer(1), Value::Object(child)),
        Err(VmError::InjectedFailure(FailPoint::RememberedReserve))
    );
    assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
    assert_eq!(vm.gc_trace().remembered_len, 0);
    assert_eq!(vm.ledger_snapshot(), before);
    vm.remove_root(root).unwrap();
    assert_eq!(vm.collect_major(), Ok(2));
    println!(
        "P12_STAGE\tp12_3_public_mode_threshold_and_remembered_failure\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_2_black_to_white_table_barrier_survives_incremental_sweep() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let table = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, table).unwrap();
    for _ in 0..16 {
        vm.incremental_step(1).unwrap();
        if vm.gc_color(table) == Ok(GcColor::Black) {
            break;
        }
    }
    assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
    let child = vm.allocate_table().unwrap();
    assert_eq!(vm.gc_color(child), Ok(GcColor::White));
    vm.raw_set(table, Value::Integer(1), Value::Object(child))
        .unwrap();
    assert_eq!(vm.gc_color(child), Ok(GcColor::Gray));
    assert!(vm.gc_trace().barrier_count > 0);
    for _ in 0..64 {
        if vm.incremental_step(1).unwrap().phase == GcPhase::Pause {
            break;
        }
    }
    assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
    assert_eq!(
        vm.raw_get(table, Value::Integer(1)),
        Ok(Value::Object(child))
    );
    assert!(vm.object_kind(child).is_ok());
    vm.remove_root(root).unwrap();
    assert_eq!(vm.collect(), Ok(2));
    println!(
        "P12_STAGE\tp12_2_black_to_white_table_barrier_survives_incremental_sweep\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_2_public_phase_budget_and_worklist_failure_boundary() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let object = vm.allocate(Value::Integer(5)).unwrap();
    let ledger = vm.ledger_snapshot();
    assert_eq!(vm.incremental_step(0), Err(VmError::InvalidGcStepBudget));
    vm.inject_failure_once(FailPoint::WorkReserve);
    assert_eq!(
        vm.incremental_step(1),
        Err(VmError::InjectedFailure(FailPoint::WorkReserve))
    );
    assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
    assert_eq!(vm.ledger_snapshot(), ledger);
    let mut phases = Vec::new();
    for _ in 0..32 {
        let trace = vm.incremental_step(1).unwrap();
        phases.push(trace.phase);
        if trace.phase == GcPhase::Pause {
            break;
        }
    }
    assert!(phases.contains(&GcPhase::RootMark));
    assert!(phases.contains(&GcPhase::Propagate));
    assert!(phases.contains(&GcPhase::Atomic));
    assert!(phases.contains(&GcPhase::Sweep));
    assert_eq!(phases.last(), Some(&GcPhase::Pause));
    assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
    assert!(vm.gc_trace().reclaimed_bytes > 0);
    println!(
        "P12_STAGE\tp12_2_public_phase_budget_and_worklist_failure_boundary\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_2_debt_driven_steps_preserve_active_vm_values() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.set_gc_debt_threshold(1);
    let module = compile(
        b"local t = {}; for i = 1, 40 do t[i] = {}; t[i][1] = i end; return t[40][1]",
        &profile,
    );
    let mut execution = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(40)]))
    );
    drop(execution);
    assert!(vm.gc_trace().transition_count >= 2, "{:?}", vm.gc_trace());
    assert!(
        vm.gc_trace().worklist_len
            <= vm.gc_trace().white + vm.gc_trace().gray + vm.gc_trace().black
    );
    vm.remove_root(root).unwrap();
    assert!(vm.collect().unwrap() > 0);
    println!(
        "P12_STAGE\tp12_2_debt_driven_steps_preserve_active_vm_values\t{profile}\tstatus=PASS"
    );
}

fn profile() -> String {
    let name = std::env::var("RIVETLUA_P12_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    assert!(matches!(name.as_str(), "lua55-i64f64" | "lua54-i64f64"));
    name
}

fn new_profile_vm(profile: &str) -> Vm {
    let runtime_profile = match profile {
        "lua54-i64f64" => rivetlua_core::LuaProfile::Lua54,
        "lua55-i64f64" => rivetlua_core::LuaProfile::Lua55,
        _ => unreachable!(),
    };
    Vm::new_with_profile(runtime_profile).unwrap()
}

fn compile(source: &[u8], profile: &str) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => unreachable!(),
    };
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

fn lua_finalizer(
    vm: &mut Vm,
    environment: rivetlua_core::ObjectRef,
    profile: &str,
    source: &[u8],
) -> rivetlua_core::ObjectRef {
    let mut execution = vm
        .load_with_environment(compile(source, profile), Value::Object(environment))
        .unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("缺少 Lua finalizer closure");
    };
    let Value::Object(callback) = values[0] else {
        panic!("finalizer 必須是 closure");
    };
    callback
}

fn attach_finalizer(
    vm: &mut Vm,
    target: rivetlua_core::ObjectRef,
    callback: rivetlua_core::ObjectRef,
) -> rivetlua_core::ObjectRef {
    let metatable = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"__gc").unwrap();
    vm.raw_set(metatable, Value::Object(key), Value::Object(callback))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    metatable
}

#[test]
fn p12_1_active_execution_root_releases_after_return() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let environment = vm.allocate_table().unwrap();
    let mut execution = vm
        .load_with_environment(
            compile(b"return missing", &profile),
            Value::Object(environment),
        )
        .unwrap();
    let mut active = Vec::new();
    execution
        .visit_active_roots(|kind, object| active.push((kind, object)))
        .unwrap();
    assert!(active.contains(&(ActiveRootKind::Frame, environment)));
    assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![Value::Nil])));
    drop(execution);
    assert!(vm.collect().unwrap() >= 1);
    // 結果不持有 environment；執行器退出後其最後一個 stack root 應已移除。
    assert_eq!(vm.object_kind(environment), Err(VmError::StaleObject));
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P12_STAGE\tp12_1_active_execution_root_releases_after_return\t{profile}\tstatus=PASS"
    );
}

#[test]
fn p12_1_public_root_provenance_cycle_and_failed_write() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let first = vm.allocate_table().unwrap();
    let second = vm.allocate_table().unwrap();
    vm.raw_set(first, Value::Integer(1), Value::Object(second))
        .unwrap();
    vm.raw_set(second, Value::Integer(1), Value::Object(first))
        .unwrap();
    let registry = vm.add_root(RootKind::Registry, first).unwrap();
    let mut seen = Vec::new();
    vm.visit_roots(|kind, id, object| seen.push((kind, id, object)));
    assert_eq!(seen, vec![(RootKind::Registry, registry, first)]);
    assert_eq!(vm.collect(), Ok(0));

    let foreign = Vm::new().unwrap().allocate_table().unwrap();
    let before = vm.ledger_snapshot();
    assert_eq!(
        vm.raw_set(first, Value::Integer(1), Value::Object(foreign)),
        Err(VmError::WrongVm)
    );
    assert_eq!(
        vm.raw_get(first, Value::Integer(1)),
        Ok(Value::Object(second))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    vm.inject_failure_once(FailPoint::TableInsert);
    assert_eq!(
        vm.raw_set(first, Value::Integer(2), Value::Object(second)),
        Err(VmError::InjectedFailure(FailPoint::TableInsert))
    );
    assert_eq!(vm.raw_get(first, Value::Integer(2)), Ok(Value::Nil));
    assert_eq!(vm.ledger_snapshot(), before);
    vm.remove_root(registry).unwrap();
    assert_eq!(vm.collect(), Ok(2));
    assert_eq!(vm.roots().total_count(), 0);
    let after_sweep = vm.ledger_snapshot();
    assert_eq!(
        vm.raw_set(first, Value::Integer(1), Value::Object(second)),
        Err(VmError::StaleObject)
    );
    assert_eq!(vm.ledger_snapshot(), after_sweep);
    let hosted = vm.allocate(Value::Integer(7)).unwrap();
    let handle = HostHandle::<Value>::new(&mut vm, hosted).unwrap();
    let mut host_roots = Vec::new();
    vm.visit_roots(|kind, id, object| host_roots.push((kind, id, object)));
    assert_eq!(host_roots, vec![(RootKind::Host, handle.root_id(), hosted)]);
    drop(handle);
    assert_eq!(vm.collect(), Ok(1));
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P12_STAGE\tp12_1_public_root_provenance_cycle_and_failed_write\t{profile}\tstatus=PASS"
    );
}

fn record_gc_case(id: &str, profile: &str, actual: &str) {
    println!(
        "P12_CASE\t{id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted-by-formal-case"
    );
}

#[test]
fn gc_case_001() {
    let profile = profile();
    let mut vm = new_profile_vm(&profile);
    let first = vm.allocate_table().unwrap();
    let second = vm.allocate_table().unwrap();
    vm.raw_set(first, Value::Integer(1), Value::Object(second))
        .unwrap();
    vm.raw_set(second, Value::Integer(1), Value::Object(first))
        .unwrap();
    let root = vm.add_root(RootKind::Stack, first).unwrap();
    assert_eq!(vm.collect(), Ok(0));
    assert_eq!(vm.remove_root(root), Ok(first));
    assert_eq!(vm.collect(), Ok(2));
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
    assert_eq!(vm.object_kind(second), Err(VmError::StaleObject));
    let replacement = vm.allocate_table().unwrap();
    assert_ne!(replacement, first);
    assert!(vm.object_kind(replacement).is_ok());
    assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
    record_gc_case(
        "GC-001",
        &profile,
        "cycle=reclaimed;roots=0;generation=stale-handle-rejected",
    );
}

#[test]
fn gc_case_002() {
    let profile = profile();
    p12_2_black_to_white_table_barrier_survives_incremental_sweep();
    record_gc_case(
        "GC-002",
        &profile,
        "barrier=marked;child=retained;cycle=complete",
    );
}

#[test]
fn gc_case_003() {
    let profile = profile();
    p12_4_public_ephemeron_and_all_weak_cleanup();
    record_gc_case(
        "GC-003",
        &profile,
        "ephemeron=converged;reverse-key=not-root;pair=cleared",
    );
}

#[test]
fn gc_case_004() {
    let profile = profile();
    p12_5_lua_finalizer_revives_once_then_reclaims();
    record_gc_case(
        "GC-004",
        &profile,
        "finalizer=once;revival=observed;reclaimed=after-root-drop",
    );
}

#[test]
fn gc_case_005() {
    let profile = profile();
    p12_6_allocation_failure_each_lua_site_ordinal_fails_atomically_and_retries();
    p12_6_closure_capture_site_ordinal_fails_and_retries();
    record_gc_case(
        "GC-005",
        &profile,
        "allocation=atomic;lua-sites=covered;ordinals=failed-and-retried",
    );
}

#[test]
fn gc_case_006() {
    let profile = profile();
    p12_6_vm_lifecycle_10_000_balances_all_domains();
    record_gc_case(
        "GC-006",
        &profile,
        "vms=10000;domains=balanced;coroutines=collected",
    );
}

#[test]
fn gc_case_007() {
    let profile = profile();
    p12_3_old_to_young_minor_then_unrooted_major_reclaims_both();
    record_gc_case(
        "GC-007",
        &profile,
        "minor=retained;major=reclaimed;remembered-set=cleared",
    );
}

#[test]
fn gc_case_009() {
    let profile = profile();
    p12_5_error_yield_and_explicit_remark();
    record_gc_case(
        "GC-009",
        &profile,
        "yield=warning;error=diagnostic;gc-reentry=unit-asserted",
    );
}

#[test]
fn gc_case_010() {
    let profile = profile();
    p12_5_error_yield_and_explicit_remark();
    record_gc_case(
        "GC-010",
        &profile,
        "explicit-remark=next-eligible-only;unmarked=not-repeated",
    );
}
