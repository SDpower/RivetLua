use std::ffi::{c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_getmetatable, lua_gettop, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber,
    lua_pushvalue, lua_rawequal, lua_setmetatable, lua_settop,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, FailPoint, FinalizerState, GcAge,
    GcColor, GcMode, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind, Vm, VmError,
};

unsafe extern "C" {
    fn rivetlua_capi_test_protected_index_a4b(
        state: *mut lua_State,
        operation: c_int,
        index: c_int,
        argument: c_int,
        name: *const c_char,
        answer: *mut c_int,
    ) -> c_int;
}

fn protected_meta(state: *mut lua_State, operation: c_int, index: c_int) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：私有 C checkpoint 捕捉 Lua 錯誤並清除 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            operation,
            index,
            0,
            std::ptr::null(),
            &mut answer,
        )
    };
    (status, answer)
}

fn prime_checkpoint(state: *mut lua_State) {
    assert_eq!(protected_meta(state, -1, 0).0, 0);
}

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type Snapshot = (LedgerSnapshot, AllocationTrace, GcTrace, Roots);

fn snapshot(owner: &StateOwner) -> Snapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (
                vm.ledger_snapshot(),
                vm.allocation_trace(),
                vm.gc_trace(),
                roots,
            )
        })
        .unwrap()
}

fn registry(vm: &Vm) -> ObjectRef {
    let mut found = Vec::new();
    vm.visit_roots(|kind, _, object| {
        if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
            found.push(object);
        }
    });
    assert_eq!(found.len(), 1);
    found[0]
}

fn host_roots(roots: &Roots) -> Vec<(RootId, ObjectRef)> {
    roots
        .iter()
        .filter_map(|(kind, id, object)| (*kind == RootKind::Host).then_some((*id, *object)))
        .collect()
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).3;
    // SAFETY：StateOwner 保證 state 在此呼叫期間有效。
    unsafe { lua_createtable(owner.as_ptr(), 0, 0) };
    let after = snapshot(owner).3;
    let prior = host_roots(&before);
    let added: Vec<_> = host_roots(&after)
        .into_iter()
        .filter(|(id, _)| !prior.iter().any(|(old, _)| old == id))
        .collect();
    assert_eq!(added.len(), 1);
    added[0].1
}

fn assert_unchanged(owner: &StateOwner, state: *mut lua_State, top: i32, before: &Snapshot) {
    // SAFETY：只讀取目前有效 owner 的 stack top。
    assert_eq!(unsafe { lua_gettop(state) }, top);
    let after = snapshot(owner);
    assert_eq!(after.0, before.0, "ledger 不得半更新");
    assert_eq!(after.2, before.2, "GC 不得半轉移");
    assert_eq!(after.3, before.3, "roots 不得半發布");
}

fn assert_raised_settles(owner: &StateOwner, state: *mut lua_State, top: i32, before: &Snapshot) {
    assert_eq!(unsafe { lua_gettop(state) }, top);
    assert_eq!(snapshot(owner).3, before.3, "錯誤不可殘留 root");
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.gc_trace().worklist_len, 0);
        })
        .unwrap();
    assert_eq!(unsafe { lua_gettop(state) }, top);
    assert_eq!(snapshot(owner).3, before.3);
}

fn ordinary_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let before = snapshot(&owner);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 0);
    assert_eq!(snapshot(&owner), before);

    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(mt))
    );
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
    let roots_before_get = host_roots(&snapshot(&owner).3);
    assert_eq!(unsafe { lua_getmetatable(state, -1) }, 1);
    assert_eq!(unsafe { lua_rawequal(state, 2, 1) }, 0);
    let roots_after_get = host_roots(&snapshot(&owner).3);
    assert_eq!(roots_after_get.len(), roots_before_get.len() + 1);
    assert_eq!(roots_after_get.last().unwrap().1, mt);
    assert_ne!(roots_after_get.last().unwrap().0, roots_before_get[0].0);

    // 解除 table edge 後，get 所建立的獨立 root 仍保活 metatable。
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 0);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Err(VmError::StaleObject));
        })
        .unwrap();

    let mt2 = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, -2) }, 1);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 1);
    assert_eq!(host_roots(&snapshot(&owner).3).last().unwrap().1, mt2);
    let replacement = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 1);
    assert_eq!(
        host_roots(&snapshot(&owner).3).last().unwrap().1,
        replacement
    );
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt2), Err(VmError::StaleObject));
        })
        .unwrap();

    // target/metatable alias 與自 metatable 均須依呼叫前 top 解讀。
    unsafe { lua_pushvalue(state, 1) };
    assert_eq!(unsafe { lua_setmetatable(state, -1) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(table))
    );
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 1);
    assert_eq!(unsafe { lua_rawequal(state, 1, -1) }, 1);
    unsafe { lua_settop(state, 1) };
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 0);

    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    assert_eq!(unsafe { lua_getmetatable(state, REGISTRY_INDEX) }, 0);
    unsafe { lua_pushvalue(state, REGISTRY_INDEX) };
    assert_eq!(unsafe { lua_setmetatable(state, REGISTRY_INDEX) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(reg)).unwrap(),
        Ok(Some(reg))
    );
    assert_eq!(unsafe { lua_getmetatable(state, REGISTRY_INDEX) }, 1);
    assert_eq!(unsafe { lua_rawequal(state, -1, REGISTRY_INDEX) }, 1);
    unsafe { lua_settop(state, 1) };
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, REGISTRY_INDEX) }, 1);
    assert_eq!(unsafe { lua_getmetatable(state, REGISTRY_INDEX) }, 0);
    assert_eq!(owner.with_vm(|vm| vm.get_metatable(reg)).unwrap(), Ok(None));
}

fn invalid_inputs() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let mut token = 0_u8;
    // SAFETY：字串來源在呼叫期間有效；C 入口立即複製位元組。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 12);
        lua_pushnumber(state, 1.5);
        lua_pushlightuserdata(state, (&mut token as *mut u8).cast::<c_void>());
        lua_pushlstring(state, b"text".as_ptr().cast(), 4);
    }
    let builtin = owner
        .with_vm(|vm| {
            let reg = registry(vm);
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            let value = vm.raw_get(globals, Value::Object(key)).unwrap();
            let Value::Object(object) = value else {
                panic!()
            };
            assert_eq!(vm.object_kind(object), Ok(ObjectKind::Builtin));
            value
        })
        .unwrap();
    owner.push_value(builtin).unwrap();
    let coroutine = owner
        .with_vm(|vm| vm.new_coroutine(builtin).unwrap())
        .unwrap();
    let coroutine_value = owner.with_vm(|vm| coroutine.as_value(vm).unwrap()).unwrap();
    owner.push_value(coroutine_value).unwrap();
    drop(coroutine);
    let top = unsafe { lua_gettop(state) };
    prime_checkpoint(state);
    let before = snapshot(&owner);
    for index in 2..=9 {
        assert_eq!(unsafe { lua_getmetatable(state, index) }, 0, "get {index}");
        assert_unchanged(&owner, state, top, &before);
    }
    for index in [0, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        let before = snapshot(&owner);
        assert!(protected_meta(state, 4, index).0 > 0, "get {index}");
        assert_raised_settles(&owner, state, top, &before);
        let before = snapshot(&owner);
        assert!(protected_meta(state, 5, index).0 > 0, "set {index}");
        assert_raised_settles(&owner, state, top, &before);
    }
    for source in 3..=9 {
        unsafe { lua_pushvalue(state, source) };
        let invalid_top = snapshot(&owner);
        assert!(protected_meta(state, 5, 1).0 > 0, "top {source}");
        assert_raised_settles(&owner, state, top + 1, &invalid_top);
        unsafe { lua_settop(state, top) };
    }
    for target in 2..=9 {
        unsafe { lua_pushvalue(state, 1) };
        assert_eq!(
            unsafe { lua_setmetatable(state, target) },
            1,
            "target {target}"
        );
        assert_eq!(unsafe { lua_getmetatable(state, target) }, 1);
        assert_eq!(unsafe { lua_rawequal(state, -1, 1) }, 1);
        unsafe { lua_settop(state, top) };
        unsafe { lua_pushnil(state) };
        assert_eq!(unsafe { lua_setmetatable(state, target) }, 1);
        assert_eq!(unsafe { lua_getmetatable(state, target) }, 0);
        assert_eq!(unsafe { lua_gettop(state) }, top);
    }
    for target in 2..=9 {
        unsafe { lua_pushnil(state) };
        assert_eq!(
            unsafe { lua_setmetatable(state, target) },
            1,
            "nil to {target}"
        );
        assert_eq!(unsafe { lua_gettop(state) }, top);
    }
    // top 是 coroutine；非 table/nil 時連合法 target 也不可 pop。
    let before = snapshot(&owner);
    assert!(protected_meta(state, 5, 1).0 > 0);
    assert_raised_settles(&owner, state, top, &before);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(mt))
    );
    unsafe { lua_settop(state, 0) };
    let absent = snapshot(&owner);
    assert!(protected_meta(state, 5, REGISTRY_INDEX).0 > 0);
    assert_raised_settles(&owner, state, 0, &absent);
    assert_eq!(protected_meta(std::ptr::null_mut(), 4, 1).0, -1);
    assert_eq!(protected_meta(std::ptr::null_mut(), 5, 1).0, -1);
    owner
        .with_vm(|_| {
            assert_eq!(protected_meta(state, 4, REGISTRY_INDEX).0, -1);
            assert_eq!(protected_meta(state, 5, REGISTRY_INDEX).0, -1);
        })
        .unwrap();
    let pointer = state as usize;
    assert_eq!(
        std::thread::spawn(move || protected_meta(pointer as *mut lua_State, 4, 1).0)
            .join()
            .unwrap(),
        -1
    );
    assert_eq!(
        std::thread::spawn(move || protected_meta(pointer as *mut lua_State, 5, 1).0)
            .join()
            .unwrap(),
        -1
    );
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    assert_eq!(snapshot(&owner).3, absent.3);
}

#[test]
fn metatable_stack_a19_matrix() {
    ordinary_and_lifetime();
    invalid_inputs();
    incremental_and_generational();
    weak_and_finalizer();
    fault_matrix();
}

fn incremental_and_generational() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(table) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
        })
        .unwrap();
    let mt = add_table(&owner);
    let before = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    // C stack slot 的 Host root 先經 mark_gc_object；active GC 中的 mt 因此已是 Gray。
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(mt)).unwrap(),
        Ok(GcColor::Gray)
    );
    assert_eq!(unsafe { lua_setmetatable(state, -2) }, 1);
    let after = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(after.barrier_count, before.barrier_count);
    assert_eq!(after.transition_count, before.transition_count);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
    println!("A19_INCREMENTAL before={before:?} after={after:?}");

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
        })
        .unwrap();
    let mt = add_table(&owner);
    assert_eq!(owner.with_vm(|vm| vm.gc_age(mt)).unwrap(), Ok(GcAge::Young));
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    assert!(protected_meta(state, 5, 1).0 > 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(snapshot(&owner).3, before.3);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(None)
    );
    let failure = owner
        .with_vm(|vm| vm.allocation_trace().last_failure)
        .unwrap()
        .unwrap();
    assert_eq!(failure.kind, AllocationFailureKind::Injection);
    assert_eq!(failure.attempt.point, Some(FailPoint::RememberedReserve));
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(mt))
    );
    let remembered = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(remembered.remembered_len, 1);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
    println!(
        "A19_GENERATIONAL before={:?} remembered={remembered:?}",
        before.2
    );
}

fn weak_and_finalizer() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let mt = add_table(&owner);
    let first = owner
        .with_vm(|vm| {
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode = vm.allocate_byte_string(b"v").unwrap();
            vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode))
                .unwrap();
            let value = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Object(value))
                .unwrap();
            value
        })
        .unwrap();
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
            assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        })
        .unwrap();
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let second = owner
        .with_vm(|vm| {
            let value = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Object(value))
                .unwrap();
            vm.collect().unwrap();
            assert_eq!(
                vm.raw_get(table, Value::Integer(1)),
                Ok(Value::Object(value))
            );
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
            value
        })
        .unwrap();
    assert_ne!(first, second);

    let plain = add_table(&owner);
    let plain_mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, -2) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(plain)).unwrap(),
        Ok(FinalizerState::Unregistered)
    );
    let finalizable = add_table(&owner);
    let gc_mt = add_table(&owner);
    owner.with_vm(|vm| {
        let reg = registry(vm);
        let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else { panic!() };
        vm.install_error_builtins(globals).unwrap();
        let error_key = vm.allocate_byte_string(b"error").unwrap();
        let builtin = vm.raw_get(globals, Value::Object(error_key)).unwrap();
        let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
        assert!(matches!(builtin, Value::Object(object) if vm.object_kind(object) == Ok(ObjectKind::Builtin)));
        vm.raw_set(gc_mt, Value::Object(gc_key), builtin).unwrap();
    }).unwrap();
    assert_eq!(unsafe { lua_setmetatable(state, -2) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(finalizable)).unwrap(),
        Ok(FinalizerState::Registered)
    );
    // 不觸發 callback；這裡只驗證註冊狀態與 C 設定入口。
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(plain)).unwrap(),
        Ok(Some(plain_mt))
    );
}

fn fault_matrix() {
    let preflight = StateOwner::new().unwrap();
    let preflight_state = preflight.as_ptr();
    let _table = add_table(&preflight);
    let _mt = add_table(&preflight);
    assert_eq!(unsafe { lua_setmetatable(preflight_state, 1) }, 1);
    unsafe { lua_settop(preflight_state, 20) };
    let before_preflight = snapshot(&preflight);
    preflight
        .with_vm(|vm| vm.inject_allocation_failure_at(before_preflight.1.next_ordinal))
        .unwrap();
    assert_eq!(protected_meta(preflight_state, -1, 0).0, -1);
    assert_unchanged(&preflight, preflight_state, 20, &before_preflight);
    let preflight_failure = snapshot(&preflight).1.last_failure.unwrap();
    assert_eq!(preflight_failure.kind, AllocationFailureKind::Injection);
    assert_eq!(
        preflight_failure.attempt.ordinal,
        before_preflight.1.next_ordinal
    );
    assert_eq!(protected_meta(preflight_state, -1, 0).0, 0);
    let prepared = snapshot(&preflight);
    assert_eq!(
        prepared.0.host_allocation_bytes - before_preflight.0.host_allocation_bytes,
        2880
    );
    assert_eq!(protected_meta(preflight_state, -1, 0).0, 0);
    assert_eq!(snapshot(&preflight).0, prepared.0);
    let probe = preflight.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(preflight);
    assert_eq!(probe.snapshot().committed, 0);

    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..8 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let table = add_table(&owner);
        let mt = add_table(&owner);
        assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
        // checkpoint 先預留第 21 格，API 故障矩陣只涵蓋 getter 自身。
        unsafe { lua_settop(state, 20) };
        prime_checkpoint(state);
        let before = snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| {
                let at = vm.allocation_trace().next_ordinal + offset;
                vm.inject_allocation_failure_at(at);
                at
            })
            .unwrap();
        let (status, result) = protected_meta(state, 4, 1);
        let after = snapshot(&owner);
        if status > 0 {
            assert_unchanged(&owner, state, 20, &before);
            assert_eq!(
                owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
                Ok(Some(mt))
            );
            let failure = after.1.last_failure.unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, ordinal);
            assert_eq!(failure.attempt.domain, AllocationDomain::Host);
            failures.push((
                offset,
                failure.attempt.point,
                failure.attempt.site.file,
                failure.attempt.site.line,
            ));
        } else {
            assert_eq!(status, 0);
            assert_eq!(result, 1);
            assert_eq!(unsafe { lua_gettop(state) }, 21);
            assert_eq!(host_roots(&after.3).len(), host_roots(&before.3).len() + 1);
            assert_eq!(host_roots(&after.3).last().unwrap().1, mt);
            assert_eq!(after.2, before.2);
            assert_eq!(after.1.next_ordinal - before.1.next_ordinal, 1);
            successes.push(offset);
        }
    }
    assert_eq!(failures.len(), 1);
    assert_eq!(successes, (1..8).collect::<Vec<_>>());
    assert_eq!(failures[0].1, None);
    assert_eq!(failures[0].2, "crates/rivetlua-runtime/src/roots.rs");
    assert!(failures.iter().all(|entry| entry.3 > 0));
    println!("A19_GET_FAULT failures={failures:?} successes={successes:?}");

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let ordinal = owner
        .with_vm(|vm| {
            let at = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(at);
            at
        })
        .unwrap();
    let before = snapshot(&owner);
    assert_eq!(unsafe { lua_getmetatable(state, 1) }, 0);
    assert_eq!(snapshot(&owner), before);
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
        .unwrap();
    let _mt = add_table(&owner);
    // 建 table 會消耗配置，因此重新注入目前 next ordinal。
    let next = owner
        .with_vm(|vm| {
            let at = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(at);
            at
        })
        .unwrap();
    let before_set = snapshot(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let after_set = snapshot(&owner);
    assert_eq!(after_set.1.next_ordinal, next);
    assert_eq!(after_set.1.last_failure, before_set.1.last_failure);
    assert!(
        owner
            .with_vm(|vm| vm.get_metatable(table))
            .unwrap()
            .unwrap()
            .is_some()
    );
    println!("A19_NO_ALLOC get_none_next={ordinal} set_next={next}");
}
