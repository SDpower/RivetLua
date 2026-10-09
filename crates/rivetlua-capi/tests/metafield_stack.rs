use std::ffi::{CString, c_char, c_int, c_void};

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

fn protected_metafield(state: *mut lua_State, index: c_int, name: *const c_char) -> c_int {
    // SAFETY：呼叫者持有存活 state，或刻意測試 null／錯誤執行緒拒絕；C frame 捕捉 Lua 錯誤。
    unsafe {
        rivetlua_capi_test_protected_index_a4b(state, 3, index, 0, name, std::ptr::null_mut())
    }
}

fn protected_metafield_answer(
    state: *mut lua_State,
    index: c_int,
    name: *const c_char,
) -> (c_int, c_int) {
    let mut answer = 0;
    let status =
        unsafe { rivetlua_capi_test_protected_index_a4b(state, 3, index, 0, name, &mut answer) };
    (status, answer)
}

fn prime_metafield_checkpoint(state: *mut lua_State) -> c_int {
    unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            -1,
            0,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    }
}

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_pushvalue,
    lua_rawequal, lua_setmetatable, lua_settop, lua_tointegerx, lua_tonumberx, lua_topointer,
    lua_touserdata, lua_type, luaL_getmetafield,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, FailPoint, GcAge, GcColor, GcMode,
    GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind, Vm, VmError,
};

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

fn host_roots(roots: &Roots) -> Vec<(RootId, ObjectRef)> {
    roots
        .iter()
        .filter_map(|(kind, id, object)| (*kind == RootKind::Host).then_some((*id, *object)))
        .collect()
}

fn only_added_host(before: &Roots, after: &Roots) -> ObjectRef {
    let previous = host_roots(before);
    let added: Vec<_> = host_roots(after)
        .into_iter()
        .filter(|(id, _)| !previous.iter().any(|(old, _)| old == id))
        .collect();
    assert_eq!(added.len(), 1);
    added[0].1
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).3;
    // SAFETY：owner 在呼叫期間持有有效 state。
    unsafe { lua_createtable(owner.as_ptr(), 0, 0) };
    only_added_host(&before, &snapshot(owner).3)
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

fn set_field(owner: &StateOwner, metatable: ObjectRef, name: &[u8], value: Value) {
    owner
        .with_vm(|vm| {
            let key = vm.allocate_byte_string(name).unwrap();
            vm.raw_set(metatable, Value::Object(key), value).unwrap();
        })
        .unwrap();
}

fn assert_no_change(owner: &StateOwner, state: *mut lua_State, top: i32, before: &Snapshot) {
    // SAFETY：只讀取有效 owner 的 stack top。
    assert_eq!(unsafe { lua_gettop(state) }, top);
    let after = snapshot(owner);
    assert_eq!(after.0, before.0, "帳款不得半更新");
    assert_eq!(after.2, before.2, "GC 不得半轉移");
    assert_eq!(after.3, before.3, "root 不得半發布");
}

fn stack_digest(state: *mut lua_State) -> Vec<(i32, i64, u64, usize)> {
    let top = unsafe { lua_gettop(state) };
    (1..=top)
        .map(|index| unsafe {
            (
                lua_type(state, index),
                lua_tointegerx(state, index, std::ptr::null_mut()),
                lua_tonumberx(state, index, std::ptr::null_mut()).to_bits(),
                lua_topointer(state, index) as usize,
            )
        })
        .collect()
}

fn assert_raised_error_settles(
    owner: &StateOwner,
    state: *mut lua_State,
    before: &Snapshot,
    stack: &[(i32, i64, u64, usize)],
) {
    assert_eq!(stack_digest(state), stack, "錯誤不得修改 caller stack 內容");
    let transient = snapshot(owner);
    assert_eq!(transient.3, before.3, "錯誤傳輸不得殘留 root");
    assert!(transient.0.lua_heap_bytes >= before.0.lua_heap_bytes);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    let settled = snapshot(owner);
    assert_eq!(settled.0, before.0, "錯誤字串回收後帳本須回復");
    assert_eq!(settled.3, before.3, "錯誤傳輸後 root 須回復");
    assert_eq!(settled.2.phase, GcPhase::Pause);
    assert_eq!(settled.2.worklist_len, 0);
    assert_eq!(stack_digest(state), stack);
}

fn ordinary_lookup_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let event = CString::new("__a20").unwrap();
    let table = add_table(&owner);
    let before = snapshot(&owner);
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 0);
    assert_eq!(snapshot(&owner), before);

    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let before = snapshot(&owner);
    assert_eq!(unsafe { luaL_getmetafield(state, -1, event.as_ptr()) }, 0);
    assert_no_change(&owner, state, 1, &before);

    set_field(&owner, mt, b"__a20", Value::Integer(42));
    assert_eq!(unsafe { luaL_getmetafield(state, -1, event.as_ptr()) }, 3);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        42
    );
    unsafe { lua_settop(state, 1) };

    set_field(&owner, mt, b"__a20", Value::Boolean(false));
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 1);
    assert_eq!(unsafe { lua_type(state, -1) }, 1);
    unsafe { lua_settop(state, 1) };

    set_field(&owner, mt, b"__a20", Value::Float(2.25));
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 3);
    assert_eq!(
        unsafe { lua_tonumberx(state, -1, std::ptr::null_mut()) },
        2.25
    );
    unsafe { lua_settop(state, 1) };
    let mut token = 0_u8;
    let address = (&mut token as *mut u8) as usize;
    set_field(&owner, mt, b"__a20", Value::LightUserdata(address));
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 2);
    assert_eq!(unsafe { lua_touserdata(state, -1) } as usize, address);
    unsafe { lua_settop(state, 1) };

    let string = owner
        .with_vm(|vm| vm.allocate_byte_string(b"answer").unwrap())
        .unwrap();
    set_field(&owner, mt, b"__a20", Value::Object(string));
    let roots_before = snapshot(&owner).3;
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 4);
    assert_eq!(only_added_host(&roots_before, &snapshot(&owner).3), string);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(string), Ok(ObjectKind::ByteString));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };

    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, mt, b"__a20", Value::Object(value));
    let roots_before = snapshot(&owner).3;
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 5);
    assert_eq!(only_added_host(&roots_before, &snapshot(&owner).3), value);
    assert_eq!(unsafe { lua_rawequal(state, 1, 2) }, 0);
    set_field(&owner, mt, b"__a20", Value::Nil);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        })
        .unwrap();
    let before = snapshot(&owner);
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 0);
    assert_no_change(&owner, state, 1, &before);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(mt))
    );

    // 名稱是 C 字串：首個 NUL 前的位元組構成 key；空名稱也是有效 key。
    let embedded = b"__a20\0ignored\0";
    set_field(&owner, mt, b"", Value::Integer(7));
    assert_eq!(
        unsafe { luaL_getmetafield(state, 1, embedded.as_ptr().cast()) },
        0
    );
    assert_eq!(unsafe { luaL_getmetafield(state, 1, c"".as_ptr()) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        7
    );
    unsafe { lua_settop(state, 1) };
    set_field(&owner, mt, b"__a20", Value::Integer(8));
    assert_eq!(
        unsafe { luaL_getmetafield(state, 1, embedded.as_ptr().cast()) },
        3
    );
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        8
    );
    unsafe { lua_settop(state, 1) };

    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let builtin = owner
        .with_vm(|vm| {
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(globals, Value::Object(key)).unwrap()
        })
        .unwrap();
    let Value::Object(builtin_object) = builtin else {
        panic!()
    };
    set_field(&owner, mt, b"__a20", builtin);
    let roots_before = snapshot(&owner).3;
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 6);
    assert_eq!(
        only_added_host(&roots_before, &snapshot(&owner).3),
        builtin_object
    );
    unsafe { lua_settop(state, 1) };

    let coroutine = owner
        .with_vm(|vm| vm.new_coroutine(builtin).unwrap())
        .unwrap();
    let thread_value = owner.with_vm(|vm| coroutine.as_value(vm).unwrap()).unwrap();
    let Value::Object(thread_object) = thread_value else {
        panic!()
    };
    set_field(&owner, mt, b"__a20", thread_value);
    drop(coroutine);
    let roots_before = snapshot(&owner).3;
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 8);
    assert_eq!(
        only_added_host(&roots_before, &snapshot(&owner).3),
        thread_object
    );
    unsafe { lua_settop(state, 1) };

    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let no_mt = snapshot(&owner);
    assert_eq!(unsafe { luaL_getmetafield(state, 1, event.as_ptr()) }, 0);
    assert_eq!(snapshot(&owner), no_mt);
}

fn registry_and_invalid_inputs() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let event = c"__a20";
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    unsafe { lua_pushvalue(state, REGISTRY_INDEX) };
    assert_eq!(unsafe { lua_setmetatable(state, REGISTRY_INDEX) }, 1);
    set_field(&owner, reg, b"__a20", Value::Integer(99));
    assert_eq!(
        unsafe { luaL_getmetafield(state, REGISTRY_INDEX, event.as_ptr()) },
        3
    );
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        99
    );
    unsafe { lua_settop(state, 0) };

    let table = add_table(&owner);
    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    set_field(&owner, mt, b"__a20", Value::Integer(11));
    let mut token = 0_u8;
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
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(globals, Value::Object(key)).unwrap()
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
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    let before = snapshot(&owner);
    for index in [2, 3, 4, 5, 6, 7, 8, 9] {
        assert_eq!(
            unsafe { luaL_getmetafield(state, index, event.as_ptr()) },
            0,
            "index {index}"
        );
        assert_no_change(&owner, state, top, &before);
    }
    let stack = stack_digest(state);
    for index in [0, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert!(
            protected_metafield(state, index, event.as_ptr()) > 0,
            "index {index}"
        );
        assert_raised_error_settles(&owner, state, &before, &stack);
    }
    assert!(protected_metafield(state, 1, std::ptr::null()) > 0);
    assert_raised_error_settles(&owner, state, &before, &stack);
    assert_eq!(
        protected_metafield(std::ptr::null_mut(), 1, event.as_ptr()),
        -1
    );
    owner
        .with_vm(|_| {
            assert_eq!(protected_metafield(state, 1, event.as_ptr()), -1);
        })
        .unwrap();
    let pointer = state as usize;
    let event_pointer = event.as_ptr() as usize;
    assert_eq!(
        std::thread::spawn(move || {
            protected_metafield(pointer as *mut lua_State, 1, event_pointer as *const i8)
        })
        .join()
        .unwrap(),
        -1
    );
    assert_eq!(stack_digest(state), stack);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(Some(mt))
    );
}

fn result_survives_metatable_edge_removal() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, mt, b"__a20", Value::Object(result));
    assert_eq!(
        unsafe { luaL_getmetafield(state, -1, c"__a20".as_ptr()) },
        5
    );
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    // 結果已有獨立 Host root；移除 table→metatable 邊仍應存活。
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
        Ok(None)
    );
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn active_gc_and_weak_value() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
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
    set_field(&owner, mt, b"__a20", Value::Integer(5));
    let before = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(unsafe { luaL_getmetafield(state, 1, c"__a20".as_ptr()) }, 3);
    let after = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(after.phase, before.phase);
    assert_eq!(after.transition_count, before.transition_count);
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
        })
        .unwrap();
    let young = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, mt, b"__a20", Value::Object(young));
    assert_eq!(unsafe { luaL_getmetafield(state, 1, c"__a20".as_ptr()) }, 5);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(young), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };

    let weak_mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let weak_mode = owner
        .with_vm(|vm| vm.allocate_byte_string(b"v").unwrap())
        .unwrap();
    set_field(&owner, weak_mt, b"__mode", Value::Object(weak_mode));
    assert_eq!(
        owner
            .with_vm(|vm| vm.set_metatable(mt, Some(weak_mt)))
            .unwrap(),
        Ok(())
    );
    owner
        .with_vm(|vm| {
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();
    let weak_value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, mt, b"__a20", Value::Object(weak_value));
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(weak_value)).unwrap(),
        Ok(GcColor::White)
    );
    let roots_before = snapshot(&owner).3;
    assert_eq!(unsafe { luaL_getmetafield(state, 1, c"__a20".as_ptr()) }, 5);
    assert_eq!(
        only_added_host(&roots_before, &snapshot(&owner).3),
        weak_value
    );
    assert_ne!(
        owner.with_vm(|vm| vm.gc_color(weak_value)).unwrap(),
        Ok(GcColor::White)
    );
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(weak_value), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(weak_value), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn allocation_failure_matrix() {
    // 首次 checkpoint 為 top+1 預留錯誤槽；其失敗仍須保持完整原子性。
    let preflight = StateOwner::new().unwrap();
    let preflight_state = preflight.as_ptr();
    let _preflight_table = add_table(&preflight);
    let _preflight_mt = add_table(&preflight);
    assert_eq!(unsafe { lua_setmetatable(preflight_state, 1) }, 1);
    unsafe { lua_settop(preflight_state, 20) };
    let before_preflight = snapshot(&preflight);
    preflight
        .with_vm(|vm| vm.inject_allocation_failure_at(before_preflight.1.next_ordinal))
        .unwrap();
    assert_eq!(prime_metafield_checkpoint(preflight_state), -1);
    assert_no_change(&preflight, preflight_state, 20, &before_preflight);
    let failed_preflight = snapshot(&preflight).1.last_failure.unwrap();
    assert_eq!(failed_preflight.kind, AllocationFailureKind::Injection);
    assert_eq!(
        failed_preflight.attempt.ordinal,
        before_preflight.1.next_ordinal
    );
    let probe = preflight.with_vm(|vm| vm.ledger_probe()).unwrap();
    assert_eq!(prime_metafield_checkpoint(preflight_state), 0);
    let prepared = snapshot(&preflight);
    assert_eq!(
        prepared.0.host_allocation_bytes - before_preflight.0.host_allocation_bytes,
        2880
    );
    assert_eq!(prime_metafield_checkpoint(preflight_state), 0);
    assert_eq!(snapshot(&preflight).0, prepared.0, "錯誤槽容量只預留一次");
    drop(preflight);
    assert_eq!(probe.snapshot().committed, 0);

    let mut failed = Vec::new();
    let mut succeeded = Vec::new();
    for offset in 0..24 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let table = add_table(&owner);
        let mt = add_table(&owner);
        assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        set_field(&owner, mt, b"__a20", Value::Object(value));
        // 第 21 格先由 checkpoint 預留 error/result 共用的 stack capacity。
        unsafe { lua_settop(state, 20) };
        assert_eq!(prime_metafield_checkpoint(state), 0);
        let before = snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| {
                let at = vm.allocation_trace().next_ordinal + offset;
                vm.inject_allocation_failure_at(at);
                at
            })
            .unwrap();
        let (status, result) = protected_metafield_answer(state, 1, c"__a20".as_ptr());
        let after = snapshot(&owner);
        if status != 0 {
            assert_no_change(&owner, state, 20, &before);
            let failure = after.1.last_failure.unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, ordinal);
            assert_eq!(
                owner.with_vm(|vm| vm.get_metatable(table)).unwrap(),
                Ok(Some(mt))
            );
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
                Ok(ObjectKind::Table)
            );
            failed.push((
                offset,
                failure.attempt.domain,
                failure.attempt.point,
                failure.attempt.site.file,
                failure.attempt.bytes,
            ));
            let (retry_status, retry_result) =
                protected_metafield_answer(state, 1, c"__a20".as_ptr());
            assert_eq!(retry_status, 0);
            assert_eq!(retry_result, 5);
            assert_eq!(unsafe { lua_gettop(state) }, 21);
        } else {
            assert_eq!(result, 5);
            assert_eq!(unsafe { lua_gettop(state) }, 21);
            assert_eq!(only_added_host(&before.3, &after.3), value);
            assert_eq!(
                after
                    .3
                    .iter()
                    .filter(|(kind, _, _)| *kind == RootKind::Temporary)
                    .count(),
                before
                    .3
                    .iter()
                    .filter(|(kind, _, _)| *kind == RootKind::Temporary)
                    .count()
            );
            assert_eq!(after.2, before.2);
            succeeded.push(offset);
        }
    }
    assert_eq!(
        failed.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (0..5).collect::<Vec<_>>()
    );
    assert_eq!(succeeded, (5..24).collect::<Vec<_>>());
    let expected = [
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::StringBytesReserve),
            "crates/rivetlua-runtime/src/string.rs",
            5,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            "crates/rivetlua-runtime/src/heap.rs",
            136,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            "crates/rivetlua-runtime/src/heap.rs",
            312,
        ),
        (
            AllocationDomain::Host,
            None,
            "crates/rivetlua-runtime/src/roots.rs",
            120,
        ),
        (
            AllocationDomain::Host,
            None,
            "crates/rivetlua-runtime/src/roots.rs",
            208,
        ),
    ];
    for (offset, actual) in failed.iter().enumerate() {
        assert_eq!(
            *actual,
            (
                offset as u64,
                expected[offset].0,
                expected[offset].1,
                expected[offset].2,
                expected[offset].3
            )
        );
    }
    assert!(
        failed
            .iter()
            .any(|entry| entry.1 == AllocationDomain::LuaHeap)
    );
    assert!(failed.iter().any(|entry| entry.1 == AllocationDomain::Host));
    assert!(
        failed
            .iter()
            .any(|entry| entry.3 == "crates/rivetlua-runtime/src/roots.rs")
    );
    // B14 的 5-byte inline short key 省去一次 canonical key bytes 複製。

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let _table = add_table(&owner);
    let mt = add_table(&owner);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    unsafe { lua_settop(state, 20) };
    let before = snapshot(&owner);
    let next = before.1.next_ordinal;
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(next + 4))
        .unwrap();
    assert_eq!(
        unsafe { luaL_getmetafield(state, 1, c"absent".as_ptr()) },
        0
    );
    assert_no_change(&owner, state, 20, &before);
    let after = snapshot(&owner);
    assert_eq!(after.1.next_ordinal, next + 4);
    assert_eq!(after.1.last_failure, before.1.last_failure);
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
        .unwrap();
    set_field(&owner, mt, b"absent", Value::Nil);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(before.1.next_ordinal + 4))
        .unwrap();
    assert_eq!(
        unsafe { luaL_getmetafield(state, 1, c"absent".as_ptr()) },
        0
    );
    assert_no_change(&owner, state, 20, &before);
    let after = snapshot(&owner);
    assert_eq!(after.1.next_ordinal, before.1.next_ordinal + 4);
    assert_eq!(after.1.last_failure, before.1.last_failure);
}

#[test]
fn metafield_stack_a20_matrix() {
    ordinary_lookup_and_lifetime();
    registry_and_invalid_inputs();
    result_survives_metatable_edge_removal();
    active_gc_and_weak_value();
    allocation_failure_matrix();
}
