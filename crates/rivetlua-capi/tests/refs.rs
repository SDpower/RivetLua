use std::ffi::{c_char, c_int};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushboolean, lua_pushinteger,
    lua_pushnil, lua_rawgeti, lua_rawseti, lua_settop, lua_tointegerx, lua_type, luaL_ref,
    luaL_unref,
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

fn protected_ref(state: *mut lua_State, index: c_int) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：純 C checkpoint 捕捉 Lua error，並於返回前消費 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(state, 9, index, 0, std::ptr::null(), &mut answer)
    };
    (status, answer)
}

fn protected_unref(state: *mut lua_State, index: c_int, reference: c_int) -> c_int {
    unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            10,
            index,
            reference,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    }
}

fn prime_checkpoint(state: *mut lua_State) {
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            -1,
            0,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, 0);
}
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, FailPoint, GcAge, GcColor, GcMode, GcPhase,
    HostHandle, ObjectKind, RootKind, VmError,
};

#[cfg(feature = "lua55")]
const FIRST: i32 = 2;
#[cfg(feature = "lua54")]
const FIRST: i32 = 1;
#[cfg(feature = "lua55")]
const REGISTRY: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const HEADER: i64 = 1;
#[cfg(feature = "lua54")]
const HEADER: i64 = 3;

fn table(owner: &StateOwner) -> ObjectRef {
    let mut found = Vec::new();
    owner
        .with_vm(|vm| {
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    found.push(object);
                }
            })
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    found[0]
}

fn field(owner: &StateOwner, table: ObjectRef, key: i64) -> Value {
    owner
        .with_vm(|vm| vm.raw_get(table, Value::Integer(key)).unwrap())
        .unwrap()
}

fn sequence() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保持 state 存活，index 指向 table 或 registry。
    unsafe {
        lua_createtable(state, 0, 0);
        let table = table(&owner);
        lua_pushnil(state);
        assert_eq!(luaL_ref(state, -2), -1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(field(&owner, table, HEADER), Value::Nil);
        lua_pushinteger(state, 71);
        let first = luaL_ref(state, -2);
        assert_eq!(first, FIRST);
        assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
        lua_pushinteger(state, 72);
        let second = luaL_ref(state, 1);
        assert_eq!(second, first + 1);
        assert_eq!(lua_rawgeti(state, 1, i64::from(second)), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 72);
        lua_settop(state, 1);
        luaL_unref(state, 1, first);
        assert_eq!(
            field(&owner, table, HEADER),
            Value::Integer(i64::from(first))
        );
        assert_eq!(field(&owner, table, i64::from(first)), Value::Integer(0));
        luaL_unref(state, -1, second);
        assert_eq!(
            field(&owner, table, HEADER),
            Value::Integer(i64::from(second))
        );
        assert_eq!(
            field(&owner, table, i64::from(second)),
            Value::Integer(i64::from(first))
        );
        lua_pushinteger(state, 73);
        assert_eq!(luaL_ref(state, 1), second);
        lua_pushinteger(state, 74);
        assert_eq!(luaL_ref(state, 1), first);
        assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
        assert_eq!(lua_gettop(state), 1);

        // registry 從 4 開始配置；5.5 key3 為 main thread，5.4 起初缺席。
        assert_eq!(
            lua_rawgeti(state, REGISTRY, 3),
            if cfg!(feature = "lua55") { 8 } else { 0 }
        );
        lua_settop(state, 1);
        assert_eq!(lua_rawgeti(state, REGISTRY, 2), 5);
        lua_settop(state, 1);
        lua_pushinteger(state, 101);
        assert_eq!(luaL_ref(state, REGISTRY), 4);
        lua_pushinteger(state, 102);
        assert_eq!(luaL_ref(state, REGISTRY), 5);
        assert_eq!(
            lua_rawgeti(state, REGISTRY, 3),
            if cfg!(feature = "lua55") { 8 } else { 3 }
        );
        if cfg!(feature = "lua54") {
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 0);
        }
        lua_settop(state, 1);
        luaL_unref(state, REGISTRY, 4);
        lua_pushinteger(state, 103);
        assert_eq!(luaL_ref(state, REGISTRY), 4);
    }
    let occupied = StateOwner::new().unwrap();
    let state = occupied.as_ptr();
    // SAFETY：以公開 raw API 預占 key4，確認新 ref 避開它。
    unsafe {
        lua_pushinteger(state, 444);
        lua_rawseti(state, REGISTRY, 4);
        lua_pushinteger(state, 555);
        assert_eq!(luaL_ref(state, REGISTRY), 5);
        assert_eq!(lua_rawgeti(state, REGISTRY, 4), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 444);
    }
}

fn invalid() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：無效 index／NULL 只應 fail-closed，owner 保持其餘 state 有效。
    unsafe {
        lua_createtable(state, 0, 0);
        let table = table(&owner);
        lua_pushinteger(state, 9);
        prime_checkpoint(state);
        assert!(protected_ref(state, 0).0 > 0);
        assert!(protected_ref(state, REGISTRY - 1).0 > 0);
        assert_eq!(protected_ref(std::ptr::null_mut(), 1).0, -1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(field(&owner, table, HEADER), Value::Nil);
        assert_eq!(luaL_ref(state, 1), FIRST);
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        luaL_unref(state, 1, -2);
        luaL_unref(state, 1, -1);
        assert_eq!(protected_unref(std::ptr::null_mut(), 1, -1), -1);
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);
        assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
        // 非負但 nil slot 為 P16 安全限制；負 ref 則是官方 no-op。
        assert!(protected_unref(state, 1, FIRST + 20) > 0);
        assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
        assert!(protected_unref(state, 1, 0) > 0);
        assert!(protected_unref(state, 1, HEADER as i32) > 0);
        assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
        luaL_unref(state, 1, FIRST);
        let freed = field(&owner, table, HEADER);
        assert!(protected_unref(state, 1, FIRST) > 0);
        assert_eq!(field(&owner, table, HEADER), freed);
        lua_pushinteger(state, 33);
        assert_eq!(owner.with_vm(|_| protected_ref(state, 1).0).unwrap(), -1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(luaL_ref(state, 1), FIRST);
        lua_settop(state, 0);
        lua_pushinteger(state, 1);
        lua_pushinteger(state, 2);
        assert!(protected_ref(state, 1).0 > 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), 3);
    }

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：預置 false header；5.5 當初始狀態處理，5.4 拒絕畸形 header。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushboolean(state, 0);
        lua_rawseti(state, 1, HEADER);
        lua_pushinteger(state, 10);
        let (status, answer) = protected_ref(state, 1);
        if cfg!(feature = "lua55") {
            assert_eq!((status, answer), (0, FIRST));
        } else {
            assert!(status > 0);
        }
        assert_eq!(
            lua_gettop(state),
            if cfg!(feature = "lua55") { 1 } else { 2 }
        );
    }

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：故意造出自迴圈的自由串列；ref 應 fail-closed 並保留 value。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 11);
        let reference = luaL_ref(state, 1);
        luaL_unref(state, 1, reference);
        lua_pushinteger(state, i64::from(reference));
        lua_rawseti(state, 1, i64::from(reference));
        lua_pushinteger(state, 12);
        assert!(protected_ref(state, 1).0 > 0);
        assert_eq!(lua_gettop(state), 2);
    }
}

fn lifetime() {
    for string in [false, true] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：state 存活，第一個 slot 為 table。
        unsafe { lua_createtable(state, 0, 0) };
        let table = table(&owner);
        let object = owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_promotion_survivals(1).unwrap();
                vm.collect().unwrap();
                if string {
                    vm.allocate_byte_string(b"held-by-ref").unwrap()
                } else {
                    vm.allocate_table().unwrap()
                }
            })
            .unwrap();
        owner.push_value(Value::Object(object)).unwrap();
        let reference = unsafe { luaL_ref(state, 1) };
        assert_eq!(reference, FIRST);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        owner.with_vm(|vm| vm.collect_minor().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Ok(if string {
                ObjectKind::ByteString
            } else {
                ObjectKind::Table
            })
        );
        assert_eq!(
            field(&owner, table, i64::from(reference)),
            Value::Object(object)
        );
        // SAFETY：有效 ref；unref 不改動 stack。
        unsafe { luaL_unref(state, 1, reference) };
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Err(VmError::StaleObject)
        );
    }
}

fn function_or_coroutine(owner: &StateOwner, coroutine: bool) -> HostHandle<Value> {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            let mut roots = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    roots.push(object);
                }
            });
            assert_eq!(roots.len(), 1);
            let Value::Object(globals) = vm.raw_get(roots[0], Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須為 table");
            };
            vm.install_basic_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"type").unwrap();
            let function = vm.raw_get(globals, Value::Object(key)).unwrap();
            let Value::Object(function_object) = function else {
                panic!("type 必須為 function");
            };
            let function_handle = HostHandle::<Value>::new(vm, function_object).unwrap();
            let result = if coroutine {
                vm.new_coroutine(function).unwrap()
            } else {
                function_handle
            };
            vm.raw_set(globals, Value::Object(key), Value::Nil).unwrap();
            result
        })
        .unwrap()
}

fn function_thread_lifetime() {
    for coroutine in [false, true] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：state 存活，第一個 slot 為 table。
        unsafe { lua_createtable(state, 0, 0) };
        let handle = function_or_coroutine(&owner, coroutine);
        let value = owner.with_vm(|vm| handle.as_value(vm).unwrap()).unwrap();
        let Value::Object(object) = value else {
            panic!("handle 必須指向物件");
        };
        owner.push_value(value).unwrap();
        drop(handle);
        let reference = unsafe { luaL_ref(state, 1) };
        assert_eq!(reference, FIRST);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Ok(if coroutine {
                ObjectKind::Coroutine
            } else {
                ObjectKind::Builtin
            })
        );
        // SAFETY：unref 移除 table 強邊；之後物件可回收。
        unsafe { luaL_unref(state, 1, reference) };
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Err(VmError::StaleObject)
        );
    }
}

fn active_gc_and_reuse() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：先建 ref 並 unref，讓後續 object ref 走自由串列重用。
        unsafe {
            lua_createtable(state, 0, 0);
            lua_pushinteger(state, 3);
            assert_eq!(luaL_ref(state, 1), FIRST);
            luaL_unref(state, 1, FIRST);
        }
        let table = table(&owner);
        owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_mode(mode).unwrap();
                vm.set_gc_promotion_survivals(1).unwrap();
                vm.collect().unwrap();
                if mode == GcMode::Generational {
                    assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
                }
                for _ in 0..256 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause
                        && vm.gc_color(table) == Ok(GcColor::Black)
                    {
                        break;
                    }
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
            })
            .unwrap();
        let object = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.gc_color(object)).unwrap(),
            Ok(GcColor::White)
        );
        owner.push_value(Value::Object(object)).unwrap();
        prime_checkpoint(state);
        let before = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                )
            })
            .unwrap();
        if mode == GcMode::Generational {
            owner
                .with_vm(|vm| {
                    vm.inject_failure_once(rivetlua_runtime::FailPoint::RememberedReserve)
                })
                .unwrap();
            assert!(protected_ref(state, 1).0 > 0);
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            assert_eq!(
                field(&owner, table, HEADER),
                Value::Integer(i64::from(FIRST))
            );
            assert_eq!(field(&owner, table, i64::from(FIRST)), Value::Integer(0));
            assert_eq!(
                owner
                    .with_vm(|vm| (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().total_count()
                    ))
                    .unwrap(),
                before
            );
        }
        assert_eq!(unsafe { luaL_ref(state, 1) }, FIRST);
        assert_ne!(
            owner.with_vm(|vm| vm.gc_color(object)).unwrap(),
            Ok(GcColor::White)
        );
        if mode == GcMode::Generational {
            assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
        }
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Ok(ObjectKind::Table)
        );
        // SAFETY：reference 有效；移除後不再有 table 到 object 的強邊。
        unsafe { luaL_unref(state, 1, FIRST) };
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
            Err(VmError::StaleObject)
        );
    }
}

fn faults() {
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..12 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：table/value 均在有效 stack；失敗須保留兩格。
        unsafe {
            lua_createtable(state, 0, 0);
            lua_pushinteger(state, 87);
        }
        prime_checkpoint(state);
        let table = table(&owner);
        let before = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                )
            })
            .unwrap();
        let next = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
            .unwrap();
        let (status, result) = protected_ref(state, 1);
        if status > 0 {
            assert_eq!(unsafe { lua_gettop(state) }, 2, "offset {offset}");
            assert_eq!(field(&owner, table, HEADER), Value::Nil);
            assert_eq!(field(&owner, table, i64::from(FIRST)), Value::Nil);
            assert_eq!(
                owner
                    .with_vm(|vm| (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().total_count()
                    ))
                    .unwrap(),
                before
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, next + offset);
            assert!(
                failure.attempt.site.file.ends_with("table.rs")
                    || failure.attempt.site.file.ends_with("heap.rs")
            );
            failures.push((offset, failure.attempt.domain, failure.attempt.point));
        } else {
            assert_eq!(status, 0);
            assert_eq!(result, FIRST);
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
            assert_eq!(field(&owner, table, i64::from(result)), Value::Integer(87));
            successes.push(offset);
        }
    }
    assert_eq!(
        failures,
        vec![(
            0,
            AllocationDomain::LuaHeap,
            Some(FailPoint::TableArrayGrow)
        )]
    );
    assert_eq!(successes, (1..12).collect::<Vec<_>>());
}

fn boundary_and_unref_faults() {
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..8 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：三個已配置 ref 使下一個 ref=5 跨 array 容量邊界。
        unsafe {
            lua_createtable(state, 0, 0);
            for value in 0..3 {
                lua_pushinteger(state, value);
                assert!(luaL_ref(state, 1) > 0);
            }
            lua_pushinteger(state, 99);
        }
        prime_checkpoint(state);
        let table = table(&owner);
        assert_eq!(field(&owner, table, 5), Value::Nil);
        let before = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                )
            })
            .unwrap();
        let next = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
            .unwrap();
        let (status, result) = protected_ref(state, 1);
        if status > 0 {
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            assert_eq!(field(&owner, table, HEADER), Value::Integer(0));
            assert_eq!(field(&owner, table, 5), Value::Nil);
            assert_eq!(
                owner
                    .with_vm(|vm| (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().total_count()
                    ))
                    .unwrap(),
                before
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, next + offset);
            failures.push((offset, failure.attempt.domain, failure.attempt.point));
        } else {
            assert_eq!(status, 0);
            assert_eq!(result, 5);
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            assert_eq!(field(&owner, table, 5), Value::Integer(99));
            successes.push(offset);
        }
    }
    assert_eq!(
        failures,
        vec![(
            0,
            AllocationDomain::LuaHeap,
            Some(FailPoint::TableArrayGrow)
        )]
    );
    assert_eq!(successes, (1..8).collect::<Vec<_>>());

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：指定 checkpoint 故障須保留 table 與 stack；既存欄位 unref 不配置。
    unsafe {
        lua_createtable(state, 0, 0);
        let table = table(&owner);
        lua_pushinteger(state, 44);
        prime_checkpoint(state);
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::TableInsert))
            .unwrap();
        assert!(protected_ref(state, 1).0 > 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(field(&owner, table, HEADER), Value::Nil);
        assert_eq!(field(&owner, table, i64::from(FIRST)), Value::Nil);
        let reference = luaL_ref(state, 1);
        assert_eq!(reference, FIRST);
        let next = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(next))
            .unwrap();
        luaL_unref(state, 1, reference);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(
            field(&owner, table, HEADER),
            Value::Integer(i64::from(reference))
        );
        assert_eq!(
            field(&owner, table, i64::from(reference)),
            Value::Integer(0)
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap(),
            next
        );
    }
}

#[test]
fn refs_a13_matrix() {
    sequence();
    invalid();
    lifetime();
    function_thread_lifetime();
    active_gc_and_reuse();
    faults();
    boundary_and_unref_faults();
}
