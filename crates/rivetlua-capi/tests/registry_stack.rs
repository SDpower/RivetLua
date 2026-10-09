use std::cell::RefCell;
use std::ffi::{c_char, c_int};
use std::rc::Rc;

use rivetlua_capi::stack::{
    StackError, StateOwner, lua_State, lua_absindex, lua_copy, lua_gettop, lua_isnumber,
    lua_isstring, lua_pushinteger, lua_pushlightuserdata, lua_pushnil, lua_pushvalue, lua_rawequal,
    lua_rawget, lua_rawgeti, lua_rawgetp, lua_rawset, lua_rawseti, lua_rawsetp, lua_rotate,
    lua_settop, lua_toboolean, lua_tointegerx, lua_tolstring, lua_touserdata, lua_type,
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
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, FailPoint, LedgerProbe, ObjectKind, RootKind, VmError,
};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua55")]
const MAINTHREAD_ENTRY: i64 = 3;
#[cfg(feature = "lua54")]
const MAINTHREAD_ENTRY: i64 = 1;
#[cfg(feature = "lua55")]
const DEFERRED_FREELIST_ENTRY: i64 = 1;
#[cfg(feature = "lua54")]
const DEFERRED_FREELIST_ENTRY: i64 = 3;

fn registry(owner: &StateOwner) -> ObjectRef {
    owner
        .with_vm(|vm| {
            let mut found = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    found.push(object);
                }
            });
            assert_eq!(found.len(), 1);
            found[0]
        })
        .unwrap()
}

fn globals(owner: &StateOwner) -> ObjectRef {
    let table = registry(owner);
    owner
        .with_vm(|vm| {
            let Value::Object(globals) = vm.raw_get(table, Value::Integer(2)).unwrap() else {
                panic!("registry[2] 必須是 table");
            };
            assert_eq!(vm.object_kind(globals), Ok(ObjectKind::Table));
            globals
        })
        .unwrap()
}

fn registry_stack_pseudo_index_is_permanent_table_and_globals_are_real() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在所有 C API 呼叫期間存活。
    unsafe {
        assert_eq!(lua_absindex(state, REGISTRY_INDEX), REGISTRY_INDEX);
        assert_eq!(lua_type(state, REGISTRY_INDEX), 5);
        assert_eq!(lua_toboolean(state, REGISTRY_INDEX), 1);
        assert_eq!(lua_isnumber(state, REGISTRY_INDEX), 0);
        assert_eq!(lua_isstring(state, REGISTRY_INDEX), 0);
        assert!(lua_tolstring(state, REGISTRY_INDEX, std::ptr::null_mut()).is_null());
        assert!(lua_touserdata(state, REGISTRY_INDEX).is_null());
        assert_eq!(lua_type(state, OTHER_REGISTRY_INDEX), -1);
        assert_eq!(lua_gettop(state), 0);
        lua_pushvalue(state, REGISTRY_INDEX);
        assert_eq!(lua_type(state, -1), 5);
        assert_eq!(lua_rawequal(state, REGISTRY_INDEX, -1), 1);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
            .unwrap();
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), -1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), 5);
        assert_eq!(lua_type(state, -1), 5);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Registry))
                .unwrap(),
            3
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            2
        );
        lua_settop(state, 0);
        assert_eq!(lua_type(state, REGISTRY_INDEX), 5);
        // main thread 為 registry 常駐 coroutine；freelist 保留值依 profile 區分。
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, MAINTHREAD_ENTRY), 8);
        #[cfg(feature = "lua54")]
        assert_eq!(
            lua_rawgeti(state, REGISTRY_INDEX, DEFERRED_FREELIST_ENTRY),
            0
        );
        #[cfg(feature = "lua55")]
        {
            assert_eq!(
                lua_rawgeti(state, REGISTRY_INDEX, DEFERRED_FREELIST_ENTRY),
                1
            );
            assert_eq!(lua_toboolean(state, -1), 0);
        }
        lua_settop(state, 0);
    }
    owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().count(RootKind::Coroutine), 1);
            assert_eq!(vm.roots().total_count(), 4);
        })
        .unwrap();
}

fn registry_stack_raw_variants_and_failure_preserve_stack() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 有效；null pointer 僅作 lightuserdata 鍵，不解參照。
    unsafe {
        lua_pushinteger(state, 41);
        lua_rawseti(state, REGISTRY_INDEX, 7);
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 7), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 41);
        lua_settop(state, 0);

        lua_pushinteger(state, 8);
        lua_pushinteger(state, 52);
        lua_rawset(state, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), 0);
        lua_pushinteger(state, 8);
        assert_eq!(lua_rawget(state, REGISTRY_INDEX), 3);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 52);
        lua_settop(state, 0);

        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_rawsetp(state, REGISTRY_INDEX, std::ptr::null());
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_rawgetp(state, REGISTRY_INDEX, std::ptr::null()), 2);
        assert_eq!(lua_type(state, -1), 2);
        lua_settop(state, 0);

        lua_pushnil(state);
        lua_pushinteger(state, 99);
        lua_rawset(state, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -2), 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 99);
        lua_settop(state, 0);

        lua_pushnil(state);
        assert_eq!(lua_rawget(state, REGISTRY_INDEX), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, -1), 0);
    }
    let table = registry(&owner);
    owner
        .with_vm(|vm| {
            assert_eq!(
                vm.raw_get(table, Value::Integer(7)).unwrap(),
                Value::Integer(41)
            );
            assert_eq!(
                vm.raw_get(table, Value::Integer(8)).unwrap(),
                Value::Integer(52)
            );
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
        })
        .unwrap();
}

fn registry_stack_siblings_share_identity_and_vm_isolation_holds() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let foreign = StateOwner::new().unwrap();
    let reg = registry(&owner);
    let global = globals(&owner);
    assert_eq!(registry(&sibling), reg);
    assert_eq!(globals(&sibling), global);
    assert_ne!(registry(&foreign), reg);
    assert_ne!(globals(&foreign), global);
    assert!(matches!(
        foreign.push_value(Value::Object(reg)),
        Err(StackError::Runtime(VmError::WrongVm))
    ));
    // SAFETY：兩個 state 所屬 owner 都存活。
    unsafe {
        lua_pushinteger(owner.as_ptr(), 123);
        lua_rawseti(owner.as_ptr(), REGISTRY_INDEX, 15);
        assert_eq!(lua_rawgeti(sibling.as_ptr(), REGISTRY_INDEX, 15), 3);
        assert_eq!(
            lua_tointegerx(sibling.as_ptr(), -1, std::ptr::null_mut()),
            123
        );
        assert_eq!(lua_rawgeti(foreign.as_ptr(), REGISTRY_INDEX, 15), 0);
        assert_eq!(lua_rawgeti(owner.as_ptr(), REGISTRY_INDEX, 2), 5);
        assert_eq!(lua_rawgeti(sibling.as_ptr(), REGISTRY_INDEX, 2), 5);
    }
    owner
        .with_vm(|vm| assert_eq!(vm.roots().count(RootKind::Registry), 3))
        .unwrap();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(owner);
    sibling
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.object_kind(global), Ok(ObjectKind::Table));
        })
        .unwrap();
    drop(sibling);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

fn registry_stack_gc_and_stack_mutators_keep_permanent_registry() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let reg = registry(&owner);
    let global = globals(&owner);
    // SAFETY：state 有效；registry 可由 copy 取代，rotate 仍不可移動 pseudo-index。
    unsafe {
        lua_pushvalue(state, REGISTRY_INDEX);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        lua_pushinteger(state, 6);
        lua_rotate(state, REGISTRY_INDEX, 1);
        lua_copy(state, 2, REGISTRY_INDEX);
        assert_eq!(lua_type(state, REGISTRY_INDEX), 3);
        lua_copy(state, 1, REGISTRY_INDEX);
        assert_eq!(lua_rawequal(state, REGISTRY_INDEX, 1), 1);
        assert_eq!(lua_type(state, REGISTRY_INDEX - 1), -1);
        assert_eq!(lua_toboolean(state, REGISTRY_INDEX - 1), 0);
        assert!(
            rivetlua_capi_test_protected_index_a4b(
                state,
                11,
                REGISTRY_INDEX - 1,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            ) > 0
        );
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);
    }
    owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(reg), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(global), Ok(ObjectKind::Table));
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
        })
        .unwrap();
}

fn registry_stack_creation_allocation_failures_are_atomic() {
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..46_u64 {
        let probe = Rc::new(RefCell::new(None::<LedgerProbe>));
        let captured = Rc::clone(&probe);
        let mut injected_ordinal = None;
        let result = StateOwner::new_with_vm_setup(|vm| {
            *captured.borrow_mut() = Some(vm.ledger_probe());
            let ordinal = vm.allocation_trace().next_ordinal + offset;
            injected_ordinal = Some(ordinal);
            vm.inject_allocation_failure_at(ordinal);
        });
        let probe = probe.borrow().as_ref().unwrap().clone();
        match result {
            Err(StackError::Runtime(VmError::InjectedAllocation(attempt))) => {
                assert_eq!(
                    attempt.ordinal,
                    injected_ordinal.unwrap(),
                    "offset {offset}"
                );
                let failure = probe.trace().last_failure.unwrap();
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt, attempt);
                failures.push((
                    offset,
                    attempt.domain,
                    attempt.bytes,
                    attempt.point,
                    attempt.site.file,
                ));
                let retry = StateOwner::new().unwrap();
                assert_eq!(
                    retry
                        .with_vm(|vm| vm.roots().count(RootKind::Registry))
                        .unwrap(),
                    3
                );
                drop(retry);
            }
            Ok(owner) => {
                successes.push(offset);
                assert_eq!(
                    owner
                        .with_vm(|vm| vm.roots().count(RootKind::Registry))
                        .unwrap(),
                    3
                );
                assert_eq!(
                    owner
                        .with_vm(|vm| vm.roots().count(RootKind::Host))
                        .unwrap(),
                    0
                );
                let global = globals(&owner);
                assert_eq!(
                    owner.with_vm(|vm| vm.object_kind(global)).unwrap(),
                    Ok(ObjectKind::Table)
                );
                drop(owner);
            }
            Err(error) => panic!("offset {offset}: {error:?}"),
        }
        assert_eq!(probe.snapshot().committed, 0, "offset {offset}");
        assert_eq!(probe.snapshot().reserved, 0, "offset {offset}");
    }
    const HEAP: &str = "crates/rivetlua-runtime/src/heap.rs";
    const TABLE: &str = "crates/rivetlua-runtime/src/table.rs";
    const ROOTS: &str = "crates/rivetlua-runtime/src/roots.rs";
    // StateGroup 現含 hook bridge 與 native lease；RefCell 另含借用旗標。
    assert_eq!(StateOwner::allocation_component_sizes().0, 2600);
    assert_eq!(StateOwner::allocation_component_sizes().1, 2608);
    // Rc 的兩個計數器各占一個 usize，與 group_accounted_bytes 的 Layout 相同。
    assert_eq!(
        StateOwner::allocation_component_sizes().1 + 2 * size_of::<usize>(),
        2624
    );
    // StateAllocation 內嵌的 StateControl 含暫停、重設與 continuation 狀態。
    assert_eq!(StateOwner::allocation_component_sizes().3, 2096);
    let mut expected = vec![
        (AllocationDomain::Host, 2624, None, HEAP),
        (
            AllocationDomain::LuaHeap,
            0,
            Some(FailPoint::TableArrayReserve),
            TABLE,
        ),
        (
            AllocationDomain::LuaHeap,
            0,
            Some(FailPoint::TableHashReserve),
            TABLE,
        ),
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 208, None, ROOTS),
        (
            AllocationDomain::LuaHeap,
            0,
            Some(FailPoint::TableArrayReserve),
            TABLE,
        ),
        (
            AllocationDomain::LuaHeap,
            0,
            Some(FailPoint::TableHashReserve),
            TABLE,
        ),
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 208, None, ROOTS),
        (
            AllocationDomain::LuaHeap,
            104,
            Some(FailPoint::TableHashGrow),
            TABLE,
        ),
    ];
    #[cfg(feature = "lua55")]
    expected.push((
        AllocationDomain::LuaHeap,
        160,
        Some(FailPoint::TableArrayGrow),
        TABLE,
    ));
    expected.extend([
        (AllocationDomain::Host, 120, None, ROOTS),
        (AllocationDomain::Host, 18, None, HEAP),
        (AllocationDomain::Host, 216, None, HEAP),
        (
            AllocationDomain::LuaHeap,
            17,
            Some(FailPoint::StringBytesReserve),
            "crates/rivetlua-runtime/src/string.rs",
        ),
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 120, None, ROOTS),
        // Coroutine 現含暫停執行與 host attachment，main thread payload 依目前布局計費。
        (
            AllocationDomain::LuaHeap,
            3232,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 208, None, ROOTS),
    ]);
    #[cfg(feature = "lua54")]
    expected.push((
        AllocationDomain::LuaHeap,
        160,
        Some(FailPoint::TableArrayGrow),
        TABLE,
    ));
    // B12 的 main coroutine 專用 root 在 registry 陣列邊發布後建立。
    expected.push((AllocationDomain::Host, 120, None, ROOTS));
    // B10b2 建構時預先建立且 Registry-rooted 的 hidden CClosure：nil capture、
    // closure object、暫存 Host root 及永久 Registry root 均有精確配置序列。
    expected.extend([
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 120, None, ROOTS),
        (
            AllocationDomain::LuaHeap,
            32,
            Some(FailPoint::ClosureCapturesReserve),
            "crates/rivetlua-runtime/src/closure.rs",
        ),
        (
            AllocationDomain::LuaHeap,
            136,
            Some(FailPoint::SlotReserve),
            HEAP,
        ),
        (
            AllocationDomain::LuaHeap,
            312,
            Some(FailPoint::ObjectReserve),
            HEAP,
        ),
        (AllocationDomain::Host, 208, None, ROOTS),
        (AllocationDomain::Host, 120, None, ROOTS),
    ]);
    expected.push((AllocationDomain::Host, 2096, None, HEAP));
    let expected: Vec<_> = expected
        .into_iter()
        .enumerate()
        .map(|(ordinal, (domain, bytes, point, site))| (ordinal as u64, domain, bytes, point, site))
        .collect();
    assert_eq!(failures, expected);
    assert_eq!(successes, (34..46).collect::<Vec<_>>());
}

fn registry_stack_constructor_active_gc_publishes_live_tables() {
    let mut probe = None;
    let mut before_transitions = None;
    let owner = StateOwner::new_with_vm_setup(|vm| {
        probe = Some(vm.ledger_probe());
        before_transitions = Some(vm.gc_trace().transition_count);
        vm.set_collect_every_allocation(true);
    })
    .unwrap();
    let registry = registry(&owner);
    let globals = globals(&owner);
    owner
        .with_vm(|vm| {
            assert!(vm.gc_trace().transition_count > before_transitions.unwrap());
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().count(RootKind::Coroutine), 1);
            assert_eq!(vm.roots().total_count(), 4);
            assert_eq!(vm.object_kind(registry), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(globals), Ok(ObjectKind::Table));
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(registry), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(globals), Ok(ObjectKind::Table));
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
        })
        .unwrap();
    drop(owner);
    let after = probe.unwrap().snapshot();
    assert_eq!(after.committed, 0);
    assert_eq!(after.reserved, 0);
}

#[test]
fn registry_stack_a5_matrix() {
    registry_stack_pseudo_index_is_permanent_table_and_globals_are_real();
    registry_stack_raw_variants_and_failure_preserve_stack();
    registry_stack_siblings_share_identity_and_vm_isolation_holds();
    registry_stack_gc_and_stack_mutators_keep_permanent_registry();
    registry_stack_creation_allocation_failures_are_atomic();
    registry_stack_constructor_active_gc_publishes_live_tables();
}
