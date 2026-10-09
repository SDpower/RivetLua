use rivetlua_capi::stack::{
    StackError, StateOwner, lua_createtable, lua_gettop, lua_pushinteger, lua_pushlightuserdata,
    lua_pushnil, lua_pushvalue, lua_rawgeti, lua_rawseti, lua_settop, lua_touserdata, lua_type,
    lua_xmove,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, GcAge, GcColor, GcPhase, LedgerSnapshot, ObjectKind, RootKind,
    VmError,
};

fn snapshot(owner: &StateOwner) -> LedgerSnapshot {
    owner.with_vm(|vm| vm.ledger_snapshot()).unwrap()
}

fn only_rooted_table(owner: &StateOwner) -> ObjectRef {
    let mut tables = Vec::new();
    owner
        .with_vm(|vm| {
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    tables.push(object);
                }
            });
        })
        .unwrap();
    assert_eq!(tables.len(), 1);
    tables[0]
}

#[test]
fn table_stack_create_zero_nonzero_hints_and_invalid_inputs() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 於 owner 存活期間有效。
    unsafe {
        lua_createtable(state, 0, 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, -1), 5);
    }
    let empty = only_rooted_table(&owner);
    assert_eq!(
        owner
            .with_vm(|vm| vm.with_table(empty, |t| (t.array_capacity(), t.hash_capacity())))
            .unwrap(),
        Ok((0, 0))
    );
    // SAFETY：移除唯一 slot 後才建立下一個 table。
    unsafe { lua_settop(state, 0) };
    unsafe { lua_createtable(state, 3, 2) };
    let reserved = only_rooted_table(&owner);
    let capacities = owner
        .with_vm(|vm| vm.with_table(reserved, |t| (t.array_capacity(), t.hash_capacity())))
        .unwrap()
        .unwrap();
    assert!(capacities.0 >= 3 && capacities.1 >= 2);
    let before = snapshot(&owner);
    // SAFETY：無效 hints 必須 fail-closed，不改 table slot。
    unsafe {
        lua_createtable(state, -1, 0);
        lua_createtable(state, 0, -1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, -1), 5);
    }
    assert_eq!(snapshot(&owner), before);
    owner
        .with_vm(|vm| vm.set_allocation_limit(before.committed))
        .unwrap();
    let limited = snapshot(&owner);
    // SAFETY：額度不足的容量預留及極大 hint 均不得部分發布。
    unsafe {
        lua_createtable(state, 8, 8);
        lua_createtable(state, i32::MAX, i32::MAX);
        assert_eq!(lua_gettop(state), 1);
    }
    assert_eq!(snapshot(&owner), limited);
    assert_eq!(only_rooted_table(&owner), reserved);
}

#[test]
fn table_stack_raw_integer_boundaries_relative_indices_and_stack_effect() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：所有 index 在 push/pop 前按固定 Lua header 解讀。
    unsafe {
        lua_createtable(state, 0, 0);
        assert_eq!(lua_rawgeti(state, -1, i64::MIN), 0);
        assert_eq!(lua_type(state, -1), 0);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 1);

        lua_pushinteger(state, 17);
        lua_rawseti(state, -2, i64::MIN);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawgeti(state, 1, i64::MIN), 3);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 1);

        lua_pushinteger(state, 23);
        lua_rawseti(state, -2, i64::MIN);
        assert_eq!(lua_rawgeti(state, -1, i64::MIN), 3);
        lua_settop(state, 1);
        assert_eq!(lua_rawgeti(state, -1, i64::MAX), 0);
        lua_settop(state, 1);

        lua_pushnil(state);
        lua_rawseti(state, -2, i64::MIN);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawgeti(state, -1, i64::MIN), 0);
        lua_settop(state, 1);

        lua_pushinteger(state, 9);
        assert_eq!(lua_rawgeti(state, -1, 1), -1);
        assert_eq!(lua_gettop(state), 2);
        lua_rawseti(state, -1, 1);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);
    }
}

#[test]
fn table_stack_lightuserdata_value_roundtrip() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 7_u8;
    let pointer = (&mut token as *mut u8).cast();
    // SAFETY：token 在整個測試期間存活，C API 只保存不解參照 pointer。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushlightuserdata(state, pointer);
        lua_rawseti(state, -2, 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawgeti(state, -1, 1), 2);
        assert_eq!(lua_touserdata(state, -1), pointer);
        lua_settop(state, 0);
    }
}

#[test]
fn table_stack_lightuserdata_null_and_pointer_push_have_no_heap_or_root_charge() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 1_u8;
    let pointer = (&mut token as *mut u8).cast();
    let before = snapshot(&owner);
    let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
    // SAFETY：C API 只記錄位址；不解參照指標，owner 持續持有有效 state。
    unsafe {
        lua_pushlightuserdata(state, core::ptr::null_mut());
        lua_pushlightuserdata(state, pointer);
        assert_eq!(lua_type(state, -2), 2);
        assert_eq!(lua_type(state, -1), 2);
        assert_eq!(lua_touserdata(state, -2), core::ptr::null_mut());
        assert_eq!(lua_touserdata(state, -1), pointer);
    }
    let after = snapshot(&owner);
    assert_eq!(after.lua_heap_bytes, before.lua_heap_bytes);
    assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
    // SAFETY：兩個 scalar slot 均可直接移除。
    unsafe { lua_settop(state, 0) };
    assert_eq!(snapshot(&owner), before);
}

#[test]
fn table_stack_rawget_push_failure_preserves_table_value_and_ledger() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    unsafe { lua_createtable(state, 0, 0) };
    let table = only_rooted_table(&owner);
    let value = owner
        .with_vm(|vm| vm.allocate_byte_string(b"value").unwrap())
        .unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    unsafe { lua_rawseti(state, -2, 1) };
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    // SAFETY：新 slot root 失敗時不可 push，table 原值仍在。
    unsafe {
        assert_eq!(lua_rawgeti(state, -1, 1), -1);
        assert_eq!(lua_gettop(state), 1);
    }
    assert_eq!(snapshot(&owner), before);
    assert_eq!(
        owner
            .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
            .unwrap(),
        Ok(Value::Object(value))
    );
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        1
    );
}

#[test]
fn table_stack_value_gc_copy_xmove_drop_and_cross_vm_rejection() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let foreign = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let moved = sibling.as_ptr();
    unsafe { lua_createtable(state, 0, 0) };
    let table = only_rooted_table(&owner);
    let value = owner
        .with_vm(|vm| vm.allocate_byte_string(b"reachable").unwrap())
        .unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    unsafe {
        lua_rawseti(state, -2, 1);
        lua_pushvalue(state, 1);
        lua_xmove(state, moved, 1);
        lua_settop(state, 0);
    }
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Ok(ObjectKind::ByteString)
    );
    assert_eq!(
        foreign.push_value(Value::Object(table)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    assert_eq!(
        foreign
            .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
            .unwrap(),
        Err(VmError::WrongVm)
    );
    drop(owner);
    // SAFETY：同 VM sibling 仍持有 table root。
    unsafe {
        assert_eq!(lua_rawgeti(moved, -1, 1), 4);
        lua_settop(moved, 1);
        lua_pushnil(moved);
        lua_rawseti(moved, -2, 1);
        lua_settop(moved, 0);
    }
    sibling.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        sibling.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        sibling.with_vm(|vm| vm.object_kind(table)).unwrap(),
        Err(VmError::StaleObject)
    );
}

#[test]
fn table_stack_create_publication_failures_active_gc_are_atomic() {
    let mut failed = Vec::new();
    let mut succeeded = Vec::new();
    for offset in 0..24 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { lua_settop(state, 128) };
        let anchor = owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                let object = vm.allocate_table().unwrap();
                let root = vm.add_root(RootKind::Host, object).unwrap();
                for _ in 0..128 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause {
                        break;
                    }
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                root
            })
            .unwrap();
        let before = snapshot(&owner);
        let before_gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
        owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
            })
            .unwrap();
        // SAFETY：固定有效 state；以 top 區分 void API 是否發布成功。
        unsafe { lua_createtable(state, 2, 3) };
        if unsafe { lua_gettop(state) } == 128 {
            assert_eq!(snapshot(&owner), before, "offset {offset}");
            assert_eq!(
                owner.with_vm(|vm| vm.gc_trace()).unwrap(),
                before_gc,
                "offset {offset}"
            );
            assert_eq!(
                owner
                    .with_vm(|vm| vm.roots().count(RootKind::Host))
                    .unwrap(),
                1
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            failed.push((
                offset,
                failure.attempt.domain,
                failure.attempt.bytes,
                failure.attempt.site.file,
            ));
        } else {
            assert_eq!(unsafe { lua_gettop(state) }, 129);
            assert_eq!(unsafe { lua_type(state, -1) }, 5);
            succeeded.push(offset);
            unsafe { lua_settop(state, 0) };
        }
        owner.with_vm(|vm| vm.remove_root(anchor).unwrap()).unwrap();
    }
    assert_eq!(
        failed,
        vec![
            (
                0,
                AllocationDomain::LuaHeap,
                80,
                "crates/rivetlua-runtime/src/table.rs"
            ),
            (
                1,
                AllocationDomain::LuaHeap,
                312,
                "crates/rivetlua-runtime/src/table.rs"
            ),
            (
                2,
                AllocationDomain::LuaHeap,
                136,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
            (
                3,
                AllocationDomain::LuaHeap,
                312,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
            (
                4,
                AllocationDomain::Host,
                1,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
            (
                5,
                AllocationDomain::Host,
                32,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
            (
                6,
                AllocationDomain::Host,
                208,
                "crates/rivetlua-runtime/src/roots.rs"
            ),
            (
                7,
                AllocationDomain::Host,
                36864,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
        ]
    );
    assert_eq!(succeeded, (8..24).collect::<Vec<_>>());
}

#[test]
fn table_stack_rawset_failure_matrix_and_generational_barrier() {
    let mut failed = Vec::new();
    let mut succeeded = Vec::new();
    for offset in 0..20 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { lua_createtable(state, 0, 0) };
        let table = only_rooted_table(&owner);
        let value = owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_promotion_survivals(1).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
                for _ in 0..128 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause
                        && vm.gc_color(table) == Ok(GcColor::Black)
                    {
                        break;
                    }
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
                vm.allocate_byte_string(b"young").unwrap()
            })
            .unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        let before = snapshot(&owner);
        let before_gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
        owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
            })
            .unwrap();
        // SAFETY：相對 index 必須在 pop 前解析；失敗時 value slot 仍在 top。
        unsafe { lua_rawseti(state, -2, 1) };
        let top = unsafe { lua_gettop(state) };
        if top == 2 {
            assert_eq!(snapshot(&owner), before, "offset {offset}");
            assert_eq!(
                owner.with_vm(|vm| vm.gc_trace()).unwrap(),
                before_gc,
                "offset {offset}"
            );
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
                    .unwrap(),
                Ok(Value::Nil)
            );
            assert_eq!(
                owner
                    .with_vm(|vm| vm.roots().count(RootKind::Host))
                    .unwrap(),
                2
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            failed.push((
                offset,
                failure.attempt.domain,
                failure.attempt.bytes,
                failure.attempt.site.file,
            ));
        } else {
            assert_eq!(top, 1);
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
                    .unwrap(),
                Ok(Value::Object(value))
            );
            assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
                Ok(ObjectKind::ByteString)
            );
            succeeded.push(offset);
        }
    }
    assert_eq!(
        failed,
        vec![
            (
                0,
                AllocationDomain::LuaHeap,
                160,
                "crates/rivetlua-runtime/src/table.rs"
            ),
            (
                1,
                AllocationDomain::Host,
                32,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
        ]
    );
    assert_eq!(succeeded, (2..20).collect::<Vec<_>>());
}
