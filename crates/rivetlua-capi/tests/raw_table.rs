use std::ffi::{CString, c_int, c_void};

use rivetlua_capi::stack::{
    StackError, StateOwner, lua_State, lua_compare, lua_createtable, lua_gettop, lua_isinteger,
    lua_newuserdatauv, lua_pushboolean, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring,
    lua_pushnil, lua_pushnumber, lua_pushstring, lua_pushvalue, lua_rawequal, lua_rawget,
    lua_rawgetp, lua_rawset, lua_rawsetp, lua_settop, lua_toboolean, lua_tointegerx, lua_tonumberx,
    lua_topointer, lua_touserdata, lua_type,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, GcAge, GcColor, GcMode, GcPhase, LedgerSnapshot, ObjectKind, RootKind,
    VmError,
};

unsafe extern "C" fn compare_a47_first(_state: *mut lua_State) -> c_int {
    0
}

unsafe extern "C" fn compare_a47_second(_state: *mut lua_State) -> c_int {
    0
}

unsafe extern "C" {
    fn lua_pushcclosure(
        state: *mut lua_State,
        function: Option<unsafe extern "C" fn(*mut lua_State) -> c_int>,
        upvalues: c_int,
    );
}

#[derive(Debug, Eq, PartialEq)]
enum CompareA47Slot {
    Nil,
    Boolean(c_int),
    LightUserdata(usize),
    Integer(i64),
    Float(u64),
    Object(c_int, usize),
    Other(c_int),
}

fn compare_a47_stack_snapshot(state: *mut lua_State) -> (c_int, Vec<CompareA47Slot>) {
    // SAFETY：呼叫者保有 StateOwner；此處只讀取有效 stack slot 的 scalar／identity view。
    unsafe {
        let top = lua_gettop(state);
        let mut slots = Vec::with_capacity(top.max(0) as usize);
        for index in 1..=top {
            let kind = lua_type(state, index);
            let slot = match kind {
                0 => CompareA47Slot::Nil,
                1 => CompareA47Slot::Boolean(lua_toboolean(state, index)),
                2 => CompareA47Slot::LightUserdata(lua_touserdata(state, index) as usize),
                3 if lua_isinteger(state, index) != 0 => {
                    CompareA47Slot::Integer(lua_tointegerx(state, index, std::ptr::null_mut()))
                }
                3 => CompareA47Slot::Float(
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits(),
                ),
                4..=8 => CompareA47Slot::Object(kind, lua_topointer(state, index) as usize),
                other => CompareA47Slot::Other(other),
            };
            slots.push(slot);
        }
        (top, slots)
    }
}

fn assert_compare_a47_pure(
    owner: &StateOwner,
    state: *mut lua_State,
    left: c_int,
    right: c_int,
    op: c_int,
    expected: c_int,
) {
    let before_stack = compare_a47_stack_snapshot(state);
    let before_vm = owner
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.roots().total_count(),
                vm.allocation_trace(),
                vm.gc_trace(),
            )
        })
        .unwrap();
    for _ in 0..3 {
        // SAFETY：owner 保活有效 state；比較保持 stack 不變，無效 index 回零。
        assert_eq!(unsafe { lua_compare(state, left, right, op) }, expected);
        assert_eq!(compare_a47_stack_snapshot(state), before_stack);
        let after_vm = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.roots().total_count(),
                    vm.allocation_trace(),
                    vm.gc_trace(),
                )
            })
            .unwrap();
        assert_eq!(after_vm.0.reserved, 0);
        assert_eq!(after_vm.1, before_vm.1);
        assert_eq!(after_vm.2.last_failure, before_vm.2.last_failure);
        assert!(after_vm.2.next_ordinal >= before_vm.2.next_ordinal);
        assert_eq!(after_vm.3.mode, before_vm.3.mode);
    }
}

fn ledger(owner: &StateOwner) -> LedgerSnapshot {
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

fn assert_rawequal_pure(owner: &StateOwner, left: i32, right: i32, expected: i32) {
    let before = ledger(owner);
    let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
    let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    // SAFETY：測試中的 owner 持有有效 state；index 可無效，API 須回 false。
    assert_eq!(
        unsafe { lua_rawequal(owner.as_ptr(), left, right) },
        expected
    );
    assert_eq!(ledger(owner), before);
    assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
}

#[test]
fn raw_table_generic_boolean_numeric_string_missing_and_stack_effects() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let name = CString::new("same-key").unwrap();
    // SAFETY：owner 與 name 在整段測試期間有效，API 僅借用 C 字串。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 42);
        lua_rawset(state, -3);
        assert_eq!(lua_gettop(state), 1);

        lua_pushboolean(state, 1);
        assert_eq!(lua_rawget(state, -2), 3);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
        lua_settop(state, 1);

        lua_pushinteger(state, 1);
        lua_pushinteger(state, 77);
        lua_rawset(state, 1);
        lua_pushnumber(state, 1.0);
        assert_eq!(lua_rawget(state, 1), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 77);
        lua_settop(state, 1);

        lua_pushstring(state, name.as_ptr());
        lua_pushinteger(state, 88);
        lua_rawset(state, -3);
        lua_pushstring(state, name.as_ptr());
        assert_eq!(lua_rawget(state, -2), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 88);
        lua_settop(state, 1);

        lua_pushboolean(state, 0);
        assert_eq!(lua_rawget(state, -2), 0);
        assert_eq!(lua_type(state, -1), 0);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 1);

        lua_pushnil(state);
        assert_eq!(lua_rawget(state, -2), 0);
        assert_eq!(lua_type(state, -1), 0);
        lua_settop(state, 1);
        lua_pushnumber(state, f64::NAN);
        assert_eq!(lua_rawget(state, -2), 0);
        assert_eq!(lua_type(state, -1), 0);
        lua_settop(state, 1);

        lua_pushinteger(state, 9);
        let before = ledger(&owner);
        assert_eq!(lua_rawget(state, -1), -1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(ledger(&owner), before);
        lua_settop(state, 0);
    }
}

#[test]
fn raw_table_pointer_keys_include_null_and_share_generic_address_class() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 7_u8;
    let pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：指標只作位址鍵，從不解參照；owner 保持 state 有效。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 31);
        lua_rawsetp(state, -2, std::ptr::null());
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawgetp(state, -1, std::ptr::null()), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 31);
        lua_settop(state, 1);

        lua_pushinteger(state, 32);
        lua_rawsetp(state, 1, pointer.cast_const());
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawgetp(state, 1, pointer.cast_const()), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 32);
        lua_settop(state, 1);

        lua_pushlightuserdata(state, pointer);
        assert_eq!(lua_rawget(state, -2), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 32);
        lua_settop(state, 1);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        assert_eq!(lua_rawget(state, -2), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 31);
        lua_settop(state, 1);

        let other = (&mut token as *mut u8).wrapping_add(1).cast::<c_void>();
        assert_eq!(lua_rawgetp(state, -1, other.cast_const()), 0);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 1);
        lua_pushnil(state);
        lua_rawsetp(state, -2, pointer.cast_const());
        assert_eq!(lua_rawgetp(state, -1, pointer.cast_const()), 0);
        lua_settop(state, 0);
    }
}

#[test]
fn raw_table_rawequal_full_scalar_string_pointer_and_identity_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let name = CString::new("equal-bytes").unwrap();
    // SAFETY：state 與 C 字串在測試內持續有效；所有 pointer 不解參照。
    unsafe {
        assert_rawequal_pure(&owner, 1, -1, 0);
        lua_pushnil(state);
        lua_pushnil(state);
        assert_rawequal_pure(&owner, 1, -1, 1);
        lua_settop(state, 0);

        lua_pushboolean(state, 1);
        lua_pushboolean(state, 0);
        assert_rawequal_pure(&owner, 1, 2, 0);
        lua_settop(state, 0);

        lua_pushinteger(state, 7);
        lua_pushnumber(state, 7.0);
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_settop(state, 0);
        lua_pushinteger(state, i64::MAX);
        lua_pushnumber(state, i64::MAX as f64);
        assert_rawequal_pure(&owner, 1, 2, 0);
        lua_settop(state, 0);
        lua_pushnumber(state, -0.0);
        lua_pushinteger(state, 0);
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_settop(state, 0);
        lua_pushnumber(state, f64::NAN);
        assert_rawequal_pure(&owner, 1, 1, 0);
        lua_settop(state, 0);

        lua_pushstring(state, name.as_ptr());
        lua_pushstring(state, name.as_ptr());
        let mut objects = Vec::new();
        owner
            .with_vm(|vm| {
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Host
                        && vm.object_kind(object) == Ok(ObjectKind::ByteString)
                    {
                        objects.push(object);
                    }
                });
            })
            .unwrap();
        assert_eq!(objects.len(), 2);
        assert_ne!(objects[0], objects[1]);
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_settop(state, 0);

        let mut token = 3_u8;
        let first = (&mut token as *mut u8).cast::<c_void>();
        let other = (&mut token as *mut u8).wrapping_add(1).cast::<c_void>();
        lua_pushlightuserdata(state, first);
        lua_pushlightuserdata(state, first);
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_settop(state, 1);
        lua_pushlightuserdata(state, other);
        assert_rawequal_pure(&owner, 1, 2, 0);
        lua_settop(state, 0);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, std::ptr::null_mut());
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_pushvalue(state, 1);
        assert_rawequal_pure(&owner, 1, 2, 1);
        lua_createtable(state, 0, 0);
        assert_rawequal_pure(&owner, 1, 3, 0);
        lua_settop(state, 0);
        lua_pushinteger(state, 1);
        lua_pushboolean(state, 1);
        assert_rawequal_pure(&owner, 1, 2, 0);
        assert_rawequal_pure(&owner, 0, 2, 0);
        assert_rawequal_pure(&owner, 1, 99, 0);
        lua_settop(state, 0);
    }
}

#[test]
fn raw_table_rejects_invalid_keys_without_pop_or_mutation() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 持有 state；失敗 API 必保留 top key/value。
    unsafe {
        lua_createtable(state, 0, 0);
        let table = only_rooted_table(&owner);
        for invalid_nan in [false, true] {
            if invalid_nan {
                lua_pushnumber(state, f64::NAN);
            } else {
                lua_pushnil(state);
            }
            lua_pushinteger(state, 17);
            let before = ledger(&owner);
            let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
            lua_rawset(state, -3);
            assert_eq!(lua_gettop(state), 3);
            assert_eq!(lua_type(state, -2), if invalid_nan { 3 } else { 0 });
            assert_eq!(lua_type(state, -1), 3);
            assert_eq!(ledger(&owner), before);
            assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
                    .unwrap(),
                Ok(Value::Nil)
            );
            lua_settop(state, 1);
        }
        lua_pushinteger(state, 1);
        lua_pushinteger(state, 2);
        let before = ledger(&owner);
        lua_rawset(state, -1);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(ledger(&owner), before);
        lua_settop(state, 0);
    }
}

#[test]
fn raw_table_table_itself_as_top_key_replaces_last_root_safely() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：table index 在 pop 前解析；讀取時 table 可同時是唯一 key slot。
    unsafe {
        lua_createtable(state, 0, 0);
        let table = only_rooted_table(&owner);
        lua_pushvalue(state, 1);
        lua_pushboolean(state, 1);
        lua_rawset(state, -3);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_rawget(state, -1), 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, 1), 1);
        owner
            .with_vm(|vm| {
                assert_eq!(vm.roots().count(RootKind::Registry), 3);
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                assert_eq!(vm.roots().total_count(), 4);
            })
            .unwrap();
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(table)).unwrap(),
            Err(VmError::StaleObject)
        );
        lua_settop(state, 0);
    }
}

#[test]
fn raw_table_object_key_value_survive_pop_gc_and_delete_collects_both() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：所有 C 入口的 state 有效；物件身分由受控 VM 建立。
    unsafe { lua_createtable(state, 0, 0) };
    let table = only_rooted_table(&owner);
    let (key, value) = owner
        .with_vm(|vm| {
            (
                vm.allocate_table().unwrap(),
                vm.allocate_byte_string(b"value").unwrap(),
            )
        })
        .unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    unsafe {
        lua_rawset(state, -3);
        assert_eq!(lua_gettop(state), 1);
    }
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Ok(ObjectKind::Table)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Ok(ObjectKind::ByteString)
    );
    owner.push_value(Value::Object(key)).unwrap();
    unsafe {
        assert_eq!(lua_rawget(state, 1), 4);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 1);
    }
    owner.push_value(Value::Object(key)).unwrap();
    unsafe {
        lua_pushnil(state);
        lua_rawset(state, -3);
        assert_eq!(lua_gettop(state), 1);
    }
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(table)).unwrap(),
        Ok(ObjectKind::Table)
    );
}

#[test]
fn raw_table_get_string_key_and_returned_root_failures_are_atomic() {
    let mut failed = Vec::new();
    let mut succeeded = Vec::new();
    let name = CString::new("lookup").unwrap();
    for offset in 0..16 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：C 字串有效；先建置 table entry，失敗注入僅套用後續 rawget。
        unsafe { lua_createtable(state, 0, 0) };
        let table = only_rooted_table(&owner);
        let value = owner
            .with_vm(|vm| vm.allocate_byte_string(b"result").unwrap())
            .unwrap();
        unsafe { lua_pushstring(state, name.as_ptr()) };
        owner.push_value(Value::Object(value)).unwrap();
        unsafe { lua_rawset(state, -3) };
        unsafe { lua_pushstring(state, name.as_ptr()) };
        let mut rooted_key = Vec::new();
        owner
            .with_vm(|vm| {
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Host
                        && vm.object_kind(object) == Ok(ObjectKind::ByteString)
                    {
                        rooted_key.push(object);
                    }
                });
            })
            .unwrap();
        assert_eq!(rooted_key.len(), 1);
        let key = rooted_key[0];
        let before = ledger(&owner);
        let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
        let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
        owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
            })
            .unwrap();
        let tag = unsafe { lua_rawget(state, -2) };
        if tag == -1 {
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            assert_eq!(unsafe { lua_type(state, -1) }, 4);
            assert_eq!(ledger(&owner), before, "offset {offset}");
            assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
            assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Object(key)))
                    .unwrap(),
                Ok(Value::Object(value))
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
            assert_eq!(tag, 4);
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            succeeded.push(offset);
        }
    }
    assert_eq!(
        failed,
        vec![(
            0,
            AllocationDomain::Host,
            208,
            "crates/rivetlua-runtime/src/roots.rs"
        ),]
    );
    assert_eq!(succeeded, (1..16).collect::<Vec<_>>());
}

#[test]
fn raw_table_set_string_key_resize_and_barrier_failures_are_atomic() {
    let mut failed = Vec::new();
    let mut succeeded = Vec::new();
    for offset in 0..20 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：此處只建立真正 stack table，稍後測試相對 index 與兩格 pop。
        unsafe { lua_createtable(state, 0, 0) };
        let table = only_rooted_table(&owner);
        let (key, value) = owner
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
                (
                    vm.allocate_byte_string(b"young-key").unwrap(),
                    vm.allocate_byte_string(b"young-value").unwrap(),
                )
            })
            .unwrap();
        owner.push_value(Value::Object(key)).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        let before = ledger(&owner);
        let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
        let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
        owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
            })
            .unwrap();
        // SAFETY：若 mutation 失敗，key/value slot 均須保留。
        unsafe { lua_rawset(state, -3) };
        if unsafe { lua_gettop(state) } == 3 {
            assert_eq!(ledger(&owner), before, "offset {offset}");
            assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
            assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Object(key)))
                    .unwrap(),
                Ok(Value::Nil)
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
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
                Ok(ObjectKind::ByteString)
            );
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
                Ok(ObjectKind::ByteString)
            );
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Object(key)))
                    .unwrap(),
                Ok(Value::Object(value))
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
                9,
                "crates/rivetlua-runtime/src/string.rs"
            ),
            (
                1,
                AllocationDomain::LuaHeap,
                224,
                "crates/rivetlua-runtime/src/table.rs"
            ),
            (
                2,
                AllocationDomain::LuaHeap,
                104,
                "crates/rivetlua-runtime/src/table.rs"
            ),
            (
                3,
                AllocationDomain::Host,
                32,
                "crates/rivetlua-runtime/src/heap.rs"
            ),
        ]
    );
    assert_eq!(succeeded, (4..20).collect::<Vec<_>>());
}

#[test]
fn raw_table_pointer_set_and_get_failure_preserve_slots_and_table() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：所有 pointer 僅作位址鍵；C stack 的 table index 指向實際 table。
    unsafe { lua_createtable(state, 0, 0) };
    let table = only_rooted_table(&owner);
    let value = owner
        .with_vm(|vm| vm.allocate_byte_string(b"pointer-value").unwrap())
        .unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    let before = ledger(&owner);
    let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(rivetlua_runtime::FailPoint::TableHashGrow))
        .unwrap();
    unsafe { lua_rawsetp(state, -2, std::ptr::null()) };
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(ledger(&owner), before);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
    assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
    assert_eq!(
        owner
            .with_vm(|vm| vm.raw_get(table, Value::LightUserdata(0)))
            .unwrap(),
        Ok(Value::Nil)
    );
    unsafe { lua_rawsetp(state, -2, std::ptr::null()) };
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    let before = ledger(&owner);
    let gc = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    let roots = owner.with_vm(|vm| vm.roots().total_count()).unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(rivetlua_runtime::FailPoint::RootReserve))
        .unwrap();
    assert_eq!(unsafe { lua_rawgetp(state, -1, std::ptr::null()) }, -1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(ledger(&owner), before);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace()).unwrap(), gc);
    assert_eq!(owner.with_vm(|vm| vm.roots().total_count()).unwrap(), roots);
    assert_eq!(unsafe { lua_rawgetp(state, -1, std::ptr::null()) }, 4);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 0) };
}

#[test]
fn raw_table_cross_vm_and_stale_object_cannot_enter_key_slot() {
    let owner = StateOwner::new().unwrap();
    let foreign = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    unsafe { lua_createtable(state, 0, 0) };
    let table = only_rooted_table(&owner);
    let foreign_key = foreign.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let stale_key = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(stale_key)).unwrap(),
        Err(VmError::StaleObject)
    );
    let before = ledger(&owner);
    assert_eq!(
        owner.push_value(Value::Object(foreign_key)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    assert_eq!(
        owner.push_value(Value::Object(stale_key)),
        Err(StackError::Runtime(VmError::StaleObject))
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(ledger(&owner), before);
    assert_eq!(
        owner
            .with_vm(|vm| vm.raw_get(table, Value::Integer(1)))
            .unwrap(),
        Ok(Value::Nil)
    );
}

#[test]
fn compare_a47_raw_subset_matrix() {
    const LUA_OPEQ: c_int = 0;
    const LUA_OPLT: c_int = 1;
    const LUA_OPLE: c_int = 2;

    let registry_index = if cfg!(feature = "lua55") {
        -(c_int::MAX / 2 + 1000)
    } else {
        -1_001_000
    };
    let other_profile_registry = if cfg!(feature = "lua55") {
        -1_001_000
    } else {
        -(c_int::MAX / 2 + 1000)
    };

    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new_with_vm_setup(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(mode).unwrap();
        })
        .unwrap();
        let state = owner.as_ptr();
        let mut pointer_token = 13_u8;
        let pointer = (&mut pointer_token as *mut u8).cast::<c_void>();
        let other_pointer = pointer.wrapping_add(1);
        // SAFETY：owner 保活 state；位址只當 lightuserdata 值且不解參照；closure callback 不執行。
        unsafe {
            lua_pushnil(state);
            lua_pushnil(state);
            lua_pushboolean(state, 1);
            lua_pushboolean(state, 0);
            lua_pushinteger(state, 7);
            lua_pushnumber(state, 7.0);
            lua_pushinteger(state, 9_007_199_254_740_993);
            lua_pushnumber(state, 9_007_199_254_740_992.0);
            lua_pushnumber(state, f64::NAN);
            lua_pushnumber(state, f64::NAN);
            lua_pushnumber(state, 0.0);
            lua_pushnumber(state, -0.0);
            lua_pushlstring(state, b"a\0b".as_ptr().cast(), 3);
            lua_pushlstring(state, b"a\0b".as_ptr().cast(), 3);
            lua_pushlstring(state, b"a\0c".as_ptr().cast(), 3);
            lua_pushlightuserdata(state, pointer);
            lua_pushlightuserdata(state, pointer);
            lua_pushlightuserdata(state, other_pointer);
            lua_pushcclosure(state, Some(compare_a47_first), 0);
            lua_pushcclosure(state, Some(compare_a47_first), 0);
            lua_pushcclosure(state, Some(compare_a47_second), 0);
            lua_createtable(state, 0, 0);
            lua_pushvalue(state, 22);
            lua_createtable(state, 0, 0);
            assert!(!lua_newuserdatauv(state, 8, 0).is_null());
            lua_pushvalue(state, 25);
            assert!(!lua_newuserdatauv(state, 8, 0).is_null());
            lua_pushvalue(state, registry_index);
            lua_pushinteger(state, i64::MAX);
            lua_pushnumber(state, 9_223_372_036_854_775_808.0);
            lua_pushinteger(state, i64::MIN);
            lua_pushnumber(state, -9_223_372_036_854_775_808.0);
            lua_pushnumber(state, f64::INFINITY);
            lua_pushnumber(state, f64::NEG_INFINITY);
        }
        assert_eq!(unsafe { lua_gettop(state) }, 34);

        owner
            .with_vm(|vm| {
                for _ in 0..128 {
                    if vm.gc_trace().phase != GcPhase::Pause {
                        break;
                    }
                    vm.incremental_step(1).unwrap();
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            })
            .unwrap();

        for (left, right, expected) in [
            (1, 2, 1),
            (3, 3, 1),
            (3, 4, 0),
            (5, 6, 1),
            (7, 8, 0),
            (9, 9, 0),
            (9, 10, 0),
            (11, 12, 1),
            (13, 14, 1),
            (13, 15, 0),
            (16, 17, 1),
            (16, 18, 0),
            (19, 20, 1),
            (19, 21, 0),
            (22, 23, 1),
            (22, 24, 0),
            (25, 26, 1),
            (25, 27, 0),
            (28, 28, 1),
            (registry_index, 28, 1),
            (5, 4 - unsafe { lua_gettop(state) }, 1),
        ] {
            assert_compare_a47_pure(&owner, state, left, right, LUA_OPEQ, expected);
        }

        for (left, right, op, expected) in [
            (5, 6, LUA_OPLT, 0),
            (6, 5, LUA_OPLT, 0),
            (5, 6, LUA_OPLE, 1),
            (6, 5, LUA_OPLE, 1),
            (7, 8, LUA_OPLT, 0),
            (8, 7, LUA_OPLT, 1),
            (29, 30, LUA_OPLT, 1),
            (30, 29, LUA_OPLT, 0),
            (31, 32, LUA_OPLT, 0),
            (31, 32, LUA_OPLE, 1),
            (34, 31, LUA_OPLT, 1),
            (29, 33, LUA_OPLT, 1),
            (33, 33, LUA_OPLE, 1),
            (9, 10, LUA_OPLT, 0),
            (9, 10, LUA_OPLE, 0),
            (13, 14, LUA_OPLT, 0),
            (13, 14, LUA_OPLE, 1),
            (13, 15, LUA_OPLT, 1),
            (13, 15, LUA_OPLE, 1),
        ] {
            assert_compare_a47_pure(&owner, state, left, right, op, expected);
        }

        let top = unsafe { lua_gettop(state) };
        for index in [
            0,
            top + 1,
            -top - 1,
            registry_index - 1,
            registry_index + 1,
            other_profile_registry,
        ] {
            for op in [LUA_OPEQ, LUA_OPLT, LUA_OPLE] {
                assert_compare_a47_pure(&owner, state, index, 5, op, 0);
            }
        }

        // 需拋 Lua 錯誤的型別與無效 opcode 由固定 header C fixture 的
        // 純 C checkpoint 覆蓋，避免錯誤 longjmp 穿越 Rust 測試 frame。
        // SAFETY：owner 保活 state；正常比較後原始值仍在原 stack slot。
        unsafe { assert_eq!(lua_rawequal(state, 7, 8), 0) };
    }
}
