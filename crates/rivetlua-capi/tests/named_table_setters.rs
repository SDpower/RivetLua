use std::ffi::{CString, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_getfield, lua_getglobal, lua_gettop,
    lua_pushboolean, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil,
    lua_pushnumber, lua_pushvalue, lua_setfield, lua_setglobal, lua_settop, lua_tointegerx,
    lua_type,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, GcAge, GcColor, GcMode, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, Vm, VmError,
};

unsafe extern "C" {
    fn rivetlua_capi_test_prime_a4a(state: *mut lua_State);
    fn rivetlua_capi_test_public_protected_a4a(
        state: *mut lua_State,
        operation: i32,
        index: i32,
        name: *const i8,
        key: i64,
        entries: *const c_void,
        nup: i32,
        inject_offset: i32,
        injection_start: *mut u64,
    ) -> i32;
}

fn protected_set(
    owner: &StateOwner,
    operation: i32,
    index: i32,
    name: *const i8,
    inject_offset: i32,
) -> (i32, u64) {
    let mut start = 0;
    // SAFETY：測試夾具於 C callback 的 lua_pcall 內執行 setter。
    let status = unsafe {
        rivetlua_capi_test_public_protected_a4a(
            owner.as_ptr(),
            operation,
            index,
            name,
            0,
            std::ptr::null(),
            0,
            inject_offset,
            &mut start,
        )
    };
    (status, start)
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
type Snapshot = (LedgerSnapshot, GcTrace, Roots);

fn snapshot(owner: &StateOwner) -> Snapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap()
}

fn only_added_host(before: &Roots, after: &Roots) -> ObjectRef {
    let added: Vec<_> = after
        .iter()
        .filter(|(kind, id, _)| {
            *kind == RootKind::Host && !before.iter().any(|(_, old, _)| old == id)
        })
        .map(|(_, _, object)| *object)
        .collect();
    assert_eq!(added.len(), 1);
    added[0]
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).2;
    // SAFETY：owner 持有有效 state。
    unsafe { lua_createtable(owner.as_ptr(), 0, 0) };
    only_added_host(&before, &snapshot(owner).2)
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

fn globals(vm: &Vm) -> ObjectRef {
    let Value::Object(object) = vm.raw_get(registry(vm), Value::Integer(2)).unwrap() else {
        panic!()
    };
    assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
    object
}

fn raw_name(owner: &StateOwner, table: ObjectRef, name: &[u8]) -> Value {
    owner
        .with_vm(|vm| {
            vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
                .unwrap()
        })
        .unwrap()
}

fn field(owner: &StateOwner, index: i32, name: &CString) {
    // SAFETY：owner 與 C 字串在本次呼叫期間有效；index 可無效，入口應 fail-closed。
    unsafe { lua_setfield(owner.as_ptr(), index, name.as_ptr()) };
}

fn global(owner: &StateOwner, name: &CString) {
    // SAFETY：owner 與 C 字串在本次呼叫期間有效。
    unsafe { lua_setglobal(owner.as_ptr(), name.as_ptr()) };
}

fn field_global_registry_and_names() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let global_table = owner.with_vm(|vm| globals(vm)).unwrap();
    let registry_table = owner.with_vm(|vm| registry(vm)).unwrap();
    let answer = CString::new("answer").unwrap();
    unsafe { lua_pushinteger(state, 11) };
    global(&owner, &answer);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(
        raw_name(&owner, global_table, b"answer"),
        Value::Integer(11)
    );
    let sibling = owner.new_sibling().unwrap();
    assert_eq!(
        unsafe { lua_getglobal(sibling.as_ptr(), answer.as_ptr()) },
        3
    );
    assert_eq!(
        unsafe { lua_tointegerx(sibling.as_ptr(), -1, std::ptr::null_mut()) },
        11
    );
    unsafe { lua_settop(sibling.as_ptr(), 0) };
    let other = StateOwner::new().unwrap();
    assert_eq!(unsafe { lua_getglobal(other.as_ptr(), answer.as_ptr()) }, 0);
    unsafe { lua_settop(other.as_ptr(), 0) };

    unsafe { lua_pushinteger(state, 12) };
    field(&owner, -2, &answer);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(raw_name(&owner, table, b"answer"), Value::Integer(12));
    unsafe { lua_pushinteger(state, 13) };
    field(&owner, REGISTRY_INDEX, &answer);
    assert_eq!(
        raw_name(&owner, registry_table, b"answer"),
        Value::Integer(13)
    );

    let redirected = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(global_table)).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(registry_table, Value::Integer(2), Value::Object(redirected))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushinteger(state, 18) };
    global(&owner, &CString::new("redirected").unwrap());
    assert_eq!(
        raw_name(&owner, redirected, b"redirected"),
        Value::Integer(18)
    );
    assert_eq!(raw_name(&owner, global_table, b"redirected"), Value::Nil);
    owner
        .with_vm(|vm| {
            vm.raw_set(
                registry_table,
                Value::Integer(2),
                Value::Object(global_table),
            )
            .unwrap()
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };

    unsafe { lua_pushinteger(state, 14) };
    field(&owner, 1, &answer);
    assert_eq!(raw_name(&owner, table, b"answer"), Value::Integer(14));
    unsafe { lua_pushnil(state) };
    field(&owner, 1, &answer);
    assert_eq!(raw_name(&owner, table, b"answer"), Value::Nil);
    unsafe { lua_pushnil(state) };
    field(&owner, 1, &answer);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    // 公開 field API 在送入 VM 前實體化短字串名稱；回收後 ledger 回到基線。
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();

    let empty = CString::new("").unwrap();
    unsafe { lua_pushinteger(state, 15) };
    global(&owner, &empty);
    assert_eq!(raw_name(&owner, global_table, b""), Value::Integer(15));
    let embedded = b"prefix\0ignored\0";
    unsafe {
        lua_pushinteger(state, 16);
        lua_setfield(state, 1, embedded.as_ptr().cast());
    }
    assert_eq!(raw_name(&owner, table, b"prefix"), Value::Integer(16));
    assert_eq!(raw_name(&owner, table, b"prefix\0ignored"), Value::Nil);
    let long = CString::new(vec![b'q'; 256]).unwrap();
    unsafe { lua_pushinteger(state, 17) };
    field(&owner, 1, &long);
    assert_eq!(raw_name(&owner, table, long.as_bytes()), Value::Integer(17));
    unsafe { lua_settop(state, 0) };
}

fn values_aliases_and_metamethod_limit() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let global_table = owner.with_vm(|vm| globals(vm)).unwrap();
    let name = CString::new("value").unwrap();
    let mut pointer = 9_u8;
    unsafe {
        lua_pushnil(state);
        lua_setfield(state, 1, name.as_ptr());
        lua_pushboolean(state, 1);
        lua_setfield(state, 1, name.as_ptr());
    }
    assert_eq!(raw_name(&owner, table, b"value"), Value::Boolean(true));
    unsafe {
        lua_pushinteger(state, 41);
        lua_setfield(state, 1, name.as_ptr());
        lua_pushnumber(state, 1.25);
        lua_setfield(state, 1, name.as_ptr());
    }
    assert_eq!(raw_name(&owner, table, b"value"), Value::Float(1.25));
    unsafe {
        lua_pushlightuserdata(state, (&mut pointer as *mut u8).cast::<c_void>());
        lua_setfield(state, 1, name.as_ptr());
        lua_pushlstring(state, b"payload".as_ptr().cast(), 7);
        lua_setfield(state, 1, name.as_ptr());
    }
    let string = raw_name(&owner, table, b"value");
    assert!(
        matches!(string, Value::Object(object) if owner.with_vm(|vm| vm.object_kind(object)).unwrap() == Ok(ObjectKind::ByteString))
    );

    let value_table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(value_table)).unwrap();
    field(&owner, 1, &name);
    assert_eq!(
        raw_name(&owner, table, b"value"),
        Value::Object(value_table)
    );
    let builtin = owner
        .with_vm(|vm| {
            vm.install_error_builtins(global_table).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(global_table, Value::Object(key)).unwrap()
        })
        .unwrap();
    owner.push_value(builtin).unwrap();
    field(&owner, 1, &name);
    assert_eq!(raw_name(&owner, table, b"value"), builtin);
    let coroutine = owner
        .with_vm(|vm| vm.new_coroutine(builtin).unwrap())
        .unwrap();
    let coroutine_value = owner.with_vm(|vm| coroutine.as_value(vm).unwrap()).unwrap();
    owner.push_value(coroutine_value).unwrap();
    field(&owner, 1, &name);
    assert_eq!(raw_name(&owner, table, b"value"), coroutine_value);
    drop(coroutine);

    unsafe { lua_pushvalue(state, 1) };
    field(&owner, -2, &CString::new("self").unwrap());
    assert_eq!(raw_name(&owner, table, b"self"), Value::Object(table));
    owner.push_value(Value::Object(global_table)).unwrap();
    global(&owner, &CString::new("self").unwrap());
    assert_eq!(
        raw_name(&owner, global_table, b"self"),
        Value::Object(global_table)
    );
    owner.push_value(Value::Object(reg)).unwrap();
    field(&owner, REGISTRY_INDEX, &CString::new("self").unwrap());
    assert_eq!(raw_name(&owner, reg, b"self"), Value::Object(reg));
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    let mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let fallback = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            let event = vm.allocate_byte_string(b"__newindex").unwrap();
            vm.raw_set(mt, Value::Object(event), Value::Object(fallback))
                .unwrap();
            vm.set_metatable(table, Some(mt)).unwrap();
        })
        .unwrap();
    let absent = CString::new("absent").unwrap();
    unsafe { lua_pushinteger(state, 51) };
    field(&owner, 1, &absent);
    assert_eq!(raw_name(&owner, table, b"absent"), Value::Nil);
    assert_eq!(raw_name(&owner, fallback, b"absent"), Value::Integer(51));
    owner
        .with_vm(|vm| {
            let event = vm.allocate_byte_string(b"__newindex").unwrap();
            vm.raw_set(mt, Value::Object(event), builtin).unwrap();
        })
        .unwrap();
    unsafe { lua_pushinteger(state, 52) };
    assert_eq!(protected_set(&owner, 5, 1, c"other".as_ptr(), -1).0, -2);
    assert_eq!(raw_name(&owner, table, b"other"), Value::Nil);
    owner
        .with_vm(|vm| vm.set_metatable(global_table, Some(mt)).unwrap())
        .unwrap();
    unsafe { lua_pushinteger(state, 53) };
    assert_eq!(
        protected_set(&owner, 7, 0, c"global-direct".as_ptr(), -1).0,
        -2
    );
    assert_eq!(raw_name(&owner, global_table, b"global-direct"), Value::Nil);
    assert_eq!(unsafe { lua_gettop(state) }, 3);
    unsafe { lua_settop(state, 0) };
}

fn invalid_and_fail_closed() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let global_table = owner.with_vm(|vm| globals(vm)).unwrap();
    let name = CString::new("invalid").unwrap();
    unsafe { lua_settop(state, 0) };
    let empty = snapshot(&owner);
    assert_eq!(protected_set(&owner, 7, 0, name.as_ptr(), -1).0, -2);
    assert_eq!(
        protected_set(&owner, 5, REGISTRY_INDEX, name.as_ptr(), -1).0,
        -2
    );
    assert_eq!(snapshot(&owner).2, empty.2);

    owner.push_value(Value::Object(table)).unwrap();
    unsafe {
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 61);
    }
    let before = snapshot(&owner);
    for index in [0, 2, 3, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert_eq!(protected_set(&owner, 5, index, name.as_ptr(), -1).0, -2);
        assert_eq!(unsafe { lua_gettop(state) }, 3);
        assert_eq!(snapshot(&owner).2, before.2);
    }
    assert_eq!(unsafe { lua_type(state, 2) }, 1);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        61
    );
    assert_eq!(raw_name(&owner, table, b"invalid"), Value::Nil);
    assert_eq!(raw_name(&owner, global_table, b"invalid"), Value::Nil);
    unsafe { lua_settop(state, 1) };

    owner
        .with_vm(|vm| {
            vm.raw_set(reg, Value::Integer(2), Value::Integer(4))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushinteger(state, 62) };
    let before = snapshot(&owner);
    assert_eq!(protected_set(&owner, 7, 0, name.as_ptr(), -1).0, -2);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(snapshot(&owner).2, before.2);
    owner
        .with_vm(|vm| {
            vm.raw_set(reg, Value::Integer(2), Value::Object(global_table))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };
}

fn publication_and_immediate_cleanup() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let name = CString::new("published").unwrap();
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    field(&owner, 1, &name);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Ok(ObjectKind::Table)
    );
    assert_eq!(unsafe { lua_getfield(state, 1, name.as_ptr()) }, 5);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 1) };

    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    let before = snapshot(&owner);
    owner.push_value(Value::Object(value)).unwrap();
    field(&owner, 1, &name);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(snapshot(&owner).0, before.0);
    assert_eq!(snapshot(&owner).2, before.2);
    let absent = CString::new("absent").unwrap();
    unsafe { lua_pushnil(state) };
    field(&owner, 1, &absent);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(snapshot(&owner).0, before.0);
    assert_eq!(snapshot(&owner).2, before.2);
    unsafe { lua_pushnil(state) };
    field(&owner, 1, &name);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(raw_name(&owner, table, b"published"), Value::Nil);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );
}

fn incremental_publication_and_generational_rollback() {
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
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(value)).unwrap(),
        Ok(GcColor::White)
    );
    owner.push_value(Value::Object(value)).unwrap();
    assert_ne!(
        owner.with_vm(|vm| vm.gc_color(value)).unwrap(),
        Ok(GcColor::White)
    );
    let phase = owner.with_vm(|vm| vm.gc_trace().phase).unwrap();
    field(&owner, 1, &CString::new("incremental").unwrap());
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().phase).unwrap(), phase);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        })
        .unwrap();
    assert_eq!(
        raw_name(&owner, table, b"incremental"),
        Value::Object(value)
    );

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
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    let name = CString::new("young").unwrap();
    assert_eq!(protected_set(&owner, 5, 1, name.as_ptr(), -1).0, -4);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(raw_name(&owner, table, b"young"), Value::Nil);
    // 一次性故障已耗用；第一次保留的 value slot 在此重試後才可 pop。
    field(&owner, 1, &name);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        })
        .unwrap();
    assert_eq!(raw_name(&owner, table, b"young"), Value::Object(value));
}

fn weak_byte_key_modes() {
    for mode in [b"k".as_slice(), b"v", b"kv"] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let table = add_table(&owner);
        let mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner
            .with_vm(|vm| {
                let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
                let mode_value = vm.allocate_byte_string(mode).unwrap();
                vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode_value))
                    .unwrap();
                vm.set_metatable(table, Some(mt)).unwrap();
            })
            .unwrap();
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        field(&owner, 1, &CString::new("weak").unwrap());
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        if mode == b"k" {
            assert_eq!(raw_name(&owner, table, b"weak"), Value::Object(value));
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
                Ok(ObjectKind::Table)
            );
        } else {
            assert_eq!(raw_name(&owner, table, b"weak"), Value::Nil);
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
                Err(VmError::StaleObject)
            );
        }
    }
}

fn insertion_fault_matrix() {
    let mut failed = Vec::new();
    for offset in 0..25 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { rivetlua_capi_test_prime_a4a(state) };
        let table = add_table(&owner);
        owner
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
            })
            .unwrap();
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        let before = snapshot(&owner);
        let name = CString::new("ordinal").unwrap();
        let (status, start) = protected_set(&owner, 5, 1, name.as_ptr(), offset as i32);
        if status == -4 {
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            assert_eq!(snapshot(&owner).2, before.2);
            assert_eq!(unsafe { lua_type(state, -1) }, 5);
            assert_eq!(
                owner
                    .with_vm(|vm| vm.with_table(table, |stored| stored.is_empty()))
                    .unwrap(),
                Ok(true)
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.attempt.ordinal, start + offset);
            failed.push((
                offset,
                failure.attempt.domain,
                failure.attempt.point,
                failure.attempt.site.file,
            ));
        } else {
            panic!("setter offset {offset} returned {status}");
        }
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
            .unwrap();
        field(&owner, 1, &name);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        owner
            .with_vm(|vm| {
                while vm.gc_trace().phase != GcPhase::Pause {
                    vm.incremental_step(1024).unwrap();
                }
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
            })
            .unwrap();
        assert_eq!(raw_name(&owner, table, b"ordinal"), Value::Object(value));
    }
    use AllocationDomain::{Host, LuaHeap};
    assert_eq!(
        failed
            .iter()
            .map(|(_, domain, point, _)| (*domain, *point))
            .collect::<Vec<_>>(),
        vec![
            (Host, None),
            (Host, None),
            (LuaHeap, Some(FailPoint::StringBytesReserve)),
            (LuaHeap, Some(FailPoint::SlotReserve)),
            (LuaHeap, Some(FailPoint::ObjectReserve)),
            (Host, Some(FailPoint::MarkReserve)),
            (Host, None),
            (Host, None),
            (Host, None),
            (Host, Some(FailPoint::WorkReserve)),
            (Host, Some(FailPoint::WorkReserve)),
            (Host, None),
            (Host, None),
            (Host, None),
            (Host, Some(FailPoint::FrameRegistersReserve)),
            (Host, Some(FailPoint::FrameRootsReserve)),
            (Host, Some(FailPoint::FrameRegistersReserve)),
            (Host, Some(FailPoint::FrameRootsReserve)),
            (Host, None),
            (Host, None),
            (Host, None),
            (Host, Some(FailPoint::CallFrameReserve)),
            (Host, Some(FailPoint::WorkReserve)),
            (LuaHeap, Some(FailPoint::TableHashGrow)),
            (Host, Some(FailPoint::RememberedReserve)),
        ]
    );

    for point in [
        FailPoint::RootReserve,
        FailPoint::StringBytesReserve,
        FailPoint::SlotReserve,
        FailPoint::ObjectReserve,
        FailPoint::TableHashGrow,
        FailPoint::TableRehash,
        FailPoint::TableInsert,
        FailPoint::RememberedReserve,
    ] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { rivetlua_capi_test_prime_a4a(state) };
        let table = add_table(&owner);
        owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_promotion_survivals(1).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
            })
            .unwrap();
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        let before = snapshot(&owner);
        let code = match point {
            FailPoint::RootReserve => 3,
            FailPoint::StringBytesReserve => 6,
            FailPoint::SlotReserve => 0,
            FailPoint::ObjectReserve => 1,
            FailPoint::TableHashGrow => 7,
            FailPoint::TableRehash => 8,
            FailPoint::TableInsert => 9,
            FailPoint::RememberedReserve => 12,
            _ => unreachable!(),
        };
        assert_eq!(
            protected_set(&owner, 5, 1, c"point".as_ptr(), -2 - code).0,
            -4
        );
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_table(table, |stored| stored.is_empty()))
                .unwrap(),
            Ok(true)
        );
        field(&owner, 1, &CString::new("point").unwrap());
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        assert_eq!(raw_name(&owner, table, b"point"), Value::Object(value));
    }
}

fn replacement_delete_noop_fault_matrix() {
    fn setup(action: i32) -> (StateOwner, ObjectRef, CString) {
        let owner = StateOwner::new().unwrap();
        unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
        let table = add_table(&owner);
        let name = CString::new("existing").unwrap();
        if action != 2 {
            owner.push_value(Value::Integer(1)).unwrap();
            field(&owner, 1, &name);
        }
        owner
            .push_value(if action == 0 {
                Value::Integer(2)
            } else {
                Value::Nil
            })
            .unwrap();
        (owner, table, name)
    }
    for action in [0, 1, 2] {
        let mut failed = Vec::new();
        let (probe, _, probe_name) = setup(action);
        let attempts = protected_set(&probe, 5, 1, probe_name.as_ptr(), -1000).0;
        assert!(attempts > 0);
        for offset in 0..attempts {
            let (owner, table, name) = setup(action);
            let state = owner.as_ptr();
            let before = snapshot(&owner);
            let expected = if action == 2 {
                Value::Nil
            } else {
                Value::Integer(1)
            };
            let (status, start) = protected_set(&owner, 5, 1, name.as_ptr(), offset);
            assert_eq!(status, -4, "action={action};offset={offset}");
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            assert_eq!(snapshot(&owner).2, before.2);
            assert_eq!(raw_name(&owner, table, b"existing"), expected);
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.attempt.ordinal, start + offset as u64);
            failed.push((offset, failure.attempt.point));
            field(&owner, 1, &name);
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            assert_eq!(
                raw_name(&owner, table, b"existing"),
                if action == 0 {
                    Value::Integer(2)
                } else {
                    Value::Nil
                }
            );
        }
        assert_eq!(attempts, 19, "action={action}");
        assert_eq!(
            failed.iter().map(|(_, point)| *point).collect::<Vec<_>>(),
            vec![
                None,
                None,
                Some(FailPoint::StringBytesReserve),
                Some(FailPoint::SlotReserve),
                Some(FailPoint::ObjectReserve),
                None,
                None,
                Some(FailPoint::WorkReserve),
                Some(FailPoint::WorkReserve),
                None,
                None,
                Some(FailPoint::FrameRegistersReserve),
                Some(FailPoint::FrameRootsReserve),
                Some(FailPoint::FrameRegistersReserve),
                Some(FailPoint::FrameRootsReserve),
                None,
                None,
                Some(FailPoint::CallFrameReserve),
                Some(FailPoint::WorkReserve),
            ]
        );
    }
}

#[test]
fn named_table_setters_a23_matrix() {
    field_global_registry_and_names();
    values_aliases_and_metamethod_limit();
    invalid_and_fail_closed();
    publication_and_immediate_cleanup();
    incremental_publication_and_generational_rollback();
    weak_byte_key_modes();
    insertion_fault_matrix();
    replacement_delete_noop_fault_matrix();
}
