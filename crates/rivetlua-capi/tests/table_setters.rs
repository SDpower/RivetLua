use std::ffi::c_void;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_pushvalue, lua_seti,
    lua_settable, lua_settop, lua_tointegerx, lua_type,
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
    key: i64,
    inject_offset: i32,
) -> (i32, u64) {
    let mut start = 0;
    // SAFETY：測試夾具於 C callback 的 lua_pcall 內執行 setter。
    let status = unsafe {
        rivetlua_capi_test_public_protected_a4a(
            owner.as_ptr(),
            operation,
            index,
            std::ptr::null(),
            key,
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

fn raw(owner: &StateOwner, table: ObjectRef, key: Value) -> Value {
    owner.with_vm(|vm| vm.raw_get(table, key).unwrap()).unwrap()
}

fn settable(owner: &StateOwner, index: i32) {
    // SAFETY：owner 持有有效 state；index 可無效，入口必 fail-closed。
    unsafe { lua_settable(owner.as_ptr(), index) };
}

fn seti(owner: &StateOwner, index: i32, key: i64) {
    // SAFETY：owner 持有有效 state；index 可無效，入口必 fail-closed。
    unsafe { lua_seti(owner.as_ptr(), index, key) };
}

fn basic_keys_values_and_stack() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    unsafe {
        lua_pushinteger(state, 1);
        lua_pushinteger(state, 11);
    }
    settable(&owner, -3);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Integer(11));
    unsafe {
        lua_pushnumber(state, 1.0);
        lua_pushinteger(state, 12);
    }
    settable(&owner, 1);
    assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Integer(12));
    unsafe {
        lua_pushnumber(state, 1.0);
        lua_pushnil(state);
    }
    settable(&owner, -3);
    assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Nil);

    let mut pointer = 4_u8;
    let keys = [
        Value::Boolean(true),
        Value::LightUserdata((&mut pointer as *mut u8).addr()),
        Value::Float(1.25),
    ];
    for (ordinal, key) in keys.into_iter().enumerate() {
        owner.push_value(key).unwrap();
        owner.push_value(Value::Integer(ordinal as i64)).unwrap();
        settable(&owner, 1);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        assert_eq!(raw(&owner, table, key), Value::Integer(ordinal as i64));
    }
    unsafe {
        lua_pushlightuserdata(state, (&mut pointer as *mut u8).cast::<c_void>());
        lua_pushinteger(state, 70);
    }
    settable(&owner, 1);
    assert_eq!(
        raw(
            &owner,
            table,
            Value::LightUserdata((&mut pointer as *mut u8).addr())
        ),
        Value::Integer(70)
    );
    unsafe {
        lua_pushlstring(state, b"bytes".as_ptr().cast(), 5);
        lua_pushinteger(state, 71);
    }
    settable(&owner, 1);
    let bytes = owner
        .with_vm(|vm| vm.allocate_byte_string(b"bytes").unwrap())
        .unwrap();
    assert_eq!(raw(&owner, table, Value::Object(bytes)), Value::Integer(71));

    let key = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Integer(72)).unwrap();
    settable(&owner, 1);
    assert_eq!(raw(&owner, table, Value::Object(key)), Value::Integer(72));
    unsafe {
        lua_pushvalue(state, 1);
        lua_pushvalue(state, 1);
    }
    settable(&owner, -3);
    assert_eq!(
        raw(&owner, table, Value::Object(table)),
        Value::Object(table)
    );

    for number in [0, -1, i64::MIN, i64::MAX] {
        owner.push_value(Value::Integer(number)).unwrap();
        seti(&owner, -2, number);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        assert_eq!(
            raw(&owner, table, Value::Integer(number)),
            Value::Integer(number)
        );
        owner.push_value(Value::Nil).unwrap();
        seti(&owner, 1, number);
        assert_eq!(raw(&owner, table, Value::Integer(number)), Value::Nil);
    }

    let builtin = owner
        .with_vm(|vm| {
            let reg = registry(vm);
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            let name = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(globals, Value::Object(name)).unwrap()
        })
        .unwrap();
    let coroutine = owner
        .with_vm(|vm| vm.new_coroutine(builtin).unwrap())
        .unwrap();
    let coroutine_value = owner.with_vm(|vm| coroutine.as_value(vm).unwrap()).unwrap();
    let string = owner
        .with_vm(|vm| vm.allocate_byte_string(b"value").unwrap())
        .unwrap();
    let value_table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let values = [
        Value::Nil,
        Value::Boolean(false),
        Value::Integer(9),
        Value::Float(2.5),
        Value::LightUserdata((&mut pointer as *mut u8).addr()),
        Value::Object(string),
        Value::Object(value_table),
        builtin,
        coroutine_value,
    ];
    for value in values {
        owner.push_value(value).unwrap();
        seti(&owner, 1, 100);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        assert_eq!(raw(&owner, table, Value::Integer(100)), value);
    }
    drop(coroutine);
    unsafe { lua_settop(state, 0) };
}

fn registry_alias_and_metamethod_limit() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    unsafe {
        lua_pushinteger(state, 501);
        lua_pushinteger(state, 502);
    }
    settable(&owner, REGISTRY_INDEX);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(raw(&owner, reg, Value::Integer(501)), Value::Integer(502));
    owner.push_value(Value::Boolean(true)).unwrap();
    seti(&owner, REGISTRY_INDEX, 503);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(raw(&owner, reg, Value::Integer(503)), Value::Boolean(true));

    unsafe {
        lua_pushinteger(state, 601);
        lua_pushvalue(state, 1);
    }
    settable(&owner, -3);
    assert_eq!(
        raw(&owner, table, Value::Integer(601)),
        Value::Object(table)
    );
    unsafe { lua_pushvalue(state, 1) };
    seti(&owner, -2, 602);
    assert_eq!(
        raw(&owner, table, Value::Integer(602)),
        Value::Object(table)
    );
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
    owner.push_value(Value::Integer(701)).unwrap();
    owner.push_value(Value::Integer(702)).unwrap();
    settable(&owner, 1);
    assert_eq!(raw(&owner, table, Value::Integer(701)), Value::Nil);
    assert_eq!(
        raw(&owner, fallback, Value::Integer(701)),
        Value::Integer(702)
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);
}

fn invalid_and_boundary_calls() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let empty = snapshot(&owner);
    assert_eq!(protected_set(&owner, 4, REGISTRY_INDEX, 0, -1).0, -2);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(snapshot(&owner).2, empty.2);
    unsafe { lua_settop(state, 0) };
    let empty = snapshot(&owner);
    assert_eq!(protected_set(&owner, 6, REGISTRY_INDEX, 1, -1).0, -2);
    assert_eq!(protected_set(&owner, 4, REGISTRY_INDEX, 0, -1).0, -2);
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    assert_eq!(snapshot(&owner).2, empty.2);
    owner.push_value(Value::Object(table)).unwrap();
    unsafe {
        lua_pushinteger(state, 801);
        lua_pushinteger(state, 802);
    }
    let before = snapshot(&owner);
    for index in [0, 2, 3, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert_eq!(protected_set(&owner, 4, index, 0, -1).0, -2);
        assert_eq!(protected_set(&owner, 6, index, 803, -1).0, -2);
        assert_eq!(unsafe { lua_gettop(state) }, 3);
        assert_eq!(snapshot(&owner).2, before.2);
    }
    assert_eq!(raw(&owner, table, Value::Integer(801)), Value::Nil);
    assert_eq!(
        unsafe { lua_tointegerx(state, -2, std::ptr::null_mut()) },
        801
    );
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        802
    );
    unsafe { lua_settop(state, 1) };

    for nan in [false, true] {
        if nan {
            unsafe { lua_pushnumber(state, f64::NAN) };
        } else {
            unsafe { lua_pushnil(state) };
        }
        unsafe { lua_pushinteger(state, 804) };
        let before = snapshot(&owner);
        assert_eq!(protected_set(&owner, 4, 1, 0, -1).0, -2);
        assert_eq!(unsafe { lua_gettop(state) }, 3);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(unsafe { lua_type(state, -2) }, if nan { 3 } else { 0 });
        assert_eq!(raw(&owner, table, Value::Integer(804)), Value::Nil);
        unsafe { lua_settop(state, 1) };
    }

    unsafe {
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 805);
        lua_pushinteger(state, 806);
    }
    let before = snapshot(&owner);
    assert_eq!(protected_set(&owner, 4, 2, 0, -1).0, -2);
    assert_eq!(protected_set(&owner, 6, 2, 807, -1).0, -2);
    assert_eq!(unsafe { lua_gettop(state) }, 4);
    assert_eq!(snapshot(&owner).2, before.2);
    unsafe { lua_settop(state, 1) };
}

fn object_edges_and_collection() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let (key, value) = owner
        .with_vm(|vm| (vm.allocate_table().unwrap(), vm.allocate_table().unwrap()))
        .unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    settable(&owner, -3);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Ok(ObjectKind::Table)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Ok(ObjectKind::Table)
    );
    assert_eq!(raw(&owner, table, Value::Object(key)), Value::Object(value));
    owner.push_value(Value::Object(key)).unwrap();
    unsafe { lua_pushnil(state) };
    settable(&owner, -3);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );
}

fn incremental_root_and_barrier() {
    let owner = StateOwner::new().unwrap();
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
    let (key, value) = owner
        .with_vm(|vm| (vm.allocate_table().unwrap(), vm.allocate_table().unwrap()))
        .unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(key)).unwrap(),
        Ok(GcColor::White)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(value)).unwrap(),
        Ok(GcColor::White)
    );
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    assert_ne!(
        owner.with_vm(|vm| vm.gc_color(key)).unwrap(),
        Ok(GcColor::White)
    );
    assert_ne!(
        owner.with_vm(|vm| vm.gc_color(value)).unwrap(),
        Ok(GcColor::White)
    );
    let phase = owner.with_vm(|vm| vm.gc_trace().phase).unwrap();
    settable(&owner, -3);
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().phase).unwrap(), phase);
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(key), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        })
        .unwrap();
    assert_eq!(raw(&owner, table, Value::Object(key)), Value::Object(value));
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Nil).unwrap();
    settable(&owner, 1);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Err(VmError::StaleObject)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );
}

fn generational_remembered_reserve() {
    for integer_key in [false, true] {
        let owner = StateOwner::new().unwrap();
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
        let key = (!integer_key).then(|| owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap());
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        if let Some(key) = key {
            owner.push_value(Value::Object(key)).unwrap();
        }
        owner.push_value(Value::Object(value)).unwrap();
        let top = if integer_key { 2 } else { 3 };
        let before = snapshot(&owner);
        assert_eq!(
            protected_set(
                &owner,
                if integer_key { 6 } else { 4 },
                if integer_key { -2 } else { -3 },
                1,
                -2 - 12
            )
            .0,
            -4
        );
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, top);
        assert_eq!(snapshot(&owner).2, before.2);
        let raw_key = key.map_or(Value::Integer(1), Value::Object);
        assert_eq!(raw(&owner, table, raw_key), Value::Nil);
        if integer_key {
            seti(&owner, -2, 1);
        } else {
            settable(&owner, -3);
        }
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
        owner
            .with_vm(|vm| {
                vm.collect_minor().unwrap();
                assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
                if let Some(key) = key {
                    assert_eq!(vm.object_kind(key), Ok(ObjectKind::Table));
                }
            })
            .unwrap();
        assert_eq!(raw(&owner, table, raw_key), Value::Object(value));
    }
}

fn weak_table_modes() {
    for mode in [b"k".as_slice(), b"v", b"kv"] {
        let owner = StateOwner::new().unwrap();
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
        let key = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(key)).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        settable(&owner, 1);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(raw(&owner, table, Value::Integer(0)), Value::Nil);
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_table(table, |stored| stored.is_empty()))
                .unwrap(),
            Ok(true)
        );
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
            Err(VmError::StaleObject)
        );
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
            if mode == b"v" {
                Ok(ObjectKind::Table)
            } else {
                Err(VmError::StaleObject)
            }
        );
    }

    let owner = StateOwner::new().unwrap();
    let table = add_table(&owner);
    let mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode_value = vm.allocate_byte_string(b"v").unwrap();
            vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode_value))
                .unwrap();
            vm.set_metatable(table, Some(mt)).unwrap();
        })
        .unwrap();
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    seti(&owner, 1, 4);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(raw(&owner, table, Value::Integer(4)), Value::Nil);
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Err(VmError::StaleObject)
    );

    let owner = StateOwner::new().unwrap();
    let table = add_table(&owner);
    let mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode_value = vm.allocate_byte_string(b"k").unwrap();
            vm.raw_set(mt, Value::Object(mode_key), Value::Object(mode_value))
                .unwrap();
            vm.set_metatable(table, Some(mt)).unwrap();
        })
        .unwrap();
    let key = owner
        .with_vm(|vm| vm.allocate_byte_string(b"weak-string").unwrap())
        .unwrap();
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    owner.push_value(Value::Object(value)).unwrap();
    settable(&owner, 1);
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(raw(&owner, table, Value::Object(key)), Value::Object(value));
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(key)).unwrap(),
        Ok(ObjectKind::ByteString)
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
        Ok(ObjectKind::Table)
    );
}

fn named_failpoint_matrix() {
    for point in [
        FailPoint::StringBytesReserve,
        FailPoint::TableHashGrow,
        FailPoint::TableRehash,
        FailPoint::TableInsert,
    ] {
        let owner = StateOwner::new().unwrap();
        let table = add_table(&owner);
        let key = owner
            .with_vm(|vm| vm.allocate_byte_string(b"named-fault").unwrap())
            .unwrap();
        let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(key)).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        let before = snapshot(&owner);
        let code = match point {
            FailPoint::StringBytesReserve => 6,
            FailPoint::TableHashGrow => 7,
            FailPoint::TableRehash => 8,
            FailPoint::TableInsert => 9,
            _ => unreachable!(),
        };
        assert_eq!(protected_set(&owner, 4, 1, 0, -2 - code).0, -4);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 3);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(raw(&owner, table, Value::Object(key)), Value::Nil);
        settable(&owner, 1);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert_eq!(raw(&owner, table, Value::Object(key)), Value::Object(value));
    }
    for point in [FailPoint::TableArrayGrow, FailPoint::TableInsert] {
        let owner = StateOwner::new().unwrap();
        let table = add_table(&owner);
        owner.push_value(Value::Integer(901)).unwrap();
        let before = snapshot(&owner);
        let code = match point {
            FailPoint::TableArrayGrow => 15,
            FailPoint::TableInsert => 9,
            _ => unreachable!(),
        };
        assert_eq!(protected_set(&owner, 6, 1, 1, -2 - code).0, -4);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 2);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Nil);
        seti(&owner, 1, 1);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Integer(901));
    }
}

fn allocation_ordinal_matrix() {
    fn hash_owner() -> (StateOwner, ObjectRef, ObjectRef, ObjectRef) {
        let owner = StateOwner::new().unwrap();
        unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
        let table = add_table(&owner);
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
                    vm.allocate_byte_string(b"ordinal-key").unwrap(),
                    vm.allocate_table().unwrap(),
                )
            })
            .unwrap();
        owner.push_value(Value::Object(key)).unwrap();
        owner.push_value(Value::Object(value)).unwrap();
        (owner, table, key, value)
    }
    fn array_owner() -> (StateOwner, ObjectRef) {
        let owner = StateOwner::new().unwrap();
        unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
        let table = add_table(&owner);
        owner.push_value(Value::Integer(902)).unwrap();
        (owner, table)
    }
    let mut hash_failures = Vec::new();
    let (probe, _, _, _) = hash_owner();
    let hash_attempts = protected_set(&probe, 4, -3, 0, -1000).0;
    assert!(hash_attempts > 0);
    for offset in 0..hash_attempts {
        let (owner, table, key, value) = hash_owner();
        let before = snapshot(&owner);
        let (status, start) = protected_set(&owner, 4, -3, 0, offset);
        assert_eq!(status, -4, "hash offset={offset}");
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 3);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(raw(&owner, table, Value::Object(key)), Value::Nil);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failure.attempt.ordinal, start + offset as u64);
        hash_failures.push((offset, failure.attempt.domain, failure.attempt.site.file));
        settable(&owner, -3);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert_eq!(raw(&owner, table, Value::Object(key)), Value::Object(value));
    }
    assert_eq!(hash_attempts, 21);
    assert_eq!(hash_failures.len(), 21);
    assert_eq!(
        hash_failures
            .iter()
            .map(|(_, domain, _)| *domain)
            .collect::<Vec<_>>(),
        [
            vec![AllocationDomain::Host; 15],
            vec![AllocationDomain::LuaHeap; 5],
            vec![AllocationDomain::Host]
        ]
        .concat()
    );
    assert_eq!(
        hash_failures
            .iter()
            .map(|(_, _, file)| file.rsplit('/').next().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "heap.rs",
            "pending_op.rs",
            "pending_op.rs",
            "roots.rs",
            "roots.rs",
            "roots.rs",
            "call.rs",
            "call.rs",
            "call.rs",
            "call.rs",
            "roots.rs",
            "roots.rs",
            "roots.rs",
            "mod.rs",
            "mod.rs",
            "string.rs",
            "table.rs",
            "string.rs",
            "table.rs",
            "table.rs",
            "heap.rs",
        ]
    );

    let mut array_failures = Vec::new();
    let (probe, _) = array_owner();
    let array_attempts = protected_set(&probe, 6, -2, 1, -1000).0;
    assert!(array_attempts > 0);
    for offset in 0..array_attempts {
        let (owner, table) = array_owner();
        let before = snapshot(&owner);
        let (status, start) = protected_set(&owner, 6, -2, 1, offset);
        assert_eq!(status, -4, "array offset={offset}");
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 2);
        assert_eq!(snapshot(&owner).2, before.2);
        assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Nil);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failure.attempt.ordinal, start + offset as u64);
        array_failures.push((offset, failure.attempt.domain, failure.attempt.site.file));
        seti(&owner, -2, 1);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert_eq!(raw(&owner, table, Value::Integer(1)), Value::Integer(902));
    }
    assert_eq!(array_attempts, 12);
    assert_eq!(array_failures.len(), 12);
    assert_eq!(
        array_failures
            .iter()
            .map(|(_, domain, _)| *domain)
            .collect::<Vec<_>>(),
        [
            vec![AllocationDomain::Host; 11],
            vec![AllocationDomain::LuaHeap]
        ]
        .concat()
    );
    assert_eq!(
        array_failures
            .iter()
            .map(|(_, _, file)| file.rsplit('/').next().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "heap.rs",
            "pending_op.rs",
            "pending_op.rs",
            "roots.rs",
            "call.rs",
            "call.rs",
            "call.rs",
            "call.rs",
            "roots.rs",
            "mod.rs",
            "mod.rs",
            "table.rs",
        ]
    );
}

fn replacement_delete_rollback() {
    for integer_key in [false, true] {
        for delete in [false, true] {
            let owner = StateOwner::new().unwrap();
            let table = add_table(&owner);
            let key = if integer_key {
                Value::Integer(1)
            } else {
                Value::Boolean(true)
            };
            owner
                .with_vm(|vm| vm.raw_set(table, key, Value::Integer(1)).unwrap())
                .unwrap();
            if !integer_key {
                owner.push_value(key).unwrap();
            }
            owner
                .push_value(if delete {
                    Value::Nil
                } else {
                    Value::Integer(2)
                })
                .unwrap();
            let before = snapshot(&owner);
            let (status, start) = protected_set(&owner, if integer_key { 6 } else { 4 }, 1, 1, 0);
            assert_eq!(status, -4);
            assert_eq!(
                unsafe { lua_gettop(owner.as_ptr()) },
                if integer_key { 2 } else { 3 }
            );
            assert_eq!(snapshot(&owner).2, before.2);
            assert_eq!(raw(&owner, table, key), Value::Integer(1));
            assert_eq!(
                owner
                    .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
                    .unwrap(),
                start
            );
            if integer_key {
                seti(&owner, 1, 1);
            } else {
                settable(&owner, 1);
            }
            assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
            assert_eq!(
                raw(&owner, table, key),
                if delete {
                    Value::Nil
                } else {
                    Value::Integer(2)
                }
            );
        }
    }
}

#[test]
fn table_setters_a22_matrix() {
    basic_keys_values_and_stack();
    registry_alias_and_metamethod_limit();
    invalid_and_boundary_calls();
    object_edges_and_collection();
    incremental_root_and_barrier();
    generational_remembered_reserve();
    weak_table_modes();
    named_failpoint_matrix();
    allocation_ordinal_matrix();
    replacement_delete_rollback();
}
