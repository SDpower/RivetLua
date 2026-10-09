use std::ffi::c_void;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_copy, lua_createtable, lua_getfield, lua_getglobal, lua_geti,
    lua_gettable, lua_gettop, lua_pushboolean, lua_pushinteger, lua_pushlightuserdata,
    lua_pushlstring, lua_pushnil, lua_pushnumber, lua_pushvalue, lua_rawequal, lua_setmetatable,
    lua_settop, lua_tointegerx, lua_tonumberx, lua_touserdata, lua_type,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, GcAge, GcColor, GcMode, GcPhase,
    GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind, Vm, VmError,
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

fn protected_get(
    owner: &StateOwner,
    operation: i32,
    index: i32,
    name: *const i8,
    key: i64,
    inject_offset: i32,
) -> (i32, u64) {
    let mut start = 0;
    // SAFETY：C 夾具在 lua_pcall callback 內呼叫 public getter，錯誤於 C frame 捕獲。
    let status = unsafe {
        rivetlua_capi_test_public_protected_a4a(
            owner.as_ptr(),
            operation,
            index,
            name,
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
    let prior = host_roots(before);
    let added: Vec<_> = host_roots(after)
        .into_iter()
        .filter(|(id, _)| !prior.iter().any(|(old, _)| old == id))
        .collect();
    assert_eq!(added.len(), 1);
    added[0].1
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).3;
    // SAFETY：owner 在整次呼叫期間持有有效 state。
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

fn globals(vm: &Vm) -> ObjectRef {
    let Value::Object(object) = vm.raw_get(registry(vm), Value::Integer(2)).unwrap() else {
        panic!()
    };
    assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
    object
}

fn set_field(owner: &StateOwner, table: ObjectRef, key: &[u8], value: Value) {
    owner
        .with_vm(|vm| {
            let key = vm.allocate_byte_string(key).unwrap();
            vm.raw_set(table, Value::Object(key), value).unwrap();
        })
        .unwrap();
}

fn assert_unchanged(owner: &StateOwner, state: *mut lua_State, top: i32, before: &Snapshot) {
    // SAFETY：只讀取目前有效 owner 的 stack top。
    assert_eq!(unsafe { lua_gettop(state) }, top);
    let after = snapshot(owner);
    assert_eq!(after.0.reserved, 0, "帳款不得留下未提交預約");
    assert_eq!(after.3, before.3, "root 不得半發布");
}

fn field_types_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let field = c"answer";
    let before = snapshot(&owner);
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    assert_eq!(snapshot(&owner).3, before.3);
    unsafe { lua_settop(state, 1) };

    for (value, tag) in [
        (Value::Boolean(false), 1),
        (Value::Integer(42), 3),
        (Value::Float(2.25), 3),
    ] {
        set_field(&owner, table, b"answer", value);
        assert_eq!(unsafe { lua_getfield(state, -1, field.as_ptr()) }, tag);
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(unsafe { lua_type(state, -1) }, tag);
        if value == Value::Integer(42) {
            assert_eq!(
                unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
                42
            );
        }
        if value == Value::Float(2.25) {
            assert_eq!(
                unsafe { lua_tonumberx(state, -1, std::ptr::null_mut()) },
                2.25
            );
        }
        unsafe { lua_settop(state, 1) };
    }
    let mut token = 0_u8;
    let address = (&mut token as *mut u8) as usize;
    set_field(&owner, table, b"answer", Value::LightUserdata(address));
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 2);
    assert_eq!(unsafe { lua_touserdata(state, -1) } as usize, address);
    unsafe { lua_settop(state, 1) };

    let string = owner
        .with_vm(|vm| vm.allocate_byte_string(b"payload").unwrap())
        .unwrap();
    set_field(&owner, table, b"answer", Value::Object(string));
    let before = snapshot(&owner).3;
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 4);
    assert_eq!(only_added_host(&before, &snapshot(&owner).3), string);
    unsafe { lua_settop(state, 1) };

    let object = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, table, b"answer", Value::Object(object));
    let before = snapshot(&owner).3;
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 5);
    assert_eq!(only_added_host(&before, &snapshot(&owner).3), object);
    set_field(&owner, table, b"answer", Value::Nil);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
        })
        .unwrap();
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 0);
    unsafe { lua_settop(state, 1) };

    let builtin = owner
        .with_vm(|vm| {
            let global = globals(vm);
            vm.install_error_builtins(global).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(global, Value::Object(key)).unwrap()
        })
        .unwrap();
    let Value::Object(builtin_object) = builtin else {
        panic!()
    };
    set_field(&owner, table, b"answer", builtin);
    let before = snapshot(&owner).3;
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 6);
    assert_eq!(
        only_added_host(&before, &snapshot(&owner).3),
        builtin_object
    );
    unsafe { lua_settop(state, 1) };

    let coroutine = owner
        .with_vm(|vm| vm.new_coroutine(builtin).unwrap())
        .unwrap();
    let thread = owner.with_vm(|vm| coroutine.as_value(vm).unwrap()).unwrap();
    let Value::Object(thread_object) = thread else {
        panic!()
    };
    set_field(&owner, table, b"answer", thread);
    drop(coroutine);
    let before = snapshot(&owner).3;
    assert_eq!(unsafe { lua_getfield(state, 1, field.as_ptr()) }, 8);
    assert_eq!(only_added_host(&before, &snapshot(&owner).3), thread_object);
    unsafe { lua_settop(state, 1) };

    // __index 函式可拋錯，table target 則沿鏈讀取。
    let mt = add_table(&owner);
    set_field(&owner, mt, b"__index", builtin);
    assert_eq!(unsafe { lua_setmetatable(state, 1) }, 1);
    assert_eq!(
        protected_get(&owner, 1, 1, c"missing".as_ptr(), 0, -1).0,
        -2
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    let fallback = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, mt, b"__index", Value::Object(fallback));
    assert_eq!(unsafe { lua_getfield(state, 1, c"missing".as_ptr()) }, 0);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    unsafe { lua_settop(state, 1) };
    assert_eq!(unsafe { lua_geti(state, 1, 999) }, 0);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    unsafe { lua_settop(state, 1) };
    unsafe { lua_pushinteger(state, 999) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 0);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    unsafe { lua_settop(state, 1) };
}

fn table_key_replacement_and_integer() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Integer(7), Value::Integer(70))
                .unwrap();
            vm.raw_set(table, Value::Integer(-1), Value::Integer(71))
                .unwrap();
            vm.raw_set(table, Value::Integer(i64::MIN), Value::Integer(72))
                .unwrap();
            vm.raw_set(table, Value::Integer(i64::MAX), Value::Integer(73))
                .unwrap();
        })
        .unwrap();
    for (key, value) in [(7, 70), (-1, 71), (i64::MIN, 72), (i64::MAX, 73)] {
        assert_eq!(unsafe { lua_geti(state, -1, key) }, 3);
        assert_eq!(
            unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
            value
        );
        unsafe { lua_settop(state, 1) };
    }
    assert_eq!(unsafe { lua_geti(state, 1, 0) }, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 1) };

    // SAFETY：下列 key 來源均在對應 getter 呼叫期間有效。
    unsafe { lua_pushinteger(state, 7) };
    assert_eq!(unsafe { lua_gettable(state, -2) }, 3);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        70
    );
    unsafe { lua_settop(state, 1) };
    set_field(&owner, table, b"named", Value::Integer(80));
    unsafe { lua_pushlstring(state, b"named".as_ptr().cast(), 5) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        80
    );
    unsafe { lua_settop(state, 1) };
    let mut token = 1_u8;
    let address = (&mut token as *mut u8) as usize;
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::LightUserdata(address), Value::Integer(81))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushlightuserdata(state, (&mut token as *mut u8).cast::<c_void>()) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        81
    );
    unsafe { lua_settop(state, 1) };
    let key = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Object(key), Value::Integer(82))
                .unwrap()
        })
        .unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    assert_eq!(unsafe { lua_gettable(state, -2) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        82
    );
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Object(table), Value::Integer(83))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushvalue(state, 1) };
    assert_eq!(unsafe { lua_gettable(state, -1) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        83
    );
    unsafe { lua_settop(state, 1) };
    unsafe { lua_pushnil(state) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 0);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
}

fn global_registry_and_invalid() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let global = owner.with_vm(|vm| globals(vm)).unwrap();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    set_field(&owner, global, b"answer", Value::Integer(100));
    assert_eq!(unsafe { lua_getglobal(state, c"answer".as_ptr()) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        100
    );
    unsafe { lua_settop(state, 0) };
    let sibling = owner.new_sibling().unwrap();
    assert_eq!(
        unsafe { lua_getglobal(sibling.as_ptr(), c"answer".as_ptr()) },
        3
    );
    assert_eq!(
        unsafe { lua_tointegerx(sibling.as_ptr(), -1, std::ptr::null_mut()) },
        100
    );
    let other = StateOwner::new().unwrap();
    assert_eq!(
        unsafe { lua_getglobal(other.as_ptr(), c"answer".as_ptr()) },
        0
    );
    assert_eq!(unsafe { lua_type(other.as_ptr(), -1) }, 0);
    let embedded = b"answer\0ignored\0";
    assert_eq!(unsafe { lua_getglobal(state, embedded.as_ptr().cast()) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        100
    );
    unsafe { lua_settop(state, 0) };
    set_field(&owner, global, b"", Value::Integer(101));
    assert_eq!(unsafe { lua_getglobal(state, c"".as_ptr()) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        101
    );
    unsafe { lua_settop(state, 0) };
    set_field(&owner, global, b"answer", Value::Nil);
    assert_eq!(unsafe { lua_getglobal(state, c"answer".as_ptr()) }, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    unsafe { lua_settop(state, 0) };

    set_field(&owner, reg, b"named", Value::Integer(111));
    owner
        .with_vm(|vm| {
            vm.raw_set(reg, Value::Integer(12), Value::Integer(112))
                .unwrap()
        })
        .unwrap();
    assert_eq!(
        unsafe { lua_getfield(state, REGISTRY_INDEX, c"named".as_ptr()) },
        3
    );
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        111
    );
    unsafe { lua_settop(state, 0) };
    assert_eq!(unsafe { lua_geti(state, REGISTRY_INDEX, 12) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        112
    );
    unsafe { lua_settop(state, 0) };
    unsafe { lua_pushlstring(state, b"named".as_ptr().cast(), 5) };
    assert_eq!(unsafe { lua_gettable(state, REGISTRY_INDEX) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        111
    );
    unsafe { lua_settop(state, 0) };
    let named_mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, reg, b"named", Value::Object(named_mt));
    let roots_before = snapshot(&owner).3;
    assert_eq!(
        unsafe { lua_getfield(state, REGISTRY_INDEX, c"named".as_ptr()) },
        5
    );
    assert_eq!(
        only_added_host(&roots_before, &snapshot(&owner).3),
        named_mt
    );
    unsafe { lua_pushlstring(state, b"named".as_ptr().cast(), 5) };
    assert_eq!(unsafe { lua_gettable(state, REGISTRY_INDEX) }, 5);
    assert_eq!(unsafe { lua_rawequal(state, 1, 2) }, 1);
    set_field(&owner, reg, b"named", Value::Nil);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(named_mt), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(named_mt), Err(VmError::StaleObject));
        })
        .unwrap();

    // globals table 若被 registry 寫壞，getglobal 必須拒絕且不動 stack。
    owner.push_value(Value::Object(global)).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(reg, Value::Integer(2), Value::Integer(4))
                .unwrap()
        })
        .unwrap();
    let invalid_global = snapshot(&owner);
    assert_eq!(protected_get(&owner, 3, 0, c"x".as_ptr(), 0, -1).0, -2);
    assert_unchanged(&owner, state, 1, &invalid_global);
    owner
        .with_vm(|vm| {
            vm.raw_set(reg, Value::Integer(2), Value::Object(global))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };

    let table = add_table(&owner);
    let mut token = 0_u8;
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 3);
        lua_pushnumber(state, 1.5);
        lua_pushlightuserdata(state, (&mut token as *mut u8).cast::<c_void>());
        lua_pushlstring(state, b"text".as_ptr().cast(), 4);
    }
    let top = unsafe { lua_gettop(state) };
    // SAFETY：夾具 callback 登錄後再取基準，排除其固定 registry 容量。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let before = snapshot(&owner);
    for index in [
        2,
        3,
        4,
        5,
        6,
        7,
        0,
        99,
        -99,
        OTHER_REGISTRY_INDEX,
        REGISTRY_INDEX - 1,
    ] {
        assert_eq!(protected_get(&owner, 1, index, c"x".as_ptr(), 0, -1).0, -2);
        assert_eq!(
            protected_get(&owner, 2, index, std::ptr::null(), 1, -1).0,
            -2
        );
        assert_eq!(
            protected_get(&owner, 0, index, std::ptr::null(), 0, -1).0,
            -2
        );
        assert_unchanged(&owner, state, top, &before);
    }
    assert_eq!(protected_get(&owner, 1, 1, std::ptr::null(), 0, -1).0, -2);
    assert_eq!(protected_get(&owner, 3, 0, std::ptr::null(), 0, -1).0, -2);
    assert_unchanged(&owner, state, top, &before);
    unsafe { lua_settop(state, 0) };
    let empty = snapshot(&owner);
    assert_eq!(
        protected_get(&owner, 0, REGISTRY_INDEX, std::ptr::null(), 0, -1).0,
        -2
    );
    assert_unchanged(&owner, state, 0, &empty);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn result_roots_survive_source_removal() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, table, b"held", Value::Object(result));
    assert_eq!(unsafe { lua_getfield(state, 1, c"held".as_ptr()) }, 5);
    // 先移除來源欄位，再以 copy 將 target slot 改為結果，釋放 target root。
    set_field(&owner, table, b"held", Value::Nil);
    unsafe { lua_copy(state, 2, 1) };
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Err(VmError::StaleObject));
        })
        .unwrap();

    let table = add_table(&owner);
    let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Integer(4), Value::Object(result))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushinteger(state, 4) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 5);
    owner
        .with_vm(|vm| vm.raw_set(table, Value::Integer(4), Value::Nil).unwrap())
        .unwrap();
    owner
        .with_vm(|vm| {
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
    unsafe { lua_settop(state, 0) };

    let global = owner.with_vm(|vm| globals(vm)).unwrap();
    let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, global, b"held", Value::Object(result));
    assert_eq!(unsafe { lua_getglobal(state, c"held".as_ptr()) }, 5);
    set_field(&owner, global, b"held", Value::Nil);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn gc_result_publication_and_weak_value() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    let weak_mt = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let mode = owner
        .with_vm(|vm| vm.allocate_byte_string(b"v").unwrap())
        .unwrap();
    set_field(&owner, weak_mt, b"__mode", Value::Object(mode));
    owner
        .with_vm(|vm| vm.set_metatable(table, Some(weak_mt)).unwrap())
        .unwrap();
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
    let weak_value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, table, b"weak", Value::Object(weak_value));
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(weak_value)).unwrap(),
        Ok(GcColor::White)
    );
    let roots_before = snapshot(&owner).3;
    let trace_before = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(unsafe { lua_getfield(state, 1, c"weak".as_ptr()) }, 5);
    assert_eq!(
        only_added_host(&roots_before, &snapshot(&owner).3),
        weak_value
    );
    assert_ne!(
        owner.with_vm(|vm| vm.gc_color(weak_value)).unwrap(),
        Ok(GcColor::White)
    );
    let trace_after = owner.with_vm(|vm| vm.gc_trace()).unwrap();
    assert_eq!(trace_after.phase, trace_before.phase);
    assert_eq!(trace_after.transition_count, trace_before.transition_count);
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
    let young = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.gc_age(young)).unwrap(),
        Ok(GcAge::Young)
    );
    set_field(&owner, table, b"young", Value::Object(young));
    assert_eq!(unsafe { lua_getfield(state, 1, c"young".as_ptr()) }, 5);
    set_field(&owner, table, b"young", Value::Nil);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(young), Ok(ObjectKind::Table));
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(young), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn named_fault_owner(global_getter: bool) -> (StateOwner, ObjectRef, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：夾具 callback 在 failpoint 基準前登錄。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let table = if global_getter {
        owner.with_vm(|vm| globals(vm)).unwrap()
    } else {
        add_table(&owner)
    };
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    set_field(&owner, table, b"fault", Value::Object(value));
    unsafe { lua_settop(state, 20) };
    (owner, table, value)
}

fn named_getter_fault_matrix(global_getter: bool) {
    let operation = if global_getter { 3 } else { 1 };
    let (probe, _, _) = named_fault_owner(global_getter);
    let (attempts, _) = protected_get(&probe, operation, 1, c"fault".as_ptr(), 0, -1000);
    assert!(attempts > 0);
    let mut domains = Vec::new();
    for offset in 0..attempts {
        let (owner, table, value) = named_fault_owner(global_getter);
        let state = owner.as_ptr();
        let before = snapshot(&owner);
        let (status, start) = protected_get(&owner, operation, 1, c"fault".as_ptr(), 0, offset);
        assert_eq!(status, -4, "global={global_getter};offset={offset}");
        assert_unchanged(&owner, state, 20, &before);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        assert_eq!(failure.attempt.ordinal, start + offset as u64);
        domains.push(failure.attempt.domain);
        assert_eq!(
            owner.with_vm(|vm| vm.object_kind(value)).unwrap(),
            Ok(ObjectKind::Table)
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm
                    .with_temporary_byte_string(b"fault", |vm, key| vm
                        .raw_get(table, Value::Object(key)))
                    .unwrap())
                .unwrap(),
            Value::Object(value)
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        let tag = if global_getter {
            unsafe { lua_getglobal(state, c"fault".as_ptr()) }
        } else {
            unsafe { lua_getfield(state, 1, c"fault".as_ptr()) }
        };
        assert_eq!(tag, 5);
        assert_eq!(unsafe { lua_gettop(state) }, 21);
        assert_eq!(only_added_host(&before.3, &snapshot(&owner).3), value);
    }
    assert!(domains.contains(&AllocationDomain::Host));
    assert!(domains.contains(&AllocationDomain::LuaHeap));

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    if !global_getter {
        add_table(&owner);
    }
    let tag = if global_getter {
        unsafe { lua_getglobal(state, c"absent".as_ptr()) }
    } else {
        unsafe { lua_getfield(state, 1, c"absent".as_ptr()) }
    };
    assert_eq!(tag, 0);
    assert_eq!(unsafe { lua_type(state, -1) }, 0);
    assert_eq!(
        unsafe { lua_gettop(state) },
        if global_getter { 1 } else { 2 }
    );
}

fn get_i_fault_owner() -> (StateOwner, ObjectRef, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：先登錄夾具 callback，避免污染 failpoint 起點。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let table = add_table(&owner);
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Integer(4), Value::Object(value))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_settop(state, 20) };
    (owner, table, value)
}

fn get_table_fault_owner() -> (StateOwner, ObjectRef, ObjectRef, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：先登錄夾具 callback，避免污染 failpoint 起點。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let table = add_table(&owner);
    let key = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let value = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Object(key), Value::Object(value))
                .unwrap()
        })
        .unwrap();
    owner.push_value(Value::Object(key)).unwrap();
    (owner, table, key, value)
}

fn integer_and_replacement_fault_matrices() {
    let (probe, _, _) = get_i_fault_owner();
    let (attempts, _) = protected_get(&probe, 2, 1, std::ptr::null(), 4, -1000);
    assert!(attempts > 0);
    for offset in 0..attempts {
        let (owner, table, value) = get_i_fault_owner();
        let state = owner.as_ptr();
        let before = snapshot(&owner);
        let (status, start) = protected_get(&owner, 2, 1, std::ptr::null(), 4, offset);
        assert_eq!(status, -4, "geti offset={offset}");
        assert_unchanged(&owner, state, 20, &before);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        assert_eq!(failure.attempt.ordinal, start + offset as u64);
        assert_eq!(
            owner
                .with_vm(|vm| vm.raw_get(table, Value::Integer(4)))
                .unwrap(),
            Ok(Value::Object(value))
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(unsafe { lua_geti(state, 1, 4) }, 5);
        assert_eq!(unsafe { lua_gettop(state) }, 21);
        assert_eq!(only_added_host(&before.3, &snapshot(&owner).3), value);
    }

    let (probe, _, _, _) = get_table_fault_owner();
    let (attempts, _) = protected_get(&probe, 0, -2, std::ptr::null(), 0, -1000);
    assert!(attempts > 0);
    for offset in 0..attempts {
        let (owner, table, key, value) = get_table_fault_owner();
        let state = owner.as_ptr();
        let before = snapshot(&owner);
        let (status, start) = protected_get(&owner, 0, -2, std::ptr::null(), 0, offset);
        assert_eq!(status, -4, "gettable offset={offset}");
        assert_unchanged(&owner, state, 2, &before);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        assert_eq!(failure.attempt.ordinal, start + offset as u64);
        assert_eq!(host_roots(&snapshot(&owner).3).last().unwrap().1, key);
        assert_eq!(
            owner
                .with_vm(|vm| vm.raw_get(table, Value::Object(key)))
                .unwrap(),
            Ok(Value::Object(value))
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(unsafe { lua_gettable(state, -2) }, 5);
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(host_roots(&snapshot(&owner).3).last().unwrap().1, value);
    }

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.raw_set(table, Value::Integer(1), Value::Integer(9))
                .unwrap()
        })
        .unwrap();
    unsafe { lua_pushinteger(state, 1) };
    assert_eq!(unsafe { lua_gettable(state, 1) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        9
    );
    unsafe { lua_settop(state, 1) };
    assert_eq!(unsafe { lua_geti(state, 1, 1) }, 3);
    assert_eq!(
        unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
        9
    );
}

#[test]
fn table_getters_a21_matrix() {
    field_types_and_lifetime();
    table_key_replacement_and_integer();
    global_registry_and_invalid();
    result_roots_survive_source_removal();
    gc_result_publication_and_weak_value();
    named_getter_fault_matrix(false);
    named_getter_fault_matrix(true);
    integer_and_replacement_fault_matrices();
}
