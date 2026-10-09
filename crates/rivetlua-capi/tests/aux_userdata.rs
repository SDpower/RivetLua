use std::ffi::{CString, c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_newuserdatauv, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber,
    lua_setmetatable, lua_settop, lua_touserdata, lua_type, luaL_newmetatable, luaL_testudata,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationFailureKind, FailPoint, GcColor, GcMode, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, Vm,
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

fn protected_testudata(state: *mut lua_State, index: c_int, name: *const c_char) -> (c_int, bool) {
    let mut answer = 0;
    // SAFETY：C checkpoint 捕捉正式 Lua 錯誤，且於返回前消費 pending 狀態。
    let status =
        unsafe { rivetlua_capi_test_protected_index_a4b(state, 8, index, 0, name, &mut answer) };
    (status, answer != 0)
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

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

// SAFETY：各測試由存活的 StateOwner 持有 state；跨執行緒僅傳位址驗證拒絕。
macro_rules! c_call {
    ($expression:expr) => {{ unsafe { $expression } }};
}

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type Snapshot = (LedgerSnapshot, GcTrace, Roots, Vec<(i32, usize)>);

fn snapshot(owner: &StateOwner) -> Snapshot {
    let state = owner.as_ptr();
    let top = c_call!(lua_gettop(state));
    let stack = (1..=top)
        .map(|index| {
            (
                c_call!(lua_type(state, index)),
                c_call!(lua_touserdata(state, index)) as usize,
            )
        })
        .collect();
    let (ledger, trace, roots) = owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap();
    (ledger, trace, roots, stack)
}

fn settle_error(owner: &StateOwner) {
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.gc_trace().worklist_len, 0);
        })
        .unwrap();
}

fn added_host(before: &Roots, after: &Roots) -> ObjectRef {
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

fn add_userdata(owner: &StateOwner, size: usize) -> (ObjectRef, *mut c_void) {
    let before = snapshot(owner).2;
    let pointer = c_call!(lua_newuserdatauv(owner.as_ptr(), size, 0));
    assert!(!pointer.is_null());
    let object = added_host(&before, &snapshot(owner).2);
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
        Ok(ObjectKind::Userdata)
    );
    (object, pointer)
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).2;
    c_call!(lua_createtable(owner.as_ptr(), 0, 0));
    added_host(&before, &snapshot(owner).2)
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

fn named(owner: &StateOwner, name: &[u8], value: Value) {
    owner
        .with_vm(|vm| {
            let reg = registry(vm);
            vm.raw_set_byte_string_key(reg, name, value).unwrap();
        })
        .unwrap();
}

fn create_named(owner: &StateOwner, name: &CString) -> ObjectRef {
    let before = snapshot(owner).2;
    assert_eq!(c_call!(luaL_newmetatable(owner.as_ptr(), name.as_ptr())), 1);
    added_host(&before, &snapshot(owner).2)
}

fn metatable(owner: &StateOwner, target: ObjectRef) -> Option<ObjectRef> {
    owner
        .with_vm(|vm| vm.get_metatable(target).unwrap())
        .unwrap()
}

#[test]
fn aux_userdata_a31_matrix() {
    pointer_identity_and_registry();
    names_and_alias();
    fail_closed_targets_and_state();
    active_gc_and_failpoints();
    allocation_ordinal_matrix();
}

fn pointer_identity_and_registry() {
    for size in [0, 17] {
        let owner = StateOwner::new().unwrap();
        owner
            .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
            .unwrap();
        let state = owner.as_ptr();
        let (target, pointer) = add_userdata(&owner, size);
        let name = CString::new(format!("a31-size-{size}")).unwrap();
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);

        let mt = create_named(&owner, &name);
        assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
        assert_eq!(metatable(&owner, target), Some(mt));
        for index in [1, -1] {
            let before = snapshot(&owner);
            assert_eq!(
                c_call!(luaL_testudata(state, index, name.as_ptr())),
                pointer
            );
            assert_eq!(c_call!(lua_touserdata(state, index)), pointer);
            assert_eq!(snapshot(&owner), before);
        }
        c_call!(lua_pushinteger(state, 7));
        let before = snapshot(&owner);
        assert_eq!(c_call!(luaL_testudata(state, -2, name.as_ptr())), pointer);
        assert_eq!(snapshot(&owner), before);
        c_call!(lua_settop(state, 1));

        // 名稱相同不足以成立；必須是 registry 中同一個 metatable ObjectRef。
        let alternate = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        named(&owner, name.as_bytes(), Value::Object(alternate));
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);
        assert_eq!(metatable(&owner, target), Some(mt));
        named(&owner, name.as_bytes(), Value::Integer(9));
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);
        named(&owner, name.as_bytes(), Value::Nil);
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, c"a31-missing".as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);

        named(&owner, name.as_bytes(), Value::Object(mt));
        assert_eq!(c_call!(luaL_testudata(state, 1, name.as_ptr())), pointer);
        let wrong_mt = add_table(&owner);
        assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
        assert_eq!(metatable(&owner, target), Some(wrong_mt));
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);
        owner.push_value(Value::Object(mt)).unwrap();
        assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
        assert_eq!(metatable(&owner, target), Some(mt));
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.userdata_ptr(target), Ok(pointer.cast()));
            })
            .unwrap();
        assert_eq!(c_call!(luaL_testudata(state, 1, name.as_ptr())), pointer);
        c_call!(lua_pushnil(state));
        assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
        let before = snapshot(&owner);
        assert!(c_call!(luaL_testudata(state, 1, name.as_ptr())).is_null());
        assert_eq!(snapshot(&owner), before);
    }
}

fn names_and_alias() {
    let owner = StateOwner::new().unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    let state = owner.as_ptr();
    let (target, pointer) = add_userdata(&owner, 8);
    let mt = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    for name in [
        b"".as_slice(),
        b"nul",
        b"a-very-long-name-for-a31-userdata-metatable-identity-check-with-many-bytes",
    ] {
        named(&owner, name, Value::Object(mt));
        let c_name = CString::new(name).unwrap();
        let before = snapshot(&owner);
        assert_eq!(c_call!(luaL_testudata(state, 1, c_name.as_ptr())), pointer);
        assert_eq!(snapshot(&owner), before);
    }
    let before = snapshot(&owner);
    assert_eq!(
        c_call!(luaL_testudata(state, 1, b"nul\0ignored\0".as_ptr().cast())),
        pointer
    );
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, target), Some(mt));

    let bytes = b"alias-name\0";
    let (_alias, alias_pointer) = add_userdata(&owner, bytes.len());
    // SAFETY：剛配置的 full userdata payload 長度等於 bytes.len()，兩者不重疊；
    // alias slot 持續保活，直到 luaL_testudata 返回後才可移除。
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), alias_pointer.cast::<u8>(), bytes.len())
    };
    named(&owner, b"alias-name", Value::Object(mt));
    let before = snapshot(&owner);
    assert_eq!(
        c_call!(luaL_testudata(state, 1, alias_pointer.cast())),
        pointer
    );
    assert_eq!(snapshot(&owner), before);
    assert_eq!(c_call!(lua_touserdata(state, 2)), alias_pointer);
}

fn fail_closed_targets_and_state() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let (target, pointer) = add_userdata(&owner, 3);
    let name = CString::new("a31-valid").unwrap();
    let mt = create_named(&owner, &name);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    let mut token = 0_u8;
    c_call!(lua_pushnil(state));
    c_call!(lua_pushboolean(state, 1));
    c_call!(lua_pushinteger(state, 4));
    c_call!(lua_pushnumber(state, 2.5));
    c_call!(lua_pushlightuserdata(state, (&mut token as *mut u8).cast()));
    c_call!(lua_pushlstring(state, b"str".as_ptr().cast(), 3));
    let _table = add_table(&owner);
    let (builtin, thread) = owner
        .with_vm(|vm| {
            let reg = registry(vm);
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            let builtin = vm
                .with_temporary_byte_string(b"error", |vm, key| {
                    vm.raw_get(globals, Value::Object(key))
                })
                .unwrap();
            let coroutine = vm.new_coroutine(builtin).unwrap();
            let thread = coroutine.as_value(vm).unwrap();
            (builtin, (thread, coroutine))
        })
        .unwrap();
    owner.push_value(builtin).unwrap();
    owner.push_value(thread.0).unwrap();
    drop(thread.1);
    prime_checkpoint(state);
    for index in [
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        0,
        99,
        -99,
        REGISTRY_INDEX,
        OTHER_REGISTRY_INDEX,
        REGISTRY_INDEX - 1,
    ] {
        let before = snapshot(&owner);
        let (status, matched) = protected_testudata(state, index, name.as_ptr());
        assert!(!matched, "index={index}");
        assert!(status == 0 || status > 0, "index={index} status={status}");
        if status == 0 {
            assert_eq!(snapshot(&owner), before, "index={index}");
        } else {
            assert_eq!(snapshot(&owner).2, before.2, "index={index}");
            assert_eq!(snapshot(&owner).3, before.3, "index={index}");
            settle_error(&owner);
            assert_eq!(snapshot(&owner).2, before.2, "index={index}");
        }
    }
    let before = snapshot(&owner);
    assert!(protected_testudata(state, 1, std::ptr::null()).0 > 0);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(snapshot(&owner).3, before.3);
    settle_error(&owner);
    assert_eq!(
        protected_testudata(std::ptr::null_mut(), 1, name.as_ptr()).0,
        -1
    );
    let before = snapshot(&owner);
    let pointer_value = state as usize;
    std::thread::spawn(move || {
        let state = pointer_value as *mut lua_State;
        assert_eq!(protected_testudata(state, 1, c"a31-valid".as_ptr()).0, -1);
    })
    .join()
    .unwrap();
    owner
        .with_vm(|_| {
            assert_eq!(protected_testudata(state, 1, name.as_ptr()).0, -1);
        })
        .unwrap();
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, target), Some(mt));
    assert_eq!(c_call!(lua_touserdata(state, 1)), pointer);
}

fn setup_query(matched: bool) -> (StateOwner, ObjectRef, ObjectRef, *mut c_void) {
    let owner = StateOwner::new().unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    let (target, pointer) = add_userdata(&owner, 7);
    let name = CString::new("a31-query").unwrap();
    let mt = create_named(&owner, &name);
    assert_eq!(c_call!(lua_setmetatable(owner.as_ptr(), 1)), 1);
    if !matched {
        let other = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        named(&owner, name.as_bytes(), Value::Object(other));
    }
    prime_checkpoint(owner.as_ptr());
    (owner, target, mt, pointer)
}

fn active_gc_and_failpoints() {
    let (owner, target, mt, pointer) = setup_query(true);
    owner
        .with_vm(|vm| {
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            let reg = registry(vm);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause
                    && vm.gc_color(target) == Ok(GcColor::Black)
                    && vm.gc_color(reg) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            assert_eq!(vm.gc_color(target), Ok(GcColor::Black));
            assert_eq!(vm.gc_color(reg), Ok(GcColor::Black));
        })
        .unwrap();
    let before = snapshot(&owner);
    assert_eq!(
        c_call!(luaL_testudata(owner.as_ptr(), 1, c"a31-query".as_ptr())),
        pointer
    );
    let after = snapshot(&owner);
    assert_eq!(after.0, before.0);
    assert_eq!(after.2, before.2);
    assert_eq!(after.3, before.3);
    assert_eq!(metatable(&owner, target), Some(mt));
    for point in [
        FailPoint::ObjectReserve,
        FailPoint::StringBytesReserve,
        FailPoint::RootReserve,
    ] {
        let (owner, target, mt, pointer) = setup_query(true);
        owner
            .with_vm(|vm| {
                vm.set_gc_mode(GcMode::Incremental).unwrap();
                vm.collect().unwrap();
                vm.incremental_step(1).unwrap();
                vm.inject_failure_once(point);
            })
            .unwrap();
        let before = snapshot(&owner);
        assert!(protected_testudata(owner.as_ptr(), 1, c"a31-query".as_ptr()).0 > 0);
        assert_eq!(snapshot(&owner).2, before.2, "point={point:?}");
        assert_eq!(snapshot(&owner).3, before.3, "point={point:?}");
        settle_error(&owner);
        assert_eq!(snapshot(&owner).2, before.2, "point={point:?}");
        assert_eq!(metatable(&owner, target), Some(mt));
        assert_eq!(
            c_call!(luaL_testudata(owner.as_ptr(), 1, c"a31-query".as_ptr())),
            pointer
        );
    }
}

fn allocation_ordinal_matrix() {
    for matched in [true, false] {
        let (dry, target, mt, pointer) = setup_query(matched);
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        let result = c_call!(luaL_testudata(dry.as_ptr(), 1, c"a31-query".as_ptr()));
        assert_eq!(
            result,
            if matched {
                pointer
            } else {
                std::ptr::null_mut()
            }
        );
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start);
        assert_eq!(metatable(&dry, target), Some(mt));
        for offset in 0..end - start {
            let (owner, target, mt, pointer) = setup_query(matched);
            let before = snapshot(&owner);
            let next = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
                .unwrap();
            assert!(
                protected_testudata(owner.as_ptr(), 1, c"a31-query".as_ptr()).0 > 0,
                "matched={matched} offset={offset}"
            );
            assert_eq!(
                snapshot(&owner).2,
                before.2,
                "matched={matched} offset={offset}"
            );
            assert_eq!(
                snapshot(&owner).3,
                before.3,
                "matched={matched} offset={offset}"
            );
            settle_error(&owner);
            assert_eq!(
                snapshot(&owner).2,
                before.2,
                "matched={matched} offset={offset}"
            );
            assert_eq!(metatable(&owner, target), Some(mt));
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, next + offset);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            let retry = c_call!(luaL_testudata(owner.as_ptr(), 1, c"a31-query".as_ptr()));
            assert_eq!(
                retry,
                if matched {
                    pointer
                } else {
                    std::ptr::null_mut()
                }
            );
        }
        println!("A31_ORDINAL matched={matched} checked={}", end - start);
    }
}
