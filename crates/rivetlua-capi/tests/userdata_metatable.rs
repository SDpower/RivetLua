use std::ffi::{CString, c_char, c_int};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_getmetatable, lua_gettop, lua_newuserdatauv,
    lua_pushinteger, lua_pushnil, lua_rawequal, lua_setmetatable, lua_settop, lua_tointegerx,
    lua_type, luaL_getmetafield, luaL_setmetatable,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    FailPoint, FinalizerState, GcAge, GcColor, GcMode, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, Vm, VmError,
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

fn protected_meta(
    state: *mut lua_State,
    operation: c_int,
    index: c_int,
    name: *const c_char,
) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：私有 C checkpoint 捕捉正式 Lua error，並清除 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(state, operation, index, 0, name, &mut answer)
    };
    (status, answer)
}

fn prime_checkpoint(state: *mut lua_State) {
    assert_eq!(protected_meta(state, -1, 0, std::ptr::null()).0, 0);
}

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

// SAFETY：各測試期間 StateOwner 持有有效 state；跨執行緒只傳位址以驗證入口拒絕。
macro_rules! c_call {
    ($expression:expr) => {{ unsafe { $expression } }};
}

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type Snapshot = (LedgerSnapshot, GcTrace, Roots, i32);

fn snapshot(owner: &StateOwner) -> Snapshot {
    let (ledger, trace, roots) = owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap();
    (ledger, trace, roots, c_call!(lua_gettop(owner.as_ptr())))
}

fn assert_raised_settles(owner: &StateOwner, before: &Snapshot) {
    let after = snapshot(owner);
    assert_eq!(after.2, before.2);
    assert_eq!(after.3, before.3);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.gc_trace().worklist_len, 0);
        })
        .unwrap();
    let settled = snapshot(owner);
    assert_eq!(settled.2, before.2);
    assert_eq!(settled.3, before.3);
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

fn add_userdata(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).2;
    assert!(!c_call!(lua_newuserdatauv(owner.as_ptr(), 7, 1)).is_null());
    let object = added_host(&before, &snapshot(owner).2);
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
        Ok(ObjectKind::Userdata)
    );
    object
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

fn metatable(owner: &StateOwner, object: ObjectRef) -> Option<ObjectRef> {
    owner
        .with_vm(|vm| vm.get_metatable(object).unwrap())
        .unwrap()
}

fn named(owner: &StateOwner, name: &[u8], value: Value) {
    owner
        .with_vm(|vm| {
            let reg = registry(vm);
            vm.raw_set_byte_string_key(reg, name, value).unwrap();
        })
        .unwrap();
}

#[test]
fn userdata_metatable_a30_matrix() {
    ordinary_identity_and_lifetime();
    metafield_and_named_registry();
    fail_closed_inputs();
    active_incremental_edge();
    generational_and_finalizer();
    allocation_failure_atomicity();
    ordinal_failure_matrix();
    named_failpoint_matrix();
    setter_ordinal_failure();
}

fn ordinary_identity_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    let before = snapshot(&owner);
    assert_eq!(c_call!(lua_getmetatable(state, 1)), 0);
    assert_eq!(snapshot(&owner), before);

    let first = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(c_call!(lua_gettop(state)), 1);
    assert_eq!(metatable(&owner, target), Some(first));
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
        })
        .unwrap();
    let roots_before = snapshot(&owner).2;
    assert_eq!(c_call!(lua_getmetatable(state, -1)), 1);
    assert_eq!(added_host(&roots_before, &snapshot(&owner).2), first);
    assert_eq!(c_call!(lua_rawequal(state, 1, -1)), 0);
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(metatable(&owner, target), None);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_settop(state, 1));
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        })
        .unwrap();

    let second = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, -2)), 1);
    assert_eq!(metatable(&owner, target), Some(second));
    let replacement = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(metatable(&owner, target), Some(replacement));
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(c_call!(lua_getmetatable(state, 1)), 0);
}

fn metafield_and_named_registry() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    let before = snapshot(&owner);
    assert_eq!(c_call!(luaL_getmetafield(state, 1, c"__a30".as_ptr())), 0);
    assert_eq!(snapshot(&owner), before);
    let mt = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    let before = snapshot(&owner);
    assert_eq!(c_call!(luaL_getmetafield(state, -1, c"__a30".as_ptr())), 0);
    assert_eq!(snapshot(&owner), before);
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(mt, b"__a30", Value::Integer(42))
                .unwrap()
        })
        .unwrap();
    assert_eq!(c_call!(luaL_getmetafield(state, 1, c"__a30".as_ptr())), 3);
    assert_eq!(c_call!(lua_tointegerx(state, -1, std::ptr::null_mut())), 42);
    c_call!(lua_settop(state, 1));
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(mt, b"__a30", Value::Nil)
                .unwrap()
        })
        .unwrap();
    let before = snapshot(&owner);
    assert_eq!(c_call!(luaL_getmetafield(state, 1, c"__a30".as_ptr())), 0);
    assert_eq!(snapshot(&owner), before);

    let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(mt, b"__a30", Value::Object(result))
                .unwrap()
        })
        .unwrap();
    let before = snapshot(&owner).2;
    assert_eq!(c_call!(luaL_getmetafield(state, 1, c"__a30".as_ptr())), 5);
    assert_eq!(added_host(&before, &snapshot(&owner).2), result);
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(mt, b"__a30", Value::Nil)
                .unwrap()
        })
        .unwrap();
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_settop(state, 1));
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result), Err(VmError::StaleObject));
        })
        .unwrap();

    let name = CString::new("a30-named").unwrap();
    named(&owner, name.as_bytes(), Value::Object(mt));
    c_call!(luaL_setmetatable(state, name.as_ptr()));
    assert_eq!(c_call!(lua_gettop(state)), 1);
    assert_eq!(metatable(&owner, target), Some(mt));
    named(&owner, name.as_bytes(), Value::Nil);
    c_call!(luaL_setmetatable(state, name.as_ptr()));
    assert_eq!(metatable(&owner, target), None);
    named(&owner, name.as_bytes(), Value::Integer(7));
    let before = snapshot(&owner);
    c_call!(luaL_setmetatable(state, name.as_ptr()));
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, target), None);
    named(&owner, name.as_bytes(), Value::Nil);
}

fn fail_closed_inputs() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    let mt = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    c_call!(lua_pushinteger(state, 9));
    prime_checkpoint(state);
    let before = snapshot(&owner);
    assert_eq!(c_call!(lua_getmetatable(state, 2)), 0);
    assert_eq!(c_call!(luaL_getmetafield(state, 2, c"__a30".as_ptr())), 0);
    assert_eq!(snapshot(&owner), before);
    for index in [0, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        let before = snapshot(&owner);
        assert!(protected_meta(state, 4, index, std::ptr::null()).0 > 0);
        assert_raised_settles(&owner, &before);
        let before = snapshot(&owner);
        assert!(protected_meta(state, 3, index, c"__a30".as_ptr()).0 > 0);
        assert_raised_settles(&owner, &before);
    }
    for index in [0, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        c_call!(lua_pushnil(state));
        let before = snapshot(&owner);
        assert!(protected_meta(state, 5, index, std::ptr::null()).0 > 0);
        assert_raised_settles(&owner, &before);
        c_call!(lua_settop(state, 2));
    }
    c_call!(lua_pushinteger(state, 11));
    let before = snapshot(&owner);
    assert!(protected_meta(state, 5, 1, std::ptr::null()).0 > 0);
    c_call!(luaL_setmetatable(state, c"a30".as_ptr()));
    assert_raised_settles(&owner, &before);
    c_call!(lua_settop(state, 2));
    let _wrong_mt = add_userdata(&owner);
    let before = snapshot(&owner);
    assert!(protected_meta(state, 5, 1, std::ptr::null()).0 > 0);
    assert_raised_settles(&owner, &before);
    c_call!(lua_settop(state, 2));
    let before = snapshot(&owner);
    assert!(protected_meta(state, 3, 1, std::ptr::null()).0 > 0);
    assert_raised_settles(&owner, &before);
    assert_eq!(
        protected_meta(std::ptr::null_mut(), 4, 1, std::ptr::null()).0,
        -1
    );
    assert_eq!(
        protected_meta(std::ptr::null_mut(), 5, 1, std::ptr::null()).0,
        -1
    );
    c_call!(luaL_setmetatable(state, std::ptr::null()));
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(snapshot(&owner).3, before.3);
    let pointer = state as usize;
    std::thread::spawn(move || {
        let state = pointer as *mut lua_State;
        assert_eq!(protected_meta(state, 4, 1, std::ptr::null()).0, -1);
        assert_eq!(protected_meta(state, 3, 1, c"__a30".as_ptr()).0, -1);
        assert_eq!(protected_meta(state, 5, 1, std::ptr::null()).0, -1);
        c_call!(luaL_setmetatable(state, c"a30".as_ptr()));
    })
    .join()
    .unwrap();
    owner
        .with_vm(|_| {
            assert_eq!(protected_meta(state, 4, 1, std::ptr::null()).0, -1);
            assert_eq!(protected_meta(state, 3, 1, c"__a30".as_ptr()).0, -1);
            assert_eq!(protected_meta(state, 5, 1, std::ptr::null()).0, -1);
            c_call!(luaL_setmetatable(state, c"a30".as_ptr()));
        })
        .unwrap();
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(snapshot(&owner).3, before.3);
    assert_eq!(metatable(&owner, target), Some(mt));
    assert_eq!(c_call!(lua_type(state, 2)), 3);
}

fn active_incremental_edge() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause
                    && vm.gc_color(target) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            assert_eq!(vm.gc_color(target), Ok(GcColor::Black));
        })
        .unwrap();
    let mt = add_table(&owner);
    assert_eq!(
        owner.with_vm(|vm| vm.gc_color(mt)).unwrap(),
        Ok(GcColor::Gray)
    );
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(metatable(&owner, target), Some(mt));
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert!(protected_meta(state, 4, 1, std::ptr::null()).0 > 0);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(c_call!(lua_getmetatable(state, 1)), 1);
    c_call!(lua_settop(state, 1));
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
}

fn generational_and_finalizer() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(target), Ok(GcAge::Old));
        })
        .unwrap();
    let mt = add_table(&owner);
    assert_eq!(owner.with_vm(|vm| vm.gc_age(mt)).unwrap(), Ok(GcAge::Young));
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    assert!(protected_meta(state, 5, 1, std::ptr::null()).0 > 0);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, target), None);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(metatable(&owner, target), Some(mt));
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();

    let finalizable = add_userdata(&owner);
    let gc_mt = add_table(&owner);
    owner
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
            vm.raw_set_byte_string_key(gc_mt, b"__gc", builtin).unwrap();
        })
        .unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(finalizable)).unwrap(),
        Ok(FinalizerState::Unregistered)
    );
    assert_eq!(c_call!(lua_setmetatable(state, -2)), 1);
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(finalizable)).unwrap(),
        Ok(FinalizerState::Registered)
    );

    let another = add_userdata(&owner);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(another), Ok(GcAge::Old));
        })
        .unwrap();
    let gc_mt = add_table(&owner);
    owner
        .with_vm(|vm| {
            let reg = registry(vm);
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            let builtin = vm
                .with_temporary_byte_string(b"error", |vm, key| {
                    vm.raw_get(globals, Value::Object(key))
                })
                .unwrap();
            vm.raw_set_byte_string_key(gc_mt, b"__gc", builtin).unwrap();
        })
        .unwrap();
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    assert!(protected_meta(state, 5, -2, std::ptr::null()).0 > 0);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, another), None);
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(another)).unwrap(),
        Ok(FinalizerState::Unregistered)
    );
    assert_eq!(c_call!(lua_setmetatable(state, -2)), 1);
    assert_eq!(metatable(&owner, another), Some(gc_mt));
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(another)).unwrap(),
        Ok(FinalizerState::Registered)
    );
}

fn allocation_failure_atomicity() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let target = add_userdata(&owner);
    let mt = add_table(&owner);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    c_call!(lua_settop(state, 20));
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert!(protected_meta(state, 4, 1, std::ptr::null()).0 > 0);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(metatable(&owner, target), Some(mt));
    assert_eq!(c_call!(lua_getmetatable(state, 1)), 1);
    c_call!(lua_settop(state, 1));
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(mt, b"__a30", Value::Integer(17))
                .unwrap()
        })
        .unwrap();
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::ObjectReserve))
        .unwrap();
    assert!(protected_meta(state, 3, 1, c"__a30".as_ptr()).0 > 0);
    assert_eq!(snapshot(&owner), before);
    assert_eq!(c_call!(luaL_getmetafield(state, 1, c"__a30".as_ptr())), 3);
    c_call!(lua_settop(state, 1));
    let name = CString::new("a30-fault").unwrap();
    named(&owner, name.as_bytes(), Value::Object(mt));
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::ObjectReserve))
        .unwrap();
    c_call!(luaL_setmetatable(state, name.as_ptr()));
    assert_eq!(snapshot(&owner), before);
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    c_call!(luaL_setmetatable(state, name.as_ptr()));
    assert_eq!(metatable(&owner, target), Some(mt));
}

#[derive(Clone, Copy)]
enum FaultAction {
    Get,
    Field,
    Named,
}

fn setup_fault(action: FaultAction) -> (StateOwner, ObjectRef, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    let target = add_userdata(&owner);
    let mt = add_table(&owner);
    match action {
        FaultAction::Named => {
            named(&owner, b"a30-ordinal", Value::Object(mt));
            c_call!(lua_settop(owner.as_ptr(), 1));
        }
        FaultAction::Get | FaultAction::Field => {
            assert_eq!(c_call!(lua_setmetatable(owner.as_ptr(), 1)), 1);
            if matches!(action, FaultAction::Field) {
                let result = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
                owner
                    .with_vm(|vm| {
                        vm.raw_set_byte_string_key(mt, b"__a30", Value::Object(result))
                            .unwrap()
                    })
                    .unwrap();
            }
            c_call!(lua_settop(owner.as_ptr(), 20));
        }
    }
    prime_checkpoint(owner.as_ptr());
    (owner, target, mt)
}

fn invoke_fault(action: FaultAction, owner: &StateOwner, target: ObjectRef) -> (i32, i32) {
    let state = owner.as_ptr();
    match action {
        FaultAction::Get => protected_meta(state, 4, 1, std::ptr::null()),
        FaultAction::Field => protected_meta(state, 3, 1, c"__a30".as_ptr()),
        FaultAction::Named => {
            c_call!(luaL_setmetatable(state, c"a30-ordinal".as_ptr()));
            (0, i32::from(metatable(owner, target).is_some()))
        }
    }
}

fn ordinal_failure_matrix() {
    for action in [FaultAction::Get, FaultAction::Field, FaultAction::Named] {
        let (dry, target, _) = setup_fault(action);
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        let expected = match action {
            FaultAction::Get | FaultAction::Named => 1,
            FaultAction::Field => 5,
        };
        assert_eq!(invoke_fault(action, &dry, target), (0, expected));
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start);
        for offset in 0..end - start {
            let (owner, target, mt) = setup_fault(action);
            let before = snapshot(&owner);
            let next = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
                .unwrap();
            let (status, value) = invoke_fault(action, &owner, target);
            assert_eq!(value, 0, "offset={offset}");
            assert_eq!(status > 0, !matches!(action, FaultAction::Named));
            assert_eq!(snapshot(&owner), before, "offset={offset}");
            assert_eq!(
                metatable(&owner, target),
                if matches!(action, FaultAction::Named) {
                    None
                } else {
                    Some(mt)
                }
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.attempt.ordinal, next + offset);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            assert_eq!(invoke_fault(action, &owner, target), (0, expected));
        }
        println!(
            "A30_ORDINAL action={} checked={}",
            match action {
                FaultAction::Get => "get",
                FaultAction::Field => "field",
                FaultAction::Named => "named",
            },
            end - start
        );
    }
}

fn named_failpoint_matrix() {
    for (action, points) in [
        (
            FaultAction::Get,
            &[FailPoint::RootReserve, FailPoint::HostLease][..],
        ),
        (
            FaultAction::Field,
            &[
                FailPoint::ObjectReserve,
                FailPoint::StringBytesReserve,
                FailPoint::RootReserve,
                FailPoint::HostLease,
            ][..],
        ),
        (
            FaultAction::Named,
            &[
                FailPoint::ObjectReserve,
                FailPoint::StringBytesReserve,
                FailPoint::RootReserve,
                FailPoint::HostLease,
            ][..],
        ),
    ] {
        for &point in points {
            let (owner, target, mt) = setup_fault(action);
            let before = snapshot(&owner);
            owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
            let (status, value) = invoke_fault(action, &owner, target);
            assert_eq!(value, 0, "point={point:?}");
            assert_eq!(status > 0, !matches!(action, FaultAction::Named));
            assert_eq!(snapshot(&owner), before, "point={point:?}");
            assert_eq!(
                metatable(&owner, target),
                if matches!(action, FaultAction::Named) {
                    None
                } else {
                    Some(mt)
                }
            );
            if matches!(
                point,
                FailPoint::ObjectReserve | FailPoint::StringBytesReserve
            ) {
                assert_eq!(
                    owner
                        .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.point)
                        .unwrap(),
                    Some(point)
                );
            }
        }
    }
}

fn setup_finalizer_setter() -> (StateOwner, ObjectRef, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    let target = add_userdata(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(target), Ok(GcAge::Old));
        })
        .unwrap();
    let mt = add_table(&owner);
    owner
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
            vm.raw_set_byte_string_key(mt, b"__gc", builtin).unwrap();
            assert_eq!(vm.gc_age(mt), Ok(GcAge::Young));
        })
        .unwrap();
    prime_checkpoint(owner.as_ptr());
    (owner, target, mt)
}

fn setter_ordinal_failure() {
    let (dry, target, mt) = setup_finalizer_setter();
    let start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert_eq!(c_call!(lua_setmetatable(dry.as_ptr(), 1)), 1);
    let end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(end > start);
    assert_eq!(metatable(&dry, target), Some(mt));
    assert_eq!(
        dry.with_vm(|vm| vm.finalizer_state(target)).unwrap(),
        Ok(FinalizerState::Registered)
    );
    for offset in 0..end - start {
        let (owner, target, mt) = setup_finalizer_setter();
        let before = snapshot(&owner);
        let next = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
            .unwrap();
        assert!(
            protected_meta(owner.as_ptr(), 5, 1, std::ptr::null()).0 > 0,
            "offset={offset}"
        );
        assert_eq!(snapshot(&owner), before);
        assert_eq!(metatable(&owner, target), None);
        assert_eq!(
            owner.with_vm(|vm| vm.finalizer_state(target)).unwrap(),
            Ok(FinalizerState::Unregistered)
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
                .unwrap(),
            next + offset
        );
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
            .unwrap();
        assert_eq!(c_call!(lua_setmetatable(owner.as_ptr(), 1)), 1);
        assert_eq!(metatable(&owner, target), Some(mt));
        assert_eq!(
            owner.with_vm(|vm| vm.finalizer_state(target)).unwrap(),
            Ok(FinalizerState::Registered)
        );
    }
    println!("A30_ORDINAL action=setter checked={}", end - start);
}
