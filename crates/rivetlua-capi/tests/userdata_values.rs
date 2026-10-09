use std::ffi::{c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_checkstack, lua_createtable, lua_getiuservalue, lua_gettop,
    lua_newuserdatauv, lua_pushinteger, lua_pushlightuserdata, lua_pushnil, lua_pushvalue,
    lua_rawequal, lua_setiuservalue, lua_settop, lua_touserdata, lua_type, lua_xmove,
};
use rivetlua_core::{ObjectRef, SlotId, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, GcAge, GcColor, GcMode, GcPhase, GcTrace, HostHandle,
    LedgerSnapshot, ObjectKind, RootId, RootKind, SlotState, VmError,
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
    fn rivetlua_capi_test_full_stack_boundary_a4b(state: *mut lua_State, mode: c_int) -> c_int;
}

fn protected_uservalue(
    state: *mut lua_State,
    operation: c_int,
    index: c_int,
    n: c_int,
) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：私有純 C checkpoint 擷取錯誤並於返回前清除 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            operation,
            index,
            n,
            std::ptr::null(),
            &mut answer,
        )
    };
    (status, answer)
}

fn prime_checkpoint(state: *mut lua_State) {
    assert_eq!(protected_uservalue(state, -1, 0, 0).0, 0);
}

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

// SAFETY：各測試的 state 均由仍存活的 StateOwner 持有；巨集只呼叫固定 C ABI，
// 不解參照 C 指標。跨執行緒測試只傳位址並驗證 fail-closed。
macro_rules! c_call {
    ($expression:expr) => {{ unsafe { $expression } }};
}

type Snapshot = (
    LedgerSnapshot,
    GcTrace,
    Vec<(RootKind, RootId, ObjectRef)>,
    Vec<Option<SlotState>>,
    Vec<i32>,
);

fn snapshot(owner: &StateOwner) -> Snapshot {
    let state = owner.as_ptr();
    let top = c_call!(lua_gettop(state));
    let tags = (1..=top)
        .map(|index| c_call!(lua_type(state, index)))
        .collect();
    let (ledger, trace, roots, slots) = owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            let slots = (0..64)
                .map(|index| vm.slot_state(SlotId::new(index)))
                .collect();
            (vm.ledger_snapshot(), vm.gc_trace(), roots, slots)
        })
        .unwrap();
    (ledger, trace, roots, slots, tags)
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

fn slot_census(owner: &StateOwner) -> (usize, usize, usize) {
    owner
        .with_vm(|vm| {
            let mut result = (0, 0, 0);
            let mut index = 0;
            while let Some(state) = vm.slot_state(SlotId::new(index)) {
                match state {
                    SlotState::Occupied => result.0 += 1,
                    SlotState::Free => result.1 += 1,
                    SlotState::Retired => result.2 += 1,
                }
                index += 1;
            }
            result
        })
        .unwrap()
}

fn assert_raised_state(owner: &StateOwner, before: &Snapshot) {
    let after = snapshot(owner);
    assert_eq!(after.2, before.2, "錯誤不得殘留 root");
    assert_eq!(after.4, before.4, "錯誤不得改動 stack");
    settle_error(owner);
    let settled = snapshot(owner);
    assert_eq!(settled.2, before.2);
    assert_eq!(settled.4, before.4);
}

fn userdata_at_root(owner: &StateOwner) -> ObjectRef {
    owner
        .with_vm(|vm| {
            let mut found = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Userdata) {
                    found.push(object);
                }
            });
            assert_eq!(found.len(), 1);
            found[0]
        })
        .unwrap()
}

fn assert_failed_get(owner: &StateOwner, index: i32) {
    prime_checkpoint(owner.as_ptr());
    let before = snapshot(owner);
    assert!(protected_uservalue(owner.as_ptr(), 6, index, 1).0 > 0);
    assert_raised_state(owner, &before);
}

fn assert_failed_set(owner: &StateOwner, index: i32) {
    prime_checkpoint(owner.as_ptr());
    let before = snapshot(owner);
    assert!(protected_uservalue(owner.as_ptr(), 7, index, 1).0 > 0);
    assert_raised_state(owner, &before);
}

#[test]
fn userdata_values_a29_matrix() {
    values_boundaries_and_macro();
    zero_slot_and_overwrite_lifetime();
    fail_closed_targets();
    roots_siblings_and_lifetime();
    getter_capacity_and_failures();
    active_getter_root_failure_atomicity();
    setter_remembered_failure();
}

fn active_getter_root_failure_atomicity() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    c_call!(lua_createtable(state, 0, 0));
    let child = owner
        .with_vm(|vm| {
            let mut child = None;
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    child = Some(object);
                }
            });
            child.unwrap()
        })
        .unwrap();
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    prime_checkpoint(state);
    owner
        .with_vm(|vm| {
            vm.incremental_step(1).unwrap();
            assert_eq!(vm.gc_color(child), Ok(GcColor::White));
            vm.inject_failure_once(FailPoint::RootReserve);
        })
        .unwrap();
    let before = snapshot(&owner);
    assert!(protected_uservalue(state, 6, 1, 1).0 > 0);
    assert_raised_state(&owner, &before);
}

fn zero_slot_and_overwrite_lifetime() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 0)).is_null());
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), -1);
    assert_eq!(c_call!(lua_type(state, -1)), 0);
    c_call!(lua_settop(state, 1));
    c_call!(lua_pushinteger(state, 7));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 0);
    assert_eq!(c_call!(lua_gettop(state)), 1);
    c_call!(lua_settop(state, 0));

    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    let target = userdata_at_root(&owner);
    let (first, first_root) = owner
        .with_vm(|vm| {
            let object = vm.allocate_table().unwrap();
            (object, HostHandle::<Value>::new(vm, object).unwrap())
        })
        .unwrap();
    owner.push_value(Value::Object(first)).unwrap();
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    drop(first_root);
    let (second, second_root) = owner
        .with_vm(|vm| {
            let object = vm.allocate_table().unwrap();
            (object, HostHandle::<Value>::new(vm, object).unwrap())
        })
        .unwrap();
    owner.push_value(Value::Object(second)).unwrap();
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    drop(second_root);
    owner
        .with_vm(|vm| {
            assert_eq!(vm.get_uservalue(target, 1), Ok(Some(Value::Object(second))));
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(second), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(second), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn values_boundaries_and_macro() {
    #[cfg(feature = "lua55")]
    let header = include_str!("../../../vendor/lua55/lua-5.5.1/src/lua.h");
    #[cfg(feature = "lua54")]
    let header = include_str!("../../../vendor/lua54/lua-5.4.9/src/lua.h");
    for line in [
        "#define lua_getuservalue(L,idx)\tlua_getiuservalue(L,idx,1)",
        "#define lua_setuservalue(L,idx)\tlua_setiuservalue(L,idx,1)",
    ] {
        assert!(header.lines().any(|actual| actual == line));
    }
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 3)).is_null());
    let target = userdata_at_root(&owner);
    assert_eq!(c_call!(lua_getiuservalue(state, -1, 1)), 0);
    assert_eq!(c_call!(lua_type(state, -1)), 0);
    c_call!(lua_settop(state, 1));
    for n in [-1, 0, 4, i32::MAX] {
        assert_eq!(c_call!(lua_getiuservalue(state, -1, n)), -1, "n={n}");
        assert_eq!(c_call!(lua_type(state, -1)), 0);
        assert_eq!(c_call!(lua_gettop(state)), 2);
        c_call!(lua_settop(state, 1));
    }
    c_call!(lua_pushinteger(state, 42));
    assert_eq!(c_call!(lua_setiuservalue(state, -2, 1)), 1);
    assert_eq!(c_call!(lua_gettop(state)), 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_uservalue(target, 1)).unwrap(),
        Ok(Some(Value::Integer(42)))
    );
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), 3);
    assert_eq!(c_call!(lua_type(state, -1)), 3);
    c_call!(lua_settop(state, 1));
    for n in [-1, 0, 4, i32::MAX] {
        c_call!(lua_pushinteger(state, 99));
        assert_eq!(c_call!(lua_setiuservalue(state, -2, n)), 0, "n={n}");
        assert_eq!(c_call!(lua_gettop(state)), 1);
        assert_eq!(
            owner.with_vm(|vm| vm.get_uservalue(target, 1)).unwrap(),
            Ok(Some(Value::Integer(42)))
        );
    }
    let mut token = 0x55_u8;
    let light = (&mut token as *mut u8).cast::<c_void>();
    c_call!(lua_pushlightuserdata(state, light));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 2)), 1);
    assert_eq!(c_call!(lua_getiuservalue(state, -1, 2)), 2);
    assert_eq!(c_call!(lua_touserdata(state, -1)), light);
    c_call!(lua_settop(state, 1));
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 3)), 1);
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 3)), 0);
    c_call!(lua_settop(state, 1));

    for (object, expected_tag) in [
        (
            owner
                .with_vm(|vm| vm.allocate_byte_string(b"value").unwrap())
                .unwrap(),
            4,
        ),
        (owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap(), 5),
        (
            owner
                .with_vm(|vm| vm.allocate_userdata(0, 0).unwrap())
                .unwrap(),
            7,
        ),
    ] {
        let held = owner
            .with_vm(|vm| HostHandle::<Value>::new(vm, object).unwrap())
            .unwrap();
        owner.push_value(Value::Object(object)).unwrap();
        assert_eq!(c_call!(lua_setiuservalue(state, 1, 3)), 1);
        assert_eq!(
            owner.with_vm(|vm| vm.get_uservalue(target, 3)).unwrap(),
            Ok(Some(Value::Object(object)))
        );
        assert_eq!(c_call!(lua_getiuservalue(state, 1, 3)), expected_tag);
        owner.push_value(Value::Object(object)).unwrap();
        assert_eq!(c_call!(lua_rawequal(state, -1, -2)), 1);
        c_call!(lua_settop(state, 1));
        drop(held);
    }
    // -1 在 pop 前指向剛複製的 target，因此能將 userdata 自身寫進 slot 1。
    c_call!(lua_pushvalue(state, 1));
    assert_eq!(c_call!(lua_setiuservalue(state, -1, 1)), 1);
    assert_eq!(
        owner.with_vm(|vm| vm.get_uservalue(target, 1)).unwrap(),
        Ok(Some(Value::Object(target)))
    );
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), 7);
    assert_eq!(c_call!(lua_rawequal(state, 1, -1)), 1);
    c_call!(lua_settop(state, 1));
    // lua.h 的兩個巨集直接轉送 n=1；以 index 1 primitive 路徑驗證其效果。
    c_call!(lua_pushinteger(state, 7));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), 3);
    c_call!(lua_settop(state, 0));
}

fn fail_closed_targets() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 1_u8;
    for kind in 0..6 {
        c_call!(lua_settop(state, 0));
        match kind {
            0 => c_call!(lua_pushnil(state)),
            1 => c_call!(lua_pushinteger(state, 3)),
            2 => c_call!(lua_pushlightuserdata(state, (&mut token as *mut u8).cast())),
            3 => c_call!(lua_createtable(state, 0, 0)),
            4 | 5 => {
                let value = owner
                    .with_vm(|vm| {
                        let mut registry = None;
                        vm.visit_roots(|root_kind, _, object| {
                            if root_kind == RootKind::Registry
                                && vm.object_kind(object) == Ok(ObjectKind::Table)
                            {
                                registry = Some(object);
                            }
                        });
                        let Value::Object(globals) =
                            vm.raw_get(registry.unwrap(), Value::Integer(2)).unwrap()
                        else {
                            panic!("globals");
                        };
                        vm.install_basic_builtins(globals).unwrap();
                        let key = vm.allocate_byte_string(b"type").unwrap();
                        let Value::Object(function) =
                            vm.raw_get(globals, Value::Object(key)).unwrap()
                        else {
                            panic!("type");
                        };
                        if kind == 4 {
                            (function, HostHandle::<Value>::new(vm, function).unwrap())
                        } else {
                            let handle = vm.new_coroutine(Value::Object(function)).unwrap();
                            let Value::Object(object) = handle.as_value(vm).unwrap() else {
                                panic!("thread");
                            };
                            (object, handle)
                        }
                    })
                    .unwrap();
                owner.push_value(Value::Object(value.0)).unwrap();
            }
            _ => unreachable!(),
        }
        assert_failed_get(&owner, 1);
        c_call!(lua_pushinteger(state, 9));
        assert_failed_set(&owner, 1);
    }
    c_call!(lua_settop(state, 0));
    assert_failed_get(&owner, 0);
    assert_failed_get(&owner, 1);
    assert_failed_get(&owner, -1);
    assert_failed_get(&owner, REGISTRY_INDEX);
    assert_failed_get(&owner, OTHER_REGISTRY_INDEX);
    assert_failed_get(&owner, REGISTRY_INDEX - 1);
    c_call!(lua_pushinteger(state, 9));
    for index in [
        0,
        2,
        -2,
        REGISTRY_INDEX,
        OTHER_REGISTRY_INDEX,
        REGISTRY_INDEX - 1,
    ] {
        assert_failed_set(&owner, index);
    }
    c_call!(lua_settop(state, 0));
    assert_failed_set(&owner, 1); // top value 不存在。
    assert_eq!(protected_uservalue(std::ptr::null_mut(), 6, 1, 1).0, -1);
    assert_eq!(protected_uservalue(std::ptr::null_mut(), 7, 1, 1).0, -1);
    let before = snapshot(&owner);
    owner
        .with_vm(|_| {
            assert_eq!(protected_uservalue(state, 6, 1, 1).0, -1);
            assert_eq!(protected_uservalue(state, 7, 1, 1).0, -1);
        })
        .unwrap();
    assert_eq!(snapshot(&owner), before);
    let address = state.expose_provenance();
    std::thread::spawn(move || {
        let foreign = std::ptr::with_exposed_provenance_mut(address);
        assert_eq!(protected_uservalue(foreign, 6, 1, 1).0, -1);
        assert_eq!(protected_uservalue(foreign, 7, 1, 1).0, -1);
    })
    .join()
    .unwrap();
    assert_eq!(snapshot(&owner), before);
}

fn roots_siblings_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    let other = sibling.as_ptr();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    let target = userdata_at_root(&owner);
    let child = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let hold = owner
        .with_vm(|vm| HostHandle::<Value>::new(vm, child).unwrap())
        .unwrap();
    owner.push_value(Value::Object(child)).unwrap();
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    drop(hold);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_pushvalue(state, 1));
    c_call!(lua_xmove(state, other, 1));
    c_call!(lua_settop(state, 0));
    assert_eq!(c_call!(lua_getiuservalue(other, 1, 1)), 5);
    assert_eq!(c_call!(lua_gettop(other)), 2);
    c_call!(lua_settop(other, 64));
    c_call!(lua_settop(other, 2));
    sibling
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(target), Ok(ObjectKind::Userdata));
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_pushnil(other));
    assert_eq!(c_call!(lua_setiuservalue(other, 1, 1)), 1);
    c_call!(lua_settop(other, 2)); // getter 的獨立 stack root 應繼續保活 child。
    sibling
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_settop(other, 1));
    sibling
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        })
        .unwrap();
    drop(owner);
    assert_eq!(c_call!(lua_getiuservalue(other, 1, 1)), 0);
    c_call!(lua_settop(other, 0));
    sibling
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(target), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn getter_capacity_and_failures() {
    let limited = StateOwner::new().unwrap();
    let state = limited.as_ptr();
    let limited_probe = limited.with_vm(|vm| vm.ledger_probe()).unwrap();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    prime_checkpoint(state);
    let before = snapshot(&limited);
    let before_slots = slot_census(&limited);
    for mode in 0..=4 {
        // SAFETY：私有 C helper 先建立 public pcall，再於 callback 內填滿 stack。
        let status = unsafe { rivetlua_capi_test_full_stack_boundary_a4b(state, mode) };
        assert_eq!(status, if mode == 3 { 0 } else { 4 }, "mode={mode}");
        assert_eq!(c_call!(lua_gettop(state)), 1);
        settle_error(&limited);
        let after = snapshot(&limited);
        let after_slots = slot_census(&limited);
        // 每個不同 C callback 的 registry entry 各收取 24 B；巨型暫存 stack 已退還。
        assert_eq!(
            after.0.host_allocation_bytes - before.0.host_allocation_bytes,
            24 * (mode as usize + 1),
            "mode={mode}"
        );
        assert_eq!(after_slots.0, before_slots.0, "mode={mode}");
        assert_eq!(after_slots.2, before_slots.2, "mode={mode}");
        assert_eq!(
            after.0.lua_heap_bytes - before.0.lua_heap_bytes,
            (after_slots.1 - before_slots.1) * 136,
            "mode={mode}"
        );
        assert_eq!(after.2, before.2, "mode={mode}");
        assert_eq!(after.4, before.4, "mode={mode}");
    }

    // top=20 時首次 checkpoint 須先預留錯誤槽；故障仍保持原子性。
    let preflight = StateOwner::new().unwrap();
    let preflight_state = preflight.as_ptr();
    assert!(!c_call!(lua_newuserdatauv(preflight_state, 0, 1)).is_null());
    c_call!(lua_settop(preflight_state, 20));
    let preflight_before = snapshot(&preflight);
    let ordinal = preflight
        .with_vm(|vm| {
            let ordinal = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(ordinal);
            ordinal
        })
        .unwrap();
    assert_eq!(protected_uservalue(preflight_state, -1, 0, 0).0, -1);
    assert_eq!(snapshot(&preflight), preflight_before);
    assert_eq!(
        preflight
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
            .unwrap(),
        ordinal
    );
    assert_eq!(protected_uservalue(preflight_state, -1, 0, 0).0, 0);
    let prepared = snapshot(&preflight);
    assert_eq!(
        prepared.0.host_allocation_bytes - preflight_before.0.host_allocation_bytes,
        2880
    );
    assert_eq!(protected_uservalue(preflight_state, -1, 0, 0).0, 0);
    assert_eq!(snapshot(&preflight).0, prepared.0);
    let probe = preflight.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(preflight);
    assert_eq!(probe.snapshot().committed, 0);
    settle_error(&limited);
    assert_eq!(snapshot(&limited).2, before.2);
    assert_eq!(snapshot(&limited).4, before.4);
    drop(limited);
    assert_eq!(limited_probe.snapshot().committed, 0);
    assert_eq!(limited_probe.snapshot().reserved, 0);

    let mut observed = Vec::new();
    let mut first_success = None;
    for offset in 0..8_u64 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        owner
            .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
            .unwrap();
        assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
        let target = userdata_at_root(&owner);
        c_call!(lua_createtable(state, 0, 0));
        let child = owner
            .with_vm(|vm| {
                let mut found = None;
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                        found = Some(object);
                    }
                });
                found.unwrap()
            })
            .unwrap();
        assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
        c_call!(lua_settop(state, 20));
        prime_checkpoint(state);
        let before = snapshot(&owner);
        let next = owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
                next
            })
            .unwrap();
        let (status, result) = protected_uservalue(state, 6, 1, 1);
        if status > 0 {
            assert_raised_state(&owner, &before);
            assert_eq!(
                owner.with_vm(|vm| vm.get_uservalue(target, 1)).unwrap(),
                Ok(Some(Value::Object(child)))
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            assert_eq!(failure.attempt.ordinal, next + offset);
            observed.push((
                failure.attempt.domain,
                failure.attempt.point,
                failure.attempt.site.file,
            ));
            assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), 5);
            assert_eq!(c_call!(lua_gettop(state)), 21);
        } else {
            assert_eq!(status, 0);
            assert_eq!(result, 5);
            first_success = Some(offset);
            break;
        }
    }
    assert_eq!(first_success, Some(1), "{observed:?}");
    assert_eq!(observed.len(), 1);
    for (seen, suffix) in observed.iter().zip(["roots.rs"]) {
        assert_eq!(seen.0, AllocationDomain::Host);
        assert_eq!(seen.1, None);
        assert!(seen.2.ends_with(suffix), "{seen:?}");
    }
    let named = StateOwner::new().unwrap();
    let state = named.as_ptr();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    c_call!(lua_createtable(state, 0, 0));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    prime_checkpoint(state);
    let before = snapshot(&named);
    named
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert!(protected_uservalue(state, 6, 1, 1).0 > 0);
    assert_raised_state(&named, &before);
    assert_eq!(c_call!(lua_getiuservalue(state, 1, 1)), 5);
}

#[test]
fn a4b_stack_spare_capacity_ledger() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let before = snapshot(&owner);
    let ordinal = owner
        .with_vm(|vm| {
            let ordinal = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(ordinal);
            ordinal
        })
        .unwrap();
    c_call!(lua_settop(state, 1_000_000));
    assert_eq!(c_call!(lua_gettop(state)), 0);
    assert_eq!(snapshot(&owner), before, "故障時容量成長不可半提交");
    let failure = owner
        .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
        .unwrap();
    assert_eq!(failure.attempt.ordinal, ordinal);
    assert_eq!(failure.attempt.domain, AllocationDomain::Host);
    assert_eq!(failure.attempt.bytes, 144_000_144);

    c_call!(lua_settop(state, 1_000_000));
    assert_eq!(c_call!(lua_gettop(state)), 1_000_000);
    let filled = snapshot(&owner);
    assert_eq!(
        filled.0.host_allocation_bytes - before.0.host_allocation_bytes,
        144_000_144
    );
    assert_eq!(c_call!(lua_checkstack(state, 1)), 0);
    assert_eq!(c_call!(lua_gettop(state)), 1_000_000);
    c_call!(lua_settop(state, 0));
    assert_eq!(
        snapshot(&owner).0,
        before.0,
        "空 stack 須退還 emergency backing"
    );
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

fn setter_remembered_failure() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
        })
        .unwrap();
    assert!(!c_call!(lua_newuserdatauv(state, 0, 1)).is_null());
    let target = userdata_at_root(&owner);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.gc_age(target), Ok(GcAge::Old));
        })
        .unwrap();
    c_call!(lua_createtable(state, 0, 0));
    let child = owner
        .with_vm(|vm| {
            let mut found = None;
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    found = Some(object);
                }
            });
            found.unwrap()
        })
        .unwrap();
    prime_checkpoint(state);
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    assert!(protected_uservalue(state, 7, 1, 1).0 > 0);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(snapshot(&owner).4, before.4);
    assert_eq!(
        owner.with_vm(|vm| vm.get_uservalue(target, 1)).unwrap(),
        Ok(Some(Value::Nil))
    );
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    assert_eq!(c_call!(lua_gettop(state)), 1);
    owner
        .with_vm(|vm| {
            assert_eq!(vm.get_uservalue(target, 1), Ok(Some(Value::Object(child))));
            assert_eq!(vm.gc_trace().remembered_len, 1);
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();
    c_call!(lua_pushnil(state));
    assert_eq!(c_call!(lua_setiuservalue(state, 1, 1)), 1);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        })
        .unwrap();
}
