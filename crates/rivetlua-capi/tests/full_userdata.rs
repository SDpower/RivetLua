use std::ffi::c_void;

use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_isuserdata, lua_newuserdatauv, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushvalue, lua_rawlen, lua_settop,
    lua_touserdata, lua_type, lua_xmove,
};
use rivetlua_core::{ObjectRef, SlotId, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, GcPhase, GcTrace, HostHandle, LedgerSnapshot, ObjectKind, RootId,
    RootKind, SlotState, VmError,
};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

type Snapshot = (
    LedgerSnapshot,
    GcTrace,
    Vec<(RootKind, RootId, ObjectRef)>,
    Vec<Option<SlotState>>,
    Vec<(i32, usize, usize)>,
);

fn snapshot(owner: &StateOwner) -> Snapshot {
    let state = owner.as_ptr();
    let top = unsafe { lua_gettop(state) };
    let stack = (1..=top)
        .map(|index| {
            // SAFETY：state 存活；三種查詢均為唯讀，指標僅比較位址。
            unsafe {
                (
                    lua_type(state, index),
                    lua_touserdata(state, index).expose_provenance(),
                    lua_rawlen(state, index) as usize,
                )
            }
        })
        .collect();
    let vm = owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            let slots = (0..64)
                .map(|index| vm.slot_state(SlotId::new(index)))
                .collect();
            (vm.ledger_snapshot(), vm.gc_trace(), roots, slots)
        })
        .unwrap();
    (vm.0, vm.1, vm.2, vm.3, stack)
}

fn rooted_userdata(owner: &StateOwner) -> ObjectRef {
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

fn assert_pure_reads(owner: &StateOwner, index: i32, expected: (*mut c_void, u64, i32, i32)) {
    let before = snapshot(owner);
    let before_alloc = owner.with_vm(|vm| vm.allocation_trace()).unwrap();
    // SAFETY：state 存活；讀取無效索引須 fail-closed。
    unsafe {
        for _ in 0..2 {
            assert_eq!(lua_touserdata(owner.as_ptr(), index), expected.0);
            assert_eq!(lua_rawlen(owner.as_ptr(), index), expected.1);
            assert_eq!(lua_isuserdata(owner.as_ptr(), index), expected.2);
            assert_eq!(lua_type(owner.as_ptr(), index), expected.3);
        }
    }
    assert_eq!(snapshot(owner), before);
    assert_eq!(
        owner.with_vm(|vm| vm.allocation_trace()).unwrap(),
        before_alloc
    );
}

#[test]
fn full_userdata_a28_matrix() {
    pointer_uservalues_and_gc();
    scalar_and_invalid_reads();
    siblings_and_lifetime();
    limits_and_failure_atomicity();
}

fn pointer_uservalues_and_gc() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    for (size, nuv) in [(0, 0), (1, 1), (15, 3), (16, 0), (17, 1), (4097, 3)] {
        let pointer = unsafe { lua_newuserdatauv(state, size, nuv) };
        assert!(!pointer.is_null(), "size={size} nuv={nuv}");
        assert_eq!(pointer.expose_provenance() % 16, 0);
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        let object = rooted_userdata(&owner);
        owner
            .with_vm(|vm| {
                assert_eq!(vm.userdata_ptr(object), Ok(pointer.cast()));
                assert_eq!(vm.userdata_len(object), Ok(size));
                for index in 1..=nuv as usize {
                    assert_eq!(vm.get_uservalue(object, index), Ok(Some(Value::Nil)));
                }
                assert_eq!(vm.get_uservalue(object, 0), Ok(None));
                assert_eq!(vm.get_uservalue(object, nuv as usize + 1), Ok(None));
            })
            .unwrap();
        assert_pure_reads(&owner, -1, (pointer, size as u64, 1, 7));
        let stress = || {
            // SAFETY：所有 C 呼叫均使用仍由 owner 持有的有效 state。
            unsafe {
                lua_pushinteger(state, 3);
                lua_pushvalue(state, 1);
                assert_eq!(lua_touserdata(state, 3), pointer);
                lua_settop(state, 1);
            }
            owner
                .with_vm(|vm| {
                    for _ in 0..24 {
                        vm.allocate_table().unwrap();
                    }
                    vm.collect().unwrap();
                    vm.collect().unwrap();
                    assert_eq!(vm.userdata_ptr(object), Ok(pointer.cast()));
                })
                .unwrap();
            assert_pure_reads(&owner, 1, (pointer, size as u64, 1, 7));
        };
        if size > 0 {
            // SAFETY：size>0、指標非空且 16 對齊、長度已核對；stress 期間
            // 第 1 個 stack slot 持續保活。僅在此區塊寫讀 C bytes，pop 後不解參。
            unsafe {
                pointer.cast::<u8>().write(0x52);
                pointer.cast::<u8>().add(size - 1).write(0xa7);
                assert_eq!(
                    pointer.cast::<u8>().read(),
                    if size == 1 { 0xa7 } else { 0x52 }
                );
                assert_eq!(pointer.cast::<u8>().add(size - 1).read(), 0xa7);
                stress();
                assert_eq!(
                    pointer.cast::<u8>().read(),
                    if size == 1 { 0xa7 } else { 0x52 }
                );
                assert_eq!(pointer.cast::<u8>().add(size - 1).read(), 0xa7);
            }
        } else {
            stress();
        }
        unsafe { lua_settop(state, 0) };
        owner
            .with_vm(|vm| {
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
            })
            .unwrap();
    }
    // 固定 lua.h：lua_newuserdata(L,s) 展開為 lua_newuserdatauv(L,s,1)。
    assert!(!unsafe { lua_newuserdatauv(state, 1, 1) }.is_null());
    let object = rooted_userdata(&owner);
    assert_eq!(
        owner.with_vm(|vm| vm.get_uservalue(object, 1)).unwrap(),
        Ok(Some(Value::Nil))
    );
    assert_eq!(
        owner.with_vm(|vm| vm.get_uservalue(object, 2)).unwrap(),
        Ok(None)
    );
    unsafe { lua_settop(state, 0) };
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

fn scalar_and_invalid_reads() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_pure_reads(&owner, 1, (std::ptr::null_mut(), 0, 0, -1));
    unsafe {
        lua_pushnil(state);
        lua_pushinteger(state, 4);
        lua_pushlstring(state, b"abc".as_ptr().cast(), 3);
        lua_createtable(state, 0, 0);
    }
    for (index, tag, length) in [(1, 0, 0), (2, 3, 0), (3, 4, 3), (4, 5, 0)] {
        assert_pure_reads(&owner, index, (std::ptr::null_mut(), length, 0, tag));
    }
    let mut token = 0x11_u8;
    let light = (&mut token as *mut u8).cast::<c_void>();
    unsafe {
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, light);
    }
    assert_pure_reads(&owner, 5, (std::ptr::null_mut(), 0, 1, 2));
    assert_pure_reads(&owner, 6, (light, 0, 1, 2));
    let (function, thread) = owner
        .with_vm(|vm| {
            let mut registry = None;
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    registry = Some(object);
                }
            });
            let registry = registry.unwrap();
            let Value::Object(globals) = vm.raw_get(registry, Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須是 table");
            };
            vm.install_basic_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"type").unwrap();
            let Value::Object(function) = vm.raw_get(globals, Value::Object(key)).unwrap() else {
                panic!("basic type 必須是 function");
            };
            let handle = HostHandle::<Value>::new(vm, function).unwrap();
            let thread = vm.new_coroutine(Value::Object(function)).unwrap();
            (handle, thread)
        })
        .unwrap();
    let (function_value, thread_value) = owner
        .with_vm(|vm| (function.as_value(vm).unwrap(), thread.as_value(vm).unwrap()))
        .unwrap();
    owner.push_value(function_value).unwrap();
    owner.push_value(thread_value).unwrap();
    assert_pure_reads(&owner, 7, (std::ptr::null_mut(), 0, 0, 6));
    assert_pure_reads(&owner, 8, (std::ptr::null_mut(), 0, 0, 8));
    for index in [0, 9, -9, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert_pure_reads(&owner, index, (std::ptr::null_mut(), 0, 0, -1));
    }
    let registry_len = unsafe { lua_rawlen(state, REGISTRY_INDEX) };
    assert_pure_reads(
        &owner,
        REGISTRY_INDEX,
        (std::ptr::null_mut(), registry_len, 0, 5),
    );
    unsafe { lua_settop(state, 0) };
    assert_pure_reads(&owner, -1, (std::ptr::null_mut(), 0, 0, -1));
    assert!(unsafe { lua_newuserdatauv(std::ptr::null_mut(), 8, 1) }.is_null());
    assert!(unsafe { lua_touserdata(std::ptr::null_mut(), 1) }.is_null());
}

fn siblings_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let foreign = StateOwner::new().unwrap();
    let pointer = unsafe { lua_newuserdatauv(owner.as_ptr(), 17, 1) };
    assert!(!pointer.is_null());
    let object = rooted_userdata(&owner);
    unsafe {
        lua_pushvalue(owner.as_ptr(), 1);
        lua_xmove(owner.as_ptr(), foreign.as_ptr(), 1);
        assert_eq!(lua_gettop(owner.as_ptr()), 2);
        assert_eq!(lua_gettop(foreign.as_ptr()), 0);
        lua_xmove(owner.as_ptr(), sibling.as_ptr(), 1);
        assert_eq!(lua_touserdata(sibling.as_ptr(), 1), pointer);
        lua_settop(owner.as_ptr(), 0);
    }
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_pure_reads(&sibling, 1, (pointer, 17, 1, 7));
    drop(owner);
    assert_pure_reads(&sibling, 1, (pointer, 17, 1, 7));
    unsafe { lua_settop(sibling.as_ptr(), 0) };
    sibling
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn limits_and_failure_atomicity() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let before = snapshot(&owner);
    for nuv in [-1, i16::MAX as i32, i32::MAX] {
        assert!(unsafe { lua_newuserdatauv(state, 17, nuv) }.is_null());
        assert_eq!(snapshot(&owner), before);
    }
    assert!(unsafe { lua_newuserdatauv(state, usize::MAX, 1) }.is_null());
    assert_eq!(snapshot(&owner), before);
    let near_boundary = unsafe { lua_newuserdatauv(state, 1, i16::MAX as i32 - 1) };
    assert!(!near_boundary.is_null());
    let object = rooted_userdata(&owner);
    assert_eq!(
        owner
            .with_vm(|vm| vm.get_uservalue(object, i16::MAX as usize - 1))
            .unwrap(),
        Ok(Some(Value::Nil))
    );
    assert_eq!(
        owner
            .with_vm(|vm| vm.get_uservalue(object, i16::MAX as usize))
            .unwrap(),
        Ok(None)
    );
    unsafe { lua_settop(state, 0) };

    let mut observed = Vec::new();
    let mut first_success = None;
    for offset in 0..24_u64 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { lua_settop(state, 20) };
        let before = snapshot(&owner);
        owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
            })
            .unwrap();
        let pointer = unsafe { lua_newuserdatauv(state, 17, 3) };
        if pointer.is_null() {
            assert_eq!(snapshot(&owner), before, "ordinal {offset}");
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            observed.push((
                failure.attempt.domain,
                failure.attempt.point,
                failure.attempt.site.file,
            ));
            let retry = unsafe { lua_newuserdatauv(state, 17, 3) };
            assert!(!retry.is_null(), "ordinal {offset} retry");
            assert_eq!(unsafe { lua_gettop(state) }, 21);
        } else {
            first_success = Some(offset);
            break;
        }
    }
    let first_success = first_success.expect("ordinal sweep 必須到達首個成功");
    assert_eq!(first_success, 6, "{observed:?}");
    let expected = [
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::UserdataBytesReserve),
            "heap.rs",
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::UserdataUservaluesReserve),
            "heap.rs",
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            "heap.rs",
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            "heap.rs",
        ),
        (AllocationDomain::Host, None, "roots.rs"),
        (AllocationDomain::Host, None, "heap.rs"),
    ];
    assert_eq!(observed.len(), expected.len());
    for (index, ((domain, point, site), (expected_domain, expected_point, suffix))) in
        observed.iter().zip(expected).enumerate()
    {
        assert_eq!(
            (*domain, *point),
            (expected_domain, expected_point),
            "ordinal {index}"
        );
        assert!(site.ends_with(suffix), "ordinal {index}: {site}");
    }
    for point in [
        FailPoint::UserdataBytesReserve,
        FailPoint::UserdataUservaluesReserve,
        FailPoint::SlotReserve,
        FailPoint::ObjectReserve,
        FailPoint::ObjectInitialize,
        FailPoint::RootReserve,
    ] {
        let named = StateOwner::new().unwrap();
        let named_before = snapshot(&named);
        named.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        assert!(unsafe { lua_newuserdatauv(named.as_ptr(), 17, 3) }.is_null());
        assert_eq!(snapshot(&named), named_before);
        assert!(!unsafe { lua_newuserdatauv(named.as_ptr(), 17, 3) }.is_null());
    }

    let budget = StateOwner::new().unwrap();
    let ceiling = budget.with_vm(|vm| vm.ledger_snapshot().committed).unwrap();
    budget
        .with_vm(|vm| vm.set_allocation_limit(ceiling))
        .unwrap();
    let budget_before = snapshot(&budget);
    assert!(unsafe { lua_newuserdatauv(budget.as_ptr(), 17, 3) }.is_null());
    assert_eq!(snapshot(&budget), budget_before);
    budget
        .with_vm(|vm| vm.set_allocation_limit(usize::MAX))
        .unwrap();
    assert!(!unsafe { lua_newuserdatauv(budget.as_ptr(), 17, 3) }.is_null());

    let limited = StateOwner::new().unwrap();
    let limited_state = limited.as_ptr();
    unsafe { lua_settop(limited_state, 1_000_000) };
    assert_eq!(unsafe { lua_gettop(limited_state) }, 1_000_000);
    let limit_before = limited
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().count(RootKind::Host),
            )
        })
        .unwrap();
    assert!(unsafe { lua_newuserdatauv(limited_state, 1, 0) }.is_null());
    assert_eq!(unsafe { lua_gettop(limited_state) }, 1_000_000);
    assert_eq!(
        limited
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().count(RootKind::Host),
                )
            })
            .unwrap(),
        limit_before
    );
    unsafe { lua_settop(limited_state, 0) };

    let busy = StateOwner::new().unwrap();
    let busy_state = busy.as_ptr();
    busy.with_vm(|_| {
        assert!(unsafe { lua_newuserdatauv(busy_state, 1, 0) }.is_null());
        assert!(unsafe { lua_touserdata(busy_state, 1) }.is_null());
    })
    .unwrap();
    let wrong_state = busy_state.expose_provenance();
    std::thread::spawn(move || {
        let pointer = std::ptr::with_exposed_provenance_mut(wrong_state);
        assert!(unsafe { lua_newuserdatauv(pointer, 1, 0) }.is_null());
        assert!(unsafe { lua_touserdata(pointer, 1) }.is_null());
    })
    .join()
    .unwrap();

    let active = StateOwner::new().unwrap();
    let state = active.as_ptr();
    active
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();
    for point in [FailPoint::MarkReserve, FailPoint::WorkReserve] {
        let before = snapshot(&active);
        active.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        assert!(
            unsafe { lua_newuserdatauv(state, 17, 3) }.is_null(),
            "{point:?}"
        );
        assert_eq!(snapshot(&active), before, "{point:?}");
        if point == FailPoint::MarkReserve {
            assert_eq!(
                active
                    .with_vm(|vm| vm.allocation_trace().last_failure)
                    .unwrap()
                    .unwrap()
                    .attempt
                    .point,
                Some(point)
            );
        }
        assert!(!unsafe { lua_newuserdatauv(state, 17, 3) }.is_null());
        unsafe { lua_settop(state, 0) };
    }
}
