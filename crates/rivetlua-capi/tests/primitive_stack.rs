use std::ffi::c_void;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_isinteger, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushnil, lua_pushnumber, lua_rawequal, lua_rotate,
    lua_settop, lua_toboolean, lua_tointegerx, lua_tonumberx, lua_touserdata, lua_type, lua_xmove,
};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, VmError,
};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, RootSnapshot);
type StackSnapshot = (i32, Vec<(i32, i64, u64, i32, usize)>, Vec<i32>);

fn vm_snapshot(owner: &StateOwner) -> VmSnapshot {
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

fn stack_snapshot(state: *mut lua_State) -> StackSnapshot {
    // SAFETY：對應的 StateOwner 在呼叫期間有效；僅讀取目前 top 內的 slots。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer = if tag == 3 && lua_isinteger(state, index) != 0 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let number = if tag == 3 && lua_isinteger(state, index) == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let boolean = if tag == 1 {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                let pointer = if tag == 2 {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                (tag, integer, number, boolean, pointer)
            })
            .collect();
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        (top, slots, identities)
    }
}

fn host_tables(owner: &StateOwner) -> Vec<ObjectRef> {
    owner
        .with_vm(|vm| {
            let mut tables = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    tables.push(object);
                }
            });
            tables
        })
        .unwrap()
}

fn assert_unchanged(
    owner: &StateOwner,
    state: *mut lua_State,
    stack: &StackSnapshot,
    vm: &VmSnapshot,
) {
    assert_eq!(&stack_snapshot(state), stack);
    assert_eq!(&vm_snapshot(owner), vm);
}

fn scalar_and_settop_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 7_u8;
    let pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：owner 有效；lightuserdata 指標只作 opaque 值，不解參照。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 0);
        lua_pushboolean(state, -7);
        lua_pushinteger(state, i64::MIN);
        lua_pushinteger(state, i64::MAX);
        lua_pushnumber(state, -0.0);
        lua_pushnumber(state, f64::NAN);
        lua_pushnumber(state, 1.25);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, pointer);
        assert_eq!(lua_gettop(state), 10);
        assert_eq!(lua_type(state, 1), 0);
        assert_eq!(lua_toboolean(state, 2), 0);
        assert_eq!(lua_toboolean(state, 3), 1);
        assert_eq!(lua_tointegerx(state, 4, std::ptr::null_mut()), i64::MIN);
        assert_eq!(lua_tointegerx(state, 5, std::ptr::null_mut()), i64::MAX);
        assert_eq!(lua_isinteger(state, 6), 0);
        assert_eq!(
            lua_tonumberx(state, 6, std::ptr::null_mut()).to_bits(),
            (-0.0_f64).to_bits()
        );
        assert!(lua_tonumberx(state, 7, std::ptr::null_mut()).is_nan());
        assert_eq!(lua_tonumberx(state, 8, std::ptr::null_mut()), 1.25);
        assert!(lua_touserdata(state, 9).is_null());
        assert_eq!(lua_touserdata(state, 10), pointer);
        lua_settop(state, 0);
        assert_eq!(lua_gettop(state), 0);

        lua_pushinteger(state, 10);
        lua_pushinteger(state, 20);
        lua_settop(state, 5);
        assert_eq!(lua_gettop(state), 5);
        for index in 3..=5 {
            assert_eq!(lua_type(state, index), 0);
        }
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 4);
        lua_settop(state, -1);
        assert_eq!(lua_gettop(state), 4);
        let stack = stack_snapshot(state);
        let vm = vm_snapshot(&owner);
        lua_settop(state, -6);
        assert_unchanged(&owner, state, &stack, &vm);
        lua_settop(state, i32::MAX);
        assert_unchanged(&owner, state, &stack, &vm);
        lua_settop(state, REGISTRY_INDEX);
        assert_unchanged(&owner, state, &stack, &vm);

        lua_createtable(state, 0, 0);
        let object = host_tables(&owner)[0];
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        lua_settop(state, -2);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
        lua_settop(state, 0);
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
            })
            .unwrap();
    }
    let stack = stack_snapshot(state);
    let vm = vm_snapshot(&owner);
    // SAFETY：null state 須由既有 with_state fail-closed；有效 state 不受影響。
    unsafe {
        lua_settop(std::ptr::null_mut(), 5);
        lua_pushnil(std::ptr::null_mut());
        lua_pushboolean(std::ptr::null_mut(), 1);
        lua_pushinteger(std::ptr::null_mut(), 1);
        lua_pushnumber(std::ptr::null_mut(), 1.0);
        lua_pushlightuserdata(std::ptr::null_mut(), pointer);
    }
    assert_unchanged(&owner, state, &stack, &vm);
    let busy = owner.with_vm(|_| {
        // SAFETY：state 有效；同 VM 借用中所有入口須拒絕。
        unsafe {
            lua_pushnil(state);
            lua_pushboolean(state, 1);
            lua_pushinteger(state, 1);
            lua_pushnumber(state, 1.0);
            lua_pushlightuserdata(state, pointer);
            lua_settop(state, 1);
        }
    });
    assert!(busy.is_ok());
    assert_unchanged(&owner, state, &stack, &vm);
}

fn rotate_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 有效；測試 slot 重排且不新增 root。
    unsafe {
        lua_pushinteger(state, 1);
        lua_pushinteger(state, 2);
        lua_pushinteger(state, 3);
        lua_createtable(state, 0, 0);
        let roots = vm_snapshot(&owner);
        lua_rotate(state, 1, 1);
        assert_eq!(lua_type(state, 1), 5);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 1);
        lua_rotate(state, 2, -1);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 2);
        assert_eq!(lua_tointegerx(state, 4, std::ptr::null_mut()), 1);
        lua_rotate(state, 1, 1001);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 1);
        lua_rotate(state, -1, i32::MAX);
        assert_eq!(lua_tointegerx(state, 4, std::ptr::null_mut()), 3);
        assert_eq!(vm_snapshot(&owner), roots);
        let stack = stack_snapshot(state);
        let vm = vm_snapshot(&owner);
        lua_rotate(state, 0, 1);
        assert_unchanged(&owner, state, &stack, &vm);
        lua_rotate(state, REGISTRY_INDEX, 1);
        assert_unchanged(&owner, state, &stack, &vm);
        lua_rotate(state, 5, 1);
        assert_unchanged(&owner, state, &stack, &vm);
        lua_rotate(std::ptr::null_mut(), 1, 1);
        assert_unchanged(&owner, state, &stack, &vm);
    }
    let stack = stack_snapshot(state);
    let vm = vm_snapshot(&owner);
    owner
        .with_vm(|_| {
            // SAFETY：有效 state 處於 busy VM borrow，rotate 須保持原樣。
            unsafe { lua_rotate(state, 1, 1) };
        })
        .unwrap();
    assert_unchanged(&owner, state, &stack, &vm);
}

fn xmove_cases() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let foreign = StateOwner::new().unwrap();
    let source = owner.as_ptr();
    let destination = sibling.as_ptr();
    // SAFETY：三個 owner 有效；跨 VM 與無效 count 只應 fail-closed。
    unsafe {
        lua_pushinteger(source, 1);
        lua_createtable(source, 0, 0);
        lua_pushinteger(source, 2);
        lua_createtable(source, 0, 0);
        lua_pushinteger(source, 3);
        lua_pushinteger(destination, 99);
    }
    let objects = host_tables(&owner);
    assert_eq!(objects.len(), 2);
    let before = vm_snapshot(&owner);
    let source_before = stack_snapshot(source);
    let dest_before = stack_snapshot(destination);
    // SAFETY：兩個 state 屬同 VM；count=0 不需變動。
    unsafe { lua_xmove(source, destination, 0) };
    assert_eq!(stack_snapshot(source), source_before);
    assert_eq!(stack_snapshot(destination), dest_before);
    assert_eq!(vm_snapshot(&owner), before);
    // SAFETY：無效來源、目的地或 count 應在 mutation 前拒絕。
    unsafe {
        lua_xmove(source, source, 5);
        lua_xmove(source, source, 6);
        lua_xmove(source, foreign.as_ptr(), 1);
        lua_xmove(source, destination, -1);
        lua_xmove(source, destination, 6);
        lua_xmove(std::ptr::null_mut(), destination, 1);
        lua_xmove(source, std::ptr::null_mut(), 1);
    }
    assert_eq!(stack_snapshot(source), source_before);
    assert_eq!(stack_snapshot(destination), dest_before);
    assert_eq!(vm_snapshot(&owner), before);
    owner
        .with_vm(|_| {
            // SAFETY：兩個 state 有效；busy VM borrow 應在 xmove 前拒絕。
            unsafe { lua_xmove(source, destination, 1) };
        })
        .unwrap();
    assert_eq!(stack_snapshot(source), source_before);
    assert_eq!(stack_snapshot(destination), dest_before);
    assert_eq!(vm_snapshot(&owner), before);

    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            vm.set_collect_every_allocation(true);
        })
        .unwrap();
    let gc_before = vm_snapshot(&owner);
    // SAFETY：相同 VM sibling 間轉移最後兩個 slots；根 lease 隨 slot 移交。
    unsafe {
        lua_xmove(source, destination, 2);
        assert_eq!(lua_gettop(source), 3);
        assert_eq!(lua_gettop(destination), 3);
        assert_eq!(lua_type(destination, 2), 5);
        assert_eq!(lua_tointegerx(destination, 3, std::ptr::null_mut()), 3);
    }
    assert_eq!(vm_snapshot(&owner), gc_before);
    // SAFETY：再將剩餘三個 slots 原序移交，source 變空。
    unsafe {
        lua_xmove(source, destination, 3);
        assert_eq!(lua_gettop(source), 0);
        assert_eq!(lua_gettop(destination), 6);
        assert_eq!(lua_tointegerx(destination, 1, std::ptr::null_mut()), 99);
        assert_eq!(lua_type(destination, 2), 5);
        assert_eq!(lua_tointegerx(destination, 3, std::ptr::null_mut()), 3);
        assert_eq!(lua_tointegerx(destination, 4, std::ptr::null_mut()), 1);
        assert_eq!(lua_type(destination, 5), 5);
        assert_eq!(lua_tointegerx(destination, 6, std::ptr::null_mut()), 2);
    }
    let after_move = vm_snapshot(&owner);
    assert_eq!(after_move.3, gc_before.3);
    assert_eq!(after_move.2, gc_before.2);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            for object in objects.iter().copied() {
                assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
            }
        })
        .unwrap();
    // SAFETY：移除所有目的 slots 後，Host roots 應歸零。
    unsafe { lua_settop(destination, 0) };
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        0
    );
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            for object in objects.iter().copied() {
                assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
            }
        })
        .unwrap();
}

fn macro_expansion_cases() {
    let lua54 = include_str!("../../../include/rivetlua/lua54/lua.h");
    let lua55 = include_str!("../../../include/rivetlua/lua55/lua.h");
    let aux54 = include_str!("../../../include/rivetlua/lua54/lauxlib.h");
    let aux55 = include_str!("../../../include/rivetlua/lua55/lauxlib.h");
    for header in [lua54, lua55] {
        assert!(header.contains("#define lua_pop(L,n)\t\tlua_settop(L, -(n)-1)"));
        assert!(header.contains("#define lua_insert(L,idx)\tlua_rotate(L, (idx), 1)"));
        assert!(
            header.contains("#define lua_remove(L,idx)\t(lua_rotate(L, (idx), -1), lua_pop(L, 1))")
        );
    }
    assert!(aux54.contains("#define luaL_pushfail(L)\tlua_pushnil(L)"));
    assert!(aux55.contains("#define luaL_pushfail(L)\tlua_pushboolean(L, 0)"));
    assert!(aux55.contains("#define luaL_pushfail(L)\tlua_pushnil(L)"));
    assert!(lua54.contains("#define lua_pushunsigned(L,n)\tlua_pushinteger(L, (lua_Integer)(n))"));

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：固定 header 的展開式只呼叫這些已驗證的 primitive；state 由 owner 保活。
    unsafe {
        for value in [1, 2, 3] {
            lua_pushinteger(state, value);
        }
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 2);
        lua_rotate(state, 1, 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 2);
        lua_rotate(state, 1, -1);
        lua_settop(state, -2);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 1);
        lua_pushnil(state);
        assert_eq!(lua_type(state, -1), 0);
        lua_pushboolean(state, 0);
        assert_eq!(lua_type(state, -1), 1);
        assert_eq!(lua_toboolean(state, -1), 0);
        lua_pushinteger(state, u64::MAX as i64);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), -1);
    }
}

fn enter_active_gc(owner: &StateOwner) {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            vm.set_collect_every_allocation(true);
        })
        .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum GrowthOperation {
    PushNil,
    PushBoolean,
    PushInteger,
    PushNumber,
    PushLightUserdata,
    SetTop,
}

fn check_prefix_and_tail(
    label: &str,
    failures: &[(u64, AllocationDomain, &'static str)],
    successes: &[u64],
    end: u64,
) {
    let first_success = failures.len() as u64;
    assert!(first_success >= 1, "{label}: 必須命中實際 host 配置點");
    assert!(first_success <= 4, "{label}: 配置點數超出本片可解釋範圍");
    assert_eq!(
        failures.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (0..first_success).collect::<Vec<_>>(),
        "{label}: 失敗必須是完整前綴"
    );
    assert_eq!(
        successes,
        (first_success..end).collect::<Vec<_>>(),
        "{label}: 成功必須覆蓋連續尾段"
    );
    assert!(end - first_success >= 8, "{label}: 成功尾段太短");
    for (_, domain, site) in failures {
        assert_eq!(*domain, AllocationDomain::Host, "{label}");
        assert_eq!(*site, "crates/rivetlua-runtime/src/heap.rs", "{label}");
    }
    println!("A10_ALLOC\t{label}\tfailures={failures:?}\tsuccesses={successes:?}");
}

fn scalar_and_settop_growth_fault_matrix() {
    const END: u64 = 16;
    for operation in [
        GrowthOperation::PushNil,
        GrowthOperation::PushBoolean,
        GrowthOperation::PushInteger,
        GrowthOperation::PushNumber,
        GrowthOperation::PushLightUserdata,
        GrowthOperation::SetTop,
    ] {
        let mut failures = Vec::new();
        let mut successes = Vec::new();
        for offset in 0..END {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            enter_active_gc(&owner);
            let before_stack = stack_snapshot(state);
            let before_vm = vm_snapshot(&owner);
            let ordinal = owner
                .with_vm(|vm| {
                    let ordinal = vm.allocation_trace().next_ordinal + offset;
                    vm.inject_allocation_failure_at(ordinal);
                    ordinal
                })
                .unwrap();
            // SAFETY：owner 有效；本矩陣只對已有 ABI 入口注入 host 容量失敗。
            unsafe {
                match operation {
                    GrowthOperation::PushNil => lua_pushnil(state),
                    GrowthOperation::PushBoolean => lua_pushboolean(state, -9),
                    GrowthOperation::PushInteger => lua_pushinteger(state, i64::MIN),
                    GrowthOperation::PushNumber => lua_pushnumber(state, -0.0),
                    GrowthOperation::PushLightUserdata => {
                        lua_pushlightuserdata(state, std::ptr::null_mut())
                    }
                    GrowthOperation::SetTop => lua_settop(state, 20),
                }
            }
            if stack_snapshot(state) == before_stack {
                let after_vm = vm_snapshot(&owner);
                assert_eq!(after_vm.0, before_vm.0, "{operation:?} offset {offset}");
                assert_eq!(after_vm.2, before_vm.2, "{operation:?} offset {offset}");
                assert_eq!(after_vm.3, before_vm.3, "{operation:?} offset {offset}");
                let failure = owner
                    .with_vm(|vm| vm.allocation_trace().last_failure)
                    .unwrap()
                    .unwrap();
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt.ordinal, ordinal);
                failures.push((offset, failure.attempt.domain, failure.attempt.site.file));
            } else {
                let expected = if matches!(operation, GrowthOperation::SetTop) {
                    20
                } else {
                    1
                };
                // SAFETY：成功路徑的 top 已由 owner 保活，可讀取精確 slot 數。
                assert_eq!(unsafe { lua_gettop(state) }, expected);
                successes.push(offset);
            }
        }
        check_prefix_and_tail(&format!("{operation:?}"), &failures, &successes, END);
    }
}

fn xmove_growth_fault_matrix() {
    const END: u64 = 16;
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..END {
        let owner = StateOwner::new().unwrap();
        let sibling = owner.new_sibling().unwrap();
        let source = owner.as_ptr();
        let destination = sibling.as_ptr();
        // SAFETY：兩個 state 由同 VM owner/sibling 持有；source 含物件與 scalar。
        unsafe {
            lua_createtable(source, 0, 0);
            lua_pushinteger(source, 47);
        }
        let object = host_tables(&owner)[0];
        enter_active_gc(&owner);
        let before_source = stack_snapshot(source);
        let before_destination = stack_snapshot(destination);
        let before_vm = vm_snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| {
                let ordinal = vm.allocation_trace().next_ordinal + offset;
                vm.inject_allocation_failure_at(ordinal);
                ordinal
            })
            .unwrap();
        // SAFETY：兩個有效 sibling；目的容量失敗前不得 drain source。
        unsafe { lua_xmove(source, destination, 2) };
        if stack_snapshot(source) == before_source {
            assert_eq!(
                stack_snapshot(destination),
                before_destination,
                "offset {offset}"
            );
            let after_vm = vm_snapshot(&owner);
            assert_eq!(after_vm.0, before_vm.0, "offset {offset}");
            assert_eq!(after_vm.2, before_vm.2, "offset {offset}");
            assert_eq!(after_vm.3, before_vm.3, "offset {offset}");
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
                Ok(ObjectKind::Table)
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(failure.attempt.ordinal, ordinal);
            failures.push((offset, failure.attempt.domain, failure.attempt.site.file));
        } else {
            // SAFETY：成功時 source 變空且 destination 保留原順序與物件身分。
            unsafe {
                assert_eq!(lua_gettop(source), 0);
                assert_eq!(lua_gettop(destination), 2);
                assert_eq!(lua_type(destination, 1), 5);
                assert_eq!(lua_tointegerx(destination, 2, std::ptr::null_mut()), 47);
            }
            let after_vm = vm_snapshot(&owner);
            assert_eq!(
                after_vm.3, before_vm.3,
                "offset {offset}: root lease 不可複製"
            );
            assert_eq!(
                after_vm.2, before_vm.2,
                "offset {offset}: active GC 不可轉移"
            );
            owner
                .with_vm(|vm| {
                    vm.inject_allocation_failure_at(u64::MAX);
                    vm.collect().unwrap();
                    vm.collect().unwrap();
                    assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
                })
                .unwrap();
            successes.push(offset);
        }
    }
    check_prefix_and_tail("XMove", &failures, &successes, END);
}

fn existing_capacity_is_allocation_free() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：先配置足夠容量，再於不跨容量邊界的範圍執行操作。
    unsafe { lua_settop(state, 10) };
    enter_active_gc(&owner);
    let before = owner
        .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
        .unwrap();
    // SAFETY：目前容量至少十格，以下 shrink／rotate／scalar push 不應配置。
    unsafe {
        lua_settop(state, 4);
        lua_rotate(state, 1, -1);
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, i64::MAX);
        lua_pushnumber(state, f64::NAN);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_settop(state, 10);
        assert_eq!(lua_gettop(state), 10);
    }
    assert_eq!(
        owner
            .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
            .unwrap(),
        before
    );
}

#[test]
fn primitive_stack_a10_matrix() {
    scalar_and_settop_cases();
    rotate_cases();
    xmove_cases();
    macro_expansion_cases();
    scalar_and_settop_growth_fault_matrix();
    xmove_growth_fault_matrix();
    existing_capacity_is_allocation_free();
}
