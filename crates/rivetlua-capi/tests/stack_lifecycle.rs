use std::alloc::Layout;
#[cfg(feature = "lua54")]
use std::ffi::c_uint;
use std::ffi::{CStr, c_void};
use std::mem::{align_of, size_of};

use rivetlua_capi::stack::{
    StackError, StateOwner, lua_State, lua_absindex, lua_checkstack, lua_close, lua_copy,
    lua_createtable, lua_getglobal, lua_gettop, lua_isinteger, lua_isyieldable, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushnil, lua_pushnumber, lua_pushstring,
    lua_pushvalue, lua_rawequal, lua_rawgeti, lua_rawseti, lua_rotate, lua_setglobal, lua_settop,
    lua_status, lua_toboolean, lua_tointegerx, lua_tonumberx, lua_touserdata, lua_type,
    lua_typename, lua_xmove, luaL_newstate,
};
#[cfg(feature = "lua54")]
use rivetlua_capi::stack::{lua_setcstacklimit, lua_topointer};
use rivetlua_core::Value;
use rivetlua_runtime::{FailPoint, GcPhase, ObjectKind, RootKind, VmError};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

unsafe extern "C" {
    fn rivetlua_capi_test_protected_index_a4b(
        state: *mut lua_State,
        operation: i32,
        index: i32,
        argument: i32,
        name: *const std::ffi::c_char,
        answer: *mut i32,
    ) -> i32;
}

#[test]
fn c_owned_default_state_a33_matrix() {
    let first = luaL_newstate();
    let second = luaL_newstate();
    assert!(!first.is_null());
    assert!(!second.is_null());
    assert_ne!(first, second);
    let key = c"a33_value";
    // SAFETY：兩個 C-owned state 均由本測試建立且尚未關閉；extraspace 位於 control 前。
    unsafe {
        for state in [first, second] {
            assert_eq!(lua_gettop(state), 0);
            let extraspace = state.cast::<u8>().sub(size_of::<*mut c_void>());
            for offset in 0..size_of::<*mut c_void>() {
                assert_eq!(*extraspace.add(offset), 0);
            }
            assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), 5);
            lua_settop(state, 0);
        }
        lua_pushinteger(first, 41);
        assert!(!lua_pushstring(first, c"text".as_ptr()).is_null());
        lua_createtable(first, 0, 0);
        lua_pushinteger(first, 99);
        lua_rawseti(first, -2, 1);
        assert_eq!(lua_rawgeti(first, -1, 1), 3);
        assert_eq!(lua_tointegerx(first, -1, std::ptr::null_mut()), 99);
        lua_settop(first, 0);
        lua_pushinteger(first, 17);
        lua_setglobal(first, key.as_ptr());
        assert_eq!(lua_getglobal(second, key.as_ptr()), 0);
        assert_eq!(lua_getglobal(first, key.as_ptr()), 3);
        assert_eq!(lua_tointegerx(first, -1, std::ptr::null_mut()), 17);
        assert_eq!(lua_gettop(first), 1);
        assert_eq!(lua_gettop(second), 1);
        lua_close(std::ptr::null_mut());
    }
    let foreign_address = first as usize;
    std::thread::spawn(move || {
        // SAFETY：owner thread 在 join 前保持 state 存活；異執行緒呼叫必須拒絕釋放。
        unsafe { lua_close(foreign_address as *mut rivetlua_capi::stack::lua_State) };
    })
    .join()
    .unwrap();
    // SAFETY：wrong-thread close 未釋放，兩個 pointer 此刻仍有效；之後每個 pointer 只 close 一次。
    unsafe {
        assert_eq!(lua_gettop(first), 1);
        lua_close(first);
        assert_eq!(lua_gettop(second), 1);
        lua_close(second);
    }
    let owner = StateOwner::new().unwrap();
    let rust_owned = owner.as_ptr();
    // SAFETY：Rust owner 仍存活，C close 必須拒絕其 pointer。
    unsafe {
        lua_close(rust_owned);
        lua_pushinteger(rust_owned, 7);
        assert_eq!(lua_gettop(rust_owned), 1);
    }
    drop(owner);
    for value in 0..8 {
        let state = luaL_newstate();
        assert!(!state.is_null());
        // SAFETY：每個 state 新建後可用，只由建立者執行緒 close 一次。
        unsafe {
            lua_pushinteger(state, value);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), value);
            lua_close(state);
        }
    }
}

#[test]
fn main_state_status_a36_matrix() {
    unsafe extern "C" {
        fn lua_newthread(state: *mut lua_State) -> *mut lua_State;
    }

    // SAFETY：null 不指向 state；兩個查詢必須以零值 fail-closed。
    unsafe {
        assert_eq!(lua_status(std::ptr::null_mut()), 0);
        assert_eq!(lua_isyieldable(std::ptr::null_mut()), 0);
    }

    let c_owned = luaL_newstate();
    assert!(!c_owned.is_null());
    // SAFETY：C-owned main state 於此作用域存活，且每個 pointer 只 close 一次。
    unsafe {
        lua_pushinteger(c_owned, 31);
        for _ in 0..32 {
            assert_eq!(lua_status(c_owned), 0);
            assert_eq!(lua_isyieldable(c_owned), 0);
            assert_eq!(lua_gettop(c_owned), 1);
            assert_eq!(lua_tointegerx(c_owned, 1, std::ptr::null_mut()), 31);
        }
        lua_close(c_owned);
    }

    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let main = owner.as_ptr();
    let overlay = sibling.as_ptr();
    let mut token = 7_u8;
    let token_pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：owner/sibling 在下方所有 C API 呼叫期間存活；child 由 main stack 保活。
    let child = unsafe {
        lua_pushinteger(main, 23);
        lua_createtable(main, 0, 0);
        lua_pushvalue(main, 2);
        lua_pushlightuserdata(main, token_pointer);
        lua_pushinteger(overlay, 47);
        assert_eq!(lua_rawequal(main, 2, 3), 1);
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(lua_isyieldable(child), 1);
        child
    };
    owner
        .with_vm(|vm| {
            vm.incremental_step(1).unwrap();
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();
    let snapshot = |state_owner: &StateOwner| {
        state_owner
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
    };
    let before = snapshot(&owner);
    // SAFETY：main、child 與 overlay 都仍有效；查詢只讀且不應改動 slot、GC 或帳本。
    unsafe {
        for _ in 0..32 {
            assert_eq!(lua_status(main), 0);
            assert_eq!(lua_isyieldable(main), 0);
            assert_eq!(lua_status(overlay), 0);
            assert_eq!(lua_isyieldable(overlay), 0);
            assert_eq!(lua_isyieldable(child), 1);
        }
        assert_eq!(lua_gettop(main), 5);
        assert_eq!(lua_tointegerx(main, 1, std::ptr::null_mut()), 23);
        assert_eq!(lua_rawequal(main, 2, 3), 1);
        assert_eq!(lua_touserdata(main, 4), token_pointer);
        assert_eq!(lua_gettop(overlay), 1);
        assert_eq!(lua_tointegerx(overlay, 1, std::ptr::null_mut()), 47);
        assert_eq!(lua_gettop(child), 0);
    }
    assert_eq!(snapshot(&owner), before);
    let foreign_address = main as usize;
    let foreign_child_address = child as usize;
    let foreign = std::thread::spawn(move || {
        let pointer = foreign_address as *mut rivetlua_capi::stack::lua_State;
        let child = foreign_child_address as *mut rivetlua_capi::stack::lua_State;
        // SAFETY：owner 活至 join；跨執行緒入口須先拒絕而不可建立非 Sync 參照。
        unsafe {
            (
                lua_status(pointer),
                lua_isyieldable(pointer),
                lua_isyieldable(child),
            )
        }
    })
    .join()
    .unwrap();
    assert_eq!(foreign, (0, 0, 0));
    owner
        .with_vm(|vm| {
            let before_busy = (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace());
            // SAFETY：state 有效，但 VM 正借用中；入口必須以零值 fail-closed。
            unsafe {
                assert_eq!(lua_status(main), 0);
                assert_eq!(lua_isyieldable(main), 0);
                assert_eq!(lua_isyieldable(child), 0);
            }
            assert_eq!(
                (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace()),
                before_busy
            );
        })
        .unwrap();
    assert_eq!(snapshot(&owner), before);
    // SAFETY：wrong-thread 與 busy 查詢均未破壞 owner，三個 state 仍可正常查詢。
    unsafe {
        assert_eq!(lua_status(main), 0);
        assert_eq!(lua_isyieldable(overlay), 0);
        assert_eq!(lua_isyieldable(child), 1);
    }
}

#[test]
fn stack_lifecycle_state_layout_extraspace_and_move() {
    let owner = StateOwner::new().unwrap();
    let pointer = owner.as_ptr();
    assert_eq!(pointer as usize % align_of::<usize>(), 0);
    let extra_size = size_of::<*mut c_void>();
    // SAFETY：owner 存活，control 前恰有由 StateAllocation 持有的 extraspace bytes。
    unsafe {
        let extraspace = pointer.cast::<u8>().sub(extra_size);
        for offset in 0..extra_size {
            *extraspace.add(offset) = 0xa0 + offset as u8;
        }
        assert_eq!(lua_gettop(pointer), 0);
    }
    let moved = owner;
    assert_eq!(moved.as_ptr(), pointer);
    // SAFETY：moved 仍持有同一 allocation，前置 bytes 與 control 均有效。
    unsafe {
        let extraspace = pointer.cast::<u8>().sub(extra_size);
        for offset in 0..extra_size {
            assert_eq!(*extraspace.add(offset), 0xa0 + offset as u8);
        }
        lua_pushinteger(pointer, 7);
        assert_eq!(lua_gettop(pointer), 1);
    }
    let probe = moved.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(moved);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn stack_lifecycle_foreign_thread_rejected_before_state_borrow() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 存活，呼叫仍在所屬執行緒且 state 指標有效。
    unsafe {
        lua_pushinteger(state, 42);
        assert_eq!(lua_gettop(state), 1);
    }
    let address = state as usize;
    let foreign_top = std::thread::spawn(move || {
        // SAFETY：owner 在 join 前存活；入口應在建立非 Sync state 參照前拒絕異執行緒。
        unsafe { lua_gettop(address as *mut rivetlua_capi::stack::lua_State) }
    })
    .join()
    .unwrap();
    assert_eq!(foreign_top, 0);
    // SAFETY：主執行緒仍持有 owner，可繼續使用原 state。
    unsafe { assert_eq!(lua_gettop(state), 1) };
}

#[test]
fn stack_lifecycle_zero_xmove_does_not_allocate() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let committed = owner.with_vm(|vm| vm.ledger_snapshot().committed).unwrap();
    owner
        .with_vm(|vm| vm.set_allocation_limit(committed))
        .unwrap();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    // SAFETY：兩個 state 有效且屬於同一 VM，count=0 不需配置 slot。
    unsafe { lua_xmove(owner.as_ptr(), sibling.as_ptr(), 0) };
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), baseline);
    // SAFETY：若空目的 stack 被偷建了 capacity，此查詢仍回零；ledger 斷言確認無配置。
    unsafe { assert_eq!(lua_gettop(sibling.as_ptr()), 0) };
}

#[test]
fn stack_lifecycle_group_refcell_accounting_budget_and_sibling_lifetime() {
    let (raw_group, refcell_group, refcell_align, state_bytes) =
        StateOwner::allocation_component_sizes();
    assert!(refcell_group > raw_group); // 舊公式漏掉的 RefCell borrow flag 必須有可觀察差額。
    let header = Layout::array::<usize>(2).unwrap();
    let payload = Layout::from_size_align(refcell_group, refcell_align).unwrap();
    let group_bytes = header.extend(payload).unwrap().0.pad_to_align().size();
    let total_bytes = group_bytes.checked_add(state_bytes).unwrap();
    let mut dry_baseline = None;
    let dry =
        StateOwner::new_with_vm_setup(|vm| dry_baseline = Some(vm.ledger_snapshot())).unwrap();
    let dry_before = dry_baseline.unwrap();
    let dry_after = dry.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    // B10b2 的永久 hidden hook bridge 多占一個 Registry root。
    assert_eq!(
        dry.with_vm(|vm| vm.roots().count(RootKind::Registry))
            .unwrap(),
        3
    );
    assert_eq!(
        dry.with_vm(|vm| vm.roots().count(RootKind::Host)).unwrap(),
        0
    );
    let registry_bytes = dry_after.committed - dry_before.committed - total_bytes;
    let registry_host_bytes =
        dry_after.host_allocation_bytes - dry_before.host_allocation_bytes - total_bytes;
    assert!(registry_bytes > registry_host_bytes);
    let total_with_registry = total_bytes + registry_bytes;
    drop(dry);

    // 初始化期間兩個暫時 Host root 與 Registry root 會重疊，額度須涵蓋峰值。
    let succeeds_at = |allowance: usize| {
        let mut probe = None;
        let result = StateOwner::new_with_vm_setup(|vm| {
            let baseline = vm.ledger_snapshot();
            probe = Some(vm.ledger_probe());
            vm.set_allocation_limit(baseline.committed + allowance);
        });
        let success = match result {
            Ok(owner) => {
                drop(owner);
                true
            }
            Err(StackError::Runtime(VmError::AllocationFailed)) => false,
            Err(error) => panic!("非預期的配置結果：{error:?}"),
        };
        let after = probe.unwrap().snapshot();
        assert_eq!(after.committed, 0);
        assert_eq!(after.reserved, 0);
        success
    };
    let mut failing_allowance = total_with_registry - 1;
    let mut sufficient_allowance = total_with_registry + 8192;
    assert!(!succeeds_at(failing_allowance));
    assert!(succeeds_at(sufficient_allowance));
    while sufficient_allowance - failing_allowance > 1 {
        let middle = failing_allowance + (sufficient_allowance - failing_allowance) / 2;
        if succeeds_at(middle) {
            sufficient_allowance = middle;
        } else {
            failing_allowance = middle;
        }
    }
    assert!(sufficient_allowance >= total_with_registry);

    let mut failed_probe = None;
    let failed = StateOwner::new_with_vm_setup(|vm| {
        let baseline = vm.ledger_snapshot();
        failed_probe = Some(vm.ledger_probe());
        vm.set_allocation_limit(baseline.committed.checked_add(failing_allowance).unwrap());
    });
    assert!(matches!(
        failed,
        Err(StackError::Runtime(VmError::AllocationFailed))
    ));
    let failed_snapshot = failed_probe.unwrap().snapshot();
    assert_eq!(failed_snapshot.committed, 0);
    assert_eq!(failed_snapshot.reserved, 0);

    let mut baseline = None;
    let mut probe = None;
    let owner = StateOwner::new_with_vm_setup(|vm| {
        let before = vm.ledger_snapshot();
        baseline = Some(before);
        probe = Some(vm.ledger_probe());
        vm.set_allocation_limit(before.committed.checked_add(sufficient_allowance).unwrap());
    })
    .unwrap();
    let before = baseline.unwrap();
    let first = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    assert_eq!(first.committed - before.committed, total_with_registry);
    assert_eq!(
        first.host_allocation_bytes - before.host_allocation_bytes,
        total_bytes + registry_host_bytes
    );

    owner
        .with_vm(|vm| vm.set_allocation_limit(first.committed))
        .unwrap();
    let capped = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();

    assert!(matches!(
        owner.new_sibling(),
        Err(StackError::Runtime(VmError::AllocationFailed))
    ));
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), capped);
    owner
        .with_vm(|vm| {
            vm.set_allocation_limit(first.committed + state_bytes);
        })
        .unwrap();
    let sibling = owner.new_sibling().unwrap();
    let second = sibling.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    assert_eq!(second.committed - first.committed, state_bytes);
    assert_eq!(
        second.host_allocation_bytes - first.host_allocation_bytes,
        state_bytes
    );

    drop(owner);
    let surviving = sibling.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    assert_eq!(surviving.committed - before.committed, total_with_registry);
    drop(sibling);
    let final_snapshot = probe.unwrap().snapshot();
    assert_eq!(final_snapshot.committed, 0);
    assert_eq!(final_snapshot.reserved, 0);
}

#[test]
fn stack_lifecycle_indices_settop_rotate_copy_and_pseudo_boundaries() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在整個區塊內存活；傳入固定 header 的有效數值 ABI。
    unsafe {
        lua_pushinteger(state, 10);
        lua_pushinteger(state, 20);
        lua_pushinteger(state, 30);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_absindex(state, -1), 3);
        assert_eq!(lua_absindex(state, -3), 1);
        assert_eq!(lua_absindex(state, REGISTRY_INDEX), REGISTRY_INDEX);
        assert_eq!(lua_absindex(state, REGISTRY_INDEX - 1), REGISTRY_INDEX - 1);
        assert_eq!(lua_type(state, 0), -1);
        assert_eq!(lua_type(state, 4), -1);
        assert_eq!(lua_type(state, REGISTRY_INDEX), 5);
        assert_eq!(lua_type(state, OTHER_REGISTRY_INDEX), -1);
        assert_eq!(lua_type(state, REGISTRY_INDEX - 1), -1);
        lua_pushvalue(state, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), 4);
        assert_eq!(lua_type(state, -1), 5);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
        assert_ne!(
            rivetlua_capi_test_protected_index_a4b(
                state,
                11,
                REGISTRY_INDEX - 1,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            0
        );
        assert_ne!(
            rivetlua_capi_test_protected_index_a4b(
                state,
                11,
                OTHER_REGISTRY_INDEX,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            0
        );
        assert_eq!(lua_gettop(state), 3);
        lua_rotate(state, REGISTRY_INDEX, 1);
        lua_copy(state, 1, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_type(state, REGISTRY_INDEX), 3);
        assert_eq!(
            lua_tointegerx(state, REGISTRY_INDEX, std::ptr::null_mut()),
            10
        );

        lua_rotate(state, 1, 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 30);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 20);
        lua_rotate(state, 1, -1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 10);
        lua_copy(state, 1, -1);
        assert_eq!(lua_tointegerx(state, 3, std::ptr::null_mut()), 10);
        lua_copy(state, REGISTRY_INDEX, 2);
        assert_eq!(lua_type(state, 2), 3);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 10);
        assert_eq!(
            rivetlua_capi::stack::lua_rawequal(state, 2, REGISTRY_INDEX),
            1
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 4);
        assert_eq!(lua_type(state, 3), 0);
        assert_eq!(lua_type(state, 4), 0);
        lua_settop(state, -6);
        assert_eq!(lua_gettop(state), 4);
        lua_settop(state, 0);
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_absindex(state, -1), 0);
    }
    owner
        .with_vm(|vm| {
            // B12 registry destination 已改為整數；只剩 emergency 與 B10 bridge。
            assert_eq!(vm.roots().count(RootKind::Registry), 2);
            assert_eq!(vm.roots().count(RootKind::Coroutine), 1);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().total_count(), 3);
        })
        .unwrap();
}

#[test]
fn stack_lifecycle_checkstack_limit_failure_and_refund() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    owner
        .with_vm(|vm| vm.set_allocation_limit(baseline.committed + 1))
        .unwrap();
    // SAFETY：state 有效；負值、巨大要求與正常要求均不涉及無效指標。
    unsafe {
        assert_eq!(lua_checkstack(state, -1), 0);
        assert_eq!(lua_checkstack(state, 1_000_001), 0);
        assert_eq!(lua_checkstack(state, 20), 0);
        assert_eq!(lua_gettop(state), 0);
    }
    owner
        .with_vm(|vm| vm.set_allocation_limit(baseline.limit))
        .unwrap();
    // SAFETY：state 有效；成功預留後 settop(0) 釋放空 stack capacity。
    unsafe {
        assert_eq!(lua_checkstack(state, 20), 1);
        assert_eq!(lua_gettop(state), 0);
        lua_settop(state, 0);
    }
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), baseline);
}

#[test]
fn stack_lifecycle_scalar_types_and_numeric_boundaries() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut flag = -1;
    // SAFETY：state 有效，flag 是可寫且對齊的 c_int，lightuserdata 只儲存不解參照。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 0);
        lua_pushboolean(state, -7);
        lua_pushinteger(state, i64::MIN);
        lua_pushinteger(state, i64::MAX);
        lua_pushnumber(state, -0.0);
        lua_pushnumber(state, f64::NAN);
        lua_pushnumber(state, 42.0);
        lua_pushnumber(state, 42.5);
        lua_pushnumber(state, 9_223_372_036_854_775_808.0);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        assert_eq!(lua_gettop(state), 11);
        assert_eq!(lua_type(state, 1), 0);
        assert_eq!(lua_type(state, 2), 1);
        assert_eq!(lua_type(state, 4), 3);
        assert_eq!(lua_type(state, 11), 2);
        assert_eq!(lua_toboolean(state, 1), 0);
        assert_eq!(lua_toboolean(state, 2), 0);
        assert_eq!(lua_toboolean(state, 3), 1);
        assert_eq!(lua_toboolean(state, 6), 1);
        assert_eq!(lua_toboolean(state, 11), 1);
        assert_eq!(lua_toboolean(state, 12), 0);
        assert_eq!(lua_isinteger(state, 4), 1);
        assert_eq!(lua_isinteger(state, 6), 0);
        assert_eq!(lua_tointegerx(state, 4, &mut flag), i64::MIN);
        assert_eq!(flag, 1);
        assert_eq!(lua_tointegerx(state, 5, &mut flag), i64::MAX);
        assert_eq!(flag, 1);
        assert_eq!(lua_tointegerx(state, 6, &mut flag), 0);
        assert_eq!(flag, 1);
        assert_eq!(lua_tointegerx(state, 7, &mut flag), 0);
        assert_eq!(flag, 0);
        assert_eq!(lua_tointegerx(state, 8, &mut flag), 42);
        assert_eq!(flag, 1);
        assert_eq!(lua_tointegerx(state, 9, &mut flag), 0);
        assert_eq!(flag, 0);
        assert_eq!(lua_tointegerx(state, 10, &mut flag), 0);
        assert_eq!(flag, 0);
        assert!(lua_tonumberx(state, 7, &mut flag).is_nan());
        assert_eq!(flag, 1);
        assert!(lua_tonumberx(state, 6, &mut flag).is_sign_negative());
        assert_eq!(flag, 1);
        assert_eq!(lua_tonumberx(state, 1, &mut flag), 0.0);
        assert_eq!(flag, 0);
        assert!(lua_touserdata(state, 11).is_null());
        for (ty, expected) in [
            (-1, b"no value".as_slice()),
            (0, b"nil".as_slice()),
            (1, b"boolean".as_slice()),
            (2, b"userdata".as_slice()),
            (3, b"number".as_slice()),
            (4, b"string".as_slice()),
            (5, b"table".as_slice()),
            (6, b"function".as_slice()),
            (7, b"userdata".as_slice()),
            (8, b"thread".as_slice()),
        ] {
            assert_eq!(CStr::from_ptr(lua_typename(state, ty)).to_bytes(), expected);
        }
        assert!(lua_typename(state, 9).is_null());
        lua_settop(state, 0);
    }
}

#[test]
fn stack_lifecycle_same_vm_xmove_cross_vm_rejection_and_roots() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let other = StateOwner::new().unwrap();
    let object = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(object)).unwrap();
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        1
    );
    // SAFETY：三個 state 均有效；跨 VM xmove 須原樣拒絕。
    unsafe {
        lua_xmove(owner.as_ptr(), other.as_ptr(), 1);
        assert_eq!(lua_gettop(owner.as_ptr()), 1);
        assert_eq!(lua_gettop(other.as_ptr()), 0);
        lua_xmove(owner.as_ptr(), sibling.as_ptr(), 1);
        assert_eq!(lua_gettop(owner.as_ptr()), 0);
        assert_eq!(lua_gettop(sibling.as_ptr()), 1);
    }
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        1
    );
    sibling
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Ok(ObjectKind::Table));
        })
        .unwrap();
    // SAFETY：sibling 有效，縮減 top 會釋放移入的 root。
    unsafe { lua_settop(sibling.as_ptr(), 0) };
    owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
        })
        .unwrap();
}

#[test]
fn stack_lifecycle_collectable_clone_copy_pop_drop_and_cross_vm_value() {
    let owner = StateOwner::new().unwrap();
    let other = StateOwner::new().unwrap();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let object = owner
        .with_vm(|vm| vm.allocate_byte_string(b"root").unwrap())
        .unwrap();
    assert_eq!(
        other.push_value(Value::Object(object)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    owner.push_value(Value::Object(object)).unwrap();
    // SAFETY：owner 存活；複製與覆寫各自持有獨立 root。
    unsafe {
        lua_pushvalue(owner.as_ptr(), 1);
        assert_eq!(lua_gettop(owner.as_ptr()), 2);
    }
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        2
    );
    let replaced = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(replaced)).unwrap();
    // SAFETY：owner 存活；copy 覆寫目的 slot 時應退掉被替換物件的 root。
    unsafe { lua_copy(owner.as_ptr(), 1, 3) };
    owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 3);
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(replaced), Err(VmError::StaleObject));
        })
        .unwrap();
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(object), Ok(ObjectKind::ByteString));
        })
        .unwrap();
    // SAFETY：owner 存活；縮減後只剩原 slot，兩個 clone 的 root 均解除。
    unsafe { lua_settop(owner.as_ptr(), 1) };
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        1
    );
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn stack_lifecycle_root_failure_rolls_back_without_partial_slot() {
    let owner = StateOwner::new().unwrap();
    let object = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    assert_eq!(
        owner.push_value(Value::Object(object)),
        Err(StackError::Runtime(VmError::InjectedFailure(
            FailPoint::RootReserve
        )))
    );
    // SAFETY：owner 存活；失敗不新增 slot。
    unsafe { assert_eq!(lua_gettop(owner.as_ptr()), 0) };
    owner
        .with_vm(|vm| {
            // B10b2 的永久 hidden hook bridge 多占一個 Registry root。
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Coroutine), 1);
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().total_count(), 4);
        })
        .unwrap();
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), baseline);
}

#[cfg(feature = "lua54")]
#[test]
fn cstack_limit_a39_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 由仍存活的 Rust owner 持有；stack values 由 state 保活。
    unsafe {
        lua_pushinteger(state, 73);
        lua_createtable(state, 0, 0);
    }
    owner
        .with_vm(|vm| {
            vm.incremental_step(1).unwrap();
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();

    let snapshot = |state_owner: &StateOwner| {
        state_owner
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
    };
    let before = snapshot(&owner);
    assert_ne!(before.2.phase, GcPhase::Pause);
    // SAFETY：state 仍有效；這些唯讀查詢只確認本測試建立的 stack values 與 status。
    let stack_before = unsafe {
        (
            lua_gettop(state),
            lua_tointegerx(state, -2, std::ptr::null_mut()),
            lua_topointer(state, -1),
            lua_status(state),
        )
    };
    assert_eq!(stack_before.0, 2);
    assert_eq!(stack_before.1, 73);
    assert!(!stack_before.2.is_null());
    assert_eq!(stack_before.3, 0);

    let limits = [0 as c_uint, 1, 200, c_uint::MAX];
    // SAFETY：Rust owner 保證 state 有效；官方 5.4.9 實作忽略所有 limit 並回傳 200。
    let rust_owned_results = unsafe {
        limits.map(|limit| {
            (
                lua_setcstacklimit(state, limit),
                lua_setcstacklimit(state, limit),
            )
        })
    };
    assert_eq!(rust_owned_results, [(200, 200); 4]);

    let c_owned = luaL_newstate();
    assert!(!c_owned.is_null());
    // SAFETY：c_owned 是此測試剛建立且尚未關閉的 C-owned state；完成呼叫後只關閉一次。
    let c_owned_results = unsafe {
        let results = limits.map(|limit| {
            (
                lua_setcstacklimit(c_owned, limit),
                lua_setcstacklimit(c_owned, limit),
            )
        });
        lua_close(c_owned);
        results
    };
    assert_eq!(c_owned_results, [(200, 200); 4]);

    // SAFETY：null state 是此入口必須 fail-closed 的無效 state。
    assert_eq!(unsafe { lua_setcstacklimit(std::ptr::null_mut(), 200) }, 0);

    let state_address = state as usize;
    let wrong_thread = std::thread::spawn(move || {
        // SAFETY：owner 在 join 前保持 state 有效；跨執行緒 state 必須回傳 0。
        unsafe { lua_setcstacklimit(state_address as *mut rivetlua_capi::stack::lua_State, 1) }
    });
    assert_eq!(wrong_thread.join().unwrap(), 0);

    let busy_result = owner
        .with_vm(|vm| {
            let before_busy = (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace());
            // SAFETY：state 有效，但外層 VM 借用中，入口必須 fail-closed 回 0。
            let result = unsafe { lua_setcstacklimit(state, c_uint::MAX) };
            assert_eq!(
                (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace()),
                before_busy
            );
            result
        })
        .unwrap();
    assert_eq!(busy_result, 0);

    // SAFETY：state 仍由 owner 持有；驗證所有 API 呼叫後 state/status 與 stack identity 未改變。
    let stack_after = unsafe {
        (
            lua_gettop(state),
            lua_tointegerx(state, -2, std::ptr::null_mut()),
            lua_topointer(state, -1),
            lua_status(state),
        )
    };
    assert_eq!(stack_after, stack_before);
    assert_eq!(snapshot(&owner), before);

    // SAFETY：state 仍有效，成功 no-op 後仍可由既有 stack API 使用。
    unsafe {
        lua_pushinteger(state, 99);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 99);
    }
}
