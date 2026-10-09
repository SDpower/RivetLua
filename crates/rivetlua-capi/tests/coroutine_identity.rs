use std::ffi::c_void;
use std::mem::size_of;

use rivetlua_capi::stack::{
    StateOwner, lua_checkstack, lua_close, lua_getglobal, lua_gettop, lua_isyieldable,
    lua_pushinteger, lua_pushvalue, lua_rawgeti, lua_setglobal, lua_settop, lua_status,
    lua_tointegerx, lua_type, lua_xmove, luaL_newstate,
};
use rivetlua_runtime::{FailPoint, GcMode, ObjectKind, RootKind, VmError};

#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const MAINTHREAD_INDEX: i64 = 1;
#[cfg(feature = "lua55")]
const MAINTHREAD_INDEX: i64 = 3;

unsafe extern "C" {
    fn lua_newthread(
        state: *mut rivetlua_capi::stack::lua_State,
    ) -> *mut rivetlua_capi::stack::lua_State;
    fn lua_tothread(
        state: *mut rivetlua_capi::stack::lua_State,
        index: i32,
    ) -> *mut rivetlua_capi::stack::lua_State;
    fn lua_pushthread(state: *mut rivetlua_capi::stack::lua_State) -> i32;
}

#[test]
fn main_and_child_thread_identity_b3() {
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：main 與 child 在所有呼叫期間由 registry／C stack 保活。
    unsafe {
        assert_eq!(lua_status(main), 0);
        assert_eq!(lua_isyieldable(main), 0);
        assert_eq!(lua_rawgeti(main, REGISTRY_INDEX, MAINTHREAD_INDEX), 8);
        assert_eq!(lua_tothread(main, -1), main);
        lua_settop(main, 0);
        assert_eq!(lua_pushthread(main), 1);
        assert_eq!(lua_tothread(main, -1), main);
        lua_settop(main, 0);

        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_ne!(child, main);
        assert_eq!(lua_status(child), 0);
        assert_eq!(lua_isyieldable(child), 1);
        assert_eq!(lua_gettop(main), 1);
        assert_eq!(lua_type(main, -1), 8);
        assert_eq!(lua_tothread(main, -1), child);
        lua_pushvalue(main, -1);
        assert_eq!(lua_tothread(main, -1), child);
        lua_settop(main, 1);
        assert!(lua_tothread(main, 0).is_null());
        assert!(lua_tothread(main, 2).is_null());
        lua_pushinteger(main, 42);
        assert!(lua_tothread(main, -1).is_null());
        lua_settop(main, 1);
        assert_eq!(lua_pushthread(child), 0);
        assert_eq!(lua_tothread(child, -1), child);
        assert_eq!(lua_gettop(child), 1);
        lua_pushinteger(main, 37);
        lua_setglobal(main, c"shared_b3".as_ptr());
        assert_eq!(lua_getglobal(child, c"shared_b3".as_ptr()), 3);
        assert_eq!(lua_tointegerx(child, -1, std::ptr::null_mut()), 37);
        assert_eq!(lua_rawgeti(child, REGISTRY_INDEX, MAINTHREAD_INDEX), 8);
        assert_eq!(lua_tothread(child, -1), main);
        lua_close(main);
    }
}

#[test]
fn main_owner_drop_and_busy_foreign_calls_fail_closed_b3() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let main = owner.as_ptr();
    let overlay = sibling.as_ptr();
    // SAFETY：owner 與 sibling 存活，外執行緒 join 前不釋放 main。
    unsafe {
        assert_eq!(lua_rawgeti(overlay, REGISTRY_INDEX, MAINTHREAD_INDEX), 8);
        assert_eq!(lua_tothread(overlay, -1), main);
    }
    owner
        .with_vm(|_| {
            // SAFETY：state 仍存活；group 的活躍可變借用應讓入口 fail-closed。
            unsafe {
                assert!(lua_tothread(main, -1).is_null());
                assert!(lua_newthread(main).is_null());
                assert_eq!(lua_pushthread(main), 0);
            }
        })
        .unwrap();
    let main_address = main as usize;
    std::thread::spawn(move || {
        let pointer = main_address as *mut rivetlua_capi::stack::lua_State;
        // SAFETY：owner 在 join 前保持配置存活；外執行緒入口須拒絕。
        unsafe {
            assert!(lua_tothread(pointer, -1).is_null());
            assert!(lua_newthread(pointer).is_null());
            assert_eq!(lua_pushthread(pointer), 0);
        }
    })
    .join()
    .unwrap();
    drop(owner);
    // SAFETY：sibling 保有 group 與 registry；main owner 已釋放，不能回懸空位址。
    unsafe {
        assert!(lua_tothread(overlay, -1).is_null());
        assert_eq!(lua_gettop(overlay), 1);
        assert_eq!(lua_pushthread(overlay), 0);
    }
}

#[test]
fn grandchild_extraspace_comes_from_main_b3() {
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：main、child、grandchild 均由未清除的 C stack 值保活。
    unsafe {
        let main_extra = main.cast::<u8>().sub(size_of::<*mut c_void>());
        for offset in 0..size_of::<*mut c_void>() {
            *main_extra.add(offset) = 0x41 + offset as u8;
        }
        let child = lua_newthread(main);
        assert!(!child.is_null());
        let child_extra = child.cast::<u8>().sub(size_of::<*mut c_void>());
        for offset in 0..size_of::<*mut c_void>() {
            assert_eq!(*child_extra.add(offset), *main_extra.add(offset));
            *child_extra.add(offset) = 0x7f;
        }
        let grandchild = lua_newthread(child);
        assert!(!grandchild.is_null());
        let grandchild_extra = grandchild.cast::<u8>().sub(size_of::<*mut c_void>());
        for offset in 0..size_of::<*mut c_void>() {
            assert_eq!(*grandchild_extra.add(offset), *main_extra.add(offset));
        }
        lua_close(main);
    }
}

#[test]
fn thread_identity_survives_xmove_and_overlay_rejects_b3() {
    let owner = StateOwner::new().unwrap();
    let overlay = owner.new_sibling().unwrap();
    let main = owner.as_ptr();
    let sibling = overlay.as_ptr();
    // SAFETY：兩個 StateOwner 都存活；child 由 main stack 保活。
    unsafe {
        assert!(lua_newthread(sibling).is_null());
        assert_eq!(lua_pushthread(sibling), 0);
        assert_eq!(lua_isyieldable(sibling), 0);
        assert_eq!(lua_gettop(sibling), 0);
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(lua_isyieldable(child), 1);
        lua_xmove(main, sibling, 1);
        assert_eq!(lua_tothread(sibling, -1), child);
        assert_eq!(lua_isyieldable(sibling), 0);
        assert_eq!(lua_isyieldable(child), 1);
        assert_eq!(lua_gettop(main), 0);
    }
}

#[test]
fn child_attachment_follows_reachability_and_refunds_host_charge_b3() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let main = owner.as_ptr();
        owner.with_vm(|vm| vm.set_gc_mode(mode).unwrap()).unwrap();
        // SAFETY：main 在 owner 存活期間有效；第一個 integer 保持 stack 容量。
        unsafe {
            lua_pushinteger(main, 1);
            assert_eq!(lua_checkstack(main, 1), 1);
        }
        let before = owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                vm.ledger_snapshot()
            })
            .unwrap();
        // SAFETY：thread 在 main stack 有一個 HostHandle root。
        let child = unsafe { lua_newthread(main) };
        assert!(!child.is_null());
        let (object, held) = owner
            .with_vm(|vm| {
                let mut hosts = Vec::new();
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Host {
                        hosts.push(object);
                    }
                });
                assert_eq!(hosts.len(), 1);
                (hosts[0], vm.ledger_snapshot())
            })
            .unwrap();
        assert!(
            held.host_allocation_bytes - before.host_allocation_bytes
                >= StateOwner::allocation_component_sizes().3
        );
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(object), Ok(ObjectKind::Coroutine));
            })
            .unwrap();
        // SAFETY：pop 後不再使用 child 裸指標；main 的 integer 仍保有 stack 容量。
        unsafe { lua_settop(main, 1) };
        let unrooted = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        assert_eq!(
            unrooted.host_allocation_bytes - before.host_allocation_bytes,
            StateOwner::allocation_component_sizes().3
        );
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
                assert_eq!(
                    vm.ledger_snapshot().host_allocation_bytes,
                    before.host_allocation_bytes
                );
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            })
            .unwrap();
    }
}

#[test]
fn child_creation_failpoints_refund_and_retry_b3() {
    for point in [
        FailPoint::ObjectReserve,
        FailPoint::ObjectInitialize,
        FailPoint::RootReserve,
        FailPoint::HostLease,
    ] {
        let owner = StateOwner::new().unwrap();
        let main = owner.as_ptr();
        // SAFETY：main 在 owner 存活期間有效；預留後測試僅改動 thread 建立交易。
        unsafe {
            lua_pushinteger(main, 9);
            assert_eq!(lua_checkstack(main, 1), 1);
        }
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        // SAFETY：無 checkpoint 的配置錯誤依 A50 契約返回 NULL，stack 不變。
        unsafe {
            assert!(lua_newthread(main).is_null(), "{point:?}");
            assert_eq!(lua_gettop(main), 1);
        }
        owner
            .with_vm(|vm| {
                assert_eq!(vm.ledger_snapshot(), before, "{point:?}");
                assert_eq!(vm.roots().count(RootKind::Host), 0);
            })
            .unwrap();
        // SAFETY：失敗注入為一次性；重試應正常發布唯一 child root。
        unsafe {
            assert!(!lua_newthread(main).is_null(), "{point:?}");
            assert_eq!(lua_gettop(main), 2);
            lua_settop(main, 1);
        }
    }
}
