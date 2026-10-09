use std::ffi::{CStr, c_char};

use rivetlua_capi::stack::{StateOwner, lua_State, lua_gettop, lua_settop, lua_tolstring};
use rivetlua_runtime::{GcMode, RootKind};

unsafe extern "C" {
    fn luaL_traceback(
        state: *mut lua_State,
        source: *mut lua_State,
        message: *const c_char,
        level: i32,
    );
}

#[test]
fn public_traceback_idle_message_and_stack_boundary() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：同一 live state；固定 C 字串在呼叫期間有效。
    unsafe {
        assert_eq!(lua_gettop(state), 0);
        luaL_traceback(state, state, c"trace".as_ptr(), 0);
        assert_eq!(lua_gettop(state), 1);
        let mut length = 0;
        let pointer = lua_tolstring(state, -1, &mut length);
        assert!(!pointer.is_null());
        let bytes = std::slice::from_raw_parts(pointer.cast::<u8>(), length);
        assert!(bytes.starts_with(b"trace\nstack traceback:"));
        assert_eq!(CStr::from_ptr(pointer).to_bytes(), bytes);
        lua_settop(state, 0);
    }
}

#[test]
fn public_traceback_accepts_sibling_and_rejects_foreign_vm_atomically() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let foreign = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：三個 state 都由 owner 保活；跨 VM 拒絕不得更動目標 stack。
    unsafe {
        luaL_traceback(state, sibling.as_ptr(), std::ptr::null(), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_gettop(sibling.as_ptr()), 0);
        luaL_traceback(state, foreign.as_ptr(), c"foreign".as_ptr(), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_gettop(foreign.as_ptr()), 0);
    }
}

#[test]
fn public_traceback_repeated_gc_modes_release_temporary_roots() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        // 首次 auxiliary buffer 會建立可重用容量；先暖機再比較重複呼叫。
        unsafe {
            luaL_traceback(state, state, c"repeated".as_ptr(), 0);
            lua_settop(state, 0);
        }
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        let before = owner
            .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
            .unwrap();
        for _ in 0..3 {
            // SAFETY：owner 保活同一 state；只讀同步建立的頂端字串。
            unsafe {
                luaL_traceback(state, state, c"repeated".as_ptr(), 0);
                assert_eq!(lua_gettop(state), 1);
                let mut len = 0;
                assert!(!lua_tolstring(state, -1, &mut len).is_null());
                assert!(len >= b"repeated\nstack traceback:".len());
                lua_settop(state, 0);
            }
            owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
            let after = owner
                .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
                .unwrap();
            assert_eq!(after.0.reserved, 0);
            assert_eq!(after.0.committed, before.0.committed);
            assert_eq!(after.1, before.1);
        }
    }
}
