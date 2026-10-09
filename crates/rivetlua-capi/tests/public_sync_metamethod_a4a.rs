use std::cell::Cell;
use std::ffi::{c_char, c_int};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_getfield, lua_getglobal, lua_geti,
    lua_getmetatable, lua_gettable, lua_gettop, lua_newuserdatauv, lua_pushcclosure,
    lua_pushinteger, lua_pushlightuserdata, lua_pushvalue, lua_rawequal, lua_rawgeti, lua_setfield,
    lua_setglobal, lua_seti, lua_setmetatable, lua_settable, lua_settop, lua_tointegerx, lua_type,
    luaL_getmetafield, luaL_getsubtable, luaL_testudata,
};
use rivetlua_runtime::{GcMode, GcPhase, RootKind};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;

type LuaCFunction = unsafe extern "C" fn(*mut lua_State) -> c_int;

#[repr(C)]
struct LuaLReg {
    name: *const c_char,
    func: Option<LuaCFunction>,
}

unsafe extern "C" {
    fn luaL_callmeta(state: *mut lua_State, index: c_int, event: *const c_char) -> c_int;
    fn luaL_setfuncs(state: *mut lua_State, entries: *const LuaLReg, nup: c_int);
    fn rivetlua_capi_test_public_protected_a4a(
        state: *mut lua_State,
        operation: c_int,
        index: c_int,
        name: *const c_char,
        key: i64,
        entries: *const LuaLReg,
        nup: c_int,
        inject_offset: c_int,
        injection_start: *mut u64,
    ) -> c_int;
}

thread_local! {
    static SET_VALUE: Cell<i64> = const { Cell::new(-1) };
}

unsafe extern "C" fn index_answer(state: *mut lua_State) -> c_int {
    // SAFETY：C callback 的 state 由公開呼叫持有；此 callback 只正常返回。
    unsafe {
        lua_pushinteger(state, if lua_gettop(state) == 2 { 42 } else { -42 });
    }
    1
}

unsafe extern "C" fn meta_answer(state: *mut lua_State) -> c_int {
    // SAFETY：同上，luaL_callmeta 只傳入物件本身。
    unsafe {
        lua_pushinteger(state, if lua_gettop(state) == 1 { 73 } else { -73 });
    }
    1
}

unsafe extern "C" fn capture_set(state: *mut lua_State) -> c_int {
    // SAFETY：同上；__newindex 接收 target/key/value 三參數。
    unsafe {
        SET_VALUE.with(|seen| {
            seen.set(if lua_gettop(state) == 3 {
                lua_tointegerx(state, 3, std::ptr::null_mut())
            } else {
                -999
            });
        });
    }
    0
}

fn add_metatable(
    state: *mut lua_State,
    target: c_int,
    name: &'static std::ffi::CStr,
    callback: LuaCFunction,
) {
    // SAFETY：呼叫期間 state 存活，target 於加上 metatable 前固定，名稱為靜態字串。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushcclosure(state, Some(callback), 0);
        lua_setfield(state, -2, name.as_ptr());
        assert_eq!(lua_setmetatable(state, target), 1);
    }
}

#[test]
fn public_callmeta_missing_and_one_result_a4a() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 由 owner 保活；缺席時 stack 不變，命中時留下單一結果。
    unsafe {
        lua_createtable(state, 0, 0);
        assert_eq!(luaL_callmeta(state, 1, c"__answer".as_ptr()), 0);
        assert_eq!(lua_gettop(state), 1);
        add_metatable(state, 1, c"__answer", meta_answer);
        assert_eq!(luaL_callmeta(state, 1, c"__answer".as_ptr()), 1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 73);
    }
}

#[test]
fn public_getters_function_chain_global_and_userdata_a4a() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        let state = owner.as_ptr();
        // SAFETY：owner 保活 state，函式型 __index 由 C callback 正常返回。
        unsafe {
            lua_createtable(state, 0, 0);
            add_metatable(state, 1, c"__index", index_answer);
            assert_eq!(lua_getfield(state, 1, c"absent".as_ptr()), 3);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 1);
            lua_pushinteger(state, 9);
            assert_eq!(lua_gettable(state, 1), 3);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 1);
            assert_eq!(lua_geti(state, 1, 9), 3);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 1);

            assert!(!lua_newuserdatauv(state, 1, 0).is_null());
            add_metatable(state, 2, c"__index", index_answer);
            assert_eq!(lua_getfield(state, 2, c"userdata".as_ptr()), 3);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 2);
            assert_eq!(lua_getmetatable(state, 2), 1);
            lua_pushcclosure(state, Some(capture_set), 0);
            lua_setfield(state, -2, c"__newindex".as_ptr());
            lua_settop(state, 2);
            SET_VALUE.with(|seen| seen.set(-1));
            lua_pushinteger(state, 81);
            lua_setfield(state, 2, c"userdata-set".as_ptr());
            assert_eq!(SET_VALUE.with(Cell::get), 81);

            assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), 5);
            add_metatable(state, 3, c"__index", index_answer);
            assert_eq!(lua_getglobal(state, c"global-absent".as_ptr()), 3);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 0);
        }
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
    }
}

#[test]
fn public_setters_function_and_table_chain_a4a() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    SET_VALUE.with(|seen| seen.set(-1));
    // SAFETY：owner 保活 state；函式 callback 只正常返回。
    unsafe {
        lua_createtable(state, 0, 0);
        add_metatable(state, 1, c"__newindex", capture_set);
        lua_pushinteger(state, 1);
        lua_pushinteger(state, 37);
        lua_settable(state, 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(SET_VALUE.with(Cell::get), 37);
        lua_pushinteger(state, 38);
        lua_setfield(state, 1, c"field".as_ptr());
        assert_eq!(SET_VALUE.with(Cell::get), 38);
        lua_pushinteger(state, 39);
        lua_seti(state, 1, 4);
        assert_eq!(SET_VALUE.with(Cell::get), 39);

        // table 型 __newindex 將寫入導向 fallback table。
        lua_settop(state, 0);
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_pushvalue(state, 2);
        lua_setfield(state, 3, c"__newindex".as_ptr());
        assert_eq!(lua_setmetatable(state, 1), 1);
        lua_pushinteger(state, 55);
        lua_setfield(state, 1, c"chained".as_ptr());
        assert_eq!(lua_getfield(state, 2, c"chained".as_ptr()), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 55);
        lua_settop(state, 2);

        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), 5);
        add_metatable(state, 3, c"__newindex", capture_set);
        lua_pushinteger(state, 77);
        lua_setglobal(state, c"new-global".as_ptr());
        assert_eq!(SET_VALUE.with(Cell::get), 77);
    }
}

#[test]
fn public_getter_table_chain_a4a() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：三張 table 由 stack root 保活；table 型 __index 要直接查 fallback。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 55);
        lua_setfield(state, 2, c"answer".as_ptr());
        lua_createtable(state, 0, 0);
        lua_pushvalue(state, 2);
        lua_setfield(state, 3, c"__index".as_ptr());
        assert_eq!(lua_setmetatable(state, 1), 1);
        assert_eq!(lua_getfield(state, 1, c"answer".as_ptr()), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 55);
        assert_eq!(lua_gettop(state), 3);
    }
}

#[test]
fn public_primitive_type_metatable_auxiliary_boundaries_a4a() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；同一數字型別共用 metatable，但 full userdata 判定仍拒絕 primitive。
    unsafe {
        lua_pushinteger(state, 1);
        add_metatable(state, 1, c"__index", index_answer);
        lua_pushinteger(state, 2);
        assert_eq!(lua_getmetatable(state, 2), 1);
        assert_eq!(lua_gettop(state), 3);
        lua_settop(state, 2);
        assert_eq!(lua_getfield(state, 2, c"primitive".as_ptr()), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
        lua_settop(state, 2);
        assert_eq!(luaL_getmetafield(state, 2, c"__index".as_ptr()), 6);
        assert_eq!(lua_type(state, -1), 6);
        lua_settop(state, 2);
        assert_eq!(lua_getmetatable(state, 2), 1);
        lua_pushcclosure(state, Some(capture_set), 0);
        lua_setfield(state, -2, c"__newindex".as_ptr());
        lua_settop(state, 2);
        SET_VALUE.with(|seen| seen.set(-1));
        lua_pushinteger(state, 63);
        lua_seti(state, 2, 5);
        assert_eq!(SET_VALUE.with(Cell::get), 63);
        assert!(luaL_testudata(state, 2, c"number-type".as_ptr()).is_null());
        lua_pushlightuserdata(state, 1usize as *mut _);
        assert!(luaL_testudata(state, 3, c"number-type".as_ptr()).is_null());
    }
}

#[test]
fn public_aux_subtable_and_setfuncs_use_metamethods_a4a() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    SET_VALUE.with(|seen| seen.set(-1));
    // SAFETY：owner 保活 state；getsubtable 對 __index chain 一般查值，setfuncs 對 __newindex 一般寫入。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 5);
        lua_setfield(state, 3, c"found".as_ptr());
        lua_pushvalue(state, 3);
        lua_setfield(state, 2, c"child".as_ptr());
        lua_createtable(state, 0, 0);
        lua_pushvalue(state, 2);
        lua_setfield(state, 4, c"__index".as_ptr());
        assert_eq!(lua_setmetatable(state, 1), 1);
        assert_eq!(luaL_getsubtable(state, 1, c"child".as_ptr()), 1);
        assert_eq!(lua_rawequal(state, -1, 3), 1);
        lua_settop(state, 0);
        lua_createtable(state, 0, 0);
        add_metatable(state, 1, c"__newindex", capture_set);
        let entries = [
            LuaLReg {
                name: c"f".as_ptr(),
                func: Some(meta_answer),
            },
            LuaLReg {
                name: std::ptr::null(),
                func: None,
            },
        ];
        luaL_setfuncs(state, entries.as_ptr(), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_ne!(SET_VALUE.with(Cell::get), -1);
    }
}

#[test]
fn protected_public_getter_failpoint_keeps_roots_and_retries_a4a() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        let state = owner.as_ptr();
        // SAFETY：C helper 於 lua_pcall 的純 C callback 內呼叫公開 getter。
        unsafe {
            lua_createtable(state, 0, 0);
            add_metatable(state, 1, c"__index", index_answer);
            let mut steady = None;
            for _ in 0..2 {
                let mut ordinal = 0;
                assert_eq!(
                    rivetlua_capi_test_public_protected_a4a(
                        state,
                        1,
                        1,
                        c"absent".as_ptr(),
                        0,
                        std::ptr::null(),
                        0,
                        0,
                        &mut ordinal,
                    ),
                    -4,
                );
                assert!(ordinal > 0);
                assert_eq!(lua_gettop(state), 1);
                let after = owner
                    .with_vm(|vm| {
                        assert_eq!(
                            vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
                            ordinal
                        );
                        while vm.gc_trace().phase != GcPhase::Pause {
                            vm.incremental_step(1024).unwrap();
                        }
                        vm.collect().unwrap();
                        (vm.ledger_snapshot(), vm.roots().count(RootKind::Host))
                    })
                    .unwrap();
                assert_eq!(after.0.reserved, 0);
                assert_eq!(after.1, 1);
                if let Some(previous) = steady {
                    assert_eq!(after, previous);
                }
                steady = Some(after);
            }
            assert_eq!(
                rivetlua_capi_test_public_protected_a4a(
                    state,
                    1,
                    1,
                    c"absent".as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    -1,
                    std::ptr::null_mut(),
                ),
                3,
            );
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
            lua_settop(state, 0);
        }
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
    }
}
