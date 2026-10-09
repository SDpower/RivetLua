use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_copy, lua_gettop, lua_pushcclosure, lua_pushinteger, lua_pushvalue,
    lua_settop, lua_tointegerx, lua_type,
};
use std::ffi::{CStr, c_char, c_void};

#[cfg(feature = "lua54")]
const UPVALUE_1: i32 = -1_001_001;
#[cfg(feature = "lua55")]
const UPVALUE_1: i32 = -(i32::MAX / 2 + 1000) - 1;
const UPVALUE_2: i32 = UPVALUE_1 - 1;

unsafe extern "C" {
    fn lua_pcallk(
        state: *mut lua_State,
        nargs: i32,
        nresults: i32,
        errfunc: i32,
        context: isize,
        continuation: Option<unsafe extern "C" fn(*mut lua_State, i32, isize) -> i32>,
    ) -> i32;
    fn rivetlua_capi_test_push_lua_b4(state: *mut lua_State, selector: i32) -> i32;
    fn lua_getupvalue(state: *mut lua_State, index: i32, n: i32) -> *const c_char;
    fn lua_setupvalue(state: *mut lua_State, index: i32, n: i32) -> *const c_char;
    fn lua_upvalueid(state: *mut lua_State, index: i32, n: i32) -> *mut c_void;
    fn lua_upvaluejoin(state: *mut lua_State, index1: i32, n1: i32, index2: i32, n2: i32);
    fn rivetlua_capi_test_upvalue_cache_lifecycle_a4b(state: *mut lua_State, mode: i32) -> i32;
    fn rivetlua_capi_test_upvalue_cache_len_a4b(state: *mut lua_State) -> usize;
}

#[test]
fn upvalue_string_publications_release_on_callback_exit_and_state_close_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let mut stable_ledger = None;
    for round in 0..2 {
        for mode in 0..4 {
            // SAFETY：有效 state；私有 C 夾具以 lua_pcall 捕捉 return/error/lua_error/nested callback。
            let status = unsafe { rivetlua_capi_test_upvalue_cache_lifecycle_a4b(state, mode) };
            assert_eq!(status, if mode == 1 || mode == 2 { 2 } else { 0 });
            assert_eq!(unsafe { lua_gettop(state) }, 0);
            assert_eq!(
                unsafe { rivetlua_capi_test_upvalue_cache_len_a4b(state) },
                0
            );
            owner
                .with_vm(|vm| {
                    while vm.gc_trace().phase != rivetlua_runtime::GcPhase::Pause {
                        vm.incremental_step(1024).unwrap();
                    }
                    vm.collect().unwrap();
                })
                .unwrap();
        }
        let ledger = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        if round == 0 {
            // 首輪註冊固定 C function；次輪需重用而不累積 cache charge。
            stable_ledger = Some(ledger);
        } else {
            assert_eq!(Some(ledger), stable_ledger);
        }
    }
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

unsafe extern "C" fn increment_cell(state: *mut lua_State) -> i32 {
    // SAFETY：公開 protected call 正同步執行此 C closure，state 與 cell 均由外層保活。
    unsafe {
        assert_eq!(lua_type(state, UPVALUE_1), 3);
        let current = lua_tointegerx(state, UPVALUE_1, std::ptr::null_mut());
        lua_pushinteger(state, current + 1);
        lua_copy(state, -1, UPVALUE_1);
        lua_settop(state, 0);
        lua_pushinteger(
            state,
            lua_tointegerx(state, UPVALUE_1, std::ptr::null_mut()),
        );
    }
    1
}

unsafe extern "C" fn nested_inner(state: *mut lua_State) -> i32 {
    // SAFETY：呼叫位於最內層 C closure 的同步 checkpoint。
    unsafe {
        if lua_tointegerx(state, UPVALUE_1, std::ptr::null_mut()) != 41 {
            return 0;
        }
        lua_pushinteger(state, 42);
        lua_copy(state, -1, UPVALUE_1);
        lua_settop(state, 0);
        lua_pushvalue(state, UPVALUE_1);
    }
    1
}

unsafe extern "C" fn nested_outer(state: *mut lua_State) -> i32 {
    // SAFETY：外層捕獲 Lua 函式；Lua→內層 C callback 呼叫完後，外層 cell 仍存活。
    unsafe {
        lua_pushvalue(state, UPVALUE_2);
        lua_pushinteger(state, 41);
        lua_pushcclosure(state, Some(nested_inner), 1);
        lua_pushinteger(state, 0);
        if lua_pcallk(state, 2, 1, 0, 0, None) != 0 {
            return 0;
        }
        lua_pushvalue(state, UPVALUE_1);
    }
    2
}

unsafe extern "C" fn join_captured_lua(state: *mut lua_State) -> i32 {
    // SAFETY：兩個 pseudo-index 均指向目前 C closure 保活的 Lua closure。
    unsafe {
        let before = lua_upvalueid(state, UPVALUE_1, 1);
        let source = lua_upvalueid(state, UPVALUE_2, 1);
        if before.is_null() || source.is_null() || before == source {
            return 0;
        }
        lua_pushinteger(state, 33);
        if lua_setupvalue(state, UPVALUE_2, 1).is_null() {
            return 0;
        }
        lua_upvaluejoin(state, UPVALUE_1, 1, UPVALUE_2, 1);
        lua_upvaluejoin(state, UPVALUE_1, 1, UPVALUE_1, 1);
        if lua_upvalueid(state, UPVALUE_1, 1) != source {
            return 0;
        }
        if lua_getupvalue(state, UPVALUE_1, 1).is_null() {
            return 0;
        }
        lua_pushvalue(state, UPVALUE_1);
        if lua_pcallk(state, 0, 1, 0, 0, None) != 0 {
            return 0;
        }
    }
    2
}

unsafe extern "C" fn mutate_open_lua_cell(state: *mut lua_State) -> i32 {
    // SAFETY：selector 8 的 Lua frame 停在本次同步 C callback，參數一保活 open closure。
    unsafe {
        if lua_gettop(state) != 1 {
            return 0;
        }
        let name = lua_getupvalue(state, 1, 1);
        if name.is_null() || CStr::from_ptr(name).to_bytes() != b"(no name)" {
            return 0;
        }
        if lua_gettop(state) != 2 || lua_tointegerx(state, -1, std::ptr::null_mut()) != 17 {
            return 0;
        }
        let identity = lua_upvalueid(state, 1, 1);
        lua_pushinteger(state, 23);
        if lua_setupvalue(state, 1, 1).is_null() || lua_gettop(state) != 2 {
            return 0;
        }
        if lua_upvalueid(state, 1, 1) != identity {
            return 0;
        }
        lua_settop(state, 1);
        if lua_getupvalue(state, 1, 1).is_null()
            || lua_tointegerx(state, -1, std::ptr::null_mut()) != 23
        {
            return 0;
        }
    }
    0
}

#[test]
fn public_c_closure_pseudovalue_write_persists_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；每次呼叫都在 lua_pcallk 的 C checkpoint 內完成。
    unsafe {
        lua_pushinteger(state, 17);
        lua_pushcclosure(state, Some(increment_cell), 1);
        assert_eq!(lua_gettop(state), 1);
        for expected in [18, 19] {
            lua_pushvalue(state, 1);
            assert_eq!(lua_pcallk(state, 0, 1, 0, 0, None), 0);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), expected);
            lua_settop(state, 1);
        }
    }
}

#[test]
fn public_lua_upvalue_name_value_identity_and_join_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：fixture 只產生已驗證的本機閉合 Lua 函式，state 由 owner 保活。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 6), 1);
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 7), 1);
        assert_eq!(lua_gettop(state), 2);
        let first_id = lua_upvalueid(state, 1, 1);
        let second_id = lua_upvalueid(state, 2, 1);
        assert!(!first_id.is_null());
        assert!(!second_id.is_null());
        assert_ne!(first_id, second_id);
        let name = lua_getupvalue(state, 1, 1);
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"x");
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 17);
        lua_settop(state, 2);
        let name = lua_getupvalue(state, 2, 1);
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"(no name)");
        lua_settop(state, 2);
        assert!(lua_getupvalue(state, 1, 2).is_null());
        assert_eq!(lua_gettop(state), 2);
        lua_pushinteger(state, 23);
        let name = lua_setupvalue(state, 1, 1);
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"x");
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_upvalueid(state, 1, 1), first_id);
        lua_upvaluejoin(state, 2, 1, 1, 1);
        assert_eq!(lua_upvalueid(state, 2, 1), first_id);
        lua_pushvalue(state, 2);
        assert_eq!(lua_pcallk(state, 0, 1, 0, 0, None), 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 23);
        lua_settop(state, 2);
        lua_pushinteger(state, 31);
        let name = lua_setupvalue(state, 2, 1);
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"(no name)");
        assert_eq!(lua_upvalueid(state, 1, 1), first_id);
        let name = lua_getupvalue(state, 1, 1);
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"x");
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 31);
        lua_settop(state, 2);
    }
}

#[test]
fn nested_c_lua_c_callbacks_keep_innermost_cells_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：fixture selector 1 產生已驗證 Lua 函式；兩次呼叫均有 public checkpoint。
    unsafe {
        lua_pushinteger(state, 17);
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        lua_pushcclosure(state, Some(nested_outer), 2);
        assert_eq!(lua_pcallk(state, 0, 2, 0, 0, None), 0);
        assert_eq!(lua_tointegerx(state, -2, std::ptr::null_mut()), 42);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 17);
    }
}

#[test]
fn lua_upvalue_functions_accept_captured_function_indices_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：selector 6/7 均產生已驗證 Lua closure，外層 C closure 保活兩個 capture。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 6), 1);
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 7), 1);
        lua_pushcclosure(state, Some(join_captured_lua), 2);
        assert_eq!(lua_pcallk(state, 0, 2, 0, 0, None), 0);
        assert_eq!(lua_tointegerx(state, -2, std::ptr::null_mut()), 33);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 33);
    }
}

#[test]
fn public_get_setupvalue_reach_open_lua_frame_a4b() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：selector 8 已驗證，公開 call 停放 Lua frame 時呼叫 C callback。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 8), 1);
        lua_pushcclosure(state, Some(mutate_open_lua_cell), 0);
        let status = lua_pcallk(state, 1, 2, 0, 0, None);
        assert_eq!(status, 0);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 23);
        assert!(!lua_getupvalue(state, 2, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 23);
    }
}
