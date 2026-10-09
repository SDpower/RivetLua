use std::cell::Cell;
use std::ffi::c_void;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushcclosure, lua_pushinteger,
    lua_pushlstring, lua_rawset, lua_setmetatable, lua_settop, lua_tointegerx,
};
use rivetlua_runtime::FailPoint;

thread_local! {
    static FINALIZER_CALLS_B8: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "C" {
    fn lua_gc(state: *mut lua_State, what: i32, ...) -> i32;
    fn rivetlua_capi_call_b4(state: *mut lua_State, nargs: i32, nresults: i32) -> i32;
    fn rivetlua_capi_gc_prepare_b8(
        state: *mut lua_State,
        what: i32,
        bytes: usize,
        first: i32,
        second: i32,
        third: i32,
    ) -> GcStepB8;
}

#[repr(C)]
struct GcStepB8 {
    kind: i32,
    value: i32,
    function: Option<unsafe extern "C" fn(*mut lua_State) -> i32>,
    _hook: Option<unsafe extern "C" fn(*mut lua_State, *mut c_void)>,
    _event: i32,
    _currentline: i32,
    _token: *mut c_void,
}

unsafe extern "C" fn finalizer_b8(state: *mut lua_State) -> i32 {
    FINALIZER_CALLS_B8.with(|count| count.set(count.get() + 1));
    // SAFETY：finalizer callback 由 B8 C driver 同步呼叫，沒有借用跨越 FFI。
    unsafe {
        assert_eq!(lua_gc(state, 2), -1);
    }
    0
}

unsafe fn add_finalizable_b8(state: *mut lua_State) {
    // SAFETY：有效 state 由測試 owner 保活；rawset/setmetatable 依固定 C stack 契約消耗值。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__gc".as_ptr().cast(), 4);
        lua_pushcclosure(state, Some(finalizer_b8), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        lua_settop(state, -2);
    }
}

unsafe extern "C" fn outer_gc_b8(state: *mut lua_State) -> i32 {
    // SAFETY：B4 driver 將此函式掛在最上層 parked token，nested GC 必須同步返回。
    unsafe {
        add_finalizable_b8(state);
        assert_eq!(lua_gc(state, 2), 0);
        lua_pushinteger(state, 77);
    }
    1
}

#[test]
fn c_finalizer_drains_inside_outer_callback_b8() {
    FINALIZER_CALLS_B8.with(|count| count.set(0));
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap();
    // SAFETY：owner 保活 state，B4/B8 C driver 在 Rust frame 已返回後執行 C callback。
    unsafe {
        add_finalizable_b8(state);
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(lua_gettop(state), 0);
        lua_pushcclosure(state, Some(outer_gc_b8), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 77);
        lua_settop(state, 0);
    }
    FINALIZER_CALLS_B8.with(|count| assert_eq!(count.get(), 2));
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        baseline
    );
}

#[test]
fn gc_command_numbering_and_varargs_b8() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在所有同步 C ABI 呼叫期間保活 state，變參型別依固定 header。
    unsafe {
        let count = lua_gc(state, 3);
        let remainder = lua_gc(state, 4);
        assert!((0..1024).contains(&remainder));
        assert_eq!(
            (count as usize) * 1024 + remainder as usize,
            owner.with_vm(|vm| vm.ledger_snapshot().committed).unwrap()
        );
        assert_eq!(lua_gc(state, 0), 0);
        assert_eq!(lua_gc(state, 1), 0);
        if cfg!(feature = "lua54") {
            assert_eq!(lua_gc(state, 9), 1);
            assert_eq!(lua_gc(state, 6, 200_i32), 200);
            assert_eq!(lua_gc(state, 7, 100_i32), 100);
            assert_eq!(lua_gc(state, 10, 20_i32, 100_i32), 10);
            assert_eq!(lua_gc(state, 11, 200_i32, 100_i32, 13_i32), 10);
            assert_eq!(lua_gc(state, 10, 0_i32, 0_i32), 11);
            assert!((0..=1).contains(&lua_gc(state, 5, 0_i32)));
        } else {
            assert_eq!(lua_gc(state, 6), 1);
            for (param, expected) in [20, 50, 68, 250, 200, 9600].into_iter().enumerate() {
                assert_eq!(lua_gc(state, 9, param as i32, -1_i32), expected);
            }
            assert_eq!(lua_gc(state, 9, 0_i32, 32_i32), 20);
            assert_eq!(lua_gc(state, 9, 0_i32, -1_i32), 31);
            assert_eq!(lua_gc(state, 9, 2_i32, 0_i32), 68);
            assert_eq!(lua_gc(state, 9, 2_i32, -1_i32), 0);
            assert_eq!(lua_gc(state, 9, -1_i32, -1_i32), -1);
            assert_eq!(lua_gc(state, 9, 6_i32, -1_i32), -1);
            assert_eq!(lua_gc(state, 7), 7);
            assert_eq!(lua_gc(state, 8), 7);
            assert!((0..=1).contains(&lua_gc(state, 5, 0_usize)));
        }
        assert_eq!(lua_gc(state, 999), -1);
    }
}

#[test]
fn gc_prepare_allocation_failure_retries_on_same_state_b8() {
    FINALIZER_CALLS_B8.with(|count| count.set(0));
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；prepare 的 C ABI 不執行 callback，錯誤作為 step 返回。
    unsafe {
        add_finalizable_b8(state);
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::MarkReserve))
            .unwrap();
        let failed = rivetlua_capi_gc_prepare_b8(state, 2, 0, 0, 0, 0);
        assert_eq!((failed.kind, failed.value), (-1, 5));
        assert!(failed.function.is_none());
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(lua_gettop(state), 0);
    }
    FINALIZER_CALLS_B8.with(|count| assert_eq!(count.get(), 1));
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        0
    );
}
