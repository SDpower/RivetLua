use std::cell::Cell;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_close, lua_createtable, lua_gettop, lua_pushcclosure,
    lua_pushinteger, lua_pushlstring, lua_rawset, lua_setmetatable, lua_settop, lua_type,
    luaL_newstate,
};

thread_local! {
    static CLOSED_B11: Cell<usize> = const { Cell::new(0) };
    static SELFCLOSE_RETURNED_B11: Cell<bool> = const { Cell::new(false) };
    static SELFCLOSE_ENTERED_B11: Cell<bool> = const { Cell::new(false) };
    static BUSY_STATUS_B11: Cell<i32> = const { Cell::new(0) };
    static RUNTIME_CLOSED_B11: Cell<usize> = const { Cell::new(0) };
    static RUNTIME_AFTER_OVERLAY_B11: Cell<bool> = const { Cell::new(false) };
    static RESET_REENTRY_STATUS_B11: Cell<i32> = const { Cell::new(0) };
    static CLOSE_REENTRY_LIVE_B11: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" {
    fn lua_newthread(state: *mut lua_State) -> *mut lua_State;
    fn lua_toclose(state: *mut lua_State, index: i32);
    fn lua_closethread(state: *mut lua_State, from: *mut lua_State) -> i32;
    #[cfg(feature = "lua54")]
    fn lua_resetthread(state: *mut lua_State) -> i32;
    #[cfg(feature = "lua55")]
    fn rivetlua_capi_test_set_entry_b11(state: *mut lua_State) -> i32;
    #[cfg(feature = "lua55")]
    fn rivetlua_capi_test_resume_b11(state: *mut lua_State) -> i32;
    fn rivetlua_capi_test_install_runtime_close_b11(state: *mut lua_State) -> i32;
    fn luaL_checktype(state: *mut lua_State, index: i32, tag: i32);
}

#[cfg(feature = "lua55")]
unsafe extern "C" fn selfclose_callback_b11(state: *mut lua_State) -> i32 {
    SELFCLOSE_ENTERED_B11.with(|entered| entered.set(true));
    // SAFETY：此 child 正在 resume；一般 reset 須拒絕且保留停放的外部 token。
    let busy = unsafe { lua_closethread(state, std::ptr::null_mut()) };
    BUSY_STATUS_B11.with(|status| status.set(busy));
    // SAFETY：callback 的 state 為執行中 child；此呼叫在純 C checkpoint 跳回 resume。
    unsafe { lua_closethread(state, state) };
    SELFCLOSE_RETURNED_B11.with(|returned| returned.set(true));
    0
}

#[cfg(feature = "lua55")]
unsafe extern "C" fn selfclose_error_callback_b11(state: *mut lua_State) -> i32 {
    // SAFETY：callback 的 C overlay mark 會先於保存的 child overlay 由 B7 driver 關閉。
    unsafe {
        push_close_mark_with_b11(state, runtime_close_error_b11);
        lua_closethread(state, state);
    }
    SELFCLOSE_RETURNED_B11.with(|returned| returned.set(true));
    0
}

unsafe extern "C" fn close_mark_b11(_state: *mut lua_State) -> i32 {
    CLOSED_B11.with(|closed| closed.set(closed.get() + 1));
    0
}

unsafe extern "C" fn reset_reentry_b11(state: *mut lua_State) -> i32 {
    // SAFETY：外層 reset checkpoint 尚在執行；內層呼叫須 fail-closed 且不改 overlay。
    let status = unsafe { lua_closethread(state, std::ptr::null_mut()) };
    RESET_REENTRY_STATUS_B11.with(|observed| observed.set(status));
    0
}

unsafe extern "C" fn close_reentry_b11(state: *mut lua_State) -> i32 {
    // SAFETY：外層 lua_close 保活 state；重入 close 應直接拒絕。
    unsafe { lua_close(state) };
    CLOSE_REENTRY_LIVE_B11.with(|observed| observed.set(unsafe { lua_gettop(state) } >= 1));
    0
}

unsafe extern "C" fn runtime_close_mark_b11(_state: *mut lua_State) -> i32 {
    RUNTIME_CLOSED_B11.with(|count| count.set(count.get() + 1));
    RUNTIME_AFTER_OVERLAY_B11.with(|observed| observed.set(CLOSED_B11.with(Cell::get) > 0));
    0
}

unsafe extern "C" fn runtime_close_error_b11(state: *mut lua_State) -> i32 {
    RUNTIME_CLOSED_B11.with(|count| count.set(count.get() + 1));
    // SAFETY：`__close` 第一參數為 table；要求 number 觸發受 C checkpoint 保護的 Lua error。
    unsafe { luaL_checktype(state, 1, 3) };
    0
}

unsafe fn push_runtime_close_value_b11(
    state: *mut lua_State,
    closer: unsafe extern "C" fn(*mut lua_State) -> i32,
) {
    // SAFETY：呼叫者持有存活 state，以下只在其同步 C stack 上建立 metatable。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__close".as_ptr().cast(), 7);
        lua_pushcclosure(state, Some(closer), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
    }
}

unsafe fn push_close_mark_with_b11(
    state: *mut lua_State,
    closer: unsafe extern "C" fn(*mut lua_State) -> i32,
) {
    // SAFETY：呼叫者持有有效且未關閉的 C state。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__close".as_ptr().cast(), 7);
        lua_pushcclosure(state, Some(closer), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        lua_toclose(state, -1);
    }
}

unsafe fn push_close_mark_b11(state: *mut lua_State) {
    // SAFETY：呼叫者持有存活 C state。
    unsafe { push_close_mark_with_b11(state, close_mark_b11) };
}

#[test]
fn child_pointer_close_runs_main_pending_close_b11() {
    CLOSED_B11.with(|closed| closed.set(0));
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：main 與 child 在關閉前均由同組 C state 保活；close 後不再取用指標。
    unsafe {
        push_close_mark_b11(main);
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(lua_gettop(main), 2);
        lua_close(child);
    }
    assert_eq!(CLOSED_B11.with(Cell::get), 1);
}

#[test]
fn thread_reset_closes_overlay_and_rejects_foreign_from_b11() {
    CLOSED_B11.with(|closed| closed.set(0));
    let main = luaL_newstate();
    let foreign = luaL_newstate();
    assert!(!main.is_null() && !foreign.is_null());
    // SAFETY：兩個 main state 均 live；child 由本組 main stack 保活。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        push_close_mark_b11(child);
        assert_ne!(lua_closethread(child, foreign), 0);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(CLOSED_B11.with(Cell::get), 0);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(lua_gettop(child), 0);
        assert_eq!(CLOSED_B11.with(Cell::get), 1);
        push_close_mark_b11(child);
        #[cfg(feature = "lua54")]
        assert_eq!(lua_resetthread(child), 0);
        #[cfg(feature = "lua55")]
        assert_eq!(lua_closethread(child, std::ptr::null_mut()), 0);
        assert_eq!(lua_gettop(child), 0);
        assert_eq!(CLOSED_B11.with(Cell::get), 2);
        lua_close(foreign);
        lua_close(main);
    }
}

#[test]
fn overlay_closes_before_runtime_context_and_runtime_error_replaces_b11() {
    CLOSED_B11.with(|count| count.set(0));
    RUNTIME_CLOSED_B11.with(|count| count.set(0));
    RUNTIME_AFTER_OVERLAY_B11.with(|observed| observed.set(false));
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：child 在 main stack 保活；private fixture 安裝單一有根 runtime close frame。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        push_runtime_close_value_b11(child, runtime_close_mark_b11);
        assert_eq!(rivetlua_capi_test_install_runtime_close_b11(child), 1);
        lua_settop(child, 0);
        push_close_mark_b11(child);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(lua_gettop(child), 0);
        assert_eq!(CLOSED_B11.with(Cell::get), 1);
        assert_eq!(RUNTIME_CLOSED_B11.with(Cell::get), 1);
        assert!(RUNTIME_AFTER_OVERLAY_B11.with(Cell::get));

        push_runtime_close_value_b11(child, runtime_close_error_b11);
        assert_eq!(rivetlua_capi_test_install_runtime_close_b11(child), 1);
        lua_settop(child, 0);
        push_close_mark_b11(child);
        assert_eq!(lua_closethread(child, main), 2);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_type(child, -1), 4);
        assert_eq!(CLOSED_B11.with(Cell::get), 2);
        assert_eq!(RUNTIME_CLOSED_B11.with(Cell::get), 2);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(lua_gettop(child), 0);
        lua_close(main);
    }
}

#[cfg(feature = "lua55")]
#[test]
fn self_close_from_running_c_callback_never_returns_b11() {
    CLOSED_B11.with(|closed| closed.set(0));
    SELFCLOSE_RETURNED_B11.with(|returned| returned.set(false));
    SELFCLOSE_ENTERED_B11.with(|entered| entered.set(false));
    BUSY_STATUS_B11.with(|status| status.set(0));
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：child 在 main stack 保活；private fixture 只啟動已驗證的固定 closure。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(rivetlua_capi_test_set_entry_b11(child), 1);
        push_close_mark_b11(child);
        lua_pushcclosure(child, Some(selfclose_callback_b11), 0);
        let status = rivetlua_capi_test_resume_b11(child);
        assert_eq!(
            status,
            0,
            "callback_entered={} callback_returned={} closed={} top={}",
            SELFCLOSE_ENTERED_B11.with(Cell::get),
            SELFCLOSE_RETURNED_B11.with(Cell::get),
            CLOSED_B11.with(Cell::get),
            lua_gettop(child)
        );
        assert!(!SELFCLOSE_RETURNED_B11.with(Cell::get));
        assert_eq!(BUSY_STATUS_B11.with(Cell::get), 2);
        assert_eq!(CLOSED_B11.with(Cell::get), 1);
        assert_eq!(lua_gettop(child), 0);
        assert_eq!(lua_closethread(child, std::ptr::null_mut()), 0);
        lua_close(main);
    }
}

#[cfg(feature = "lua55")]
#[test]
fn self_close_overlay_error_reaches_initiating_resume_b11() {
    CLOSED_B11.with(|closed| closed.set(0));
    SELFCLOSE_RETURNED_B11.with(|returned| returned.set(false));
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：private fixture 啟動同組 child；self-close 只回純 C resume checkpoint。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(rivetlua_capi_test_set_entry_b11(child), 1);
        push_close_mark_b11(child);
        lua_pushcclosure(child, Some(selfclose_error_callback_b11), 0);
        assert_eq!(rivetlua_capi_test_resume_b11(child), 2);
        assert!(!SELFCLOSE_RETURNED_B11.with(Cell::get));
        assert_eq!(CLOSED_B11.with(Cell::get), 1);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_type(child, -1), 4);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(lua_gettop(child), 0);
        lua_close(main);
    }
}

#[test]
fn reset_allocation_failure_keeps_idle_state_retryable_b11() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    // SAFETY：owner 保活 state；失敗時須保留原空 stack 與 coroutine identity。
    unsafe {
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 4);
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 0);
        assert_eq!(lua_gettop(state), 0);
        lua_pushinteger(state, 7);
        assert_eq!(lua_gettop(state), 1);
    }
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    // SAFETY：既有 stack capacity 已足夠，下一次拒絕應發生在 runtime prepare。
    unsafe {
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 4);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 0);
        assert_eq!(lua_gettop(state), 0);
    }
}

#[test]
fn reset_prepare_allocation_failure_preserves_overlay_close_mark_b11() {
    CLOSED_B11.with(|closed| closed.set(0));
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；建立單一 overlay close mark。
    unsafe { push_close_mark_b11(state) };
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    // SAFETY：配置拒絕應在執行 callback 前完成，且原 mark 可重試。
    unsafe {
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 4);
        assert_eq!(CLOSED_B11.with(Cell::get), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_closethread(state, std::ptr::null_mut()), 0);
        assert_eq!(CLOSED_B11.with(Cell::get), 1);
        assert_eq!(lua_gettop(state), 0);
    }
}

#[test]
fn reset_and_shutdown_reentry_fail_closed_b11() {
    RESET_REENTRY_STATUS_B11.with(|status| status.set(0));
    CLOSE_REENTRY_LIVE_B11.with(|live| live.set(false));
    let main = luaL_newstate();
    assert!(!main.is_null());
    // SAFETY：C callback 在同執行緒內同步結束；外層 driver 保活 state。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        push_close_mark_with_b11(child, reset_reentry_b11);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(RESET_REENTRY_STATUS_B11.with(Cell::get), 2);
        assert_eq!(lua_gettop(child), 0);
        push_close_mark_with_b11(main, close_reentry_b11);
        lua_close(main);
    }
    assert!(CLOSE_REENTRY_LIVE_B11.with(Cell::get));
}
