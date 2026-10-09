use std::cell::{Cell, RefCell};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_copy, lua_createtable, lua_gettop, lua_pushboolean,
    lua_pushcclosure, lua_pushinteger, lua_pushlstring, lua_rawset, lua_rotate, lua_setmetatable,
    lua_settop, lua_tointegerx, lua_type, lua_xmove,
};
use rivetlua_runtime::{GcMode, RootKind};

thread_local! {
    static CLOSE_TRACE_B7: RefCell<Vec<(i32, i32, i32)>> = const { RefCell::new(Vec::new()) };
    static CLOSE_OWNER_B7: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
    static CLOSE_GC_OK_B7: Cell<bool> = const { Cell::new(true) };
}

unsafe extern "C" {
    fn lua_arith(state: *mut lua_State, operation: i32);
    fn lua_toclose(state: *mut lua_State, index: i32);
    fn lua_closeslot(state: *mut lua_State, index: i32);
    fn lua_newthread(state: *mut lua_State) -> *mut lua_State;
    fn rivetlua_capi_call_b4(state: *mut lua_State, nargs: i32, nresults: i32) -> i32;
    fn rivetlua_capi_test_push_lua_b4(state: *mut lua_State, selector: i32) -> i32;
    fn rivetlua_capi_toclose_prepare_b7(state: *mut lua_State, index: i32) -> i32;
    fn rivetlua_capi_test_protected_index_a4b(
        state: *mut lua_State,
        operation: i32,
        index: i32,
        argument: i32,
        name: *const std::ffi::c_char,
        answer: *mut i32,
    ) -> i32;
}

unsafe extern "C" fn add_with_mark_b7(state: *mut lua_State) -> i32 {
    // SAFETY：B5 C driver 呼叫此 callback；mark 在 callback 返回後由同一 C frame 關閉。
    unsafe {
        lua_createtable(state, 0, 0);
        add_close_metatable(state, close_one);
        lua_toclose(state, -1);
        lua_pushinteger(state, 9);
    }
    1
}

#[test]
fn arithmetic_callback_closes_mark_before_b5_resume_b7() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    reset_trace();
    // SAFETY：metatable 只附於第一個 operand，B5 callback 與 B7 close 同步完成。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__add".as_ptr().cast(), 5);
        lua_pushcclosure(state, Some(add_with_mark_b7), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        lua_pushinteger(state, 3);
        lua_arith(state, 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 9);
    }
    assert_eq!(
        trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![1]
    );
}

fn trace() -> Vec<(i32, i32, i32)> {
    CLOSE_TRACE_B7.with(|trace| trace.borrow().clone())
}

fn reset_trace() {
    CLOSE_TRACE_B7.with(|trace| trace.borrow_mut().clear());
    CLOSE_GC_OK_B7.with(|result| result.set(true));
}

unsafe fn record_close(state: *mut lua_State, id: i32) {
    // SAFETY：B7 C driver 在 callback 期間保活 state；此處只讀 callback 自己的參數。
    let (argc, second) = unsafe { (lua_gettop(state), lua_type(state, 2)) };
    CLOSE_TRACE_B7.with(|trace| trace.borrow_mut().push((id, argc, second)));
    CLOSE_OWNER_B7.with(|cell| {
        let owner = cell.get();
        if !owner.is_null() {
            // SAFETY：測試同步持有 owner；callback 完成後立即清除 thread-local 借址。
            let collected = unsafe { &*owner }
                .with_vm(|vm| vm.collect())
                .is_ok_and(|result| result.is_ok());
            CLOSE_GC_OK_B7.with(|result| result.set(result.get() && collected));
        }
    });
}

unsafe extern "C" fn close_one(state: *mut lua_State) -> i32 {
    // SAFETY：純 C callback 已離開 Rust step，state 在返回前保持有效。
    unsafe { record_close(state, 1) };
    0
}

unsafe extern "C" fn close_two(state: *mut lua_State) -> i32 {
    // SAFETY：同上，且不保存任何 C stack 指標。
    unsafe { record_close(state, 2) };
    0
}

unsafe extern "C" fn called_by_lua_close(state: *mut lua_State) -> i32 {
    // SAFETY：Lua closure 的 __call 鏈由同一 B4 parked execution 驅動。
    unsafe { record_close(state, 3) };
    0
}

unsafe fn add_close_metatable(
    state: *mut lua_State,
    function: unsafe extern "C" fn(*mut lua_State) -> i32,
) {
    // SAFETY：呼叫者保證 stack 頂端為 table；rawset 消耗 key/value，setmetatable 消耗 mt。
    unsafe {
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__close".as_ptr().cast(), 7);
        lua_pushcclosure(state, Some(function), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
    }
}

fn expected_normal_args() -> i32 {
    if cfg!(feature = "lua54") { 2 } else { 1 }
}

#[test]
fn nil_and_false_do_not_claim_stack_positions_b7() {
    for is_false in [false, true] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        reset_trace();
        // SAFETY：copy 到已略過的 slot 必須成功；同位置其後仍可建立真正的 mark。
        unsafe {
            if is_false {
                lua_pushboolean(state, 0);
            } else {
                rivetlua_capi::stack::lua_pushnil(state);
            }
            lua_toclose(state, 1);
            lua_createtable(state, 0, 0);
            add_close_metatable(state, close_one);
            lua_copy(state, 2, 1);
            assert_eq!(lua_type(state, 1), 5);
            lua_settop(state, 1);
            lua_toclose(state, 1);
            lua_settop(state, 0);
        }
        assert_eq!(
            trace().iter().map(|event| event.0).collect::<Vec<_>>(),
            vec![1]
        );
    }
}

#[test]
fn false_nil_skip_mark_and_closeslot_then_settop_are_lifo_b7() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    reset_trace();
    // SAFETY：owner 保活 state；mark 後依由高到低順序明確關閉。
    unsafe {
        rivetlua_capi::stack::lua_pushnil(state);
        lua_toclose(state, 1);
        lua_pushboolean(state, 0);
        lua_toclose(state, 2);
        lua_createtable(state, 0, 0);
        add_close_metatable(state, close_one);
        lua_toclose(state, 3);
        lua_createtable(state, 0, 0);
        add_close_metatable(state, close_two);
        lua_toclose(state, 4);
        lua_closeslot(state, 4);
        assert_eq!(lua_gettop(state), 4);
        assert_eq!(lua_type(state, 4), 0);
        lua_settop(state, 2);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);
    }
    assert_eq!(
        trace(),
        vec![
            (
                2,
                expected_normal_args(),
                if cfg!(feature = "lua54") { 0 } else { -1 }
            ),
            (
                1,
                expected_normal_args(),
                if cfg!(feature = "lua54") { 0 } else { -1 }
            ),
        ]
    );
}

#[test]
fn marks_stay_at_positions_across_rotate_copy_and_xmove_b7() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    reset_trace();
    // SAFETY：主 state 與新 thread 屬同一 owner/group；不在 mark 上移動 slot。
    unsafe {
        lua_createtable(state, 0, 0);
        add_close_metatable(state, close_one);
        lua_toclose(state, 1);
        lua_pushinteger(state, 10);
        lua_pushinteger(state, 20);
        lua_rotate(state, 2, 1);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 20);
        assert_eq!(lua_tointegerx(state, 3, std::ptr::null_mut()), 10);
        assert_ne!(
            rivetlua_capi_test_protected_index_a4b(
                state,
                12,
                2,
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            0
        );
        assert_eq!(lua_gettop(state), 3);
        assert!(trace().is_empty());
        lua_rotate(state, 1, 1);
        assert_eq!(lua_type(state, 1), 5);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 20);
        lua_settop(state, 0);
        assert_eq!(
            trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
            vec![1]
        );

        let child = lua_newthread(state);
        assert!(!child.is_null());
        lua_createtable(child, 0, 0);
        add_close_metatable(child, close_two);
        lua_toclose(child, 1);
        lua_pushinteger(child, 9);
        let main_top = lua_gettop(state);
        lua_xmove(child, state, 2);
        assert_eq!(lua_gettop(child), 2);
        assert_eq!(lua_gettop(state), main_top);
        lua_xmove(child, state, 1);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 9);
        lua_settop(child, 0);
    }
    assert_eq!(
        trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

unsafe extern "C" fn mark_and_return(state: *mut lua_State) -> i32 {
    // SAFETY：outer callback 是純 C frame，mark 留在其 stack 上直到 return 後關閉。
    unsafe {
        lua_createtable(state, 0, 0);
        add_close_metatable(state, close_one);
        lua_toclose(state, 1);
        lua_pushinteger(state, 42);
    }
    1
}

#[test]
fn callback_return_closes_after_c_frame_and_gc_keeps_value_alive_b7() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    reset_trace();
    CLOSE_OWNER_B7.with(|cell| cell.set(&owner));
    // SAFETY：owner 在整個同步 callback/close driver 期間保活 state。
    unsafe {
        lua_pushcclosure(state, Some(mark_and_return), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 42);
    }
    CLOSE_OWNER_B7.with(|cell| cell.set(std::ptr::null()));
    assert_eq!(
        trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![1]
    );
    assert!(CLOSE_GC_OK_B7.with(Cell::get));
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        0
    );
}

#[test]
fn lua_closure_close_uses_same_c_callback_chain_b7() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    reset_trace();
    // SAFETY：B4 私有 fixture 建立已驗證 Lua closure；__call 由同一 parked core 執行。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 2);
        lua_pushlstring(state, b"__call".as_ptr().cast(), 6);
        lua_pushcclosure(state, Some(called_by_lua_close), 0);
        lua_rawset(state, -3);
        lua_pushlstring(state, b"__close".as_ptr().cast(), 7);
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        lua_toclose(state, 1);
        lua_settop(state, 0);
    }
    assert_eq!(
        trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![3]
    );
}

#[test]
fn mark_allocation_rejection_rolls_back_and_same_state_retries_b7() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let make_owner = || {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            // SAFETY：owner 保活 state；建立的 table 與 metatable 都受 overlay root 保護。
            unsafe {
                lua_createtable(state, 0, 0);
                add_close_metatable(state, close_one);
            }
            owner
                .with_vm(|vm| {
                    vm.set_gc_mode(mode)?;
                    vm.set_collect_every_allocation(true);
                    Ok::<_, rivetlua_runtime::VmError>(())
                })
                .unwrap()
                .unwrap();
            owner
        };
        let dry = make_owner();
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        // SAFETY：私有 prepare step 只預備 mark，沒有 C callback/longjmp。
        assert_eq!(
            unsafe { rivetlua_capi_toclose_prepare_b7(dry.as_ptr(), 1) },
            1
        );
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start, "{mode:?}");
        drop(dry);

        for offset in 0..end - start {
            let owner = make_owner();
            let state = owner.as_ptr();
            reset_trace();
            let before = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            let ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
                .unwrap();
            // SAFETY：failure 在 Rust step 內被轉為 Allocation 類別，不跳過 Rust frame。
            assert_eq!(
                unsafe { rivetlua_capi_toclose_prepare_b7(state, 1) },
                -5,
                "{mode:?} offset={offset}"
            );
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            let after = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            assert_eq!(
                after.0.committed, before.0.committed,
                "{mode:?} offset={offset}"
            );
            assert_eq!(after.0.reserved, 0, "{mode:?} offset={offset}");
            assert_eq!(
                after.1.debt_bytes, before.1.debt_bytes,
                "{mode:?} offset={offset}"
            );
            assert_eq!(after.2, before.2, "{mode:?} offset={offset}");
            // SAFETY：被拒絕的 mark 不可導致縮減時關閉；同一 state 可建立並關閉新 mark。
            unsafe {
                lua_settop(state, 0);
                assert!(trace().is_empty(), "{mode:?} offset={offset}");
                lua_createtable(state, 0, 0);
                add_close_metatable(state, close_one);
                lua_toclose(state, 1);
                lua_settop(state, 0);
            }
            assert_eq!(
                trace().iter().map(|entry| entry.0).collect::<Vec<_>>(),
                vec![1]
            );
        }
    }
}
