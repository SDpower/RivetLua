use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, Ordering};

use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_pushcclosure, lua_pushinteger, lua_pushvalue,
    lua_settop, lua_tointegerx, lua_type,
};
use rivetlua_runtime::{FailPoint, GcMode, RootKind, SlotId, SlotState};

static CALLBACK_TOP: AtomicI32 = AtomicI32::new(-1);
thread_local! {
    static GC_OWNER: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
    static LIVE_TOKENS: Cell<isize> = const { Cell::new(0) };
}

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}

unsafe extern "C" fn tracked_allocator(
    _ud: *mut c_void,
    pointer: *mut c_void,
    _old_size: usize,
    new_size: usize,
) -> *mut c_void {
    if new_size == 0 {
        if !pointer.is_null() {
            LIVE_TOKENS.with(|count| count.set(count.get() - 1));
            // SAFETY：pointer 由此 allocator 的 malloc/realloc 回傳且此處釋放一次。
            unsafe { free(pointer) };
        }
        return std::ptr::null_mut();
    }
    if pointer.is_null() {
        // SAFETY：請求新的 C allocator token，零大小已在上方處理。
        let token = unsafe { malloc(new_size) };
        if !token.is_null() {
            LIVE_TOKENS.with(|count| count.set(count.get() + 1));
        }
        token
    } else {
        // SAFETY：pointer 仍是此 allocator 擁有的存活 token。
        unsafe { realloc(pointer, new_size) }
    }
}

fn live_tokens() -> isize {
    LIVE_TOKENS.with(Cell::get)
}

fn fixture_snapshot(
    owner: &StateOwner,
) -> (
    rivetlua_runtime::LedgerSnapshot,
    rivetlua_runtime::GcTrace,
    Vec<SlotState>,
    (usize, usize),
) {
    owner
        .with_vm(|vm| {
            let mut slots = Vec::new();
            while let Some(state) = vm.slot_state(SlotId::new(slots.len())) {
                slots.push(state);
            }
            let mut roots = (0, 0);
            vm.visit_roots(|kind, _, _| {
                if kind == RootKind::Registry {
                    roots.0 += 1;
                } else {
                    roots.1 += 1;
                }
            });
            (vm.ledger_snapshot(), vm.gc_trace(), slots, roots)
        })
        .unwrap()
}

unsafe extern "C" {
    fn rivetlua_capi_call_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        nargs: i32,
        nresults: i32,
    ) -> i32;
    fn rivetlua_capi_test_push_lua_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        selector: i32,
    ) -> i32;
}

unsafe extern "C" fn add_one(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：B4 driver 在 callback 期間保活 state；回傳前不保留指標或 Rust 借用。
    unsafe {
        CALLBACK_TOP.store(lua_gettop(state), Ordering::SeqCst);
        let value = lua_tointegerx(state, 1, std::ptr::null_mut());
        lua_pushinteger(state, value + 1);
    }
    1
}

unsafe extern "C" fn nested_outer(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：C driver 在 callback 返回前保活同一 state，內層 private call 同步完成。
    unsafe {
        lua_pushcclosure(state, Some(add_one), 0);
        lua_pushvalue(state, 1);
        if rivetlua_capi_call_b4(state, 1, 1) != 0 {
            return -1;
        }
        let result = lua_tointegerx(state, -1, std::ptr::null_mut());
        lua_pushinteger(state, result + 1);
    }
    1
}

unsafe extern "C" fn capture_plus_arg(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    #[cfg(feature = "lua54")]
    const UPVALUE_1: i32 = -1_001_001;
    #[cfg(feature = "lua55")]
    const UPVALUE_1: i32 = -(i32::MAX / 2 + 1000) - 1;
    // SAFETY：driver 使最上層 token 與 closure 捕獲值在 callback 期間保活。
    unsafe {
        let capture = lua_tointegerx(state, UPVALUE_1, std::ptr::null_mut());
        let argument = lua_tointegerx(state, 1, std::ptr::null_mut());
        lua_pushinteger(state, capture + argument);
    }
    1
}

unsafe extern "C" fn invalid_result_count(_state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    99
}

unsafe extern "C" fn two_results(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：同一 C callback 中只操作存活 state stack。
    unsafe {
        lua_pushinteger(state, 41);
        lua_pushinteger(state, 42);
    }
    2
}

unsafe extern "C" fn collect_during_capture(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    #[cfg(feature = "lua54")]
    const UPVALUE_1: i32 = -1_001_001;
    #[cfg(feature = "lua55")]
    const UPVALUE_1: i32 = -(i32::MAX / 2 + 1000) - 1;
    let collected = GC_OWNER.with(|owner| {
        let pointer = owner.get();
        if pointer.is_null() {
            return false;
        }
        // SAFETY：測試在同執行緒且同步呼叫期間持有 StateOwner，返回後立即清空 thread-local。
        unsafe { &*pointer }
            .with_vm(|vm| vm.collect())
            .is_ok_and(|result| result.is_ok())
    });
    if !collected {
        return -1;
    }
    // SAFETY：同一 callback 的 C closure 捕獲值由 parked core 保活。
    unsafe {
        if lua_type(state, UPVALUE_1) != 5 {
            return -1;
        }
        lua_pushinteger(state, 42);
    }
    1
}

#[test]
fn c_function_callback_has_arg_base_and_fixed_result_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    CALLBACK_TOP.store(-1, Ordering::SeqCst);
    // SAFETY：owner 保活 state；C driver 必須在返回後才讓 Rust 借用結束。
    unsafe {
        lua_pushcclosure(state, Some(add_one), 0);
        lua_pushinteger(state, 41);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(CALLBACK_TOP.load(Ordering::SeqCst), 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn nested_c_callback_reuses_execution_and_restores_outer_stack_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；兩層 C callback 均由私有 driver 同步完成。
    unsafe {
        lua_pushcclosure(state, Some(nested_outer), 0);
        lua_pushinteger(state, 40);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn c_closure_capture_pseudo_index_is_visible_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；捕獲值在 closure 及 parked core 中均受 roots 保護。
    unsafe {
        lua_pushinteger(state, 40);
        lua_pushcclosure(state, Some(capture_plus_arg), 1);
        lua_pushinteger(state, 2);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn invalid_callback_result_count_aborts_and_same_state_retries_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；失敗的 C driver 必須清空 callback frame 與 token。
    unsafe {
        lua_pushcclosure(state, Some(invalid_result_count), 0);
        assert_ne!(rivetlua_capi_call_b4(state, 0, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        lua_settop(state, 0);
        lua_pushcclosure(state, Some(add_one), 0);
        lua_pushinteger(state, 41);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn allocation_failure_before_callback_keeps_stack_and_retries_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；失敗後原 function 與參數仍在 stack。
    unsafe {
        lua_pushcclosure(state, Some(add_one), 0);
        lua_pushinteger(state, 41);
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::WorkReserve))
            .unwrap();
        assert_ne!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn fixed_and_multret_callback_results_follow_c_stack_contract_b4() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；各次私有呼叫同步完成後才檢查輸出 stack。
    unsafe {
        lua_pushcclosure(state, Some(two_results), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 41);
        lua_settop(state, 0);
        lua_pushcclosure(state, Some(two_results), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 3), 0);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 42);
        assert_eq!(lua_type(state, 3), 0);
        lua_settop(state, 0);
        lua_pushcclosure(state, Some(two_results), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, -1), 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 42);
    }
}

#[test]
fn callback_allocation_ordinals_rollback_and_retry_b4() {
    LIVE_TOKENS.with(|count| count.set(0));
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let make_owner = || {
            let owner =
                StateOwner::new_with_allocator(tracked_allocator, std::ptr::null_mut()).unwrap();
            let state = owner.as_ptr();
            // SAFETY：owner 保活 state；先建立相同的函式與輸入。
            unsafe {
                lua_pushcclosure(state, Some(add_one), 0);
                lua_pushinteger(state, 41);
            }
            owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
            owner
        };
        let dry = make_owner();
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        // SAFETY：乾跑建立本路徑實際 allocation ordinal 範圍。
        assert_eq!(unsafe { rivetlua_capi_call_b4(dry.as_ptr(), 1, 1) }, 0);
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start, "{mode:?}");
        for offset in 0..end - start {
            let tokens_before_owner = live_tokens();
            let owner = make_owner();
            let state = owner.as_ptr();
            let tokens_before = live_tokens();
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
            // SAFETY：每次失敗仍須完整返回 C driver 並保留原 stack 供重試。
            assert_ne!(
                unsafe { rivetlua_capi_call_b4(state, 1, 1) },
                0,
                "mode={mode:?} offset={offset}"
            );
            assert_eq!(
                unsafe { lua_gettop(state) },
                2,
                "mode={mode:?} offset={offset}"
            );
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
                "mode={mode:?} offset={offset} before={:?} after={:?}",
                before.0, after.0
            );
            assert_eq!(after.0.reserved, 0, "mode={mode:?} offset={offset}");
            assert_eq!(
                after.1.debt_bytes, before.1.debt_bytes,
                "mode={mode:?} offset={offset}"
            );
            assert_eq!(after.2, before.2, "mode={mode:?} offset={offset}");
            assert_eq!(after.1.finalizer_pending, before.1.finalizer_pending);
            assert_eq!(after.1.finalizer_warnings, before.1.finalizer_warnings);
            assert_eq!(
                after.1.finalizer_deferred_terminals,
                before.1.finalizer_deferred_terminals
            );
            assert_eq!(
                live_tokens(),
                tokens_before,
                "mode={mode:?} offset={offset}"
            );
            // SAFETY：單次失敗注入消耗後，同一 state 可立即成功。
            assert_eq!(unsafe { rivetlua_capi_call_b4(state, 1, 1) }, 0);
            assert_eq!(
                unsafe { lua_tointegerx(state, -1, std::ptr::null_mut()) },
                42
            );
            drop(owner);
            assert_eq!(live_tokens(), tokens_before_owner);
        }
        drop(dry);
        assert_eq!(live_tokens(), 0);
    }
}

#[test]
fn callback_can_collect_gc_and_reacquire_captured_table_b4() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        GC_OWNER.with(|slot| slot.set(&owner));
        // SAFETY：owner 保活 state；C callback 期間 Rust VM/group 借用已完全釋放。
        unsafe {
            lua_createtable(state, 0, 0);
            lua_pushcclosure(state, Some(collect_during_capture), 1);
            assert_eq!(rivetlua_capi_call_b4(state, 0, 1), 0);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
        }
        GC_OWNER.with(|slot| slot.set(std::ptr::null()));
    }
}

#[test]
fn private_lua_fixture_probe_failure_is_atomic_and_retriable_b4() {
    LIVE_TOKENS.with(|count| count.set(0));
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let make_owner = || {
            let owner =
                StateOwner::new_with_allocator(tracked_allocator, std::ptr::null_mut()).unwrap();
            owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
            owner
        };
        let dry = make_owner();
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        // SAFETY：私有 probe 只接受已驗證的 selector=1，state 由 owner 保活。
        assert_eq!(
            unsafe { rivetlua_capi_test_push_lua_b4(dry.as_ptr(), 1) },
            1
        );
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start);
        for offset in 0..end - start {
            let tokens_before_owner = live_tokens();
            let owner = make_owner();
            let state = owner.as_ptr();
            let before = fixture_snapshot(&owner);
            let tokens_before = live_tokens();
            let ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
                .unwrap();
            assert_eq!(
                unsafe { rivetlua_capi_test_push_lua_b4(state, 1) },
                0,
                "mode={mode:?} offset={offset}"
            );
            assert_eq!(unsafe { lua_gettop(state) }, 0);
            let after = fixture_snapshot(&owner);
            let added_slots = after.2.len() - before.2.len();
            assert!(added_slots <= 2, "mode={mode:?} offset={offset}");
            assert_eq!(&after.2[..before.2.len()], before.2.as_slice());
            assert!(
                after.2[before.2.len()..]
                    .iter()
                    .all(|state| *state == SlotState::Free)
            );
            // B10b2 的 hidden hook bridge 占一個 Registry root；B12 的主 thread 另有 Coroutine root。
            assert_eq!(before.3, (3, 1));
            assert_eq!(after.3, before.3, "mode={mode:?} offset={offset}");
            assert_eq!(
                after.0.lua_heap_bytes,
                before.0.lua_heap_bytes + 136 * added_slots
            );
            assert_eq!(
                after.0.host_allocation_bytes,
                before.0.host_allocation_bytes
            );
            assert_eq!(live_tokens(), tokens_before + added_slots as isize);
            assert_eq!(after.0.reserved, 0);
            assert_eq!(after.1.finalizer_pending, before.1.finalizer_pending);
            assert_eq!(after.1.finalizer_warnings, before.1.finalizer_warnings);
            assert_eq!(
                after.1.finalizer_deferred_terminals,
                before.1.finalizer_deferred_terminals
            );
            if after.1.transition_count > before.1.transition_count {
                assert_eq!(after.1.debt_bytes, 0);
                assert_eq!(after.1.major_debt_bytes, 0);
            } else {
                assert_eq!(after.1.debt_bytes, before.1.debt_bytes);
                assert_eq!(after.1.major_debt_bytes, before.1.major_debt_bytes);
            }
            if added_slots != 0 {
                let failure_site = owner
                    .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.site)
                    .unwrap();
                for repetition in 0..2 {
                    let warm_before = fixture_snapshot(&owner);
                    let warm_tokens = live_tokens();
                    let next = owner
                        .with_vm(|vm| vm.allocation_trace().next_ordinal)
                        .unwrap();
                    owner
                        .with_vm(|vm| {
                            vm.inject_allocation_failure_at(next + offset - added_slots as u64)
                        })
                        .unwrap();
                    assert_eq!(
                        unsafe { rivetlua_capi_test_push_lua_b4(state, 1) },
                        0,
                        "mode={mode:?} offset={offset} repetition={repetition}"
                    );
                    let repeated_site = owner
                        .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.site)
                        .unwrap();
                    assert_eq!(repeated_site, failure_site);
                    assert_eq!(unsafe { lua_gettop(state) }, 0);
                    let warm_after = fixture_snapshot(&owner);
                    assert_eq!(warm_after.0, warm_before.0);
                    assert_eq!(warm_after.2, warm_before.2);
                    assert_eq!(warm_after.3, (3, 1));
                    assert_eq!(warm_after.1.debt_bytes, warm_before.1.debt_bytes);
                    assert_eq!(
                        warm_after.1.major_debt_bytes,
                        warm_before.1.major_debt_bytes
                    );
                    assert_eq!(live_tokens(), warm_tokens);
                }
            }
            assert_eq!(unsafe { rivetlua_capi_test_push_lua_b4(state, 1) }, 1);
            assert_eq!(unsafe { lua_gettop(state) }, 1);
            drop(owner);
            assert_eq!(live_tokens(), tokens_before_owner);
        }
        drop(dry);
        assert_eq!(live_tokens(), 0);
    }
}
